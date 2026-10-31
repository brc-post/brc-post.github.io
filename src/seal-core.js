// BRC Post core: signed messages and sealed notes for BrowserCoin addresses.
// Runs entirely locally. No network access is needed or used.
//
// A BrowserCoin address IS an Ed25519 public key (64 hex characters), so:
//   - a wallet can SIGN a statement, and anyone can check it against the address;
//   - anyone can SEAL a note to an address, and only that wallet can open it.
//
// Wallet loading (files, key codes, recovery words, BRC Vault backups) is shared
// with BRC Vault: see vault-core.js, which this page reuses unchanged.

import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { bytesToHex, hexToBytes } from './vault-core.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/** A signed message is a short statement, not a document. */
export const MAX_SIGNED_CHARS = 2000;
/** A sealed note holds up to 4 KB of text (a long email's worth). */
export const MAX_SEALED_BYTES = 4096;
/** Discord rejects messages over 2,000 characters; the page warns past this. */
export const DISCORD_LIMIT = 2000;
const MAX_PASTE = 64 * 1024;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

function wipe(...arrays) {
  for (const a of arrays) if (a instanceof Uint8Array) a.fill(0);
}

function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(text) {
  const clean = String(text).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 === 1) throw new Error('The sealed note is damaged: it contains characters that do not belong.');
  let bin;
  try { bin = atob(clean.padEnd(Math.ceil(clean.length / 4) * 4, '=')); } catch { throw new Error('The sealed note is damaged and cannot be read.'); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Text copied through phones and chat apps picks up invisible characters,
 * odd spaces and Windows line endings. Both signing and checking use this
 * same cleaned-up form, so those changes never break a signature.
 */
export function normalizeMessage(text) {
  return String(text)
    .normalize('NFC')
    .replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '')
    .replace(/[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g, ' ')
    .replace(/\r\n?|[\u2028\u2029]/g, '\n')
    .split('\n').map((line) => line.replace(/[ \t]+$/, '')).join('\n')
    .replace(/^\n+|\n+$/g, '');
}

/** Strip what chat apps wrap around pasted blocks: code fences, quote marks, invisible characters. */
export function cleanPaste(text) {
  if (String(text).length > MAX_PASTE) throw new Error('This is far too long to be a signed message or a sealed note.');
  return String(text)
    .replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '')
    .replace(/[\u00A0\u2007\u202F]/g, ' ')
    .replace(/\r\n?|[\u2028\u2029]/g, '\n')
    .split('\n')
    .map((line) => line.replace(/^\s*>\s?/, '').replace(/^\s*```[a-z]*\s*$/i, ''))
    .join('\n');
}

/** Address as given by a person: 64 hex characters, spaces and 0x tolerated. */
export function parseAddress(text) {
  const hex = String(text).replace(/[\s\u200B-\u200D\u2060\uFEFF]/g, '').toLowerCase().replace(/^0x/, '');
  if (!hex) throw new Error('Enter a BrowserCoin address.');
  if (!/^[0-9a-f]+$/.test(hex)) throw new Error('A BrowserCoin address only uses the characters 0–9 and a–f.');
  if (hex.length !== 64) throw new Error(`A BrowserCoin address is 64 characters long. This one has ${hex.length}.`);
  return hex;
}

/**
 * Checks that an address is a real public key that can receive sealed notes.
 * Addresses have no built-in typo check, so a mistyped address is usually
 * still a valid key. This only catches ones that are impossible or unsafe.
 */
function addressPoint(address) {
  let point;
  // Strict decoding (no non-canonical encodings).
  try { point = ed25519.Point.fromBytes(hexToBytes(address, 32), false); } catch {
    throw new Error("This address isn't a valid BrowserCoin public key. Check it for a typo.");
  }
  // Real wallets always produce a clean, prime-order key. A small-order or
  // "torsioned" key is one nobody fully controls: such addresses could appear
  // to sign anything, or eight addresses could share one key.
  if (point.isSmallOrder() || !point.isTorsionFree()) throw new Error("This address isn't a usable BrowserCoin public key.");
  return point;
}

/** True only for an address a real wallet could have. Never throws. */
export function isCleanAddress(address) {
  try { addressPoint(address); return true; } catch { return false; }
}

/** Strict signature check: clean address, canonical signature, no cofactor tricks. */
export function strictVerify(sigBytes, msgBytes, address) {
  if (!isCleanAddress(address)) return false;
  try { return ed.verify(sigBytes, msgBytes, hexToBytes(address, 32), { zip215: false }); } catch { return false; }
}

// Characters that are invisible, change text direction, or look like blanks.
// A signed message must be exactly what it looks like on screen.
const HIDDEN_CHARS = /[\p{Cf}\p{Co}\u034F\u17B4\u17B5\u3164\u2800ᅟᅠㅤﾠ⠀︀-︍᠋-᠏]|[\u{E0100}-\u{E01EF}]/u;

/** Does this text contain hidden or direction-changing characters? */
export function hasHiddenCharacters(text) {
  return HIDDEN_CHARS.test(String(text));
}

// ---------------------------------------------------------------------------
// Signed messages
// ---------------------------------------------------------------------------
//
// The bytes signed are:
//   "BrowserCoin Signed Message v1\n" + "Address: <64 hex>\n" + "Message:\n" + <message>
//
// That opening text keeps a message signature from ever being mistaken for a
// coin transaction: BrowserCoin transfers start with the chain id 0xc01dfeed,
// locks with "LOCK", and script redeems sign a 32-byte hash. These bytes start
// with "Brow" and are always longer than 32 bytes.

const SIGN_DOMAIN = 'BrowserCoin Signed Message v1\n';
const SIGNED_BEGIN = '-----BEGIN BRC SIGNED MESSAGE-----';
const SIG_BEGIN = '-----BEGIN BRC SIGNATURE-----';
const SIG_END = '-----END BRC SIGNATURE-----';

function signedBytes(address, message) {
  return enc.encode(`${SIGN_DOMAIN}Address: ${address}\nMessage:\n${message}`);
}

export function checkMessageText(message) {
  if (!message) throw new Error('Write a message to sign.');
  if (message.length > MAX_SIGNED_CHARS) throw new Error(`Keep a signed message under ${MAX_SIGNED_CHARS.toLocaleString('en-US')} characters. This one has ${message.length.toLocaleString('en-US')}.`);
  if (/(BEGIN|END)\s*BRC/i.test(message)) throw new Error('A signed message cannot contain BRC Post markers such as "BEGIN BRC".');
  if (/^\s*(>|```)/m.test(message)) throw new Error('Lines cannot start with > or ```. Chat apps change those lines, which would break the signature.');
  if (hasHiddenCharacters(message)) throw new Error('This message contains hidden or direction-changing characters. Remove them so the message reads exactly as it looks.');
}

/** Sign a message with a loaded wallet. Returns the block of text to share. */
export function signMessage(wallet, text) {
  const message = normalizeMessage(text);
  checkMessageText(message);
  const signature = ed.sign(signedBytes(wallet.address, message), wallet.privateKey);
  return {
    address: wallet.address,
    message,
    signature: bytesToHex(signature),
    armored: [SIGNED_BEGIN, message, SIG_BEGIN, `Address: ${wallet.address}`, `Signature: ${bytesToHex(signature)}`, SIG_END].join('\n'),
  };
}

/** The hex (spaces allowed) that follows `label`, up to `stop` or the end. Returns [all, hex] like a match, or null. */
function fieldAfter(text, label, stop) {
  const at = text.indexOf(label);
  if (at < 0) return null;
  let rest = text.slice(at + label.length);
  if (stop) { const end = rest.indexOf(stop); if (end >= 0) rest = rest.slice(0, end); }
  const hex = rest.replace(/\s+/g, '');
  if (!hex || !/^[0-9a-fA-F]+$/.test(hex)) return stop ? null : (/^[0-9a-fA-F]/.test(hex) ? [rest, hex.match(/^[0-9a-fA-F]+/)[0]] : null);
  return [rest, hex];
}

/** Pull the message, address and signature out of a pasted signed-message block. */
export function parseSigned(text) {
  const t = cleanPaste(text);
  const a = t.indexOf(SIGNED_BEGIN);
  const b = t.indexOf(SIG_BEGIN);
  const c = t.indexOf(SIG_END);
  if (a < 0 && b < 0) throw new Error('This is not a BRC signed message. It should start with -----BEGIN BRC SIGNED MESSAGE-----.');
  if (a < 0) throw new Error('The first line, -----BEGIN BRC SIGNED MESSAGE-----, is missing. Copy the whole block.');
  if (b < 0 || b < a) throw new Error('The signature part is missing. Copy the whole block, down to -----END BRC SIGNATURE-----.');
  if (c < 0 || c < b) throw new Error('The last line, -----END BRC SIGNATURE-----, is missing. Copy the whole block.');
  if (t.indexOf(SIGNED_BEGIN, a + 1) >= 0) throw new Error('This contains more than one signed message. Check one at a time.');
  const message = normalizeMessage(t.slice(a + SIGNED_BEGIN.length, b));
  const tail = t.slice(b + SIG_BEGIN.length, c);
  // Read field values without regexes that can backtrack on long runs of spaces.
  const addrMatch = fieldAfter(tail, 'Address:', 'Signature:');
  const sigMatch = fieldAfter(tail, 'Signature:', null);
  if (!addrMatch) throw new Error('The Address line is missing from the signature.');
  if (!sigMatch) throw new Error('The Signature line is missing.');
  const address = parseAddress(addrMatch[1]);
  const signature = sigMatch[1].replace(/\s+/g, '').toLowerCase();
  if (signature.length !== 128) throw new Error(`The signature should be 128 characters long. This one has ${signature.length}, so part of it was lost when it was copied.`);
  if (!message) throw new Error('The message part is empty.');
  return { message, address, signature };
}

/**
 * Check a pasted signed message. Never throws for a bad signature: returns
 * { valid: false, reason } so the page can explain what went wrong.
 */
export function verifySigned(text) {
  const parsed = parseSigned(text);
  if (!isCleanAddress(parsed.address)) {
    return { ...parsed, valid: false, reason: "This address isn't one a real wallet could have, so it can't vouch for anything." };
  }
  const valid = strictVerify(hexToBytes(parsed.signature, 64), signedBytes(parsed.address, parsed.message), parsed.address);
  return valid
    ? { ...parsed, valid: true, hidden: hasHiddenCharacters(parsed.message) }
    : { ...parsed, valid: false, reason: 'The signature does not match. Either the message was changed after it was signed, or this address did not sign it.' };
}

// ---------------------------------------------------------------------------
// Sealed notes
// ---------------------------------------------------------------------------
//
// Sealing (anyone can do it, no wallet needed):
//   1. Turn the recipient's address (an Ed25519 key) into an X25519 encryption key.
//   2. Make a one-time key pair just for this note and do X25519 with the recipient.
//   3. Derive the note key and nonce with HKDF-SHA256 from that shared secret.
//   4. Encrypt with XChaCha20-Poly1305. The recipient's address is bound in as
//      associated data, so the note cannot be relabelled for someone else.
// Signing the note (optional): the sender's wallet signs the text, the
// recipient's address and the one-time key, and that signature goes INSIDE
// the encryption, so outsiders can't see who sent it. (The recipient could
// later show others that the sender wrote it; a signature is proof.)
// Every note reserves room for a sender signature, filled with zeros when
// unsigned, so signed and anonymous notes are the same size. The whole body
// is padded to a multiple of 64 bytes so the exact length is hidden.
//
// Opening needs the recipient's wallet: its private key converts to the
// matching X25519 key.
//
// Unlike BRC Post, notes have no rotating keys: if a wallet's key ever leaks,
// every note ever sealed to that address can be read. Fine for one-off notes,
// not for ongoing private conversation.

const SEAL_VERSION = 1;
const SEAL_INFO = enc.encode('BRC Post v1');
const SEAL_AAD = enc.encode('BRCSEAL1');
const SEAL_SIG_DOMAIN = enc.encode('BrowserCoin Sealed Note v1\n');
const SEALED_BEGIN = '-----BEGIN BRC SEALED NOTE-----';
const SEALED_END = '-----END BRC SEALED NOTE-----';
const FLAG_SIGNED = 1;
const PAD = 64;
const SENDER_SLOT = 96; // 32-byte sender address + 64-byte signature

function noteKey(shared, ephPub, recipientX) {
  const okm = hkdf(sha256, shared, concat(ephPub, recipientX), SEAL_INFO, 56);
  return { key: okm.slice(0, 32), nonce: okm.slice(32, 56), okm };
}

function noteSigBytes(recipientEd, ephPub, textBytes) {
  return concat(SEAL_SIG_DOMAIN, recipientEd, ephPub, textBytes);
}

/**
 * Seal a note to an address. If a sender wallet is given, the note is signed
 * inside the encryption so the recipient can see who sent it.
 */
export function sealNote(recipientAddress, text, senderWallet = null) {
  const address = parseAddress(recipientAddress);
  addressPoint(address);
  const message = normalizeMessage(text);
  if (!message) throw new Error('Write a note to seal.');
  const textBytes = enc.encode(message);
  if (textBytes.length > MAX_SEALED_BYTES) throw new Error(`A sealed note holds up to ${MAX_SEALED_BYTES.toLocaleString('en-US')} bytes of text. This one has ${textBytes.length.toLocaleString('en-US')}.`);
  const recipientEd = hexToBytes(address, 32);
  const recipientX = ed25519.utils.toMontgomery(recipientEd);

  const ephPriv = randomBytes(32);
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientX);
  const { key, nonce, okm } = noteKey(shared, ephPub, recipientX);

  const signed = !!senderWallet;
  const sender = signed
    ? concat(hexToBytes(senderWallet.address, 32), ed.sign(noteSigBytes(recipientEd, ephPub, textBytes), senderWallet.privateKey))
    : new Uint8Array(SENDER_SLOT);
  const header = new Uint8Array([SEAL_VERSION, signed ? FLAG_SIGNED : 0, textBytes.length >> 8, textBytes.length & 255]);
  const bodyLen = header.length + sender.length + textBytes.length;
  const body = new Uint8Array(Math.ceil(bodyLen / PAD) * PAD);
  body.set(header, 0);
  body.set(sender, header.length);
  body.set(textBytes, header.length + sender.length);

  const ciphertext = xchacha20poly1305(key, nonce, concat(SEAL_AAD, recipientEd)).encrypt(body);
  wipe(ephPriv, shared, key, nonce, okm, body);
  const payload = concat(new Uint8Array([SEAL_VERSION]), ephPub, ciphertext);
  const b64 = toBase64(payload);
  const lines = b64.match(/.{1,64}/g) || [];
  const armored = [SEALED_BEGIN, `To: ${address}`, '', ...lines, SEALED_END].join('\n');
  return { to: address, signed, armored, length: armored.length };
}

/** Read the recipient and the encrypted bytes from a pasted sealed note, without opening it. */
export function parseSealed(text) {
  const t = cleanPaste(text);
  const a = t.indexOf(SEALED_BEGIN);
  const b = t.indexOf(SEALED_END);
  if (a < 0) throw new Error('This is not a BRC sealed note. It should start with -----BEGIN BRC SEALED NOTE-----.');
  if (b < 0 || b < a) throw new Error('The last line, -----END BRC SEALED NOTE-----, is missing. Copy the whole block.');
  if (t.indexOf(SEALED_BEGIN, a + 1) >= 0) throw new Error('This contains more than one sealed note. Open one at a time.');
  const inner = t.slice(a + SEALED_BEGIN.length, b);
  const toAt = inner.search(/To:/i);
  if (toAt < 0) throw new Error('The "To:" line naming the recipient is missing.');
  // Read exactly 64 address characters after "To:", even if a phone wrapped
  // the line; whatever follows is the encrypted note.
  let hex = '';
  let i = toAt + 3;
  for (; i < inner.length && hex.length < 64; i++) {
    const ch = inner[i];
    if (/\s/.test(ch)) continue;
    if (!/[0-9a-fA-F]/.test(ch)) break;
    hex += ch;
  }
  const to = parseAddress(hex);
  const payload = fromBase64(inner.slice(i));
  if (payload.length < 1 + 32 + 2 * PAD + 16) throw new Error('The sealed note is too short. Part of it was lost when it was copied.');
  if (payload[0] !== SEAL_VERSION) throw new Error('This sealed note was made by a newer version of BRC Post.');
  if ((payload.length - 1 - 32 - 16) % PAD !== 0) throw new Error('The sealed note is damaged: part of it is missing or extra text crept in.');
  return { to, payload };
}

/** Open a sealed note with the recipient's wallet. */
export function openNote(text, wallet) {
  const { to, payload } = parseSealed(text);
  if (to !== wallet.address) {
    throw new Error(`This note is sealed to a different address (${to.slice(0, 10)}…${to.slice(-4)}). Load that wallet to open it.`);
  }
  const recipientEd = hexToBytes(to, 32);
  const recipientX = ed25519.utils.toMontgomery(recipientEd);
  const myX = ed25519.utils.toMontgomerySecret(wallet.privateKey);
  const ephPub = payload.slice(1, 33);
  const ciphertext = payload.slice(33);
  let shared;
  try { shared = x25519.getSharedSecret(myX, ephPub); } catch { wipe(myX); throw new Error('The sealed note is damaged and cannot be opened.'); }
  const { key, nonce, okm } = noteKey(shared, ephPub, recipientX);
  let body;
  try {
    body = xchacha20poly1305(key, nonce, concat(SEAL_AAD, recipientEd)).decrypt(ciphertext);
  } catch {
    throw new Error('This note could not be opened. It was changed or damaged after it was sealed.');
  } finally {
    wipe(myX, shared, key, nonce, okm);
  }
  if (body[0] !== SEAL_VERSION) throw new Error('This sealed note was made by a newer version of BRC Post.');
  const signed = (body[1] & FLAG_SIGNED) !== 0;
  if (body[1] & ~FLAG_SIGNED) throw new Error('This sealed note uses features this version does not understand.');
  const len = (body[2] << 8) | body[3];
  const start = 4 + SENDER_SLOT;
  if (start + len > body.length || body.subarray(start + len).some((x) => x !== 0)) throw new Error('The sealed note is damaged inside.');
  if (!signed && body.subarray(4, start).some((x) => x !== 0)) throw new Error('The sealed note is damaged inside.');
  const textBytes = body.slice(start, start + len);
  let message;
  try { message = dec.decode(textBytes); } catch { throw new Error('The sealed note is damaged inside.'); }
  if (!signed) return { to, message, signed: false, hidden: hasHiddenCharacters(message) };
  const from = bytesToHex(body.slice(4, 36));
  const sig = body.slice(36, 100);
  const ok = strictVerify(sig, noteSigBytes(recipientEd, ephPub, textBytes), from);
  return { to, message, signed: true, from, signatureValid: ok, hidden: hasHiddenCharacters(message) };
}

// ---------------------------------------------------------------------------
// Block raffle (shared with BRC Pulse, which runs the live draw)
// ---------------------------------------------------------------------------
//
// To enter, a wallet signs exactly raffleEntryText(height).
// Making a new wallet costs nothing, so signatures alone can't stop one person
// entering thousands of times. Only addresses that are ELIGIBLE count: by
// default, addresses that mined at least one block before a snapshot height
// announced in advance. BRC Pulse supplies that list from the chain.
// Before the block arrives, the organizer publishes the list fingerprint
// (raffleListHash), so the entries can't be changed after the result is known.
// The winner is: the sorted list of entry addresses, at position
//   SHA-256("BRC raffle v1\n" + height + "\n" + block hash) mod (number of entries).
// Anyone can rerun this. The miner of that block could in theory throw away a
// winning-for-someone-else block, so keep the prize well under the 50 BRC
// block reward, which they would lose by doing so.

function raffleHeight(height) {
  const h = typeof height === 'string' ? Number(height.replace(/[,\s]/g, '')) : height;
  if (!Number.isSafeInteger(h) || h <= 0) throw new Error('The giveaway block height must be a whole number, like 100000.');
  return h;
}

export function raffleEntryText(height) {
  return `I'm entering the BrowserCoin block ${raffleHeight(height).toLocaleString('en-US')} giveaway.`;
}

/**
 * Check pasted entries against the eligible addresses (a Set of addresses,
 * e.g. everyone who mined a block before the snapshot). Returns the valid,
 * de-duplicated, sorted entry addresses and what was rejected.
 */
export function checkRaffleEntries(blocks, height, eligible) {
  if (!(eligible instanceof Set)) throw new Error('A raffle needs the list of eligible addresses (for example, everyone who mined a block before the snapshot).');
  const want = raffleEntryText(height);
  const seen = new Set();
  const rejected = [];
  for (const block of blocks) {
    try {
      const v = verifySigned(block);
      if (!v.valid) { rejected.push({ address: v.address, reason: 'signature does not match' }); continue; }
      if (v.message !== want) { rejected.push({ address: v.address, reason: 'wrong entry text' }); continue; }
      if (seen.has(v.address)) { rejected.push({ address: v.address, reason: 'duplicate entry' }); continue; }
      if (!eligible.has(v.address)) { rejected.push({ address: v.address, reason: 'not eligible at the snapshot' }); continue; }
      seen.add(v.address);
    } catch (e) {
      rejected.push({ address: null, reason: e.message });
    }
  }
  const entries = [...seen].sort();
  return { entries, rejected };
}

/** Split a pasted list into separate signed-message blocks. */
export function splitSignedBlocks(text) {
  const t = cleanPaste(text);
  const out = [];
  let i = t.indexOf(SIGNED_BEGIN);
  while (i >= 0) {
    const end = t.indexOf(SIG_END, i);
    if (end < 0) { out.push(t.slice(i)); break; }
    out.push(t.slice(i, end + SIG_END.length));
    i = t.indexOf(SIGNED_BEGIN, end);
  }
  return out;
}

/** Fingerprint of the sorted entry list, published before the draw. */
export function raffleListHash(entries) {
  return bytesToHex(sha256(enc.encode([...entries].sort().join('\n'))));
}

/**
 * Pick the winner from the entry list and the raffle block's hash. Pass the
 * list fingerprint that was published before the block, and the draw refuses
 * to run on a different list.
 */
export function drawRaffle(entries, height, blockHash, publishedListHash) {
  const h = raffleHeight(height);
  if (!entries.length) throw new Error('There are no valid entries to draw from.');
  if (publishedListHash !== undefined && raffleListHash(entries) !== String(publishedListHash).trim().toLowerCase()) {
    throw new Error('These entries do not match the list fingerprint published before the draw.');
  }
  const hash = String(blockHash).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('A block hash is 64 characters, 0–9 and a–f.');
  const sorted = [...entries].sort();
  const seed = sha256(concat(enc.encode(`BRC raffle v1\n${h}\n`), hexToBytes(hash, 32)));
  const index = Number(BigInt('0x' + bytesToHex(seed)) % BigInt(sorted.length));
  return { winner: sorted[index], index, count: sorted.length, seed: bytesToHex(seed), listHash: raffleListHash(sorted) };
}
