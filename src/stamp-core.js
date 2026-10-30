// BRC Stamp core: put a file's fingerprint on the BrowserCoin chain, and check it later.
//
// How a stamp works, using only what BrowserCoin already has (no fork, no new tx type):
//
//   1. The file never leaves the device. Its SHA-256 fingerprint is computed locally.
//   2. A "stamp phrase" is made from the fingerprint, a random salt, and optionally a
//      recent block ("after") and/or a recent drand beacon:
//      BRCSTAMP1_<fingerprint>_<salt>[_A<height>_<block hash>][_D<drand round>_<drand signature>]
//   3. The owner pastes that phrase into the official app: Scripts → "Create a hash-locked
//      payment", recipient = their own address. The app builds exactly this script
//      (src/ui/scripts.ts scriptFor + src/chain/scriptBuild.ts hashlockSigScript):
//          OP_SHA256 <SHA256(SHA256(phrase))> OP_EQUALVERIFY <owner> OP_CHECKSIG
//      and locks a tiny amount under SHA256(script). The lock lands in a block, whose
//      timestamp dates the stamp. The Lock ID is SHA256 of the encoded lock tx.
//   4. Proof: from the file + receipt, rebuild the phrase, script and script hash, then
//      find the lock tx by its ID in the block named on the receipt and compare.
//
// What a stamp proves: the file existed no later than that block. With "after", the
// stamp was also made no earlier than the "after" block. With a drand beacon, it was
// made after that beacon's moment, to within 3 seconds (drand-core.js). The lock is signed by the
// wallet that made it, so it also shows which address stamped it.
// The salt keeps the fingerprint private: nobody can test guesses of the file's
// contents against the chain without the receipt.
// The owner can take the locked coins back later with the same phrase (Redeem in the
// official app). Redeeming reveals only SHA256(phrase) (the app's preimage), never
// the phrase itself, so the fingerprint and salt stay private.

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from './vault-core.js';
import { parseAddress, isCleanAddress } from './seal-core.js';
import { verifyDrand, drandRoundTime } from './drand-core.js';

const enc = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;

export const STAMP_PREFIX = 'BRCSTAMP1';
/** Suggested amount to lock, in BRC. The owner can redeem it later. */
export const SUGGESTED_AMOUNT = '0.001';

// BrowserCoin opcodes used by the official hash-locked payment script.
const OP_SHA256 = 0xa8;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;

// Transaction tags (src/chain/transaction.ts).
const CHAIN_ID = 0xc01dfeed;
const LOCK_TAG = 0x4c4f434b; // 'LOCK'
const REDEEM_TAG = 0x52444d31; // 'RDM1'
const HEADER_LEN = 148;
const TRANSFER_LEN = 152;
const LOCK_LEN = 156;

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
const u32 = (b, p) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
const u16 = (b, p) => (b[p] << 8) | b[p + 1];
const u64 = (b, p) => (BigInt(u32(b, p)) << 32n) | BigInt(u32(b, p + 4));

function cleanHex(text, what, len = 64) {
  const h = String(text || '').replace(/[\s\u200B-\u200D\u2060\uFEFF]/g, '').toLowerCase().replace(/^0x/, '');
  if (!new RegExp(`^[0-9a-f]{${len}}$`).test(h)) throw new Error(`${what} should be ${len} characters, 0–9 and a–f.`);
  return h;
}

// ---------------------------------------------------------------------------
// Making a stamp
// ---------------------------------------------------------------------------

/** SHA-256 fingerprint of a file's bytes, as 64 hex characters. */
export function fingerprint(bytes) {
  return bytesToHex(sha256(bytes));
}

/**
 * A new stamp for a fingerprint. `owner` is the address that can take the locked
 * coins back (normally your own). `after` is optional: { height, hash } of a recent
 * block, which proves the stamp was made after that block.
 */
export function newStamp({ fingerprint: fp, owner, after = null, drand = null, salt = null }) {
  const f = cleanHex(fp, 'The fingerprint');
  const o = parseAddress(owner);
  if (!isCleanAddress(o)) throw new Error("The owner address isn't one a real wallet could have. Check it for a typo.");
  let a = null;
  if (after) {
    const height = Number(String(after.height).replace(/[,\s]/g, ''));
    if (!Number.isSafeInteger(height) || height < 1) throw new Error('The "after" block number should be a whole number, like 92510.');
    a = { height, hash: cleanHex(after.hash, 'The "after" block ID') };
  }
  let d = null;
  if (drand) {
    const round = Number(drand.round);
    const sig = String(drand.signature || '').replace(/\s+/g, '').toLowerCase();
    if (!verifyDrand(round, sig)) throw new Error("The drand beacon's signature doesn't check out. Copy it again from BRC Pulse → Stamps.");
    d = { round, signature: sig };
  }
  let s = salt;
  if (s == null) {
    const b = new Uint8Array(16);
    globalThis.crypto.getRandomValues(b);
    s = bytesToHex(b);
  }
  s = cleanHex(s, 'The salt', 32);
  return { fingerprint: f, salt: s, owner: o, after: a, drand: d };
}

/** The phrase to paste into the official app's "Secret phrase" box. One unbroken word, so a double-click selects all of it. */
export function stampPhrase(st) {
  return `${STAMP_PREFIX}_${st.fingerprint}_${st.salt}${st.after ? `_A${st.after.height}_${st.after.hash}` : ''}${st.drand ? `_D${st.drand.round}_${st.drand.signature}` : ''}`;
}

/** The exact redeem script the official app builds for this phrase and owner. */
export function stampScript(st) {
  const preimage = sha256(enc.encode(stampPhrase(st)));
  return concat(new Uint8Array([OP_SHA256, 0x20]), sha256(preimage), new Uint8Array([OP_EQUALVERIFY, 0x20]), hexToBytes(st.owner, 32), new Uint8Array([OP_CHECKSIG]));
}

/** SHA-256 of the script: what the lock records on-chain. */
export function stampScriptHash(st) {
  return bytesToHex(sha256(stampScript(st)));
}

/** The script as hex, as the official app's script preview shows it. */
export function stampScriptHex(st) {
  return bytesToHex(stampScript(st));
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

const R_BEGIN = '-----BEGIN BRC STAMP RECEIPT-----';
const R_END = '-----END BRC STAMP RECEIPT-----';

/**
 * The receipt to keep with the file. `lockId` is optional: BRC Pulse can find the lock from the
 * script it holds. `block` (height) is optional and filled in once the lock is found.
 */
export function receiptText(st, { lockId = null, block = null, fileName = '', fileSize = null } = {}) {
  const lines = [R_BEGIN];
  if (fileName) {
    const safe = String(fileName).replace(/[\r\n\u2028\u2029]/g, ' ').slice(0, 200);
    lines.push(`File: ${safe}${fileSize != null ? ` (${Number(fileSize).toLocaleString('en-US')} bytes)` : ''}`);
  }
  lines.push(`Fingerprint: ${st.fingerprint}`);
  lines.push(`Salt: ${st.salt}`);
  if (st.after) lines.push(`After: ${st.after.height} ${st.after.hash}`);
  if (st.drand) lines.push(`Drand: ${st.drand.round} ${st.drand.signature}`);
  lines.push(`Owner: ${st.owner}`);
  if (lockId != null && String(lockId).trim()) lines.push(`Lock ID: ${cleanHex(lockId, 'The Lock ID')}`);
  if (block != null) lines.push(`Block: ${block}`);
  lines.push(R_END);
  return lines.join('\n');
}

/** Read a pasted receipt. The "File:" line is a label only; the fingerprint is what counts. */
export function parseReceipt(text) {
  // Same cleaning as BRC Pulse's reader: line endings, invisible characters, 0x, thousands commas.
  if (String(text || '').length > 20000) throw new Error('This is far too long to be a stamp receipt.');
  const t = String(text || '').replace(/\r\n?/g, '\n').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '');
  const a = t.indexOf(R_BEGIN);
  const b = t.indexOf(R_END);
  if (a < 0) throw new Error('This is not a BRC stamp receipt. It should start with -----BEGIN BRC STAMP RECEIPT-----.');
  if (b < a) throw new Error('The last line, -----END BRC STAMP RECEIPT-----, is missing. Copy the whole receipt.');
  const body = t.slice(a + R_BEGIN.length, b);
  const field = (name) => {
    // Line by line, so a paste full of blank lines can't make the search slow.
    const want = name.toLowerCase() + ':';
    for (const raw of body.split('\n')) {
      const line = raw.replace(/^[ \t]*>?[ \t]*/, '');
      if (line.slice(0, want.length).toLowerCase() === want) { const v = line.slice(want.length).trim(); return v || null; }
    }
    return null;
  };
  const need = (name) => {
    const v = field(name);
    if (!v) throw new Error(`The receipt's "${name}:" line is missing.`);
    return v;
  };
  let after = null;
  const afterLine = field('After');
  if (afterLine) {
    const m = afterLine.match(/^(\d[\d,]*)\s+(?:0x)?([0-9a-fA-F]{64})$/);
    if (!m) throw new Error('The receipt\'s "After:" line should be a block number and a block ID.');
    after = { height: m[1], hash: m[2] };
  }
  let drand = null;
  const drandLine = field('Drand');
  if (drandLine) {
    const m = drandLine.replace(/,/g, '').match(/^(\d+)\s+(?:0x)?([0-9a-fA-F]{96})$/);
    if (!m) throw new Error('The receipt\'s "Drand:" line should be a round number and a 96-character signature.');
    drand = { round: Number(m[1]), signature: m[2] };
  }
  const st = newStamp({ fingerprint: need('Fingerprint'), owner: need('Owner'), salt: need('Salt'), after, drand });
  const lockLine = field('Lock ID');
  const lockId = lockLine ? cleanHex(lockLine, 'The Lock ID') : null;
  const blockLine = field('Block');
  let block = null;
  if (blockLine) {
    block = Number(blockLine.replace(/[,\s]/g, ''));
    if (!Number.isSafeInteger(block) || block < 1) throw new Error('The receipt\'s "Block:" line should be a block number.');
  }
  const fileLine = field('File');
  return { stamp: st, lockId, block, fileLabel: fileLine };
}

// ---------------------------------------------------------------------------
// Reading BrowserCoin blocks (layout from src/chain/block.ts and transaction.ts)
// ---------------------------------------------------------------------------

function merkleRoot(leaves) {
  if (leaves.length === 0) return new Uint8Array(32);
  if (leaves.length === 1) return sha256(leaves[0]);
  let layer = leaves.map((l) => sha256(l));
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(sha256(concat(layer[i], layer[i + 1] || layer[i])));
    layer = next;
  }
  return layer[0];
}

/**
 * Decode a block (hex or bytes) far enough to find locks. Rebuilds the block's
 * txRoot from its transactions and refuses the block if it doesn't match, so a
 * helper server can't slip in a fake lock without also faking the header.
 */
export function readBlock(block) {
  const b = typeof block === 'string' ? hexToBytes(block) : block;
  if (b.length < HEADER_LEN + 4) throw new Error('This block is too short.');
  const height = u32(b, 0);
  const txRoot = b.slice(36, 68);
  const timestamp = Number(u64(b, 100));
  const count = u32(b, HEADER_LEN);
  let p = HEADER_LEN + 4;
  const txs = [];
  for (let i = 0; i < count; i++) {
    const tag = u32(b, p);
    let raw;
    if (tag === CHAIN_ID) { raw = b.slice(p, p + TRANSFER_LEN); p += TRANSFER_LEN; txs.push({ kind: 'transfer', raw }); continue; }
    if (tag === LOCK_TAG) {
      raw = b.slice(p, p + LOCK_LEN);
      if (raw.length !== LOCK_LEN) throw new Error('A lock in this block is cut short.');
      p += LOCK_LEN;
      txs.push({ kind: 'lock', raw, id: bytesToHex(sha256(raw)), from: bytesToHex(raw.slice(8, 40)), amount: u64(raw, 40), fee: u64(raw, 48), scriptHash: bytesToHex(raw.slice(60, 92)) });
      continue;
    }
    if (tag === REDEEM_TAG) {
      let q = p + 4 + 32 + 32 + 8 + 8;
      const slen = u16(b, q); q += 2 + slen;
      const wc = b[q]; q += 1;
      for (let w = 0; w < wc; w++) q += 2 + u16(b, q);
      raw = b.slice(p, q); p = q;
      txs.push({ kind: 'redeem', raw });
      continue;
    }
    throw new Error('This block contains a transaction type this page does not know.');
  }
  if (p !== b.length) throw new Error('This block has unexpected extra data.');
  const root = merkleRoot(txs.map((t) => t.raw));
  if (bytesToHex(root) !== bytesToHex(txRoot)) throw new Error("This block's contents don't match its header. The server sent a damaged or altered block.");
  return { height, timestamp, hash: bytesToHex(sha256(b.slice(0, HEADER_LEN))), txs };
}

/**
 * Check a receipt against the block that should contain its lock. This checks the
 * block's contents only; whether the block is really on the chain is checked
 * online by BRC Pulse, which compares it across independent helper servers.
 * Returns { ok: true, height, timestamp, from, amount } or { ok: false, reason }.
 */
export function checkStampInBlock(receipt, block) {
  const blk = readBlock(block);
  const locks = blk.txs.filter((t) => t.kind === 'lock');
  // Without a Lock ID, the lock is the one holding this stamp's script (for the Owner line, or the wallet that signed it).
  const lock = receipt.lockId
    ? locks.find((t) => t.id === receipt.lockId)
    : locks.find((t) => t.scriptHash === stampScriptHash(receipt.stamp) || t.scriptHash === stampScriptHash({ ...receipt.stamp, owner: t.from }));
  if (!lock) return { ok: false, reason: receipt.lockId ? `Lock ${receipt.lockId.slice(0, 10)}… is not in block ${blk.height}.` : `No lock holding this stamp is in block ${blk.height}.` };
  if (receipt.lockId && lock.scriptHash !== stampScriptHash(receipt.stamp)) {
    return { ok: false, reason: 'A lock with this ID exists, but it does not hold this stamp. The fingerprint, salt or owner on the receipt is different from what was stamped.' };
  }
  // ownerFixed: the coins go back to the wallet that signed the lock, not the receipt's Owner line.
  const ownerFixed = lock.scriptHash !== stampScriptHash(receipt.stamp) ? lock.from : null;
  return { ok: true, height: blk.height, timestamp: blk.timestamp, blockHash: blk.hash, from: lock.from, amount: lock.amount, ownerFixed };
}

/** When the receipt's drand beacon was published (seconds), or null. */
export function stampDrandTime(st) {
  return st.drand ? drandRoundTime(st.drand.round) : null;
}

/** Does this file match the receipt? */
export function fileMatches(receipt, bytes) {
  return fingerprint(bytes) === receipt.stamp.fingerprint;
}
