// BRC chain signatures: prove that a coin address wrote a message, without that
// address's key ever touching this page.
//
// How it works, using only what BrowserCoin already has:
//   1. The message and the coin address are fingerprinted together:
//        SHA-256("BrowserCoin Chain-Signed Message v1\nAddress: <A>\nMessage:\n<message>")
//   2. That fingerprint becomes a postmark phrase (stamp-core.js), with A as the owner.
//   3. The owner pastes the phrase into the official app (Scripts → Create a hash-locked
//      payment, recipient = their own address) and locks a tiny amount. The official app
//      signs that lock with A's key, and every node checks the signature.
//   4. Anyone holding the signed message can rebuild the phrase and its script, find the
//      lock on the chain, and see that A made it: only A's key could have.
//
// So the key stays in the official app, the one place it already lives. The proof is
// the chain itself, checked online by BRC Pulse (this page works offline and can only
// check that the receipt is well-formed).
//
// A mailbox link is a chain-signed message of a fixed form, saying "my mailbox is M",
// which also carries M's own signature saying "my coin address is A". Both sides agree,
// so nobody can claim someone else's mailbox, and no mailbox can claim a coin address.

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from './vault-core.js';
import { normalizeMessage, cleanPaste, checkMessageText, parseAddress, isCleanAddress, strictVerify, hasHiddenCharacters } from './seal-core.js';
import { newStamp, stampPhrase, stampScriptHash, stampScriptHex, readBlock } from './stamp-core.js';

const enc = new TextEncoder();
const CHAIN_DOMAIN = 'BrowserCoin Chain-Signed Message v1\n';
export const CHAIN_BEGIN = '-----BEGIN BRC CHAIN SIGNED MESSAGE-----';
const CSIG_BEGIN = '-----BEGIN BRC CHAIN SIGNATURE-----';
const CSIG_END = '-----END BRC CHAIN SIGNATURE-----';

/** The fingerprint that goes on the chain: the message bound to the address that signs it. */
export function chainFingerprint(address, message) {
  return bytesToHex(sha256(enc.encode(`${CHAIN_DOMAIN}Address: ${address}\nMessage:\n${message}`)));
}

/**
 * Start a chain signature: { address, message, stamp }. Paste stampPhrase(stamp)
 * into the official app as the secret phrase, with `address` as the recipient.
 */
export function newChainSignature({ address, text, after = null, drand = null, salt = null }) {
  const a = parseAddress(address);
  if (!isCleanAddress(a)) throw new Error("This address isn't one a real wallet could have. Check it for a typo.");
  const message = normalizeMessage(text);
  checkMessageText(message);
  const stamp = newStamp({ fingerprint: chainFingerprint(a, message), owner: a, after, drand, salt });
  return { address: a, message, stamp };
}

export const chainPhrase = (cs) => stampPhrase(cs.stamp);
export const chainScriptHex = (cs) => stampScriptHex(cs.stamp);

/** The block to share: the message, then everything needed to find and check its lock. */
export function chainSignedText(cs, { lockId = null, block = null } = {}) {
  const lines = [CHAIN_BEGIN, cs.message, CSIG_BEGIN, `Address: ${cs.address}`, `Salt: ${cs.stamp.salt}`];
  if (cs.stamp.after) lines.push(`After: ${cs.stamp.after.height} ${cs.stamp.after.hash}`);
  if (cs.stamp.drand) lines.push(`Drand: ${cs.stamp.drand.round} ${cs.stamp.drand.signature}`);
  if (lockId != null && String(lockId).trim()) {
    const id = String(lockId).replace(/[\s​-‍⁠﻿]/g, '').toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('The Lock ID should be 64 characters, 0–9 and a–f.');
    lines.push(`Lock ID: ${id}`);
  }
  if (block != null) lines.push(`Block: ${block}`);
  lines.push(CSIG_END);
  return lines.join('\n');
}

/** Is this text (probably) a chain-signed message? */
export function looksChainSigned(text) {
  return String(text || '').includes(CHAIN_BEGIN);
}

/** Read a pasted chain-signed message. Throws with a plain reason if it's damaged. */
export function parseChainSigned(text) {
  if (String(text || '').length > 20000) throw new Error('This is far too long to be a chain-signed message.');
  const t = cleanPaste(text);
  const a = t.indexOf(CHAIN_BEGIN);
  if (a < 0) throw new Error('This is not a BRC chain-signed message. It should start with -----BEGIN BRC CHAIN SIGNED MESSAGE-----.');
  if (t.indexOf(CHAIN_BEGIN, a + 1) >= 0) throw new Error('This contains more than one chain-signed message. Check one at a time.');
  const b = t.indexOf(CSIG_BEGIN, a);
  const c = t.indexOf(CSIG_END, b);
  if (b < 0) throw new Error('The signature part is missing. Copy the whole block, down to -----END BRC CHAIN SIGNATURE-----.');
  if (c < 0) throw new Error('The last line, -----END BRC CHAIN SIGNATURE-----, is missing. Copy the whole block.');
  const message = normalizeMessage(t.slice(a + CHAIN_BEGIN.length, b));
  if (!message) throw new Error('The message part is empty.');
  const body = t.slice(b + CSIG_BEGIN.length, c);
  const field = (name) => {
    const want = name.toLowerCase() + ':';
    for (const raw of body.split('\n')) {
      const line = raw.trim();
      if (line.slice(0, want.length).toLowerCase() === want) { const v = line.slice(want.length).trim(); return v || null; }
    }
    return null;
  };
  const need = (name) => { const v = field(name); if (!v) throw new Error(`The "${name}:" line is missing from the signature.`); return v; };
  let after = null;
  const afterLine = field('After');
  if (afterLine) {
    const m = afterLine.match(/^(\d[\d,]*)\s+(?:0x)?([0-9a-fA-F]{64})$/);
    if (!m) throw new Error('The "After:" line should be a block number and a block ID.');
    after = { height: m[1], hash: m[2] };
  }
  let drand = null;
  const drandLine = field('Drand');
  if (drandLine) {
    const m = drandLine.replace(/,/g, '').match(/^(\d+)\s+(?:0x)?([0-9a-fA-F]{96})$/);
    if (!m) throw new Error('The "Drand:" line should be a round number and a 96-character signature.');
    drand = { round: Number(m[1]), signature: m[2] };
  }
  const address = parseAddress(need('Address'));
  const cs = { address, message, stamp: newStamp({ fingerprint: chainFingerprint(address, message), owner: address, salt: need('Salt'), after, drand }) };
  const lockLine = field('Lock ID');
  let lockId = null;
  if (lockLine) {
    lockId = lockLine.replace(/\s+/g, '').toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{64}$/.test(lockId)) throw new Error('The "Lock ID:" line should be 64 characters, 0–9 and a–f.');
  }
  const blockLine = field('Block');
  let block = null;
  if (blockLine) {
    block = Number(blockLine.replace(/[,\s]/g, ''));
    if (!Number.isSafeInteger(block) || block < 1) throw new Error('The "Block:" line should be a block number.');
  }
  return { ...cs, lockId, block, hidden: hasHiddenCharacters(message), link: readLink(message, address) };
}

/** The script hash its lock must hold (what BRC Pulse searches the chain for). */
export const chainScriptHash = (cs) => stampScriptHash(cs.stamp);

/**
 * Check a parsed chain-signed message against the block that should hold its lock.
 * The lock must hold this exact message's script AND have been made by the signing
 * address. Whether the block is really on the chain is checked by BRC Pulse.
 */
export function checkChainSignedInBlock(cs, block) {
  const blk = readBlock(block);
  const want = stampScriptHash(cs.stamp);
  const locks = blk.txs.filter((t) => t.kind === 'lock');
  // Anyone can copy a shared message's script and lock coins to it, so without a Lock ID
  // the signer's own lock is the one that counts.
  const lock = cs.lockId ? locks.find((t) => t.id === cs.lockId)
    : locks.find((t) => t.scriptHash === want && t.from === cs.address) || locks.find((t) => t.scriptHash === want);
  if (!lock) return { ok: false, reason: cs.lockId ? `Lock ${cs.lockId.slice(0, 10)}… is not in block ${blk.height}.` : `No lock holding this message is in block ${blk.height}.` };
  if (lock.scriptHash !== want) return { ok: false, reason: 'A lock with this ID exists, but it holds something else. The message, address or salt was changed after it was signed.' };
  if (lock.from !== cs.address) return { ok: false, reason: `The lock holding this message was made by a different address (${lock.from.slice(0, 10)}…), so it doesn't show that ${cs.address.slice(0, 10)}… signed it.` };
  return { ok: true, height: blk.height, timestamp: blk.timestamp, blockHash: blk.hash, lockId: lock.id, from: lock.from };
}

// ---------------------------------------------------------------------------
// Mailbox links
// ---------------------------------------------------------------------------

const LINK_HEAD = 'BRC mailbox link v1';
const LINK_SIG_DOMAIN = 'BrowserCoin Mailbox Link v1\n';
const linkBody = (coin, mailbox) => `${LINK_HEAD}\nCoin address: ${coin}\nMailbox: ${mailbox}`;

/**
 * The message a coin address signs on the chain to link a mailbox. The loaded
 * mailbox key signs it first, so the link is agreed by both sides.
 */
export function linkMessage(mailboxWallet, coinAddress) {
  const coin = parseAddress(coinAddress);
  if (!isCleanAddress(coin)) throw new Error("This coin address isn't one a real wallet could have. Check it for a typo.");
  if (coin === mailboxWallet.address) throw new Error('That is the mailbox itself. Enter the coin address you want to link it to.');
  const body = linkBody(coin, mailboxWallet.address);
  const sig = ed.sign(enc.encode(LINK_SIG_DOMAIN + body), mailboxWallet.privateKey);
  return `${body}\nMailbox signature: ${bytesToHex(sig)}`;
}

/**
 * If a chain-signed message is a mailbox link, read it: { coin, mailbox, valid, reason }.
 * `valid` covers the mailbox's own signature and that the chain signer is the coin
 * address named. Returns null when the message isn't a link at all.
 */
export function readLink(message, signer) {
  const lines = String(message).split('\n');
  if (lines[0] !== LINK_HEAD) return null;
  const get = (label) => { const l = lines.find((x) => x.startsWith(label)); return l ? l.slice(label.length).trim().toLowerCase() : null; };
  const coin = get('Coin address:');
  const mailbox = get('Mailbox:');
  const sig = get('Mailbox signature:');
  const bad = (reason) => ({ coin, mailbox, valid: false, reason });
  if (lines.length !== 4 || !/^[0-9a-f]{64}$/.test(coin || '') || !/^[0-9a-f]{64}$/.test(mailbox || '') || !/^[0-9a-f]{128}$/.test(sig || '')) return bad('This mailbox link is damaged.');
  if (signer && signer !== coin) return bad('This link was signed on the chain by a different address than the coin address it names.');
  if (!strictVerify(hexToBytes(sig, 64), enc.encode(LINK_SIG_DOMAIN + linkBody(coin, mailbox)), mailbox)) return bad("The mailbox's own signature doesn't match, so the mailbox never agreed to this link.");
  return { coin, mailbox, valid: true };
}
