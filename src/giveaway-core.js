// BRC Works giveaway: address-only entries, sealed to the giveaway mailbox; a
// published entry list; and a draw from a drand beacon fixed in advance.
//
// Entering needs no private key. An entry is a sealed letter whose text is
// exactly entryText(address). The prize can only ever go to the address in the
// entry, so entering someone else's address can't win anything for whoever
// entered it; it only gives that address's owner a chance. Eligibility (an
// address that received BRC recently) keeps dead wallets out.
//
// The draw: the organizer publishes the sorted entry list and its fingerprint
// before the draw time. The winner is
//   SHA-256("BRC Works giveaway draw v1\n" + list fingerprint + "\n" + round + "\n" + signature) mod (number of entries)
// using the drand quicknet beacon for the round announced in advance. Nobody,
// including the organizer and BrowserCoin's miners, can know that beacon
// before it's published, and anyone can rerun the draw.

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from './vault-core.js';
import { parseAddress, isCleanAddress, sealNote, openNote, parseSealed, normalizeMessage } from './seal-core.js';
import { verifyDrand, QUICKNET } from './drand-core.js';

const enc = new TextEncoder();
export const ENTRY_HEADER = 'BRC Works giveaway entry v1';
const ENTRY_RE = /^BRC Works giveaway entry v1\nAddress: ([0-9a-f]{64})$/;

/** The exact text of an entry for this address. */
export function entryText(address) {
  const a = parseAddress(address);
  if (!isCleanAddress(a)) throw new Error("This isn't an address a real wallet could have. Check you copied the whole address.");
  return `${ENTRY_HEADER}\nAddress: ${a}`;
}

/** Seal an entry to the giveaway mailbox. No wallet or key involved. */
export function sealEntry(mailbox, address) {
  return sealNote(mailbox, entryText(address), null);
}

/** The address in an opened entry, or throws if the text isn't exactly an entry. */
export function parseEntryText(text) {
  const m = normalizeMessage(text).match(ENTRY_RE);
  if (!m) throw new Error('Not a giveaway entry.');
  if (!isCleanAddress(m[1])) throw new Error("The address in this entry isn't one a real wallet could have.");
  return m[1];
}

function fingerprintOf(label, addresses) {
  const sorted = [...new Set(addresses)].sort();
  for (const a of sorted) if (!/^[0-9a-f]{64}$/.test(a)) throw new Error('Every address must be 64 characters, 0–9 and a–f.');
  return bytesToHex(sha256(enc.encode(`${label}\n${sorted.join('\n')}`)));
}

/** Fingerprint of an entry list (order and duplicates don't matter). */
export const listFingerprint = (addresses) => fingerprintOf('BRC Works giveaway list v1', addresses);
/** Fingerprint of the eligible-address list. */
export const eligibleFingerprint = (addresses) => fingerprintOf('BRC Works giveaway eligible v1', addresses);

/**
 * Open every letter from the mailbox and keep the valid entries: exactly the
 * entry text, an eligible address, one entry per address. `letters` is a list of
 * armored sealed letters; `eligible` a Set of addresses (or null to skip).
 */
export function readEntries(letters, mailboxWallet, eligible) {
  const seen = new Set();
  const rejected = [];
  letters.forEach((letter, i) => {
    let address;
    try {
      const { to } = parseSealed(letter);
      if (to !== mailboxWallet.address) throw new Error('Sealed to a different address, not this mailbox.');
      address = parseEntryText(openNote(letter, mailboxWallet).message);
    } catch (e) { rejected.push({ index: i, reason: e.message }); return; }
    if (eligible && !eligible.has(address)) { rejected.push({ index: i, address, reason: 'This address is not on the eligible list.' }); return; }
    if (seen.has(address)) { rejected.push({ index: i, address, reason: 'This address already entered.' }); return; }
    seen.add(address);
  });
  const entries = [...seen].sort();
  return { entries, rejected, fingerprint: entries.length ? listFingerprint(entries) : null };
}

/** The first drand quicknet round published at or after this Unix time (seconds). */
// The list commitment: before the draw, the BRC Works release address signs this on the
// chain (a chain-signed message, chain-core.js). BRC Pulse shows a winner only if that
// lock is in a block well before the drand round, so the list and the round were fixed
// before anyone could know the beacon (security review, Oct 31).
const COMMIT_HEAD = 'BRC Works giveaway list v1';
export function listCommitMessage({ count, fingerprint, round }) {
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('The entry count is not a whole number.');
  if (!/^[0-9a-f]{64}$/.test(String(fingerprint))) throw new Error('The list fingerprint should be 64 characters, 0–9 and a–f.');
  if (!Number.isSafeInteger(round) || round < 1) throw new Error('The draw round should be a drand round number.');
  return `${COMMIT_HEAD}\nGiveaway: block 100,000\nEntries: ${count}\nFingerprint: ${fingerprint}\nDraw round: ${round}`;
}
/** Read a list commitment back, or null. Only the exact form counts. */
export function readListCommit(message) {
  const m = /^BRC Works giveaway list v1\nGiveaway: block 100,000\nEntries: (\d{1,9})\nFingerprint: ([0-9a-f]{64})\nDraw round: (\d{1,12})$/.exec(String(message));
  if (!m) return null;
  const r = { count: Number(m[1]), fingerprint: m[2], round: Number(m[3]) };
  try { return listCommitMessage(r) === message ? r : null; } catch { return null; }
}

export function roundAt(unixTime) {
  const t = Number(unixTime);
  if (!Number.isFinite(t) || t < QUICKNET.genesis) throw new Error('That time is before drand quicknet started.');
  return Math.ceil((t - QUICKNET.genesis) / QUICKNET.period) + 1;
}

/**
 * Pick the winner. `publishedFingerprint` is the list fingerprint published
 * before the draw; the draw refuses a list that doesn't match it, and a beacon
 * that isn't drand's real one for that round.
 */
export function drawWinner(addresses, publishedFingerprint, beacon) {
  const sorted = [...new Set(addresses)].sort();
  if (!sorted.length) throw new Error('There are no entries to draw from.');
  const fp = listFingerprint(sorted);
  if (String(publishedFingerprint || '').trim().toLowerCase() !== fp) throw new Error('This list does not match the fingerprint published before the draw.');
  const round = Number(beacon && beacon.round);
  const sig = String((beacon && beacon.signature) || '').trim().toLowerCase();
  if (!Number.isSafeInteger(round) || round < 1 || !/^[0-9a-f]{96}$/.test(sig)) throw new Error('The drand beacon should be a round number and a 96-character signature.');
  if (!verifyDrand(round, sig)) throw new Error("This drand beacon's signature doesn't check out, so it isn't drand's real beacon for that round.");
  const seed = sha256(enc.encode(`BRC Works giveaway draw v1\n${fp}\n${round}\n${sig}`));
  const index = Number(BigInt('0x' + bytesToHex(seed)) % BigInt(sorted.length));
  return { winner: sorted[index], index, count: sorted.length, seed: bytesToHex(seed), fingerprint: fp, round };
}
