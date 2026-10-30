// drand "quicknet": a public randomness beacon run by the League of Entropy.
// Every 3 seconds it publishes a new signed random value. Nobody can know a
// round's signature before that round, so putting one in a stamp proves the
// stamp was made after that moment.
//
// Checking a beacon needs no network: the signature is verified here against
// quicknet's public key (scheme bls-unchained-g1-rfc9380). Signature on G1,
// public key on G2, message = SHA-256(round as 8-byte big-endian), hashed to
// G1 with DST BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_ (noble's G1 default).
// Values below were read from four public relays run by two operators
// (api.drand.sh, api2.drand.sh, api3.drand.sh, drand.cloudflare.com), which all agreed.

import { bls12_381 } from '@noble/curves/bls12-381';
import { sha256 } from '@noble/hashes/sha2';

export const QUICKNET = Object.freeze({
  chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  publicKey: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  genesis: 1692803367,
  period: 3,
});

/** Unix time (seconds) at which a quicknet round was published. */
export function drandRoundTime(round) {
  return QUICKNET.genesis + (round - 1) * QUICKNET.period;
}

function roundMessage(round) {
  const b = new Uint8Array(8);
  let v = BigInt(round);
  for (let i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; }
  return sha256(b);
}

/** True if this signature is quicknet's real beacon for this round. Never throws. */
export function verifyDrand(round, signatureHex) {
  try {
    if (!Number.isSafeInteger(round) || round < 1) return false;
    if (!/^[0-9a-f]{96}$/.test(signatureHex)) return false;
    const S = bls12_381.shortSignatures;
    return S.verify(signatureHex, S.hash(roundMessage(round)), QUICKNET.publicKey);
  } catch {
    return false;
  }
}

/**
 * Read a beacon as people will paste it: "33522523 a6aeb7…" (BRC Pulse's Copy),
 * or the JSON a drand relay returns. Returns { round, signature } or throws.
 */
export function parseDrand(text) {
  if (String(text || '').length > 2000) throw new Error('This is far too long to be a drand beacon.');
  const t = String(text || '').trim();
  let round, sig;
  if (t.startsWith('{')) {
    let j;
    try { j = JSON.parse(t); } catch { throw new Error("This looks like drand JSON but it can't be read. Copy it again."); }
    round = Number(j.round); sig = String(j.signature || '');
  } else {
    // Collapse whitespace first, so the pattern below can't backtrack on long runs of spaces.
    const m = t.replace(/,/g, '').replace(/\s+/g, ' ').match(/^(\d+)(?: ?: ?| )([0-9a-fA-F ]+)$/);
    if (!m) throw new Error('A drand beacon is a round number and a signature, like "33522523 a6aeb7…". Copy it from BRC Pulse → Stamps.');
    round = Number(m[1]); sig = m[2];
  }
  sig = sig.replace(/\s+/g, '').toLowerCase();
  if (!Number.isSafeInteger(round) || round < 1) throw new Error('The drand round should be a whole number.');
  if (!/^[0-9a-f]{96}$/.test(sig)) throw new Error(`The drand signature should be 96 characters, 0–9 and a–f. This one has ${sig.length}.`);
  if (!verifyDrand(round, sig)) throw new Error("This drand beacon's signature doesn't check out. It may have been copied wrongly, or it isn't from drand.");
  return { round, signature: sig };
}
