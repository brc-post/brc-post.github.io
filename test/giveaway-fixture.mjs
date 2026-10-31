// Test data for BRC Pulse's giveaway page: a mailbox wallet, a prize pool, an
// eligible list, an entry list, and settings for two phases (entries open; winner drawn).
import { writeFileSync, readFileSync } from 'node:fs';
import * as c from '../build/seal-core.mjs';
import { makeChain } from './chain-block.mjs';

const rand = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); return c.bytesToHex(b); };
const mailbox = c.walletFromPrivateKeyHex(rand());
const pool = c.walletFromPrivateKeyHex(rand()).address;
const eligible = Array.from({ length: 40 }, () => c.walletFromPrivateKeyHex(rand()).address).sort();
const notEligible = c.walletFromPrivateKeyHex(rand()).address;
const entries = eligible.slice(0, 25);
const beacon = JSON.parse(readFileSync('test/drand-vectors.json', 'utf8')).beacons[2];
const drawAt = new Date(c.drandRoundTime(beacon.round) * 1000).toISOString();
const now = Date.now();
const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
const SERVICE = 'https://brc-mailbox.test.workers.dev';
const eligibleFile = { v: 1, cutoff: 92500, cutoffTime: 0, fromHeight: 75000, fromTime: 0, count: eligible.length, fingerprint: c.eligibleFingerprint(eligible), addresses: eligible };
const entriesFile = { v: 1, letters: 31, count: entries.length, fingerprint: c.listFingerprint(entries), addresses: entries, setAside: [{ seq: 4, reason: 'This address already entered.' }] };
const base = { v: 1, mailbox: mailbox.address, pool, service: SERVICE, eligible: { cutoff: 92500, count: eligible.length, fingerprint: eligibleFile.fingerprint } };
const open = { ...base, opensAt: iso(now - 86400e3), closesAt: iso(now + 2 * 86400e3), drawAt: iso(now + 4 * 86400e3), entries: null };
const drawn = { ...base, opensAt: iso(Date.parse(drawAt) - 9 * 86400e3), closesAt: iso(Date.parse(drawAt) - 2 * 86400e3), drawAt, entries: { count: entries.length, fingerprint: entriesFile.fingerprint } };
const expected = c.drawWinner(entries, entriesFile.fingerprint, beacon);
// Giveaway messages signed on the chain by the release address: the launch (rules and draw round),
// then the list commitment. Small chains of their own, timed around the draw round:
//   92600-92620 run from three days before the draw, 92621-92640 from an hour before it.
//   good:   launch locks in 92602, the list commitment in 92605 (settled days ahead).
//   double: the same, plus a second lock by the release address in 92610.
//   late:   launch in 92602, the list commitment only in 92622 (settles after the draw).
const ch = makeChain(c);
const rel = c.walletFromPrivateKeyHex(rand());
const roundT = c.drandRoundTime(beacon.round);
const launchFor = (cfg) => c.newChainSignature({ address: rel.address, text: c.launchMessage({ mailbox: cfg.mailbox, pool: cfg.pool, eligible: cfg.eligible.fingerprint, closesAt: cfg.closesAt, round: c.roundAt(Math.floor(Date.parse(cfg.drawAt) / 1000)) }) });
const openLaunch = launchFor(open), drawnLaunch = launchFor(drawn);
const commitText = c.listCommitMessage({ count: entries.length, fingerprint: entriesFile.fingerprint, round: beacon.round });
const goodCs = c.newChainSignature({ address: rel.address, text: commitText });
const lateCs = c.newChainSignature({ address: rel.address, text: commitText });
const L = { openLaunch: ch.lock(rel, c.chainScriptHash(openLaunch)), drawnLaunch: ch.lock(rel, c.chainScriptHash(drawnLaunch)), good: ch.lock(rel, c.chainScriptHash(goodCs)), late: ch.lock(rel, c.chainScriptHash(lateCs)), extra: ch.lock(rel, c.chainScriptHash(c.newChainSignature({ address: rel.address, text: 'Another list, just in case.' }))) };
const ts = (h) => (h <= 92620 ? roundT - 3 * 86400 + (h - 92600) * 600 : roundT - 3600 + (h - 92621) * 600);
function chainWith(extra) {
  const blocks = {};
  for (let h = 92600; h <= 92640; h++) blocks[h] = ch.block(h, h === 92602 ? [L.openLaunch, L.drawnLaunch] : extra[h] || [], ts(h));
  return { tip: 92640, blocks };
}
writeFileSync('build/giveaway-chain.json', JSON.stringify({
  good: chainWith({ 92605: [L.good] }),
  double: chainWith({ 92605: [L.good], 92610: [L.extra] }),
  late: chainWith({ 92622: [L.late] }),
}));
writeFileSync('build/giveaway-official.json', JSON.stringify([{ address: rel.address, name: 'BRC Works release address', role: 'release' }]));
const signed = (cs, lock, block) => c.chainSignedText(cs, { lockId: c.fingerprint(lock), block });
const launchOpen = signed(openLaunch, L.openLaunch, 92602), launchDrawn = signed(drawnLaunch, L.drawnLaunch, 92602);
const commitment = signed(goodCs, L.good, 92605), lateCommitment = signed(lateCs, L.late, 92622);
writeFileSync('build/giveaway-open.json', JSON.stringify({ ...open, launch: launchOpen }));
writeFileSync('build/giveaway-open-nolaunch.json', JSON.stringify(open));
writeFileSync('build/giveaway-drawn.json', JSON.stringify({ ...drawn, launch: launchDrawn, commitment }));
writeFileSync('build/giveaway-drawn-nocommit.json', JSON.stringify({ ...drawn, launch: launchDrawn }));
writeFileSync('build/giveaway-drawn-late.json', JSON.stringify({ ...drawn, launch: launchDrawn, commitment: lateCommitment }));
writeFileSync('build/giveaway-drawn-moved.json', JSON.stringify({ ...drawn, drawAt: new Date((roundT + 60) * 1000).toISOString(), launch: launchDrawn, commitment }));
writeFileSync('build/giveaway-fixture.json', JSON.stringify({ mailboxKey: c.bytesToHex(mailbox.privateKey), mailbox: mailbox.address, pool, eligible: eligibleFile, entries: entriesFile, notEligible, beacon, expected }));
console.log(`giveaway fixture: ${eligible.length} eligible, ${entries.length} entries, winner index ${expected.index}`);
