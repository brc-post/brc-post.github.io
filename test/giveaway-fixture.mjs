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
const iso = (ms) => new Date(ms).toISOString();
const SERVICE = 'https://brc-mailbox.test.workers.dev';
const eligibleFile = { v: 1, cutoff: 92500, cutoffTime: 0, fromHeight: 75000, fromTime: 0, count: eligible.length, fingerprint: c.eligibleFingerprint(eligible), addresses: eligible };
const entriesFile = { v: 1, letters: 31, count: entries.length, fingerprint: c.listFingerprint(entries), addresses: entries, setAside: [{ seq: 4, reason: 'This address already entered.' }] };
const base = { v: 1, mailbox: mailbox.address, pool, service: SERVICE, eligible: { cutoff: 92500, count: eligible.length, fingerprint: eligibleFile.fingerprint } };
const open = { ...base, opensAt: iso(now - 86400e3), closesAt: iso(now + 2 * 86400e3), drawAt: iso(now + 4 * 86400e3), entries: null };
const drawn = { ...base, opensAt: iso(Date.parse(drawAt) - 9 * 86400e3), closesAt: iso(Date.parse(drawAt) - 2 * 86400e3), drawAt, entries: { count: entries.length, fingerprint: entriesFile.fingerprint } };
const expected = c.drawWinner(entries, entriesFile.fingerprint, beacon);
// The list commitment: the release address signs the list and the draw round on the chain. A small
// chain of its own, timed before the draw: the good commitment is settled two hours ahead; a late
// one lands as the draw happens.
const ch = makeChain(c);
const rel = c.walletFromPrivateKeyHex(rand());
const roundT = c.drandRoundTime(beacon.round);
const commitText = c.listCommitMessage({ count: entries.length, fingerprint: entriesFile.fingerprint, round: beacon.round });
const goodCs = c.newChainSignature({ address: rel.address, text: commitText });
const lateCs = c.newChainSignature({ address: rel.address, text: commitText });
const goodLock = ch.lock(rel, c.chainScriptHash(goodCs)), lateLock = ch.lock(rel, c.chainScriptHash(lateCs));
const gblocks = {};
for (let h = 92600; h <= 92630; h++) gblocks[h] = ch.block(h, h === 92610 ? [goodLock] : h === 92618 ? [lateLock] : [], roundT - 7200 + (h - 92600) * 300);
writeFileSync('build/giveaway-chain.json', JSON.stringify({ tip: 92630, blocks: gblocks }));
writeFileSync('build/giveaway-official.json', JSON.stringify([{ address: rel.address, name: 'BRC Works release address', role: 'release' }]));
const commitment = c.chainSignedText(goodCs, { lockId: c.fingerprint(goodLock), block: 92610 });
const lateCommitment = c.chainSignedText(lateCs, { lockId: c.fingerprint(lateLock), block: 92618 });
writeFileSync('build/giveaway-open.json', JSON.stringify(open));
writeFileSync('build/giveaway-drawn.json', JSON.stringify({ ...drawn, commitment }));
writeFileSync('build/giveaway-drawn-nocommit.json', JSON.stringify(drawn));
writeFileSync('build/giveaway-drawn-late.json', JSON.stringify({ ...drawn, commitment: lateCommitment }));
writeFileSync('build/giveaway-fixture.json', JSON.stringify({ mailboxKey: c.bytesToHex(mailbox.privateKey), mailbox: mailbox.address, pool, eligible: eligibleFile, entries: entriesFile, notEligible, beacon, expected }));
console.log(`giveaway fixture: ${eligible.length} eligible, ${entries.length} entries, winner index ${expected.index}`);
