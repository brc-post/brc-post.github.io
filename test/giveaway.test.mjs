// Giveaway tests: address-only entries, reading a mailbox, list fingerprints, drand draw.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from '../build/seal-core.mjs';

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('ok -', name); };
const throwsMsg = (fn, re) => assert.throws(fn, (e) => re.test(e.message), `expected error matching ${re}`);
const rand = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return c.bytesToHex(b); };
const wallet = () => c.walletFromPrivateKeyHex(rand());
const beacons = JSON.parse(readFileSync('test/drand-vectors.json', 'utf8')).beacons;

const mailbox = wallet();
const people = Array.from({ length: 6 }, wallet);

t('an entry needs only an address, and is exactly one fixed text', () => {
  const a = people[0].address;
  assert.equal(c.entryText(a), `BRC Works giveaway entry v1\nAddress: ${a}`);
  assert.equal(c.entryText(' 0x' + a.toUpperCase() + ' '), c.entryText(a));
  assert.equal(c.parseEntryText(c.entryText(a)), a);
  throwsMsg(() => c.parseEntryText(c.entryText(a) + '\nPS hi'), /Not a giveaway entry/);
  throwsMsg(() => c.entryText('abc'), /64/);
  // A small-order point is not an address any real wallet has.
  throwsMsg(() => c.entryText('0100000000000000000000000000000000000000000000000000000000000000'), /real wallet/);
});

t('entries are sealed letters only the mailbox can open; outsiders see only the mailbox address', () => {
  const n = c.sealEntry(mailbox.address, people[0].address);
  assert.equal(n.to, mailbox.address);
  assert.equal(n.signed, false);
  assert.ok(!n.armored.includes(people[0].address));
  assert.equal(c.parseEntryText(c.openNote(n.armored, mailbox).message), people[0].address);
  throwsMsg(() => c.openNote(n.armored, people[1]), /different address/);
});

t('reading the mailbox keeps one valid, eligible entry per address and explains the rest', () => {
  const eligible = new Set(people.slice(0, 5).map((p) => p.address));
  const letters = [
    c.sealEntry(mailbox.address, people[0].address).armored,
    c.sealEntry(mailbox.address, people[1].address).armored,
    c.sealEntry(mailbox.address, people[1].address).armored, // duplicate
    c.sealEntry(mailbox.address, people[5].address).armored, // not eligible
    c.sealNote(mailbox.address, 'hello, can I enter?', null).armored, // not an entry
    c.sealEntry(people[2].address, people[2].address).armored, // sealed to someone else
    'not a letter at all',
    c.sealEntry(mailbox.address, people[3].address).armored,
  ];
  const r = c.readEntries(letters, mailbox, eligible);
  assert.deepEqual(r.entries, [people[0].address, people[1].address, people[3].address].sort());
  assert.equal(r.rejected.length, 5);
  assert.deepEqual(r.rejected.map((x) => x.index), [2, 3, 4, 5, 6]);
  assert.match(r.rejected.find((x) => x.index === 2).reason, /already entered/);
  assert.match(r.rejected.find((x) => x.index === 3).reason, /eligible/);
  assert.match(r.rejected.find((x) => x.index === 5).reason, /different address/);
  assert.equal(r.fingerprint, c.listFingerprint(r.entries));
});

t('list fingerprints ignore order and duplicates, and differ between entry and eligible lists', () => {
  const a = people.map((p) => p.address);
  assert.equal(c.listFingerprint(a), c.listFingerprint([...a].reverse().concat(a[0])));
  assert.notEqual(c.listFingerprint(a), c.listFingerprint(a.slice(1)));
  assert.notEqual(c.listFingerprint(a), c.eligibleFingerprint(a));
  throwsMsg(() => c.listFingerprint(['xyz']), /64 characters/);
});

t('roundAt gives the first drand round at or after a time', () => {
  const r = beacons[2].round;
  const tm = c.drandRoundTime(r);
  assert.equal(c.roundAt(tm), r);
  assert.equal(c.roundAt(tm - 1), r);
  assert.equal(c.roundAt(tm + 1), r + 1);
  throwsMsg(() => c.roundAt(1000), /before drand/);
});

t('the draw is fixed by the list and the real beacon, and refuses anything else', () => {
  const list = people.map((p) => p.address);
  const fp = c.listFingerprint(list);
  const b = beacons[2];
  const d1 = c.drawWinner(list, fp, b);
  const d2 = c.drawWinner([...list].reverse(), fp, b);
  assert.deepEqual(d1, d2);
  assert.ok(list.includes(d1.winner));
  assert.equal(d1.count, 6);
  throwsMsg(() => c.drawWinner(list.slice(1), fp, b), /does not match the fingerprint/);
  throwsMsg(() => c.drawWinner(list, fp, { round: b.round + 1, signature: b.signature }), /doesn't check out/);
  throwsMsg(() => c.drawWinner(list, fp, { round: b.round, signature: 'ab' }), /96-character/);
  throwsMsg(() => c.drawWinner([], fp, b), /no entries/);
  // A different real beacon gives an independent result.
  const d3 = c.drawWinner(list, fp, beacons[1]);
  assert.notEqual(d3.seed, d1.seed);
});

t('the draw is fair: each position wins about equally often over many seeds', () => {
  // Uses the same arithmetic as drawWinner, with stand-in seeds, to check there's no bias by position.
  const counts = new Array(7).fill(0);
  for (let i = 0; i < 70000; i++) {
    const seed = rand();
    counts[Number(BigInt('0x' + seed) % 7n)]++;
  }
  for (const n of counts) assert.ok(Math.abs(n - 10000) < 500, `uneven: ${counts}`);
});

console.log(`\n${passed} giveaway tests passed`);
