// Core tests for BRC Seal. Run with: npm test
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import * as c from '../build/seal-core.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('ok -', name); };
const throwsMsg = (fn, re) => assert.throws(fn, (e) => re.test(e.message), `expected error matching ${re}`);

const rand = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); return c.bytesToHex(b); };
const alice = c.walletFromPrivateKeyHex(rand());
const bob = c.walletFromPrivateKeyHex(rand());
const carol = c.walletFromPrivateKeyHex(rand());

// ---------------- Signed messages ----------------

t('sign then verify', () => {
  const s = c.signMessage(alice, "I'm pb-hash on Discord.");
  const v = c.verifySigned(s.armored);
  assert.equal(v.valid, true);
  assert.equal(v.address, alice.address);
  assert.equal(v.message, "I'm pb-hash on Discord.");
});

t('a changed message fails', () => {
  const s = c.signMessage(alice, 'I owe Bob 1 BRC.');
  const v = c.verifySigned(s.armored.replace('1 BRC', '9 BRC'));
  assert.equal(v.valid, false);
});

t('a different address fails', () => {
  const s = c.signMessage(alice, 'hello');
  const v = c.verifySigned(s.armored.replace(alice.address, bob.address));
  assert.equal(v.valid, false);
});

t('survives chat-app mangling: CRLF, trailing spaces, quote marks, code fences, invisible characters, wrapped signature', () => {
  const s = c.signMessage(alice, 'Line one\nLine two');
  const sig = s.signature;
  const mangled = '```\r\n' + s.armored
    .replace('Line one', 'Line one   ')
    .replace(sig, sig.slice(0, 60) + '\n' + sig.slice(60))
    .split('\n').map((l) => '> ' + l).join('\r\n')
    .replace('Line two', 'Line​ two') + '\r\n```';
  const v = c.verifySigned(mangled);
  assert.equal(v.valid, true);
});

t('signature can never be a BrowserCoin transaction', () => {
  // Rebuild the exact signed bytes and check their shape.
  const bytes = new TextEncoder().encode(`BrowserCoin Signed Message v1\nAddress: ${alice.address}\nMessage:\nx`);
  const head = c.bytesToHex(bytes.slice(0, 4));
  assert.notEqual(head, 'c01dfeed'); // transfer preimage starts with CHAIN_ID
  assert.notEqual(head, '4c4f434b'); // 'LOCK'
  assert.ok(bytes.length > 32);       // script redeems sign a 32-byte hash
});

t('rejects empty, too long, and marker-containing messages', () => {
  throwsMsg(() => c.signMessage(alice, '   \n '), /Write a message/);
  throwsMsg(() => c.signMessage(alice, 'x'.repeat(c.MAX_SIGNED_CHARS + 1)), /under 2,000/);
  throwsMsg(() => c.signMessage(alice, 'hi -----BEGIN BRC SIGNATURE-----'), /markers/);
});

t('explains incomplete pastes', () => {
  const s = c.signMessage(alice, 'hello').armored;
  throwsMsg(() => c.verifySigned('just some text'), /not a BRC signed message/);
  throwsMsg(() => c.verifySigned(s.split('\n').slice(1).join('\n')), /first line/);
  throwsMsg(() => c.verifySigned(s.split('\n').slice(0, -1).join('\n')), /last line/);
  throwsMsg(() => c.verifySigned(s.replace(/Signature: [0-9a-f]{128}/, (m) => m.slice(0, -10))), /128 characters/);
});

// ---------------- Sealed notes ----------------

t('anonymous seal opens for the recipient only', () => {
  const n = c.sealNote(bob.address, 'Meet at block 100,000.');
  assert.equal(n.signed, false);
  const o = c.openNote(n.armored, bob);
  assert.equal(o.message, 'Meet at block 100,000.');
  assert.equal(o.signed, false);
  throwsMsg(() => c.openNote(n.armored, carol), /different address/);
});

t('signed seal tells the recipient who sent it', () => {
  const n = c.sealNote(bob.address, 'From Alice, really.', alice);
  const o = c.openNote(n.armored, bob);
  assert.equal(o.signed, true);
  assert.equal(o.from, alice.address);
  assert.equal(o.signatureValid, true);
  assert.ok(!n.armored.includes(alice.address), 'sender address must not appear outside the encryption');
});

t('relabelling a note to another address does not open', () => {
  const n = c.sealNote(bob.address, 'secret');
  const relabelled = n.armored.replace(bob.address, carol.address);
  throwsMsg(() => c.openNote(relabelled, carol), /could not be opened/);
});

t('any changed character breaks the note', () => {
  const n = c.sealNote(bob.address, 'secret');
  const lines = n.armored.split('\n');
  const k = 4; // a base64 line
  const ch = lines[k][10] === 'A' ? 'B' : 'A';
  lines[k] = lines[k].slice(0, 10) + ch + lines[k].slice(11);
  throwsMsg(() => c.openNote(lines.join('\n'), bob), /could not be opened|damaged/);
});

t('missing pieces are explained', () => {
  const n = c.sealNote(bob.address, 'secret').armored;
  const lines = n.split('\n');
  throwsMsg(() => c.openNote(lines.slice(0, -1).join('\n'), bob), /last line/);
  throwsMsg(() => c.openNote([...lines.slice(0, 3), ...lines.slice(4)].join('\n'), bob), /damaged|too short|could not be opened/);
});

t('survives a phone wrapping the To line and a quoted, fenced paste', () => {
  const n = c.sealNote(bob.address, 'wrapped').armored;
  const wrapped = n.replace(`To: ${bob.address}`, `To: ${bob.address.slice(0, 30)}\n${bob.address.slice(30)}`);
  const quoted = '```\n' + wrapped.split('\n').map((l) => '> ' + l).join('\r\n') + '\n```';
  assert.equal(c.openNote(quoted, bob).message, 'wrapped');
});

t('length is hidden in 64-byte steps', () => {
  const a = c.sealNote(bob.address, 'a').armored.length;
  const b = c.sealNote(bob.address, 'x'.repeat(28)).armored.length; // 4 + 96 + 28 = 128 bytes
  const d = c.sealNote(bob.address, 'x'.repeat(29)).armored.length; // one byte more, next step
  assert.equal(a, b);
  assert.ok(d > b);
});

t('every note is different, even with the same text', () => {
  assert.notEqual(c.sealNote(bob.address, 'same').armored, c.sealNote(bob.address, 'same').armored);
});

t('unicode and the size limit', () => {
  const msg = 'Hola, ¿cómo estás? 🌱 Caisán';
  assert.equal(c.openNote(c.sealNote(bob.address, msg).armored, bob).message, msg);
  const max = 'x'.repeat(c.MAX_SEALED_BYTES);
  assert.equal(c.openNote(c.sealNote(bob.address, max).armored, bob).message, max);
  throwsMsg(() => c.sealNote(bob.address, max + 'x'), /4,096 bytes/);
});

t('bad addresses are refused', () => {
  throwsMsg(() => c.sealNote('abc', 'x'), /64 characters/);
  throwsMsg(() => c.sealNote('z'.repeat(64), 'x'), /0–9 and a–f/);
  throwsMsg(() => c.sealNote('01' + '00'.repeat(31), 'x'), /usable/); // the identity point
  // y = 2 is not on the curve
  throwsMsg(() => c.sealNote('02' + '00'.repeat(31), 'x'), /valid BrowserCoin public key/);
});

t('address encryption key matches the wallet key, across 200 random wallets', () => {
  for (let i = 0; i < 200; i++) {
    const w = c.walletFromPrivateKeyHex(rand());
    const n = c.sealNote(w.address, `n${i}`);
    assert.equal(c.openNote(n.armored, w).message, `n${i}`);
  }
});

// ---------------- Raffle ----------------

t('raffle: only eligible addresses count, duplicates and wrong text dropped, same winner every time', () => {
  const H = 100000;
  const text = c.raffleEntryText(H);
  assert.equal(text, "I'm entering the BrowserCoin block 100,000 giveaway.");
  const wallets = Array.from({ length: 7 }, () => c.walletFromPrivateKeyHex(rand()));
  const eligible = new Set(wallets.map((w) => w.address));
  const blocks = wallets.map((w) => c.signMessage(w, text).armored);
  blocks.push(c.signMessage(wallets[0], text).armored);            // duplicate
  blocks.push(c.signMessage(carol, 'I want in').armored);           // wrong text
  blocks.push(c.signMessage(bob, text).armored.replace('block 100,000', 'block 100,001')); // tampered
  for (let i = 0; i < 20; i++) blocks.push(c.signMessage(c.walletFromPrivateKeyHex(rand()), text).armored); // throwaway wallets
  const pasted = blocks.join('\n\nsome chatter in between\n\n');
  const split = c.splitSignedBlocks(pasted);
  assert.equal(split.length, 30);
  const { entries, rejected } = c.checkRaffleEntries(split, H, eligible);
  assert.equal(entries.length, 7);
  assert.equal(rejected.filter((r) => r.reason === 'not eligible at the snapshot').length, 20);
  assert.throws(() => c.checkRaffleEntries(split, H));
  const hash = 'ab'.repeat(32);
  const listHash = c.raffleListHash(entries);
  const d1 = c.drawRaffle(entries, H, hash, listHash);
  const d2 = c.drawRaffle([...entries].reverse(), '100,000', hash, listHash);
  assert.equal(d1.winner, d2.winner);
  assert.equal(d1.seed, c.drawRaffle(entries, '100000', hash).seed);
  assert.ok(entries.includes(d1.winner));
  assert.notEqual(c.drawRaffle(entries, H, 'cd'.repeat(32)).seed, d1.seed);
  throwsMsg(() => c.drawRaffle(entries.slice(1), H, hash, listHash), /do not match the list fingerprint/);
  throwsMsg(() => c.drawRaffle(entries, '0100000x', hash), /whole number/);
  throwsMsg(() => c.drawRaffle(entries, 1.5, hash), /whole number/);
});

t('raffle: roughly fair over many block hashes', () => {
  const entries = Array.from({ length: 5 }, () => rand()).sort();
  const counts = new Map(entries.map((e) => [e, 0]));
  for (let i = 0; i < 5000; i++) {
    const w = c.drawRaffle(entries, 100000, rand()).winner;
    counts.set(w, counts.get(w) + 1);
  }
  for (const n of counts.values()) assert.ok(n > 800 && n < 1200, `count ${n} out of expected range`);
});

// ---------------- Fixes from the independent review ----------------

const { Point } = c.ed25519;
const SMALL_ORDER = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
];

t('review M1: small-order addresses never verify, even with a keyless signature', () => {
  for (const addr of SMALL_ORDER) {
    const block = ['-----BEGIN BRC SIGNED MESSAGE-----', 'I control nothing.', '-----BEGIN BRC SIGNATURE-----', `Address: ${addr}`, `Signature: ${'01' + '00'.repeat(63)}`, '-----END BRC SIGNATURE-----'].join('\n');
    const v = c.verifySigned(block);
    assert.equal(v.valid, false, addr);
    assert.equal(c.isCleanAddress(addr), false);
  }
});

t('review M1: torsioned look-alike addresses are refused everywhere', () => {
  const A = Point.fromHex(alice.address);
  const T = Point.fromHex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
  const twin = A.add(T).toHex();
  assert.equal(c.isCleanAddress(alice.address), true);
  assert.equal(c.isCleanAddress(twin), false);
  const s = c.signMessage(alice, 'hello').armored.replace(alice.address, twin);
  assert.equal(c.verifySigned(s).valid, false);
  throwsMsg(() => c.sealNote(twin, 'x'), /usable/);
});

t('review L1/L2: lines chat apps rewrite, hidden characters and look-alike markers are refused when signing', () => {
  throwsMsg(() => c.signMessage(alice, '> quoted\nreply'), /cannot start with >/);
  throwsMsg(() => c.signMessage(alice, '```\ncode'), /cannot start with >/);
  throwsMsg(() => c.signMessage(alice, 'pay ‮ecila'), /hidden or direction-changing/);
  throwsMsg(() => c.signMessage(alice, 'blankㅤname'), /hidden or direction-changing/);
  throwsMsg(() => c.signMessage(alice, 'tag\u{E0041}'), /hidden or direction-changing/);
  throwsMsg(() => c.signMessage(alice, '—----BEGIN BRC SIGNATURE-----'), /markers/);
  assert.equal(c.verifySigned(c.signMessage(alice, 'I ❤️ BRC \u{1F331}').armored).valid, true); // ordinary emoji still fine
});

t('review L3: signed and anonymous notes are the same size', () => {
  for (const text of ['a', 'x'.repeat(60), 'x'.repeat(500)]) {
    assert.equal(c.sealNote(bob.address, text).length, c.sealNote(bob.address, text, alice).length);
  }
});

// ---------------- Fixtures for the independent cross-check ----------------

mkdirSync('build', { recursive: true });
const fixture = {
  bob: { privateKeyHex: c.bytesToHex(bob.privateKey), address: bob.address },
  alice: { address: alice.address },
  signed: c.signMessage(alice, 'Cross-check: signed by Alice.').armored,
  anon: c.sealNote(bob.address, 'Cross-check: anonymous note to Bob. 🌱').armored,
  fromAlice: c.sealNote(bob.address, 'Cross-check: signed note from Alice to Bob.', alice).armored,
};
writeFileSync('build/crosscheck.json', JSON.stringify(fixture, null, 2));

console.log(`\n${passed} core tests passed`);

// A BRC Vault backup and a wallet file for the page test (fast scrypt setting so the test is quick).
const pageWallet = c.walletFromPrivateKeyHex(rand());
const backup = await c.encryptWallet(pageWallet, 'correct horse battery staple', { kdf: { name: 'scrypt', logN: 14, r: 8, p: 1, dkLen: 32 } });
writeFileSync('build/page-fixture.json', JSON.stringify({
  walletFile: JSON.stringify({ type: 'browsercoin-wallet', version: 1, address: pageWallet.address, privateKeyHex: c.bytesToHex(pageWallet.privateKey), warning: 'Anyone with the private key controls the wallet. Keep this safe.' }, null, 2),
  address: pageWallet.address,
  backup: JSON.stringify(backup, null, 2),
  password: 'correct horse battery staple',
}));
