// Builds a simulated chain with one stamp lock in it, for testing BRC Pulse's "Check a stamp".
import { writeFileSync, mkdirSync } from 'node:fs';
import * as c from '../build/seal-core.mjs';
const rand = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return c.bytesToHex(b); };
const be32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const be64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
const cat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const sha = (b) => c.hexToBytes(c.fingerprint(b));
function merkle(leaves) {
  if (!leaves.length) return new Uint8Array(32);
  if (leaves.length === 1) return sha(leaves[0]);
  let layer = leaves.map(sha);
  while (layer.length > 1) { const n = []; for (let i = 0; i < layer.length; i += 2) n.push(sha(cat(layer[i], layer[i + 1] || layer[i]))); layer = n; }
  return layer[0];
}
const miners = [rand(), rand(), rand()];
// Real drand beacon; block 92,510 (the stamp) is 5 minutes after it, as in real life.
const beacon = JSON.parse((await import('node:fs')).readFileSync('test/drand-vectors.json', 'utf8')).beacons.at(-1);
const T0 = c.drandRoundTime(beacon.round) + 300 - 210 * 150;
function block(h, txs) {
  const header = cat(be32(h), c.hexToBytes(rand()), merkle(txs), c.hexToBytes(rand()), be64(T0 + (h - 92300) * 150), be32(0x1d0a0000), be32(h * 7), c.hexToBytes(miners.at(h % 3)));
  return c.bytesToHex(cat(header, be32(txs.length), ...txs));
}
const me = c.walletFromPrivateKeyHex(rand());
const file = new TextEncoder().encode('Farm lease, signed copy. Version 3.\n');
const blocks = {};
for (let h = 92300; h <= 92530; h++) if (h !== 92510) blocks[h] = block(h, h % 5 ? [] : [cat(be32(0xc01dfeed), c.hexToBytes(rand(148)))]);
const afterHash = c.readBlock(blocks[92500]).hash;
const st = c.newStamp({ fingerprint: c.fingerprint(file), owner: me.address, after: { height: 92500, hash: afterHash }, drand: beacon });
// A receipt whose drand beacon was tampered with.
const st0 = st;
const pre = cat(be32(0x4c4f434b), be32(0xc01dfeed), c.hexToBytes(me.address), be64(100000n), be64(1000n), be32(3), c.hexToBytes(c.stampScriptHash(st)));
const lock = cat(pre, c.ed25519.sign(pre, me.privateKey));
blocks[92510] = block(92510, [cat(be32(0xc01dfeed), c.hexToBytes(rand(148))), lock]);
const receipt = c.receiptText(st, { lockId: c.fingerprint(lock), fileName: 'lease-v3.txt', fileSize: file.length });
// A receipt for a lock that isn't on the chain, and one whose salt was edited.
const missing = c.receiptText(st, { lockId: rand() });
const noLockId = c.receiptText(st, { fileName: 'lease-v3.txt', fileSize: file.length });
const edited = receipt.replace(/Salt: ([0-9a-f]{32})/, (m, s) => `Salt: ${s.slice(0, 31)}${s.at(-1) === '0' ? '1' : '0'}`);
// A lying helper's invented block above the real tip, holding a lock for a brand-new receipt.
const st2 = c.newStamp({ fingerprint: c.fingerprint(new TextEncoder().encode('forged')), owner: me.address });
const pre2 = cat(be32(0x4c4f434b), be32(0xc01dfeed), c.hexToBytes(me.address), be64(100000n), be64(1000n), be32(4), c.hexToBytes(c.stampScriptHash(st2)));
const lock2 = cat(pre2, c.ed25519.sign(pre2, me.privateKey));
const fakeBlock = block(99999, [lock2]);
const fakeReceipt = c.receiptText(st2, { lockId: c.fingerprint(lock2), block: 99999 });
const fakeReceiptNoBlock = c.receiptText(st2, { lockId: c.fingerprint(lock2) });
// The receipt's Owner line differs from the address the app actually locked to.
const other = c.walletFromPrivateKeyHex(rand());
const wrongOwner = receipt.replace(`Owner: ${me.address}`, `Owner: ${other.address}`);
// Chain-signed messages (BRC Seal 0.5): one signed by `me`, a mailbox link, and a copy someone
// else locked to the same script, which must not count as `me` signing.
const mk = (w, sh, n) => { const p = cat(be32(0x4c4f434b), be32(0xc01dfeed), c.hexToBytes(w.address), be64(100000n), be64(1000n), be32(n), c.hexToBytes(sh)); return cat(p, c.ed25519.sign(p, w.privateKey)); };
const cs = c.newChainSignature({ address: me.address, text: "I'm pb-hash on the BrowserCoin Discord. Oct 31, 2026." });
const mailbox = c.walletFromPrivateKeyHex(rand());
const lcs = c.newChainSignature({ address: me.address, text: c.linkMessage(mailbox, me.address) });
blocks[92520] = block(92520, [mk(me, c.chainScriptHash(cs), 10), mk(me, c.chainScriptHash(lcs), 11)]);
const copyCs = c.newChainSignature({ address: me.address, text: 'I owe the bearer 1,000 BRC.' });
const copyLock = mk(other, c.chainScriptHash(copyCs), 12);
blocks[92521] = block(92521, [copyLock]);
const chainSigned = c.chainSignedText(cs);
const chainEdited = chainSigned.replace('Discord', 'Discord server');
const chainLink = c.chainSignedText(lcs);
const chainBadLink = chainLink.replace(`Mailbox: ${mailbox.address}`, `Mailbox: ${other.address}`);
const chainCopy = c.chainSignedText(copyCs);
const chainCopyWithId = c.chainSignedText(copyCs, { lockId: c.fingerprint(copyLock) });
// Release postmarks: a genuine one from the release address, and a fake one signed by someone else.
const rel = c.walletFromPrivateKeyHex(rand());
const relFile = new TextEncoder().encode('<!doctype html><title>BRC Vault</title>genuine 1.1.0');
const fakeFile = new TextEncoder().encode('<!doctype html><title>BRC Vault</title>tampered');
const sha256hex = (b) => c.fingerprint(b);
const relCs = c.newChainSignature({ address: rel.address, text: c.releaseMessage({ tool: 'BRC Vault', version: '1.1.0', file: 'brc-vault.html', sha256: sha256hex(relFile) }) });
const fakeCs = c.newChainSignature({ address: other.address, text: c.releaseMessage({ tool: 'BRC Vault', version: '1.1.1', file: 'brc-vault.html', sha256: sha256hex(fakeFile) }) });
const relLock = mk(rel, c.chainScriptHash(relCs), 13), fakeLock = mk(other, c.chainScriptHash(fakeCs), 14);
blocks[92522] = block(92522, [relLock]);
blocks[92523] = block(92523, [fakeLock]);
// A griefer copies the genuine release's script into a newer lock of their own: it must not hide the release.
blocks[92524] = block(92524, [mk(other, c.chainScriptHash(relCs), 15)]);
mkdirSync('build/pulse-releases', { recursive: true });
writeFileSync('build/pulse-releases/brc-vault-1.1.0.txt', c.chainSignedText(relCs, { lockId: c.fingerprint(relLock), block: 92522 }));
writeFileSync('build/pulse-releases/brc-vault-1.1.1.txt', c.chainSignedText(fakeCs, { lockId: c.fingerprint(fakeLock), block: 92523 }));
writeFileSync('build/pulse-official.json', JSON.stringify([{ address: rel.address, name: 'BRC Works release address', role: 'release' }]));
const badDrand = c.receiptText(st0, { lockId: c.fingerprint(lock) }).replace(`Drand: ${beacon.round}`, `Drand: ${beacon.round + 1}`);
writeFileSync('build/pulse-fixture.json', JSON.stringify({ tip: 92530, badDrand, beacon, fakeBlock, fakeReceipt, fakeReceiptNoBlock, wrongOwner, blocks, receipt, noLockId, missing, edited, fileHex: c.bytesToHex(file), owner: me.address, chainSigned, chainEdited, chainLink, chainBadLink, chainCopy, chainCopyWithId, chainMessage: cs.message, linkMailbox: mailbox.address, relFileHex: c.bytesToHex(relFile), fakeFileHex: c.bytesToHex(fakeFile), relAddress: rel.address, lookalike: rel.address.slice(0, 6) + rand().slice(6), lockBlockTs: c.readBlock(blocks[92510]).timestamp }));
console.log('fixture: lock in block 92510, receipt without Block line');
