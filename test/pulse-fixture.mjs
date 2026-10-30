// Builds a simulated chain with one stamp lock in it, for testing BRC Pulse's "Check a stamp".
import { writeFileSync } from 'node:fs';
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
const T0 = Math.floor(Date.now() / 1000) - 220 * 150;
function block(h, txs) {
  const header = cat(be32(h), c.hexToBytes(rand()), merkle(txs), c.hexToBytes(rand()), be64(T0 + (h - 92300) * 150), be32(0x1d0a0000), be32(h * 7), c.hexToBytes(miners.at(h % 3)));
  return c.bytesToHex(cat(header, be32(txs.length), ...txs));
}
const me = c.walletFromPrivateKeyHex(rand());
const file = new TextEncoder().encode('Farm lease, signed copy. Version 3.\n');
const blocks = {};
for (let h = 92300; h <= 92520; h++) if (h !== 92510) blocks[h] = block(h, h % 5 ? [] : [cat(be32(0xc01dfeed), c.hexToBytes(rand(148)))]);
const afterHash = c.readBlock(blocks[92500]).hash;
const st = c.newStamp({ fingerprint: c.fingerprint(file), owner: me.address, after: { height: 92500, hash: afterHash } });
const pre = cat(be32(0x4c4f434b), be32(0xc01dfeed), c.hexToBytes(me.address), be64(100000n), be64(1000n), be32(3), c.hexToBytes(c.stampScriptHash(st)));
const lock = cat(pre, c.ed25519.sign(pre, me.privateKey));
blocks[92510] = block(92510, [cat(be32(0xc01dfeed), c.hexToBytes(rand(148))), lock]);
const receipt = c.receiptText(st, { lockId: c.fingerprint(lock), fileName: 'lease-v3.txt', fileSize: file.length });
// A receipt for a lock that isn't on the chain, and one whose salt was edited.
const missing = c.receiptText(st, { lockId: rand() });
const edited = receipt.replace(/Salt: ([0-9a-f]{32})/, (m, s) => `Salt: ${s.slice(0, 31)}${s.at(-1) === '0' ? '1' : '0'}`);
writeFileSync('build/pulse-fixture.json', JSON.stringify({ tip: 92520, blocks, receipt, missing, edited, fileHex: c.bytesToHex(file), owner: me.address, lockBlockTs: c.readBlock(blocks[92510]).timestamp }));
console.log('fixture: lock in block 92510, receipt without Block line');
