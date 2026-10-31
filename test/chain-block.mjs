// Builds simulated BrowserCoin blocks holding hash-locked payments, laid out exactly
// as the chain does (src/chain/block.ts, transaction.ts), for tests and fixtures.
const be32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const be64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const cat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };

export function makeChain(c) {
  const rand = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return c.bytesToHex(b); };
  const sha = (b) => c.hexToBytes(c.fingerprint(b));
  const merkle = (leaves) => {
    if (!leaves.length) return new Uint8Array(32);
    if (leaves.length === 1) return sha(leaves[0]);
    let layer = leaves.map(sha);
    while (layer.length > 1) { const n = []; for (let i = 0; i < layer.length; i += 2) n.push(sha(cat(layer[i], layer[i + 1] || layer[i]))); layer = n; }
    return layer[0];
  };
  let nonce = 1;
  /** A lock made (and signed) by `wallet`, holding `scriptHashHex`. */
  const lock = (wallet, scriptHashHex, amount = 100000n) => {
    const pre = cat(be32(0x4c4f434b), be32(0xc01dfeed), c.hexToBytes(wallet.address), be64(amount), be64(1000n), be32(nonce++), c.hexToBytes(scriptHashHex));
    return cat(pre, c.ed25519.sign(pre, wallet.privateKey));
  };
  const transfer = () => cat(be32(0xc01dfeed), c.hexToBytes(rand(148)));
  const block = (h, txs, ts = 1790000000 + h * 150) => {
    const header = cat(be32(h), c.hexToBytes(rand()), merkle(txs), c.hexToBytes(rand()), be64(ts), be32(0x1d0a0000), be32(h * 7), c.hexToBytes(rand()));
    return c.bytesToHex(cat(header, be32(txs.length), ...txs));
  };
  return { lock, transfer, block, lockId: (l) => c.fingerprint(l), rand };
}
