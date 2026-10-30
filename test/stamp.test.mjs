// Stamp tests: against real BrowserCoin blocks and a full simulated stamp.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import * as c from '../build/seal-core.mjs';

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('ok -', name); };
const throwsMsg = (fn, re) => assert.throws(fn, (e) => re.test(e.message), `expected error matching ${re}`);
const rand = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return c.bytesToHex(b); };
const me = c.walletFromPrivateKeyHex(rand());
const other = c.walletFromPrivateKeyHex(rand());

// ---------- Real chain ----------
const CHAIN = '../chain';
const files = existsSync(CHAIN) ? readdirSync(CHAIN).filter((f) => /^b_\d+\.json$/.test(f)) : [];
if (files.length) {
  t(`reads ${files.length * 200} real blocks, rebuilding every txRoot, and finds the same locks as the Python parser`, () => {
    const ids = [];
    let blocks = 0, scripts = 0;
    for (const f of files) {
      for (const hex of JSON.parse(readFileSync(`${CHAIN}/${f}`, 'utf8')).blocks) {
        const b = c.readBlock(hex);
        blocks++;
        for (const tx of b.txs) if (tx.kind === 'lock') ids.push(tx.id);
      }
    }
    const py = JSON.parse(readFileSync(`${CHAIN}/found.json`, 'utf8')).filter((x) => x[0] === 'lock').map((x) => x[3]);
    assert.equal(blocks, files.length * 200);
    assert.deepEqual([...ids].sort(), [...py].sort());
    assert.ok(ids.length > 0);
  });

  t('block ID matches the helper server (block 92,184 = 4c5dd99e…)', () => {
    for (const f of files) {
      for (const hex of JSON.parse(readFileSync(`${CHAIN}/${f}`, 'utf8')).blocks) {
        if (parseInt(hex.slice(0, 8), 16) === 92184) {
          assert.equal(c.readBlock(hex).hash, '4c5dd99e107f1940a4efde75dd7d59c639854f7cadbd81e5ef57c20b67d68dc6');
          return;
        }
      }
    }
    assert.fail('block 92,184 not in the download');
  });

  t('real hash-locked payments use exactly the script layout stamps rely on', () => {
    const found = JSON.parse(readFileSync(`${CHAIN}/found.json`, 'utf8'));
    const scripts = found.filter((x) => x[0] === 'redeem').map((x) => x[4].script);
    const hashlocks = scripts.filter((s) => /^a820[0-9a-f]{64}8820[0-9a-f]{64}ac$/.test(s));
    assert.ok(hashlocks.length > 0, 'no real hash-locked payments found');
    const st = c.newStamp({ fingerprint: rand(), owner: me.address });
    assert.match(c.stampScriptHex(st), /^a820[0-9a-f]{64}8820[0-9a-f]{64}ac$/);
  });

  t('an altered real block is refused', () => {
    const hex = JSON.parse(readFileSync(`${CHAIN}/${files[0]}`, 'utf8')).blocks.find((h) => parseInt(h.slice(296, 304), 16) > 0);
    const flipped = hex.slice(0, 400) + (hex[400] === '0' ? '1' : '0') + hex.slice(401);
    throwsMsg(() => c.readBlock(flipped), /don't match its header|unexpected|know|cut short/);
  });
} else {
  console.log('(skipping real-chain tests: ../chain not downloaded)');
}

// ---------- A complete simulated stamp ----------
const be32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const be64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
const cat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const sha = (b) => c.hexToBytes(c.fingerprint(b));

// A lock tx laid out exactly like src/chain/transaction.ts lockPreimage + signature.
function lockTx(wallet, scriptHashHex, amount = 100000n, fee = 1000n, nonce = 7) {
  const pre = cat(be32(0x4c4f434b), be32(0xc01dfeed), c.hexToBytes(wallet.address), be64(amount), be64(fee), be32(nonce), c.hexToBytes(scriptHashHex));
  return cat(pre, c.ed25519.sign(pre, wallet.privateKey));
}
function transferTx() { return cat(be32(0xc01dfeed), c.hexToBytes(rand(148))); } // 152 bytes, like a real transfer
function merkle(leaves) {
  if (leaves.length === 1) return sha(leaves[0]);
  let layer = leaves.map(sha);
  while (layer.length > 1) { const n = []; for (let i = 0; i < layer.length; i += 2) n.push(sha(cat(layer[i], layer[i + 1] || layer[i]))); layer = n; }
  return layer[0];
}
function block(height, txs, ts = 1793330000) {
  const header = cat(be32(height), c.hexToBytes(rand()), merkle(txs), c.hexToBytes(rand()), be64(ts), be32(0x1e00ffff), be32(42), c.hexToBytes(rand()));
  assert.equal(header.length, 148);
  return c.bytesToHex(cat(header, be32(txs.length), ...txs));
}

const file = new TextEncoder().encode('Contract between Patrick and the farm, v3.\n');
const fp = c.fingerprint(file);

t('fingerprint is plain SHA-256 of the file', () => {
  assert.equal(c.fingerprint(new TextEncoder().encode('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

t('stamp phrase is one unbroken word, with or without "after"', () => {
  const a = c.newStamp({ fingerprint: fp, owner: me.address });
  assert.match(c.stampPhrase(a), /^BRCSTAMP1_[0-9a-f]{64}_[0-9a-f]{32}$/);
  const b = c.newStamp({ fingerprint: fp, owner: me.address, after: { height: '92,510', hash: 'ab'.repeat(32) } });
  assert.match(c.stampPhrase(b), /^BRCSTAMP1_[0-9a-f]{64}_[0-9a-f]{32}_A92510_[0-9a-f]{64}$/);
  assert.notEqual(c.newStamp({ fingerprint: fp, owner: me.address }).salt, a.salt);
});

t('end to end: stamp, receipt, find the lock in its block, prove the date and who stamped it', () => {
  const st = c.newStamp({ fingerprint: fp, owner: me.address, after: { height: 92500, hash: 'cd'.repeat(32) } });
  const lock = lockTx(me, c.stampScriptHash(st));
  const lockId = c.fingerprint(lock);
  const blk = block(92510, [transferTx(), lock, transferTx()]);
  const receiptText = c.receiptText(st, { lockId, block: 92510, fileName: 'contract-v3.txt', fileSize: file.length });
  const r = c.parseReceipt(receiptText);
  assert.equal(c.fileMatches(r, file), true);
  const res = c.checkStampInBlock(r, blk);
  assert.equal(res.ok, true);
  assert.equal(res.height, 92510);
  assert.equal(res.timestamp, 1793330000);
  assert.equal(res.from, me.address);
  assert.equal(res.amount, 100000n);
});

t('a changed file, salt, owner or "after" no longer matches', () => {
  const st = c.newStamp({ fingerprint: fp, owner: me.address });
  const lock = lockTx(me, c.stampScriptHash(st));
  const blk = block(92510, [lock]);
  const r = c.parseReceipt(c.receiptText(st, { lockId: c.fingerprint(lock) }));
  assert.equal(c.fileMatches(r, new TextEncoder().encode('Contract between Patrick and the farm, v4.\n')), false);
  for (const swap of [{ salt: rand(16) }, { owner: other.address }, { after: { height: 1, hash: 'ee'.repeat(32) } }]) {
    const changed = { ...r, stamp: { ...r.stamp, ...swap } };
    assert.equal(c.checkStampInBlock(changed, blk).ok, false);
  }
});

t('a lock that is not in the named block is reported, not invented', () => {
  const st = c.newStamp({ fingerprint: fp, owner: me.address });
  const lock = lockTx(me, c.stampScriptHash(st));
  const r = c.parseReceipt(c.receiptText(st, { lockId: c.fingerprint(lock) }));
  const res = c.checkStampInBlock(r, block(92511, [transferTx()]));
  assert.equal(res.ok, false);
  assert.match(res.reason, /not in block 92511/);
});

t('receipts survive chat-app pasting and explain what is missing', () => {
  const st = c.newStamp({ fingerprint: fp, owner: me.address });
  const txt = c.receiptText(st, { lockId: 'ab'.repeat(32), fileName: 'a\nb.txt', fileSize: 10 });
  assert.ok(!/a\nb\.txt/.test(txt), 'file name must stay on one line');
  const quoted = txt.split('\n').map((l) => '> ' + l).join('\r\n');
  assert.equal(c.parseReceipt(quoted).stamp.salt, st.salt);
  throwsMsg(() => c.parseReceipt('hello'), /not a BRC stamp receipt/);
  throwsMsg(() => c.parseReceipt(txt.replace(/Salt: .*\n/, '')), /"Salt:" line is missing/);
  throwsMsg(() => c.parseReceipt(txt.replace(/Lock ID: .*/, 'Lock ID: 1234')), /Lock ID should be 64/);
});

t('owner must be a real wallet address', () => {
  throwsMsg(() => c.newStamp({ fingerprint: fp, owner: '01' + '00'.repeat(31) }), /real wallet/);
  throwsMsg(() => c.newStamp({ fingerprint: 'xyz', owner: me.address }), /fingerprint should be 64/);
});

console.log(`\n${passed} stamp tests passed`);

// Fixture for the independent Python check of the stamp script math.
import { writeFileSync } from 'node:fs';
const fx = c.newStamp({ fingerprint: fp, owner: me.address, after: { height: 92500, hash: 'cd'.repeat(32) } });
writeFileSync('build/stamp-fixture.json', JSON.stringify({ phrase: c.stampPhrase(fx), owner: me.address, scriptHash: c.stampScriptHash(fx), fileHex: c.bytesToHex(file), fingerprint: fp }));
