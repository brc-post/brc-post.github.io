// Official names, look-alikes and release messages.
import assert from 'node:assert/strict';
import * as c from '../build/seal-core.mjs';

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('ok -', name); };
const rand = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); return c.bytesToHex(b); };
const real = c.walletFromPrivateKeyHex(rand()).address;
const list = [{ address: real, name: 'BRC Works release address', role: 'release' }];

t('official addresses are named; addresses sharing the start or end with one are look-alikes', () => {
  assert.equal(c.officialFor(real, list).name, 'BRC Works release address');
  assert.equal(c.officialFor(real.toUpperCase(), list).name, 'BRC Works release address');
  assert.equal(c.lookalikeOf(real, list), null);
  const sameStart = real.slice(0, 6) + rand().slice(6);
  const sameEnd = rand().slice(0, 58) + real.slice(-6);
  assert.equal(c.lookalikeOf(sameStart, list).name, 'BRC Works release address');
  assert.equal(c.lookalikeOf(sameEnd, list).name, 'BRC Works release address');
  let other = rand(); while (other.slice(0, 6) === real.slice(0, 6) || other.slice(-6) === real.slice(-6)) other = rand();
  assert.equal(c.lookalikeOf(other, list), null);
  assert.equal(c.lookalikeOf('nonsense', list), null);
  assert.deepEqual(c.OFFICIAL, Object.freeze(c.OFFICIAL));
  assert.ok(Object.isFrozen(c.OFFICIAL));
});

t('a release message is exact, and only an exact one reads back', () => {
  const r = { tool: 'BRC Vault', version: '1.1.0', file: 'brc-vault.html', sha256: 'ab'.repeat(32) };
  const m = c.releaseMessage(r);
  assert.equal(m, `BRC Works release v1\nTool: BRC Vault\nVersion: 1.1.0\nFile: brc-vault.html\nSHA-256: ${'ab'.repeat(32)}`);
  assert.deepEqual(c.readRelease(m), r);
  assert.equal(c.readRelease(m + '\nExtra: 1'), null);
  assert.equal(c.readRelease(m.replace('1.1.0', '1.1.0-test.1')), null);
  assert.equal(c.readRelease('hello'), null);
  assert.throws(() => c.releaseMessage({ ...r, version: '1.1.0-test.1' }), /never released/);
  assert.throws(() => c.releaseMessage({ ...r, tool: 'BRC Wallet' }), /one of/);
  // A release message can be signed on the chain as is.
  const cs = c.newChainSignature({ address: real, text: m });
  assert.equal(cs.message, m);
});

console.log(`\n${passed} official-address and release tests passed`);
