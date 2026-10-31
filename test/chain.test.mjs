// Chain signatures and mailbox links.
import assert from 'node:assert/strict';
import * as c from '../build/seal-core.mjs';
import { makeChain } from './chain-block.mjs';

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('ok -', name); };
const throwsMsg = (fn, re) => assert.throws(fn, (e) => re.test(e.message), `expected error matching ${re}`);
const ch = makeChain(c);
const coin = c.walletFromPrivateKeyHex(ch.rand());
const thief = c.walletFromPrivateKeyHex(ch.rand());
const mailbox = c.walletFromPrivateKeyHex(ch.rand());

const cs = c.newChainSignature({ address: coin.address, text: "I'm pb-hash on Discord.\r\nToday is Oct 31, 2026.  " });
const goodLock = ch.lock(coin, c.chainScriptHash(cs));
const blk = ch.block(95000, [ch.transfer(), goodLock]);

t('a chain signature binds the message to the address, and the phrase is a postmark phrase the official app accepts', () => {
  assert.equal(cs.message, "I'm pb-hash on Discord.\nToday is Oct 31, 2026.");
  assert.equal(cs.stamp.owner, coin.address);
  assert.equal(cs.stamp.fingerprint, c.chainFingerprint(coin.address, cs.message));
  assert.notEqual(c.chainFingerprint(thief.address, cs.message), cs.stamp.fingerprint);
  assert.match(c.chainPhrase(cs), /^BRCSTAMP1_[0-9a-f]{64}_[0-9a-f]{32}$/);
  assert.ok(c.chainScriptHex(cs).includes(coin.address));
});

t('the shared block reads back exactly, through chat-app quoting and Windows line endings', () => {
  const text = c.chainSignedText(cs, { lockId: ch.lockId(goodLock), block: 95000 });
  const quoted = text.split('\n').map((l) => '> ' + l).join('\r\n');
  for (const x of [text, quoted, '```\n' + text + '\n```']) {
    const p = c.parseChainSigned(x);
    assert.equal(p.message, cs.message);
    assert.equal(p.address, coin.address);
    assert.equal(p.lockId, ch.lockId(goodLock));
    assert.equal(p.block, 95000);
    assert.equal(c.chainScriptHash(p), c.chainScriptHash(cs));
    assert.equal(p.link, null);
  }
});

t('found on the chain: the lock holds this message and was made by the signing address', () => {
  for (const withId of [true, false]) {
    const p = c.parseChainSigned(c.chainSignedText(cs, { lockId: withId ? ch.lockId(goodLock) : null }));
    const r = c.checkChainSignedInBlock(p, blk);
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.from, coin.address);
    assert.equal(r.height, 95000);
  }
});

t('a changed word, a changed address or a changed salt no longer matches the lock', () => {
  const text = c.chainSignedText(cs, { lockId: ch.lockId(goodLock) });
  const changed = [
    text.replace('Discord', 'Discord!'),
    text.replace(`Address: ${coin.address}`, `Address: ${thief.address}`),
    text.replace(/Salt: ([0-9a-f])/, (m, d) => `Salt: ${d === '0' ? '1' : '0'}`),
  ];
  for (const x of changed) {
    const r = c.checkChainSignedInBlock(c.parseChainSigned(x), blk);
    assert.equal(r.ok, false);
  }
  const noId = c.parseChainSigned(c.chainSignedText(cs).replace('Discord', 'Discord!'));
  assert.match(c.checkChainSignedInBlock(noId, blk).reason, /No lock holding this message/);
});

t("someone else locking coins to the same script doesn't make it their signature, or the owner's", () => {
  // A copycat can build the same script (it is public once the message is shared)
  // and lock coins to it, but the lock is then signed by the copycat, not the owner.
  const copy = ch.lock(thief, c.chainScriptHash(cs));
  const b2 = ch.block(95001, [copy]);
  const r = c.checkChainSignedInBlock(c.parseChainSigned(c.chainSignedText(cs, { lockId: ch.lockId(copy) })), b2);
  assert.equal(r.ok, false);
  assert.match(r.reason, /different address/);
  const r2 = c.checkChainSignedInBlock(c.parseChainSigned(c.chainSignedText(cs)), b2);
  assert.equal(r2.ok, false);
  // A copy in the same block as the real lock doesn't hide the real one.
  const both = ch.block(95003, [ch.lock(thief, c.chainScriptHash(cs)), ch.lock(coin, c.chainScriptHash(cs))]);
  assert.equal(c.checkChainSignedInBlock(c.parseChainSigned(c.chainSignedText(cs)), both).ok, true);
});

t('refuses messages that could change on the way, damaged blocks, and junk', () => {
  throwsMsg(() => c.newChainSignature({ address: coin.address, text: '' }), /Write a message/);
  throwsMsg(() => c.newChainSignature({ address: coin.address, text: 'hi -----BEGIN BRC SEALED NOTE-----' }), /markers/);
  throwsMsg(() => c.newChainSignature({ address: coin.address, text: 'pay‮me' }), /hidden/);
  throwsMsg(() => c.newChainSignature({ address: 'abc', text: 'x' }), /64 characters/);
  const text = c.chainSignedText(cs);
  throwsMsg(() => c.parseChainSigned(text.replace('-----END BRC CHAIN SIGNATURE-----', '')), /last line/);
  throwsMsg(() => c.parseChainSigned(text.replace(/Salt: .*\n/, '')), /"Salt:" line is missing/);
  throwsMsg(() => c.parseChainSigned(text + '\n' + text), /more than one/);
  throwsMsg(() => c.parseChainSigned('x'.repeat(30000)), /far too long/);
  throwsMsg(() => c.chainSignedText(cs, { lockId: 'abc' }), /Lock ID/);
});

t('a mailbox link is agreed by both sides: the mailbox signs it, the coin address signs it on the chain', () => {
  const msg = c.linkMessage(mailbox, coin.address);
  const lcs = c.newChainSignature({ address: coin.address, text: msg });
  const p = c.parseChainSigned(c.chainSignedText(lcs));
  assert.deepEqual(p.link, { coin: coin.address, mailbox: mailbox.address, valid: true });
  const lockL = ch.lock(coin, c.chainScriptHash(lcs));
  assert.equal(c.checkChainSignedInBlock(p, ch.block(95002, [lockL])).ok, true);
});

t('a link signed by the wrong coin address, pointing at someone else\'s mailbox, or edited, is refused', () => {
  const msg = c.linkMessage(mailbox, coin.address);
  // The thief chain-signs a link naming the real coin address: the chain signer doesn't match.
  assert.equal(c.readLink(msg, thief.address).valid, false);
  // The thief claims the victim's mailbox for the thief's own coin address: the mailbox never agreed.
  const claimed = msg.replace(`Coin address: ${coin.address}`, `Coin address: ${thief.address}`);
  const r = c.readLink(claimed, thief.address);
  assert.equal(r.valid, false);
  assert.match(r.reason, /never agreed/);
  // A swapped mailbox.
  const other = c.walletFromPrivateKeyHex(ch.rand());
  assert.equal(c.readLink(msg.replace(`Mailbox: ${mailbox.address}`, `Mailbox: ${other.address}`), coin.address).valid, false);
  assert.equal(c.readLink('Hello', coin.address), null);
  throwsMsg(() => c.linkMessage(mailbox, mailbox.address), /mailbox itself/);
});

console.log(`\n${passed} chain signature tests passed`);
