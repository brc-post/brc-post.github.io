// BRC Seal page logic. All work happens here, in the browser; the page has no
// network access (see the Content-Security-Policy in index.html).

import * as vault from './vault-core.js';
import * as seal from './seal-core.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

// ---------------------------------------------------------------------------
// Small DOM helpers. User-supplied text is only ever set with textContent.
// ---------------------------------------------------------------------------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

function say(id, text, tone = 'info') {
  const m = $(id);
  m.textContent = text || '';
  if (text) m.dataset.tone = tone; else delete m.dataset.tone;
}

const ICONS = {
  good: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.7 2.7L16.5 9.5"/></svg>',
  bad: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4 2.8 19.5h18.4L12 4Z"/><path d="M12 10v4M12 17h.01"/></svg>',
};

function verdict(tone, title, ...body) {
  const head = el('div', { class: 'verdict-title' });
  head.innerHTML = ICONS[tone]; // fixed icon markup only, never user text
  head.append(el('span', { text: title }));
  return el('div', { class: 'verdict', 'data-tone': tone, role: 'status' }, head, ...body);
}

function kv(rows) {
  return el('dl', { class: 'kv' }, rows.map(([k, v]) => el('div', {}, el('dt', { text: k }), el('dd', {}, v))));
}

function addressNode(address) {
  const name = nameFor(address);
  return el('span', {}, el('span', { class: 'mono', text: address }), name ? el('span', { text: `  (${name})` }) : null);
}

// ---------------------------------------------------------------------------
// Wallet state. The private key lives only in memory and is wiped on forget.
// ---------------------------------------------------------------------------

let wallet = null;          // { privateKey, address }
let testWallets = null;     // { alice, bob } while trying the page out
let pendingBackup = null;   // a password-protected backup waiting for its password
let pendingConfirm = null;  // a key with no typo check, waiting for "this is my address"
let loadGen = 0;            // bumps on cancel/forget so a slow unlock can't load afterwards

function randomWallet() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  const w = vault.walletFromPrivateKeyHex(vault.bytesToHex(b));
  b.fill(0);
  return w;
}

function nameFor(address) {
  if (testWallets) {
    if (address === testWallets.alice.address) return 'test wallet Alice';
    if (address === testWallets.bob.address) return 'test wallet Bob';
  }
  if (wallet && !testWallets && address === wallet.address) return 'your loaded wallet';
  return '';
}

function forgetEverything() {
  if (testWallets) { vault.wipeWallet(testWallets.alice); vault.wipeWallet(testWallets.bob); }
  else if (wallet) vault.wipeWallet(wallet);
  wallet = null;
  testWallets = null;
  pendingBackup = null;
  if (pendingConfirm) vault.wipeWallet(pendingConfirm.wallet);
  pendingConfirm = null;
}

function renderWallet() {
  const card = $('#wallet');
  const title = $('#wallet-title');
  const sub = $('#wallet-sub');
  card.dataset.state = wallet ? 'loaded' : 'empty';
  $('#btn-forget').hidden = !wallet;
  $('#btn-test').hidden = !!testWallets;
  $('#btn-load').hidden = !!wallet && !testWallets;
  $('#who').hidden = !testWallets;
  $('#seal-quick').hidden = !testWallets;
  if (!wallet) {
    title.textContent = 'No wallet loaded';
    sub.textContent = 'You can check signatures and seal notes without one. Signing and opening need a wallet.';
  } else {
    title.textContent = testWallets ? `Acting as test wallet ${wallet === testWallets.alice ? 'Alice' : 'Bob'}` : 'Your wallet is loaded';
    sub.replaceChildren(el('span', { class: 'mono', text: wallet.address }));
  }
  for (const b of $$('#who button')) b.setAttribute('aria-pressed', String(!!testWallets && testWallets[b.dataset.who] === wallet));
  const canSign = !!wallet;
  const wrap = $('#seal-sign-wrap');
  $('#seal-sign').disabled = !canSign;
  if (!canSign) $('#seal-sign').checked = false;
  wrap.setAttribute('aria-disabled', String(!canSign));
  $('#seal-sign-label').textContent = canSign
    ? `Sign it so they know it's from me (${wallet.address.slice(0, 10)}…${wallet.address.slice(-4)}).`
    : "Sign it so they know it's from me. Load a wallet to use this.";
}

$('#btn-test').addEventListener('click', () => {
  forgetEverything();
  testWallets = { alice: randomWallet(), bob: randomWallet() };
  wallet = testWallets.alice;
  $('#loader').hidden = true;
  renderWallet();
});

for (const b of $$('#who button')) {
  b.addEventListener('click', () => {
    if (!testWallets) return;
    wallet = testWallets[b.dataset.who];
    renderWallet();
  });
}

$('#btn-forget').addEventListener('click', () => {
  forgetEverything();
  clearLoader();
  $('#loader').hidden = true;
  clearSecretsFromPage();
  renderWallet();
});

$('#btn-load').addEventListener('click', () => {
  $('#loader').hidden = false;
  $('#wallet-paste').focus();
});

$('#btn-load-cancel').addEventListener('click', () => {
  $('#loader').hidden = true;
  clearLoader();
});

function clearLoader() {
  loadGen++;
  $('#wallet-paste').value = '';
  $('#wallet-password').value = '';
  $('#wallet-file').value = '';
  $('#password-field').hidden = true;
  $('#confirm-field').hidden = true;
  $('#confirm-mine').checked = false;
  pendingBackup = null;
  if (pendingConfirm) vault.wipeWallet(pendingConfirm.wallet);
  pendingConfirm = null;
  say('#load-msg', '');
}

/** After forgetting a wallet, remove anything on screen that came from it. */
function clearSecretsFromPage() {
  $('#sign-out').hidden = true;
  $('#sign-block').textContent = '';
  $('#open-out').replaceChildren();
  say('#sign-msg', ''); say('#open-msg', '');
}

async function readWalletText(text) {
  say('#load-msg', '');
  const id = vault.identifyInput(text);
  if (id.kind === 'vault-backup' || id.kind === 'desktop-backup') {
    pendingBackup = id.backup;
    $('#password-field').hidden = false;
    $('#wallet-password').focus();
    say('#load-msg', 'Enter the backup password, then press Load wallet.', 'info');
    return null;
  }
  // A bare 64-character code could be a private key OR an address, and a key
  // or recovery words have no typo check. Show the address it gives and ask.
  if (id.kind === 'private-key' && (id.ambiguous || id.checked !== true)) {
    pendingConfirm = { wallet: id.wallet, ambiguous: !!id.ambiguous };
    $('#confirm-address').textContent = id.wallet.address;
    $('#confirm-ambiguous').hidden = !id.ambiguous;
    $('#confirm-field').hidden = false;
    $('#confirm-mine').checked = false;
    say('#load-msg', 'Check the address below, tick the box, then press Load wallet.', 'info');
    return null;
  }
  return { wallet: id.wallet };
}

function useWallet(w) {
  const keep = w;
  if (pendingConfirm && pendingConfirm.wallet === w) pendingConfirm = null; // hand over, don't wipe
  forgetEverything();
  wallet = keep;
  clearSecretsFromPage();
  clearLoader();
  $('#loader').hidden = true;
  renderWallet();
}

$('#btn-load-go').addEventListener('click', async () => {
  const btn = $('#btn-load-go');
  btn.disabled = true;
  const gen = loadGen;
  try {
    if (pendingConfirm) {
      if (!$('#confirm-mine').checked) { say('#load-msg', 'Tick the box to confirm this is your address, or press Cancel.', 'bad'); return; }
      useWallet(pendingConfirm.wallet);
      return;
    }
    if (pendingBackup) {
      const pw = $('#wallet-password').value;
      if (!pw) { say('#load-msg', 'Enter the backup password.', 'bad'); return; }
      say('#load-msg', 'Unlocking. This takes a few seconds…', 'info');
      const w = await vault.unlockAny(pendingBackup, pw);
      if (gen !== loadGen) { vault.wipeWallet(w); return; } // cancelled while unlocking
      useWallet(w);
      return;
    }
    const text = $('#wallet-paste').value;
    if (!text.trim()) { say('#load-msg', 'Choose your wallet file or paste it first.', 'bad'); return; }
    const r = await readWalletText(text);
    if (r) useWallet(r.wallet);
  } catch (e) {
    if (gen === loadGen) say('#load-msg', e.message, 'bad');
  } finally {
    btn.disabled = false;
  }
});

async function loadFile(file) {
  if (!file) return;
  if (file.size > vault.MAX_INPUT_LENGTH) { say('#load-msg', 'This file is far too large to be a wallet.', 'bad'); return; }
  try {
    const text = await file.text();
    $('#wallet-paste').value = '';
    const r = await readWalletText(text);
    if (r) useWallet(r.wallet);
  } catch (e) {
    say('#load-msg', e.message, 'bad');
  }
}

// Editing the pasted text starts over: a pending password or confirmation
// belonged to the old text.
$('#wallet-paste').addEventListener('input', () => {
  if (!pendingBackup && !pendingConfirm) return;
  const keep = $('#wallet-paste').value;
  clearLoader();
  $('#wallet-paste').value = keep;
});

$('#wallet-file').addEventListener('change', (e) => loadFile(e.target.files && e.target.files[0]));
const drop = $('#drop');
for (const ev of ['dragenter', 'dragover']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('is-over'); });
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, () => drop.classList.remove('is-over'));
drop.addEventListener('drop', (e) => { e.preventDefault(); loadFile(e.dataTransfer.files && e.dataTransfer.files[0]); });
$('#wallet-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#btn-load-go').click(); });

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

const TABS = ['sign', 'verify', 'seal', 'open'];

function showTab(name, focus = false) {
  for (const t of TABS) {
    const tab = $(`#tab-${t}`);
    const on = t === name;
    tab.setAttribute('aria-selected', String(on));
    tab.tabIndex = on ? 0 : -1;
    $(`#p-${t}`).hidden = !on;
    if (on && focus) tab.focus();
  }
}

for (const t of TABS) $(`#tab-${t}`).addEventListener('click', () => showTab(t));
$('.segmented').addEventListener('keydown', (e) => {
  const i = TABS.findIndex((t) => $(`#tab-${t}`).getAttribute('aria-selected') === 'true');
  if (e.key === 'ArrowRight') { e.preventDefault(); showTab(TABS[(i + 1) % TABS.length], true); }
  if (e.key === 'ArrowLeft') { e.preventDefault(); showTab(TABS[(i + TABS.length - 1) % TABS.length], true); }
});

// Links from BRC Pulse: #seal&to=<address> opens Seal with the address filled in.
function readHash() {
  let h = '';
  try { h = decodeURIComponent(location.hash.replace(/^#/, '')); } catch { return; }
  const to = h.match(/(?:^|&)to=([0-9a-fA-F]{64})(?:&|$)/);
  if (to) {
    $('#seal-to').value = to[1].toLowerCase();
    showTab('seal');
    say('#seal-msg', 'Address filled in from a link. Check it is the one you meant before sealing.', 'warn');
    return;
  }
  const tab = TABS.find((t) => h === t || h.startsWith(t + '&'));
  if (tab) showTab(tab);
}
window.addEventListener('hashchange', readHash);

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

const today = () => new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
const FILLS = {
  raffle: () => seal.raffleEntryText(100000),
  discord: () => `I'm ____ on the BrowserCoin Discord. Signed on ${today()}.`,
  pool: () => `This is my payout address for ____ pool. Signed on ${today()}.`,
};
for (const chip of $$('[data-fill]')) {
  chip.addEventListener('click', () => {
    $('#sign-text').value = FILLS[chip.dataset.fill]();
    updateSignCount();
    $('#sign-text').focus();
  });
}

function updateSignCount() {
  const n = seal.normalizeMessage($('#sign-text').value).length;
  const c = $('#sign-count');
  c.textContent = n ? `${n.toLocaleString('en-US')} / ${seal.MAX_SIGNED_CHARS.toLocaleString('en-US')}` : '';
  if (n > seal.MAX_SIGNED_CHARS) c.dataset.over = ''; else delete c.dataset.over;
}
$('#sign-text').addEventListener('input', updateSignCount);

$('#btn-sign').addEventListener('click', () => {
  $('#sign-out').hidden = true;
  if (!wallet) { say('#sign-msg', 'Load a wallet or use the test wallets first. Signing needs a private key.', 'bad'); return; }
  try {
    const s = seal.signMessage(wallet, $('#sign-text').value);
    $('#sign-block').textContent = s.armored;
    $('#sign-out').hidden = false;
    say('#sign-msg', '');
  } catch (e) {
    say('#sign-msg', e.message, 'bad');
  }
});

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

$('#btn-verify').addEventListener('click', () => {
  const out = $('#verify-out');
  out.replaceChildren();
  say('#verify-msg', '');
  const text = $('#verify-text').value;
  if (!text.trim()) { say('#verify-msg', 'Paste a signed message first.', 'bad'); return; }
  let v;
  try { v = seal.verifySigned(text); } catch (e) { say('#verify-msg', e.message, 'bad'); return; }
  if (v.valid && v.hidden) {
    out.append(verdict('warn', 'Valid signature, but the message has hidden characters',
      el('p', { text: 'It contains invisible or direction-changing characters, so it may not read the way it looks. Ask the signer for a plain version.' }),
      kv([['Signed by', addressNode(v.address)], ['Message', el('div', { class: 'message-box', text: v.message })]])));
  } else if (v.valid) {
    out.append(verdict('good', 'Valid signature',
      el('p', { text: 'This exact message was signed by the wallet that controls this address.' }),
      kv([['Signed by', addressNode(v.address)], ['Message', el('div', { class: 'message-box', text: v.message })]])));
  } else {
    out.append(verdict('bad', 'Not valid',
      el('p', { text: v.reason }),
      kv([['Claims to be', addressNode(v.address)]])));
  }
});

// ---------------------------------------------------------------------------
// Seal
// ---------------------------------------------------------------------------

for (const chip of $$('[data-to]')) {
  chip.addEventListener('click', () => {
    if (!testWallets) return;
    $('#seal-to').value = testWallets[chip.dataset.to].address;
  });
}

function updateSealCount() {
  const n = new TextEncoder().encode(seal.normalizeMessage($('#seal-text').value)).length;
  const c = $('#seal-count');
  c.textContent = n ? `${n.toLocaleString('en-US')} / ${seal.MAX_SEALED_BYTES.toLocaleString('en-US')} bytes` : '';
  if (n > seal.MAX_SEALED_BYTES) c.dataset.over = ''; else delete c.dataset.over;
}
$('#seal-text').addEventListener('input', updateSealCount);

$('#btn-seal').addEventListener('click', () => {
  $('#seal-out').hidden = true;
  say('#seal-msg', '');
  try {
    const signIt = $('#seal-sign').checked && !!wallet;
    const n = seal.sealNote($('#seal-to').value, $('#seal-text').value, signIt ? wallet : null);
    $('#seal-to').value = n.to;
    $('#seal-block').textContent = n.armored;
    const who = nameFor(n.to);
    $('#seal-out-title').textContent = `Sealed to ${n.to.slice(0, 10)}…${n.to.slice(-4)}${who ? ` (${who})` : ''}${n.signed ? ', signed by you' : ', anonymous'}.`;
    const len = $('#seal-len');
    if (n.length > seal.DISCORD_LIMIT) {
      len.dataset.tone = 'warn';
      len.textContent = `${n.length.toLocaleString('en-US')} characters: too long for one Discord message (limit 2,000). Shorten the note, or send the block as a .txt file.`;
    } else {
      len.dataset.tone = 'info';
      len.textContent = `${n.length.toLocaleString('en-US')} characters. Fits in one Discord message.`;
    }
    $('#seal-out').hidden = false;
  } catch (e) {
    say('#seal-msg', e.message, 'bad');
  }
});

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

$('#btn-open').addEventListener('click', () => {
  const out = $('#open-out');
  out.replaceChildren();
  say('#open-msg', '');
  const text = $('#open-text').value;
  if (!text.trim()) { say('#open-msg', 'Paste a sealed note first.', 'bad'); return; }
  if (!wallet) { say('#open-msg', 'Load the wallet this note was sealed to. Opening needs its private key.', 'bad'); return; }
  let o;
  try {
    o = seal.openNote(text, wallet);
  } catch (e) {
    let hint = '';
    try {
      const { to } = seal.parseSealed(text);
      const name = nameFor(to);
      if (testWallets && name) hint = ` It's for ${name.replace('test wallet ', '')}: switch to ${name.replace('test wallet ', '')} above.`;
    } catch { /* the original error says enough */ }
    say('#open-msg', e.message + hint, 'bad');
    return;
  }
  let fromRow;
  let tone = 'good';
  let title = 'Opened';
  let lede = 'Only your wallet could open this note.';
  if (!o.signed) {
    fromRow = el('span', { text: "Anonymous. The sender didn't sign it, so it could be from anyone." });
  } else if (o.signatureValid) {
    fromRow = el('span', {}, addressNode(o.from), el('span', { class: 'ok-text', text: '  signature checked' }));
  } else {
    tone = 'warn';
    title = "Opened, but the sender's signature is wrong";
    lede = "Don't trust who this note claims to be from.";
    fromRow = addressNode(o.from);
  }
  if (o.hidden && tone === 'good') {
    tone = 'warn';
    lede = 'Opened, but the note contains invisible or direction-changing characters, so it may not read the way it looks.';
  }
  out.append(verdict(tone, title, el('p', { text: lede }),
    kv([['From', fromRow], ['Note', el('div', { class: 'message-box', text: o.message })]])));
});

// ---------------------------------------------------------------------------
// Copy buttons, top bar
// ---------------------------------------------------------------------------

for (const b of $$('[data-copy]')) {
  b.addEventListener('click', async () => {
    const text = document.getElementById(b.dataset.copy).textContent;
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch {
      const r = document.createRange();
      r.selectNodeContents(document.getElementById(b.dataset.copy));
      const s = getSelection(); s.removeAllRanges(); s.addRange(r);
      ok = document.execCommand && document.execCommand('copy');
    }
    const was = b.textContent;
    b.textContent = ok ? 'Copied' : 'Select and copy';
    setTimeout(() => { b.textContent = was; }, 1600);
  });
}

const topbar = $('#topbar');
addEventListener('scroll', () => topbar.classList.toggle('is-scrolled', scrollY > 4), { passive: true });

renderWallet();
readHash();
