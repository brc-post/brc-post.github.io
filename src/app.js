// BRC Seal page logic. All work happens here, in the browser; the page has no
// network access (see the Content-Security-Policy in index.html).

import * as vault from './vault-core.js';
import * as seal from './seal-core.js';
import * as stamp from './stamp-core.js';
import * as drand from './drand-core.js';
import * as giveaway from './giveaway-core.js';
import * as chain from './chain-core.js';
import * as known from './known-core.js';
import { sha256 } from '@noble/hashes/sha2';

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
  good: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle class="check-ring" pathLength="1" cx="12" cy="12" r="9" transform="rotate(-90 12 12)"/><path class="check-draw" pathLength="1" d="m8 12.5 2.7 2.7L16.5 9.5"/></svg>',
  bad: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>',
  info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4 2.8 19.5h18.4L12 4Z"/><path d="M12 10v4M12 17h.01"/></svg>',
};

function verdict(tone, title, ...body) {
  const head = el('div', { class: 'verdict-title' });
  head.innerHTML = ICONS[tone]; // fixed icon markup only, never user text
  head.append(el('span', { text: title }));
  const v = el('div', { class: 'verdict', 'data-tone': tone, role: 'status' }, head, ...body);
  v.classList.add(tone === 'bad' ? 'anim-shake' : 'anim-in');
  return v;
}

/** Restart an entrance animation on an element that is being shown again. */
function play(node, ...classes) {
  const cls = classes.length ? classes : ['anim-in'];
  node.classList.remove(...cls);
  void node.offsetWidth; // reflow, so the animation runs again
  node.classList.add(...cls);
}

/** The small 3x3 address picture, the same in every BRC Works tool (known-core.js addressPicture). */
function paintIdenticon(node, address) {
  node.replaceChildren();
  if (!address) { node.classList.add('empty'); node.style.background = ''; return; }
  node.classList.remove('empty');
  for (const colour of known.addressPicture(address).colors) {
    const cell = document.createElement('i');
    cell.style.background = colour;
    node.append(cell);
  }
}

function kv(rows) {
  return el('dl', { class: 'kv' }, rows.map(([k, v]) => el('div', {}, el('dt', { text: k }), el('dd', {}, v))));
}

function addressNode(address) {
  const name = nameFor(address);
  const fake = lookalikeNote(address);
  return el('span', {}, el('span', { class: 'mono', text: address }), name ? el('span', { text: `  (${name})` }) : null,
    fake ? el('span', { class: 'bad-text lookalike', text: ` ${fake}` }) : null);
}

// ---------------------------------------------------------------------------
// Mailbox key state. BRC Seal holds only a mailbox key: a key made in BRC Vault
// for letters and signing, which never holds coins. Coin keys are refused
// outright (see readWalletText). The key lives only in memory and is wiped on forget.
// (The code calls it `wallet` because it is the same kind of Ed25519 key.)
// ---------------------------------------------------------------------------

let wallet = null;          // { privateKey, address }: the open mailbox key
let testWallets = null;     // { alice, bob } while trying the page out
let pendingBackup = null;   // a locked mailbox key waiting for its password
let loadGen = 0;            // bumps on cancel/forget so a slow unlock can't load afterwards

function randomWallet() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  const w = vault.walletFromPrivateKeyHex(vault.bytesToHex(b));
  b.fill(0);
  return w;
}

// Addresses BRC Seal recognises by name come from src/official.js (shared with BRC Pulse).
// An address that imitates one of them is refused for sealing and flagged everywhere else.
function lookalikeNote(address) {
  const o = known.lookalikeOf(address);
  return o ? `Careful: this address looks like the ${o.name} (${o.address.slice(0, 6)}…${o.address.slice(-6)}), but it isn't. Someone may be imitating it. Compare every character.` : '';
}

// Opened inside another page (a frame), or by another window: that page could watch the
// keyboard or rewire buttons, so real wallets aren't loaded here. Test wallets still work.
const EMBEDDED = (() => { try { return window.top !== window.self || !!window.opener; } catch { return true; } })();

function nameFor(address) {
  const o = known.officialFor(address);
  if (o) return o.name;
  if (testWallets) {
    if (address === testWallets.alice.address) return 'test key Alice';
    if (address === testWallets.bob.address) return 'test key Bob';
  }
  if (wallet && !testWallets && address === wallet.address) return 'your mailbox';
  return '';
}

function forgetEverything() {
  if (testWallets) { vault.wipeWallet(testWallets.alice); vault.wipeWallet(testWallets.bob); }
  else if (wallet) vault.wipeWallet(wallet);
  wallet = null;
  testWallets = null;
  pendingBackup = null;
}

const shortAddr = (a) => `${a.slice(0, 4)} ${a.slice(4, 8)} … ${a.slice(-8, -4)} ${a.slice(-4)}`;

function renderWallet() {
  const card = $('#wallet');
  const title = $('#wallet-title');
  const sub = $('#wallet-sub');
  card.dataset.state = wallet ? 'loaded' : 'empty';
  $('#btn-forget').hidden = !wallet;
  $('#btn-test').hidden = !!testWallets;
  $('#btn-load').hidden = !!wallet && !testWallets;
  $('#btn-link').hidden = !wallet;
  $('#btn-sheet-done').hidden = !wallet;
  $('#who').hidden = !testWallets;
  $('#seal-quick').hidden = !testWallets;
  $('#st-test-lock').hidden = !testWallets;
  $('#sign-quick').hidden = !testWallets;
  const testName = testWallets ? (wallet === testWallets.alice ? 'Alice' : 'Bob') : '';
  if (!wallet) {
    title.textContent = 'No mailbox key open';
    sub.textContent = 'You can sign on the chain, check and seal without one. Opening letters needs your mailbox key.';
  } else {
    title.textContent = testWallets ? `Acting as test key ${testName}` : 'Your mailbox key is open';
    sub.replaceChildren(el('span', { class: 'mono', text: wallet.address }));
  }
  // Every wallet chip on the page shows the same thing.
  for (const node of $$('[data-idc]')) paintIdenticon(node, wallet ? wallet.address : '');
  for (const node of $$('[data-wallet-name]')) node.textContent = !wallet ? 'No mailbox key' : testWallets ? `Test key ${testName}` : 'Your mailbox';
  for (const node of $$('[data-wallet-sub]')) {
    if (wallet) node.replaceChildren(el('span', { class: 'mono', text: shortAddr(wallet.address) }));
    else node.textContent = 'Needed to open letters';
  }
  for (const node of $$('[data-wallet-act]')) node.textContent = wallet ? 'Switch' : 'Open';
  for (const node of $$('[data-wallet-short]')) node.textContent = !wallet ? 'No key' : testWallets ? testName : `${wallet.address.slice(0, 4)}…${wallet.address.slice(-4)}`;
  for (const b of $$('#who button')) b.setAttribute('aria-pressed', String(!!testWallets && testWallets[b.dataset.who] === wallet));
  const canSign = !!wallet;
  const wrap = $('#seal-sign-wrap');
  $('#seal-sign').disabled = !canSign;
  if (!canSign) $('#seal-sign').checked = false;
  wrap.setAttribute('aria-disabled', String(!canSign));
  $('#seal-sign-label').textContent = canSign
    ? `Sign it with my mailbox key so they know it's from me (${wallet.address.slice(0, 10)}…${wallet.address.slice(-4)}).`
    : "Sign it so they know it's from me. Open your mailbox key to use this.";
}

/** A quick pulse on the wallet chips, so a change of wallet is noticed. */
function flashWallet() {
  for (const node of $$('.wallet-chip, .wallet-mini')) play(node, 'flash');
}

// ---------------------------------------------------------------------------
// Wallet sheet: slides up from the bottom on phones, a centred card on desktop.
// ---------------------------------------------------------------------------

const sheet = $('#wallet-sheet');
let sheetReturn = null;

function openSheet() {
  if (sheet.open) return;
  sheetReturn = document.activeElement;
  sheet.classList.remove('closing');
  sheet.showModal();
}

function closeSheet() {
  if (!sheet.open || sheet.classList.contains('closing')) return;
  const finish = () => {
    sheet.classList.remove('closing');
    sheet.close();
    if (sheetReturn && sheetReturn.isConnected) sheetReturn.focus({ preventScroll: true });
  };
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) { finish(); return; }
  sheet.classList.add('closing');
  sheet.addEventListener('animationend', finish, { once: true });
  setTimeout(() => { if (sheet.classList.contains('closing')) finish(); }, 400); // in case animationend never fires
}

for (const b of $$('[data-wallet]')) b.addEventListener('click', openSheet);
$('#btn-sheet-close').addEventListener('click', closeSheet);
$('#btn-sheet-done').addEventListener('click', closeSheet);
sheet.addEventListener('cancel', (e) => { e.preventDefault(); closeSheet(); });
// A tap on the dimmed backdrop closes it. The dialog box itself is the backdrop's hit target.
sheet.addEventListener('click', (e) => { if (e.target === sheet) closeSheet(); });

$('#btn-test').addEventListener('click', () => {
  forgetEverything();
  testWallets = { alice: randomWallet(), bob: randomWallet() };
  wallet = testWallets.alice;
  $('#loader').hidden = true;
  renderWallet();
  flashWallet();
});

for (const b of $$('#who button')) {
  b.addEventListener('click', () => {
    if (!testWallets) return;
    wallet = testWallets[b.dataset.who];
    renderWallet();
    flashWallet();
  });
}

$('#btn-forget').addEventListener('click', () => {
  forgetEverything();
  stopLinking();
  clearLoader();
  $('#loader').hidden = true;
  clearSecretsFromPage();
  renderWallet();
});

$('#btn-load').addEventListener('click', () => {
  if (EMBEDDED) { $('#frame-warning').hidden = false; play($('#frame-warning'), 'anim-shake'); return; }
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
  pendingBackup = null;
  say('#load-msg', '');
}

/** After forgetting a wallet, remove anything on screen that came from it. */
function clearSecretsFromPage() {
  $('#sign-out').hidden = true;
  $('#sign-block').textContent = '';
  $('#open-out').replaceChildren();
  say('#sign-msg', ''); say('#open-msg', '');
}

const NOT_A_MAILBOX_KEY = "This isn't a mailbox key. BRC Seal opens only mailbox keys made in BRC Vault: a brc-mailbox-key-….json file, or its BRCMBOX1 paper code.";
const COIN_KEY = "That's a key that can hold coins. BRC Seal never takes those: no wallet files, private keys or recovery words, so nobody can talk you into pasting one here. It wasn't kept. To prove a coin address, use Add my signature → My coin address. To open letters, use a mailbox key from BRC Vault.";
const COIN_BACKUP = "That's a BRC Vault backup of a coin wallet. BRC Seal never opens keys that can hold coins. Use a mailbox key: in BRC Vault, choose Make a new wallet, then Mailbox key for BRC Seal.";

/** Only a locked mailbox key gets through. Anything that can hold coins is refused and wiped. */
async function readWalletText(text) {
  say('#load-msg', '');
  if (EMBEDDED) throw new Error('BRC Seal is open inside another page, so real keys are turned off. Open it in its own tab.');
  // Look at the text before parsing anything: only something that names itself a mailbox key
  // gets parsed. A pasted coin key is refused here, without ever being turned into a key.
  const flat = String(text).replace(/[\u200B-\u200D\u2060\uFEFF\u00AD\s]/g, '').toUpperCase();
  const named = /["\u201C\u201D]TYPE["\u201C\u201D]:["\u201C\u201D]BRC-VAULT-MAILBOX-KEY["\u201C\u201D]/.test(flat);
  if (!named && !flat.startsWith('BRCMBOX1')) {
    $('#wallet-paste').value = '';
    if (/BRC-VAULT-BACKUP|^BRCVAULT1/.test(flat)) throw new Error(COIN_BACKUP);
    if (/BROWSERCOIN-WALLET|PRIVATEKEY|^BRCKEY1|^(0X)?[0-9A-F]{64}$/.test(flat) || /^\s*([a-z]+\s+){11,}[a-z]+\s*$/i.test(String(text))) throw new Error(COIN_KEY);
    throw new Error(NOT_A_MAILBOX_KEY);
  }
  let id;
  try { id = vault.identifyInput(text); } catch { throw new Error(NOT_A_MAILBOX_KEY); }
  if (id.kind === 'vault-backup' && id.backup.type === vault.MAILBOX_TYPE) {
    pendingBackup = id.backup;
    $('#password-field').hidden = false;
    $('#wallet-password').focus();
    say('#load-msg', 'Enter the password for this mailbox key, then press Open key.', 'info');
    return null;
  }
  if (id.wallet) vault.wipeWallet(id.wallet);
  $('#wallet-paste').value = '';
  throw new Error(id.kind === 'vault-backup' ? COIN_BACKUP : COIN_KEY);
}

function useWallet(w) {
  const keep = w;
  forgetEverything();
  wallet = keep;
  clearSecretsFromPage();
  clearLoader();
  $('#loader').hidden = true;
  renderWallet();
  flashWallet();
  closeSheet();
}

$('#btn-load-go').addEventListener('click', async () => {
  const btn = $('#btn-load-go');
  btn.disabled = true;
  const gen = loadGen;
  try {
    if (pendingBackup) {
      const pw = $('#wallet-password').value;
      if (!pw) { say('#load-msg', 'Enter the backup password.', 'bad'); return; }
      say('#load-msg', 'Unlocking. This takes a few seconds…', 'info');
      const w = await vault.unlockAny(pendingBackup, pw);
      if (gen !== loadGen) { vault.wipeWallet(w); return; } // cancelled while unlocking
      if (w.purpose !== 'mailbox') { vault.wipeWallet(w); throw new Error(COIN_BACKUP); }
      useWallet(w);
      return;
    }
    const text = $('#wallet-paste').value;
    if (!text.trim()) { say('#load-msg', 'Choose your mailbox key file or paste it first.', 'bad'); return; }
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
  if (file.size > vault.MAX_INPUT_LENGTH) { say('#load-msg', 'This file is far too large to be a mailbox key.', 'bad'); return; }
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
  if (!pendingBackup) return;
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
// Screens. Each one has its own #address, so the phone's back gesture works.
// ---------------------------------------------------------------------------

const SCREENS = { home: '#s-home', sign: '#p-sign', seal: '#p-seal', postmark: '#p-stamp', received: '#s-received', verify: '#p-verify', open: '#p-open', check: '#p-check', inbox: '#p-inbox' };
const PARENT = { sign: 'home', seal: 'home', postmark: 'home', received: 'home', verify: 'received', open: 'received', check: 'received', inbox: 'received' };
const ALIASES = { stamp: 'postmark', '': 'home' };
const depth = (name) => (name === 'home' ? 0 : PARENT[name] === 'home' ? 1 : 2);
let current = null;

function show(name) {
  if (!SCREENS[name]) name = 'home';
  const prev = current;
  if (prev === name) return;
  current = name;
  for (const [n, sel] of Object.entries(SCREENS)) $(sel).hidden = n !== name;
  const screen = $(SCREENS[name]);
  document.body.classList.remove('intro', 'returning');
  if (prev === null) {
    // First screen of the visit. On the home screen, the logo draws itself.
    if (name === 'home') { document.body.classList.add('intro'); $('#hero-mark').classList.add('play'); }
  } else {
    screen.classList.remove('enter-fwd', 'enter-back');
    void screen.offsetWidth;
    screen.classList.add(depth(name) >= depth(prev) ? 'enter-fwd' : 'enter-back');
    if (name === 'home') document.body.classList.add('returning');
    window.scrollTo(0, 0);
    // Move focus to the new screen's title, for keyboards and screen readers.
    const h = screen.querySelector('h2') || screen;
    h.focus({ preventScroll: true });
  }
  document.title = name === 'home' ? 'BRC Seal' : `${screen.querySelector('h2').textContent} · BRC Seal`;
}

// Inside an embedded viewer (for example a preview frame) the page may not be allowed to change its
// own address. Then Seal keeps its own back history instead of the browser's.
let canUseHistory = true;
const memoryBack = [];

/** Go to a screen, adding a history entry so Back (and the phone's back gesture) return here. */
function go(name) {
  if (current === name) return;
  if (canUseHistory) {
    try { history.pushState({ brcSeal: true }, '', '#' + name); readHash(); return; } catch { canUseHistory = false; }
  }
  memoryBack.push(current);
  show(name);
}

function goBack() {
  if (canUseHistory && history.state && history.state.brcSeal) { history.back(); return; }
  if (memoryBack.length) { show(memoryBack.pop()); return; }
  const parent = PARENT[current] || 'home';
  if (canUseHistory) {
    try { history.replaceState(null, '', '#' + parent); readHash(); return; } catch { canUseHistory = false; }
  }
  show(parent);
}

for (const b of $$('[data-back]')) b.addEventListener('click', goBack);
for (const a of $$('a[href^="#"]')) {
  a.addEventListener('click', (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button) return;
    e.preventDefault();
    go(a.dataset.go || a.getAttribute('href').slice(1) || 'home');
  });
}

// Routes, including links from BRC Pulse: #to=<address> opens Seal with the address filled in.
// A link like #to=<address> (from BRC Pulse) fills in the Seal address, but only when the page
// first opens, only into an empty box, and never inside another page. Later changes to the
// address bar are ignored, so another window can't quietly swap the address while you write.
let firstRoute = true;
function readHash() {
  const initial = firstRoute;
  firstRoute = false;
  let h = '';
  try { h = decodeURIComponent(location.hash.replace(/^#/, '')); } catch { show('home'); return; }
  const to = h.match(/(?:^|&)to=([0-9a-fA-F]{64})(?:&|$)/);
  if (to) {
    if (!initial) return;
    show('seal');
    try { history.replaceState(null, '', '#seal'); } catch { /* inside a viewer that can't change the address */ }
    if (EMBEDDED) { say('#seal-msg', 'A link tried to fill in the address, but BRC Seal is open inside another page, so it was ignored. Paste the address yourself.', 'warn'); return; }
    if (!$('#seal-to').value.trim()) $('#seal-to').value = to[1].toLowerCase();
    say('#seal-msg', 'Address filled in from a link. Check it is the one you meant before sealing.', 'warn');
    return;
  }
  const key = h.split('&')[0];
  show(ALIASES[key] ?? (SCREENS[key] ? key : 'home'));
}
window.addEventListener('hashchange', readHash);
window.addEventListener('popstate', readHash);

// ---------------------------------------------------------------------------
// I received something: paste it, and it goes to the right place.
// ---------------------------------------------------------------------------

function routePaste(text) {
  const t = text || '';
  if (!t.trim()) { say('#rx-msg', ''); return; }
  if (/BEGIN BRC SIGNED MESSAGE|BEGIN BRC CHAIN SIGNED MESSAGE/i.test(t)) {
    $('#verify-text').value = t;
    go('verify');
    $('#btn-verify').click();
  } else if (/BEGIN BRC SEALED NOTE/i.test(t)) {
    $('#open-text').value = t;
    go('open');
    if (wallet) $('#btn-open').click();
    else say('#open-msg', 'This is a sealed letter. Open the mailbox key it was sealed to, then press Open the letter.', 'info');
  } else if (/BEGIN BRC STAMP RECEIPT/i.test(t)) {
    $('#st-cmp-receipt').value = t;
    go('check');
    runCompare();
    if (!cmpFp) say('#st-cmp-msg', 'This is a postmark receipt. Choose the file it belongs to, to check they match.', 'info');
  } else {
    say('#rx-msg', "This doesn't look like something from BRC Seal. Copy the whole block, from -----BEGIN to -----END.", 'bad');
    return;
  }
  say('#rx-msg', '');
  $('#rx-text').value = '';
}
$('#rx-text').addEventListener('paste', () => setTimeout(() => routePaste($('#rx-text').value), 0));
let rxTimer = 0;
$('#rx-text').addEventListener('input', () => { clearTimeout(rxTimer); rxTimer = setTimeout(() => routePaste($('#rx-text').value), 700); });

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

const today = () => new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
const FILLS = {
  mine: () => `This address is mine. Signed on ${today()}.`,
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

// Who will see the signature: anyone (posted publicly), or one person (sealed to their address).
let signMode = 'public';
const PRIVACY = {
  public: ['Public and permanent. ', "Signing links this address to what you write, for good. Anyone can then look up its balance and payments. Use an address that holds little, or choose One person."],
  private: ['Only they can check it. ', 'Your signature is sealed inside a letter to their address and tied to them, so nobody else sees it or your address. They could still show others that you wrote it to them, so choose someone you trust.'],
};
function renderSignMode() {
  for (const b of $$('#sign-mode button')) b.setAttribute('aria-checked', String(b.dataset.mode === signMode));
  const note = $('#sign-privacy');
  note.dataset.mode = signMode;
  note.replaceChildren(el('strong', { text: PRIVACY[signMode][0] }), PRIVACY[signMode][1]);
  $('#sign-private').hidden = signMode !== 'private';
  $('#sign-out').hidden = true;
  say('#sign-msg', '');
  renderSignAs();
}
for (const b of $$('#sign-mode button')) b.addEventListener('click', () => { signMode = b.dataset.mode; renderSignMode(); });
$('#sign-mode').addEventListener('keydown', (e) => {
  if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
  e.preventDefault();
  signMode = signMode === 'public' ? 'private' : 'public';
  renderSignMode();
  $(`#sign-mode [data-mode="${signMode}"]`).focus();
});
for (const chip of $$('[data-sign-to]')) chip.addEventListener('click', () => { if (testWallets) $('#sign-to').value = testWallets[chip.dataset.signTo].address; });

// Sign as: my coin address (on the chain, no key here) or my mailbox (instant, mailbox key).
let signAs = 'chain';
let scSig = null;        // the chain signature waiting for its lock
let linking = null;      // { mailbox } while the message is a mailbox link
const AS_NOTE = {
  chain: ['No key needed here. ', 'You lock a tiny amount in the official app with a phrase made from your message. Your key signs that lock inside the app, and the chain becomes your signature. Check it on BRC Pulse once the lock is in a block.'],
  mailbox: ['Signed by your mailbox key. ', 'Instant, and no coins involved. It proves your mailbox wrote it; link your mailbox to your coin address once, on the chain, so people know whose mailbox it is.'],
};
function renderSignAs() {
  for (const b of $$('#sign-as button')) b.setAttribute('aria-checked', String(b.dataset.as === signAs));
  const note = $('#sign-as-note');
  note.dataset.mode = signAs;
  note.replaceChildren(el('strong', { text: AS_NOTE[signAs][0] }), AS_NOTE[signAs][1]);
  $('#sign-chain-part').hidden = signAs !== 'chain';
  $('#sign-mailbox-part').hidden = signAs !== 'mailbox';
  $('#btn-sign').textContent = signAs === 'chain' ? 'Make the phrase' : signMode === 'private' ? 'Sign and seal for them' : 'Sign with my mailbox key';
  resetChainSig();
}
function resetChainSig() {
  scSig = null;
  $('#sc-recipe').hidden = true;
  $('#sc-lockid').value = '';
  tidyScLockId();
  say('#sc-msg', '');
}
function setSignAs(as) {
  if (signAs === as) return;
  signAs = as;
  if (as !== 'chain') { stopLinking(); stopCommit(); }
  $('#sign-out').hidden = true;
  say('#sign-msg', '');
  renderSignAs();
}
for (const b of $$('#sign-as button')) b.addEventListener('click', () => setSignAs(b.dataset.as));
$('#sign-as').addEventListener('keydown', (e) => {
  if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
  e.preventDefault();
  setSignAs(signAs === 'chain' ? 'mailbox' : 'chain');
  $(`#sign-as [data-as="${signAs}"]`).focus();
});
for (const id of ['#sc-address', '#sign-text']) $(id).addEventListener('input', () => { if (scSig) { resetChainSig(); $('#sign-out').hidden = true; } });

function tidyScLockId() {
  const box = $('#sc-lockid'), out = $('#sc-lockid-status');
  const raw = box.value;
  const found = raw.replace(/\s+/g, '').match(/(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])/);
  if (found && found[1].toLowerCase() !== raw) box.value = found[1].toLowerCase();
  delete out.dataset.over; delete out.dataset.good;
  const v = box.value.trim();
  if (!v) out.textContent = 'optional';
  else if (/^[0-9a-f]{64}$/.test(v)) { out.textContent = 'looks right'; out.dataset.good = ''; }
  else { out.textContent = 'not a Lock ID'; out.dataset.over = ''; }
}
$('#sc-lockid').addEventListener('input', () => { tidyScLockId(); $('#sign-out').hidden = true; });

// Linking a mailbox: the message is fixed, already signed by the mailbox key.
function startLinking() {
  if (!wallet) return;
  stopCommit();
  linking = { mailbox: wallet.address };
  closeSheet();
  go('sign');
  signAs = 'chain';
  renderSignAs();
  $('#sc-link-note').hidden = false;
  $('#sc-link-mailbox').textContent = `${wallet.address.slice(0, 10)}…${wallet.address.slice(-4)}`;
  $('#sign-text').value = '';
  $('#sign-text').readOnly = true;
  $('#sign-text').placeholder = 'Enter your coin address above. The link message appears here.';
  $('#sign-fills').hidden = true;
  updateLinkText();
  $('#sc-address').focus();
}
function updateLinkText() {
  if (!linking) return;
  const a = $('#sc-address').value.trim();
  let text = '';
  try { if (a && wallet && wallet.address === linking.mailbox) text = chain.linkMessage(wallet, a); } catch { /* shown when making the phrase */ }
  $('#sign-text').value = text;
  updateSignCount();
}
function stopLinking() {
  if (!linking) return;
  linking = null;
  $('#sc-link-note').hidden = true;
  $('#sign-text').readOnly = false;
  $('#sign-text').value = '';
  $('#sign-text').placeholder = "I'm pb-hash on Discord. Today is Oct 31, 2026.";
  $('#sign-fills').hidden = false;
  updateSignCount();
}
$('#sc-address').addEventListener('input', updateLinkText);
$('#btn-sc-unlink').addEventListener('click', () => { stopLinking(); resetChainSig(); $('#sign-text').focus(); });
$('#btn-link').addEventListener('click', startLinking);

// Fixing the giveaway list before the draw: the message is fixed and read-only.
let committing = null;
function startCommit(message) {
  stopLinking();
  committing = message;
  go('sign');
  signAs = 'chain';
  renderSignAs();
  $('#sc-commit-note').hidden = false;
  $('#sign-text').value = message;
  $('#sign-text').readOnly = true;
  $('#sign-fills').hidden = true;
  updateSignCount();
  $('#sc-address').focus();
}
function stopCommit() {
  if (!committing) return;
  committing = null;
  $('#sc-commit-note').hidden = true;
  $('#sign-text').readOnly = false;
  $('#sign-text').value = '';
  $('#sign-fills').hidden = false;
  updateSignCount();
}
$('#btn-sc-uncommit').addEventListener('click', () => { stopCommit(); resetChainSig(); $('#sign-text').focus(); });

renderSignMode();

$('#btn-sign').addEventListener('click', () => {
  $('#sign-out').hidden = true;
  $('#sign-pulse').hidden = true;
  if (signAs === 'chain') { makeChainPhrase(); return; }
  if (!wallet) { say('#sign-msg', 'Open your mailbox key, or use the test keys, first. Or sign as your coin address, on the chain.', 'bad'); openSheet(); return; }
  try {
    const s = seal.signMessage(wallet, $('#sign-text').value);
    if (signMode === 'private') {
      if (!$('#sign-to').value.trim()) throw new Error('Paste the address of the person who will check it.');
      // A signed letter: the signature covers the recipient and this one letter, so it can't be
      // re-sealed to anyone else or passed off as written to someone else.
      const n = seal.sealNote($('#sign-to').value, s.message, wallet);
      if (n.to === wallet.address) throw new Error("That's your own address. Paste the address of the person who will check it.");
      $('#sign-to').value = n.to;
      const who = nameFor(n.to);
      $('#sign-block').textContent = n.armored;
      $('#sign-out-title').textContent = `Signed and sealed for ${who ? who.replace('test key ', '') : `${n.to.slice(0, 6)}…${n.to.slice(-4)}`}`;
      $('#sign-out-sub').textContent = 'Send this whole block. Only they can open it and check your signature.';
      $('#btn-sign-copy').querySelector('.lbl').textContent = $('#btn-sign-copy').dataset.label = 'Copy the sealed letter';
    } else {
      $('#sign-block').textContent = s.armored;
      $('#sign-out-title').textContent = 'Signed by your mailbox';
      $('#sign-out-sub').textContent = 'Share this whole block. Anyone can check it.';
      $('#btn-sign-copy').querySelector('.lbl').textContent = $('#btn-sign-copy').dataset.label = 'Copy the signed message';
    }
    $('#sign-out').hidden = false;
    play($('#sign-out'));
    say('#sign-msg', '');
  } catch (e) {
    say('#sign-msg', e.message, 'bad');
  }
});

function makeChainPhrase() {
  resetChainSig();
  say('#sign-msg', '');
  try {
    if (linking && (!wallet || wallet.address !== linking.mailbox)) throw new Error('Your mailbox key was closed. Open it again to link it.');
    if (linking) updateLinkText();
    const cs = chain.newChainSignature({ address: $('#sc-address').value, text: $('#sign-text').value });
    $('#sc-address').value = cs.address;
    scSig = cs;
    $('#sc-amount').textContent = stamp.SUGGESTED_AMOUNT;
    $('#sc-owner-copy').textContent = cs.address;
    $('#sc-phrase').textContent = chain.chainPhrase(cs);
    const scriptHex = chain.chainScriptHex(cs);
    // The app's preview prints each push as "PUSH(32) <first 20 hex>…" (src/chain/scriptDisasm.ts).
    $('#sc-check').textContent = `PUSH(32) ${scriptHex.slice(4, 24)}…`;
    $('#sc-check-owner').textContent = `PUSH(32) ${cs.address.slice(0, 20)}…`;
    $('#sc-recipe').hidden = false;
    play($('#sc-recipe'));
    $('#sc-recipe').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  } catch (e) {
    say('#sign-msg', e.message, 'bad');
    play($('#sign-msg'), 'anim-shake');
  }
}

$('#btn-sc-done').addEventListener('click', () => {
  say('#sc-msg', '');
  if (!scSig) return;
  try {
    const text = chain.chainSignedText(scSig, { lockId: $('#sc-lockid').value.trim() || null });
    $('#sign-block').textContent = text;
    $('#sign-out-title').textContent = linking ? 'Mailbox link signed on the chain' : committing ? 'Giveaway list signed on the chain' : 'Signed on the chain';
    $('#sign-out-sub').textContent = linking
      ? 'Share this link with anyone who should write to you: BRC Seal seals letters to your mailbox from it. Anyone can check it on BRC Pulse → Stamps once the lock is in a block.'
      : 'Share this whole block. Anyone can check it on BRC Pulse → Stamps once the lock is in a block, usually within a few minutes.';
    $('#btn-sign-copy').querySelector('.lbl').textContent = $('#btn-sign-copy').dataset.label = linking ? 'Copy the mailbox link' : 'Copy the signed message';
    $('#sign-pulse').hidden = false;
    $('#sign-out').hidden = false;
    play($('#sign-out'));
    $('#sign-out').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  } catch (e) {
    say('#sc-msg', e.message, 'bad');
  }
});

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

const PULSE_STAMPS = 'https://pb-hash.github.io/brc-pulse/#stamp';

/** A chain-signed message: everything that can be checked offline, and where to check the rest. */
function showChainSigned(text, out) {
  let p;
  try { p = chain.parseChainSigned(text); } catch (e) { say('#verify-msg', e.message, 'bad'); play($('#verify-msg'), 'anim-shake'); return; }
  const where = el('p', {}, 'BRC Seal works offline, so it can\'t look at the chain. To finish the check, paste this block into ',
    el('a', { href: PULSE_STAMPS, target: '_blank', rel: 'noopener noreferrer', text: 'BRC Pulse → Stamps' }), ', which finds the lock and checks your address made it.');
  const rows = [['Claims to be signed by', addressNode(p.address)], ['Message', el('div', { class: 'message-box', text: p.message })]];
  if (p.lockId) rows.push(['Lock ID', el('span', { class: 'mono', text: `${p.lockId.slice(0, 16)}…` })]);
  if (p.link && !p.link.valid) {
    out.append(verdict('bad', 'Not a valid mailbox link', el('p', { text: p.link.reason }), kv([['Claims to be', addressNode(p.address)]])));
    return;
  }
  if (p.link) {
    out.append(verdict('warn', "A mailbox link: only the mailbox's side is checked here", el('p', { text: 'The mailbox key\'s own signature checks out. Whether the coin address really made this link is not checked yet: anyone can write this block for any coin address. Until BRC Pulse finds the coin address\'s own lock, treat it as a claim.' }), where,
      kv([['Coin address', addressNode(p.link.coin)], ['Mailbox', addressNode(p.link.mailbox)]])));
    return;
  }
  out.append(verdict('warn', 'Not checked yet: it needs BRC Pulse',
    el('p', { text: 'Anyone can write a block like this for any address. It only counts once BRC Pulse finds the lock and confirms that address made it.' }),
    p.hidden ? el('p', { text: 'It also contains invisible or direction-changing characters, so it may not read the way it looks.' }) : null, where, kv(rows)));
}

$('#btn-verify').addEventListener('click', () => {
  const out = $('#verify-out');
  out.replaceChildren();
  say('#verify-msg', '');
  const text = $('#verify-text').value;
  if (!text.trim()) { say('#verify-msg', 'Paste a signed message first.', 'bad'); return; }
  if (chain.looksChainSigned(text)) { showChainSigned(text, out); return; }
  let v;
  try { v = seal.verifySigned(text); } catch (e) { say('#verify-msg', e.message, 'bad'); play($('#verify-msg'), 'anim-shake'); return; }
  if (v.valid && v.hidden) {
    out.append(verdict('warn', 'Valid signature, but the message has hidden characters',
      el('p', { text: 'It contains invisible or direction-changing characters, so it may not read the way it looks. Ask the signer for a plain version.' }),
      kv([['Signed by', addressNode(v.address)], ['Message', el('div', { class: 'message-box', text: v.message })]])));
  } else if (v.valid) {
    out.append(verdict('good', 'Valid signature',
      el('p', { text: 'This exact message was signed by the key that controls this address. It is usually a mailbox: check for a mailbox link to see whose.' }),
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

/** The seal-to box takes an address or a pasted mailbox link. Returns the address to seal to. */
function readSealTo() {
  const raw = $('#seal-to').value;
  if (!chain.looksChainSigned(raw)) {
    let a = null;
    try { a = seal.parseAddress(raw); } catch { /* sealing explains a bad address */ }
    const fake = a ? lookalikeNote(a) : '';
    if (fake) throw new Error(fake);
    const o = a ? known.officialFor(a) : null;
    $('#seal-link-ok-wrap').hidden = true;
    say('#seal-to-note', o ? `Sealing to the ${o.name}.` : a ? "Is this their mailbox? A coin address's key stays in the official app, which can't open letters. If you have their mailbox link, paste that instead." : '', 'info');
    return raw;
  }
  const p = chain.parseChainSigned(raw);
  if (!p.link) throw new Error("That's a message signed on the chain, not a mailbox link. Paste their mailbox link, or their mailbox address.");
  if (!p.link.valid) throw new Error(`That mailbox link isn't valid. ${p.link.reason}`);
  const fake = lookalikeNote(p.link.mailbox) || lookalikeNote(p.link.coin);
  if (fake) throw new Error(fake);
  $('#seal-link-ok-wrap').hidden = false;
  say('#seal-to-note', `A link to the mailbox of coin address ${p.link.coin.slice(0, 10)}…${p.link.coin.slice(-4)}. Only the mailbox's side can be checked here. Check the link on BRC Pulse → Stamps first: anyone can write a link that names someone else's coin address.`, 'warn');
  return p.link.mailbox;
}
$('#seal-to').addEventListener('input', () => { $('#seal-link-ok').checked = false; try { readSealTo(); } catch (e) { $('#seal-link-ok-wrap').hidden = true; say('#seal-to-note', e.message, 'bad'); } });

$('#btn-seal').addEventListener('click', () => {
  $('#seal-out').hidden = true;
  say('#seal-msg', '');
  try {
    const signIt = $('#seal-sign').checked && !!wallet;
    const to = readSealTo();
    if (chain.looksChainSigned($('#seal-to').value) && !$('#seal-link-ok').checked) throw new Error('Check the mailbox link on BRC Pulse → Stamps first, then tick the box. An unchecked link could send this letter to someone pretending to be them.');
    const n = seal.sealNote(to, $('#seal-text').value, signIt ? wallet : null);
    if (!chain.looksChainSigned($('#seal-to').value)) $('#seal-to').value = n.to;
    $('#seal-block').textContent = n.armored;
    const who = nameFor(n.to);
    $('#seal-out-title').textContent = `Sealed to ${who ? who.replace('test key ', '') : `${n.to.slice(0, 6)}…${n.to.slice(-4)}`}${n.signed ? ', signed by your mailbox' : ', anonymous'}`;
    const len = $('#seal-len');
    if (n.length > seal.DISCORD_LIMIT) {
      len.dataset.tone = 'warn';
      len.textContent = `${n.length.toLocaleString('en-US')} characters: too long for one Discord message (limit 2,000). Shorten the letter, or send the block as a .txt file.`;
    } else {
      len.dataset.tone = 'info';
      len.textContent = `${n.length.toLocaleString('en-US')} characters. Fits in one Discord message.`;
    }
    $('#seal-out').hidden = false;
    play($('#seal-out'), 'anim-in', 'play');
  } catch (e) {
    say('#seal-msg', e.message, 'bad');
    play($('#seal-msg'), 'anim-shake');
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
  if (!text.trim()) { say('#open-msg', 'Paste a sealed letter first.', 'bad'); return; }
  if (!wallet) { say('#open-msg', 'Open the mailbox key this letter was sealed to. Opening needs it.', 'bad'); openSheet(); return; }
  let o;
  try {
    o = seal.openNote(text, wallet);
  } catch (e) {
    let hint = '';
    try {
      const { to } = seal.parseSealed(text);
      const name = nameFor(to);
      if (testWallets && name) hint = ` It's for ${name.replace('test key ', '')}: switch to ${name.replace('test key ', '')} in your mailbox key (top right).`;
    } catch { /* the original error says enough */ }
    say('#open-msg', e.message + hint, 'bad');
    play($('#open-msg'), 'anim-shake');
    return;
  }
  let fromRow;
  let tone = 'good';
  let title = 'Opened';
  let lede = 'Only your mailbox key could open this letter.';
  if (!o.signed) {
    fromRow = el('span', { text: "Anonymous. The sender didn't sign it, so it could be from anyone." });
  } else if (o.signatureValid) {
    fromRow = el('span', {}, addressNode(o.from), el('span', { class: 'ok-text', text: '  signature checked' }));
  } else {
    tone = 'warn';
    title = "Opened, but the sender's signature is wrong";
    lede = "Don't trust who this letter claims to be from.";
    fromRow = addressNode(o.from);
  }
  if (o.hidden && tone === 'good') {
    tone = 'warn';
    lede = 'Opened, but the letter contains invisible or direction-changing characters, so it may not read the way it looks.';
  }
  let rows = [['From', fromRow], ['Letter', el('div', { class: 'message-box', text: o.message })]];
  // Someone may have pasted a signed message into the letter. Signed messages are public and
  // can be copied, so show exactly which words are signed, and flag any words that aren't.
  const sb = o.message.indexOf('-----BEGIN BRC SIGNED MESSAGE-----');
  const se = o.message.indexOf('-----END BRC SIGNATURE-----');
  if (sb >= 0) {
    let inner;
    try { inner = seal.verifySigned(o.message); } catch (e) { inner = { valid: false, reason: e.message }; }
    const outside = se > sb ? (o.message.slice(0, sb) + '\n' + o.message.slice(se + '-----END BRC SIGNATURE-----'.length)).trim() : '';
    rows = [['From', fromRow]];
    if (inner.valid) {
      rows.push(['Signed by', el('span', {}, addressNode(inner.address), el('span', { class: 'ok-text', text: '  signature checked' }))]);
      rows.push(['Signed text', el('div', { class: 'signed-box', text: inner.message })]);
      rows.push(['Note', el('span', { text: "This signed message could have been copied from anywhere. It proves who wrote those words, not who sealed this letter or who it was meant for." })]);
    } else {
      rows.push(['Signature', el('span', { class: 'bad-text', text: `Not valid. ${inner.reason}` })]);
      rows.push(['Letter', el('div', { class: 'message-box', text: o.message })]);
      if (tone === 'good') tone = 'warn';
    }
    if (inner.valid && outside) {
      rows.push(['Not signed', el('div', { class: 'unsigned-box', text: outside })]);
      tone = 'warn';
      title = 'Opened, but part of it is not signed';
      lede = 'Only the signed text below is vouched for. The words in the red box were added by whoever sealed the letter, and could be from anyone.';
    }
  }
  if (chain.looksChainSigned(o.message)) {
    rows.push(['Careful', el('span', { class: 'bad-text', text: 'This letter contains a block "signed on the chain". It is not checked here: paste that block into BRC Pulse → Stamps before trusting it.' })]);
    if (tone === 'good') tone = 'warn';
  }
  out.append(verdict(tone, title, el('p', { text: lede }), kv(rows)));
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
    const lbl = b.querySelector('.lbl') || b;
    if (!b.dataset.label) b.dataset.label = lbl.textContent;
    clearTimeout(b._copyTimer);
    lbl.textContent = ok ? 'Copied' : 'Select and copy';
    if (ok) b.dataset.copied = ''; else delete b.dataset.copied;
    b._copyTimer = setTimeout(() => { lbl.textContent = b.dataset.label; delete b.dataset.copied; }, 1600);
  });
}

const topbar = $('#topbar');
addEventListener('scroll', () => topbar.classList.toggle('is-scrolled', scrollY > 4), { passive: true });

// ---------------------------------------------------------------------------
// Stamp
// ---------------------------------------------------------------------------

let stFile = null;      // { name, size, fingerprint }
let stStamp = null;     // the stamp made from it

/** SHA-256 of a file, read in 4 MB pieces so large files don't need to fit in memory at once. */
async function hashFile(file, onProgress) {
  const h = sha256.create();
  const CHUNK = 4 * 1024 * 1024;
  for (let off = 0; off < file.size; off += CHUNK) {
    h.update(new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer()));
    if (onProgress) onProgress(Math.min(1, (off + CHUNK) / file.size));
  }
  return vault.bytesToHex(h.digest());
}

const fmtBytes = (n) => n === 1 ? '1 byte' : n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const extOf = (name) => { const m = /\.([A-Za-z0-9]{1,5})$/.exec(name || ''); return m ? m[1].toUpperCase() : 'FILE'; };

/** Show reading progress along the bottom of a drop zone. */
function dropState(drop, state, p = 0) {
  if (state) drop.dataset.state = state; else delete drop.dataset.state;
  drop.style.setProperty('--p', String(p));
}

function resetStampFrom(step) {
  if (step <= 2) { stStamp = null; $('#st-recipe').hidden = true; delete $('#st-step2').dataset.done; say('#st-make-msg', ''); }
  if (step <= 3) { $('#st-receipt-out').hidden = true; delete $('#st-step3').dataset.done; say('#st-receipt-msg', ''); }
}

let stReadGen = 0;
$('#st-file').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  const gen = ++stReadGen;
  resetStampFrom(2);
  stFile = null;
  delete $('#st-step1').dataset.done;
  const drop = $('#st-drop');
  if (!file) { dropState(drop, ''); return; }
  if (file.size > 2 * 1024 ** 3) { dropState(drop, ''); $('#st-file-title').textContent = file.name; $('#st-file-sub').textContent = 'Files over 2 GB are too large to postmark here.'; return; }
  $('#st-file-title').textContent = file.name;
  $('#st-file-sub').textContent = 'Reading…';
  dropState(drop, 'reading', 0);
  try {
    const fp = await hashFile(file, (f) => { if (gen === stReadGen) { $('#st-file-sub').textContent = `Reading… ${Math.round(f * 100)}%`; dropState(drop, 'reading', f); } });
    if (gen !== stReadGen) return; // another file was chosen meanwhile
    stFile = { name: file.name, size: file.size, fingerprint: fp };
    $('#st-file-sub').textContent = `${fmtBytes(file.size)} · fingerprint ${fp.slice(0, 16)}…`;
    $('#st-file-icon').textContent = extOf(file.name);
    dropState(drop, 'done', 1);
    $('#st-step1').dataset.done = '';
  } catch {
    if (gen !== stReadGen) return;
    dropState(drop, '');
    $('#st-file-sub').textContent = 'This file could not be read. Try again.';
  }
});

for (const id of ['#st-owner', '#st-after-height', '#st-after-hash', '#st-drand']) $(id).addEventListener('input', () => resetStampFrom(2));
const utcTime = (ts) => new Date(ts * 1000).toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'medium' }) + ' UTC';
const localTime = (ts) => new Date(ts * 1000).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short' });
const localDate = (ts) => new Date(ts * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
// Check a pasted drand beacon right away, offline, so a bad paste is caught before stamping.
$('#st-drand').addEventListener('input', () => {
  const v = $('#st-drand').value.trim(), out = $('#st-drand-status');
  delete out.dataset.over;
  delete out.dataset.good;
  if (!v) { out.textContent = ''; return; }
  try {
    const b = drand.parseDrand(v), age = Date.now() / 1000 - drand.drandRoundTime(b.round);
    out.textContent = `checked: round ${b.round.toLocaleString('en-US')}, ${utcTime(drand.drandRoundTime(b.round))}`;
    out.dataset.good = '';
    // An old beacon still works, but only proves "after" that older moment.
    if (age > 15 * 60) { out.textContent += `: ${Math.round(age / 60).toLocaleString('en-US')} minutes old, copy a fresh one for a tighter proof`; out.dataset.over = ''; delete out.dataset.good; }
  }
  catch { out.textContent = 'not a valid beacon'; out.dataset.over = ''; }
});
// BRC Pulse's "Copy both" gives "92510 <block id>": split it into the two boxes.
$('#st-after-height').addEventListener('input', () => {
  const m = $('#st-after-height').value.trim().match(/^(\d[\d,]*)\s+([0-9a-fA-F]{64})$/);
  if (m) { $('#st-after-height').value = m[1]; $('#st-after-hash').value = m[2].toLowerCase(); }
});
/** Pull the 64-character Lock ID out of whatever was pasted ("Lock ID: ab12…", spaces, line breaks). */
function tidyLockId() {
  const box = $('#st-lockid'), out = $('#st-lockid-status');
  const raw = box.value;
  const found = raw.replace(/\s+/g, '').match(/(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])/);
  if (found && found[1].toLowerCase() !== raw) box.value = found[1].toLowerCase();
  delete out.dataset.over; delete out.dataset.good;
  const v = box.value.trim();
  if (!v) out.textContent = 'optional';
  else if (/^[0-9a-f]{64}$/.test(v)) { out.textContent = 'looks right'; out.dataset.good = ''; }
  else { const n = (v.match(/[0-9a-fA-F]/g) || []).length; out.textContent = n < 64 ? `${n} of 64 characters, part is missing` : 'not a Lock ID'; out.dataset.over = ''; }
}
$('#st-lockid').addEventListener('input', () => { tidyLockId(); resetStampFrom(3); });
$('#btn-st-paste').addEventListener('click', async () => {
  try {
    $('#st-lockid').value = await navigator.clipboard.readText();
    tidyLockId(); resetStampFrom(3);
  } catch {
    // Some browsers only paste from a long-press in the box itself.
    $('#st-lockid').focus();
    const out = $('#st-lockid-status'); out.textContent = 'tap and hold in the box, then Paste'; delete out.dataset.good;
  }
});
$('#btn-st-testlock').addEventListener('click', () => {
  const b = new Uint8Array(32); crypto.getRandomValues(b);
  $('#st-lockid').value = vault.bytesToHex(b);
  tidyLockId(); resetStampFrom(3);
});

$('#btn-st-make').addEventListener('click', () => {
  resetStampFrom(2);
  if (!stFile) { say('#st-make-msg', 'Choose a file first.', 'bad'); play($('#st-make-msg'), 'anim-shake'); return; }
  try {
    const h = $('#st-after-height').value.trim();
    const x = $('#st-after-hash').value.trim();
    if (!!h !== !!x) throw new Error('For "after a recent block", fill in both the block number and its ID, or leave both empty.');
    const dv = $('#st-drand').value.trim();
    stStamp = stamp.newStamp({ fingerprint: stFile.fingerprint, owner: $('#st-owner').value, after: h ? { height: h, hash: x } : null, drand: dv ? drand.parseDrand(dv) : null });
    $('#st-owner').value = stStamp.owner;
    $('#st-amount').textContent = stamp.SUGGESTED_AMOUNT;
    $('#st-owner-copy').textContent = stStamp.owner;
    $('#st-phrase').textContent = stamp.stampPhrase(stStamp);
    const scriptHex = stamp.stampScriptHex(stStamp);
    // The app's preview prints the hash line as "PUSH(32) <first 20 hex>…" (src/chain/scriptDisasm.ts).
    $('#st-check').textContent = `PUSH(32) ${scriptHex.slice(4, 24)}…`;
    $('#st-check-owner').textContent = `PUSH(32) ${stStamp.owner.slice(0, 20)}…`;
    $('#st-recipe').hidden = false;
    play($('#st-recipe'));
    $('#st-step2').dataset.done = '';
  } catch (e) {
    say('#st-make-msg', e.message, 'bad');
    play($('#st-make-msg'), 'anim-shake');
  }
});

/** The postmark card: what the receipt proves now, and what BRC Pulse will add once the lock is in a block. */
function renderPostmark(st, file) {
  $('#pm-ext').textContent = extOf(file.name);
  $('#pm-name').textContent = file.name;
  $('#pm-size').textContent = `${fmtBytes(file.size)} · stayed on your device`;
  const t = stamp.stampDrandTime(st);
  const pm = $('#pm');
  if (t) {
    // A drand beacon is a checked lower bound: the postmark was made after this moment.
    const d = new Date(t * 1000);
    delete pm.dataset.pending;
    $('#pm-day').textContent = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }).toUpperCase();
    $('#pm-year').textContent = String(d.getFullYear());
    $('#pm-line').textContent = `AFTER ${d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
    $('#pm-after').replaceChildren(document.createTextNode(localTime(t)), el('small', { text: `${localDate(t)}, to the second (drand)` }));
  } else {
    // Without a beacon, the date comes only from the block, which BRC Pulse reads.
    const now = new Date();
    pm.dataset.pending = '';
    $('#pm-day').textContent = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }).toUpperCase();
    $('#pm-year').textContent = String(now.getFullYear());
    $('#pm-line').textContent = 'AWAITING BLOCK';
    $('#pm-after').replaceChildren(st.after
      ? document.createTextNode(`Block ${Number(st.after.height).toLocaleString('en-US')}`)
      : el('span', { text: 'Not recorded' }), el('small', { text: st.after ? 'checked on BRC Pulse' : 'add a drand beacon to record this' }));
  }
  $('#pm-title').textContent = 'Posted';
  $('#pm-sub').textContent = 'Your receipt is ready. The date is set by the block your lock lands in.';
  $('#pm-by').replaceChildren(document.createTextNode('The lock’s block'), el('small', { text: 'shown on BRC Pulse, usually within minutes' }));
  const who = nameFor(st.owner);
  $('#pm-from').replaceChildren(document.createTextNode(who || 'Your address'),
    el('small', { class: 'mono', text: `${st.owner.slice(0, 6)}…${st.owner.slice(-4)}` }));
}

/** Bring the card into view first, then stamp it, so the postmark lands where it can be seen. */
function revealPostmark() {
  const card = $('#pm-card');
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  card.classList.remove('anim-in');
  card.classList.add('pm-wait');
  $('#st-receipt-out').scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'start' });
  setTimeout(() => { card.classList.remove('pm-wait'); play(card); }, calm ? 0 : 420);
}

let stReceipt = '';
$('#btn-st-receipt').addEventListener('click', () => {
  resetStampFrom(3);
  if (!stStamp) { say('#st-receipt-msg', 'Make the postmark phrase first (step 2).', 'bad'); play($('#st-receipt-msg'), 'anim-shake'); return; }
  try {
    stReceipt = stamp.receiptText(stStamp, { lockId: $('#st-lockid').value.trim() || null, fileName: stFile.name, fileSize: stFile.size });
    $('#st-receipt').textContent = stReceipt;
    $('#st-receipt-out').hidden = false;
    $('#st-step3').dataset.done = '';
    renderPostmark(stStamp, stFile);
    revealPostmark();
  } catch (e) {
    say('#st-receipt-msg', e.message, 'bad');
    play($('#st-receipt-msg'), 'anim-shake');
  }
});

// Named after the file, so the receipt sorts next to it: contract.pdf -> contract-brc-postmark-receipt.txt
const receiptName = () => `${(stFile ? stFile.name : 'file').replace(/\.[^.]{1,8}$/, '').replace(/[^\w.-]+/g, '_').slice(0, 60) || 'file'}-brc-postmark-receipt.txt`;

$('#btn-st-save').addEventListener('click', () => {
  if (!stReceipt) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([stReceipt + '\n'], { type: 'text/plain' }));
  a.download = receiptName();
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

// On phones, hand the receipt to the share sheet (Messages, Mail, Files…). Nothing is sent by this page.
const canShareFiles = (() => {
  try { return !!(navigator.canShare && navigator.canShare({ files: [new File(['x'], 'x.txt', { type: 'text/plain' })] })); } catch { return false; }
})();
$('#btn-st-share').hidden = !canShareFiles;
$('#btn-st-share').addEventListener('click', async () => {
  if (!stReceipt) return;
  try { await navigator.share({ files: [new File([stReceipt + '\n'], receiptName(), { type: 'text/plain' })], title: 'BRC Seal postmark receipt' }); } catch { /* closed the share sheet */ }
});

// Offline comparison of a file with a receipt.
let cmpFp = null;
async function runCompare() {
  const text = $('#st-cmp-receipt').value;
  if (!text.trim() || !cmpFp) { say('#st-cmp-msg', ''); return; }
  try {
    const r = stamp.parseReceipt(text);
    if (r.stamp.fingerprint === cmpFp) say('#st-cmp-msg', 'This file matches the receipt exactly. Check the receipt on BRC Pulse → Stamps to see the date.', 'good');
    else { say('#st-cmp-msg', "This file doesn't match the receipt. It is a different file, or it was changed after it was postmarked.", 'bad'); play($('#st-cmp-msg'), 'anim-shake'); }
  } catch (e) {
    say('#st-cmp-msg', e.message, 'bad');
  }
}
$('#st-cmp-receipt').addEventListener('input', runCompare);
let cmpGen = 0;
$('#st-cmp-file').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  const gen = ++cmpGen;
  const drop = $('#st-cmp-drop');
  cmpFp = null;
  if (!file) { dropState(drop, ''); runCompare(); return; }
  $('#st-cmp-file-title').textContent = `${file.name}: reading…`;
  dropState(drop, 'reading', 0);
  try {
    const fp = await hashFile(file, (f) => { if (gen === cmpGen) dropState(drop, 'reading', f); });
    if (gen !== cmpGen) return;
    cmpFp = fp;
    $('#st-cmp-file-title').textContent = file.name;
    dropState(drop, 'done', 1);
  } catch {
    if (gen !== cmpGen) return;
    dropState(drop, '');
    $('#st-cmp-file-title').textContent = 'This file could not be read. Try again.';
  }
  runCompare();
});


// ---------------------------------------------------------------------------
// Open many letters: a mailbox owner opens a whole BRC Mailbox export at once.
// For the giveaway it keeps one valid, eligible entry per address and makes the
// list to publish, with its fingerprint. Everything happens here, offline.
// ---------------------------------------------------------------------------

let ibExport = null;   // { mailbox, letters: [{ seq, letter }] }
let ibEligible = null; // { set, fingerprint, count }
let ibResult = null;
async function readJsonFile(file) {
  if (!file) return null;
  if (file.size > 50 * 1024 * 1024) throw new Error('This file is far too large.');
  try { return JSON.parse(await file.text()); } catch { throw new Error("This file isn't readable JSON. Choose the file as it was downloaded."); }
}
$('#ib-file').addEventListener('change', async (e) => {
  ibExport = null; $('#ib-out').hidden = true; say('#ib-msg', '');
  const f = e.target.files && e.target.files[0]; if (!f) return;
  try {
    const d = await readJsonFile(f);
    if (!d || !Array.isArray(d.letters) || !d.letters.every((l) => l && typeof l.letter === 'string')) throw new Error("This isn't a letters file from the BRC Mailbox.");
    ibExport = { mailbox: String(d.mailbox || ''), round: Number.isSafeInteger(d.round) && d.round > 0 ? d.round : null, letters: d.letters.map((l, i) => ({ seq: Number(l.seq) || i + 1, letter: l.letter })) };
    $('#ib-file-title').textContent = f.name;
    $('#ib-file-sub').textContent = `${ibExport.letters.length.toLocaleString('en-US')} letters for ${ibExport.mailbox ? `${ibExport.mailbox.slice(0, 6)}…${ibExport.mailbox.slice(-4)}` : 'an unnamed mailbox'}`;
    dropState($('#ib-drop'), 'done', 1);
  } catch (err) { say('#ib-msg', err.message, 'bad'); dropState($('#ib-drop'), ''); }
});
$('#ib-elig').addEventListener('change', async (e) => {
  ibEligible = null; $('#ib-out').hidden = true; say('#ib-msg', '');
  const f = e.target.files && e.target.files[0]; if (!f) return;
  try {
    const d = await readJsonFile(f);
    if (!d || !Array.isArray(d.addresses)) throw new Error("This isn't an eligible list.");
    const fp = giveaway.eligibleFingerprint(d.addresses);
    if (d.fingerprint && d.fingerprint !== fp) throw new Error("This eligible list doesn't match its own fingerprint. It was changed after it was made.");
    ibEligible = { set: new Set(d.addresses), fingerprint: fp, count: new Set(d.addresses).size };
    $('#ib-elig-title').textContent = f.name;
    $('#ib-elig-sub').textContent = `${ibEligible.count.toLocaleString('en-US')} addresses · fingerprint ${fp.slice(0, 16)}…`;
    dropState($('#ib-elig-drop'), 'done', 1);
  } catch (err) { say('#ib-msg', err.message, 'bad'); dropState($('#ib-elig-drop'), ''); }
});
$('#btn-ib-open').addEventListener('click', () => {
  $('#ib-out').hidden = true; say('#ib-msg', '');
  if (!ibExport) { say('#ib-msg', 'Choose the letters file first.', 'bad'); play($('#ib-msg'), 'anim-shake'); return; }
  if (!wallet) { say('#ib-msg', 'Open the mailbox key first. Opening needs it.', 'bad'); openSheet(); return; }
  if (ibExport.mailbox && ibExport.mailbox !== wallet.address) { say('#ib-msg', `These letters are for mailbox ${ibExport.mailbox.slice(0, 10)}…, not the key you opened. Open that mailbox's key.`, 'bad'); return; }
  const r = giveaway.readEntries(ibExport.letters.map((l) => l.letter), wallet, ibEligible ? ibEligible.set : null);
  ibResult = { ...r, letters: ibExport.letters.length, setAside: r.rejected.map((x) => ({ seq: ibExport.letters[x.index].seq, reason: x.reason })) };
  const rows = $('#ib-rows'); rows.replaceChildren();
  const row = (k, v, small) => rows.append(el('div', {}, el('dt', { text: k }), el('dd', {}, v, small ? el('small', { text: small }) : null)));
  row('Letters', ibResult.letters.toLocaleString('en-US'));
  row('Valid entries', r.entries.length.toLocaleString('en-US'), ibEligible ? 'one per eligible address' : 'one per address; no eligible list checked');
  row('Set aside', r.rejected.length.toLocaleString('en-US'));
  row('List fingerprint', r.fingerprint ? `${r.fingerprint.slice(0, 16)}…` : 'none', r.fingerprint ? 'publish this before the draw' : '');
  $('#ib-fp').textContent = r.fingerprint || '';
  const aside = $('#ib-aside'); aside.replaceChildren();
  if (r.rejected.length) {
    const counts = new Map();
    for (const x of r.rejected) counts.set(x.reason, (counts.get(x.reason) || 0) + 1);
    aside.append(el('p', { class: 'pm-note', text: 'Set aside: ' + [...counts].map(([k, n]) => `${n} × ${k.replace(/\.$/, '')}`).join('; ') + '.' }));
  }
  $('#btn-ib-save').disabled = !r.entries.length;
  $('#btn-ib-commit').hidden = !r.entries.length;
  $('#ib-out').hidden = false; play($('#ib-out'));
});
$('#btn-ib-commit').addEventListener('click', () => {
  if (!ibResult || !ibResult.entries.length) return;
  if (!ibExport.round) { say('#ib-msg', "This letters file doesn't say which drand round the draw uses. Download it again from BRC Pulse → Giveaway.", 'bad'); return; }
  try { startCommit(giveaway.listCommitMessage({ count: ibResult.entries.length, fingerprint: ibResult.fingerprint, round: ibExport.round })); } catch (e) { say('#ib-msg', e.message, 'bad'); }
});
$('#btn-ib-save').addEventListener('click', () => {
  if (!ibResult || !ibResult.entries.length) return;
  const body = { v: 1, mailbox: wallet ? wallet.address : null, round: ibExport ? ibExport.round : null, letters: ibResult.letters, count: ibResult.entries.length, fingerprint: ibResult.fingerprint,
    eligibleFingerprint: ibEligible ? ibEligible.fingerprint : null, addresses: ibResult.entries, setAside: ibResult.setAside };
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(body, null, 1) + '\n'], { type: 'application/json' }));
  a.download = 'entries.json';
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

// ---------------------------------------------------------------------------
// Swipe right to go back. Inside apps that keep the edge swipe for themselves,
// this gives the page its own back gesture. Starts near the left edge only.
// ---------------------------------------------------------------------------

let swipe = null;
const hint = $('#edge-hint');
function endSwipe(back) {
  if (!swipe) return;
  const scr = swipe.screen;
  swipe = null;
  scr.classList.remove('dragging');
  hint.style.opacity = '0';
  hint.style.transform = '';
  if (back) {
    scr.style.transform = ''; scr.style.opacity = '';
    scr.querySelector('[data-back]').click();
    return;
  }
  scr.classList.add('snap');
  scr.style.transform = ''; scr.style.opacity = '';
  setTimeout(() => scr.classList.remove('snap'), 400);
}
document.addEventListener('touchstart', (e) => {
  if (current === 'home' || sheet.open || e.touches.length !== 1) return;
  const t = e.touches[0];
  if (t.clientX > Math.min(72, innerWidth * 0.2)) return;
  if (e.target.closest('input, textarea, pre, .inline-copy, .chips')) return;
  swipe = { x: t.clientX, y: t.clientY, t: performance.now(), dx: 0, horizontal: null, screen: $(SCREENS[current]) };
}, { passive: true });
document.addEventListener('touchmove', (e) => {
  if (!swipe) return;
  const t = e.touches[0], dx = t.clientX - swipe.x, dy = t.clientY - swipe.y;
  if (swipe.horizontal === null && (Math.abs(dx) > 8 || Math.abs(dy) > 8)) swipe.horizontal = Math.abs(dx) > Math.abs(dy) * 1.2 && dx > 0;
  if (swipe.horizontal === false) { swipe = null; return; }
  if (!swipe.horizontal) return;
  swipe.dx = Math.max(0, dx);
  const p = Math.min(1, swipe.dx / 120);
  swipe.screen.classList.add('dragging');
  swipe.screen.style.transform = `translateX(${Math.round(swipe.dx * 0.55)}px)`;
  swipe.screen.style.opacity = String(1 - p * 0.25);
  hint.style.opacity = String(p);
  hint.style.transform = `translateX(${Math.round(p * 64)}px) scale(${0.7 + p * 0.3})`;
}, { passive: true });
document.addEventListener('touchend', () => {
  if (!swipe) return;
  const fast = swipe.dx > 60 && swipe.dx / Math.max(1, performance.now() - swipe.t) > 0.5;
  endSwipe(swipe.horizontal === true && (swipe.dx > 100 || fast));
});
document.addEventListener('touchcancel', () => endSwipe(false)); // the browser took the gesture (e.g. Safari's own back swipe)

// A file dropped anywhere outside a drop zone would otherwise open in the tab, showing a
// wallet file's contents. Ignore such drops.
for (const ev of ['dragover', 'drop']) document.addEventListener(ev, (e) => { if (!(e.target instanceof Element && e.target.closest('.drop'))) e.preventDefault(); });

// A real wallet is forgotten after 10 minutes without use, in case the tab is left open.
const IDLE_MS = 10 * 60 * 1000;
let lastActive = Date.now();
for (const ev of ['pointerdown', 'keydown', 'input', 'touchstart']) document.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true, capture: true });
function idleCheck() {
  if (wallet && !testWallets && Date.now() - lastActive > IDLE_MS) {
    forgetEverything();
    clearLoader();
    clearSecretsFromPage();
    renderWallet();
    stopLinking();
    $('#wallet-sub').textContent = 'Your mailbox key was closed after 10 minutes without use. Open it again when you need it.';
    for (const node of $$('[data-wallet-sub]')) node.textContent = 'Forgotten after 10 minutes idle';
  }
}
setInterval(idleCheck, 15 * 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) idleCheck(); });

if (EMBEDDED) { $('#frame-warning').hidden = false; $('#btn-load').title = 'Turned off inside another page'; }
renderWallet();
readHash();
