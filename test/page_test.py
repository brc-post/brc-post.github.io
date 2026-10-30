"""Headless-browser checks for dist/brc-seal.html.

Usage: python3 test/page_test.py <output-dir-for-screenshots>
"""
import json, os, pathlib, sys
from playwright.sync_api import sync_playwright, expect

out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'build/page-test')
out.mkdir(parents=True, exist_ok=True)
page_url = (pathlib.Path('dist/brc-seal.html').resolve()).as_uri()
fx = json.load(open('build/page-fixture.json'))
passed = []
def ok(msg): passed.append(msg); print('ok -', msg)

def sheet_open(pg):
    return pg.evaluate("document.querySelector('#wallet-sheet').open")

def open_wallet(pg):
    expect(pg.locator('#wallet-sheet.closing')).to_have_count(0)
    if not sheet_open(pg):
        pg.locator('[data-wallet]:visible').first.click()
    expect(pg.locator('#wallet-sheet')).to_be_visible()

def close_wallet(pg):
    expect(pg.locator('#wallet-sheet.closing')).to_have_count(0)
    if sheet_open(pg):
        pg.click('#btn-sheet-close')
    expect(pg.locator('#wallet-sheet[open]')).to_have_count(0)

def goto(pg, name):
    """Go to a screen the way a link does."""
    close_wallet(pg)
    pg.evaluate(f"location.hash = '{name}'")
    expect(pg.locator(f'[data-screen="{name}"]')).to_be_visible()

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    ctx = browser.new_context(viewport={'width': 1200, 'height': 900})
    page = ctx.new_page()
    errors, requests = [], []
    page.on('console', lambda m: errors.append(m.text) if m.type == 'error' else None)
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('request', lambda r: requests.append(r.url))
    page.goto(page_url)
    expect(page.locator('#wallet-title')).to_have_text('No wallet loaded')
    expect(page.locator('#s-home')).to_be_visible()
    expect(page.locator('#hero-mark')).to_have_class('big-mark play')
    page.wait_for_timeout(1800)  # let the intro finish
    page.screenshot(path=str(out / '01-start.png'), full_page=True)
    ok('page loads on the home screen, with no wallet')

    # --- Moving between screens ---
    page.click('#go-sign')
    expect(page.locator('#p-sign')).to_be_visible()
    expect(page.locator('#s-home')).to_be_hidden()
    assert page.evaluate('location.hash') == '#sign'
    page.locator('#p-sign [data-back]').click()
    expect(page.locator('#s-home')).to_be_visible()
    page.click('#go-received')
    page.click('#go-check')
    expect(page.locator('#p-check')).to_be_visible()
    page.go_back()
    expect(page.locator('#s-received')).to_be_visible()
    page.go_back()
    expect(page.locator('#s-home')).to_be_visible()
    page.go_forward()
    expect(page.locator('#s-received')).to_be_visible()
    page.locator('#s-received [data-back]').click()
    expect(page.locator('#s-home')).to_be_visible()
    ok('tiles, Back buttons and the browser back/forward move between screens')

    # --- Test wallets: sign as Alice, verify ---
    page.click('#go-sign')
    page.click('#btn-sign')  # no wallet yet: asks for one
    expect(page.locator('#sign-msg')).to_contain_text('Load a wallet')
    expect(page.locator('#wallet-sheet')).to_be_visible()
    page.click('#btn-test')
    expect(page.locator('#wallet-title')).to_have_text('Acting as test wallet Alice')
    alice = page.locator('#wallet-sub .mono').inner_text()
    expect(page.locator('#btn-sheet-done')).to_be_visible()
    page.screenshot(path=str(out / '01b-wallet-sheet.png'))
    page.click('#btn-sheet-done')
    expect(page.locator('#wallet-sheet[open]')).to_have_count(0)
    expect(page.locator('#p-sign [data-wallet-short]')).to_have_text('Alice')
    page.click('[data-fill="giveaway"]')
    expect(page.locator('#sign-text')).to_have_value("I'm entering the BrowserCoin block 100,000 giveaway.")
    page.click('#btn-sign')
    block = page.locator('#sign-block').inner_text()
    assert block.startswith('-----BEGIN BRC SIGNED MESSAGE-----') and alice in block
    page.screenshot(path=str(out / '02-signed.png'), full_page=True)
    ok('signs the giveaway entry as test wallet Alice')

    goto(page, 'verify')
    page.fill('#verify-text', block)
    page.click('#btn-verify')
    expect(page.locator('#verify-out .verdict')).to_have_attribute('data-tone', 'good')
    expect(page.locator('#verify-out')).to_contain_text('test wallet Alice')
    page.screenshot(path=str(out / '03-verified.png'), full_page=True)
    ok('verifies the signature and names the signer')

    page.fill('#verify-text', block.replace('100,000', '100,001'))
    page.click('#btn-verify')
    expect(page.locator('#verify-out .verdict')).to_have_attribute('data-tone', 'bad')
    ok('a changed message is shown as not valid')

    page.fill('#verify-text', 'hello there')
    page.click('#btn-verify')
    expect(page.locator('#verify-msg')).to_contain_text('not a BRC signed message')
    ok('explains a paste that is not a signed message')

    # --- I received something: paste, and it goes to the right screen ---
    goto(page, 'received')
    page.fill('#rx-text', 'just some text')
    expect(page.locator('#rx-msg')).to_contain_text("doesn't look like")
    page.fill('#rx-text', block)
    expect(page.locator('#p-verify')).to_be_visible()
    expect(page.locator('#verify-out .verdict')).to_have_attribute('data-tone', 'good')
    ok('a pasted signed message is recognised and checked')

    # --- Seal from Alice to Bob, open as Bob ---
    goto(page, 'seal')
    page.click('[data-to="bob"]')
    page.fill('#seal-text', 'Hi Bob, this is Alice. Meet at block 100,000.')
    page.check('#seal-sign')
    page.click('#btn-seal')
    sealed = page.locator('#seal-block').inner_text()
    assert sealed.startswith('-----BEGIN BRC SEALED NOTE-----') and alice not in sealed
    expect(page.locator('#seal-out-title')).to_contain_text('signed by you')
    expect(page.locator('#seal-len')).to_contain_text('Fits in one Discord message')
    page.screenshot(path=str(out / '04-sealed.png'), full_page=True)
    ok('seals a signed note to Bob without revealing Alice')

    goto(page, 'received')
    page.fill('#rx-text', sealed)
    expect(page.locator('#p-open')).to_be_visible()
    expect(page.locator('#open-text')).to_have_value(sealed)
    expect(page.locator('#open-msg')).to_contain_text('switch to Bob')
    ok('opening as the wrong wallet explains which one to use')

    open_wallet(page)
    page.click('#who button[data-who="bob"]')
    close_wallet(page)
    expect(page.locator('#p-open [data-wallet-short]')).to_have_text('Bob')
    page.click('#btn-open')
    expect(page.locator('#open-out .verdict')).to_have_attribute('data-tone', 'good')
    expect(page.locator('#open-out')).to_contain_text('Meet at block 100,000.')
    expect(page.locator('#open-out')).to_contain_text('test wallet Alice')
    expect(page.locator('#open-out')).to_contain_text('signature checked')
    page.screenshot(path=str(out / '05-opened.png'), full_page=True)
    ok('Bob opens it and sees it was signed by Alice')

    goto(page, 'seal')
    page.uncheck('#seal-sign')
    page.click('[data-to="bob"]')
    page.fill('#seal-text', 'Guess who.')
    page.click('#btn-seal')
    anon = page.locator('#seal-block').inner_text()
    goto(page, 'open')
    page.fill('#open-text', anon)
    page.click('#btn-open')
    expect(page.locator('#open-out')).to_contain_text('Anonymous')
    ok('an unsigned letter opens as anonymous')

    goto(page, 'seal')
    page.fill('#seal-text', 'x')
    page.fill('#seal-to', 'abc')
    page.click('#btn-seal')
    expect(page.locator('#seal-msg')).to_contain_text('64 characters')
    page.fill('#seal-to', alice)
    page.fill('#seal-text', 'y' * 1600)
    page.click('#btn-seal')
    expect(page.locator('#seal-len')).to_contain_text('too long for one Discord message')
    ok('bad addresses and over-long notes are explained')

    # --- Real wallet file, then a password-protected Vault backup ---
    open_wallet(page)
    page.click('#btn-forget')
    expect(page.locator('#wallet-title')).to_have_text('No wallet loaded')
    expect(page.locator('#sign-out')).to_be_hidden()
    page.click('#btn-load')
    page.fill('#wallet-paste', fx['walletFile'])
    page.click('#btn-load-go')
    expect(page.locator('#wallet-title')).to_have_text('Your wallet is loaded')
    expect(page.locator('#wallet-sub')).to_contain_text(fx['address'])
    expect(page.locator('#wallet-sheet[open]')).to_have_count(0)
    ok('loads a BrowserCoin wallet file, and the wallet sheet closes')

    # A bare 64-character key needs an explicit "this is my address" tick (review M3)
    priv = json.loads(fx['walletFile'])['privateKeyHex']
    open_wallet(page)
    page.click('#btn-forget')
    page.click('#btn-load')
    page.fill('#wallet-paste', priv)
    page.click('#btn-load-go')
    expect(page.locator('#confirm-field')).to_be_visible()
    expect(page.locator('#confirm-ambiguous')).to_be_visible()
    expect(page.locator('#confirm-address')).to_have_text(fx['address'])
    expect(page.locator('#wallet-title')).to_have_text('No wallet loaded')
    page.click('#btn-load-go')
    expect(page.locator('#load-msg')).to_contain_text('Tick the box')
    page.check('#confirm-mine')
    page.click('#btn-load-go')
    expect(page.locator('#wallet-title')).to_have_text('Your wallet is loaded')
    ok('a bare key only loads after confirming the address it gives')

    open_wallet(page)
    page.click('#btn-forget')
    page.click('#btn-load')
    page.fill('#wallet-paste', fx['address'])  # the address pasted by mistake
    page.click('#btn-load-go')
    expect(page.locator('#confirm-ambiguous')).to_contain_text('private key or an address')
    assert page.locator('#confirm-address').inner_text() != fx['address']
    page.click('#btn-load-cancel')
    expect(page.locator('#wallet-title')).to_have_text('No wallet loaded')
    ok('pasting an address by mistake is caught before it loads')

    page.click('#btn-test')
    page.click('#btn-load')
    page.fill('#wallet-paste', priv)
    page.click('#btn-forget')
    page.click('#btn-load')
    expect(page.locator('#wallet-paste')).to_have_value('')
    page.click('#btn-load-cancel')
    ok('Forget wallet also clears a half-typed key')

    page.click('#btn-load')
    page.locator('#wallet-file').set_input_files({'name': 'backup.json', 'mimeType': 'application/json', 'buffer': fx['backup'].encode()})
    expect(page.locator('#password-field')).to_be_visible()
    page.fill('#wallet-password', 'wrong password here')
    page.click('#btn-load-go')
    expect(page.locator('#load-msg')).to_have_attribute('data-tone', 'bad', timeout=30000)
    page.fill('#wallet-password', fx['password'])
    page.click('#btn-load-go')
    expect(page.locator('#wallet-title')).to_have_text('Your wallet is loaded', timeout=30000)
    expect(page.locator('#wallet-sub')).to_contain_text(fx['address'])
    ok('unlocks a BRC Vault backup with its password, refuses a wrong one')

    goto(page, 'sign')
    page.fill('#sign-text', 'Real-wallet test.')
    page.click('#btn-sign')
    real_block = page.locator('#sign-block').inner_text()
    goto(page, 'verify')
    page.fill('#verify-text', real_block)
    page.click('#btn-verify')
    expect(page.locator('#verify-out')).to_contain_text('your loaded wallet')
    ok('signs and verifies with the loaded wallet')

    # --- Stamp ---
    import hashlib, re
    doc = b'Farm lease, signed copy. Version 3.\n'
    open_wallet(page)
    page.click('#btn-forget')
    page.click('#btn-test')
    goto(page, 'postmark')
    expect(page.locator('#st-owner')).to_have_value(page.locator('#wallet-sub .mono').inner_text())
    page.click('#btn-st-make')
    expect(page.locator('#st-make-msg')).to_contain_text('Choose a file first')
    page.locator('#st-file').set_input_files({'name': 'lease-v3.txt', 'mimeType': 'text/plain', 'buffer': doc})
    expect(page.locator('#st-file-sub')).to_contain_text('fingerprint ' + hashlib.sha256(doc).hexdigest()[:16])
    page.click('#st-more summary')
    page.fill('#st-after-height', '92510')
    page.click('#btn-st-make')
    expect(page.locator('#st-make-msg')).to_contain_text('fill in both')
    page.fill('#st-after-height', '92510 ' + 'ab' * 32)  # pasted from Pulse's "Copy both"
    expect(page.locator('#st-after-height')).to_have_value('92510')
    expect(page.locator('#st-after-hash')).to_have_value('ab' * 32)
    beacon = json.load(open('test/drand-vectors.json'))['beacons'][-1]
    page.fill('#st-drand', f"{beacon['round']} {beacon['signature'][:-2]}00")
    expect(page.locator('#st-drand-status')).to_have_text('not a valid beacon')
    page.click('#btn-st-make')
    expect(page.locator('#st-make-msg')).to_contain_text("doesn't check out")
    page.fill('#st-drand', f"{beacon['round']} {beacon['signature']}")
    expect(page.locator('#st-drand-status')).to_contain_text('Oct 30, 2026, 2:35:33')
    page.click('#btn-st-make')
    phrase = page.locator('#st-phrase').inner_text()
    assert re.fullmatch(r'BRCSTAMP1_' + hashlib.sha256(doc).hexdigest() + r'_[0-9a-f]{32}_A92510_' + 'ab' * 32 + f"_D{beacon['round']}_{beacon['signature']}", phrase), phrase
    owner = page.locator('#st-owner-copy').inner_text()
    pre = hashlib.sha256(phrase.encode()).digest()
    script = b'\xa8\x20' + hashlib.sha256(pre).digest() + b'\x88\x20' + bytes.fromhex(owner) + b'\xac'
    expect(page.locator('#st-check')).to_have_text('PUSH(32) ' + script.hex()[4:24] + '\u2026')
    expect(page.locator('#st-check-owner')).to_have_text('PUSH(32) ' + owner[:20] + '\u2026')
    ok('Stamp makes the exact phrase and script the official app will build')

    expect(page.locator('#st-lockid-status')).to_have_text('optional')
    expect(page.locator('#st-test-lock')).to_be_visible()
    page.fill('#st-lockid', '12345')
    expect(page.locator('#st-lockid-status')).to_contain_text('5 of 64')
    page.click('#btn-st-receipt')
    expect(page.locator('#st-receipt-msg')).to_contain_text('Lock ID should be 64')
    page.fill('#st-lockid', 'ab' * 32 + 'c')
    expect(page.locator('#st-lockid-status')).to_have_text('not a Lock ID')
    page.fill('#st-lockid', '')
    page.click('#btn-st-receipt')
    expect(page.locator('#pm-card')).to_be_visible()
    assert 'Lock ID' not in page.locator('#st-receipt').text_content()
    ok('the Lock ID is optional: a receipt can be made without it')
    page.click('#btn-st-testlock')
    expect(page.locator('#st-lockid-status')).to_have_text('looks right')
    page.fill('#st-lockid', 'Lock ID:  0x' + 'CD' * 16 + '\n' + 'cd' * 16)
    expect(page.locator('#st-lockid')).to_have_value('cd' * 32)
    expect(page.locator('#st-lockid-status')).to_have_text('looks right')
    ok('a pasted Lock ID is tidied (label, 0x, line breaks) and checked as you go')
    page.click('#btn-st-receipt')
    receipt = page.locator('#st-receipt').text_content()
    assert f"Drand: {beacon['round']} {beacon['signature']}" in receipt, receipt
    assert 'File: lease-v3.txt (36 bytes)' in receipt and 'Lock ID: ' + 'cd' * 32 in receipt and 'After: 92510 ' + 'ab' * 32 in receipt, receipt
    with page.expect_download() as dl:
        page.click('#btn-st-save')
    assert dl.value.suggested_filename == 'lease-v3-brc-postmark-receipt.txt', dl.value.suggested_filename
    expect(page.locator('#pm-card')).to_be_visible()
    assert page.locator('#pm-line').inner_text().startswith('AFTER '), page.locator('#pm-line').inner_text()
    expect(page.locator('#pm-from')).to_contain_text('You')
    expect(page.locator('#pm-name')).to_have_text('lease-v3.txt')
    page.wait_for_timeout(1500)
    page.screenshot(path=str(out / '07-stamp.png'), full_page=True)
    page.locator('#pm-card').screenshot(path=str(out / '07b-postmark-card.png'))
    ok('makes a receipt, shows the postmark card, and saves it as a file')

    goto(page, 'received')
    page.fill('#rx-text', receipt)
    expect(page.locator('#p-check')).to_be_visible()
    expect(page.locator('#st-cmp-receipt')).to_have_value(receipt)
    expect(page.locator('#st-cmp-msg')).to_contain_text('Choose the file')
    page.locator('#st-cmp-file').set_input_files({'name': 'lease-v3.txt', 'mimeType': 'text/plain', 'buffer': doc})
    expect(page.locator('#st-cmp-msg')).to_contain_text('matches the receipt exactly')
    page.locator('#st-cmp-file').set_input_files({'name': 'lease-v4.txt', 'mimeType': 'text/plain', 'buffer': doc.replace(b'3', b'4')})
    expect(page.locator('#st-cmp-msg')).to_contain_text("doesn't match")
    ok('checks a file against its receipt, offline')

    # --- Link from BRC Pulse ---
    page.goto(page_url + '#to=' + fx['address'])
    page.reload()
    expect(page.locator('#p-seal')).to_be_visible()
    expect(page.locator('#seal-to')).to_have_value(fx['address'])
    ok('a #to= link opens Seal with the address filled in')

    # --- Phone width ---
    phone = browser.new_context(viewport={'width': 390, 'height': 844}, device_scale_factor=2, is_mobile=True, has_touch=True)
    p2 = phone.new_page()
    p2.goto(page_url)
    p2.wait_for_timeout(1800)
    assert p2.evaluate('document.documentElement.scrollWidth') <= 390, 'home scrolls sideways on a phone'
    p2.screenshot(path=str(out / '06a-phone-home.png'), full_page=True)
    open_wallet(p2)
    p2.click('#btn-test')
    p2.screenshot(path=str(out / '06b-phone-wallet.png'))
    goto(p2, 'postmark')
    p2.locator('#st-file').set_input_files({'name': 'x.txt', 'mimeType': 'text/plain', 'buffer': b'x'})
    p2.click('#btn-st-make')
    assert p2.evaluate('document.documentElement.scrollWidth') <= 390, 'stamp tab scrolls sideways on a phone'
    p2.screenshot(path=str(out / '08-phone-stamp.png'), full_page=True)
    goto(p2, 'seal')
    p2.click('[data-to="bob"]')
    p2.fill('#seal-text', 'Phone check.')
    p2.click('#btn-seal')
    width = p2.evaluate('document.documentElement.scrollWidth')
    assert width <= 390, f'page scrolls sideways on a phone ({width}px)'
    p2.screenshot(path=str(out / '06-phone.png'), full_page=True)
    ok('fits a 390px phone screen without sideways scrolling')

    # --- Reduced motion: everything still appears, straight away ---
    calm = browser.new_context(viewport={'width': 390, 'height': 844}, reduced_motion='reduce')
    p3 = calm.new_page()
    p3.on('pageerror', lambda e: errors.append(str(e)))
    p3.goto(page_url)
    p3.wait_for_timeout(150)
    op = p3.evaluate("getComputedStyle(document.querySelector('#hero-mark .dot')).opacity")
    assert float(op) == 1.0, f'logo dot hidden with reduced motion ({op})'
    op = p3.evaluate("getComputedStyle(document.querySelector('.tiles .tile:last-child')).opacity")
    assert float(op) == 1.0, f'tiles hidden with reduced motion ({op})'
    ok('with reduced motion, nothing waits on an animation')

    # --- Swipe right from the left edge goes back (for apps that keep the edge swipe) ---
    p2.evaluate('location.hash = "seal"')
    expect(p2.locator('#p-seal')).to_be_visible()
    swipe_js = '''(pts) => {
      const t = (x, y) => new Touch({ identifier: 1, target: document.body, clientX: x, clientY: y });
      const fire = (type, x, y) => document.body.dispatchEvent(new TouchEvent(type, { bubbles: true, cancelable: true, touches: type === 'touchend' ? [] : [t(x, y)], changedTouches: [t(x, y)] }));
      fire('touchstart', pts[0][0], pts[0][1]);
      for (const p of pts.slice(1)) fire('touchmove', p[0], p[1]);
      const last = pts[pts.length - 1]; fire('touchend', last[0], last[1]);
    }'''
    p2.evaluate(swipe_js, [[30, 400], [50, 402], [70, 403]])  # too short: stays
    p2.wait_for_timeout(500)
    expect(p2.locator('#p-seal')).to_be_visible()
    p2.evaluate(swipe_js, [[200, 400], [260, 400], [360, 400]])  # starts mid-screen: ignored
    expect(p2.locator('#p-seal')).to_be_visible()
    p2.evaluate(swipe_js, [[20, 400], [60, 402], [120, 404], [190, 405]])
    expect(p2.locator('#s-home')).to_be_visible()
    ok('swiping right from the left edge goes back; short or mid-screen swipes do not')

    others = [u for u in requests if not u.startswith('file:') and not u.startswith('data:')]
    assert not others, f'unexpected network requests: {others}'
    ok('made no network requests')
    assert not errors, f'console errors: {errors}'
    ok('no console errors')
    browser.close()

print(f'\n{len(passed)} page checks passed')
