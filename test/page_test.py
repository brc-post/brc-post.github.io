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
    page.screenshot(path=str(out / '01-start.png'), full_page=True)
    ok('page loads with no wallet')

    # --- Test wallets: sign as Alice, verify ---
    page.click('#btn-test')
    expect(page.locator('#wallet-title')).to_have_text('Acting as test wallet Alice')
    alice = page.locator('#wallet-sub .mono').inner_text()
    page.click('[data-fill="raffle"]')
    expect(page.locator('#sign-text')).to_have_value("I'm entering the BrowserCoin block 100,000 raffle.")
    page.click('#btn-sign')
    block = page.locator('#sign-block').inner_text()
    assert block.startswith('-----BEGIN BRC SIGNED MESSAGE-----') and alice in block
    page.screenshot(path=str(out / '02-signed.png'), full_page=True)
    ok('signs the raffle entry as test wallet Alice')

    page.click('#tab-verify')
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

    # --- Seal from Alice to Bob, open as Bob ---
    page.click('#tab-seal')
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

    page.click('#tab-open')
    page.fill('#open-text', sealed)
    page.click('#btn-open')
    expect(page.locator('#open-msg')).to_contain_text('switch to Bob')
    ok('opening as the wrong wallet explains which one to use')

    page.click('#who button[data-who="bob"]')
    page.click('#btn-open')
    expect(page.locator('#open-out .verdict')).to_have_attribute('data-tone', 'good')
    expect(page.locator('#open-out')).to_contain_text('Meet at block 100,000.')
    expect(page.locator('#open-out')).to_contain_text('test wallet Alice')
    expect(page.locator('#open-out')).to_contain_text('signature checked')
    page.screenshot(path=str(out / '05-opened.png'), full_page=True)
    ok('Bob opens it and sees it was signed by Alice')

    page.click('#tab-seal')
    page.uncheck('#seal-sign')
    page.click('[data-to="bob"]')
    page.fill('#seal-text', 'Guess who.')
    page.click('#btn-seal')
    anon = page.locator('#seal-block').inner_text()
    page.click('#tab-open')
    page.fill('#open-text', anon)
    page.click('#btn-open')
    expect(page.locator('#open-out')).to_contain_text('Anonymous')
    ok('an unsigned note opens as anonymous')

    page.click('#tab-seal')
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
    page.click('#btn-forget')
    expect(page.locator('#wallet-title')).to_have_text('No wallet loaded')
    expect(page.locator('#sign-out')).to_be_hidden()
    page.click('#btn-load')
    page.fill('#wallet-paste', fx['walletFile'])
    page.click('#btn-load-go')
    expect(page.locator('#wallet-title')).to_have_text('Your wallet is loaded')
    expect(page.locator('#wallet-sub')).to_contain_text(fx['address'])
    ok('loads a BrowserCoin wallet file')

    # A bare 64-character key needs an explicit "this is my address" tick (review M3)
    priv = json.loads(fx['walletFile'])['privateKeyHex']
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

    page.click('#tab-sign')
    page.fill('#sign-text', 'Real-wallet test.')
    page.click('#btn-sign')
    real_block = page.locator('#sign-block').inner_text()
    page.click('#tab-verify')
    page.fill('#verify-text', real_block)
    page.click('#btn-verify')
    expect(page.locator('#verify-out')).to_contain_text('your loaded wallet')
    ok('signs and verifies with the loaded wallet')

    # --- Link from BRC Pulse ---
    page.goto(page_url + '#to=' + fx['address'])
    expect(page.locator('#p-seal')).to_be_visible()
    expect(page.locator('#seal-to')).to_have_value(fx['address'])
    ok('a #to= link opens Seal with the address filled in')

    # --- Phone width ---
    phone = browser.new_context(viewport={'width': 390, 'height': 844}, device_scale_factor=2, is_mobile=True, has_touch=True)
    p2 = phone.new_page()
    p2.goto(page_url)
    p2.click('#btn-test')
    p2.click('#tab-seal')
    p2.click('[data-to="bob"]')
    p2.fill('#seal-text', 'Phone check.')
    p2.click('#btn-seal')
    width = p2.evaluate('document.documentElement.scrollWidth')
    assert width <= 390, f'page scrolls sideways on a phone ({width}px)'
    p2.screenshot(path=str(out / '06-phone.png'), full_page=True)
    ok('fits a 390px phone screen without sideways scrolling')

    others = [u for u in requests if not u.startswith('file:') and not u.startswith('data:')]
    assert not others, f'unexpected network requests: {others}'
    ok('made no network requests')
    assert not errors, f'console errors: {errors}'
    ok('no console errors')
    browser.close()

print(f'\n{len(passed)} page checks passed')
