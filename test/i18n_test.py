"""The English / 中文 switch in BRC Post, in headless Chromium.

Usage: python3 test/i18n_test.py <page.html> <output-dir>

The switch must only change words. People's messages and letters are never changed, even when
they are exactly the words of a button, and signing, sealing and opening work the same in Chinese.
"""
import re, sys, pathlib
from playwright.sync_api import sync_playwright, expect

PAGE = pathlib.Path(sys.argv[1]).resolve().as_uri()
OUT = pathlib.Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
HAN = re.compile(r"[一-鿿]")
passed = []
def ok(msg): passed.append(msg); print("ok -", msg)

ENGLISH_LEFT = """() => {
  const skip = (e) => { for (; e; e = e.parentElement) { if (/^(SCRIPT|STYLE|CODE|PRE|KBD|SAMP|TEXTAREA)$/.test(e.tagName) || e.getAttribute('translate') === 'no' || (typeof e.className === 'string' && /(^|\\s)(mono|addr|message-box|signed-box|unsigned-box|signed-msg)(\\s|$)/.test(e.className))) return true; } return false; };
  const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let all = 0; const left = [];
  for (let n; (n = w.nextNode());) {
    const t = n.data.replace(/\\s+/g, ' ').trim();
    if (!/[a-z]{3,}/.test(t) || !n.parentElement || skip(n.parentElement) || !vis(n.parentElement)) continue;
    all++;
    const words = t.replace(/\\b(BrowserCoin|BRC|Vault|Pulse|Post|Works|Discord|drand|pb-hash|Alice|Bob|Chrome|Safari|iPhone|JSON|QR|github|io|brc|post|json|https?)\\b/g, '');
    if (/[a-z]{3,}/.test(words) && !/[\\u4e00-\\u9fff]/.test(t)) left.push(t.slice(0, 80));
  }
  return { all, left };
}"""

def goto(pg, name):
    pg.evaluate(f"location.hash = '{name}'")
    expect(pg.locator(f'[data-screen="{name}"]')).to_be_visible()

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    errors = []
    ctx = browser.new_context(viewport={"width": 1200, "height": 900}, locale="en-US")
    page = ctx.new_page()
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto(PAGE)
    page.wait_for_timeout(1800)
    expect(page.locator("[data-lang-toggle]")).to_have_text("中文")
    english = page.evaluate("() => document.body.innerText")
    ok("an English browser gets English, with a 中文 button in the top bar")

    page.click("[data-lang-toggle]")
    expect(page.locator("[data-lang-toggle]")).to_have_text("EN")
    assert page.evaluate("document.documentElement.lang") == "zh-CN"
    cover = page.evaluate(ENGLISH_LEFT)
    print("   visible text left in English:", len(cover["left"]), "of", cover["all"], cover["left"][:8])
    assert len(cover["left"]) <= max(3, cover["all"] // 25), cover["left"]
    page.screenshot(path=str(OUT / "zh-1-home.png"), full_page=True)
    ok(f"中文 switches the home screen to Chinese ({cover['all'] - len(cover['left'])} of {cover['all']} visible texts)")

    page.click("[data-lang-toggle]")
    assert page.evaluate("() => document.body.innerText") == english, "switching back did not restore the exact English"
    page.click("[data-lang-toggle]")
    ok("EN switches back to exactly the original English")

    # Sign, in Chinese, a message that is exactly the words of a button.
    UI_WORDS = "Seal a letter"
    goto(page, "sign")
    page.click('#sign-as [data-as="mailbox"]')
    page.click("#btn-sign")
    expect(page.locator("#wallet-sheet")).to_be_visible()
    page.click("#btn-test")
    expect(page.locator("#btn-sheet-done")).to_be_visible()
    page.click("#btn-sheet-done")
    expect(page.locator("#wallet-sheet[open]")).to_have_count(0)
    expect(page.locator("#p-sign [data-wallet-short]")).to_have_text("Alice")
    page.fill("#sign-text", UI_WORDS)
    assert page.input_value("#sign-text") == UI_WORDS
    page.click("#btn-sign")
    block = page.locator("#sign-block").inner_text()
    assert block.startswith("-----BEGIN BRC SIGNED MESSAGE-----") and f"\n{UI_WORDS}\n" in block and not HAN.search(block)
    page.screenshot(path=str(OUT / "zh-2-signed.png"), full_page=True)
    ok("signing in Chinese signs exactly what was typed, and the signed block is untouched")

    goto(page, "verify")
    page.fill("#verify-text", block)
    page.click("#btn-verify")
    expect(page.locator("#verify-out .verdict")).to_have_attribute("data-tone", "good")
    expect(page.locator("#verify-out .message-box")).to_have_text(UI_WORDS)
    expect(page.locator("#verify-out")).to_contain_text(HAN)
    page.screenshot(path=str(OUT / "zh-3-verified.png"), full_page=True)
    ok("verifying in Chinese shows the signed words exactly as signed, never translated")

    # Seal a letter whose words are a button's words, open it as Bob, in Chinese.
    goto(page, "seal")
    page.click('[data-to="bob"]')
    page.fill("#seal-text", "Back up")
    page.click("#btn-seal")
    sealed = page.locator("#seal-block").inner_text()
    assert sealed.startswith("-----BEGIN BRC SEALED NOTE-----") and not HAN.search(sealed)
    goto(page, "received")
    page.fill("#rx-text", sealed)
    expect(page.locator("#p-open")).to_be_visible()
    page.locator("[data-wallet]:visible").first.click()
    page.click('#who button[data-who="bob"]')
    page.click("#btn-sheet-close")
    page.click("#btn-open")
    expect(page.locator("#open-out .verdict")).to_have_attribute("data-tone", "good")
    expect(page.locator("#open-out .message-box")).to_have_text("Back up")
    page.screenshot(path=str(OUT / "zh-4-opened.png"), full_page=True)
    ok("a letter opened in Chinese shows its words exactly as written")

    page.reload(); page.wait_for_timeout(800)
    expect(page.locator("[data-lang-toggle]")).to_have_text("EN")
    ok("the choice is remembered on this device after a reload")
    ctx.close()

    ctx = browser.new_context(locale="zh-CN", viewport={"width": 390, "height": 844})
    page = ctx.new_page(); page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(PAGE); page.wait_for_timeout(1500)
    expect(page.locator("[data-lang-toggle]")).to_have_text("EN")
    expect(page.locator("[data-lang-toggle]")).to_be_visible()
    width = page.evaluate("() => document.documentElement.scrollWidth")
    assert width <= 390, f"page is {width}px wide on a phone"
    page.screenshot(path=str(OUT / "zh-5-phone.png"), full_page=True)
    page.goto(PAGE + "?lang=en"); page.wait_for_timeout(500)
    expect(page.locator("[data-lang-toggle]")).to_have_text("中文")
    ok("a Chinese browser opens in Chinese and fits a phone; ?lang=en opens English")
    ctx.close()

    assert not errors, errors
    ok("no script errors")
    browser.close()

print(f"\n{len(passed)} language checks passed")
