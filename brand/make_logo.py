"""Build the BRC Post logo as clean vector artwork.

The mark shares BRC Vault's rounded box. Inside: an envelope flap (a chevron)
closed by a round indigo wax seal at its point. The wordmark is set in Geist
(Vercel, SIL OFL 1.1) and converted to outlines, exactly like BRC Vault's,
so it renders identically everywhere.
Usage: python3 brand/make_logo.py <out-dir>
"""
import math, sys, io, pathlib
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

OUT = pathlib.Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
INK = "#353535"
DOT = "#5956FD"
VAR = "node_modules/geist/dist/fonts/geist-sans/Geist-Variable.ttf"

# ---------------- Mark ----------------
BOX_X, BOX_Y, BOX_W, STROKE, R_OUT = 307.6, 90.0, 1316.0, 107.8, 252.6   # same box as BRC Vault
CX = BOX_X + BOX_W / 2           # 965.6, the vertical axis of symmetry
FLAP_TOP, FLAP_HALF, FLAP_POINT = 430.0, 420.8, 790.0   # envelope flap: top corners and point
SEAL_CY, SEAL_R = 820.0, 190.0                          # the wax seal over the flap's point

def mark_paths():
    half = STROKE / 2
    r_mid = R_OUT - half
    box = (f'<rect x="{BOX_X + half:.1f}" y="{BOX_Y + half:.1f}" width="{BOX_W - STROKE:.1f}" '
           f'height="{BOX_W - STROKE:.1f}" rx="{r_mid:.1f}" fill="none" stroke="{{ink}}" stroke-width="{STROKE:.1f}"/>')
    flap = (f'<path d="M{CX - FLAP_HALF:.1f} {FLAP_TOP:.1f}L{CX:.1f} {FLAP_POINT:.1f}L{CX + FLAP_HALF:.1f} {FLAP_TOP:.1f}" '
            f'fill="none" stroke="{{ink}}" stroke-width="{STROKE:.1f}" stroke-linecap="round" stroke-linejoin="round"/>')
    seal = f'<circle cx="{CX:.1f}" cy="{SEAL_CY:.1f}" r="{SEAL_R:.1f}" fill="{{dot}}"/>'
    return box, flap, seal

# ---------------- Wordmark ----------------
# The original wordmark sat about 20 units right of centre. It is now set flush
# with the box's outer edges, so it is centred and exactly as wide as the mark.
GAP = 52.0                                  # space between box and wordmark, as in the original
LEFT, RIGHT = BOX_X, BOX_X + BOX_W
CAP_TOP = BOX_Y + BOX_W + GAP

def instance(wght):
    f = TTFont(VAR)
    return instantiateVariableFont(f, {"wght": wght}, inplace=False)

def word_glyphs(font, text):
    cmap = font.getBestCmap(); gs = font.getGlyphSet(); hmtx = font["hmtx"]
    return [(cmap[ord(ch)], gs[cmap[ord(ch)]], hmtx[cmap[ord(ch)]][0]) for ch in text]

# With the tight tracking, bold E and A touch; give that one pair a little air.
KERN = {("E", "A"): 16.0}

def kern(text, i):
    return KERN.get((text[i], text[i + 1]), 0.0) if i + 1 < len(text) else 0.0

def set_word(font, text, x, scale, tracking, baseline):
    out = []
    for i, (name, glyph, adv) in enumerate(word_glyphs(font, text)):
        pen = SVGPathPen(font.getGlyphSet())
        glyph.draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
        out.append(pen.getCommands())
        x += adv * scale + tracking + kern(text, i)
    return " ".join(out), x

def stem_ratio(font):
    gs = font.getGlyphSet(); bp = BoundsPen(gs); gs["I"].draw(bp)
    cap = font["OS/2"].sCapHeight
    return (bp.bounds[2] - bp.bounds[0]) / cap

def weight_for(target):
    lo, hi = 100, 900
    for _ in range(14):
        mid = (lo + hi) / 2
        if stem_ratio(instance(mid)) < target: lo = mid
        else: hi = mid
    return round((lo + hi) / 2)

light_w = weight_for(22.0 / 178.0)          # stem/cap-height ratios measured from the original
bold_w = weight_for(36.0 / 178.0)
light, bold = instance(light_w), instance(bold_w)

def ink_bounds(font, text, x0, scale, tracking):
    """Left and right edges of the actual letter shapes (not their side bearings)."""
    gs = font.getGlyphSet(); x = x0; lefts = []; rights = []
    for i, (name, glyph, adv) in enumerate(word_glyphs(font, text)):
        bp = BoundsPen(gs); glyph.draw(bp)
        if bp.bounds:
            lefts.append(x + bp.bounds[0] * scale); rights.append(x + bp.bounds[2] * scale)
        x += adv * scale + tracking + kern(text, i)
    return min(lefts), max(rights), x

# Same proportions as the original: cap height 178 for an ink width of 1208, tracking -20.3 at that size.
CAP = 178.0 * (RIGHT - LEFT) / 1208.0
scale = CAP / light["OS/2"].sCapHeight
CAP_BOTTOM = CAP_TOP + CAP

def measure(tracking, x0=0.0):
    l1, r1, x = ink_bounds(light, "BRC", x0, scale, tracking)
    l2, r2, _ = ink_bounds(bold, "POST", x, scale, tracking)
    return l1, r2

def wordmark_d(tracking, x0):
    d1, x = set_word(light, "BRC", x0, scale, tracking, CAP_BOTTOM)
    d2, _ = set_word(bold, "POST", x, scale, tracking, CAP_BOTTOM)
    return d1 + " " + d2

# Same letter size and spacing as BRC Vault's wordmark (its fitted tracking is
# -18.1), so the family matches. "POST" is shorter than "VAULT", so instead of
# stretching it to the box width, the word is centred under the box.
tracking = -18.1
l, r = measure(tracking)
x0 = CX - (l + r) / 2
word_d = wordmark_d(tracking, x0)
l, r = measure(tracking, x0)
print(f"wordmark ink {l:.2f} to {r:.2f} (box {LEFT:.2f} to {RIGHT:.2f}), cap height {CAP:.1f}")
print(f"wordmark: BRC wght {light_w}, POST wght {bold_w}, tracking {tracking:.1f}")

def svg(view, body):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}">{body}</svg>\n'

def colored(parts, ink=INK, dot=DOT):
    return "".join(p.replace("{ink}", ink).replace("{dot}", dot) for p in parts)

box, v, dot = mark_paths()  # v = envelope flap, dot = seal
mark_view = f"{BOX_X:.1f} {BOX_Y:.1f} {BOX_W:.1f} {BOX_W:.1f}"
lockup_view = f"{BOX_X - 80:.1f} {BOX_Y - 80:.1f} {BOX_W + 160:.1f} {CAP_BOTTOM - BOX_Y + 160:.1f}"
word = f'<path fill="{{ink}}" d="{word_d}"/>'

files = {
    "brc-post-mark.svg": svg(mark_view, colored([box, v, dot])),
    "brc-post-mark-white.svg": svg(mark_view, colored([f'<rect x="{BOX_X}" y="{BOX_Y}" width="{BOX_W}" height="{BOX_W}" rx="{R_OUT}" fill="#fff"/>', box, v, dot])),
    "brc-post-logo.svg": svg(lockup_view, colored([box, v, dot, word])),
    "brc-post-logo-mono.svg": svg(lockup_view, colored([box, v, dot, word], ink="#000", dot="#000")),
}
for name, text in files.items():
    (OUT / name).write_text(text)
    print(name, len(text), "bytes")

# Small pieces the page build inlines.
(OUT / "mark-inner.txt").write_text(colored([box, v, dot], ink="currentColor", dot="var(--brand)"))
(OUT / "mark-print.txt").write_text(colored([box, v, dot], ink="#000", dot="#000"))
