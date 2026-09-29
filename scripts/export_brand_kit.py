"""Build social artwork from the canonical Grantline vector logo.

The generated SVGs stay editable. Raster PNGs can be exported with a browser.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "web" / "public" / "brand"
OUT = BRAND

DEEP = "#123d2d"
GREEN = "#184b37"
MINT = "#d3e5c4"
IVORY = "#f4f4eb"


def inner_svg(name: str, color: str) -> str:
    source = (BRAND / name).read_text(encoding="utf-8")
    source = re.sub(r"^.*?<svg[^>]*>", "", source, count=1)
    source = source.rsplit("</svg>", 1)[0]
    source = re.sub(r"<title>.*?</title>", "", source)
    source = source.replace("#22664c", color).replace("#184b37", color)
    source = source.replace("#d3e5c4", color).replace("#f4f4eb", color)
    return source


def mark(x: float, y: float, scale: float, color: str) -> str:
    return f'<g transform="translate({x} {y}) scale({scale})" fill="none">{inner_svg("grantline-symbol.svg", color)}</g>'


def wordmark(x: float, y: float, scale: float, color: str) -> str:
    return f'<g transform="translate({x} {y}) scale({scale})" fill="none">{inner_svg("grantline-wordmark.svg", color)}</g>'


def svg(name: str, width: int, height: int, contents: str) -> None:
    (OUT / name).write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="Grantline">'
        f'<title>Grantline</title>{contents}</svg>\n',
        encoding="utf-8",
    )


def background(width: int, height: int) -> str:
    return f'<rect width="{width}" height="{height}" fill="{DEEP}"/>'


def arcs(width: int, height: int, opacity: str = ".12") -> str:
    return (
        f'<g fill="none" stroke="{MINT}" stroke-width="2" opacity="{opacity}">'
        f'<path d="M-140 {height*.26:.0f} C{width*.16:.0f} {height*.26:.0f} '
        f'{width*.13:.0f} {height*.73:.0f} {width*.36:.0f} {height*.73:.0f}"/>'
        f'<path d="M{width*.68:.0f} {height*.20:.0f} C{width*.87:.0f} {height*.20:.0f} '
        f'{width*.83:.0f} {height*.79:.0f} {width+140} {height*.79:.0f}"/>'
        f'<circle cx="{width*.13:.0f}" cy="{height*.26:.0f}" r="7" fill="{MINT}" stroke="none"/>'
        f'<circle cx="{width*.86:.0f}" cy="{height*.79:.0f}" r="7" fill="{MINT}" stroke="none"/>'
        '</g>'
    )


svg("github-avatar-1024.svg", 1024, 1024, background(1024, 1024) + mark(72, 72, 22, MINT))
svg("linkedin-logo-400.svg", 400, 400, background(400, 400) + mark(30, 30, 8.5, MINT))
svg("symbol-transparent-1024.svg", 1024, 1024, mark(72, 72, 22, GREEN))

svg(
    "linkedin-cover-4200x700.svg", 4200, 700,
    background(4200, 700) + arcs(4200, 700) +
    wordmark(1519, 181, 7, IVORY) +
    f'<text x="2100" y="566" text-anchor="middle" fill="{MINT}" '
    'font-family="Arial, sans-serif" font-size="52" font-weight="600" '
    'letter-spacing="8">NON-HUMAN IDENTITY SECURITY</text>',
)

svg(
    "instagram-story-1080x1920.svg", 1080, 1920,
    background(1080, 1920) + arcs(1080, 1920, ".17") +
    mark(240, 300, 15, MINT) + wordmark(208, 1000, 4, IVORY) +
    f'<path d="M360 1230H720" stroke="{MINT}" stroke-width="2" opacity=".55"/>'
    f'<text x="540" y="1330" text-anchor="middle" fill="{MINT}" '
    'font-family="Arial, sans-serif" font-size="28" font-weight="600" '
    'letter-spacing="5">NON-HUMAN IDENTITY SECURITY</text>',
)

svg(
    "readme-banner-1600x500.svg", 1600, 500,
    background(1600, 500) + arcs(1600, 500, ".16") +
    wordmark(468, 110, 4, IVORY) +
    f'<text x="800" y="359" text-anchor="middle" fill="{MINT}" '
    'font-family="Arial, sans-serif" font-size="27" font-weight="600" '
    'letter-spacing="5">NON-HUMAN IDENTITY SECURITY</text>',
)

print(f"Wrote SVG brand kit to {OUT}")
