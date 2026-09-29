"""Rebuild outlined wordmarks from the licensed, self-hosted IBM Plex font."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin/font-tools'))
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

font=TTFont(ROOT/'web/node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-600-normal.woff')
glyphs=font.getGlyphSet();cmap=font.getBestCmap();scale=27/font['head'].unitsPerEm
pen=SVGPathPen(glyphs);x=52
for character in 'grantline':
    glyph=glyphs[cmap[ord(character)]]
    glyph.draw(TransformPen(pen,(scale,0,0,-scale,x,29)))
    x+=glyph.width*scale-.3
brand=ROOT/'web/public/brand'
symbol=(brand/'grantline-symbol.svg').read_text()
for name,color in [('grantline-wordmark','#184b37'),('grantline-wordmark-light','#f4f4eb'),('grantline-wordmark-mono','currentColor')]:
    icon=symbol[symbol.index('<path'):symbol.rindex('</svg>')].replace('#22664c',color)
    (brand/f'{name}.svg').write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {x+4:.1f} 40" role="img" aria-label="Grantline"><title>Grantline</title>{icon}<path d="{pen.getCommands()}" fill="{color}"/></svg>\n')
(brand/'grantline-symbol-mono.svg').write_text(symbol.replace('#22664c','currentColor'))
public=ROOT/'docs/guide/public/brand';public.mkdir(parents=True,exist_ok=True)
(public/'grantline-symbol.svg').write_text(symbol)
print('Outlined light, dark and monochrome logo assets generated.')
