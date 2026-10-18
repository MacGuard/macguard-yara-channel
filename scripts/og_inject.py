#!/usr/bin/env python3
"""Adds Open Graph / Twitter card tags to every HTML page of a built site, using absolute URLs of the host that will serve it.

usage: og_inject.py SITE_DIR BASE_URL     (BASE_URL e.g. https://macguard.github.io/macguard-yara-channel/)
The preview image is web/img/yara-rules.png (copied into the site by build_site). Idempotent: an earlier block is replaced, so the same
built site can be re-targeted to another host (GitHub Pages and the Cloudflare mirror each get their own absolute URLs)."""
import html, pathlib, re, sys

IMAGE = 'img/yara-rules.png'; W, H = 1200, 630
ALT = 'MacGuard YARA Channel: verified rules, Sigstore signed, transparency log, safer macOS'
DEFAULT_DESC = 'Verified, signed and transparent YARA rules for macOS: Sigstore signatures, Merkle transparency log, public catalog and independent verifier.'
BLOCK = re.compile(r'<!--og-->.*?<!--/og-->', re.S)

def inject(site: pathlib.Path, base: str) -> int:
    base = base.rstrip('/') + '/'; n = 0
    if not (site / IMAGE).exists(): raise SystemExit(f'missing {IMAGE} in {site}')
    for p in sorted(site.rglob('*.html')):
        src = p.read_text(encoding='utf-8'); src = BLOCK.sub('', src)
        t = re.search(r'<title>(.*?)</title>', src, re.S)
        if not t: continue
        title = html.unescape(t.group(1)).strip()
        d = re.search(r'<meta name="description" content="([^"]*)"', src); desc = html.unescape(d.group(1)).replace('`', '') if d and d.group(1) else DEFAULT_DESC   # Markdown backticks do not belong in a share preview
        lang = re.search(r'<html lang="(\w+)"', src); loc = {'es': 'es_ES', 'en': 'en_US'}.get(lang.group(1) if lang else 'en', 'en_US')
        rel = p.relative_to(site).as_posix(); url = base + ('' if rel == 'index.html' else rel)
        e = lambda s: html.escape(s, quote=True)
        tags = ('<!--og-->'
                f'<meta property="og:type" content="website"><meta property="og:site_name" content="MacGuard YARA Channel"><meta property="og:title" content="{e(title)}">'
                f'<meta property="og:description" content="{e(desc)}"><meta property="og:url" content="{e(url)}"><meta property="og:locale" content="{loc}">'
                f'<meta property="og:image" content="{e(base + IMAGE)}"><meta property="og:image:type" content="image/png"><meta property="og:image:width" content="{W}"><meta property="og:image:height" content="{H}"><meta property="og:image:alt" content="{e(ALT)}">'
                f'<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{e(title)}"><meta name="twitter:description" content="{e(desc)}"><meta name="twitter:image" content="{e(base + IMAGE)}"><meta name="twitter:image:alt" content="{e(ALT)}">'
                '<!--/og-->')
        if not d: tags = tags.replace('<!--og-->', f'<!--og--><meta name="description" content="{e(desc)}">', 1)
        src = src[:t.end()] + tags + src[t.end():]
        p.write_text(src, encoding='utf-8'); n += 1
    return n

if __name__ == '__main__':
    if len(sys.argv) != 3 or not sys.argv[2].startswith(('https://', 'http://127.0.0.1')): sys.exit(__doc__)
    print(f'og tags written to {inject(pathlib.Path(sys.argv[1]), sys.argv[2])} pages for {sys.argv[2]}')
