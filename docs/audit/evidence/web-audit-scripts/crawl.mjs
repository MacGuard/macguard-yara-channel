// Polite crawler (GET only, <=4 req/s, depth 3) for both hosts. Saves bodies to ./mirror/<hostkey>/ and writes crawl.json
import fs from 'fs'; import path from 'path'; import crypto from 'crypto';
const HOSTS = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' };
const OUT = path.dirname(new URL(import.meta.url).pathname);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const res = {};
for (const [k, base] of Object.entries(HOSTS)) {
  const seen = new Map(), q = [[base, 0, 'root']]; const origin = new URL(base).origin;
  const broken = [], ext = new Set(), redirects = [];
  while (q.length) {
    const [u, d, from] = q.shift(); const key = u.split('#')[0];
    if (seen.has(key)) continue; seen.set(key, { depth: d });
    await sleep(260);
    let r; try { r = await fetch(key, { redirect: 'manual', signal: AbortSignal.timeout(30000) }); } catch (e) { broken.push({ url: key, from, err: String(e) }); continue; }
    const rec = seen.get(key); rec.status = r.status; rec.ct = r.headers.get('content-type'); rec.cc = r.headers.get('cache-control');
    if (r.status >= 300 && r.status < 400) { const loc = new URL(r.headers.get('location'), key).href; redirects.push({ from: key, to: loc, status: r.status }); if (loc.startsWith(base)) q.push([loc, d, key]); continue; }
    if (r.status >= 400) { broken.push({ url: key, from, status: r.status }); continue; }
    const buf = Buffer.from(await r.arrayBuffer()); rec.bytes = buf.length; rec.sha = crypto.createHash('sha256').update(buf).digest('hex');
    const rel = new URL(key).pathname.slice(new URL(base).pathname.length) || 'index'; const fp = path.join(OUT, 'mirror', k, rel.endsWith('/') ? rel + 'index.html' : rel);
    if (buf.length < 3e6) { fs.mkdirSync(path.dirname(fp), { recursive: true }); fs.writeFileSync(fp, buf); }
    if (/html/.test(rec.ct || '') && d < 3) {
      const t = buf.toString('utf8'); const re = /(?:href|src)=["']([^"'#][^"']*)["']/g; let m;
      while ((m = re.exec(t))) { const h = m[1]; if (/^(mailto:|javascript:|data:)/.test(h)) continue; let abs; try { abs = new URL(h, key).href } catch { continue }
        if (!abs.startsWith(origin)) { ext.add(abs.split('#')[0] + ' <- ' + key); continue }
        if (!abs.startsWith(base)) { broken.push({ url: abs, from: key, note: 'outside base path' }); continue }
        // skip the 1100+ individual rule files: only sample (they are downloads, not pages)
        if (/\/rules\/.+\.(yar|yara)$/i.test(abs) || /\/rules\//.test(abs) && !/\.html$/.test(abs) && d >= 1) continue;
        q.push([abs, d + 1, key]); }
      // anchors check
      const ids = new Set([...t.matchAll(/\sid=["']([^"']+)["']/g)].map(x => x[1])); rec.ids = [...ids];
      rec.anchors = [...t.matchAll(/href=["']([^"']*)#([^"']+)["']/g)].map(x => [x[1], x[2]]);
    }
  }
  res[k] = { count: seen.size, pages: Object.fromEntries(seen), broken, redirects, ext: [...ext] };
  // anchor validation
  const bad = [];
  for (const [u, rec] of seen) for (const [p, a] of (rec.anchors || [])) { const tu = p ? new URL(p, u).href : u; const tr = seen.get(tu.split('#')[0]); if (tr && tr.ids && !tr.ids.includes(a) && !tr.ids.includes(decodeURIComponent(a))) bad.push({ in: u, to: tu + '#' + a }); }
  res[k].badAnchors = bad;
}
fs.writeFileSync(path.join(OUT, 'crawl.json'), JSON.stringify(res, null, 1));
for (const k in res) console.log(k, 'pages', res[k].count, 'broken', res[k].broken.length, 'badAnchors', res[k].badAnchors.length, 'ext', res[k].ext.length, 'redirects', res[k].redirects.length);
