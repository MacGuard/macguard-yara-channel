// Lighthouse (mobile default preset) on selected URLs, sequential, one Chrome at a time. usage: node lh.mjs gh|cf
import lighthouse from 'lighthouse'; import * as chromeLauncher from 'chrome-launcher'; import { chromium } from 'playwright'; import fs from 'fs';
const D = '/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/web-audit';
const hk = process.argv[2] || 'gh'; const B = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' }[hk];
const urls = { index: B, rules: B + 'rules.html', doc_mermaid: B + 'docs/es/architecture.html', transparency: B + 'transparency.html' };
const out = {};
for (const [name, url] of Object.entries(urls)) {
  const chrome = await chromeLauncher.launch({ chromePath: chromium.executablePath(), chromeFlags: ['--headless=new', '--no-sandbox', '--disable-gpu'] });
  try {
    const r = await lighthouse(url, { port: chrome.port, output: 'json', logLevel: 'error' }, undefined);
    const l = r.lhr; const a = l.audits;
    out[name] = { url, perf: l.categories.performance.score, a11y: undefined, fcp: a['first-contentful-paint'].numericValue, lcp: a['largest-contentful-paint'].numericValue, cls: a['cumulative-layout-shift'].numericValue, tbt: a['total-blocking-time'].numericValue, si: a['speed-index'].numericValue, tti: a['interactive'] && a['interactive'].numericValue, transfer: a['total-byte-weight'].numericValue, reqs: a['network-requests'].details.items.map(i => ({ u: i.url.replace(B, '/'), t: i.transferSize, s: i.resourceSize, type: i.resourceType })).filter(i => i.t > 0).sort((x, y) => y.t - x.t).slice(0, 12), lcpEl: a['largest-contentful-paint-element'] && a['largest-contentful-paint-element'].details && JSON.stringify(a['largest-contentful-paint-element'].details.items && a['largest-contentful-paint-element'].details.items[0] && a['largest-contentful-paint-element'].details.items[0].items && a['largest-contentful-paint-element'].details.items[0].items[0] && a['largest-contentful-paint-element'].details.items[0].items[0].node && a['largest-contentful-paint-element'].details.items[0].items[0].node.snippet), opps: Object.values(a).filter(x => x.score !== null && x.score < 0.9 && x.details && x.scoreDisplayMode !== 'informative' && x.scoreDisplayMode !== 'notApplicable').map(x => x.id + ':' + (x.score)).slice(0, 15), mainThread: a['mainthread-work-breakdown'] && a['mainthread-work-breakdown'].numericValue, bootup: a['bootup-time'] && a['bootup-time'].numericValue, throttling: l.configSettings.throttlingMethod, form: l.configSettings.formFactor };
    console.log(name, JSON.stringify(out[name]).slice(0, 900));
    fs.writeFileSync(`${D}/out/lh_${hk}_${name}.json`, JSON.stringify(l));
  } catch (e) { out[name] = { error: String(e).slice(0, 300) }; console.log(name, 'ERR', out[name].error); }
  await chrome.kill();
}
fs.writeFileSync(`${D}/out/lh_${hk}.json`, JSON.stringify(out, null, 1));
