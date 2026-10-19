// Repro of index race: tiles-dist drawn before latest.json arrives. usage: node race.mjs gh|cf
import { chromium } from 'playwright';
const hk = process.argv[2] || 'gh'; const B = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' }[hk];
const br = await chromium.launch({ headless: true });
for (const delay of [0, 0, 0, 1500]) {
  const ctx = await br.newContext({ serviceWorkers: 'block' }); const p = await ctx.newPage();
  if (delay) await p.route('**/latest.json', async r => { await new Promise(x => setTimeout(x, delay)); r.continue(); });
  await p.goto(B, { waitUntil: 'networkidle' }); await p.waitForTimeout(2500);
  console.log(hk, 'delay', delay, (await p.locator('#tiles-dist').innerText()).replace(/\s+/g, ' '));
  await ctx.close();
}
await br.close();
