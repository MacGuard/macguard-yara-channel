import { chromium } from 'playwright'; import fs from 'fs'; import { createRequire } from 'module';
const require = createRequire(import.meta.url); const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const B='https://macguard.github.io/macguard-yara-channel/'; const br=await chromium.launch({headless:true});
for (const p of ['', 'rules.html','releases.html','transparency.html','docs/es/overview.html']) {
 const ctx=await br.newContext({viewport:{width:1280,height:800},reducedMotion:'reduce'}); const pg=await ctx.newPage(); await pg.addInitScript(()=>localStorage.setItem('theme','dark'));
 await pg.goto(B+p,{waitUntil:'networkidle'}); await pg.waitForTimeout(1500); await pg.addScriptTag({content:axeSrc});
 const v=await pg.evaluate(async()=>{const x=await axe.run(document,{runOnly:['color-contrast']});return x.violations.map(a=>a.nodes.map(n=>n.target.join(' ')+' :: '+(n.any[0]&&n.any[0].message||'').slice(0,110))).flat().slice(0,6)});
 console.log(p||'index', v.length, JSON.stringify(v)); await ctx.close();}
await br.close();
