import fs from 'fs';import crypto from 'crypto';
const r=JSON.parse(fs.readFileSync('crawl.json'));
const norm=(u,b)=>u.replace(b,'');const G='https://macguard.github.io/macguard-yara-channel/',C='https://macguard-rules.pages.dev/';
const gm=new Map(Object.entries(r.gh.pages).map(([u,v])=>[norm(u,G),v]));
const cm=new Map();for(const [u,v] of Object.entries(r.cf.pages)){if(v.status&&v.status<300)cm.set(norm(u,C),v)}
let same=0,diff=[],missing=[];
for(const [p,v] of gm){const key=p||'';let c=cm.get(p)||cm.get(p.replace(/\.html$/,''))||(p===''?cm.get(''):null);if(!c){missing.push(p);continue}
 if(c.sha===v.sha)same++;else diff.push(p+' gh='+v.bytes+' cf='+c.bytes)}
console.log({same,diffCount:diff.length,missing});console.log(diff.join('\n'));
