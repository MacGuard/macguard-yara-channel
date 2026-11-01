/* Shared helpers for the channel pages. No framework; every function degrades to the static links in <noscript>. */
(function(){
var MG=window.MG={};
MG.lang=function(){var v='es';try{v=localStorage.getItem('lang')||(navigator.language||'es').slice(0,2)}catch(e){}return v==='es'?'es':'en'};
MG.setLang=function(v){try{localStorage.setItem('lang',v)}catch(e){}};
MG.$=function(i){return document.getElementById(i)};
MG.el=function(tag,attrs,kids){var e=document.createElement(tag);for(var k in (attrs||{})){if(k==='text')e.textContent=attrs[k];else e.setAttribute(k,attrs[k])}(kids||[]).forEach(function(c){e.appendChild(typeof c==='string'?document.createTextNode(c):c)});return e};
MG.get=function(u,json){return fetch(u,{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error(u+' '+r.status);return json?r.json():r.text()})};
MG.bytes=function(n){if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';return (n/1048576).toFixed(1)+' MB'};
MG.day=function(iso){return String(iso||'').slice(0,10)};
MG.path=function(p){return p.split('/').map(encodeURIComponent).join('/')};
MG.hex=function(buf){return Array.prototype.map.call(new Uint8Array(buf),function(b){return ('0'+b.toString(16)).slice(-2)}).join('')};
MG.fromHex=function(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a};
MG.sha256=function(bytes){if(!(window.crypto&&crypto.subtle))return Promise.reject(new Error('SubtleCrypto needs https or localhost'));return crypto.subtle.digest('SHA-256',bytes)};
/* JSON from the SAME origin by default, with a timeout, no credentials and no redirects; a non-JSON answer is an error. */
MG.getT=function(u,ms){var c=window.AbortController?new AbortController():null,t=c?setTimeout(function(){c.abort()},ms||8000):null;
 return fetch(u,{cache:'no-store',credentials:'omit',redirect:'error',signal:c?c.signal:undefined}).then(function(r){if(t)clearTimeout(t);if(!r.ok)throw new Error('HTTP '+r.status);if((r.headers.get('content-type')||'').indexOf('json')<0)throw new Error('not JSON');return r.json()},function(e){if(t)clearTimeout(t);throw e})};
/* Shared navigation and footer texts of every portal page (a page dictionary overrides them). The Spanish text is also the one already in the HTML. */
MG.NAV={es:{nav_home:'Inicio',nav_catalog:'Biblioteca',nav_iocs:'Indicadores',nav_vulns:'Vulnerabilidades',nav_packages:'Descargas',nav_plans:'Planes',nav_transparency:'Transparencia',nav_docs:'Documentación',skip:'Saltar al contenido',theme:'Tema oscuro',disclaimer:'Proyecto independiente. Sin afiliación ni aval de las fuentes.'},
 en:{nav_home:'Home',nav_catalog:'Library',nav_iocs:'Indicators',nav_vulns:'Vulnerabilities',nav_packages:'Downloads',nav_plans:'Plans',nav_transparency:'Transparency',nav_docs:'Documentation',skip:'Skip to content',theme:'Dark theme',disclaimer:'Independent project. Not affiliated with or endorsed by upstream sources.'}};
/* i18n: elements with data-t="key" take dict[lang][key] (or MG.NAV); missing keys keep the Spanish text already in the HTML. */
MG.i18n=function(dict,onchange){
 var sel=MG.$('lang'),dark=false;
 function apply(){var l=sel?sel.value:MG.lang();document.documentElement.lang=l;var d=Object.assign({},MG.NAV[l]||{},dict[l]||{});
  // the Spanish markup of the page (links included) is kept once and restored when a language has no text for that key: switching EN -> ES gives the original back
  document.querySelectorAll('[data-t]').forEach(function(e){var k=e.getAttribute('data-t');if(!e._mgOrig)e._mgOrig=Array.prototype.map.call(e.childNodes,function(n){return n.cloneNode(true)});
   if(d[k]!==undefined)e.textContent=d[k];else{e.textContent='';e._mgOrig.forEach(function(n){e.appendChild(n.cloneNode(true))})}});
  document.querySelectorAll('[data-t-label]').forEach(function(e){var k=e.getAttribute('data-t-label');if(d[k]!==undefined)e.setAttribute('aria-label',d[k])});
  if(onchange)onchange(l)}
 if(sel){sel.value=MG.lang();sel.addEventListener('change',function(){MG.setLang(sel.value);apply()})}
 try{if(localStorage.getItem('theme')==='dark')document.body.classList.add('dark')}catch(e){}
 /* WCAG 4.1.2: the theme button is a toggle ("Dark theme", one language per page) whose state is exposed with aria-pressed */
 var th=MG.$('theme');function thSync(){if(th)th.setAttribute('aria-pressed',document.body.classList.contains('dark')?'true':'false')}thSync();
 if(th)th.addEventListener('click',function(){document.body.classList.toggle('dark');thSync();try{localStorage.setItem('theme',document.body.classList.contains('dark')?'dark':'light')}catch(e){}});
 apply();return apply};
MG.L=function(){var s=MG.$('lang');return s?s.value:MG.lang()};
/* Merkle (RFC 6962 hashing, RFC 9162 verification) with SubtleCrypto. Inputs and outputs are Uint8Array. */
var enc=new TextEncoder();
function cat(){var n=0,i;for(i=0;i<arguments.length;i++)n+=arguments[i].length;var o=new Uint8Array(n),p=0;for(i=0;i<arguments.length;i++){o.set(arguments[i],p);p+=arguments[i].length}return o}
function h(b){return MG.sha256(b).then(function(x){return new Uint8Array(x)})}
var M=MG.merkle={};
M.leaf=function(bytes){return h(cat(new Uint8Array([0]),bytes))};
M.node=function(l,r){return h(cat(new Uint8Array([1]),l,r))};
M.eq=function(a,b){if(a.length!==b.length)return false;for(var i=0;i<a.length;i++)if(a[i]!==b[i])return false;return true};
M.root=function(leaves){var n=leaves.length;if(n===0)return h(new Uint8Array(0));if(n===1)return Promise.resolve(leaves[0]);var k=1;while(k*2<n)k*=2;
 return Promise.all([M.root(leaves.slice(0,k)),M.root(leaves.slice(k))]).then(function(p){return M.node(p[0],p[1])})};
M.verifyInclusion=function(index,size,leaf,proof,root){
 if(index<0||index>=size)return Promise.resolve(false);var fn=index,sn=size-1,r=Promise.resolve(leaf);
 proof.forEach(function(p){r=r.then(function(cur){if(sn===0){fn=-1;return cur}
  var out;if((fn&1)||fn===sn){out=M.node(p,cur);if(!(fn&1)){while(!(fn&1)&&fn!==0){fn>>=1;sn>>=1}}}else{out=M.node(cur,p)}
  return out.then(function(v){fn>>=1;sn>>=1;return v})})});
 return r.then(function(v){return fn!==-1&&sn===0&&M.eq(v,root)})};
M.verifyConsistency=function(first,second,firstRoot,secondRoot,proof){
 if(first>second||first<0)return Promise.resolve(false);
 if(first===second)return Promise.resolve(proof.length===0&&M.eq(firstRoot,secondRoot));
 if(first===0)return Promise.resolve(proof.length===0);
 var p=proof.slice();if((first&(first-1))===0)p.unshift(firstRoot);if(!p.length)return Promise.resolve(false);
 var fn=first-1,sn=second-1;while(fn&1){fn>>=1;sn>>=1}
 var fr=p[0],sr=p[0],bad=false,chain=Promise.resolve();
 p.slice(1).forEach(function(c){chain=chain.then(function(){if(bad)return;if(sn===0){bad=true;return}
  if((fn&1)||fn===sn){return Promise.all([M.node(c,fr),M.node(c,sr)]).then(function(v){fr=v[0];sr=v[1];if(!(fn&1)){while(!(fn&1)&&fn!==0){fn>>=1;sn>>=1}}fn>>=1;sn>>=1})}
  return M.node(sr,c).then(function(v){sr=v;fn>>=1;sn>>=1})})});
 return chain.then(function(){return !bad&&sn===0&&M.eq(fr,firstRoot)&&M.eq(sr,secondRoot)})};
M.splitLines=function(buf){var u=new Uint8Array(buf),out=[],s=0;for(var i=0;i<u.length;i++)if(u[i]===10){if(i>s)out.push(u.subarray(s,i));s=i+1}if(s<u.length)out.push(u.subarray(s));return out};
M.b64=function(s){var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a};
MG.enc=enc;
})();

/* scrollable tables must be reachable and named for keyboard and screen-reader users */
document.querySelectorAll('.tablewrap').forEach(function(w){var cap=w.querySelector('caption');w.setAttribute('tabindex','0');w.setAttribute('role','region');if(cap&&cap.textContent)w.setAttribute('aria-label',cap.textContent)});

/* Identifier detection shared by the hub search, the explorer and the vulnerability page. Case-insensitive input, canonical output.
   GCVE keeps its numbering authority (GNA); only GCVE-0 is the CVE namespace, and that equivalence is the API's business, never guessed here.
   Anything that is not an identifier is free text (vendor, product, version, rule name), searched only by the API. */
(function(MG){
var K=[['CVE',/^CVE-(\d{4})-(\d{4,})$/i,function(m){return 'CVE-'+m[1]+'-'+m[2]}],['EUVD',/^EUVD-(\d{4})-(\d{1,})$/i,function(m){return 'EUVD-'+m[1]+'-'+m[2]}],
 ['GCVE',/^GCVE-(\d{1,9})-(\d{4})-(\d{1,})$/i,function(m){return 'GCVE-'+m[1]+'-'+m[2]+'-'+m[3]}],['GHSA',/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/i,function(m){return 'GHSA'+m[0].slice(4).toLowerCase()}],
 ['CWE',/^CWE-(\d{1,5})$/i,function(m){return 'CWE-'+Number(m[1])}],['SHA256',/^[0-9a-f]{64}$/i,function(m){return m[0].toLowerCase()}],['SHA1',/^[0-9a-f]{40}$/i,function(m){return m[0].toLowerCase()}],
 ['MD5',/^[0-9a-f]{32}$/i,function(m){return m[0].toLowerCase()}],['SID',/^(?:sid[:\s]?|\d{1,3}:)(\d{1,10})$/i,function(m){return 'sid:'+Number(m[1])}]];
MG.VULN_KINDS=['CVE','EUVD','GCVE','GHSA','CWE'];
MG.idKind=function(v){v=String(v==null?'':v).trim();if(!v||v.length>128||/[\x00-\x1f<>]/.test(v))return null;
 for(var i=0;i<K.length;i++){var m=K[i][1].exec(v);if(m)return {kind:K[i][0],id:K[i][2](m)}}
 return v.length>=2?{kind:'TEXT',id:v.replace(/\s+/g,' ')}:null};
MG.vulnKind=function(v){var k=MG.idKind(v);return k&&MG.VULN_KINDS.indexOf(k.kind)>=0?k:null};
/* API base of the vulnerability lookup service (macguard.intel-search/1): only a plain https base from <meta name="mg-vuln-api">, otherwise none. */
MG.apiBase=function(){var m=document.querySelector('meta[name="mg-vuln-api"]'),v=m?String(m.getAttribute('content')||'').trim():'';
 return /^https:\/\/[a-z0-9.-]+(:\d+)?(\/[A-Za-z0-9._~\/-]*)?$/.test(v)?v.replace(/\/$/,''):''};
/* "No disponible" everywhere a value is unknown: null/undefined are never shown as 0. */
MG.na=function(v,lang){return v===null||v===undefined||v===''?(lang==='en'?'Not available':'No disponible'):String(v)};
})(window.MG);
