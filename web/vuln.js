/* Vulnerability page (vuln.html?id=). API mode: the record of contract macguard.intel-vulnerability/1, rendered by vulnrecord.js; sections the server
   withholds (Premium) arrive as {restricted:true, capability} and are shown as restricted, never filled in here. Static mode: the CISA KEV entry from a
   package verified in this build, with everything KEV does not provide shown as "No disponible". textContent only. */
(function(){var $=MG.$,el=MG.el;
var D={es:{},en:{back:'← Vulnerability explorer',h:'Vulnerability page',load:'Loading…',k_h:'How to read this page',k1:'CVSS measures technical severity (with version, vector and source); EPSS is an estimated probability of exploitation in 30 days, not a severity.',
 k2:'"Not in KEV" does not mean "not being exploited".',k3:'A "related" rule is not a validated detection of this vulnerability: only "validated detection" has tests behind it.',k4:'PoC references are metadata: executable code is never linked or distributed.'}};
var X={es:{bad:'Identificador no válido. Usa CVE-AAAA-NNNN, EUVD-AAAA-NNNN, GCVE-<GNA>-AAAA-NNNN o GHSA-xxxx-xxxx-xxxx.',fail:'La consulta no se pudo completar. No se muestra ningún dato.',nf:'Sin registro para este identificador en las fuentes disponibles.',
  needapi:'Este identificador requiere el servicio de consulta, aún no publicado. La búsqueda estática solo contiene CVE del catálogo CISA KEV.',off:'No hay servicio de consulta publicado ni paquete KEV verificado en esta publicación: no se muestra ningún dato.',
  notkev:function(v){return 'No figura en el catálogo CISA KEV publicado'+(v?' (versión '+v+')':'')+'. Esto no significa que no esté siendo explotada. NVD, EUVD, GCVE, CVSS y EPSS aún no están disponibles en el portal.'},
  ident:'Identificación',desc:'Descripción',risk:'Riesgo',det:'Detecciones',res:'Referencias de investigación',pkg:'Procedencia y paquete',na:'No disponible',
  vendor:'Fabricante',product:'Producto',name:'Nombre',summary:'Resumen',cwe:'CWE',kev:'CISA KEV',listed:'En el catálogo KEV',added:'Fecha de inclusión',due:'Fecha límite (agencias federales de EE. UU.)',action:'Acción requerida',ransom:'Uso conocido en ransomware',notes:'Notas',
  cvss:'CVSS',epss:'EPSS',src_na:'fuente no aprobada todavía',norule:'Sin regla verificada disponible',noioc:'Sin indicadores publicados',nopoc:'Sin referencias de PoC registradas',
  pkgsrc:'Fuente',lic:'Licencia',ver:'Versión del catálogo',rel:'Publicado por CISA',ret:'Obtenido',psha:'SHA-256 del paquete',msha:'SHA-256 del manifiesto',files:'Descargar paquete y firma',
  attr:'Atribución'},
 en:{bad:'Invalid identifier. Use CVE-YYYY-NNNN, EUVD-YYYY-NNNN, GCVE-<GNA>-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx.',fail:'The query could not be completed. No data is shown.',nf:'No record for this identifier in the available sources.',
  needapi:'This identifier needs the lookup service, not published yet. The static search only holds CVEs of the CISA KEV catalogue.',off:'No lookup service is published and there is no verified KEV package in this publication: no data is shown.',
  notkev:function(v){return 'Not in the published CISA KEV catalogue'+(v?' (version '+v+')':'')+'. This does not mean it is not being exploited. NVD, EUVD, GCVE, CVSS and EPSS are not available in the portal yet.'},
  ident:'Identification',desc:'Description',risk:'Risk',det:'Detections',res:'Research references',pkg:'Provenance and package',na:'Not available',
  vendor:'Vendor',product:'Product',name:'Name',summary:'Summary',cwe:'CWE',kev:'CISA KEV',listed:'In the KEV catalogue',added:'Date added',due:'Due date (US federal agencies)',action:'Required action',ransom:'Known ransomware campaign use',notes:'Notes',
  cvss:'CVSS',epss:'EPSS',src_na:'source not approved yet',norule:'No verified rule available',noioc:'No published indicators',nopoc:'No PoC references recorded',
  pkgsrc:'Source',lic:'Licence',ver:'Catalogue version',rel:'Released by CISA',ret:'Retrieved',psha:'Package SHA-256',msha:'Manifest SHA-256',files:'Download package and signature',
  attr:'Attribution'}};
var x=function(){return X[MG.L()]||X.es},API=MG.apiBase(),id=null,state=null;
function fact(dl,k,v,mono){dl.appendChild(el('dt',{text:k}));dl.appendChild(el('dd',mono?{class:'mono',text:v}:{text:v}))}
function panel(title){var s=el('section',{class:'panel'});s.appendChild(el('h2',{text:title}));$('vbody').appendChild(s);return s}
function kevPage(it,idx){var t=x(),L=MG.L(),na=function(v){return MG.na(v,L)};$('vbody').textContent='';
 var a=panel(t.ident),dl=el('dl',{class:'facts'});a.appendChild(dl);fact(dl,'CVE',it.cve_id);fact(dl,t.cwe,(it.cwes||[]).join(', ')||t.na);
 var b=panel(t.desc),dl2=el('dl',{class:'facts'});b.appendChild(dl2);fact(dl2,t.name,na(it.name));fact(dl2,t.vendor,na(it.vendor));fact(dl2,t.product,na(it.product));fact(dl2,t.summary,na(it.short_description));
 if(it.notes)fact(dl2,t.notes,it.notes);
 var c=panel(t.risk),g=el('div',{class:'risk'});c.appendChild(g);
 var k=el('article');k.appendChild(el('h3',{text:t.kev}));k.appendChild(el('p',{},[el('span',{class:'badge kev',text:t.listed})]));var kd=el('dl',{class:'facts'});k.appendChild(kd);
 fact(kd,t.added,na(it.date_added));fact(kd,t.due,na(it.due_date));fact(kd,t.action,na(it.required_action));fact(kd,t.ransom,na(it.known_ransomware_use));g.appendChild(k);
 [[t.cvss],[t.epss]].forEach(function(r){var e=el('article');e.appendChild(el('h3',{text:r[0]}));e.appendChild(el('p',{text:t.na+' ('+t.src_na+')'}));g.appendChild(e)});
 var d=panel(t.det);d.appendChild(el('p',{text:t.norule}));d.appendChild(el('p',{class:'muted',text:t.noioc}));
 var e=panel(t.res);e.appendChild(el('p',{class:'muted',text:t.nopoc}));
 var f=panel(t.pkg),dl3=el('dl',{class:'facts'});f.appendChild(dl3);var s=idx.source||{},p=idx.package||{};
 fact(dl3,t.pkgsrc,'CISA Known Exploited Vulnerabilities Catalog');fact(dl3,t.lic,'CC0-1.0');if(s.attribution)fact(dl3,t.attr,s.attribution);fact(dl3,t.ver,na(s.catalog_version));fact(dl3,t.rel,na(s.date_released));fact(dl3,t.ret,na(s.retrieved_at));
 if(p.package_sha256)fact(dl3,t.psha,p.package_sha256,true);if(p.manifest_sha256)fact(dl3,t.msha,p.manifest_sha256,true);
 var ul=el('ul',{class:'dl'});Object.keys(p.assets||{}).forEach(function(n){var u=p.assets[n];if(/^intel\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(u))ul.appendChild(el('li',{},[el('a',{href:u,text:n})]))});
 if(ul.childNodes.length){f.appendChild(el('p',{text:t.files}));f.appendChild(ul)}}
/* API record: sections the server withholds are {restricted:true, capability}: listed as restricted (vulnrecord.js shows the Premium notice), set to [] */
function apiPage(r){var rec=r&&r.record&&typeof r.record==='object'?r.record:r,held=Array.isArray(r&&r.restricted)?r.restricted.map(function(s){return typeof s==='string'?s:(s&&typeof s.section==='string'?s.section:null)}).filter(function(s){return typeof s==='string'&&/^[a-z_]{1,40}$/.test(s)}):[];/* the API emits {section,capability} (gateway/src/vulns.js); plain strings are accepted too */
 if(!rec||rec.found===false)return show(x().nf);
 ['aliases','disputed_aliases','weaknesses','severity','affected','advisories','detections','indicators','poc_references'].forEach(function(k){var v=rec[k];
  if(v&&typeof v==='object'&&!Array.isArray(v)&&v.restricted===true){held.push(k);rec[k]=[]}});
 $('vbody').textContent='';var box=el('section',{class:'panel'});$('vbody').appendChild(box);
 if(!MG.renderVuln(box,rec,MG.L(),held)){$('vbody').textContent='';return show(x().fail,'badmsg')}$('vstate').hidden=true}
function show(msg,cls){var s=$('vstate');s.hidden=false;s.textContent=msg;s.className='state'+(cls?' '+cls:'')}
function load(){var t=x();id=MG.vulnKind(new URLSearchParams(location.search).get('id'));
 if(!id||id.kind==='CWE'){$('vbody').textContent='';return show(t.bad)}
 $('vid').textContent=id.id;document.title=id.id+' · MacGuard';
 if(API)return MG.getT(API+'/v1/vulns/'+encodeURIComponent(id.id),10000).then(function(r){state={api:r};apiPage(r)},function(){show(x().fail,'badmsg')});
 if(id.kind!=='CVE')return show(t.needapi);
 return MG.kev.index().then(function(idx){return MG.kev.get(id.id).then(function(it){state={kev:it,idx:idx};if(!it){$('vbody').textContent='';return show(x().notkev(idx.source&&idx.source.catalog_version))}
  $('vstate').hidden=true;kevPage(it,idx)})},function(){show(x().off)})}
MG.i18n(D,function(){if(!state)return;if(state.api)apiPage(state.api);else if(state.kev)kevPage(state.kev,state.idx);else if(state.idx)show(x().notkev(state.idx.source&&state.idx.source.catalog_version))});
load();
})();
