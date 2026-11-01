/* Vulnerability explorer. Two modes, never mixed:
   - API (macguard.intel-search/1) when <meta name="mg-vuln-api"> holds a plain https base: bounded, parameterised, keyset-paged queries; the browser
     never downloads the catalogue. Restricted (Premium) sections arrive already withheld by the server.
   - Static KEV (kevstatic.js) otherwise: the CISA KEV catalogue only, from a package verified in this build. CVSS, EPSS, rules and access filters need
     the API and are disabled. If no verified KEV package exists either, the page says so and shows nothing.
   Every value is written with textContent; null/absent is "No disponible", never 0. */
(function(){var $=MG.$,el=MG.el;
var D={es:{},en:{h:'Vulnerability explorer',intro:'Search by CVE, EUVD, GCVE, GHSA or CWE, by vendor, product or version, or by hash or SID. Only data from approved sources is shown; an unavailable source is marked as such.',
 s_h:'Search',q_l:'Identifier or text',f_vendor:'Vendor',f_product:'Product',f_cwe:'CWE',f_kev:'CISA KEV',any:'Any',kev_only:'Only in KEV',f_from:'From',f_to:'To',f_cvss_min:'CVSS min.',f_cvss_max:'CVSS max.',
 f_epss:'EPSS min. (0–1)',f_rules:'Rules',with_rules:'With verified rules',f_source:'Source',f_access:'Access',go:'Search',reset:'Clear',r_h:'Results',cap:'Vulnerabilities found',c_id:'Identifier',c_title:'Name',
 c_vp:'Vendor · product',c_kev:'KEV',c_rules:'Rules',c_access:'Access',prev:'Previous',next:'Next',k_h:'How to read the data',k1:'CVSS measures technical severity; there can be several scores from different sources and versions.',
 k2:'EPSS is an estimated probability of exploitation in the next 30 days, not a severity.',k3:'"Not in KEV" does not mean "not being exploited".',k4:'If there is no verified rule for a vulnerability, the page says so; it is never invented.'}};
var X={es:{kind:function(k){return k.kind==='TEXT'?'Texto libre':'Tipo detectado: '+k.kind+' · '+k.id},bad:'Formato no reconocido.',
  api:'Consulta en el servicio de inteligencia (paginada en el servidor).',stat:function(v){return 'Catálogo CISA KEV, búsqueda estática'+(v?' (versión '+v+')':'')+'. No incluye NVD, EUVD ni GCVE; CVSS, EPSS, reglas y acceso requieren el servicio de consulta, aún no publicado.'},
  off:'No hay servicio de consulta publicado ni paquete KEV verificado en esta publicación: no se muestra ningún dato.',needapi:'Este tipo de búsqueda requiere el servicio de consulta, aún no publicado. En la búsqueda estática solo hay CVE del catálogo CISA KEV.',
  load:'Cargando…',fail:'La consulta no se pudo completar. No se muestra ningún dato.',none:'Sin resultados.',cont:'Sin coincidencias en los años revisados; pulsa «Siguiente» para seguir buscando en años anteriores.',n:function(n,more){return n+' resultado(s) en esta página'+(more?'; hay más':'')},page:function(p){return 'Página '+p},
  na:'No disponible',kev_y:'En KEV desde ',kev_n:'No figura',kev_u:'Desconocido',rules_y:'Sí',rules_n:'Sin regla verificada',src_na:'fuente no disponible',src_ok:'disponible',src_h:'Fuentes: ',
  states:{APPROVED:'aprobada',RETAINED:'retenida (licencia o aprobación pendiente)',BLOCKED:'bloqueada',UNAVAILABLE:'no disponible'}},
 en:{kind:function(k){return k.kind==='TEXT'?'Free text':'Detected kind: '+k.kind+' · '+k.id},bad:'Unrecognised format.',
  api:'Query on the intelligence service (paged on the server).',stat:function(v){return 'CISA KEV catalogue, static search'+(v?' (version '+v+')':'')+'. It does not include NVD, EUVD or GCVE; CVSS, EPSS, rules and access need the lookup service, not published yet.'},
  off:'No lookup service is published and there is no verified KEV package in this publication: no data is shown.',needapi:'This kind of search needs the lookup service, not published yet. The static search only holds CVEs of the CISA KEV catalogue.',
  load:'Loading…',fail:'The query could not be completed. No data is shown.',none:'No results.',cont:'No matches in the years searched so far; press “Next” to keep searching earlier years.',n:function(n,more){return n+' result(s) on this page'+(more?'; there are more':'')},page:function(p){return 'Page '+p},
  na:'Not available',kev_y:'In KEV since ',kev_n:'Not listed',kev_u:'Unknown',rules_y:'Yes',rules_n:'No verified rule',src_na:'source not available',src_ok:'available',src_h:'Sources: ',
  states:{APPROVED:'approved',RETAINED:'retained (licence or approval pending)',BLOCKED:'blocked',UNAVAILABLE:'not available'}}};
var x=function(){return X[MG.L()]||X.es},API=MG.apiBase(),mode=API?'api':'static',kevIdx=null,srcs=null,stack=[],cur=null,last=null,gen=0;   /* every search or reset starts a new generation; an answer from an older one is dropped (Codex pr81 F2) */
var F=['vendor','product','cwe','kev','date_from','date_to','cvss_min','cvss_max','epss_min','has_rules','source','access'],FID={vendor:'f-vendor',product:'f-product',cwe:'f-cwe',kev:'f-kev',date_from:'f-from',date_to:'f-to',cvss_min:'f-cvss-min',cvss_max:'f-cvss-max',epss_min:'f-epss',has_rules:'f-rules',source:'f-source',access:'f-access'};
function filters(){var f={},k=MG.idKind($('vq').value);F.forEach(function(n){var v=String($(FID[n]).value||'').trim();if(v)f[n]=v});
 if(f.cwe){var c=MG.idKind(f.cwe);f.cwe=c&&c.kind==='CWE'?c.id:null;if(!f.cwe)delete f.cwe}
 ['cvss_min','cvss_max'].forEach(function(n){if(f[n]!=null){var v=Number(f[n]);if(!(v>=0&&v<=10))delete f[n];else f[n]=String(v)}});
 if(f.epss_min!=null){var e=Number(f.epss_min);if(!(e>=0&&e<=1))delete f.epss_min;else f.epss_min=String(e)}
 ['date_from','date_to'].forEach(function(n){if(f[n]&&!/^\d{4}-\d{2}-\d{2}$/.test(f[n]))delete f[n]});
 return {k:k,f:f}}
function cell(tr,v,cls){tr.appendChild(el('td',cls?{class:cls,text:v}:{text:v}))}
function idCell(tr,id){var td=el('td');if(MG.vulnKind(id))td.appendChild(el('a',{href:'vuln.html?id='+encodeURIComponent(id),text:id}));else td.textContent=id;tr.appendChild(td)}
function rowsApi(items){var t=x(),tb=document.querySelector('#vtable tbody');tb.textContent='';
 items.forEach(function(it){var tr=el('tr');idCell(tr,String(it.id||''));cell(tr,MG.na(it.title,MG.L()));cell(tr,[it.vendor,it.product].filter(Boolean).join(' · ')||t.na);
  var k=it.kev||{};cell(tr,k.status==='LISTED'?t.kev_y+MG.na(k.date_added,MG.L()):k.status==='NOT_LISTED'?t.kev_n:t.kev_u);
  var c=it.cvss||{};cell(tr,c.max_score!=null?String(c.max_score)+(c.version?' (v'+c.version+(c.source?', '+c.source:'')+')':''):t.na);
  var e=it.epss||{};cell(tr,e.probability!=null?String(e.probability)+(e.score_date?' · '+e.score_date:''):t.na);
  cell(tr,(it.cwes||[]).join(', ')||t.na);cell(tr,it.has_rules===true?t.rules_y:it.has_rules===false?t.rules_n:t.na);
  var held=(it.access&&it.access.restricted_sections)||[];cell(tr,held.length?'PREMIUM: '+held.join(', '):'FREE',held.length?'':'');tb.appendChild(tr)})}
function rowsStatic(items){var t=x(),tb=document.querySelector('#vtable tbody');tb.textContent='';
 items.forEach(function(it){var tr=el('tr');idCell(tr,it.cve_id);cell(tr,MG.na(it.name,MG.L()));cell(tr,[it.vendor,it.product].filter(Boolean).join(' · ')||t.na);
  cell(tr,t.kev_y+MG.na(it.date_added,MG.L()));cell(tr,t.na);cell(tr,t.na);cell(tr,(it.cwes||[]).join(', ')||t.na);cell(tr,t.rules_n);cell(tr,'FREE');tb.appendChild(tr)})}
function setState(msg,cls){var m=$('vmode');m.textContent=msg;m.className='state'+(cls?' '+cls:'')}
function pager(more){$('vprev').disabled=stack.length===0;$('vnext').disabled=!more;$('vpage').textContent=x().page(stack.length+1)}
function sources(list){var ul=$('vsources'),t=x();ul.textContent='';if(!list||!list.length)return;ul.appendChild(el('li',{class:'muted',text:t.src_h}));
 list.forEach(function(s){var st=s.status||s.approval_state;ul.appendChild(el('li',{text:(s.name||s.id)+': '+(t.states[st]||st||t.src_na)}))})}
function run(cursor){var q=filters(),t=x();$('vkind').textContent=$('vq').value.trim()?(q.k?t.kind(q.k):t.bad):'';
 if($('vq').value.trim()&&!q.k)return;var g=++gen;$('vcount').textContent=t.load;cur=cursor||null;
 var p=mode==='api'?searchApi(q,cursor,g):searchStatic(q,cursor,g);
 p.then(function(r){if(g!==gen||!r)return;last=r;$('vcount').textContent=r.items.length?t.n(r.items.length,!!r.next):(r.next?t.cont:t.none);pager(!!r.next)},function(){if(g!==gen)return;
  document.querySelector('#vtable tbody').textContent='';$('vcount').textContent='';setState(t.fail,'badmsg');pager(false)})}
/* only the parameters the gateway accepts (macguard.intel-search/1); the access level is not a server filter (the server decides what each caller may see) */
var API_PARAMS=['kev','cwe','vendor','product','cvss_min','cvss_max','epss_min','date_from','date_to','has_rules','has_iocs','source'];
function searchApi(q,cursor,g){var u=new URLSearchParams();if(q.k)u.set('q',q.k.id);Object.keys(q.f).forEach(function(n){if(API_PARAMS.indexOf(n)>=0)u.set(n,q.f[n])});u.set('limit','25');if(cursor)u.set('cursor',cursor);
 return MG.getT(API+'/v1/vulns/search?'+u.toString(),10000).then(function(r){if(!r||r.schema!=='macguard.intel-search/1'||!Array.isArray(r.items))throw new Error('contract');
  if(g!==gen)return null;
  var acc=q.f.access,items=r.items.slice(0,100).filter(function(it){var rs=it&&it.access&&Array.isArray(it.access.restricted_sections)?it.access.restricted_sections:[];return !acc||(acc==='premium'?rs.length>0:rs.length===0)});   /* access: a view filter on this page only */
  rowsApi(items);sources(r.sources);setState(x().api);
  return {items:r.items,next:typeof r.next_cursor==='string'&&r.next_cursor.length<=512?r.next_cursor:null}})}
function searchStatic(q,cursor,g){var t=x();
 if(!kevIdx){document.querySelector('#vtable tbody').textContent='';setState(t.off);return Promise.resolve({items:[],next:null})}
 if(q.k&&q.k.kind!=='CVE'&&q.k.kind!=='TEXT'&&q.k.kind!=='CWE'){document.querySelector('#vtable tbody').textContent='';setState(t.needapi);return Promise.resolve({items:[],next:null})}
 var f={vendor:q.f.vendor,product:q.f.product,cwe:q.f.cwe,date_from:q.f.date_from,date_to:q.f.date_to};
 if(q.k&&q.k.kind==='CVE')f.cve=q.k.id;else if(q.k&&q.k.kind==='CWE')f.cwe=q.k.id;else if(q.k)f.text=q.k.id;
 return MG.kev.search(f,cursor,25).then(function(r){if(g!==gen)return null;rowsStatic(r.items);setState(t.stat(kevIdx.source&&kevIdx.source.catalog_version));return {items:r.items,next:r.next}})}
function apply(){if(mode==='static'){var dis=['f-cvss-min','f-cvss-max','f-epss','f-rules','f-source','f-access'];dis.forEach(function(i){$(i).disabled=true});$('api-filters').setAttribute('aria-disabled','true')}
 if(last){if(mode==='api')run(cur);else run(cur)}else if(mode==='static'&&!kevIdx)setState(x().off)}
MG.i18n(D,function(){if(document.readyState!=='loading')apply()});
$('vform').addEventListener('submit',function(ev){ev.preventDefault();stack=[];run(null)});
$('vform').addEventListener('reset',function(){gen++;setTimeout(function(){stack=[];last=null;document.querySelector('#vtable tbody').textContent='';$('vcount').textContent='';$('vkind').textContent='';pager(false)},0)});
$('vnext').addEventListener('click',function(){if(!last||!last.next)return;stack.push(cur);run(last.next)});
$('vprev').addEventListener('click',function(){if(!stack.length)return;run(stack.pop())});
var init=new URLSearchParams(location.search).get('q');if(init&&init.length<=128)$('vq').value=init;
(mode==='api'?MG.getT(API+'/v1/vulns/sources',8000).then(function(r){srcs=r&&Array.isArray(r.sources)?r.sources:null;
  if(srcs){var sel=$('f-source');srcs.forEach(function(s){if(/^[a-z0-9._-]{1,64}$/.test(s.id))sel.appendChild(el('option',{value:s.id,text:s.name||s.id}))})}sources(srcs)},function(){})
 :Promise.all([MG.kev.index().then(function(d){kevIdx=d},function(){kevIdx=null}),MG.getT('sources.json').then(function(d){srcs=d&&Array.isArray(d.sources)?d.sources:null;sources(srcs)},function(){})]))
 .then(function(){apply();if(init)run(null);else if(mode==='static'&&kevIdx){setState(x().stat(kevIdx.source&&kevIdx.source.catalog_version));run(null)}});
pager(false);
})();
