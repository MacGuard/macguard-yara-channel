/* Threat Intelligence Hub on the home page: hero search (identifier auto-detection), real stats, integrity and recent publications from hub.json
   (built by scripts/portal_hub.py from verified releases and packages only). textContent only; nothing is shown that the build did not verify. */
(function(){var $=MG.$,el=MG.el;
var X={es:{sub:'Busca una vulnerabilidad, una regla o un indicador. Solo se muestran datos de fuentes aprobadas y paquetes verificados.',ql:'Buscar',go:'Buscar',
  kind:function(k){return k.kind==='TEXT'?'Texto libre: se buscará por fabricante, producto, versión o nombre de regla.':'Tipo detectado: '+k.kind+' · '+k.id},bad:'Escribe un identificador (CVE, EUVD, GCVE, GHSA, CWE, hash, SID) o un texto.',
  stats_h:'Datos publicados',int_h:'Integridad',rec_h:'Publicaciones recientes',int_more:'Ver transparencia',rec_more:'Todas las descargas',load:'Cargando…',fail:'No se pudo cargar hub.json: no se muestra ningún dato.',
  yara_files:'ficheros de reglas YARA Community',yara_rules:'reglas YARA',kev:'vulnerabilidades del catálogo CISA KEV',kev_na:'CISA KEV: no disponible (sin paquete verificado en esta publicación)',
  latest:'Última release YARA',sig:'Firma del manifiesto',valid:'válida (cosign)',invalid:'NO válida',notchecked:'no comprobada',cons:'Prueba de consistencia del registro',yes:'publicada',no:'no publicada',
  intel:'Paquetes de inteligencia verificados en esta publicación',src:'Fuente: ',none:'Todavía no hay publicaciones.',
  free_h:'FREE · Community',free_p:'Búsqueda y fichas públicas de vulnerabilidades (CVSS, EPSS, KEV, CWE cuando la fuente está aprobada) y el paquete YARA Community firmado.',
  prem_h:'PREMIUM · Inteligencia',prem_p:'Sigma, Suricata, IOC enriquecidos, correlaciones y paquetes profesionales, autorizados en el servidor. Hoy en vista previa abierta (OPEN_PREMIUM_PREVIEW): sin cobros.',
  fam:{yara_community:'YARA Community','vulnerability-data':'Datos de vulnerabilidades'}},
 en:{sub:'Search for a vulnerability, a rule or an indicator. Only data from approved sources and verified packages is shown.',ql:'Search',go:'Search',
  kind:function(k){return k.kind==='TEXT'?'Free text: searched by vendor, product, version or rule name.':'Detected kind: '+k.kind+' · '+k.id},bad:'Type an identifier (CVE, EUVD, GCVE, GHSA, CWE, hash, SID) or some text.',
  stats_h:'Published data',int_h:'Integrity',rec_h:'Recent publications',int_more:'See transparency',rec_more:'All downloads',load:'Loading…',fail:'Could not load hub.json: no data is shown.',
  yara_files:'YARA Community rule files',yara_rules:'YARA rules',kev:'vulnerabilities in the CISA KEV catalogue',kev_na:'CISA KEV: not available (no verified package in this publication)',
  latest:'Latest YARA release',sig:'Manifest signature',valid:'valid (cosign)',invalid:'NOT valid',notchecked:'not checked',cons:'Log consistency proof',yes:'published',no:'not published',
  intel:'Intelligence packages verified in this publication',src:'Source: ',none:'No publications yet.',
  free_h:'FREE · Community',free_p:'Public vulnerability search and pages (CVSS, EPSS, KEV, CWE where the source is approved) and the signed YARA Community package.',
  prem_h:'PREMIUM · Intelligence',prem_p:'Sigma, Suricata, enriched IOCs, correlations and professional packages, authorised on the server. Today in open preview (OPEN_PREMIUM_PREVIEW): no charges.',
  fam:{yara_community:'YARA Community','vulnerability-data':'Vulnerability data'}}};
var x=function(){var l=MG.L()||MG.lang();return X[l]||(l==='es'?X.es:X.en)},hub=null,failed=false;
var IDS={sub:'hub-sub',ql:'hub-ql',go:'hub-go',stats_h:'hub-stats-h',int_h:'hub-int-h',rec_h:'hub-rec-h',int_more:'hub-int-more',rec_more:'hub-rec-more',free_h:'hub-free-h',free_p:'hub-free-p',prem_h:'hub-prem-h',prem_p:'hub-prem-p'};
function tile(box,n,label,src){var a=el('article');a.appendChild(el('strong',{text:String(n)}));a.appendChild(el('span',{text:label}));if(src)a.setAttribute('title',src);box.appendChild(a)}
function render(){var t=x();Object.keys(IDS).forEach(function(k){var e=$(IDS[k]);if(e)e.textContent=t[k]});
 var st=$('hub-stats'),it=$('hub-int'),rc=$('hub-rec');if(!st)return;st.textContent='';it.textContent='';rc.textContent='';
 if(failed){st.appendChild(el('p',{class:'badmsg',text:t.fail}));return}
 if(!hub){st.appendChild(el('p',{class:'muted',text:t.load}));return}
 var y=hub.stats&&hub.stats.yara,k=hub.stats&&hub.stats.kev,srcs=[];
 if(y){if(y.files!=null)tile(st,y.files,t.yara_files,y.source);if(y.yara_rules!=null)tile(st,y.yara_rules,t.yara_rules,y.source);srcs.push(y.source)}
 if(k&&k.records!=null){tile(st,k.records,t.kev+(k.catalog_version?' (v'+k.catalog_version+')':''),k.source);srcs.push(k.source)}else st.appendChild(el('p',{class:'muted',text:t.kev_na}));
 $('hub-stats-src').textContent=srcs.length?t.src+srcs.join(' · '):'';
 var g=hub.integrity||{},sig=g.latest_signature==='valid'?t.valid:g.latest_signature==='not_checked'||!g.latest_signature?t.notchecked:t.invalid;
 if(g.latest_tag)it.appendChild(el('li',{text:t.latest+': '+g.latest_tag}));
 it.appendChild(el('li',{class:g.latest_signature==='valid'?'okmsg':'',text:t.sig+': '+sig}));
 it.appendChild(el('li',{text:t.cons+': '+(g.consistency_proof?t.yes:t.no)}));
 if(g.intel_packages_verified!=null)it.appendChild(el('li',{text:t.intel+': '+g.intel_packages_verified}));
 var r=hub.recent||[];if(!r.length)rc.appendChild(el('li',{text:t.none}));
 r.forEach(function(p){var li=el('li');if(p.url&&/^https:\/\//.test(p.url))li.appendChild(el('a',{href:p.url,text:p.tag}));else li.appendChild(el('span',{text:p.tag}));
  li.appendChild(document.createTextNode(' · '+(t.fam[p.family]||p.family)+' · '+MG.day(p.published_at)+' · '+(p.signature==='valid'?t.valid:p.signature==='not_checked'?t.notchecked:t.invalid)));rc.appendChild(li)})}
var q=$('hub-q'),kind=$('hub-kind');
if(q){q.addEventListener('input',function(){var k=MG.idKind(q.value);kind.textContent=q.value.trim()?(k?x().kind(k):x().bad):''});
 $('hub-form').addEventListener('submit',function(ev){ev.preventDefault();var k=MG.idKind(q.value);if(!k){kind.textContent=x().bad;return}
  // a vulnerability identifier opens its page; anything else (text, hash, SID, CWE list) goes to the explorer
  location.href=MG.VULN_KINDS.indexOf(k.kind)>=0&&k.kind!=='CWE'?'vuln.html?id='+encodeURIComponent(k.id):'vulnerabilities.html?q='+encodeURIComponent(k.id)})}
var sel=$('lang');if(sel)sel.addEventListener('change',render);
render();
MG.getT('hub.json').then(function(d){hub=d&&d.schema==='macguard.portal-hub/1'?d:null;failed=!hub;render()}).catch(function(){failed=true;render()});
})();
