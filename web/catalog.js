/* Catalog of families: reads families.json (built by scripts/portal.py). Only a PUBLISHED family shows numbers or a download. textContent only. */
(function(){var $=MG.$,el=MG.el;
var D={es:{},en:{h:'Rules and intelligence library',intro:'Every rule, indicator and vulnerability family of the portal, with its real state. Numbers and downloads are shown only for what is published and verified.',free_h:'Published today',fam_h:'All families',cap:'Portal families and their state',c_name:'Family',c_group:'Type',c_tier:'Plan',c_state:'State',c_dl:'Package',c_up:'Upstream',loading:'Loading…',yarax:'YARA-X is a compatibility engine, not a rule collection.'}};
var X={es:{fail:'No se pudo cargar families.json',none:'Sin paquete verificado disponible',files:'ficheros de reglas',rules:'reglas YARA',open:'Abrir catálogo de reglas',records:'vulnerabilidades del catálogo',search:'Buscar en el catálogo KEV',pkgs:'Ver paquetes',asof:'Estado según la configuración del',nothing:'Todavía no hay ninguna familia publicada.',
 g:{detections:'Detección',indicators:'Indicadores',vulnerabilities:'Vulnerabilidades',context:'Contexto'},
 s:{PUBLISHED:'Publicado y firmado',RETAINED:'Retenido (pendiente de aprobación de fuente y licencia)',NO_DATA:'Sin datos vigentes',BLOCKED:'Bloqueado (sin conector aprobado)',NOT_INTEGRATED:'No integrado',ENGINE_ONLY:'Motor de compatibilidad, no se distribuye',NOT_CONFIGURED:'No configurado todavía',NOT_PUBLISHED:'No publicado'}},
 en:{fail:'Could not load families.json',none:'No verified package available',files:'rule files',rules:'YARA rules',open:'Open the rule catalog',records:'vulnerabilities in the catalogue',search:'Search the KEV catalogue',pkgs:'See packages',asof:'State as configured on',nothing:'No family is published yet.',
 g:{detections:'Detection',indicators:'Indicators',vulnerabilities:'Vulnerabilities',context:'Context'},
 s:{PUBLISHED:'Published and signed',RETAINED:'Retained (source and licence approval pending)',NO_DATA:'No current data',BLOCKED:'Blocked (no approved connector)',NOT_INTEGRATED:'Not integrated',ENGINE_ONLY:'Compatibility engine, not distributed',NOT_CONFIGURED:'Not configured yet',NOT_PUBLISHED:'Not published'}}};
var data=null,x=function(){return X[MG.L()]||X.es};
function render(){if(!data)return;var t=x(),pub=$('published');pub.textContent='';
 var p=data.families.filter(function(f){return f.state==='PUBLISHED'&&f.package});
 if(!p.length)pub.appendChild(el('p',{text:t.nothing}));
 p.forEach(function(f){var k=f.package;pub.appendChild(el('h3',{text:f.name+' · '+f.tier}));
  pub.appendChild(el('p',{text:(k.files!=null?k.files+' '+t.files:'')+(k.yara_rules!=null?' · '+k.yara_rules+' '+t.rules:'')+(k.records!=null?k.records+' '+t.records:'')+(k.tag?' · '+k.tag:'')+(k.package_bytes?' · '+MG.bytes(k.package_bytes):'')}));
  pub.appendChild(el('p',{class:'muted',text:k.source}));
  var ul=el('ul',{class:'dl'});[[f.id==='yara_community'?'rules.html':f.id==='cisa_kev'?'vulnerabilities.html':null,f.id==='cisa_kev'?t.search:t.open],['packages.html',t.pkgs],[k.manifest,'manifest.json'],[k.signature,'manifest.sigstore.json'],[k.inclusion_proof,'inclusion-proof.json']].forEach(function(a){if(a[0])ul.appendChild(el('li',{},[el('a',{href:a[0],text:a[1]})]))});pub.appendChild(ul)});
 var tb=document.querySelector('#fam-table tbody');tb.textContent='';
 data.families.forEach(function(f){var tr=el('tr');tr.appendChild(el('td',{text:f.name}));tr.appendChild(el('td',{text:t.g[f.group]||f.group}));tr.appendChild(el('td',{text:f.tier}));
  tr.appendChild(el('td',{class:f.state==='PUBLISHED'?'okmsg':'',text:t.s[f.state]||f.state}));
  var td=el('td');if(f.state==='PUBLISHED'&&f.package)td.appendChild(el('a',{href:'packages.html',text:t.pkgs}));else td.appendChild(el('span',{class:'muted',text:t.none}));tr.appendChild(td);
  tr.appendChild(el('td',{class:'muted',text:f.upstream||'—'}));tb.appendChild(tr)});
 $('fam-state').textContent=data.as_of?t.asof+' '+MG.day(data.as_of)+' (config/intel-families.json)':''}
MG.i18n(D,render);
MG.getT('families.json').then(function(d){data=d;render()}).catch(function(){$('published').textContent=x().fail});
})();
