/* Renders ONE vulnerability record of contract macguard.intel-vulnerability/1 (contracts/v1/intel-vulnerability.schema.json, R1) with textContent only.
   The API that will serve it is not published yet; vulns.js calls this only when a service base is configured. A response that does not look like the
   contract is not shown at all (no partial or guessed data). Missing data stays "not available": never zero. */
(function(){var el=MG.el;
var ID=/^(CVE-[0-9]{4}-[0-9]{4,}|EUVD-[0-9]{4}-[0-9]+|GCVE-[0-9]{1,10}-[0-9]{4}-[0-9]+|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$/;
var LISTS=['aliases','disputed_aliases','weaknesses','severity','affected','advisories','detections','indicators','poc_references'];
MG.vulnRecordOk=function(r){if(!r||typeof r!=='object'||r.schema!=='macguard.intel-vulnerability/1'||typeof r.id!=='string'||!ID.test(r.id))return false;
 if(['cve','euvd','gcve','ghsa'].indexOf(r.namespace)<0)return false;for(var i=0;i<LISTS.length;i++)if(!Array.isArray(r[LISTS[i]]))return false;
 var e=r.exploitation;if(!e||!e.kev||['LISTED','NOT_LISTED','UNKNOWN'].indexOf(e.kev.status)<0||['EVIDENCE_RECORDED','NO_EVIDENCE_RECORDED'].indexOf(e.evidence_status)<0)return false;
 if(r.poc_references.some(function(p){return p.executable_content!==false}))return false;   // the contract forbids executable content: refuse the whole record
 return r.epss===null||(r.epss&&typeof r.epss.probability==='number'&&r.epss.probability>=0&&r.epss.probability<=1&&typeof r.epss.percentile==='number'&&/^\d{4}-\d{2}-\d{2}$/.test(r.epss.score_date))};
var T={es:{bad:'La respuesta no cumple el contrato macguard.intel-vulnerability/1: no se muestra ningún dato.',ids:'Identificadores',alias:'Equivalencias declaradas por una fuente',disp:'Equivalencias en disputa (no se fusionan)',none:'No disponible',
 cwe:'Debilidades (CWE)',cvss:'CVSS por fuente',noscore:'la fuente no proporciona puntuación',epss:'EPSS',epssm:'probabilidad estimada de explotación en los próximos 30 días (no es una gravedad)',pct:'percentil',
 kev:'CISA KEV',LISTED:'Incluida en KEV',NOT_LISTED:'No figura en KEV a fecha de',UNKNOWN:'Sin dato de KEV (fuente no disponible)',notexp:'No figurar en KEV no significa que no se esté explotando.',added:'añadida',due:'fecha límite',ev:'Evidencias de explotación',noev:'Sin evidencias registradas (no implica ausencia de explotación).',
 aff:'Productos y versiones afectados',adv:'Avisos',det:'Reglas de detección',nodet:'Sin regla verificada disponible',ioc:'Indicadores',poc:'Referencias de PoC (solo metadatos; nunca se ejecutan ni se descargan desde aquí)',
 restricted:'Hay información Premium para esta vulnerabilidad que tu acceso no incluye.',lv:{'related':'relacionada','compatible':'compatible','detects-behaviour':'detecta comportamiento','claimed-detection':'detección declarada por la fuente','validated-detection':'detección validada con pruebas'},src:'fuente'},
 en:{bad:'The answer does not match contract macguard.intel-vulnerability/1: no data is shown.',ids:'Identifiers',alias:'Equivalences asserted by a source',disp:'Disputed equivalences (never merged)',none:'Not available',
 cwe:'Weaknesses (CWE)',cvss:'CVSS by source',noscore:'the source provides no score',epss:'EPSS',epssm:'estimated probability of exploitation in the next 30 days (not a severity)',pct:'percentile',
 kev:'CISA KEV',LISTED:'Listed in KEV',NOT_LISTED:'Not in KEV as of',UNKNOWN:'No KEV data (source unavailable)',notexp:'Not being in KEV does not mean it is not exploited.',added:'added',due:'due date',ev:'Exploitation evidence',noev:'No evidence recorded (this does not mean it is not exploited).',
 aff:'Affected products and versions',adv:'Advisories',det:'Detection rules',nodet:'No verified rule available',ioc:'Indicators',poc:'PoC references (metadata only; never run or downloaded from here)',
 restricted:'There is Premium information for this vulnerability that your access does not include.',lv:{'related':'related','compatible':'compatible','detects-behaviour':'detects behaviour','claimed-detection':'detection claimed by the source','validated-detection':'detection validated by tests'},src:'source'}};
function sec(box,title,items,empty){box.appendChild(el('h3',{text:title}));if(!items.length){box.appendChild(el('p',{class:'muted',text:empty}));return}var ul=el('ul');items.forEach(function(t){ul.appendChild(el('li',{text:t}))});box.appendChild(ul)}
/* restricted: list of withheld sections the API declared (e.g. ['detections','indicators']); their absence is then never shown as "none exists". */
MG.renderVuln=function(box,r,lang,restricted){var t=T[lang]||T.es;box.textContent='';restricted=restricted||[];
 if(!MG.vulnRecordOk(r)){box.appendChild(el('p',{class:'badmsg',text:t.bad}));return false}
 box.appendChild(el('h2',{text:r.id+(r.title?' · '+r.title:'')}));if(r.summary)box.appendChild(el('p',{text:r.summary}));
 if(r.published||r.modified)box.appendChild(el('p',{class:'muted',text:[r.published?'published '+String(r.published).slice(0,10):'',r.modified?'modified '+String(r.modified).slice(0,10):''].filter(Boolean).join(' · ')}));
 sec(box,t.alias,r.aliases.map(function(a){return a.id+' · '+t.src+': '+a.source+' ('+a.confidence+')'}),t.none);
 if(r.disputed_aliases.length)sec(box,t.disp,r.disputed_aliases.map(function(a){return a.id+' · '+t.src+': '+a.source+' ('+a.confidence+')'}),t.none);
 sec(box,t.cwe,r.weaknesses.map(function(w){return w.cwe+' · '+t.src+': '+w.source}),t.none);
 sec(box,t.cvss,r.severity.map(function(s){return 'CVSS '+s.cvss_version+' · '+(s.availability==='AVAILABLE'?s.base_score+' '+s.severity+' · '+s.vector:t.noscore)+' · '+t.src+': '+s.source+' · '+String(s.assessed_at).slice(0,10)}),t.none);
 box.appendChild(el('h3',{text:t.epss}));box.appendChild(el('p',r.epss?{text:(Math.round(r.epss.probability*10000)/100)+'% · '+t.pct+' '+(Math.round(r.epss.percentile*1000)/10)+' · '+r.epss.score_date+' · '+t.src+': '+r.epss.source+' — '+t.epssm}:{class:'muted',text:t.none}));
 var k=r.exploitation.kev;box.appendChild(el('h3',{text:t.kev}));
 box.appendChild(el('p',{text:k.status==='LISTED'?t.LISTED+(k.date_added?' · '+t.added+' '+k.date_added:'')+(k.due_date?' · '+t.due+' '+k.due_date:''):k.status==='NOT_LISTED'?t.NOT_LISTED+' '+String(k.as_of||'').slice(0,10):t.UNKNOWN}));
 if(k.status!=='LISTED')box.appendChild(el('p',{class:'muted',text:t.notexp}));
 sec(box,t.ev,r.exploitation.evidence.map(function(e){return e.kind+' · '+t.src+': '+e.source+' · '+String(e.observed_at).slice(0,10)}),t.noev);
 sec(box,t.aff,r.affected.map(function(a){return a.product.key+' · '+a.scheme+(a.introduced?' ≥'+a.introduced:'')+(a.fixed?' <'+a.fixed:'')+(a.last_affected?' ≤'+a.last_affected:'')+' · '+t.src+': '+a.source}),t.none);
 sec(box,t.adv,r.advisories.map(function(a){return a.id+' · '+t.src+': '+a.source}),t.none);
 [['detections',t.det,function(d){return d.rule+' · '+d.family+' · '+(t.lv[d.level]||d.level)+' · '+d.verification},t.nodet],['indicators',t.ioc,function(i){return i.type+' '+i.value+' · '+t.src+': '+i.source},t.none]].forEach(function(s){
  var held=restricted.indexOf(s[0])>=0;sec(box,s[1],r[s[0]].map(s[2]),held?t.restricted:s[3])});
 if(r.poc_references.length)sec(box,t.poc,r.poc_references.map(function(p){return p.ref+' · '+t.src+': '+p.source+' · '+p.review}),t.none);   // plain text: never a link, never embedded
 return true};
})();
