/* Indicators page: the REAL state of every indicator family (families.json, built from config + verified packages). No counts, no downloads,
   no sample data unless a family is published and verified. textContent only. */
(function(){var $=MG.$,el=MG.el;
var D={es:{},en:{h:'Indicators',intro:'Sample hashes, network IOCs (IP, domains, URLs), certificates and fingerprints, and related signatures, with their source and provenance. They are PREMIUM content and will be served only after an authorisation checked on the server.',
 st_h:'Current state',loading:'Loading…',cap:'Indicator families and their state',c_name:'Family',c_tier:'Plan',c_state:'State',c_dl:'Data',c_up:'Upstream',pv_h:'Provenance and use',
 p1:'A sample hash identifies a known malicious file; it is not the verification hash of a download. MD5 and SHA-1 are kept only as legacy identifiers, never as a cryptographic guarantee.',
 p2:'Every indicator will keep its source, its licence, the date it was observed and its confidence; no indicator is published without an approved source.',
 p3:'An indicator does not become a "detection" of a vulnerability without a reviewed relationship.',p4:'No samples or executable code are distributed.'}};
var X={es:{none:'NO DISPONIBLE: no hay ninguna fuente de indicadores aprobada ni ningún paquete verificado.',some:function(n){return n+' familia(s) publicada(s) y verificada(s).'},fail:'No se pudo cargar families.json: no se muestra ningún dato.',na:'No disponible',
  s:{PUBLISHED:'Publicado y firmado',RETAINED:'Retenido (fuente o licencia pendiente)',NO_DATA:'Sin datos vigentes',BLOCKED:'Bloqueado (sin conector aprobado)',NOT_INTEGRATED:'No integrado',NOT_CONFIGURED:'No configurado todavía',NOT_PUBLISHED:'No publicado'}},
 en:{none:'NOT AVAILABLE: there is no approved indicator source and no verified package.',some:function(n){return n+' family(ies) published and verified.'},fail:'Could not load families.json: no data is shown.',na:'Not available',
  s:{PUBLISHED:'Published and signed',RETAINED:'Retained (source or licence pending)',NO_DATA:'No current data',BLOCKED:'Blocked (no approved connector)',NOT_INTEGRATED:'Not integrated',NOT_CONFIGURED:'Not configured yet',NOT_PUBLISHED:'Not published'}}};
var x=function(){return X[MG.L()]||X.es},data=null,failed=false;
function render(){var t=x(),s=$('istate'),tb=document.querySelector('#itable tbody');tb.textContent='';
 if(failed){s.textContent=t.fail;s.className='state badmsg';return}if(!data)return;
 var list=data.families.filter(function(f){return f.group==='indicators'}),pub=list.filter(function(f){return f.state==='PUBLISHED'&&f.package});
 s.textContent=pub.length?t.some(pub.length):t.none;s.className='state';
 list.forEach(function(f){var tr=el('tr');tr.appendChild(el('td',{text:f.name}));tr.appendChild(el('td',{},[el('span',{class:'badge prem',text:f.tier})]));
  tr.appendChild(el('td',{text:t.s[f.state]||f.state}));tr.appendChild(el('td',{class:'muted',text:f.state==='PUBLISHED'&&f.package?f.package.source||'':t.na}));
  tr.appendChild(el('td',{class:'muted',text:f.upstream||'—'}));tb.appendChild(tr)})}
MG.i18n(D,render);
MG.getT('families.json').then(function(d){data=d&&Array.isArray(d.families)?d:null;failed=!data;render()},function(){failed=true;render()});
})();
