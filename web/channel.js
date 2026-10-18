(function(){var STATS=null;
var T={es:{days:'Días con datos',active:'Canal activo',act:'Reglas descargadas por día',actNav:'Actividad',ok:'Aceptadas',bad:'Rechazadas',dl:'Descargadas',today:'Hoy',range:function(n){return 'Últimos '+n+' días'},tbl:'Ver datos en tabla',date:'Fecha',noact:'Todavía no hay descargas registradas.',note:function(a,b){return 'Calculado en cada despliegue a partir del registro de transparencia; se conservan los últimos 30 días ('+a+' – '+b+'). El último análisis de cada día es el que cuenta.'},vs:'vs. ayer',docs:'Documentación',rules:'Reglas publicadas',log:'Registro de transparencia',loading:'Cargando…',none:'Todavía no hay ninguna release firmada, por eso no se listan reglas. Las reglas solo se publican aquí después de validarlas y firmarlas.',nolog:'El registro aún no tiene entradas.',err:'No se pudo cargar',src:'Fuente',file:'Fichero',bytes:'Bytes',date:'Fecha (UTC)',level:'Nivel',code:'Código',msg:'Mensaje',count:function(n){return n+' ficheros de reglas'},entries:function(n){return n+' entradas, las más recientes primero'}},
en:{days:'Days with data',active:'Channel active',act:'Rules downloaded per day',actNav:'Activity',ok:'Accepted',bad:'Rejected',dl:'Downloaded',today:'Today',range:function(n){return 'Last '+n+' days'},tbl:'Show data as a table',date:'Date',noact:'No downloads recorded yet.',note:function(a,b){return 'Recomputed on every deployment from the transparency log; the last 30 days are kept ('+a+' – '+b+'). The last run of each day counts.'},vs:'vs. yesterday',docs:'Documentation',rules:'Published rules',log:'Transparency log',loading:'Loading…',none:'There is no signed release yet, so no rules are listed. Rules are published here only after they are validated and signed.',nolog:'The log has no entries yet.',err:'Could not load',src:'Source',file:'File',bytes:'Bytes',date:'Date (UTC)',level:'Level',code:'Code',msg:'Message',count:function(n){return n+' rule files'},entries:function(n){return n+' entries, newest first'}}};
function L(){var v=document.querySelector('#lang').value;return T[v]||T.en}
function $(i){return document.getElementById(i)}
function cell(tr,t,c){var td=document.createElement('td');if(c)td.className=c;td.textContent=t;tr.appendChild(td);return td}
function get(u,j){return fetch(u,{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error(u+' '+r.status);return j?r.json():r.text()})}
var state={};
function paint(){var t=L();
 $('rules-h').textContent=t.rules;$('log-h').textContent=t.log;
 $('nav-rules').textContent=t.rules;$('nav-log').textContent=t.log;$('nav-docs').textContent=t.docs;
 var rh=document.querySelectorAll('#rules-table th'),lh=document.querySelectorAll('#log-table th');
 [t.src,t.file,'SHA-256',t.bytes].forEach(function(x,i){rh[i].textContent=x});[t.date,t.level,t.code,t.msg].forEach(function(x,i){lh[i].textContent=x});
 if(state.rulesErr)$('rules-state').textContent=state.rulesErr==='none'?t.none:t.err+' manifest.json';
 else if(state.files)$('rules-state').textContent=t.count(state.files.length);else $('rules-state').textContent=t.loading;
 if(state.files){document.querySelectorAll('.status').forEach(function(e){e.removeAttribute('data-i');e.textContent=t.active;e.style.background='#e6f4ea';e.style.color='#1b6e3c'})}
 if(state.logErr)$('log-state').textContent=t.err+' log.jsonl';
 else if(state.entries)$('log-state').textContent=state.entries.length?t.entries(state.entries.length):t.nolog;else $('log-state').textContent=t.loading}
get('manifest.json',true).then(function(m){state.files=m.files||[];var b=document.querySelector('#rules-table tbody');
 state.files.forEach(function(f){var tr=document.createElement('tr');cell(tr,f.source);var td=cell(tr,'');var a=document.createElement('a');a.href=f.path.split('/').map(encodeURIComponent).join('/');a.textContent=f.path.replace(/^rules\//,'');td.appendChild(a);cell(tr,f.sha256,'mono');cell(tr,String(f.bytes));b.appendChild(tr)});
 var meta=$('rules-meta');var parts=[];(m.sources||[]).forEach(function(s){parts.push(s.repository+' @ '+s.commit.slice(0,12))});if(m.rules_root)parts.push('rules_root '+m.rules_root.slice(0,16)+'…');
 meta.textContent=parts.join(' · ');paint()}).catch(function(){state.rulesErr='none';paint()});
get('logs/log.jsonl',false).then(function(x){state.entries=x.split('\n').filter(Boolean).map(function(l){return JSON.parse(l)}).reverse();
 var b=document.querySelector('#log-table tbody');state.entries.forEach(function(e){var tr=document.createElement('tr');cell(tr,e.time);cell(tr,e.level,'lv lv-'+e.level);cell(tr,e.event,'mono');cell(tr,e.message);b.appendChild(tr)});paint()}).catch(function(){state.logErr=1;paint()});
$('lang').addEventListener('change',function(){paint();drawActivity()});paint();
function svgEl(n,a){var e=document.createElementNS('http://www.w3.org/2000/svg',n);for(var k in a)e.setAttribute(k,a[k]);return e}
function niceMax(v){if(v<=5)return 5;var p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;return(f<=1?1:f<=2?2:f<=5?5:10)*p}
function drawActivity(){var t=L();
 $('act-h').textContent=t.act;$('nav-act').textContent=t.actNav;$('lg-ok').textContent=t.ok;$('lg-bad').textContent=t.bad;$('act-tbl-h').textContent=t.tbl;
 var sel=$('act-range');[30,14,7].forEach(function(n,i){sel.options[i].textContent=t.range(n)});
 var box=$('act-chart');box.textContent='';var tiles=$('act-tiles');tiles.textContent='';
 if(!STATS){box.textContent=t.loading;return}
 var n=parseInt(sel.value,10),days=STATS.days.slice(-n),total=days.reduce(function(a,d){return a+d.downloaded},0);
 if(!total){box.textContent=t.noact}
 var last=STATS.days[STATS.days.length-1],prev=STATS.days[STATS.days.length-2]||{downloaded:0,accepted:0,rejected:0};
 function tile(label,val,pv,inv){var d=document.createElement('div');d.className='tile';var s=document.createElement('small');s.textContent=label;var b=document.createElement('strong');b.textContent=String(val);d.appendChild(s);d.appendChild(b);
  if(pv>0||val>0){var diff=val-pv,pct=pv>0?Math.round(diff*100/pv):null,x=document.createElement('span');x.className='delta'+((inv?diff>0:diff<0)?' neg':'');x.textContent=(diff>=0?'+':'')+(pct===null?diff:pct+'%')+' '+t.vs;d.appendChild(x)}tiles.appendChild(d)}
 tile(t.dl+' · '+t.today,last.downloaded,prev.downloaded);tile(t.ok,last.accepted,prev.accepted);tile(t.bad,last.rejected,prev.rejected,true);
 var sum=days.reduce(function(a,d){return a+(d.downloaded>0?1:0)},0);var dd=document.createElement('div');dd.className='tile';var ds=document.createElement('small');ds.textContent=t.days+' · '+t.range(n).toLowerCase();var dv=document.createElement('strong');dv.textContent=String(sum);dd.appendChild(ds);dd.appendChild(dv);tiles.appendChild(dd);
 if(total){
  var W=900,H=260,l=44,r=10,tp=10,bt=28,max=niceMax(Math.max.apply(null,days.map(function(d){return d.downloaded}))),pw=W-l-r,ph=H-tp-bt,bw=pw/days.length;
  var svg=svgEl('svg',{viewBox:'0 0 '+W+' '+H,'aria-hidden':'true'});
  [0,.5,1].forEach(function(f){var y=tp+ph-ph*f;svg.appendChild(svgEl('line',{x1:l,x2:W-r,y1:y,y2:y,'class':'gl'}));var tx=svgEl('text',{x:l-6,y:y+4,'text-anchor':'end'});tx.textContent=Math.round(max*f);svg.appendChild(tx)});
  var step=n>14?5:n>7?2:1;
  days.forEach(function(d,i){var x=l+i*bw+bw*.15,w=bw*.7,hOk=ph*d.accepted/max,hBad=ph*d.rejected/max;
   var tip=d.date+': '+d.downloaded+' ('+t.ok+' '+d.accepted+', '+t.bad+' '+d.rejected+')';
   if(hOk>0){var a=svgEl('rect',{x:x,y:tp+ph-hOk,width:w,height:hOk,'class':'b-ok',rx:2});var ta=svgEl('title',{});ta.textContent=tip;a.appendChild(ta);svg.appendChild(a)}
   if(hBad>0){var b=svgEl('rect',{x:x,y:tp+ph-hOk-hBad,width:w,height:hBad,'class':'b-bad',rx:2});var tb=svgEl('title',{});tb.textContent=tip;b.appendChild(tb);svg.appendChild(b)}
   if((days.length-1-i)%step===0){var lb=svgEl('text',{x:x+w/2,y:H-8,'text-anchor':'middle'});lb.textContent=d.date.slice(8)+'/'+d.date.slice(5,7);svg.appendChild(lb)}});
  box.appendChild(svg)}
 box.setAttribute('aria-label',t.act+': '+t.range(n)+', '+t.dl+' '+total);
 var tb=document.querySelector('#act-table tbody');tb.textContent='';var th=document.querySelectorAll('#act-table th');[t.date,t.dl,t.ok,t.bad].forEach(function(x,i){th[i].textContent=x});
 days.slice().reverse().forEach(function(d){var tr=document.createElement('tr');cell(tr,d.date);cell(tr,String(d.downloaded));cell(tr,String(d.accepted));cell(tr,String(d.rejected));tb.appendChild(tr)});
 $('act-note').textContent=t.note(days[0].date,days[days.length-1].date)}
get('stats.json',true).then(function(s){STATS=s;drawActivity()}).catch(function(){STATS=null;$('act-chart').textContent=L().err+' stats.json'});
$('act-range').addEventListener('change',drawActivity);

})();
