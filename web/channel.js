/* Home page: activity chart + live status. Counts are what the pipeline observed, not downloads by users. */
(function(){var $=MG.$,el=MG.el,svg=function(n,a){var e=document.createElementNS('http://www.w3.org/2000/svg',n);for(var k in a)e.setAttribute(k,a[k]);return e};
var T={es:{act:'Actividad del canal',nav_act:'Actividad',nav_rules:'Reglas YARA',nav_rel:'Releases',nav_log:'Transparencia',nav_docs:'Documentación',vrules:'Reglas examinadas',vchanges:'Cambios entre releases',range:function(n){return 'Últimos '+n+' días'},tbl:'Ver datos en tabla',exa:'Examinadas',acc:'Aceptadas',rej:'Rechazadas',nw:'Nuevas',mod:'Modificadas',rem:'Eliminadas',date:'Fecha',obs:'Observado',yes:'Sí',no:'No observado',nodata:'Sin observación',noact:'Todavía no hay ejecuciones registradas.',lastrun:'Último análisis',lastrel:'Última release',vs:'vs. análisis anterior',err:'No se pudo cargar',active:'Canal activo',
 note:function(a,b){return 'Ventana móvil de 30 días ('+a+' – '+b+'), recalculada en cada despliegue desde el registro de transparencia y los manifiestos de las releases. «Examinadas» son los ficheros que revisó el último análisis de cada día; no son descargas de usuarios (no se mide ninguna telemetría de descargas). Un día sin análisis aparece como «sin observación», no como cero.'},
 ex_rules:'Reglas YARA',ex_rules_p:'Catálogo con búsqueda, filtros y descargas verificables.',ex_rel:'Historial de releases',ex_rel_p:'Qué se añadió, modificó o eliminó en cada publicación.',ex_log:'Transparencia',ex_log_p:'Registro Merkle, checkpoints y pruebas de inclusión y consistencia.',legend_none:'Sin observación'},
en:{act:'Channel activity',nav_act:'Activity',nav_rules:'YARA rules',nav_rel:'Releases',nav_log:'Transparency',nav_docs:'Documentation',vrules:'Rules examined',vchanges:'Changes between releases',range:function(n){return 'Last '+n+' days'},tbl:'Show data as a table',exa:'Examined',acc:'Accepted',rej:'Rejected',nw:'New',mod:'Modified',rem:'Removed',date:'Date',obs:'Observed',yes:'Yes',no:'Not observed',nodata:'No observation',noact:'No runs recorded yet.',lastrun:'Latest run',lastrel:'Latest release',vs:'vs. previous run',err:'Could not load',active:'Channel active',
 note:function(a,b){return 'Rolling 30-day window ('+a+' – '+b+'), recomputed on every deployment from the transparency log and the release manifests. "Examined" is the number of files the last run of each day looked at; it is not user downloads (no download telemetry is collected). A day without a run shows as "no observation", not zero.'},
 ex_rules:'YARA rules',ex_rules_p:'Catalog with search, filters and verifiable downloads.',ex_rel:'Release history',ex_rel_p:'What was added, modified or removed in each publication.',ex_log:'Transparency',ex_log_p:'Merkle log, checkpoints, inclusion and consistency proofs.',legend_none:'No observation'}};
var S={stats:null,rel:null},L=function(){var s=$('lang').value;return T[s]||T.en};
function lab(){var t=L();$('act-h').textContent=t.act;['act','rules','rel','log','docs'].forEach(function(k){var e=$('nav-'+k);if(e)e.textContent=t['nav_'+k]});
 [['ex-rules','ex_rules'],['ex-rel','ex_rel'],['ex-log','ex_log'],['ex-rules-p','ex_rules_p'],['ex-rel-p','ex_rel_p'],['ex-log-p','ex_log_p']].forEach(function(p){$(p[0]).textContent=t[p[1]]});
 $('act-view').options[0].textContent=t.vrules;$('act-view').options[1].textContent=t.vchanges;[30,14,7].forEach(function(n,i){$('act-range').options[i].textContent=t.range(n)});$('act-tbl-h').textContent=t.tbl;
 var th=document.querySelectorAll('#act-table th');[t.date,t.obs,t.exa,t.acc,t.rej,t.nw,t.mod,t.rem].forEach(function(x,i){th[i].textContent=x})}
function niceMax(v){if(v<=5)return 5;var p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;return(f<=1?1:f<=2?2:f<=5?5:10)*p}
function tile(box,label,val,prev,bad,sub){var d=el('div',{class:'tile'});d.appendChild(el('small',{text:label}));d.appendChild(el('strong',{text:val===null?'—':String(val)}));
 if(val!==null&&prev!==null&&prev!==undefined&&(val>0||prev>0)){var diff=val-prev,pct=prev>0?Math.round(diff*100/prev):null;d.appendChild(el('span',{class:'delta'+((bad?diff>0:diff<0)?' neg':''),text:(diff>=0?'+':'')+(pct===null?diff:pct+'%')+' '+L().vs}))}
 if(sub)d.appendChild(el('small',{class:'sub',text:sub}));$('act-tiles').appendChild(d)}
function legendItem(cls,text){var s=el('span',{class:'lg'});s.appendChild(el('i',{class:'sw '+cls}));s.appendChild(document.createTextNode(text));return s}
function draw(){var t=L(),days=S.stats&&S.stats.days;$('act-tiles').textContent='';$('act-legend').textContent='';var box=$('act-chart');box.textContent='';if(!days){box.textContent=t.err+' stats.json';return}
 var n=parseInt($('act-range').value,10),view=$('act-view').value,win=days.slice(-n),obs=days.filter(function(d){return d.observed}),
  lr=obs[obs.length-1]||null,pr=obs[obs.length-2]||{};
 tile(0,t.exa,lr?lr.examined:null,pr.examined,false,lr?t.lastrun+' · '+lr.date:t.noact);tile(0,t.acc,lr?lr.accepted:null,pr.accepted);tile(0,t.rej,lr?lr.rejected:null,pr.rejected,true);
 var rels=(S.rel&&S.rel.releases)||[],lrel=rels[rels.length-1],prel=rels[rels.length-2]||{};
 tile(0,t.nw,lrel?lrel.added:null,prel.added,false,lrel?t.lastrel+' · '+MG.day(lrel.published_at):'');tile(0,t.mod,lrel?lrel.modified:null,prel.modified);tile(0,t.rem,lrel?lrel.removed:null,prel.removed,true);
 var series=view==='rules'?[['acc','ok',t.acc],['rej','bad',t.rej]]:[['new','ok',t.nw],['modified','mod',t.mod],['removed','rem',t.rem]];
 var key={acc:'accepted',rej:'rejected',new:'new',modified:'modified',removed:'removed'};
 series.forEach(function(s){$('act-legend').appendChild(legendItem(s[1],s[2]))});$('act-legend').appendChild(legendItem('none',t.legend_none));
 var tot=function(d){return series.reduce(function(a,s){return a+(d[key[s[0]]]||0)},0)},
  W=900,H=260,l=44,r=10,tp=10,bt=28,max=niceMax(Math.max.apply(null,win.map(tot).concat([1]))),pw=W-l-r,ph=H-tp-bt,bw=pw/win.length;
 var g=svg('svg',{viewBox:'0 0 '+W+' '+H,'aria-hidden':'true'});
 var defs=svg('defs',{}),pat=svg('pattern',{id:'hatch',width:6,height:6,patternUnits:'userSpaceOnUse',patternTransform:'rotate(45)'});pat.appendChild(svg('line',{x1:0,y1:0,x2:0,y2:6,'class':'hatch-line'}));defs.appendChild(pat);g.appendChild(defs);
 [0,.5,1].forEach(function(f){var y=tp+ph-ph*f;g.appendChild(svg('line',{x1:l,x2:W-r,y1:y,y2:y,'class':'gl'}));var tx=svg('text',{x:l-6,y:y+4,'text-anchor':'end'});tx.textContent=Math.round(max*f);g.appendChild(tx)});
 var step=n>14?5:n>7?2:1;
 win.forEach(function(d,i){var x=l+i*bw+bw*.15,w=bw*.7,y=tp+ph,desc;
  if(view==='rules'&&!d.observed){var h=svg('rect',{x:x,y:tp+ph*.7,width:w,height:ph*.3,fill:'url(#hatch)','class':'nodata',rx:2});var tt=svg('title',{});tt.textContent=d.date+': '+t.nodata;h.appendChild(tt);g.appendChild(h)}
  else{desc=d.date+': '+series.map(function(s){var v=d[key[s[0]]];return s[2]+' '+(v===null||v===undefined?'—':v)}).join(', ');
   series.forEach(function(s){var v=d[key[s[0]]]||0,hh=ph*v/max;if(hh>0){y-=hh;var b=svg('rect',{x:x,y:y,width:w,height:hh,'class':'b-'+s[1],rx:2});var tt=svg('title',{});tt.textContent=desc;b.appendChild(tt);g.appendChild(b)}})}
  if((win.length-1-i)%step===0){var lb=svg('text',{x:x+w/2,y:H-8,'text-anchor':'middle'});lb.textContent=d.date.slice(8)+'/'+d.date.slice(5,7);g.appendChild(lb)}});
 box.appendChild(g);box.setAttribute('aria-label',t.act+': '+t.range(n)+'. '+(view==='rules'?t.vrules:t.vchanges));
 var tb=document.querySelector('#act-table tbody');tb.textContent='';var f=function(v){return v===null||v===undefined?'—':String(v)};
 win.slice().reverse().forEach(function(d){var tr=el('tr');[d.date,d.observed?t.yes:t.no,f(d.examined),f(d.accepted),f(d.rejected),f(d.new),f(d.modified),f(d.removed)].forEach(function(x){tr.appendChild(el('td',{text:x}))});tb.appendChild(tr)});
 $('act-note').textContent=t.note(win[0].date,win[win.length-1].date)}
function status(){if(!S.ok)return;document.querySelectorAll('.status').forEach(function(e){e.removeAttribute('data-i');e.textContent=L().active;e.style.background='#e6f4ea';e.style.color='#1b6e3c'})}
$('act-range').addEventListener('change',draw);$('act-view').addEventListener('change',draw);
var sel=$('lang');sel.addEventListener('change',function(){setTimeout(function(){lab();draw();status()},0)});
MG.get('stats.json',true).then(function(s){S.stats=s;draw()}).catch(function(){S.stats=null;draw()});
MG.get('releases.json',true).then(function(r){S.rel=r;draw()}).catch(function(){});
MG.get('manifest.json',true).then(function(){S.ok=true;status()}).catch(function(){});
lab();
})();
