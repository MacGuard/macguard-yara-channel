/* Home page: activity chart + live status. Counts are what the pipeline observed, not downloads by users. */
(function(){var $=MG.$,el=MG.el,svg=function(n,a){var e=document.createElementNS('http://www.w3.org/2000/svg',n);for(var k in a)e.setAttribute(k,a[k]);return e};
var T={es:{act:'Actividad del canal',nav_act:'Actividad',nav_rules:'Reglas YARA',nav_rel:'Releases',nav_log:'Transparencia',nav_docs:'Documentación',vrules:'Ficheros examinados',vchanges:'Cambios entre releases',range:function(n){return 'Últimos '+n+' días'},tbl:'Ver datos en tabla',exa:'Examinadas',acc:'Aceptadas',qua:'En cuarentena',rej:'Rechazadas',legacy:'(análisis anteriores no separaban cuarentena)',sumok:'✔ cuadra',sumbad:'✘ NO cuadra: estas cifras no deberían publicarse',nosum:'Este análisis es anterior a la cuarentena: no distingue cuarentena de rechazo.',quarwhy:'«En cuarentena» son archivos retenidos para revisión humana en un panel privado. No se publican hasta que una persona los aprueba y vuelven a superar todos los controles técnicos. Aquí solo se muestra cuántos son.',relvs:function(a,b){return 'Última release ('+a+') comparada con la anterior ('+b+')'},relfirst:function(a,n){return 'Primera release ('+a+'): los '+n+' ficheros cuentan como nuevos porque no hay una anterior con la que comparar.'},norel:'Todavía no hay ninguna release.',dfiles:'Ficheros distribuidos',dyara:'Reglas YARA individuales',dsize:'Paquete comprimido',dexp:'descomprimido',gap:function(a,b){return 'El último análisis aceptó '+a+' ficheros, pero la release vigente distribuye '+b+'; la web mostrará el nuevo total cuando se publique la siguiente release.'},dlreal:'Descargas reales: no se miden. Este sitio no recoge telemetría de descargas; ninguna cifra de esta página son descargas de usuarios.',h_run:'Último análisis',h_rel:'Cambios entre releases',h_dist:'Lo que se distribuye ahora',h_dl:'Descargas: no se miden',nw:'Nuevas',mod:'Modificadas',rem:'Eliminadas',date:'Fecha',obs:'Observado',yes:'Sí',no:'No observado',nodata:'Sin observación',noact:'Todavía no hay ejecuciones registradas.',lastrun:'Último análisis',lastrel:'Última release',vs:'vs. análisis anterior',err:'No se pudo cargar',active:'Canal activo',
 note:function(a,b){return 'Ventana móvil de 30 días ('+a+' – '+b+'), recalculada en cada despliegue desde el registro de transparencia y los manifiestos de las releases. «Examinadas» son los ficheros que revisó el último análisis de cada día; no son descargas de usuarios (no se mide ninguna telemetría de descargas). Un día sin análisis aparece como «sin observación», no como cero.'},
 ex_rules:'Reglas YARA',ex_rules_p:'Catálogo con búsqueda, filtros y descargas verificables.',ex_rel:'Historial de releases',ex_rel_p:'Qué se añadió, modificó o eliminó en cada publicación.',ex_log:'Transparencia',ex_log_p:'Registro Merkle, checkpoints y pruebas de inclusión y consistencia.',ex_intel_p:'Estado real de los canales de inteligencia (YARA, IOC, vulnerabilidades y los que solo son diseño), fichas de artefactos, licencias, procedencia y hoja de ruta.',legend_none:'Sin observación',yr:'ficheros examinados por análisis',yc:'ficheros por release'},
en:{act:'Channel activity',nav_act:'Activity',nav_rules:'YARA rules',nav_rel:'Releases',nav_log:'Transparency',nav_docs:'Documentation',vrules:'Files examined',vchanges:'Changes between releases',range:function(n){return 'Last '+n+' days'},tbl:'Show data as a table',exa:'Examined',acc:'Accepted',qua:'Quarantined',rej:'Rejected',legacy:'(earlier runs did not separate quarantine)',sumok:'✔ adds up',sumbad:'✘ does NOT add up: these figures should not be published',nosum:'This run predates quarantine: it does not tell quarantine from rejection.',quarwhy:'"Quarantined" files are held for human review in a private panel. They are not published until a person approves them and they pass every technical check again. This page only shows how many there are.',relvs:function(a,b){return 'Latest release ('+a+') compared with the previous one ('+b+')'},relfirst:function(a,n){return 'First release ('+a+'): all '+n+' files count as new because there is no earlier release to compare with.'},norel:'There is no release yet.',dfiles:'Files distributed',dyara:'Individual YARA rules',dsize:'Compressed package',dexp:'uncompressed',gap:function(a,b){return 'The latest analysis accepted '+a+' files but the current release distributes '+b+'; the site will show the new total once the next release is published.'},dlreal:'Real downloads: not measured. This site collects no download telemetry; none of the figures on this page are user downloads.',h_run:'Latest analysis',h_rel:'Changes between releases',h_dist:'What is distributed now',h_dl:'Downloads: not measured',nw:'New',mod:'Modified',rem:'Removed',date:'Date',obs:'Observed',yes:'Yes',no:'Not observed',nodata:'No observation',noact:'No runs recorded yet.',lastrun:'Latest run',lastrel:'Latest release',vs:'vs. previous run',err:'Could not load',active:'Channel active',
 note:function(a,b){return 'Rolling 30-day window ('+a+' – '+b+'), recomputed on every deployment from the transparency log and the release manifests. "Examined" is the number of files the last run of each day looked at; it is not user downloads (no download telemetry is collected). A day without a run shows as "no observation", not zero.'},
 ex_rules:'YARA rules',ex_rules_p:'Catalog with search, filters and verifiable downloads.',ex_rel:'Release history',ex_rel_p:'What was added, modified or removed in each publication.',ex_log:'Transparency',ex_log_p:'Merkle log, checkpoints, inclusion and consistency proofs.',ex_intel_p:'Real state of the intelligence channels (YARA, IOC, vulnerabilities and those that are only a design), artifact cards, licences, provenance and roadmap.',legend_none:'No observation',yr:'files examined per run',yc:'files per release'}};
var S={stats:null,rel:null,latest:null,man:null,ver:null},L=function(){var s=$('lang').value;return T[s]||T.en};
function lab(){var t=L();$('act-h').textContent=t.act;$('h-run').textContent=t.h_run;$('h-rel').textContent=t.h_rel;$('h-dist').textContent=t.h_dist;$('h-dl').textContent=t.h_dl;['act','rules','rel','log','docs'].forEach(function(k){var e=$('nav-'+k);if(e)e.textContent=t['nav_'+k]});
 [['ex-rules','ex_rules'],['ex-rel','ex_rel'],['ex-log','ex_log'],['ex-rules-p','ex_rules_p'],['ex-rel-p','ex_rel_p'],['ex-log-p','ex_log_p'],['ex-intel-p','ex_intel_p']].forEach(function(p){$(p[0]).textContent=t[p[1]]});
 $('act-view').options[0].textContent=t.vrules;$('act-view').options[1].textContent=t.vchanges;[30,14,7].forEach(function(n,i){$('act-range').options[i].textContent=t.range(n)});$('act-tbl-h').textContent=t.tbl;
 var th=document.querySelectorAll('#act-table th');[t.date,t.obs,t.exa,t.acc,t.qua,t.rej,t.nw,t.mod,t.rem].forEach(function(x,i){th[i].textContent=x})}
function L2(){return $('lang').value==='es'?'es-ES':'en-US'}
function niceMax(v){if(v<=5)return 5;var p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;return(f<=1?1:f<=2?2:f<=5?5:10)*p}
function tile(boxId,label,val,prev,bad,sub){var d=el('div',{class:'tile'});d.appendChild(el('small',{text:label}));d.appendChild(el('strong',{text:val===null?'—':String(val)}));
 if(val!==null&&prev!==null&&prev!==undefined&&(val>0||prev>0)){var diff=val-prev,pct=prev>0?Math.round(diff*100/prev):null;d.appendChild(el('span',{class:'delta'+((bad?diff>0:diff<0)?' neg':''),text:(diff>=0?'+':'')+(pct===null?diff:pct+'%')+' '+L().vs}))}
 if(sub)d.appendChild(el('small',{class:'sub',text:sub}));$(boxId).appendChild(d)}
function legendItem(cls,text){var s=el('span',{class:'lg'});s.appendChild(el('i',{class:'sw '+cls}));s.appendChild(document.createTextNode(text));return s}
function draw(){var t=L(),days=S.stats&&S.stats.days;$('act-legend').textContent='';var box=$('act-chart');box.textContent='';if(!days){box.textContent=t.err+' stats.json';return}
 var n=parseInt($('act-range').value,10),view=$('act-view').value,win=days.slice(-n),obs=days.filter(function(d){return d.observed}),
  lr=obs[obs.length-1]||null,pr=obs[obs.length-2]||{};
 ['tiles-run','tiles-rel','tiles-dist'].forEach(function(i){$(i).textContent=''});
 var fmt=function(v){return v===null||v===undefined?'—':v.toLocaleString(L2())};
 tile('tiles-run',t.exa,lr?lr.examined:null,pr.examined,false,lr?t.lastrun+' · '+lr.date:t.noact);
 tile('tiles-run',t.acc,lr?lr.accepted:null,pr.accepted);
 tile('tiles-run',t.qua,lr?lr.quarantined:null,pr.quarantined,true,lr&&lr.quarantined===null?t.legacy:'');
 tile('tiles-run',t.rej,lr?lr.rejected:null,pr.rejected,true);
 $('run-sum').textContent='';$('run-sum').className='muted';
 if(lr&&lr.accounting_ok!==null&&lr.accounting_ok!==undefined){var dep=lr.deprecated||0;
  $('run-sum').textContent=fmt(lr.accepted)+' + '+fmt(lr.quarantined)+' + '+fmt(lr.rejected)+(dep?' + '+fmt(dep):'')+' = '+fmt(lr.examined)+'  '+(lr.accounting_ok?t.sumok:t.sumbad);$('run-sum').className=lr.accounting_ok?'okmsg':'badmsg'}
 else if(lr){$('run-sum').textContent=t.nosum}
 $('run-quar').textContent=t.quarwhy;
 var rels=(S.rel&&S.rel.releases)||[],lrel=rels[rels.length-1],prel=rels.length>1?rels[rels.length-2]:null;
 $('rel-sub').textContent=lrel?(prel?t.relvs(lrel.tag,prel.tag):t.relfirst(lrel.tag,fmt(lrel.total))):t.norel;
 tile('tiles-rel',t.nw,lrel?lrel.added:null,null,false,lrel?t.lastrel+' · '+MG.day(lrel.published_at):'');tile('tiles-rel',t.mod,lrel?lrel.modified:null,null);tile('tiles-rel',t.rem,lrel?lrel.removed:null,null,true);
 var st=(S.latest&&S.latest.stats)||{};
 tile('tiles-dist',t.dfiles,lrel?lrel.total:null,null,false,lrel?t.lastrel+' · '+MG.day(lrel.published_at):'');tile('tiles-dist',t.dyara,st.yara_rules!==undefined?st.yara_rules:null,null);tile('tiles-dist',t.dsize,lrel&&lrel.package_bytes?MG.bytes(lrel.package_bytes):null,null,false,st.expanded_bytes?t.dexp+' '+MG.bytes(st.expanded_bytes):'');
 $('dist-gap').textContent=(lr&&lrel&&lr.accepted!==lrel.total)?t.gap(fmt(lr.accepted),fmt(lrel.total)):'';
 $('dl-real').textContent=t.dlreal;
 var series=view==='rules'?[['acc','ok',t.acc],['qua','mod',t.qua],['rej','bad',t.rej]]:[['new','ok',t.nw],['modified','mod',t.mod],['removed','rem',t.rem]];
 var key={acc:'accepted',qua:'quarantined',rej:'rejected',new:'new',modified:'modified',removed:'removed'};
 series.forEach(function(s){$('act-legend').appendChild(legendItem(s[1],s[2]))});$('act-legend').appendChild(legendItem('none',t.legend_none));
 var tot=function(d){return series.reduce(function(a,s){return a+(d[key[s[0]]]||0)},0)},
  W=900,H=260,l=58,r=10,tp=10,bt=28,max=niceMax(Math.max.apply(null,win.map(tot).concat([1]))),pw=W-l-r,ph=H-tp-bt,bw=pw/win.length;
 var g=svg('svg',{viewBox:'0 0 '+W+' '+H,'aria-hidden':'true'});
 var defs=svg('defs',{}),pat=svg('pattern',{id:'hatch',width:6,height:6,patternUnits:'userSpaceOnUse',patternTransform:'rotate(45)'});pat.appendChild(svg('line',{x1:0,y1:0,x2:0,y2:6,'class':'hatch-line'}));defs.appendChild(pat);g.appendChild(defs);
 [0,.5,1].forEach(function(f){var y=tp+ph-ph*f;g.appendChild(svg('line',{x1:l,x2:W-r,y1:y,y2:y,'class':'gl'}));var tx=svg('text',{x:l-6,y:y+4,'text-anchor':'end'});tx.textContent=Math.round(max*f);g.appendChild(tx)});
 var yt=svg('text',{x:12,y:tp+ph/2,'text-anchor':'middle',transform:'rotate(-90 12 '+(tp+ph/2)+')','class':'ytitle'});yt.textContent=view==='rules'?t.yr:t.yc;g.appendChild(yt);
 var step=n>14?5:n>7?2:1;
 win.forEach(function(d,i){var x=l+i*bw+bw*.15,w=bw*.7,y=tp+ph,desc;
  if(view==='rules'&&!d.observed){var h=svg('rect',{x:x,y:tp+ph*.7,width:w,height:ph*.3,fill:'url(#hatch)','class':'nodata',rx:2});var tt=svg('title',{});tt.textContent=d.date+': '+t.nodata;h.appendChild(tt);g.appendChild(h)}
  else{desc=d.date+': '+series.map(function(s){var v=d[key[s[0]]];return s[2]+' '+(v===null||v===undefined?'—':v)}).join(', ');
   series.forEach(function(s){var v=d[key[s[0]]]||0,hh=ph*v/max;if(hh>0){y-=hh;var b=svg('rect',{x:x,y:y,width:w,height:hh,'class':'b-'+s[1],rx:2});var tt=svg('title',{});tt.textContent=desc;b.appendChild(tt);g.appendChild(b)}})}
  if((win.length-1-i)%step===0){var lb=svg('text',{x:x+w/2,y:H-8,'text-anchor':'middle'});lb.textContent=d.date.slice(8)+'/'+d.date.slice(5,7);g.appendChild(lb)}});
 box.appendChild(g);box.setAttribute('aria-label',t.act+': '+t.range(n)+'. '+(view==='rules'?t.vrules:t.vchanges));
 var tb=document.querySelector('#act-table tbody');tb.textContent='';var f=function(v){return v===null||v===undefined?'—':String(v)};
 win.slice().reverse().forEach(function(d){var tr=el('tr');[d.date,d.observed?t.yes:t.no,f(d.examined),f(d.accepted),f(d.quarantined),f(d.rejected),f(d.new),f(d.modified),f(d.removed)].forEach(function(x){tr.appendChild(el('td',{text:x}))});tb.appendChild(tr)});
 $('act-note').textContent=t.note(win[0].date,win[win.length-1].date)}
function status(){if(!S.ok)return;document.querySelectorAll('.status').forEach(function(e){e.removeAttribute('data-i');e.textContent=L().active;e.style.background='#e6f4ea';e.style.color='#1b6e3c'})}
$('act-range').addEventListener('change',draw);$('act-view').addEventListener('change',draw);
var sel=$('lang');sel.addEventListener('change',function(){setTimeout(function(){lab();draw();status();latest()},0)});

var LT={es:{h:'Última release',loading:'Cargando…',none:'Todavía no hay ninguna release publicada.',ver:'Versión',date:'Publicada',files:'Ficheros de reglas',rules:'Reglas YARA individuales',same:'(una por fichero o ninguna diferencia)',comp:'Tamaño comprimido',exp:'Tamaño descomprimido',nw:'Nuevas',mod:'Modificadas',rem:'Retiradas',sig:'Firma del manifiesto',sigok:'válida: comprobada por GitHub Actions al desplegar (cosign, identidad del workflow)',signo:'sin comprobación registrada',who:'Identidad del publicador',root:'Rules root',cp:'Checkpoint',log:'Registro de transparencia',dl:{pkg:'Paquete completo',man:'Manifiesto',bundle:'Bundle Sigstore',proof:'Prueba Merkle',cp:'Checkpoint',meta:'Metadatos de la release',chg:'Changelog'},mirror:'copia en este sitio',canon:'copia canónica (GitHub Releases)',note:'Estas cifras salen del manifiesto firmado y de los ficheros publicados. «Nuevas/modificadas/retiradas» comparan esta release con la anterior; en la primera release todo cuenta como nuevo.',entries:function(n,r){return 'tamaño '+n+', raíz '+r}},
en:{h:'Latest release',loading:'Loading…',none:'There is no published release yet.',ver:'Version',date:'Published',files:'Rule files',rules:'Individual YARA rules',same:'(one per file or no difference)',comp:'Compressed size',exp:'Uncompressed size',nw:'New',mod:'Modified',rem:'Removed',sig:'Manifest signature',sigok:'valid: checked by GitHub Actions at deployment (cosign, workflow identity)',signo:'no verification recorded',who:'Publisher identity',root:'Rules root',cp:'Checkpoint',log:'Transparency log',dl:{pkg:'Full package',man:'Manifest',bundle:'Sigstore bundle',proof:'Merkle proof',cp:'Checkpoint',meta:'Release metadata',chg:'Changelog'},mirror:'copy on this site',canon:'canonical copy (GitHub Releases)',note:'These figures come from the signed manifest and the published files. New/modified/removed compare this release with the previous one; in the first release everything counts as new.',entries:function(n,r){return 'size '+n+', root '+r}}};
var IDENT='https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main';
function latest(){var t=LT[$('lang').value]||LT.en;$('latest-h').textContent=t.h;var box=$('latest-facts'),dl=$('latest-dl');box.textContent='';dl.textContent='';
 var rels=(S.rel&&S.rel.releases)||[],r=rels[rels.length-1];
 if(!S.rel){$('latest-state').textContent=t.loading;return}
 if(!r){$('latest-state').textContent=t.none;return}$('latest-state').textContent='';
 var st=(S.latest&&S.latest.stats)||{},m=S.man||{},add=function(k,v,mono,link){box.appendChild(el('dt',{text:k}));var d=el('dd',{class:mono?'mono':''});if(link)d.appendChild(el('a',{href:link,text:v}));else d.textContent=v;box.appendChild(d)};
 var kb=function(n){return n===null||n===undefined?'—':MG.bytes(n)};
 add(t.ver,r.tag,false,r.url);add(t.date,r.published_at.replace('T',' ').replace('Z',' UTC'));
 add(t.files,String(r.total));add(t.rules,st.yara_rules!==undefined?String(st.yara_rules)+(st.yara_rules===r.total?' '+t.same:''):'—');
 add(t.comp,kb(r.package_bytes!==null&&r.package_bytes!==undefined?r.package_bytes:st.package_bytes));add(t.exp,kb(st.expanded_bytes));
 add(t.nw,String(r.added));add(t.mod,String(r.modified));add(t.rem,String(r.removed));
 var v=S.ver;add(t.sig,v&&v.run_url?t.sigok:t.signo,false,v&&v.run_url?v.run_url:null);add(t.who,IDENT,true);add(t.root,r.rules_root,true);
 if(m.log)add(t.cp,t.entries(m.log.size,m.log.root),true,'logs/checkpoint.txt');
 var a=r.assets||{},items=[['pkg','rules-release.tar.gz'],['man','manifest.json'],['bundle','manifest.sigstore.json'],['proof','inclusion-proof.json'],['cp','checkpoint.txt'],['meta','release.json'],['chg','CHANGELOG.md']];
 items.forEach(function(it){var url=a[it[1]],local={'checkpoint.txt':'logs/checkpoint.txt','manifest.json':'manifest.json','manifest.sigstore.json':'manifest.sigstore.json','inclusion-proof.json':'inclusion-proof.json','rules-release.tar.gz':'rules-release.tar.gz'}[it[1]];
  if(!url&&!local)return;var li=el('li');li.appendChild(el('strong',{text:t.dl[it[0]]+': '}));
  if(url){li.appendChild(el('a',{href:url,text:it[1]}));li.appendChild(document.createTextNode(' · '+t.canon))}
  if(local){if(url)li.appendChild(document.createTextNode(' · '));li.appendChild(el('a',{href:local,text:it[1]}));li.appendChild(document.createTextNode(' · '+t.mirror))}
  dl.appendChild(li)});
 var li2=el('li');li2.appendChild(el('a',{href:'transparency.html',text:t.log}));li2.appendChild(document.createTextNode(' · '));li2.appendChild(el('a',{href:'releases.html',text:'Releases'}));li2.appendChild(document.createTextNode(' · '));li2.appendChild(el('a',{href:'rules.html',text:'YARA'}));dl.appendChild(li2);
 $('latest-note').textContent=t.note}
MG.get('stats.json',true).then(function(s){S.stats=s;draw()}).catch(function(){S.stats=null;draw()});
MG.get('releases.json',true).then(function(r){S.rel=r;draw();latest()}).catch(function(){S.rel={releases:[]};latest()});
MG.get('latest.json',true).then(function(x){S.latest=x;draw();latest()}).catch(function(){});
MG.get('verification.json',true).then(function(x){S.ver=x;latest()}).catch(function(){});
MG.get('manifest.json',true).then(function(m){S.man=m;S.ok=true;status();latest()}).catch(function(){});
lab();
})();
