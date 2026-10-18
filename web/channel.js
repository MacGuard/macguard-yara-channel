(function(){
var T={es:{rules:'Reglas publicadas',log:'Registro de transparencia',loading:'Cargando…',none:'Todavía no hay ninguna release firmada, por eso no se listan reglas. Las reglas solo se publican aquí después de validarlas y firmarlas.',nolog:'El registro aún no tiene entradas.',err:'No se pudo cargar',src:'Fuente',file:'Fichero',bytes:'Bytes',date:'Fecha (UTC)',level:'Nivel',code:'Código',msg:'Mensaje',count:function(n){return n+' ficheros de reglas'},entries:function(n){return n+' entradas, las más recientes primero'}},
en:{rules:'Published rules',log:'Transparency log',loading:'Loading…',none:'There is no signed release yet, so no rules are listed. Rules are published here only after they are validated and signed.',nolog:'The log has no entries yet.',err:'Could not load',src:'Source',file:'File',bytes:'Bytes',date:'Date (UTC)',level:'Level',code:'Code',msg:'Message',count:function(n){return n+' rule files'},entries:function(n){return n+' entries, newest first'}}};
function L(){var v=document.querySelector('#lang').value;return T[v]||T.en}
function $(i){return document.getElementById(i)}
function cell(tr,t,c){var td=document.createElement('td');if(c)td.className=c;td.textContent=t;tr.appendChild(td);return td}
function get(u,j){return fetch(u,{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error(u+' '+r.status);return j?r.json():r.text()})}
var state={};
function paint(){var t=L();
 $('rules-h').textContent=t.rules;$('log-h').textContent=t.log;
 $('nav-rules').textContent=t.rules;$('nav-log').textContent=t.log;
 var rh=document.querySelectorAll('#rules-table th'),lh=document.querySelectorAll('#log-table th');
 [t.src,t.file,'SHA-256',t.bytes].forEach(function(x,i){rh[i].textContent=x});[t.date,t.level,t.code,t.msg].forEach(function(x,i){lh[i].textContent=x});
 if(state.rulesErr)$('rules-state').textContent=state.rulesErr==='none'?t.none:t.err+' manifest.json';
 else if(state.files)$('rules-state').textContent=t.count(state.files.length);else $('rules-state').textContent=t.loading;
 if(state.logErr)$('log-state').textContent=t.err+' log.jsonl';
 else if(state.entries)$('log-state').textContent=state.entries.length?t.entries(state.entries.length):t.nolog;else $('log-state').textContent=t.loading}
get('manifest.json',true).then(function(m){state.files=m.files||[];var b=document.querySelector('#rules-table tbody');
 state.files.forEach(function(f){var tr=document.createElement('tr');cell(tr,f.source);var td=cell(tr,'');var a=document.createElement('a');a.href=f.path.split('/').map(encodeURIComponent).join('/');a.textContent=f.path.replace(/^rules\//,'');td.appendChild(a);cell(tr,f.sha256,'mono');cell(tr,String(f.bytes));b.appendChild(tr)});
 var meta=$('rules-meta');var parts=[];(m.sources||[]).forEach(function(s){parts.push(s.repository+' @ '+s.commit.slice(0,12))});if(m.rules_root)parts.push('rules_root '+m.rules_root.slice(0,16)+'…');
 meta.textContent=parts.join(' · ');paint()}).catch(function(){state.rulesErr='none';paint()});
get('logs/log.jsonl',false).then(function(x){state.entries=x.split('\n').filter(Boolean).map(function(l){return JSON.parse(l)}).reverse();
 var b=document.querySelector('#log-table tbody');state.entries.forEach(function(e){var tr=document.createElement('tr');cell(tr,e.time);cell(tr,e.level,'lv lv-'+e.level);cell(tr,e.event,'mono');cell(tr,e.message);b.appendChild(tr)});paint()}).catch(function(){state.logErr=1;paint()});
$('lang').addEventListener('change',paint);paint();
})();
