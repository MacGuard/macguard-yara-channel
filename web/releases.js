(function(){var $=MG.$,el=MG.el;
var D={es:{},en:{nav_home:'Home',nav_rules:'YARA rules',nav_releases:'Releases',nav_transparency:'Transparency',nav_docs:'Documentation',skip:'Skip to content',disclaimer:'Independent project. Not affiliated with or endorsed by upstream sources.',h:'Release history',intro:'GitHub Releases is the canonical archive. Changes are computed by comparing the signed manifests, file by file and hash by hash, never from the total.',cap:'Published releases',c_id:'Release',c_date:'Date',c_total:'Rules',c_add:'Added',c_mod:'Modified',c_rem:'Removed',c_sig:'Signature',c_links:'Links',loading:'Loading…',immut:'A published release is never edited: a correction is a new release. The publishing flow creates a new tag on every run; GitHub-enforced immutability is a repository setting.'}};
var X={es:{none:'Todavía no hay ninguna release publicada.',fail:'No se pudo cargar releases.json',valid:'firma del manifiesto válida (cosign, identidad del workflow)',invalid:'firma NO válida',notchecked:'no comprobada',by:'comprobado por',pkg:'paquete',man:'manifiesto',bun:'bundle',proof:'prueba',tbl:function(n){return n+' release(s), la más reciente primero'}},
en:{none:'There is no published release yet.',fail:'Could not load releases.json',valid:'manifest signature valid (cosign, workflow identity)',invalid:'signature NOT valid',notchecked:'not checked',by:'checked by',pkg:'package',man:'manifest',bun:'bundle',proof:'proof',tbl:function(n){return n+' release(s), newest first'}}};
var data=null,x=function(){return X[MG.L()]||X.es};
function render(){if(!data)return;var tb=document.querySelector('#rel-table tbody');tb.textContent='';var r=data.releases.slice().reverse();
 r.forEach(function(e){var tr=el('tr'),td=el('td');td.appendChild(el('a',{href:e.url,text:e.tag}));tr.appendChild(td);
  tr.appendChild(el('td',{text:MG.day(e.published_at)}));tr.appendChild(el('td',{text:String(e.total)}));tr.appendChild(el('td',{text:'+'+e.added}));tr.appendChild(el('td',{text:String(e.modified)}));tr.appendChild(el('td',{text:'−'+e.removed}));
  tr.appendChild(el('td',{class:'mono',title:e.rules_root,text:(e.rules_root||'').slice(0,16)+'…'}));
  td=el('td');var v=e.verification||{};var s=!v.checked?x().notchecked:v.manifest_signature==='valid'?x().valid:x().invalid;td.appendChild(el('span',{class:v.manifest_signature==='valid'?'okmsg':v.checked?'badmsg':'',text:s}));
  if(v.checked&&v.checked_by){td.appendChild(el('br'));td.appendChild(el('small',{text:x().by+': '+v.checked_by}))}tr.appendChild(td);
  td=el('td');[['rules-release.tar.gz',x().pkg],['manifest.json',x().man],['manifest.sigstore.json',x().bun],['inclusion-proof.json',x().proof]].forEach(function(p,i){if(i)td.appendChild(document.createTextNode(' · '));td.appendChild(el('a',{href:e.assets[p[0]],text:p[1]}))});tr.appendChild(td);tb.appendChild(tr)});
 $('rel-state').textContent=r.length?x().tbl(r.length):x().none}
MG.i18n(D,render);
MG.get('releases.json',true).then(function(d){data=d;render()}).catch(function(){$('rel-state').textContent=x().fail});
})();
