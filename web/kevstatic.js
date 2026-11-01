/* Static CISA KEV search: the fallback while no lookup API is configured. Reads kev/index.json and ONE year shard at a time (built by
   scripts/portal_hub.py only from a KEV package verified in the same build). Each shard's SHA-256 is checked against the index before use; a mismatch
   is an error, never partial data. It covers the CISA KEV catalogue only: no NVD, EUVD or GCVE data, no CVSS or EPSS. */
(function(){
var CVE=/^CVE-(\d{4})-(\d{4,7})$/,idx=null,cache={},MAXB=600*1024,MAXLOAD=3;
function bytes(u){var c=window.AbortController?new AbortController():null,t=c?setTimeout(function(){c.abort()},8000):null;
 return fetch(u,{cache:'no-store',credentials:'omit',redirect:'error',signal:c?c.signal:undefined}).then(function(r){if(t)clearTimeout(t);if(!r.ok)throw new Error('HTTP '+r.status);return r.arrayBuffer()},function(e){if(t)clearTimeout(t);throw e})}
function index(){if(idx)return idx;idx=MG.getT('kev/index.json').then(function(d){
  if(d&&d.available===false)throw new Error('unavailable');   /* the build had no verified KEV package */
  if(!d||d.schema!=='macguard.portal-kev-index/1'||!Array.isArray(d.shards)||!d.source||d.source.license!=='CC0-1.0')throw new Error('bad index');return d});
 idx.catch(function(){idx=null});return idx}
function shard(s){if(cache[s.file])return cache[s.file];
 if(!/^kev\/\d{4}(-\d+)?\.json$/.test(s.file)||!/^[0-9a-f]{64}$/.test(s.sha256))return Promise.reject(new Error('bad shard entry'));
 cache[s.file]=bytes(s.file).then(function(buf){if(buf.byteLength>MAXB)throw new Error('shard too large');
  var check=window.crypto&&crypto.subtle?MG.sha256(buf).then(function(h){if(MG.hex(h)!==s.sha256)throw new Error('shard hash mismatch')}):Promise.reject(new Error('SubtleCrypto unavailable: cannot verify the shard'));
  return check.then(function(){var d=JSON.parse(new TextDecoder().decode(buf));if(!d||d.schema!=='macguard.portal-kev-shard/1'||!Array.isArray(d.items))throw new Error('bad shard');return d.items})});
 cache[s.file].catch(function(){delete cache[s.file]});return cache[s.file]}
function lc(v){return String(v==null?'':v).toLowerCase()}
function match(it,f){
 if(f.cve&&it.cve_id!==f.cve)return false;
 if(f.text){var h=lc(it.cve_id+' '+it.vendor+' '+it.product+' '+it.name+' '+it.short_description);if(h.indexOf(lc(f.text))<0)return false}
 if(f.vendor&&lc(it.vendor).indexOf(lc(f.vendor))<0)return false;
 if(f.product&&lc(it.product).indexOf(lc(f.product))<0)return false;
 if(f.cwe&&(it.cwes||[]).indexOf(f.cwe)<0)return false;
 if(f.date_from&&String(it.date_added||'')<f.date_from)return false;
 if(f.date_to&&String(it.date_added||'')>f.date_to)return false;
 return true}
MG.kev={
 index:index,
 /* one record or null (not in the published KEV catalogue) */
 get:function(cve){var m=CVE.exec(cve||'');if(!m)return Promise.resolve(null);
  return index().then(function(d){var ss=d.shards.filter(function(s){return s.year===m[1]&&s.first<=cve&&s.last>=cve});
   return Promise.all(ss.map(shard)).then(function(lists){for(var i=0;i<lists.length;i++)for(var j=0;j<lists[i].length;j++)if(lists[i][j].cve_id===cve)return lists[i][j];return null})})},
 /* keyset paging over the shards, newest year first: cursor = {s: shard position, i: item offset}; loads shards one by one until the page is full */
 search:function(f,cursor,limit){limit=Math.min(Math.max(limit||25,1),100);
  return index().then(function(d){var order=d.shards.slice().sort(function(a,b){return a.file<b.file?1:-1});
   if(f.cve){var y=CVE.exec(f.cve)[1];order=order.filter(function(s){return s.year===y})}
   var out=[],pos=cursor?cursor.s:0,off=cursor?cursor.i:0,loaded=0;
   // at most MAXLOAD shards per call: a search with few matches continues on demand ("next"), it never pulls the whole catalogue at once
   function step(){if(pos>=order.length||out.length>=limit||loaded>=MAXLOAD)return Promise.resolve({items:out,next:pos<order.length?{s:pos,i:off}:null,loaded:loaded});
    return shard(order[pos]).then(function(items){loaded++;var rows=items.slice().reverse();
     for(;off<rows.length;off++){if(match(rows[off],f)){out.push(rows[off]);if(out.length>=limit){off++;break}}}
     if(off>=rows.length){pos++;off=0}
     return step()})}
   return step()})}};
})();
