/* docs/index.html: send the reader to the documentation in their language (the page also has a meta refresh and plain links). */
try{var f=document.currentScript.getAttribute('data-first')||'overview',l=localStorage.getItem('lang')||navigator.language||'en';var m=/^[a-z0-9-]+$/.exec(f);f=m?m[0]:'overview';location.replace((String(l).slice(0,2)==='es'?'es':'en')+'/'+f+'.html')}catch(e){}
