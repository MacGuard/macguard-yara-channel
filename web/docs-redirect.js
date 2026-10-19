/* docs/index.html: send the reader to the documentation in their language (the page also has a meta refresh and plain links). */
try{var f=document.currentScript.getAttribute('data-first')||'overview',l=localStorage.getItem('lang')||navigator.language||'en';if(!/^[a-z0-9-]+$/.test(f))f='overview';location.replace((String(l).slice(0,2)==='es'?'es':'en')+'/'+f+'.html')}catch(e){}
