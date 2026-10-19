/* docs/index.html: send the reader to the documentation in their language (the page also has a meta refresh and plain links). The page id is a constant: nothing is read from the DOM. */
try{var l=localStorage.getItem('lang')||navigator.language||'en';location.replace((String(l).slice(0,2)==='es'?'es':'en')+'/overview.html')}catch(e){}
