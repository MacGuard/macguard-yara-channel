/* Plans: FREE / PREMIUM as server-checked capabilities, from capabilities.json. No prices, no checkout. textContent only. */
(function(){var $=MG.$,el=MG.el;
var D={es:{},en:{h:'Plans',intro:'What each plan includes, as capabilities the server checks. There are no prices and no active payments.',mode:'During the preview period everything published is free for everyone.',inc:'Includes everything in FREE, plus:',poc_h:'PoC and exploits',poc_p:'Outside the plans. Metadata and references only, never code, granted individually after review. Never part of a package or of automatic updates.'}};
var C={es:{'catalog.public.read':'Catálogo público de familias y reglas','vulnerability.public.read':'Fichas públicas de vulnerabilidades (CVE, EUVD, GCVE, CWE, CVSS, EPSS, KEV)','yara.community.download':'Descarga del paquete YARA Community firmado',
 'rules.premium.read':'Consulta de reglas avanzadas (Sigma, Suricata y otros motores admitidos)','rules.premium.download':'Descarga de paquetes defensivos avanzados','ioc.premium.read':'IOC, hashes y firmas','intel.correlation.read':'Correlaciones vulnerabilidad ↔ regla ↔ indicador','intel.advanced.export':'Exportación avanzada de inteligencia'},
 en:{'catalog.public.read':'Public catalog of families and rules','vulnerability.public.read':'Public vulnerability pages (CVE, EUVD, GCVE, CWE, CVSS, EPSS, KEV)','yara.community.download':'Download of the signed YARA Community package',
 'rules.premium.read':'Advanced rules (Sigma, Suricata and other supported engines)','rules.premium.download':'Advanced defensive packages','ioc.premium.read':'IOCs, hashes and signatures','intel.correlation.read':'Vulnerability ↔ rule ↔ indicator correlations','intel.advanced.export':'Advanced intelligence export'}};
var data=null;
function render(){if(!data)return;var c=C[MG.L()]||C.es;[['free','caps-free'],['premium','caps-premium']].forEach(function(p){var ul=$(p[1]);ul.textContent='';var plan=data.plans.filter(function(x){return x.id===p[0]})[0];
 (plan?plan.capabilities:[]).forEach(function(k){ul.appendChild(el('li',{},[document.createTextNode(c[k]||k),' ',el('code',{class:'muted',text:k})]))})})}
MG.i18n(D,render);
MG.getT('capabilities.json').then(function(d){data=d;render()}).catch(function(){});
})();
