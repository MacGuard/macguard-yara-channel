# Regenerates web/rules.html, releases.html and transparency.html. Run from web/: python3 ../scripts/gen_pages.py
NAV=[('./','Inicio','home'),('rules.html','Reglas YARA','rules'),('releases.html','Releases','releases'),('transparency.html','Transparencia','transparency'),('docs/index.html','Documentación','docs')]
CUR=' aria-current="page"'
def shell(cur,title,body,scripts):
    nav=''.join('<a href="%s"%s data-t="nav_%s">%s</a>'%(h,CUR if k==cur else '',k,t) for h,t,k in NAV)
    return ('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s · MacGuard YARA Channel</title><link rel="stylesheet" href="style.css">'
     '<a class="skip" href="#main" data-t="skip">Saltar al contenido</a><aside><h2>🛡 MacGuard</h2><small>YARA Rules Channel</small><nav aria-label="Principal">%s</nav></aside>'
     '<main id="main"><header><div><small>MACGUARD SECURITY</small></div><div><select id="lang" aria-label="Idioma / Language"><option value="es">Español</option><option value="en">English</option></select>'
     '<button id="theme" type="button" aria-label="Claro / oscuro · Light / dark">◐</button></div></header>%s<footer data-t="disclaimer">Proyecto independiente. Sin afiliación ni aval de las fuentes.</footer></main>%s</html>')%(title,nav,body,scripts)

rules_body='''<h1 data-t="h">Reglas YARA</h1>
<p data-t="intro">Catálogo generado a partir del manifiesto firmado de la última release. La tabla no descarga el paquete: lee <a href="catalog.json">catalog.json</a>.</p>
<section class="panel" aria-labelledby="dl-h"><h2 id="dl-h" data-t="dl_h">Descargas y comprobaciones</h2>
<ul class="dl" id="dl"><li><a id="dl-pkg" href="rules-release.tar.gz" data-t="dl_pkg">Descargar paquete completo</a> <span id="dl-pkg-note" class="muted"></span></li>
<li><a href="manifest.json" data-t="dl_man">Manifiesto firmado</a> · <a href="manifest.sigstore.json" data-t="dl_bundle">bundle Sigstore</a> <span class="muted" id="dl-man-sha"></span></li>
<li><a href="logs/checkpoint.txt" data-t="dl_cp">Checkpoint</a> · <a href="logs/checkpoint.sigstore.json" data-t="dl_cpb">bundle del checkpoint</a> · <a href="inclusion-proof.json" data-t="dl_proof">Prueba de inclusión</a> · <a href="latest.json">latest.json</a></li>
<li><a href="verify_public_release.py" download>Descargar verificador · Download verifier</a> · <a href="docs/es/verification.html">Cómo verificar</a> · <a href="docs/en/verification.html">How to verify</a></li>
<li><a href="releases.html" data-t="dl_hist">Historial de publicaciones</a> · <a href="rules-list.html" data-t="dl_plain">Lista completa sin JavaScript</a></li></ul>
<div id="ver" class="verbox" role="status"></div>
<p><button id="pkg-check" type="button" data-t="pkg_check">Comprobar el SHA-256 del paquete en este navegador</button> <span id="pkg-out" aria-live="polite"></span></p></section>
<section class="panel" aria-labelledby="t-h"><h2 id="t-h" data-t="t_h">Catálogo</h2>
<div class="toolbar"><label><span data-t="q_l">Buscar</span> <input id="q" type="search" placeholder="nombre, ruta o SHA-256" autocomplete="off"></label>
<label><span data-t="f_src">Fuente</span> <select id="f-src"><option value="">—</option></select></label>
<label><span data-t="f_cat">Categoría</span> <select id="f-cat"><option value="">—</option></select></label>
<label><span data-t="f_plat">Plataforma</span> <select id="f-plat"><option value="">—</option></select></label>
<label><span data-t="f_val">Validación</span> <select id="f-val"><option value="">—</option></select></label>
<label><span data-t="f_sort">Ordenar</span> <select id="sort"><option value="name">nombre</option><option value="category">categoría</option><option value="source">fuente</option><option value="bytes">tamaño ↓</option><option value="changed">cambio reciente</option></select></label>
<label><span data-t="f_size">Por página</span> <select id="size"><option>25</option><option selected>50</option><option>100</option></select></label></div>
<p id="count" aria-live="polite" data-t="loading">Cargando…</p>
<div class="tablewrap"><table id="rules-table"><caption class="sr" data-t="cap">Reglas YARA publicadas</caption><thead><tr><th scope="col" data-t="c_name">Fichero</th><th scope="col" data-t="c_cat">Categoría</th><th scope="col" data-t="c_plat">Plataforma</th><th scope="col" data-t="c_src">Fuente</th><th scope="col" data-t="c_repo">Repositorio</th><th scope="col" data-t="c_commit">Commit</th><th scope="col">SHA-256</th><th scope="col" data-t="c_bytes">Tamaño</th><th scope="col" data-t="c_val">Validación</th><th scope="col" data-t="c_date">Incorporada / cambiada</th><th scope="col" data-t="c_act">Descarga</th></tr></thead><tbody></tbody></table></div>
<nav class="pager" aria-label="Paginación"><button id="prev" type="button" data-t="prev">Anterior</button><span id="pageinfo" aria-live="polite"></span><button id="next" type="button" data-t="next">Siguiente</button></nav>
<p class="muted" data-t="hashnote">Un SHA-256 que coincide con el manifiesto demuestra que el fichero es el publicado; no es una firma individual de la regla. La autenticidad la da la firma Sigstore del manifiesto (no se verifica en esta página).</p>
<noscript><p><a href="rules-list.html">Lista completa de reglas (HTML estático)</a> · <a href="catalog.json">catalog.json</a> · <a href="manifest.json">manifest.json</a></p></noscript></section>'''
rel_body='''<h1 data-t="h">Historial de releases</h1>
<p data-t="intro">GitHub Releases es el archivo canónico. Los cambios se calculan comparando los manifiestos firmados, fichero a fichero y hash a hash, nunca por el total de reglas.</p>
<section class="panel"><div class="tablewrap"><table id="rel-table"><caption class="sr" data-t="cap">Releases publicadas</caption><thead><tr><th scope="col" data-t="c_id">Release</th><th scope="col" data-t="c_date">Fecha</th><th scope="col" data-t="c_total">Reglas</th><th scope="col" data-t="c_size">Paquete</th><th scope="col" data-t="c_add">Añadidas</th><th scope="col" data-t="c_mod">Modificadas</th><th scope="col" data-t="c_rem">Eliminadas</th><th scope="col">rules_root</th><th scope="col" data-t="c_sig">Firma</th><th scope="col" data-t="c_links">Enlaces</th></tr></thead><tbody></tbody></table></div><p id="rel-state" aria-live="polite" data-t="loading">Cargando…</p>
<p class="muted" data-t="immut">Una release publicada no se modifica: una corrección es una release nueva. El flujo de publicación crea una etiqueta nueva en cada ejecución; la inmutabilidad impuesta por GitHub es un ajuste del repositorio.</p>
<noscript><p><a href="releases.json">releases.json</a> · <a href="https://github.com/MacGuard/macguard-yara-channel/releases">GitHub Releases</a></p></noscript></section>'''
tr_body='''<h1 data-t="h">Transparencia</h1>
<p data-t="intro">Cada paso del proceso queda en un registro Merkle de solo-añadir. Aquí se ven sus cifras y se pueden descargar los ficheros para comprobarlos por tu cuenta.</p>
<section class="panel" aria-labelledby="f-h"><h2 id="f-h" data-t="facts">Estado del registro</h2><dl id="facts" class="facts"></dl>
<p><a href="logs/checkpoint.txt" data-t="dl_cp">Checkpoint</a> · <a href="logs/checkpoint.sigstore.json" data-t="dl_cpb">bundle del checkpoint</a> · <a href="inclusion-proof.json" data-t="dl_proof">prueba de inclusión</a> <span id="cons-link"></span> · <a href="logs/log.jsonl">log.jsonl</a> · <a href="logs/LOG.md">LOG.md</a> · <a href="manifest.json">manifest.json</a></p></section>
<section class="panel" aria-labelledby="v-h"><h2 id="v-h" data-t="v_h">Comprobar en este navegador</h2>
<p data-t="policy"><b>Política de confianza.</b> Esta página comprueba matemáticas: que log.jsonl produce la raíz del checkpoint, que la prueba de inclusión lleva la entrada de la release a esa raíz y, si existe, que el árbol anterior es prefijo del actual. NO comprueba la firma Sigstore del checkpoint ni del manifiesto: para eso usa cosign verify-blob con la identidad publicada o la app MacGuard. Descargar y mostrar un JSON no es una verificación.</p>
<p><a href="verify_public_release.py" download>Descargar verificador · Download verifier</a> (<a href="verify_public_release.py.sha256">SHA-256</a>) · <a href="docs/es/verification.html">Cómo verificar</a> · <a href="docs/en/verification.html">How to verify</a></p>
<p><button id="verify" type="button" data-t="v_btn">Ejecutar comprobaciones</button></p><ul id="checks" aria-live="polite"></ul></section>
<section class="panel" aria-labelledby="d-h"><h2 id="d-h" data-t="d_h">Dos registros distintos</h2>
<p data-t="diff"><b>Sigstore (Rekor)</b> es un registro público de terceros donde queda anotada cada firma, y Fulcio emite el certificado de la identidad del workflow. <b>El registro Merkle de MacGuard</b> lo mantiene este repositorio: guarda los eventos legibles (descargas, rechazos, aprobaciones) y lo que se firmó en cada release. Se verifican por separado: el primero prueba quién firmó; el segundo, qué ocurrió y que nada se reescribió.</p></section>
<section class="panel" aria-labelledby="e-h"><h2 id="e-h" data-t="e_h">Entradas del registro</h2><p id="log-state" aria-live="polite" data-t="loading">Cargando…</p>
<div class="tablewrap"><table id="log-table"><caption class="sr" data-t="e_h">Entradas del registro</caption><thead><tr><th scope="col">#</th><th scope="col" data-t="c_time">Fecha (UTC)</th><th scope="col" data-t="c_lvl">Nivel</th><th scope="col" data-t="c_code">Código</th><th scope="col" data-t="c_msg">Mensaje</th></tr></thead><tbody></tbody></table></div>
<p><button id="more" type="button" data-t="more">Mostrar más</button></p>
<noscript><p><a href="logs/LOG.md">LOG.md</a> · <a href="logs/log.jsonl">log.jsonl</a></p></noscript></section>'''
for name,cur,title,body,js in (('rules.html','rules','Reglas YARA',rules_body,'rules.js'),('releases.html','releases','Releases',rel_body,'releases.js'),('transparency.html','transparency','Transparencia',tr_body,'transparency.js')):
    open(name,'w').write(shell(cur,title,body,'<script src="common.js"></script><script src="%s"></script>'%js))
print('pages written')
