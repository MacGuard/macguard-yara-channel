#!/usr/bin/env python3
"""Writes the static shells of the Subscriptions and Alerts pages (web/intelligence/alerts/*.html) and their ES/EN dictionary (alerts-i18n.js) from ONE table of
strings and from the versioned taxonomies (config/alerts/taxonomies/*.json), so a taxonomy value can never be missing a label in one language.

The pages contain no data and no status: alerts.js draws them from the static files under data/ next to the pages or, when a backend answers /api/v1/health, from the API.
usage: gen_alerts_pages.py [--check]     --check compares with the committed files and exits 1 on a difference"""
import html, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / 'web' / 'intelligence' / 'alerts'
TAXD = ROOT / 'config' / 'alerts' / 'taxonomies'
SITE = 'MacGuard Security Intelligence'

S = {}
def add(**kw):
    for k, v in kw.items(): S[k] = v

# ---- common chrome
add(skip=('Saltar al contenido', 'Skip to content'), nav_intel=('Inteligencia', 'Intelligence'), nav_home=('Inicio', 'Home'), nav_rules=('Reglas YARA', 'YARA rules'), nav_releases=('Releases', 'Releases'),
    nav_transparency=('Transparencia', 'Transparency'), nav_docs=('Documentación', 'Documentation'), nav_h_alerts=('Suscripciones y alertas', 'Subscriptions and alerts'), nav_h_other=('Resto del sitio', 'Rest of the site'),
    nav_explore=('Explorar alertas', 'Explore alerts'), nav_subscribe=('Crear suscripción', 'Create subscription'), nav_mine=('Mis suscripciones', 'My subscriptions'),
    nav_history=('Historial de notificaciones', 'Notification history'), nav_sources=('Fuentes de inteligencia', 'Intelligence sources'), nav_prefs=('Preferencias de entrega', 'Delivery preferences'),
    nav_org=('Administración organizativa', 'Organisation administration'),
    disclaimer=('Proyecto independiente. Sin afiliación ni aval de las fuentes.', 'Independent project. No affiliation with or endorsement by the sources.'),
    loading=('Cargando datos…', 'Loading data…'), loaded=('Datos cargados.', 'Data loaded.'),
    err_load=('No se pudieron cargar los datos (¿abres el fichero sin servidor?):', 'The data could not be loaded (are you opening the file without a server?):'),
    noscript=('Esta página necesita JavaScript. Sin él puedes leer los datos y los feeds directamente:', 'This page needs JavaScript. Without it you can read the data and the feeds directly:'),
    yes=('sí', 'yes'), no=('no', 'no'), na=('no disponible', 'not available'), all=('Todos', 'All'), none=('Ninguno', 'None'), any_=('Cualquiera', 'Any'),
    note_data_lang=('Los textos que vienen de las fuentes (títulos, descripciones, motivos) están en el idioma original, normalmente inglés.', 'Texts that come from the sources (titles, descriptions, reasons) are in their original language, usually English.'),
    generated=('Datos generados:', 'Data generated:'), origin=('origen', 'origin'), real=('Qué es real', 'What is real'))

# ---- backend state
add(be_checking=('Comprobando si hay un servicio de suscripciones…', 'Checking for a subscription service…'),
    be_none=('No hay un servicio de suscripciones conectado a esta página. Puedes explorar alertas, construir y previsualizar un filtro y usar los feeds públicos; guardar suscripciones, recibir avisos, feeds privados y la administración de organizaciones necesitan el servicio, que todavía no está desplegado. Para probarlo en local: python3 -m alerts serve.',
             'No subscription service is connected to this page. You can explore alerts, build and preview a filter and use the public feeds; saving subscriptions, receiving notifications, private feeds and organisation administration need the service, which is not deployed yet. To try it locally: python3 -m alerts serve.'),
    be_ok=('Servicio de suscripciones conectado (servidor de referencia: no es un servicio alojado).', 'Subscription service connected (reference server: not a hosted service).'),
    be_needs=('Esta función necesita el servicio de suscripciones.', 'This feature needs the subscription service.'))

# ---- auth panel
add(h_auth=('Cuenta', 'Account'), au_email=('Correo electrónico', 'E-mail'), au_password=('Contraseña (12 caracteres o más)', 'Password (12 characters or more)'), au_totp=('Código de segundo factor (si lo tienes activado)', 'Second-factor code (if you enabled it)'),
    au_login=('Iniciar sesión', 'Sign in'), au_register=('Crear cuenta', 'Create account'), au_logout=('Cerrar sesión', 'Sign out'), au_signed=('Sesión iniciada como', 'Signed in as'),
    au_registered=('Si la dirección es nueva, la cuenta ya existe. Inicia sesión.', 'If the address is new, the account exists now. Sign in.'),
    au_needs=('Inicia sesión para usar esta página.', 'Sign in to use this page.'), au_mfa_on=('Segundo factor activado', 'Second factor enabled'), au_mfa_off=('Segundo factor no activado', 'Second factor not enabled'),
    au_err_invalid_credentials=('Correo o contraseña incorrectos.', 'Wrong e-mail or password.'), au_err_locked=('Demasiados intentos: espera unos minutos.', 'Too many attempts: wait a few minutes.'),
    au_err_mfa_required=('Hace falta el código del segundo factor.', 'The second-factor code is required.'), au_err_generic=('No se pudo completar la acción:', 'The action could not be completed:'))

# ---- explore
add(t_index=('Explorar alertas', 'Explore alerts'), h_index=('Explorar alertas', 'Explore alerts'),
    p_index=('Alertas de vulnerabilidades y de nuevas versiones de reglas, con la fuente, las pruebas y los motivos de cada coincidencia. Solo aparecen datos de fuentes cuya redistribución está autorizada; si no hay ninguna, la lista queda vacía y se explica por qué. El país es el ámbito de la fuente, no dónde se explota una vulnerabilidad.',
             'Vulnerability alerts and new rule releases, with the source, the evidence and the reasons for every match. Only data from sources cleared for redistribution appears; if there is none the list is empty and says why. The country is the scope of the source, not where a vulnerability is exploited.'),
    h_filters=('Filtros', 'Filters'), h_results=('Resultados', 'Results'), h_feeds=('Feeds RSS públicos', 'Public RSS feeds'), h_snapshot=('Origen de los datos', 'Where the data comes from'),
    f_reset=('Quitar filtros', 'Clear filters'), f_apply=('Aplicar filtros', 'Apply filters'),
    snap_info=('Instantánea', 'Snapshot'), snap_count=('alertas', 'alerts'), snap_truncated=('(recortada a las más recientes)', '(truncated to the most recent)'),
    empty_title=('No hay alertas publicadas', 'No alerts are published'),
    empty_why=('Ninguna fuente de vulnerabilidades está a la vez autorizada por el registro y confirmada por el propietario, así que no se redistribuye nada de terceros. Lo que sí se publica son las versiones de reglas de MacGuard, que son datos propios. Mira «Fuentes de inteligencia».',
               'No vulnerability source is both cleared by the registry and confirmed by the owner, so nothing from third parties is redistributed. What is published are MacGuard rule releases, which are first-party data. See "Intelligence sources".'),
    count_of=('de', 'of'), count_none=('Ninguna alerta coincide con los filtros.', 'No alert matches the filters.'), count_suffix=('alertas', 'alerts'),
    r_why=('Por qué coincide', 'Why it matches'), r_open=('Ver detalle', 'Open details'), r_sources=('Fuentes', 'Sources'), r_severity=('Severidad', 'Severity'), r_exploited=('Explotación conocida según', 'Known exploitation according to'),
    r_not_asserted=('Ninguna fuente afirma explotación', 'No source asserts exploitation'), r_published=('Publicada', 'Published'), r_updated=('Actualizada', 'Updated'), r_region=('Ámbito de la fuente', 'Source scope'),
    r_unknown=('desconocida', 'unknown'), r_cvss=('CVSS', 'CVSS'), r_type=('Tipo', 'Type'), r_version=('versión del registro', 'record version'), r_fix=('Corrección indicada', 'Fix stated'),
    r_fix_unknown=('no indicada (desconocido, no «sin corrección»)', 'not stated (unknown, not "no fix")'), feed_items=('elementos', 'items'), feed_empty=('vacío: ninguna fuente autorizada alimenta este feed', 'empty: no cleared source feeds this feed'),
    feed_howto=('Copia la dirección del feed en tu lector RSS. Para comprobar un feed, calcula el SHA-256 del fichero y compáralo con feeds/index.json.', 'Copy the feed address into your RSS reader. To check a feed, compute the SHA-256 of the file and compare it with feeds/index.json.'),
    feed_lang=('Idioma', 'Language'), feed_download=('Abrir el feed', 'Open the feed'), feed_sha=('SHA-256', 'SHA-256'))

# ---- filter builder
add(fb_region=('País o región de la fuente', 'Country or region of the source'), fb_region_note=('España también cuenta como Unión Europea. Es el ámbito de la fuente, no el territorio afectado.', 'Spain also counts as the European Union. It is the scope of the source, not the affected territory.'),
    fb_sector=('Sector', 'Sector'), fb_sector_unknown=('Incluir alertas sin información de sector', 'Include alerts with no sector information'),
    fb_sector_note=('Ninguna fuente actual indica el sector. Sin esta casilla, un filtro por sector no devuelve nada.', 'No current source states a sector. Without this box a sector filter returns nothing.'),
    fb_tech=('Tecnología', 'Technology'), fb_vendor=('Fabricante (separa con comas)', 'Vendor (comma separated)'), fb_product=('Producto exacto (separa con comas)', 'Exact product (comma separated)'),
    fb_family=('Familia de producto: prefijo de palabra, por ejemplo «windows»', 'Product family: word prefix, for example "windows"'),
    fb_version=('Versión afectada', 'Affected version'), fb_version_vendor=('Fabricante', 'Vendor'), fb_version_product=('Producto', 'Product'), fb_version_version=('Versión instalada', 'Installed version'),
    fb_version_amb=('Incluir una versión suelta que la fuente no llama afectada ni corregida', 'Include a lone version the source calls neither affected nor fixed'),
    fb_version_note=('Compara con el texto del fabricante. No dice nada de un paquete de una distribución Linux: las distribuciones reaplican correcciones.', 'It compares with the vendor text. It says nothing about a Linux distribution package: distributions backport fixes.'),
    fb_os=('Sistema operativo', 'Operating system'), fb_category=('Tipo de tecnología', 'Technology type'), fb_service=('Servicio o protocolo (separa con comas)', 'Service or protocol (comma separated)'),
    fb_ecosystem=('Lenguaje o ecosistema', 'Language or ecosystem'), fb_exposure=('Exposición', 'Exposure'),
    fb_exposure_note=('La configuras tú. Solo reduce por el vector de ataque que dé la fuente (una vulnerabilidad local no importa a un servicio expuesto a Internet) y mantiene lo que no lo dice. No se deduce de puertos.', 'You set it. It only narrows by the attack vector the source states (a local vulnerability does not matter for an Internet-facing service) and keeps what does not state one. It is never inferred from ports.'),
    fb_vuln=('Vulnerabilidad', 'Vulnerability'), fb_ids=('Identificadores CVE, EUVD o GHSA (separa con comas)', 'CVE, EUVD or GHSA identifiers (comma separated)'), fb_severity=('Gravedad mínima', 'Minimum severity'),
    fb_cvss=('CVSS mínimo (0 a 10)', 'Minimum CVSS (0 to 10)'), fb_epss=('EPSS mínimo (tal como lo da la fuente)', 'Minimum EPSS (as the source gives it)'),
    fb_epss_note=('Ninguna fuente autorizada da EPSS hoy; el filtro existe y no coincide con nada hasta que la haya.', 'No cleared source gives EPSS today; the filter exists and matches nothing until there is one.'),
    fb_exploited=('Explotación conocida', 'Known exploitation'), fb_exploited_any=('Indiferente', 'Do not care'), fb_exploited_yes=('Solo explotadas según alguna fuente', 'Only exploited according to a source'), fb_exploited_no=('Solo las que ninguna fuente da por explotadas', 'Only those no source says are exploited'),
    fb_exploited_note=('«Crítica» no significa «explotada»: la explotación sale de un campo estructurado de la fuente.', '"Critical" does not mean "exploited": exploitation comes from a structured field of the source.'),
    fb_published=('Publicada desde', 'Published since'), fb_updated=('Actualizada desde', 'Updated since'), fb_new=('Incorporada en los últimos N días', 'Added in the last N days'),
    fb_fix=('Corrección', 'Fix'), fb_fix_yes=('Solo con corrección indicada', 'Only with a stated fix'), fb_fix_no=('Solo sin corrección indicada', 'Only without a stated fix'),
    fb_other=('Otras condiciones', 'Other conditions'), fb_source=('Fuente', 'Source'), fb_type=('Tipo de alerta', 'Alert type'), fb_family_threat=('Familia de amenaza (separa con comas)', 'Threat family (comma separated)'),
    fb_technique=('Técnicas MITRE ATT&CK, por ejemplo T1190 (separa con comas)', 'MITRE ATT&CK techniques, for example T1190 (comma separated)'),
    fb_technique_note=('Ninguna fuente actual indica técnicas ATT&CK.', 'No current source states ATT&CK techniques.'),
    fb_bad=('Hay un valor que no es válido:', 'A value is not valid:'),
    type_vulnerability=('Vulnerabilidad', 'Vulnerability'), type_advisory=('Aviso', 'Advisory'), type_rule_release=('Versión de reglas', 'Rule release'),
    cat_container_platform=('Plataforma de contenedores', 'Container platform'), cat_network_device=('Dispositivo de red', 'Network device'), cat_cloud=('Tecnología cloud', 'Cloud technology'),
    cat_service_protocol=('Servicio o protocolo', 'Service or protocol'), cat_library=('Biblioteca', 'Library'),
    eco_npm=('npm', 'npm'), eco_pypi=('PyPI', 'PyPI'), eco_maven=('Maven', 'Maven'), eco_go=('Go', 'Go'), eco_cargo=('Cargo', 'Cargo'), eco_nuget=('NuGet', 'NuGet'), eco_rubygems=('RubyGems', 'RubyGems'), eco_packagist=('Packagist', 'Packagist'),
    eco_debian=('Debian', 'Debian'), eco_ubuntu=('Ubuntu', 'Ubuntu'), eco_alpine=('Alpine', 'Alpine'), eco_rpm=('RPM', 'RPM'), eco_hex=('Hex', 'Hex'), eco_pub=('Pub', 'Pub'), eco_swifturl=('SwiftPM', 'SwiftPM'), eco_other=('Otro', 'Other'),
    band_none=('ninguna', 'none'), band_low=('baja', 'low'), band_medium=('media', 'medium'), band_high=('alta', 'high'), band_critical=('crítica', 'critical'), band_unknown=('desconocida', 'unknown'))

# ---- reasons and states
add(why_scope=('ámbito de la fuente', 'source scope'), why_empty=('sin condiciones', 'no conditions'), why_observed=('observado', 'observed'), why_expected=('pedido', 'asked'),
    why_basis=('base', 'basis'), why_negated=('(negado)', '(negated)'),
    st_active=('activa', 'active'), st_stale=('desactualizada', 'stale'), st_pending=('pendiente', 'pending'), st_blocked=('bloqueada', 'blocked'), st_implemented_no_data=('implementada, sin datos', 'implemented, no data'),
    st_fresh=('al día', 'fresh'), st_never=('nunca importada', 'never imported'))

# ---- alert detail
add(t_alert=('Detalle de la alerta', 'Alert details'), h_alert=('Detalle de la alerta', 'Alert details'),
    p_alert=('Todo lo que dice cada fuente sobre esta alerta, con el fichero y la posición donde se puede comprobar. Las diferencias entre fuentes se muestran, no se ocultan.', 'Everything each source says about this alert, with the file and position where it can be checked. Differences between sources are shown, not hidden.'),
    a_notfound=('No hay una alerta publicada con ese identificador.', 'There is no published alert with that identifier.'), a_ids=('Identificadores', 'Identifiers'), a_severity=('Gravedad', 'Severity'),
    a_exploitation=('Explotación según cada fuente', 'Exploitation according to each source'), a_affected=('Productos afectados (texto de cada fuente)', 'Affected products (each source\'s text)'),
    a_obs=('Observaciones por fuente', 'Observations by source'), a_discrepancies=('Diferencias entre fuentes', 'Differences between sources'), a_refs=('Referencias', 'References'), a_license=('Licencia y atribución', 'Licence and attribution'),
    a_validation=('Validación', 'Validation'), a_dates=('Fechas', 'Dates'), a_mitig=('Mitigaciones', 'Mitigations'), a_none_stated=('ninguna indicada por las fuentes', 'none stated by the sources'),
    a_evidence=('Evidencia', 'Evidence'), a_file=('Fichero', 'File'), a_locator=('Posición', 'Position'), a_hash=('SHA-256 del fichero', 'File SHA-256'), a_withheld=('fuentes retenidas por licencia', 'sources withheld for licence reasons'),
    a_source=('Fuente', 'Source'), a_since=('Desde', 'Since'), a_asserted=('Afirma explotación', 'Asserts exploitation'), a_basis=('Base', 'Basis'), a_product=('Producto', 'Product'), a_versions=('Versiones', 'Versions'),
    a_os=('Sistema', 'System'), a_independent=('Confirmación independiente', 'Independent confirmation'), a_back=('Volver a las alertas', 'Back to the alerts'))

# ---- sources
add(t_sources=('Fuentes de inteligencia', 'Intelligence sources'), h_sources=('Fuentes de inteligencia', 'Intelligence sources'),
    p_sources=('Cada fuente con su endpoint oficial, formato, frecuencia esperada, licencia y estado real. «Pendiente» y «bloqueada» significan que no alimentan ninguna alerta. Las condiciones de redistribución son evidencia leída, no asesoría legal.',
               'Each source with its official endpoint, format, expected frequency, licence and real state. "Pending" and "blocked" mean they feed no alert. Redistribution conditions are evidence read, not legal advice.'),
    so_name=('Fuente', 'Source'), so_state=('Estado', 'State'), so_region=('Ámbito', 'Scope'), so_endpoint=('Endpoint oficial', 'Official endpoint'), so_format=('Formato', 'Format'), so_freq=('Frecuencia esperada (días)', 'Expected frequency (days)'),
    so_license=('Licencia', 'Licence'), so_redistribution=('Redistribución', 'Redistribution'), so_owner=('Confirmada por el propietario', 'Confirmed by the owner'), so_publishable=('Se puede redistribuir', 'Can be redistributed'),
    so_fresh=('Frescura', 'Freshness'), so_alerts=('Alertas', 'Alerts'), so_note=('Nota', 'Note'), so_blocking=('Bloqueo', 'Blocking'), so_legend=('Qué significa cada estado', 'What each state means'),
    so_legend_active=('activa: hay un adaptador, se ha importado y los datos son recientes.', 'active: there is an adapter, it was imported and the data is recent.'),
    so_legend_stale=('desactualizada: la última importación es más antigua que el límite; sus afirmaciones de explotación no cuentan como actuales.', 'stale: the last import is older than the limit; its exploitation statements do not count as current.'),
    so_legend_implemented=('implementada, sin datos: hay adaptador pero no se ha importado nada en este servicio.', 'implemented, no data: there is an adapter but nothing was imported in this service.'),
    so_legend_pending=('pendiente: no hay adaptador. No alimenta alertas.', 'pending: there is no adapter. It feeds no alerts.'),
    so_legend_blocked=('bloqueada: no se puede integrar por sus condiciones o por su acceso. No alimenta alertas.', 'blocked: it cannot be integrated because of its terms or access. It feeds no alerts.'))

# ---- subscribe
add(t_subscribe=('Crear suscripción', 'Create subscription'), h_subscribe=('Crear suscripción', 'Create subscription'),
    p_subscribe=('Elige qué quieres recibir y cómo. La vista previa usa alertas reales y no envía nada. Una suscripción nueva solo ve lo que ocurra a partir de que la actives.', 'Choose what you want to receive and how. The preview uses real alerts and sends nothing. A new subscription only sees what happens after you activate it.'),
    h_sub_basics=('Datos de la suscripción', 'Subscription details'), sb_name=('Nombre', 'Name'), sb_scope=('Ámbito', 'Scope'), sb_org=('Organización', 'Organisation'), sb_unit=('Unidad', 'Unit'), sb_group=('Grupo de equipos', 'Device group'),
    sb_customer=('Organización cliente (MSP)', 'Customer organisation (MSP)'),
    scope_PERSONAL=('Personal', 'Personal'), scope_ORGANIZATION=('Toda la organización', 'Whole organisation'), scope_ORGANIZATION_UNIT=('Una unidad de la organización', 'One organisation unit'),
    scope_DEVICE_GROUP=('Un grupo de equipos', 'One device group'), scope_MSP_CUSTOMER=('Cliente de un MSP', 'MSP customer'),
    h_sub_save=('Guardar y probar', 'Save and test'), h_sub_delivery=('Entrega', 'Delivery'), sb_frequency=('Periodicidad', 'Frequency'), freq_immediate=('Inmediata', 'Immediate'), freq_daily=('Resumen diario', 'Daily digest'), freq_weekly=('Resumen semanal', 'Weekly digest'),
    sb_critical=('Avisar de inmediato si es crítica o aparece explotación, aunque elija un resumen', 'Notify at once if critical or exploitation appears, even if I chose a digest'),
    sb_notify=('Avisar cuando', 'Notify when'), nk_new=('aparece una alerta nueva', 'a new alert appears'), nk_exploitation_added=('una fuente afirma explotación por primera vez', 'a source asserts exploitation for the first time'),
    nk_exploitation_source_added=('otra fuente afirma explotación', 'another source asserts exploitation'), nk_fix_available=('se indica una corrección', 'a fix is stated'), nk_severity_up=('sube la gravedad', 'severity goes up'),
    nk_severity_down=('baja la gravedad', 'severity goes down'), nk_scope_added=('una fuente nueva la confirma o amplía', 'a new source confirms or extends it'), nk_affected_changed=('se añaden productos afectados', 'affected products are added'),
    nk_mitigation_added=('aparece una mitigación', 'a mitigation appears'),
    sb_channels=('Canales de entrega', 'Delivery channels'), sb_channels_none=('No tienes canales confirmados. Añádelos en «Preferencias de entrega». Las alertas siempre aparecen en tu historial y en tu feed privado.', 'You have no confirmed channels. Add them in "Delivery preferences". Alerts always appear in your history and your private feed.'),
    h_sub_preview=('Vista previa de coincidencias', 'Match preview'), sb_preview=('Ver coincidencias', 'Show matches'),
    sb_preview_note=('Vista previa: alertas reales ya existentes que cumplirían el filtro. No son avisos enviados y activar la suscripción no los envía.', 'Preview: real alerts that already exist and would satisfy the filter. They are not notifications that were sent and activating the subscription does not send them.'),
    sb_preview_source_server=('calculada por el servicio', 'computed by the service'), sb_preview_source_static=('calculada en tu navegador con la instantánea pública', 'computed in your browser from the public snapshot'),
    sb_save_draft=('Guardar como borrador', 'Save as draft'), sb_save_active=('Guardar y activar', 'Save and activate'), sb_update=('Guardar cambios', 'Save changes'), sb_test=('Enviar prueba a los canales', 'Send a test to the channels'),
    sb_saved=('Suscripción guardada.', 'Subscription saved.'), sb_test_done=('Prueba enviada (marcada como prueba, no cuenta como alerta):', 'Test sent (labelled as a test, not counted as an alert):'),
    sb_filter_json=('Filtro como datos (solo lectura)', 'Filter as data (read only)'), sb_editing=('Editando la suscripción', 'Editing subscription'),
    sb_preview_count=('coincidencias', 'matches'))

# ---- mine / history
add(t_mine=('Mis suscripciones', 'My subscriptions'), h_mine=('Mis suscripciones', 'My subscriptions'), p_mine=('Las suscripciones que puedes ver, personales y de tus organizaciones, con su estado.', 'The subscriptions you can see, personal and from your organisations, with their state.'),
    m_none=('No tienes suscripciones.', 'You have no subscriptions.'), m_create=('Crear una suscripción', 'Create a subscription'), m_edit=('Editar', 'Edit'), m_duplicate=('Duplicar', 'Duplicate'), m_suspend=('Suspender', 'Suspend'),
    m_resume=('Reactivar', 'Resume'), m_delete=('Eliminar', 'Delete'), m_confirm_delete=('Confirmar eliminación', 'Confirm deletion'), m_cancel=('Cancelar', 'Cancel'),
    m_state=('Estado', 'State'), m_scope=('Ámbito', 'Scope'), m_freq=('Periodicidad', 'Frequency'), m_channels=('Canales', 'Channels'), m_version=('Versión del filtro', 'Filter version'),
    state_active=('activa', 'active'), state_suspended=('suspendida', 'suspended'), state_draft=('borrador', 'draft'),
    t_history=('Historial de notificaciones', 'Notification history'), h_history=('Historial de notificaciones', 'Notification history'),
    p_history=('Cada coincidencia de tus suscripciones, por qué ocurrió y qué se entregó. Las alertas actualizadas solo aparecen otra vez si el cambio es relevante.', 'Every match of your subscriptions, why it happened and what was delivered. Updated alerts only appear again when the change is relevant.'),
    h_matches=('Coincidencias', 'Matches'), h_deliveries=('Entregas', 'Deliveries'), hi_unread=('Solo sin leer', 'Unread only'), hi_sub=('Suscripción', 'Subscription'), hi_none=('No hay coincidencias todavía.', 'There are no matches yet.'),
    hi_read=('Marcar como leída', 'Mark as read'), hi_ack=('Confirmar recepción', 'Acknowledge'), hi_acked=('confirmada', 'acknowledged'), hi_kind=('Tipo', 'Kind'), hi_changes=('Cambios', 'Changes'), hi_when=('Cuándo', 'When'),
    kind_new=('nueva', 'new'), kind_update=('actualizada', 'updated'), dl_state=('Estado', 'State'), dl_attempts=('Intentos', 'Attempts'), dl_mode=('Modo', 'Mode'), dl_channel=('Canal', 'Channel'), dl_error=('Último error', 'Last error'),
    dl_sent=('Enviada', 'Sent'), dl_none=('No hay entregas todavía.', 'There are no deliveries yet.'),
    dstate_pending=('pendiente', 'pending'), dstate_sent=('enviada', 'sent'), dstate_retry=('reintentando', 'retrying'), dstate_dead=('fallida definitiva', 'failed for good'), dstate_cancelled=('cancelada', 'cancelled'), dstate_sending=('enviándose', 'sending'),
    mode_immediate=('inmediata', 'immediate'), mode_digest=('resumen', 'digest'), more=('Ver más', 'Show more'))

# ---- preferences
add(t_prefs=('Preferencias de entrega', 'Delivery preferences'), h_prefs=('Preferencias de entrega', 'Delivery preferences'),
    p_prefs=('Dónde y cómo recibes los avisos: correo, webhook y feeds RSS privados. Nada se envía a una dirección hasta que su dueño la confirma.', 'Where and how you receive notifications: e-mail, webhook and private RSS feeds. Nothing is sent to an address until its owner confirms it.'),
    h_pref_lang=('Idioma de la cuenta', 'Account language'), h_channels=('Canales', 'Channels'), h_tokens=('Feeds RSS privados', 'Private RSS feeds'), h_privacy=('Tus datos', 'Your data'),
    ch_add_email=('Añadir correo', 'Add e-mail'), ch_email=('Dirección de correo', 'E-mail address'), ch_email_lang=('Idioma de los mensajes', 'Message language'), ch_add_webhook=('Añadir webhook', 'Add webhook'),
    ch_url=('Dirección HTTPS del webhook (nombre público; no se aceptan IP, puertos distintos de 443 o 8443 ni redes internas)', 'HTTPS webhook address (public name; IP addresses, ports other than 443 or 8443 and internal networks are refused)'),
    ch_none=('No tienes canales.', 'You have no channels.'), ch_pending=('pendiente de confirmar: te hemos enviado un enlace', 'waiting for confirmation: we sent you a link'),
    ch_secret=('Secreto de firma (se muestra una sola vez; guárdalo ahora):', 'Signing secret (shown only once; store it now):'), ch_rotate=('Rotar clave', 'Rotate key'), ch_test=('Enviar prueba', 'Send test'), ch_delete=('Eliminar', 'Delete'),
    ch_confirm_delete=('Confirmar eliminación', 'Confirm deletion'), ch_kind=('Tipo', 'Kind'), ch_label=('Etiqueta', 'Label'), ch_address=('Destino', 'Destination'), ch_state=('Estado', 'State'),
    ch_webhook_howto=('Verifica la cabecera X-MacGuard-Signature (t=<fecha>,v1=<HMAC-SHA256 de «fecha.cuerpo»>) con el secreto, rechaza fechas con más de 5 minutos y usa X-MacGuard-Event-Id para no procesar dos veces el mismo evento.',
                      'Verify the X-MacGuard-Signature header (t=<time>,v1=<HMAC-SHA256 of "time.body">) with the secret, reject timestamps older than 5 minutes and use X-MacGuard-Event-Id to avoid processing an event twice.'),
    ch_test_result=('Resultado de la prueba:', 'Test result:'),
    tk_create=('Crear feed privado', 'Create private feed'), tk_label=('Nombre del feed', 'Feed name'), tk_scope=('Contenido', 'Content'), tk_scope_personal=('Mis suscripciones personales', 'My personal subscriptions'),
    tk_expires=('Caduca en (días)', 'Expires in (days)'), tk_url=('Dirección del feed (se muestra una sola vez):', 'Feed address (shown only once):'),
    tk_warn=('Esa dirección ES el secreto: quien la tenga puede leer el feed hasta que la revoques. Ponla solo en tu lector RSS.', 'That address IS the secret: anyone who has it can read the feed until you revoke it. Put it only in your RSS reader.'),
    tk_howto=('En tu lector RSS elige «añadir suscripción» y pega la dirección completa. Si la pierdes, revócala y crea otra.', 'In your RSS reader choose "add subscription" and paste the full address. If you lose it, revoke it and create another.'),
    tk_revoke=('Revocar', 'Revoke'), tk_rotate=('Rotar', 'Rotate'), tk_none=('No tienes feeds privados.', 'You have no private feeds.'), tk_name=('Nombre', 'Name'), tk_created=('Creado', 'Created'), tk_expiry=('Caduca', 'Expires'),
    tk_last=('Último uso', 'Last used'), tk_uses=('Usos', 'Uses'), tk_revoked=('revocado', 'revoked'),
    pv_export=('Descargar mis datos', 'Download my data'), pv_erase=('Borrar mi cuenta', 'Erase my account'), pv_erase_confirm=('Escribe «erase my account» para confirmar el borrado definitivo', 'Type "erase my account" to confirm the permanent erasure'),
    pv_erase_go=('Borrar definitivamente', 'Erase permanently'), pv_note=('El borrado elimina tus canales, direcciones y suscripciones y anonimiza la cuenta. El registro de auditoría conserva solo identificadores.', 'Erasure removes your channels, addresses and subscriptions and anonymises the account. The audit log keeps only identifiers.'))

# ---- organisations
add(t_org=('Administración organizativa', 'Organisation administration'), h_org=('Administración organizativa', 'Organisation administration'),
    p_org=('Organizaciones, miembros y roles, unidades, grupos de equipos, relaciones con un MSP y registro de auditoría. La administración exige el segundo factor. Funciones de la fase P2: núcleo probado, sin proveedor de identidad externo.',
           'Organisations, members and roles, units, device groups, MSP relationships and the audit log. Administration requires the second factor. Phase P2 features: tested core, no external identity provider.'),
    h_orgs=('Tus organizaciones', 'Your organisations'), og_create=('Crear organización', 'Create organisation'), og_name=('Nombre de la organización', 'Organisation name'), og_kind=('Tipo', 'Kind'), og_kind_org=('Organización', 'Organisation'), og_kind_msp=('MSP', 'MSP'),
    og_none=('No perteneces a ninguna organización.', 'You do not belong to any organisation.'), og_pick=('Organización', 'Organisation'), og_role=('Rol', 'Role'), og_perms=('Permisos', 'Permissions'),
    h_members=('Miembros', 'Members'), mb_email=('Correo de una cuenta existente', 'E-mail of an existing account'), mb_role=('Rol', 'Role'), mb_unit=('Limitar a una unidad (opcional)', 'Limit to one unit (optional)'), mb_add=('Añadir miembro', 'Add member'),
    mb_remove=('Quitar', 'Remove'), mb_change=('Cambiar rol', 'Change role'), mb_since=('Desde', 'Since'),
    role_owner=('Propietario', 'Owner'), role_administrator=('Administrador', 'Administrator'), role_security_manager=('Responsable de seguridad', 'Security manager'), role_auditor=('Auditor', 'Auditor'),
    role_operator=('Operador', 'Operator'), role_viewer=('Lector', 'Viewer'), role_msp_administrator=('Administrador MSP', 'MSP administrator'),
    h_units=('Unidades y grupos de equipos', 'Units and device groups'), un_name=('Nombre', 'Name'), un_add_unit=('Añadir unidad', 'Add unit'), un_add_group=('Añadir grupo de equipos', 'Add device group'), un_parent=('Unidad superior (opcional)', 'Parent unit (optional)'),
    un_units=('Unidades', 'Units'), un_groups=('Grupos de equipos', 'Device groups'), un_none=('Ninguno', 'None'),
    h_msp=('Relación con un MSP', 'MSP relationship'), msp_note=('Un MSP propone, el cliente acepta y delega un rol; el MSP nunca gestiona miembros ni lee la auditoría del cliente. Cualquiera de las dos partes puede terminarla.', 'An MSP proposes, the customer accepts and delegates a role; the MSP never manages members or reads the customer audit log. Either side can end it.'),
    msp_customer=('Identificador de la organización cliente', 'Customer organisation identifier'), msp_role=('Rol delegado', 'Delegated role'), msp_propose=('Proponer relación', 'Propose relationship'),
    msp_link=('Identificador de la relación', 'Relationship identifier'), msp_accept=('Aceptar (cliente)', 'Accept (customer)'), msp_end=('Terminar', 'End'), msp_msporg=('Identificador de tu organización MSP', 'Identifier of your MSP organisation'),
    h_audit=('Registro de auditoría', 'Audit log'), au_when=('Cuándo', 'When'), au_actor=('Quién', 'Who'), au_action=('Acción', 'Action'), au_target=('Objeto', 'Target'), au_chain=('Cadena de hashes íntegra', 'Hash chain intact'),
    h_mfa=('Segundo factor (TOTP)', 'Second factor (TOTP)'), mfa_enroll=('Activar segundo factor', 'Enable second factor'), mfa_secret=('Clave para tu app de autenticación:', 'Key for your authenticator app:'),
    mfa_code=('Código de 6 dígitos para confirmar', '6-digit code to confirm'), mfa_confirm=('Confirmar', 'Confirm'), mfa_done=('Segundo factor activado. Se cerraron las sesiones: inicia sesión con el código.', 'Second factor enabled. Sessions were closed: sign in with the code.'),
    mfa_need=('Para administrar organizaciones inicia sesión con tu segundo factor.', 'To administer organisations sign in with your second factor.'))

# ---- taxonomy labels come from the files
def tax(name):
    return json.loads((TAXD / f'{name}.json').read_text(encoding='utf-8'))
for it in tax('sectors')['items']:
    nis2 = (f" · NIS2 anexo {it['nis2']['annex']}: {it['nis2']['sector']}", f" · NIS2 annex {it['nis2']['annex']}: {it['nis2']['sector']}") if it['nis2'] else ('', '')
    S['tax_sector_' + it['id']] = (it['es'] + nis2[0], it['en'] + nis2[1])
for it in tax('regions')['items']: S['tax_region_' + it['id']] = (it['es'], it['en'])
for it in tax('os-families')['items']: S['tax_os_' + it['id']] = (it['es'], it['en'])
for it in tax('exposure')['items']: S['tax_exposure_' + it['id']] = (it['es'], it['en'])

PAGES = ['index', 'alert', 'subscribe', 'mine', 'history', 'sources', 'prefs', 'org']
FILE = {'index': 'index.html', 'alert': 'alert.html', 'subscribe': 'subscribe.html', 'mine': 'mine.html', 'history': 'history.html', 'sources': 'sources.html', 'prefs': 'preferences.html', 'org': 'org.html'}
NAV = [('index.html', 'nav_explore', 'index'), ('subscribe.html', 'nav_subscribe', 'subscribe'), ('mine.html', 'nav_mine', 'mine'), ('history.html', 'nav_history', 'history'),
       ('sources.html', 'nav_sources', 'sources'), ('preferences.html', 'nav_prefs', 'prefs'), ('org.html', 'nav_org', 'org')]
OTHER = [('../index.html', 'nav_intel'), ('../../index.html', 'nav_home'), ('../../rules.html', 'nav_rules'), ('../../releases.html', 'nav_releases'), ('../../transparency.html', 'nav_transparency'), ('../../docs/index.html', 'nav_docs')]
AUTH_PAGES = ('subscribe', 'mine', 'history', 'prefs', 'org')

def e(s): return html.escape(s, quote=True)
def T(tag, key, cls='', extra=''):
    return f'<{tag}{(" class=" + chr(34) + cls + chr(34)) if cls else ""}{extra} data-t="{key}">{e(S[key][0])}</{tag}>'

def chrome(page, body):
    nav = ''.join(f'<a href="{h}" data-t="{k}"{" aria-current=" + chr(34) + "page" + chr(34) if p == page or (page == "alert" and p == "index") else ""}>{e(S[k][0])}</a>' for h, k, p in NAV)
    other = ''.join(f'<a href="{h}" data-t="{k}">{e(S[k][0])}</a>' for h, k in OTHER)
    return ('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{e(S["t_" + page][0])} · {SITE}</title><link rel="stylesheet" href="../../style.css"><link rel="stylesheet" href="../intel.css"><link rel="stylesheet" href="alerts.css">\n'
            f'<body data-page="{page}"><a class="skip" href="#main" data-t="skip">{e(S["skip"][0])}</a>'
            f'<aside><h2>🛡 MacGuard</h2><small>Security Intelligence</small><nav aria-label="{e(S["nav_h_alerts"][0])}" data-t-label="nav_h_alerts">{nav}</nav>'
            f'<nav class="legacy" aria-label="{e(S["nav_h_other"][0])}" data-t-label="nav_h_other">{other}</nav></aside>'
            '<main id="main"><header><div><small>MACGUARD SECURITY</small>'
            f'{T("h1", "h_" + page)}{T("p", "p_" + page)}</div>'
            '<div><select id="lang" aria-label="Idioma / Language"><option value="es">Español</option><option value="en">English</option></select>'
            '<button id="theme" type="button" aria-label="Claro / oscuro · Light / dark">◐</button></div></header>\n'
            f'<p id="load-state" role="status" data-t="loading">{e(S["loading"][0])}</p>\n<div id="backend" class="notice" role="status"></div>\n{body}\n'
            f'{T("p", "note_data_lang", "muted")}\n{T("footer", "disclaimer")}</main>'
            '<script src="../../common.js"></script><script src="alerts-i18n.js"></script><script src="filter.js"></script><script src="alerts.js"></script></html>\n')

def noscript(*files):
    links = ' · '.join(f'<a href="{f}">{f}</a>' for f in files)
    return f'<noscript><p class="notice">{e(S["noscript"][0])} {links}</p></noscript>'

def section(hid, key, inner, cls='panel'):
    return f'<section class="{cls}" aria-labelledby="{hid}">{T("h2", key, extra=" id=" + chr(34) + hid + chr(34))}{inner}</section>\n'

def auth_panel():
    return ('<section class="panel" id="auth" aria-labelledby="au-h" hidden>' + T('h2', 'h_auth', extra=' id="au-h"') + '<div id="auth-body"></div></section>\n')

def body(page):
    if page == 'index':
        return (section('flt-h', 'h_filters', '<div id="filter-ui"></div><div class="actions"><button type="button" id="f-apply" data-t="f_apply">' + e(S['f_apply'][0]) + '</button>'
                        '<button type="button" id="f-reset" data-t="f_reset">' + e(S['f_reset'][0]) + '</button></div>') +
                f'<section aria-labelledby="res-h">{T("h2", "h_results", extra=" id=" + chr(34) + "res-h" + chr(34))}<p id="count" role="status" aria-live="polite"></p><div id="empty"></div><ul class="cardlist" id="results"></ul></section>\n' +
                section('feeds-h', 'h_feeds', T('p', 'feed_howto') + '<div id="feeds"></div>') + section('snap-h', 'h_snapshot', '<div id="snapshot"></div>') + noscript('data/snapshot.json', '../../feeds/index.json'))
    if page == 'alert':
        return f'<p><a href="index.html" data-t="a_back">{e(S["a_back"][0])}</a></p><div id="alert"></div>\n' + noscript('data/snapshot.json')
    if page == 'sources':
        return section('so-h', 'h_sources', '<div id="sources"></div>') + section('lg-h', 'so_legend', '<ul class="dl" id="legend"></ul>') + noscript('data/sources.json')
    if page == 'subscribe':
        basics = ('<div class="fields"><label>' + T('span', 'sb_name') + ' <input id="sb-name" type="text" maxlength="120" autocomplete="off"></label>'
                  '<label>' + T('span', 'sb_scope') + ' <select id="sb-scope"></select></label>'
                  '<label id="sb-org-l" hidden>' + T('span', 'sb_org') + ' <select id="sb-org"></select></label>'
                  '<label id="sb-unit-l" hidden>' + T('span', 'sb_unit') + ' <select id="sb-unit"></select></label>'
                  '<label id="sb-group-l" hidden>' + T('span', 'sb_group') + ' <select id="sb-group"></select></label>'
                  '<label id="sb-customer-l" hidden>' + T('span', 'sb_customer') + ' <input id="sb-customer" type="text" maxlength="60" autocomplete="off"></label></div>')
        deliv = ('<div class="fields"><label>' + T('span', 'sb_frequency') + ' <select id="sb-freq"></select></label>'
                 '<label class="check"><input type="checkbox" id="sb-critical" checked> ' + T('span', 'sb_critical') + '</label></div>'
                 '<fieldset><legend data-t="sb_notify">' + e(S['sb_notify'][0]) + '</legend><div id="sb-notify" class="checks"></div></fieldset>'
                 '<fieldset><legend data-t="sb_channels">' + e(S['sb_channels'][0]) + '</legend><div id="sb-channels" class="checks"></div></fieldset>')
        return (auth_panel() + section('b-h', 'h_sub_basics', basics) + section('f-h', 'h_filters', '<div id="filter-ui"></div>') + section('d-h', 'h_sub_delivery', deliv) +
                section('p-h', 'h_sub_preview', '<p class="notice" data-t="sb_preview_note">' + e(S['sb_preview_note'][0]) + '</p><div class="actions"><button type="button" id="sb-preview" data-t="sb_preview">' + e(S['sb_preview'][0]) + '</button></div>'
                        '<p id="pv-count" role="status" aria-live="polite"></p><ul class="cardlist" id="pv-results"></ul>') +
                '<section class="panel" aria-labelledby="s-h">' + T('h2', 'h_sub_save', extra=' id="s-h"') + '<div class="actions"><button type="button" id="sb-save-draft" data-t="sb_save_draft">' + e(S['sb_save_draft'][0]) +
                '</button><button type="button" id="sb-save-active" data-t="sb_save_active">' + e(S['sb_save_active'][0]) + '</button><button type="button" id="sb-test" data-t="sb_test" hidden>' + e(S['sb_test'][0]) + '</button></div>'
                '<p id="sb-status" role="status" aria-live="polite"></p><details><summary data-t="sb_filter_json">' + e(S['sb_filter_json'][0]) + '</summary><pre id="sb-json" class="cmd"></pre></details></section>\n' + noscript('data/snapshot.json'))
    if page == 'mine':
        return auth_panel() + '<div id="mine"></div>\n' + noscript('data/snapshot.json')
    if page == 'history':
        flt = ('<div class="toolbar"><label>' + T('span', 'hi_sub') + ' <select id="hi-sub"></select></label><label class="check"><input type="checkbox" id="hi-unread"> ' + T('span', 'hi_unread') + '</label></div>')
        return (auth_panel() + section('mt-h', 'h_matches', flt + '<div id="matches"></div>') + section('dv-h', 'h_deliveries', '<div id="deliveries"></div>'))
    if page == 'prefs':
        lang = '<div class="fields"><label>' + T('span', 'h_pref_lang') + ' <select id="pf-lang"><option value="es">Español</option><option value="en">English</option></select></label></div>'
        email = ('<div class="fields"><label>' + T('span', 'ch_email') + ' <input id="ch-email" type="email" autocomplete="email" maxlength="200"></label>'
                 '<label>' + T('span', 'ch_email_lang') + ' <select id="ch-email-lang"><option value="es">Español</option><option value="en">English</option></select></label>'
                 '<button type="button" id="ch-email-add" data-t="ch_add_email">' + e(S['ch_add_email'][0]) + '</button></div>')
        hook = ('<div class="fields"><label>' + T('span', 'ch_url') + ' <input id="ch-url" type="url" autocomplete="off" maxlength="2000"></label>'
                '<button type="button" id="ch-hook-add" data-t="ch_add_webhook">' + e(S['ch_add_webhook'][0]) + '</button></div>' + T('p', 'ch_webhook_howto', 'muted'))
        tok = ('<div class="fields"><label>' + T('span', 'tk_label') + ' <input id="tk-label" type="text" maxlength="120" autocomplete="off"></label>'
               '<label>' + T('span', 'tk_expires') + ' <input id="tk-days" type="number" min="1" max="730" value="90"></label>'
               '<button type="button" id="tk-add" data-t="tk_create">' + e(S['tk_create'][0]) + '</button></div>' + T('p', 'tk_howto', 'muted') + '<div id="tk-new" role="status" aria-live="polite"></div>')
        priv = ('<div class="actions"><button type="button" id="pv-export" data-t="pv_export">' + e(S['pv_export'][0]) + '</button></div>' + T('p', 'pv_note', 'muted') +
                '<div class="fields"><label>' + T('span', 'pv_erase_confirm') + ' <input id="pv-erase-text" type="text" autocomplete="off"></label>'
                '<button type="button" id="pv-erase" data-t="pv_erase_go">' + e(S['pv_erase_go'][0]) + '</button></div><p id="pv-status" role="status" aria-live="polite"></p>')
        return (auth_panel() + section('pl-h', 'h_pref_lang', lang) + section('ch-h', 'h_channels', '<div id="ch-new" role="status" aria-live="polite"></div><div id="channels"></div><h3 data-t="ch_add_email">' + e(S['ch_add_email'][0]) + '</h3>' + email + '<h3 data-t="ch_add_webhook">' + e(S['ch_add_webhook'][0]) + '</h3>' + hook) +
                section('tk-h', 'h_tokens', '<div id="tokens"></div><h3 data-t="tk_create">' + e(S['tk_create'][0]) + '</h3>' + tok) + section('pr-h', 'h_privacy', priv))
    if page == 'org':
        mfa = ('<div id="mfa-body"></div>')
        create = ('<div class="fields"><label>' + T('span', 'og_name') + ' <input id="og-name" type="text" maxlength="120" autocomplete="off"></label>'
                  '<label>' + T('span', 'og_kind') + ' <select id="og-kind"><option value="organization" data-t="og_kind_org">' + e(S['og_kind_org'][0]) + '</option><option value="msp" data-t="og_kind_msp">' + e(S['og_kind_msp'][0]) + '</option></select></label>'
                  '<button type="button" id="og-add" data-t="og_create">' + e(S['og_create'][0]) + '</button></div>')
        members = ('<div id="members"></div><div class="fields"><label>' + T('span', 'mb_email') + ' <input id="mb-email" type="email" autocomplete="off" maxlength="200"></label>'
                   '<label>' + T('span', 'mb_role') + ' <select id="mb-role"></select></label><label>' + T('span', 'mb_unit') + ' <select id="mb-unit"></select></label>'
                   '<button type="button" id="mb-add" data-t="mb_add">' + e(S['mb_add'][0]) + '</button></div>')
        units = ('<div id="units"></div><div class="fields"><label>' + T('span', 'un_name') + ' <input id="un-name" type="text" maxlength="120" autocomplete="off"></label>'
                 '<label>' + T('span', 'un_parent') + ' <select id="un-parent"></select></label><button type="button" id="un-add-unit" data-t="un_add_unit">' + e(S['un_add_unit'][0]) + '</button>'
                 '<button type="button" id="un-add-group" data-t="un_add_group">' + e(S['un_add_group'][0]) + '</button></div>')
        msp = (T('p', 'msp_note', 'muted') + '<div class="fields"><label>' + T('span', 'msp_msporg') + ' <input id="msp-org" type="text" maxlength="60" autocomplete="off"></label>'
               '<label>' + T('span', 'msp_customer') + ' <input id="msp-cust" type="text" maxlength="60" autocomplete="off"></label>'
               '<label>' + T('span', 'msp_role') + ' <select id="msp-role"></select></label><button type="button" id="msp-propose" data-t="msp_propose">' + e(S['msp_propose'][0]) + '</button></div>'
               '<div class="fields"><label>' + T('span', 'msp_link') + ' <input id="msp-link" type="text" maxlength="60" autocomplete="off"></label>'
               '<button type="button" id="msp-accept" data-t="msp_accept">' + e(S['msp_accept'][0]) + '</button><button type="button" id="msp-end" data-t="msp_end">' + e(S['msp_end'][0]) + '</button></div><p id="msp-status" role="status" aria-live="polite"></p>')
        pick = '<div class="fields"><label>' + T('span', 'og_pick') + ' <select id="og-pick"></select></label></div><div id="og-info"></div>'
        return (auth_panel() + section('mfa-h', 'h_mfa', mfa) + section('og-h', 'h_orgs', pick + create + '<p id="og-status" role="status" aria-live="polite"></p>') + section('mb-h', 'h_members', members) +
                section('un-h', 'h_units', units) + section('ms-h', 'h_msp', msp) + section('au2-h', 'h_audit', '<div id="audit"></div>'))
    raise KeyError(page)

def i18n_js():
    es = {k: v[0] for k, v in sorted(S.items())}
    en = {k: v[1] for k, v in sorted(S.items())}
    tx = {'sectors': [i['id'] for i in tax('sectors')['items']], 'regions': [i['id'] for i in tax('regions')['items']], 'os': [i['id'] for i in tax('os-families')['items']],
          'exposure': [i['id'] for i in tax('exposure')['items']], 'bands': ['none', 'low', 'medium', 'high', 'critical'],
          'taxonomy_versions': {n: tax(n)['version'] for n in ('sectors', 'regions', 'os-families', 'exposure', 'severity', 'technology-map')}}
    return ('/* Generated by scripts/gen_alerts_pages.py from one table of strings and the taxonomies: do not edit by hand. Spanish is the default of the HTML; both languages have every key. */\n'
            'window.ALERTS_I18N = ' + json.dumps({'es': es, 'en': en}, ensure_ascii=False, indent=1, sort_keys=True) + ';\nwindow.ALERTS_TAX = ' + json.dumps(tx, indent=1, sort_keys=True) + ';\n')

def outputs():
    out = {'alerts-i18n.js': i18n_js()}
    for p in PAGES:
        out[FILE[p]] = chrome(p, body(p))
    return out

def main(argv):
    out = outputs()
    if '--check' in argv:
        bad = [n for n, s in out.items() if not (OUT / n).exists() or (OUT / n).read_text(encoding='utf-8') != s]
        print('gen_alerts_pages:', 'differs: ' + ', '.join(bad) if bad else 'matches')
        return 1 if bad else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for n, s in out.items(): (OUT / n).write_text(s, encoding='utf-8')
    print(f'wrote {len(out)} files under web/intelligence/alerts')
    return 0

if __name__ == '__main__': sys.exit(main(sys.argv[1:]))
