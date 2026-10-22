# User manual: Subscriptions and Alerts

*Estado: servidor de referencia, no desplegado. Cómo probarlo:* `python3 -m alerts serve --db alerts.db --site web --public-url http://127.0.0.1:8080 --insecure-cookies` *(solo en local) y abrir* `/intelligence/alerts/index.html`.

## ES — Qué puedes hacer

1. **Explorar alertas.** Filtra por país o región de la fuente, sector, tecnología (fabricante, producto, versión, sistema, tipo), exposición, gravedad, explotación conocida, fechas, fuente… Cada resultado dice **por qué coincide**. El país es el ámbito de la fuente, no dónde se explota algo. *Explotada* solo significa que una fuente lo afirma en un campo estructurado; una puntuación crítica no lo es.
2. **Crear una suscripción.** Nombre, ámbito (personal u organizativo), filtros, periodicidad (inmediata, resumen diario o semanal), «avisar de inmediato si es crítica o aparece explotación», tipos de cambio y canales. *Ver coincidencias* usa alertas reales y **no envía nada**. Una suscripción solo ve lo que ocurra desde que la activas.
3. **Canales** (Preferencias de entrega): correo (te llega un enlace; pulsa el botón de la página para confirmar), webhook (https, nombre público; guarda el secreto cuando se muestre) y feeds RSS privados (la dirección completa es el secreto: se muestra una vez; en tu lector RSS «añadir suscripción» y pega la dirección; si la pierdes, revócala y crea otra).
4. **Historial**: cada coincidencia, sus motivos y las entregas; marca como leída o confirma la recepción. Una alerta actualizada solo aparece de nuevo si el cambio es relevante (nueva explotación, corrección, subida de gravedad…).
5. **Tus datos**: descargar y borrar la cuenta.

## EN — What you can do

1. **Explore alerts**: filter by the source's country or region, sector, technology, exposure, severity, known exploitation, dates, source; every result says why it matches.
2. **Create a subscription**: name, scope, filters, frequency, immediate-critical, change kinds, channels; preview uses real alerts and sends nothing; a new subscription only sees what happens after activation.
3. **Channels**: e-mail (confirm with the button on the linked page), webhook (https, public name; store the secret when shown), private RSS (the full address is the secret, shown once; revoke and recreate if lost).
4. **History**: matches, reasons, deliveries; mark read, acknowledge.
5. **Your data**: export and erase.

Webhook receivers: verify `X-MacGuard-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">` with the secret (any `v1` may match during a rotation), reject timestamps older than 5 minutes, de-duplicate on `X-MacGuard-Event-Id`.
