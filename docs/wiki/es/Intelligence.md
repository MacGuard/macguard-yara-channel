# Inteligencia de seguridad: fuentes, alertas y suscripciones

[Inicio](ES-Home) · [Roadmap global](ES-Roadmap) · [Fuentes de YARA](ES-YARA-Sources) · [Canal YARA](ES-YARA-Channel)

## En 30 segundos

La inteligencia de seguridad es la parte de MacGuard que reúne información pública sobre vulnerabilidades y actualizaciones de reglas, la comprueba y permite **suscribirse** a lo que importa por país, sector, tecnología y gravedad. Hoy casi todo está **construido y probado pero sin publicar**: el código funciona con los datos reales de CISA, ENISA y CERT-EU, pero no se redistribuye nada de esas fuentes hasta aclarar sus condiciones de reutilización y hasta que el propietario lo confirme {{ev:EV-SI-01}}.

## Un ejemplo cotidiano

Es como un quiosco que lee muchos periódicos cada mañana, comprueba cada recorte y guarda una ficha por noticia que dice qué periódicos la dieron y qué contó cada uno. Un cliente pide «solo noticias sobre Windows, graves y de Europa» y el quiosco añade una nota con el motivo de cada recorte elegido. El quiosco no revende un periódico cuyo editor no ha dicho que se pueda.

## Qué existe hoy

- **Fuentes reales, experimental:** CISA KEV, la base europea de vulnerabilidades de ENISA, su lista de explotadas y los avisos de CERT-EU se descargan y validan; el 2026-10-22 los adaptadores aceptaron 1.754, 2.928, 1.770 y 10 registros y la fusión no encontró conflictos de identificadores {{ev:EV-SI-02}}.
- **Motor de alertas:** una alerta por vulnerabilidad conserva lo que dijo cada fuente, con la evidencia de la que salió; las actualizaciones son versiones nuevas de la misma alerta y solo los cambios relevantes avisan a alguien {{ev:EV-SI-03}}.
- **Filtros:** un lenguaje cerrado de 26 campos (región, sector, tecnología, versión, sistema, exposición, gravedad, explotación, fechas, fuente y más), nunca código, evaluado igual en el servidor y en el navegador {{ev:EV-SI-04}}.
- **Entrega:** feeds RSS públicos y privados, correo con doble confirmación y webhooks firmados protegidos contra peticiones a direcciones internas {{ev:EV-SI-05}}.
- **Organizaciones y roles:** inquilinos, unidades, grupos de equipos, relación con un MSP, roles explícitos y un registro de auditoría con cadena de hashes {{ev:EV-SI-06}}.
- **Sección web:** ocho páginas en español e inglés, comprobadas en un navegador real contra WCAG 2.2 AA {{ev:EV-SI-07}}.

## De dónde salen las alertas y qué se puede publicar

| Fuente | Estado |
|---|---|
| Registro de versiones de reglas YARA de MacGuard | activa: tres alertas, publicadas como ficheros estáticos {{ev:EV-SI-08}} |
| CISA KEV, ENISA EUVD y su lista de explotadas, CERT-EU | implementadas y probadas con datos reales, sin publicar: falta la confirmación del propietario o los términos de reutilización |
| INCIBE-CERT, CCN-CERT, feeds de abuse.ch | bloqueadas por sus términos o su acceso |
| NVD, OSV, Debian, Ubuntu, Red Hat, Sigma | pendientes: todavía sin adaptador |

«Activa» exige un adaptador, una importación reciente y datos. Una fuente que solo está en una lista se muestra como pendiente.

## Cómo se mantiene honesto

- Una puntuación crítica es **gravedad**, nunca prueba de explotación: la explotación es solo lo que una fuente afirma en un campo estructurado, y cada fuente conserva su propia afirmación.
- El país de una alerta es el ámbito de la **fuente**, no el lugar donde se explota una vulnerabilidad.
- Un paquete de Linux nunca se da por vulnerable solo por la versión original, porque las distribuciones reaplican correcciones; solo pueden decirlo los datos de la propia distribución.
- Lo desconocido sigue siendo desconocido: sin corrección indicada significa «desconocido», no «sin corrección».

## Qué falta

- No hay servicio alojado: las cuentas, las suscripciones y los feeds privados funcionan en un servidor de referencia que no está desplegado. No hay relé de correo ni proveedor de identidad {{ev:EV-SI-07}}.
- Correlacionar alertas con los equipos de un cliente necesita MacGuard Cloud, que no existe; solo están escritos el contrato y un comparador de referencia {{ev:EV-SI-09}}.
- Los datos de terceros en los feeds públicos esperan las decisiones del propietario sobre licencias y sobre un flujo de firma.

## Cómo comprobarlo tú

Ejecuta `python3 scripts/gen_alerts_site.py --check` para confirmar que los ficheros publicados son lo que produce el repositorio, y lee `docs/alerts/ARCHITECTURE.md` para ver el estado de cada fase {{ev:EV-SI-07}}.

## Límites

- Todo lo marcado como «experimental» es código y pruebas, no un servicio desplegado.
- Las condiciones de reutilización son evidencia leída de páginas públicas, no asesoría legal.
- No se prometen fechas; mira el [Roadmap global](ES-Roadmap).

## Estado

| Capacidad | Estado |
|---|---|
| Motor de alertas, filtros, entrega, multi-inquilino | implementado en el repositorio, sin desplegar {{ev:EV-SI-03}} |
| Alertas públicas de fuentes de terceros | bloqueado: licencias y confirmación del propietario {{ev:EV-SI-01}} |
| Correlación con inventario (Cloud) | planificado {{ev:EV-SI-09}} |
