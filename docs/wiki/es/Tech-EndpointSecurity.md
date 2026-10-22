# Endpoint Security

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [MacUSBGuard](ES-App-USB) · [DriverKit](ES-Tech-DriverKit)

## En 30 segundos

Endpoint Security es una tecnología de Apple para que un programa de seguridad **reciba avisos de lo que pasa en el sistema** (abrir un programa, tocar un archivo, usar un dispositivo) y, en algunos casos, **pueda responder "sí" o "no" antes de que ocurra**. Es como un guardia al que el sistema le pregunta "¿dejo pasar esto?". Apple la ofrece como framework documentado {{ev:EV-EC-35}}; para usarla un desarrollador necesita un permiso (entitlement) restringido que Apple concede caso por caso, según el README de MacUSBGuard {{ev:EV-EC-21}}.

## Con más detalle

Los eventos son de dos clases: de **notificación** (solo avisan) y de **autorización o AUTH** (el programa debe contestar permitir o denegar dentro de un plazo; si no contesta, el sistema puede actuar contra él). Un cliente se crea con `es_new_client`, se suscribe a eventos con `es_subscribe` y responde con `es_respond_auth_result`. Esta descripción general procede de la API usada en el código del proyecto; no pude leer el cuerpo de la página de Apple, así que no se apoya en ella.

## Dónde la usa este proyecto

Solo **MacUSBGuard**, y solo así {{ev:EV-EC-21}}:

- Evento suscrito: `ES_EVENT_TYPE_AUTH_IOKIT_OPEN` (alguien abre un dispositivo IOKit; sirve para decidir sobre teclados y ratones USB con el Mac bloqueado).
- Código: `Sources/MacUSBGuardPlatform/RealEndpointSecurityClient.swift` (`es_new_client`, `es_subscribe`, `es_respond_auth_result`) y el motor de decisión `EndpointSecurityDecisionEngine` en Core, que no importa Endpoint Security.
- `Package.swift` solo enlaza `libEndpointSecurity` si encuentra el SDK; si no, el resto compila sin ella.
- La decisión sin identidad fiable del dispositivo (mensaje ES anterior a la versión 10) se niega a actuar sobre una conjetura.

**Qué está verificado y qué no.** Compila y enlaza con el SDK de Xcode 26.3 según el README. **La aplicación en vivo no está verificada**: falta el permiso restringido de Apple (y la aprobación de la extensión de sistema y de Acceso total al disco), así que el estado global se muestra como solo observación y las pruebas de hardware HID siguen sin verificar {{ev:EV-EC-02}}. Tampoco hay prueba de que el sistema entregue a este cliente todos los eventos de teclado (el propio README anota la posibilidad de que WindowServer figure en una lista de silenciados por defecto).

Ninguna otra aplicación MacGuard la usa hoy; MacFirewallGuard usa la tecnología hermana de red, que no se trata aquí.

## Límites

- Un cliente AUTH decide sobre un evento concreto: no sustituye a un cortafuegos ni a un antivirus.
- Un error de decisión puede bloquear un teclado legítimo (falso positivo) o dejar pasar uno malicioso (falso negativo); por eso el diseño se niega a denegar sin identidad fiable.

## Quién más lo usa

Fuentes oficiales abiertas para esta página; no implica que ninguna de estas empresas use MacGuard.

- **Microsoft Defender for Endpoint en macOS** usa, según su documentación, una "extensión de seguridad de endpoint" (`com.microsoft.wdav.epsext`) además de una extensión de red, ambas como extensiones de sistema de Apple que requieren aprobación y Acceso total al disco. Clasificación: usa la misma tecnología (la documentación la llama endpoint security extension; no cita el nombre del framework) {{ev:EV-EC-33}}.

No añado más ejemplos porque no pude abrir una fuente oficial que los respalde.

## Estado en este proyecto

| Capacidad | Estado |
|---|---|
| Cliente ES con eventos AUTH de IOKit en MacUSBGuard | Compila; uso en vivo sin verificar (falta el permiso de Apple) |
| Aplicación en vivo de bloqueos | No verificada |

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [DriverKit](ES-Tech-DriverKit) · [Firma de código](ES-Tech-CodeSigning) · [Matriz de evidencias](ES-Evidence)
