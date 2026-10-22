# Endpoint Security

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [MacUSBGuard](ES-App-USB) · [DriverKit](ES-Tech-DriverKit)

## En 30 segundos

Endpoint Security es una función de Apple que avisa a un programa de seguridad de lo que ocurre en el Mac, como abrir un programa o usar un dispositivo {{ev:EV-EC-35}}. En algunos casos, el programa puede contestar «sí» o «no» antes de que ocurra. Para usarla hace falta un permiso especial (entitlement) que Apple concede caso por caso {{ev:EV-EC-21}}.

## Un ejemplo cotidiano

Es como un portero que, ante ciertas visitas, llama a la oficina de seguridad y espera su respuesta antes de abrir la puerta. Para otras visitas solo apunta quién entró (evento de notificación). Si la oficina no contesta a tiempo, el edificio actúa contra ella. Y solo una oficina con credencial de la administración puede atender esa línea.

## Con más detalle

Los eventos son de dos clases: de **notificación** (solo avisan) y de **autorización o AUTH** (el programa debe contestar permitir o denegar dentro de un plazo; si no contesta, el sistema puede actuar contra él). Un cliente se crea con `es_new_client`, se suscribe a eventos con `es_subscribe` y responde con `es_respond_auth_result`. Esta descripción general procede de la API usada en el código del proyecto; no se pudo leer el cuerpo de la página de Apple, así que no se apoya en ella.

## Dónde la usa este proyecto

Solo **MacUSBGuard**, y solo así {{ev:EV-EC-21}}:

- Evento suscrito: `ES_EVENT_TYPE_AUTH_IOKIT_OPEN` (alguien abre un dispositivo en IOKit, la capa de macOS que gestiona dispositivos; sirve para decidir sobre teclados y ratones USB con el Mac bloqueado).
- Implementación documentada: un adaptador de eventos de Endpoint Security y un motor de decisión separado, que usan las tres llamadas anteriores.
- La compilación separa el adaptador que requiere el SDK del resto del motor.
- La decisión sin identidad fiable del dispositivo se niega a actuar sobre una conjetura.

**Qué está verificado y qué no.** Compila y enlaza con un SDK reciente de Xcode. **La aplicación en vivo no está verificada**: ningún permiso restringido de Apple consta como utilizable (ni la aprobación de la extensión de sistema y de Acceso total al disco), así que el estado global se muestra como solo observación y las pruebas de hardware HID siguen sin verificar {{ev:EV-EC-02}}. Tampoco hay prueba de que el sistema entregue a este cliente todos los eventos de teclado (el alcance de los eventos disponibles requiere pruebas con el sistema real).

Ninguna otra aplicación MacGuard la usa hoy; MacFirewallGuard usa la tecnología hermana de red, que no se trata aquí.

## Límites

- Un cliente AUTH decide sobre un evento concreto: no sustituye a un cortafuegos ni a un antivirus.
- Un error de decisión puede bloquear un teclado legítimo (falso positivo) o dejar pasar uno malicioso (falso negativo); por eso el diseño se niega a denegar sin identidad fiable.

## Quién más lo usa

Fuentes oficiales abiertas para esta página; no implica que ninguna de estas empresas use MacGuard.

- **Microsoft Defender for Endpoint en macOS** usa, según su documentación, una "extensión de seguridad de endpoint" (`com.microsoft.wdav.epsext`) además de una extensión de red, ambas como extensiones de sistema de Apple que requieren aprobación y Acceso total al disco. Clasificación: usa la misma tecnología (la documentación la llama endpoint security extension; no cita el nombre del framework) {{ev:EV-EC-33}}.

No se añaden más ejemplos porque no se pudo abrir una fuente oficial que los respalde.

## Estado en este proyecto

| Capacidad | Estado |
|---|---|
| Cliente ES con eventos AUTH de IOKit en MacUSBGuard | Compila; uso en vivo sin verificar (sin permiso confirmado como utilizable) |
| Aplicación en vivo de bloqueos | No verificada |

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [DriverKit](ES-Tech-DriverKit) · [Firma de código](ES-Tech-CodeSigning) · [Matriz de evidencias](ES-Evidence)
