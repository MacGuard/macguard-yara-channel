# Network Extension

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [MacFirewallGuard](ES-App-Firewall) · [Firma y notarización](ES-Tech-CodeSigning)

## En 30 segundos

Network Extension es el marco de Apple que permite a un programa ver y filtrar las conexiones de red de otras apps en el Mac. Apple exige un permiso especial (entitlement), vinculado a la cuenta de desarrollador. Sin ese permiso, un programa no puede bloquear conexiones de otras apps.

## Un ejemplo cotidiano

Es una garita en la salida de un edificio, donde se decide quién sale (el filtro de red). Solo quien tiene una credencial emitida por la administración (el permiso de Apple) puede ponerse en ella. Un vecino puede apuntar quién sale desde su ventana, es decir, observar a medias, pero no puede cerrar la barrera ni impedir una salida.

{{diagram:networkext-gap}}

## Cómo funciona (técnico)

En el diseño de MacFirewallGuard, el bloqueo real iría con un **filtro de contenido por sockets** (`NEFilterDataProvider`) dentro de una **extensión del sistema**. Los documentos del proyecto mencionan además un proxy de DNS (`NEDNSProxyProvider`) y un proxy transparente (`NETransparentProxyProvider`) como alternativas, ninguna implementada {{ev:EV-EC-60}}. La implementación prevista depende del entitlement de Network Extension apropiado, cuya disponibilidad operativa no está acreditada. La aprobación y configuración necesarias deben verificarse antes de afirmar que el bloqueo funciona {{ev:EV-EC-60}}.

La documentación oficial de Apple sobre Network Extension no pudo leerse en su cuerpo desde esta herramienta; lo descrito aquí sobre los permisos procede de los documentos del proyecto, no de una cita de Apple {{ev:EV-EC-81}}.

## Dónde lo usa este proyecto

### MacFirewallGuard

- **Uso comprobado en el código:** solo tipos de datos para traducir flujos.
- **No existe** ninguna extensión del sistema ni ningún proveedor en ejecución.
- No se ha demostrado la autorización operativa (el entitlement) {{ev:EV-EC-63}}.

### Las demás aplicaciones

- **Uso comprobado en el código:** ninguno. No usan Network Extension; Installer Auditor no importa NetworkExtension en su código.

Ningún permiso consta como utilizable para este proyecto. **No verificado** si se solicitó alguno ni cuál fue la respuesta {{ev:EV-EC-60}}.

## Límites

- Sin un permiso utilizable, ninguna decisión de bloqueo se aplica: acaba como "acción no disponible: falta el permiso" {{ev:EV-EC-60}}.
- Activar el filtro de este producto puede desactivar otros filtros de contenido activos; la coexistencia es un bloqueo documentado sin resolver {{ev:EV-EC-60}}.
- Un filtro de red no sustituye a la identidad de proceso ni a la revisión de instaladores.

## Quién más lo usa

- **LuLu** (Objective-See), cortafuegos de código abierto que «bloquea conexiones salientes desconocidas»; su página dice que parte del tráfico puede no pasar por las Network Extensions «como LuLu» y explica la aprobación de su filtro en Ajustes del Sistema. Usa la misma tecnología que MacFirewallGuard pretende usar {{ev:EV-EC-79}}.

No se cita ninguna otra aplicación: una segunda página consultada (la de un cortafuegos comercial) no mencionaba el mecanismo. Esto no implica que LuLu use MacGuard.
