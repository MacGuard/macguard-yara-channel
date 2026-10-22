# Network Extension

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [MacFirewallGuard](ES-App-Firewall) · [Firma y notarización](ES-Tech-CodeSigning)

## En 30 segundos

Network Extension es el marco de Apple que permite a un programa **ver y controlar el tráfico de red de otras apps** en el Mac (filtrar conexiones, hacer de proxy de DNS, crear una VPN). Apple no deja usarlo a cualquiera: hace falta un **permiso especial (entitlement)** concedido a la cuenta de desarrollador. Para el filtro previsto en MacFirewallGuard se necesita la autorización adecuada; otras tecnologías de red pueden tener requisitos distintos.

## Un ejemplo cotidiano

Es una garita en la salida de un edificio. Solo quien tiene una credencial emitida por la administración puede ponerse en ella a mirar quién sale. Un vecino puede apuntar quién sale desde su ventana (observar a medias), pero no puede cerrar la barrera.

{{diagram:networkext-gap}}

## Cómo funciona (técnico)

En el diseño de MacFirewallGuard, el bloqueo real iría con un **filtro de contenido por sockets** (`NEFilterDataProvider`) dentro de una **extensión del sistema**. Los documentos del proyecto mencionan además un proxy de DNS (`NEDNSProxyProvider`) y un proxy transparente (`NETransparentProxyProvider`) como alternativas, ninguna implementada {{ev:EV-EC-60}}. La implementación prevista depende del entitlement de Network Extension apropiado, cuya disponibilidad operativa no está acreditada. La aprobación y configuración necesarias deben verificarse antes de afirmar que el bloqueo funciona {{ev:EV-EC-60}}.

La documentación oficial de Apple sobre Network Extension no pudo leerse en su cuerpo desde esta herramienta; lo descrito aquí sobre los permisos procede de los documentos del proyecto, no de una cita de Apple {{ev:EV-EC-81}}.

## Dónde lo usa este proyecto

| App | Uso comprobado en el código |
|---|---|
| MacFirewallGuard | Solo tipos de `NetworkExtension` (`NEFilterSocketFlow`) como **puente de traducción** (adaptadores de traducción de flujos). **No existe** ninguna extensión del sistema ni ningún proveedor en ejecución; no hay archivos de entitlements en el árbol principal {{ev:EV-EC-63}} |
| Los demás | No usan Network Extension; Installer Auditor no importa NetworkExtension en su código |

El proyecto clasifica su situación como "el permiso está ausente y se puede solicitar" (documento de decisión del entitlement). **No verificado** si la solicitud ya se presentó o respondió {{ev:EV-EC-60}}.

## Límites

- Sin el permiso, ninguna decisión BLOCK se aplica: acaba como `UNAVAILABLE(ENTITLEMENT_MISSING)` {{ev:EV-EC-60}}.
- Activar el filtro de este producto puede desactivar otros filtros de contenido activos; la coexistencia es un bloqueo documentado sin resolver {{ev:EV-EC-60}}.
- Un filtro de red no sustituye a la identidad de proceso ni a la revisión de instaladores.

## Quién más lo usa

- **LuLu** (Objective-See), cortafuegos de código abierto que «bloquea conexiones salientes desconocidas»; su página dice que parte del tráfico puede no pasar por las Network Extensions «como LuLu» y explica la aprobación de su filtro en Ajustes del Sistema. Usa la misma tecnología que MacFirewallGuard pretende usar {{ev:EV-EC-79}}.

No se cita ninguna otra aplicación: una segunda página consultada (la de un cortafuegos comercial) no mencionaba el mecanismo. Esto no implica que LuLu use MacGuard.
