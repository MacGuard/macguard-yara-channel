# MacProcessGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [MacFirewallGuard](ES-App-Firewall)

## En 30 segundos

MacProcessGuard es un **concepto**: una pieza que, si se emprende, vigilaría qué programas se ejecutan en el Mac. **No existe**: no hay repositorio, ni código, ni especificación propia {{ev:EV-EC-05}}. Esta página dice solo lo que otros proyectos escriben sobre él. **No se le atribuye ninguna función implementada.**

## Un ejemplo cotidiano

Es un hueco reservado en un plano: alguien dibujó una puerta con la etiqueta "aquí iría el control de procesos", pero la habitación no está construida. Se sabe dónde encajaría, no cómo sería.

## Diagrama

{{diagram:process-boundary}}

## Paso a paso: qué existe exactamente

1. El README de MacFirewallGuard dice literalmente que MacProcessGuard "does not exist yet" {{ev:EV-EC-05}}.
2. Sus documentos de arquitectura lo llaman un producto hermano "separate, not-yet-started"; hay una decisión registrada de mantenerlo como producto aparte {{ev:EV-EC-66}}.
3. En el código de MacFirewallGuard solo hay **huecos reservados**: un valor de enumeración `PROCESS_GUARD_CORRELATION` ("Not implemented yet; reserved") y una referencia con estado `PROVIDER_ABSENT` {{ev:EV-EC-67}}.
4. Hay marcadores de interfaz propuestos (barra lateral "Process Activity"); son maquetas de diseño, no funciones {{ev:EV-EC-66}}.

## Cómo funciona por dentro

No hay algoritmos que describir. Lo único con código es la **frontera** del lado de MacFirewallGuard:

- `ProcessSecurityIdentityReference` (Core/Attribution/ProcessAttributionV1.swift): clave `pid.pidversion` y estado de correlación `PROVIDER_ABSENT`. En producción siempre queda en ausente {{ev:EV-EC-67}}.
- `ExternalProducerType` (Core/Egress/EgressProvenanceV1.swift): lista productores externos reconocidos; trata a un productor no reconocido como no admisible.

Lo que MacFirewallGuard **dice** que MacProcessGuard haría (procedencia de ejecución, hash del ejecutable, linaje de procesos, persistencia, detección de inyección) es una **frontera trazada por otro proyecto**, no un compromiso ni una especificación {{ev:EV-EC-66}}. Endpoint Security se nombra como la API adecuada, pero no hay código ni permiso de Apple para ella en este ecosistema. No se documenta que use XPC, YARA u otra tecnología.

Nombre sin resolver: los repositorios usan también "MacEndpointGuard" (`MACENDPOINTGUARD` en un valor, `MACPROCESSGUARD` en otro). La documentación no afirma que sean el mismo producto; **no verificado**.

## Cómo comprobarlo tú

No hay nada que ejecutar. La comprobación es negativa: en las copias locales revisadas no se encontró ningún directorio, repositorio ni paquete con ese nombre, y el README de MacFirewallGuard lo declara inexistente.

## Límites

- No protege nada hoy. Nadie debe depender de él.
- Que MacFirewallGuard reserve un hueco no obliga a construir MacProcessGuard; el propietario aún no ha decidido si se emprende ({{ev:EV-EC-66}}).
- Mientras no exista, la identidad de proceso de MacFirewallGuard seguirá siendo la de su propia resolución de firma, y la detección de inyección no tiene dueño.

## Estado

| Capacidad | Estado |
|---|---|
| Producto MacProcessGuard | Concepto |
| Huecos reservados en MacFirewallGuard | Implementado (solo como marcadores) |
| Cualquier función de vigilancia de procesos | Planificado en el sentido más débil: solo mencionado; sin diseño |

Sin fechas. Ver el [Roadmap](ES-Roadmap) y [MacFirewallGuard](ES-App-Firewall).
