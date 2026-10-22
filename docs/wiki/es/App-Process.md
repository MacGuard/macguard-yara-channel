# MacProcessGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [MacFirewallGuard](ES-App-Firewall)

## En 30 segundos

MacProcessGuard es un **concepto**: una pieza que, si se emprendiera, vigilaría qué programas se ejecutan en el Mac. **No existe**: ni repositorio, ni código, ni especificación propia {{ev:EV-EC-05}}. Esta página solo dice lo que otros proyectos escriben sobre ella. **No se le atribuye ninguna función implementada.**

## Un ejemplo cotidiano

Es un hueco reservado en un plano: alguien dibujó una puerta con la etiqueta "aquí iría el control de procesos", pero la sala no está construida. Sabemos dónde encajaría, no cómo sería.

## Diagrama

{{diagram:process-boundary}}

## Paso a paso: qué existe exactamente

1. El README de MacFirewallGuard dice literalmente que MacProcessGuard "todavía no existe" {{ev:EV-EC-05}}.
2. Sus documentos de arquitectura lo llaman producto hermano "separado, aún no iniciado"; una decisión registrada lo mantiene como producto separado {{ev:EV-EC-66}}.
3. En el código de MacFirewallGuard solo hay **un hueco reservado para la identidad de proceso, no implementado** {{ev:EV-EC-67}}.
4. Hay maquetas de interfaz propuestas; son dibujos de diseño, no funciones {{ev:EV-EC-66}}.

## Cómo funciona por dentro

No hay algoritmos que describir. Lo único con código es la **frontera** del lado de MacFirewallGuard, hecha de un único hueco reservado:

- un hueco reservado para la identidad de proceso, no implementado {{ev:EV-EC-67}}.

Lo que MacFirewallGuard **dice** que haría MacProcessGuard (procedencia de ejecución, hash del ejecutable, linaje de procesos, persistencia, detección de inyección) es una **frontera trazada por otro proyecto**, no un compromiso ni una especificación {{ev:EV-EC-66}}. Se nombra Endpoint Security como la API adecuada, pero no hay código ni permiso de Apple utilizable para ella en este ecosistema. No se documenta el uso de XPC, YARA ni de ninguna otra tecnología.

Nombre sin resolver: el material del proyecto menciona a veces un producto similar orientado al endpoint. La documentación no afirma que sean el mismo producto; **no verificado**.

## Cómo comprobarlo tú

No hay nada que ejecutar. La comprobación es negativa: en las copias locales revisadas no se encontró ningún directorio, repositorio ni paquete con ese nombre, y el README de MacFirewallGuard lo declara inexistente.

## Límites

- Hoy no protege nada. Nadie debería depender de ello.
- Que MacFirewallGuard reserve un hueco no obliga a nadie a construir MacProcessGuard; el propietario aún no ha decidido si lo emprenderá ({{ev:EV-EC-66}}).
- Mientras no exista, la identidad de proceso de MacFirewallGuard sigue siendo la que dé su propia resolución de firma, y la detección de inyección no tiene responsable.

## Estado

| Capacidad | Estado |
|---|---|
| Producto MacProcessGuard | Concepto |
| Huecos reservados en MacFirewallGuard | Implementado (solo como marcadores de posición) |
| Cualquier función de vigilancia de procesos | Planificado en el sentido más débil: solo mencionado; sin diseño |

Sin fechas. Ver el [Roadmap](ES-Roadmap) y [MacFirewallGuard](ES-App-Firewall).
