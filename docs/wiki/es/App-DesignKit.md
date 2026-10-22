# MacGuardDesignKit

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [MacUSBGuard](ES-App-USB)

## En 30 segundos

MacGuardDesignKit es una **biblioteca de componentes de interfaz en SwiftUI**: botones, tarjetas, tablas, insignias de estado, barras de búsqueda y el aspecto de los gráficos. **No es un producto de protección**: no vigila, bloquea ni detecta nada. Su objetivo es que todas las aplicaciones MacGuard se vean y se comporten igual, de modo que una insignia verde "protegido" signifique lo mismo en todas {{ev:EV-EC-30}}.

**Estado: en desarrollo** (versión 0.3.1; la propia biblioteca dice que no es 1.0 porque gran parte del catálogo de 16 componentes aún no está construido). La capa de interfaz de MacFirewallGuard la importa (dependencia de paquete desde la 0.2.0); MacUSBGuard todavía no la ha adoptado, y el README de DesignKit aún dice «cero consumidores», lo que está desactualizado {{ev:EV-EC-07}}.

## Un ejemplo cotidiano

Es la caja de piezas de un mismo juego de construcción: si todas las casas se montan con las mismas piezas, un tejado rojo significa lo mismo en todas. Pero la caja de piezas no construye ninguna casa por sí sola ni la hace más segura.

## Diagrama

{{diagram:ecosystem-map}}

En el mapa aparece entre los "bloques compartidos": una pieza de apoyo que las aplicaciones podrían usar, sin lógica de seguridad propia.

## Paso a paso

1. Una aplicación declara el paquete como dependencia de SwiftPM.
2. Construye sus pantallas con componentes `MG...` (`MGCard`, `MGStatusBadge`, `MGTable`...).
3. Los componentes aplican colores, tipografía y espaciados del sistema de diseño.
4. Un script heurístico (`Scripts/anti-drift-check.sh`) puede revisar el código de la aplicación para detectar colores o tamaños de letra "a mano" que se saltan el sistema.

## Arquitectura

Un solo destino de biblioteca más uno de pruebas; swift-tools 5.9, macOS 13 o superior, **sin dependencias externas** {{ev:EV-EC-31}}. Carpetas: Charts, Colors, Components, Detail, Feedback, Icons, Search, Shell, Spacing, State, Status, Table, Theme, Typography. Importa solo SwiftUI, AppKit, CoreGraphics y Foundation: **no usa el framework Charts**; los gráficos son solo estilo.

**Restricción dura** (documentada y comprobable con un `grep` de su README): no puede depender de DriverKit, NetworkExtension, EndpointSecurity ni de ningún módulo interno de las aplicaciones. Por eso no requiere permisos ni perfiles de aprovisionamiento especiales.

## Cómo funciona por dentro

| Pieza | Problema | Cómo | Evidencia |
|---|---|---|---|
| `MGSecurityTint` | Que colores del sistema (verde, naranja, rojo, azul) fallen en contraste sobre algunos fondos | Mezcla el color hacia negro o blanco en pasos del 5 % hasta alcanzar un contraste de 4,5:1 (criterio WCAG 2.2 AA) | `Colors/MGSecurityTint.swift` |
| `MGHealthStatus` | Estados incoherentes entre apps | Vocabulario único de 9 casos, cada uno con color, símbolo SF y palabra | `Status/MGHealthStatus.swift` |
| `MGStatusBadge` | Insignias que solo dependen del color | El parámetro `text:` no es opcional: no se puede crear una insignia solo con color | `Components/MGStatusBadge.swift` |
| `MGDestructiveButton` + `MGConfirmationDialog` | Acciones destructivas sin confirmar | La confirmación no se puede omitir | `Components/MGButtons.swift` |
| `MGTable` | Tablas ordenables coherentes | Tabla genérica sobre datos `Identifiable`; la 0.3.1 corrigió la agrupación de accesibilidad de filas | `Table/MGTable.swift` |

Qué **no** garantiza: que una aplicación que la use sea accesible (depende de cómo la use), ni sustituye una validación humana con VoiceOver. El script anti-deriva es heurístico y puede dar falsos positivos y negativos.

## Pruebas

Un destino de pruebas con 3 archivos y 26 funciones `test` (recuento estático, **no ejecutadas**); no hay resultados de ejecución documentados en el repositorio {{ev:EV-EC-32}}. El README menciona unos 15 hallazgos de anti-deriva en sus propias fuentes que se dejaron sin marcar.

## Cómo comprobarlo tú

El repositorio es privado. Según su README: `swift build` y `swift test`, y el `grep` de la restricción dura. No se ejecutaron para esta wiki.

## Límites

- El README conserva texto desactualizado (versión 0.1.0 y "aún no publicado"), mientras el código declara 0.3.1; no se verificó que el repositorio remoto sea accesible ni que las etiquetas estén publicadas.
- Cinco decisiones de diseño esperan visto bueno humano {{ev:EV-EC-32}}.
- No es un control de seguridad ni protege a nadie por sí misma.

## Estado

| Capacidad | Estado |
|---|---|
| Tokens, componentes base, shell, tabla, búsqueda, estados | Implementado (0.1.0 a 0.3.1), no verificado por ejecución |
| Resto del catálogo de 16 componentes | Planificado |
| Versión 1.0 | Planeada: exige estabilidad y que al menos dos productos la usen (hoy cero) |

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Roadmap global](ES-Roadmap) · [Matriz de evidencias](ES-Evidence)
