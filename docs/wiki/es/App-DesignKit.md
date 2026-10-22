# MacGuardDesignKit

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [MacUSBGuard](ES-App-USB)

## En 30 segundos

MacGuardDesignKit es una **biblioteca de componentes SwiftUI compartida por las apps**: botones, tarjetas, tablas, insignias de estado, barras de búsqueda y el aspecto de los gráficos. **No es un producto de protección**: no vigila, no bloquea ni detecta nada. Su objetivo es que todas las aplicaciones MacGuard se vean y se comporten igual, de modo que una insignia verde de "protegido" signifique lo mismo en todas {{ev:EV-EC-30}}.

**Estado: desarrollo** (una versión anterior a la 1.0; la propia biblioteca dice que no es 1.0 porque gran parte de su catálogo previsto de componentes aún no está construida). La capa de interfaz de MacFirewallGuard la importa; MacUSBGuard todavía no la ha adoptado, y el README de la biblioteca sigue diciendo que no tiene consumidores, algo ya desactualizado {{ev:EV-EC-07}}.

## Un ejemplo cotidiano

Es la caja de piezas de un mismo juego de construcción: si todas las casas se montan con las mismas piezas, un tejado rojo significa lo mismo en todas partes. Pero la caja de piezas no construye ninguna casa por sí sola ni hace una más segura.

## Diagrama

{{diagram:ecosystem-map-1-supply}}

{{diagram:ecosystem-map-2-planned}}

{{diagram:ecosystem-map-3-others}}

En el mapa está entre los "bloques de construcción compartidos": una pieza de apoyo que las aplicaciones podrían usar, sin lógica de seguridad propia.

## Paso a paso

1. Una aplicación declara el paquete como dependencia SwiftPM.
2. Construye sus pantallas con los componentes ya hechos de la biblioteca (tarjetas, insignias de estado, tablas...).
3. Los componentes aplican los colores, la tipografía y el espaciado del sistema de diseño.
4. Un script de comprobación heurístico puede revisar el código de la aplicación en busca de colores o tamaños de letra escritos a mano que se salten el sistema.

## Arquitectura

Una biblioteca más sus pruebas, para macOS 13 o superior, **sin dependencias externas** {{ev:EV-EC-31}}. Se organiza por temas (colores, espaciado, tipografía, componentes, tablas, búsqueda, estados, estilo de gráficos). Importa solo los marcos de interfaz y gráficos de Apple y **no usa el marco Charts**; los gráficos son solo estilo.

**Restricción dura** (documentada y comprobable): no debe depender de tecnologías de seguridad de nivel de sistema ni de ningún módulo interno de las aplicaciones. Por eso no necesita permisos especiales ni perfiles de aprovisionamiento.

## Cómo funciona por dentro

| Pieza | Problema | Cómo | Evidencia |
|---|---|---|---|
| Colores de seguridad accesibles | Los colores del sistema (verde, naranja, rojo, azul) fallan en contraste sobre algunos fondos | Ajusta el color hacia negro o blanco en pasos pequeños hasta alcanzar un contraste legible (criterio WCAG 2.2 AA) | Ver la [matriz de evidencias](ES-Evidence) |
| Vocabulario de salud compartido | Estados incoherentes entre apps | Un vocabulario de estados, cada uno con color, símbolo y palabra | Ver la [matriz de evidencias](ES-Evidence) |
| Insignia de estado | Insignias que dependen solo del color | El texto es obligatorio: no se puede crear una insignia solo de color | Ver la [matriz de evidencias](ES-Evidence) |
| Botón destructivo y diálogo de confirmación | Acciones destructivas sin confirmación | La confirmación no se puede omitir | Ver la [matriz de evidencias](ES-Evidence) |
| Tabla ordenable | Tablas ordenables coherentes | Tabla genérica sobre datos identificables, con agrupación accesible de filas | Ver la [matriz de evidencias](ES-Evidence) |

Lo que **no** garantiza: que una aplicación que la usa sea accesible (depende de cómo se use), ni sustituye la validación humana con VoiceOver. El script anti-deriva es heurístico y puede dar falsos positivos y negativos.

## Pruebas

La biblioteca tiene un pequeño objetivo de pruebas (lectura estática, **no ejecutado**); no hay resultados de ejecución documentados en el repositorio {{ev:EV-EC-32}}. El README reconoce algunos hallazgos de deriva de diseño en sus propias fuentes que quedaron sin marcar.

## Cómo comprobarlo tú

El repositorio es privado. Su README describe una compilación y una ejecución de pruebas más una comprobación de dependencias; no se ejecutaron para esta wiki.

## Límites

- El README conserva texto desactualizado (una versión anterior y "aún no publicado") mientras el código declara una más reciente; no se verificó que el repositorio remoto sea accesible ni que haya etiquetas publicadas.
- Algunas decisiones de diseño esperan la aprobación humana {{ev:EV-EC-32}}.
- No es un control de seguridad y no protege a nadie por sí sola.

## Estado

| Capacidad | Estado |
|---|---|
| Tokens, componentes base, estructura, tabla, búsqueda, estados | Implementado (anterior a 1.0), no verificado por ejecución |
| Resto del catálogo previsto de componentes | Planificado |
| Versión 1.0 | Planificado: requiere estabilidad y al menos dos productos que la usen (hoy uno) |

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Roadmap global](ES-Roadmap) · [Matriz de evidencias](ES-Evidence)
