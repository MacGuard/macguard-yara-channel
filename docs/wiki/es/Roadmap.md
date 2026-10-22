# Roadmap global de MacGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem)

## En 30 segundos

Aquí ves en qué fase está cada aplicación, qué ya se hizo, qué la bloquea y qué viene después. **No hay fechas ni porcentajes**: no los inventamos. Una fase está "hecha" solo si hay evidencia enlazada; una aplicación no está "al 50 %" por tener 500 pruebas.

## Un ejemplo cotidiano

Es como el panel de obras de un edificio: dice qué planta está terminada, cuál está parada y por qué. No promete cuándo se abre.

## Vista global

{{diagram:roadmap-global-1-yara-channel}}

{{diagram:roadmap-global-2-firewall}}

{{diagram:roadmap-global-3-usb}}

{{diagram:roadmap-global-4-others}}

## Por aplicación

Etapas usadas: concepto, prototipo, desarrollo, validación, candidata a versión (release candidate) y publicada. Cada aplicación se sitúa en la que su evidencia respalda.

### YARA Channel

- **Fase:** V1 publicada; V1.1, fase 2, en desarrollo.
- **Hecho:** canal firmado y verificado (V1); fase 1 de V1.1 fusionada {{ev:EV-YC-02}} {{ev:EV-YC-06}} {{ev:EV-YC-07}}.
- **Implementado en el repositorio, aún no desplegado:** retiradas persistentes, políticas, propuestas de fuentes; archivo no operativo.
- **Bloqueos:** cambios que modifican garantías de publicación esperan una aceptación específica; faltan validaciones humanas para el visto bueno formal de V1.
- **Siguiente:** desplegar y migrar tras autorización; probar restauraciones desde los tres proveedores del archivo {{ev:EV-YC-08}}.

### Installer Auditor

- **Fase:** desarrollo.
- **Hecho:** instala reglas solo si pasan todas las verificaciones del canal {{ev:EV-YC-09}}.
- **Bloqueos:** sin firmar ni notarizar; una decisión de arquitectura pendiente de revisión humana.
- **Siguiente:** prueba de rendimiento de extremo a extremo con el canal real, planificada {{ev:EV-YC-10}}.

### MacUSBGuard

- **Fase:** validación (existe una candidata a versión en una de dos líneas de desarrollo).
- **Hecho:** un hito de candidata a versión e informes de auditoría {{ev:EV-EC-01}}.
- **Bloqueos:** ningún permiso de Endpoint Security consta como utilizable {{ev:EV-EC-02}}.
- **Siguiente:** candidata a V1; el siguiente frente de trabajo aún no está elegido.

### MacFirewallGuard

- **Fase:** desarrollo (una fase posterior está parcial).
- **Hecho:** la base, la interfaz y el módulo de integridad de red {{ev:EV-EC-04}}.
- **Bloqueos:** ningún permiso de Network Extension consta como utilizable; MacCoreGuard no existe como servicio {{ev:EV-EC-03}}.
- **Siguiente:** completar la fase parcial.

### MacCoreGuard

- **Fase:** prototipo.
- **Hecho:** protocolo y capa criptográfica con pruebas propias {{ev:EV-EC-06}}.
- **Bloqueos:** registro, firma e ingesta son marcadores de posición.
- **Siguiente:** oleadas de trabajo por etapas, sin fechas.

### MacGuardDesignKit

- **Fase:** desarrollo.
- **Hecho:** varias versiones anteriores a 1.0 {{ev:EV-EC-07}}.
- **Bloqueos:** decisiones de diseño pendientes.
- **Siguiente:** 1.0 cuando dos productos la usen.

### MacProcessGuard

- **Fase:** concepto (sin repositorio ni especificación).
- **Hecho:** nada más que la frontera descrita en otros proyectos {{ev:EV-EC-05}}.
- **Bloqueos:** no existe repositorio ni especificación.
- **Siguiente:** decidir si se emprende.

## Dependencias entre proyectos

- Installer Auditor depende de que YARA Channel siga publicando releases verificables.
- MacFirewallGuard necesita MacProcessGuard (identidad del proceso) y MacCoreGuard (evidencia verificable) para completar su diseño.
- La versión 1.0 de MacGuardDesignKit depende de que dos productos la adopten.

## Seguimiento en vivo

El avance se sigue en GitHub con hitos, incidencias y releases reales: [hito V1.1](https://github.com/MacGuard/macguard-yara-channel/milestone/2), [hito del archivo triple](https://github.com/MacGuard/macguard-yara-channel/milestone/4) y [releases](https://github.com/MacGuard/macguard-yara-channel/releases). Esta página se actualiza con cambios revisados por pull request, no automáticamente.

## Datos medidos de GitHub

{{roadmap:table}}

Los números son los que informa GitHub en la fecha indicada (se refrescan con `python3 scripts/wiki_roadmap.py` y entran por pull request). No son un porcentaje de avance.

## Lo que todavía no sabemos

- Las fechas de entrega: no están definidas ni respaldadas.
- El estado de los proyectos privados más allá de los commits revisados: cada fila indica el commit de referencia en la [matriz de evidencias](ES-Evidence).
