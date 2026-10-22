# Roadmap global de MacGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem)

## En 30 segundos

Aquí ves en qué fase está cada aplicación, qué ya se hizo, qué la bloquea y qué viene después. **No hay fechas ni porcentajes**: no los inventamos. Una fase está "hecha" solo si hay evidencia enlazada; una aplicación no está "al 50 %" por tener 500 pruebas.

## Un ejemplo cotidiano

Es como el panel de obras de un edificio: dice qué planta está terminada, cuál está parada y por qué. No promete cuándo se abre.

## Vista global

{{diagram:roadmap-global}}

## Por aplicación

| Aplicación | Fase actual | Hecho | Bloqueos | Siguiente |
|---|---|---|---|---|
| YARA Channel | V1.1, fase 2 | Canal firmado y verificado (V1); fase 1 de V1.1 fusionada {{ev:EV-YC-02}} {{ev:EV-YC-06}} {{ev:EV-YC-07}} | Tres cambios que modifican garantías de publicación esperan una aceptación específica; faltan validaciones humanas para el visto bueno formal de V1 | Desplegar y migrar tras autorización; probar restauraciones desde los tres proveedores del archivo {{ev:EV-YC-08}} |
| Installer Auditor | Desarrollo | Instala reglas solo si pasan todas las verificaciones del canal {{ev:EV-YC-09}} | Sin firmar ni notarizar; una decisión de arquitectura pendiente de revisión humana | Prueba de rendimiento de extremo a extremo con el canal real, planificada {{ev:EV-YC-10}} |
| MacUSBGuard | Validación | Tag v1.0.0-rc1 (en una línea distinta de la rama actual, ver su ficha); informes de auditoría {{ev:EV-EC-01}} | Falta el permiso de Apple para Endpoint Security {{ev:EV-EC-02}} | Candidato a V1; el siguiente frente de trabajo aún no está elegido |
| MacFirewallGuard | F2-A (parcial) | F1-A, F1-B, GUI-V1 y F2-NIM {{ev:EV-EC-04}} | Falta el permiso de Apple para Network Extension; MacCoreGuard no existe como servicio {{ev:EV-EC-03}} | Completar F2-A |
| MacCoreGuard | Prototipo | Protocolo y capa criptográfica con pruebas propias {{ev:EV-EC-06}} | Registro, firma e ingesta son marcadores de posición | Oleadas de trabajo definidas en su contrato, sin fechas |
| MacGuardDesignKit | Desarrollo | Versiones 0.1.0 a 0.3.1 {{ev:EV-EC-07}} | Cinco decisiones de diseño pendientes | 1.0 cuando dos productos la usen |
| MacProcessGuard | Concepto | Nada más que la frontera descrita en otros proyectos {{ev:EV-EC-05}} | No existe repositorio ni especificación | Decidir si se emprende |

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
