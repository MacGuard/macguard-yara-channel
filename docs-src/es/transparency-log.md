---
title: Registro y checkpoints
summary: Qué se registra, cómo se firman los checkpoints y cómo se detectan retrocesos.
---
## El registro

`logs/log.jsonl` es un registro de solo añadir con una línea JSON por evento (`time`, `level`, `event`, `message` y detalles). Su vista legible está en la página de transparencia. Los eventos llevan solo cifras: nunca nombres ni hallazgos de reglas en cuarentena.

## Checkpoints

Un checkpoint es un texto de tres líneas: el origen `macguard-rules-log v1`, el número de entradas y la raíz en base64. `publish.yml` lo firma con Sigstore (`checkpoint.sigstore.json`) y lo adjunta a la release (`checkpoint.txt`).

{{diagram:checkpoint-sequence}}

{{diagram:checkpoint-evolution}}

El manifiesto firmado incluye la cabeza del registro (`log.origin`, `log.size`, `log.root`) y debe coincidir con el checkpoint adjunto. En la última release el tamaño es {{release.log_size}} y la raíz del registro `{{release.log_root}}`.

## Eventos

Estos son los códigos de evento que emiten los workflows y scripts. Una prueba de la documentación comprueba que cada uno aparece en el fichero indicado.

{{events_table}}
