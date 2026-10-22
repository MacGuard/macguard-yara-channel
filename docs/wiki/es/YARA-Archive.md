# Archivo histórico en tres proveedores

[Inicio](ES-Home) · [Límites](ES-YARA-Limits) · [Tecnología: S3 y copias](ES-Tech-S3-Backups) · [Tecnología: Merkle](ES-Tech-Merkle) · [Tecnología: Sigstore](ES-Tech-Sigstore)

> **Estado: NO operativo.** Es un diseño con herramientas locales. Ningún flujo de trabajo de archivo en `main` escribe en un proveedor. No se ha escrito ni restaurado nada en un proveedor, y **no se ha probado ninguna restauración desde un proveedor real** {{ev:EV-YC-62}} {{ev:EV-YC-08}}. Las herramientas de la fase 1 están en `main`.

## En 30 segundos

El canal publica reglas firmadas en GitHub. Si GitHub perdiera el historial, ¿se podría demostrar qué se publicó y cuándo? El plan es guardar una copia permanente en **tres proveedores de almacenamiento independientes** (Cloudflare R2, Backblaze B2 y Scaleway Object Storage), un bucket por proveedor, de modo que el fallo o la decisión de un solo proveedor no pueda borrar ni falsificar el historial. Los tres comparten un único origen de escritura; ver Límites. {{ev:EV-YC-60}}

## Un ejemplo cotidiano

Es como guardar el acta de una asamblea en tres notarías de países distintos. Si una se incendia, quedan dos. Si alguien altera una copia, las otras dos delatan la diferencia. No impide que el acta original contuviera un error: solo conserva lo que se escribió.

{{diagram:archive-triple-storage-1-write}}

{{diagram:archive-triple-storage-2-verify}}

## Qué se guardaría

| Pieza | Para qué sirve |
|---|---|
| Paquetes de reglas (`rules-release.tar.gz`) y manifiestos | El contenido exacto de cada release |
| Hashes SHA-256 y firmas Sigstore | Comprobar integridad y origen |
| Puntos de control, pruebas Merkle y registros públicos (`logs/`) | Demostrar que el historial solo crece |
| Auditoría privada cifrada, con sellos mensuales | Conservar la cadena de decisiones sin exponer su contenido |

Fuente de la lista: sección 3 de la especificación {{ev:EV-YC-60}}. No se publican nombres de bucket, direcciones de servicio ni identificadores de cuenta.

## Paso a paso

1. Antes de escribir se comprueba que el objeto no contiene secretos ni nombres de reglas privadas, y se calcula su SHA-256.
2. La auditoría privada se cifra con `age` **antes** de salir del proceso; el proveedor nunca ve el texto en claro.
3. Se escribe en los tres proveedores con credenciales de solo escritura, sin permiso de borrado.
4. Se lee de vuelta con otra credencial de solo lectura y se comparan hashes. Si no coinciden los tres, hay alerta y no se poda nada.
5. Un manifiesto de manifiestos, firmado con Sigstore, encadena cada archivado con el anterior.

## Cómo funciona por dentro

**Versionado y bloqueo de objetos (Object Lock).** El versionado conserva las versiones antiguas en vez de sobrescribirlas. Object Lock impide borrar o sobrescribir una versión durante un periodo de retención. Hay dos modos {{ev:EV-YC-78}} {{ev:EV-YC-79}}:

- **Gobernanza:** protege frente a la mayoría de usuarios, pero una identidad con el permiso adecuado **puede saltarse el bloqueo**. No detiene a una identidad autorizada que esté comprometida.
- **Cumplimiento (compliance):** nadie puede quitarlo durante la retención. Es irreversible: un error de subida (por ejemplo, un secreto) no se podría retirar.

> **Compliance NO está activado** y activarlo requiere autorización explícita del propietario {{ev:EV-YC-60}}. La fortaleza del bloqueo depende de la configuración de cada proveedor y de los permisos de las claves usadas; las capacidades de cada proveedor aún deben confirmarse en buckets de prueba {{ev:EV-YC-63}}.

**Replicación independiente.** Tres cuentas, tres entidades legales y jurisdicciones distintas, credenciales distintas. Límite reconocido: los tres dependen de un único origen de escritura (GitHub Actions) y de un único propietario; «independiente» no significa inmune a quien controle el origen de firma {{ev:EV-YC-63}}.

**Cifrado en cliente (principios).** `age` cifra con claves públicas; el proceso de archivado solo conoce la clave pública y puede cifrar pero no descifrar. La clave privada se guarda fuera de línea y bajo control humano. Sin ella el detalle no se puede leer, aunque los sellos siguen siendo comprobables {{ev:EV-YC-60}} {{ev:EV-YC-61}}.

**Restauración.** Se diseña como ensayo independiente por proveedor: restaurar desde uno solo y verificar con el verificador público. Existen las órdenes `restore` y `rehearse` en `scripts/archivectl.py`, probadas con directorios locales, **no** con un proveedor real {{ev:EV-YC-61}}.

{{diagram:archive-provider-outage}}

## Cómo comprobarlo tú

```
python3.12 -m unittest tests.test_archive_segments tests.test_archive_providers tests.test_archive_store
```

Son pruebas rápidas y sin red. La prueba con el binario real de `age` solo corre con `ARCHIVE_REAL_AGE=1`; sin esa variable consta como no ejecutada {{ev:EV-YC-61}}. Código: [`scripts/archive/`](https://github.com/MacGuard/macguard-yara-channel/tree/main/scripts/archive), [especificación](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/audit/historical-archive-triple-spec.md).

## Límites

- Una copia inmutable de datos erróneos sigue siendo errónea; el archivo conserva, no valida el contenido de las reglas.
- Precios, capas gratuitas y funciones de cada proveedor pueden cambiar; la especificación lee los precios del 2026-10-21 y no son garantía.
- La guía de configuración todavía no está en el repositorio, así que esta página se apoya en la especificación {{ev:EV-YC-62}}.
- La retención compliance, la poda de la base de datos y cualquier restauración con la clave real exigen autorización del propietario.

## Estado

| Capacidad | Estado |
|---|---|
| Herramientas de archivo de la fase 1 (segmentos, sellos, `age`, restauración local) | implementado, no desplegado {{ev:EV-YC-61}} |
| Preparación de proveedores | no iniciada |
| Escritura en proveedores y restauración | planificado |
| Bloqueo en modo compliance | planificado, sin autorizar |
| Restauración probada desde un proveedor real | no realizada |
| Poda de filas de la auditoría | solo informe en seco; no ejecutable |
