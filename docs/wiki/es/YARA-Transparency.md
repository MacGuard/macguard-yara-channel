# Registro de transparencia

[Inicio](ES-Home) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing) · [Transparencia](ES-YARA-Transparency) · [Verificar](ES-YARA-Verify)

## En 30 segundos

El canal lleva un **registro de transparencia**: un diario pensado para que solo se añadan líneas; si alguien borra o cambia una, un verificador lo detecta (no lo impide). Cada cierto tiempo se firma una "foto" de ese diario (el **punto de control**). Cualquiera puede recalcular las matemáticas y comprobar que una publicación está en el diario y que el diario de hoy contiene entero el de ayer. Si alguien intenta alterar una publicación anterior, las cuentas dejan de salir. {{ev:EV-YC-04}} {{ev:EV-YC-50}}

## Un ejemplo cotidiano

Un libro de cuentas cuyas páginas están enlazadas matemáticamente: al final de cada página se anota una huella que depende de todo lo escrito antes. Si alguien arranca o reescribe una página antigua, la huella de las siguientes ya no cuadra con la que se firmó (y cualquiera puede comprobar esa firma). La analogía sirve para la idea; el mecanismo real es un árbol de Merkle, explicado abajo.

Palabras clave, una vez:

- **Entrada**: una línea JSON de `logs/log.jsonl` (un suceso, por ejemplo `candidate.accepted`).
- **Árbol de Merkle**: hashes de hashes; cada hoja es una entrada y cada nodo resume a sus dos hijos.
- **Raíz**: el hash de la cima; cambia si cambia cualquier hoja.
- **Punto de control**: texto de tres líneas con origen, número de entradas y raíz; se firma con Sigstore.
- **Prueba de inclusión**: los hashes hermanos que unen una entrada con la raíz.
- **Prueba de consistencia**: demuestra que el registro de tamaño *n* es un prefijo del de tamaño *m > n*.

{{diagram:log-merkle}}

## Paso a paso

1. Cada suceso se añade como una línea al final de `logs/log.jsonl`.
2. `tlog.py checkpoint` calcula la raíz de todas las líneas y escribe el punto de control.
3. `publish.yml` firma el punto de control con Sigstore (`checkpoint.sigstore.json`).
4. La release lleva `inclusion-proof.json` (la entrada de esta release está en el punto de control) y, si hay release previa, `consistency.json`.
5. El manifiesto firmado copia `log.size` y `log.root`, que deben coincidir con `checkpoint.txt`.

{{diagram:checkpoint-sequence}}

{{diagram:checkpoint-evolution}}

## Cómo funciona por dentro

**Algoritmo.** Árbol de Merkle de RFC 6962 (hashing) y RFC 9162 (pruebas). Entrada: lista ordenada de hojas. Hoja = `SHA-256(0x00 || datos)`; nodo = `SHA-256(0x01 || izquierda || derecha)`; un árbol de *n* hojas se parte en la mayor potencia de dos menor que *n*. Salida: la raíz de 32 bytes. Se leyó en `scripts/tlog.py` (`leaf_hash`, `node_hash`, `mth`) y se repite de forma independiente en `scripts/verify_public_release.py`. {{ev:EV-YC-50}}

Dos árboles con la misma regla: el **registro** (hoja = bytes exactos de la línea) y `rules_root` (hoja = `path`, un byte NUL y el SHA-256 hexadecimal del archivo, ordenados por ruta). Con `rules_root`, cambiar un byte de un archivo, quitar uno o añadir uno extra cambia la raíz.

Ejemplo mínimo con tres entradas `E0 E1 E2` (`H` = SHA-256, `||` = concatenar):

```
L0 = H(00 || E0)    L1 = H(00 || E1)    L2 = H(00 || E2)
N01  = H(01 || L0 || L1)
raíz = H(01 || N01 || L2)
prueba de inclusión de E2 = [N01]      (un hash hermano)
si E0 cambia: L0, N01 y raíz cambian; el punto de control firmado ya no coincide
```

**Punto de control.** Tres líneas: `macguard-rules-log v1`, el tamaño y la raíz en base64 (`Log.parse_checkpoint`). Lo firma Sigstore y el manifiesto repite el mismo tamaño y raíz. {{ev:EV-YC-51}}

**Qué puede comprobar cualquiera sin confiar en nosotros.** (1) La firma del punto de control y del manifiesto con la identidad esperada. (2) La raíz de `rules_root` recalculada a partir de los archivos. (3) Que la entrada de la release está en el punto de control (inclusión). (4) Que el punto de control nuevo extiende el que ya conocías (consistencia) y que el tamaño no decrece. {{ev:EV-YC-52}}

**Si alguien altera una publicación anterior.**

| Intento | Qué lo detecta | Cómo |
|---|---|---|
| Cambiar una entrada vieja | Raíz distinta | La nueva raíz no coincide con el punto de control firmado ni con la prueba de inclusión. |
| Borrar entradas (volver atrás) | Verificador con tu punto de control guardado | `ROLLBACK`: menos entradas que las que ya confías. |
| Reescribir y mantener el tamaño | Verificador | `FORK`: raíz distinta con el mismo tamaño. |
| Reescribir y crecer | Prueba de consistencia | No existe una prueba válida de que la historia reescrita contenga a la anterior. |
| Cambiar un archivo ya publicado | `rules_root` y SHA-256 | La suma deja de coincidir con el manifiesto firmado. |

Pruebas que lo cubren: `tests/test_tlog.py` (`test_consistency_detects_rewritten_history`), `tests/test_tlog_adversarial.py` (`test_a_rewritten_history_has_no_valid_consistency_proof`, `test_a_checkpoint_for_a_forked_history_or_a_longer_log_is_detected`), `tests/test_verify_public_release.py` (`test_a_fork_at_the_same_size_is_detected`). Además `publish.yml` verifica el registro existente antes de ampliarlo. {{ev:EV-YC-52}}

Qué no evita: la detección de retroceso y de fork exige haber guardado un punto de control anterior; una primera verificación no establece protección contra retroceso. Y el registro prueba que hubo una publicación, no que sus reglas sean buenas. Coste: el registro crece una línea por suceso; no se midió el tiempo de verificación para esta página.

## Cómo comprobarlo tú

Recalcula `rules_root` con la biblioteca estándar de Python (script en [merkle.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/merkle.md)) o deja que el verificador lo haga todo, incluida la inclusión: ver [Verificar](ES-YARA-Verify). Código: [tlog.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/tlog.py).

## Límites

- Las páginas web recalculan las sumas en el navegador pero **no verifican firmas Sigstore**. {{ev:EV-YC-58}}
- Este registro es nuestro; no es Rekor ni un tercero independiente. Su fuerza viene de la firma del punto de control por la identidad del flujo de trabajo y de que otras personas guarden puntos de control.
- El registro lleva recuentos y sucesos, no nombres ni hallazgos de reglas en cuarentena.

## Estado

| Capacidad | Estado |
|---|---|
| Registro, puntos de control firmados, pruebas de inclusión y consistencia en cada release | publicado {{ev:EV-YC-04}} |
| Verificación por terceros con script público y pruebas | operativo {{ev:EV-YC-52}} |
| Monitor externo independiente que vigile el registro | no verificado: no se encontró en el repositorio |
