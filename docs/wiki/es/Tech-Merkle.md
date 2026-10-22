# Tecnología: árboles de Merkle

[Inicio](ES-Home) · [Límites](ES-YARA-Limits) · [Tecnología: Sigstore](ES-Tech-Sigstore) · [Tecnología: YARA](ES-Tech-YARA) · [Archivo histórico](ES-YARA-Archive)

## En 30 segundos

Un árbol de Merkle resume una lista larga de cosas en un único número (la **raíz**). Si cambia cualquier elemento, cambia la raíz. Además permite demostrar con muy pocos datos que un elemento está en la lista (**prueba de inclusión**) y que una versión nueva de la lista solo añadió cosas a la anterior (**prueba de consistencia**).

## Un ejemplo cotidiano

Imagina un libro de registro donde cada página lleva un resumen de las anteriores y la última página lleva el resumen de todo. Si alguien arranca o cambia una página antigua, el resumen final ya no cuadra. No dice si lo escrito en las páginas era cierto.

{{diagram:rules-merkle-1-leaves}}

{{diagram:rules-merkle-2-leaves}}

{{diagram:rules-merkle-3-node}}

{{diagram:rules-merkle-4-root}}

## Cómo funciona por dentro

- **Problema:** probar que un conjunto de archivos y un registro histórico no se alteraron ni se reescribieron.
- **Algoritmo (RFC 6962):** hoja = SHA-256(`0x00` + dato); nodo = SHA-256(`0x01` + izquierda + derecha); el árbol se parte en la mayor potencia de dos menor que *n*. Los prefijos distintos evitan que una hoja se haga pasar por un nodo {{ev:EV-YC-76}}.
- **Implementación:** `scripts/tlog.py` define `leaf_hash`, `node_hash`, `mth`, `inclusion_proof`, `verify_inclusion`, `consistency_proof` y `verify_consistency` {{ev:EV-YC-68}}.
- **Dos árboles:** `rules_root` (hojas = ruta + hash de cada archivo de reglas, ordenadas por ruta; `check_inventory` rechaza rutas duplicadas, con `..` o absolutas) y el registro público `logs/log.jsonl` (una hoja por línea) {{ev:EV-YC-68}}.
- **Coste:** una prueba tiene del orden de log₂(*n*) hashes; el RFC da como máximo ⌈log₂(*n*)⌉ + 1 nodos para consistencia {{ev:EV-YC-76}}.
- **No previene:** que se añadan entradas falsas legítimamente firmadas; solo hace detectable la reescritura.

{{diagram:log-merkle-1-pair-a}}

{{diagram:log-merkle-2-pair-b}}

{{diagram:log-merkle-3-pair-c}}

{{diagram:log-merkle-4-root}}

## Quién más lo usa

Ninguna fila implica que estos proyectos usen MacGuard.

| Quién | Clasificación | Fuente |
|---|---|---|
| Certificate Transparency (RFC 6962): registros públicos de certificados con árboles de Merkle y pruebas de inclusión y consistencia | usa un algoritmo relacionado (el mismo hash de árbol que este proyecto implementa) | {{ev:EV-YC-76}} |
| Base de datos de sumas de comprobación de módulos de Go: según su blog, está construida sobre un registro transparente («árbol de Merkle») respaldado por Trillian, y `go` comprueba pruebas de inclusión y consistencia | usa un algoritmo relacionado | {{ev:EV-YC-77}} |

## Cómo comprobarlo tú

```
python3 -m unittest tests.test_tlog tests.test_tlog_adversarial tests.test_rules_root_vectors
```

Las pruebas adversarias mutan cada elemento de las pruebas para todos los tamaños de árbol probados, y comprueban historias bifurcadas, truncadas o reordenadas {{ev:EV-YC-68}}.

## Límites

La raíz demuestra integridad del conjunto, no su calidad. El registro es tan fiable como la firma de su punto de control ([Sigstore](ES-Tech-Sigstore)). El RFC 6962 está declarado obsoleto por el RFC 9162; este proyecto usa la construcción de hash del 6962 {{ev:EV-YC-76}}.

## Estado

| Capacidad | Estado |
|---|---|
| `rules_root` y registro público con puntos de control firmados | publicado {{ev:EV-YC-04}} |
| Manifiesto del archivo con raíz Merkle (herramienta local) | implementado, no desplegado {{ev:EV-YC-61}} |
