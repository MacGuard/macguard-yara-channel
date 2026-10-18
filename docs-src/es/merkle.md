---
title: Árboles Merkle
summary: Cómo se calcula `rules_root` y la raíz del registro, con un ejemplo que puedes recalcular.
---
## Reglas: `rules_root`

Los ficheros se ordenan por ruta (bytes UTF-8). La hoja de cada fichero es `SHA-256(0x00 || ruta || 0x00 || sha256_hex)` y los nodos internos `SHA-256(0x01 || izquierda || derecha)`. Un árbol de n hojas se parte en la mayor potencia de dos menor que n (RFC 6962 / RFC 9162). La raíz se guarda en el manifiesto firmado.

{{diagram:rules-merkle}}

Prueba a recalcularlo tú con el `manifest.json` de la release (solo biblioteca estándar de Python). Debe imprimir `True`:

```python
import hashlib, json
m = json.load(open('manifest.json'))
H = hashlib.sha256
leaf = lambda b: H(b'\x00' + b).digest()
node = lambda l, r: H(b'\x01' + l + r).digest()
def mth(xs):
    if len(xs) == 1: return xs[0]
    k = 1
    while k * 2 < len(xs): k *= 2
    return node(mth(xs[:k]), mth(xs[k:]))
files = sorted(m['files'], key=lambda f: f['path'].encode())
root = mth([leaf(f"{f['path']}\0{f['sha256']}".encode()) for f in files]).hex()
print(root, root == m['rules_root'])
```

Efecto práctico: añadir, quitar o modificar un solo byte de un fichero, o añadir un fichero extra al paquete, cambia `rules_root` y la verificación falla.

## Registro: raíz del log

Cada línea de `logs/log.jsonl` es una hoja: `SHA-256(0x00 || bytes exactos de la línea)`. Se combinan con la misma regla. La raíz y el número de entradas forman el checkpoint (ver [Registro y checkpoints](page:transparency-log)).

{{diagram:log-merkle}}

## Pruebas

- **Inclusión:** `inclusion-proof.json` lleva los hashes hermanos que unen la entrada del registro de esta release con la raíz del checkpoint.
- **Consistencia:** `consistency.json` demuestra que el registro del tamaño anterior es prefijo del actual (solo se añadió).

> **LÍMITE** Las páginas web recalculan estas cuentas en el navegador, pero **no verifican firmas Sigstore**. Para eso usa `cosign`, el verificador público o la app.
