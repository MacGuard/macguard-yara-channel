# Tecnología: almacenamiento S3 y copias de seguridad

[Inicio](ES-Home) · [Archivo histórico](ES-YARA-Archive) · [Límites](ES-YARA-Limits) · [Tecnología: Merkle](ES-Tech-Merkle) · [Tecnología: Sigstore](ES-Tech-Sigstore)

> **Estado: planificado.** El archivo en tres proveedores no es operativo ni se ha probado ninguna restauración real {{ev:EV-YC-62}} {{ev:EV-YC-08}}.

## En 30 segundos

«S3» es la forma de hablar con almacenes de objetos en la nube (guardas archivos en «cubos» o *buckets*). Muchos proveedores la entienden. Con **versionado** (se conservan versiones antiguas) y **Object Lock** (no se puede borrar ni sobrescribir durante un tiempo) se obtiene una copia «solo se añade», útil contra errores y borrados.

## Un ejemplo cotidiano

Es una caja fuerte con ranura: puedes meter documentos, pero durante un plazo nadie puede sacarlos ni cambiarlos. Si el dueño de la llave maestra decide abrirla (modo gobernanza), puede. Con el modo estricto (compliance) ni siquiera él.

{{diagram:archive-triple-storage}}

## Cómo funciona por dentro

- **Problema:** conservar el historial aunque falle, se corrompa o se manipule un proveedor.
- **Piezas:** versionado; retención por Object Lock; reglas de identidad que dan a la clave de escritura solo permiso de subir; lectura de vuelta con otra clave; hashes SHA-256 por objeto {{ev:EV-YC-60}}.
- **Gobernanza frente a compliance:** en gobernanza, quien tenga el permiso especial puede saltarse el bloqueo; en compliance no puede nadie durante la retención, ni el titular de la cuenta (salvo borrar la cuenta, en el caso de AWS) {{ev:EV-YC-78}} {{ev:EV-YC-79}}.
- **Tres proveedores:** Cloudflare R2, Backblaze B2 y Scaleway, un bucket cada uno. La especificación anota que la fortaleza del bloqueo depende de la configuración de cada proveedor, y que la función debe confirmarse en buckets de prueba {{ev:EV-YC-63}}.
- **Implementación en el repositorio:** `scripts/archive/providers.py` (directorio local y adaptador S3 por línea de órdenes), `store.py`, `restore.py`, entrada `scripts/archivectl.py` {{ev:EV-YC-61}}.
- **Coste:** la especificación estima de céntimos a decenas de dólares en total en casi todos los escenarios, con precios leídos el 2026-10-21 que pueden cambiar {{ev:EV-YC-60}}.
- **No previene:** un origen de escritura comprometido que suba datos falsos con firma válida; ni la pérdida de la clave de descifrado.

{{diagram:archive-provider-outage}}

## Quién más lo usa

Ninguna fila implica que estas organizaciones usen MacGuard.

| Quién | Clasificación | Fuente |
|---|---|---|
| Amazon S3: Object Lock (modelo «escribir una vez, leer muchas»), con modos de gobernanza y compliance, y requiere versionado | usa la misma tecnología | {{ev:EV-YC-78}} |
| Backblaze B2: Object Lock con modos gobernanza y compliance, que debe habilitarse en el bucket y no se puede desactivar después | implementa una solución similar | {{ev:EV-YC-79}} |

## Cómo comprobarlo tú

```
python3.12 -m unittest tests.test_archive_providers tests.test_archive_store
python3 scripts/archivectl.py --help
```

Las pruebas usan un proveedor en directorio local y proveedores hostiles simulados; no tocan ningún servicio real.

## Límites

Copias en tres proveedores no protegen contra quien controle el origen de firma, el DNS o el dispositivo del propietario. Un error subido bajo retención compliance no se puede retirar {{ev:EV-YC-60}}.

## Estado

| Capacidad | Estado |
|---|---|
| Herramientas de archivo y restauración local | implementado, no desplegado {{ev:EV-YC-61}} |
| Buckets con versionado y Object Lock en los tres proveedores | planificado |
| Modo compliance | planificado, sin autorizar |
