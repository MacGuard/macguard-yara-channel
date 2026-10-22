# Publicación y firma

[Inicio](ES-Home) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing) · [Transparencia](ES-YARA-Transparency) · [Verificar](ES-YARA-Verify)

## En 30 segundos

Cada release es un paquete completo (`rules-release.tar.gz`) con las reglas y una lista firmada (`manifest.json`) que da el SHA-256 de cada archivo. Un workflow de GitHub, `publish.yml`, firma esa lista con Sigstore sin guardar ninguna clave privada. Quien descarga puede comprobar **quién** publicó y que los **bytes** son los firmados. Eso no demuestra que todas las reglas las escribiera MacGuard ni que sean inocuas. {{ev:EV-YC-45}} {{ev:EV-YC-46}}

> La firma de MacGuard muestra la procedencia de la publicación bajo su identidad y un vínculo criptográfico con el artefacto; no muestra que MacGuard escribiera cada regla ni que todas sean inofensivas.

## Un ejemplo cotidiano

Una librería vende un libro con el sello del distribuidor y un precinto numerado. El autor es otra persona; el sello dice quién lo distribuye; el precinto dice que nadie ha cambiado las páginas desde que se selló; y nada de eso garantiza que el contenido del libro sea correcto o inocuo. Aquí es igual: autor original, distribuidor, firmante, integridad y seguridad del contenido son cinco cosas distintas.

{{diagram:trust-questions}}

| Pregunta | Qué responde | Dónde se ve |
|---|---|---|
| Autor original de una regla | El repositorio de origen y su licencia (dos fuentes de reglas) | `sources` del manifiesto {{ev:EV-YC-49}} |
| Distribuidor del paquete | El canal MacGuard, como release de GitHub | El repositorio y la release |
| Identidad del firmante | El workflow `publish.yml` de este repositorio (rama `main`) | Certificado Sigstore |
| Integridad de los bytes | SHA-256 de cada archivo y `rules_root` | `manifest.json` firmado |
| Seguridad del contenido | **No** la prueba nada de lo anterior | Pruebas estáticas y dinámicas, con sus límites |

## Paso a paso

{{diagram:release-sequence}}

1. `precheck` compara el candidato con la última release; si es idéntico, no pide aprobación ni publica.
2. `publish` (en el entorno `stable-signing-auto`, sin revisor obligatorio, mientras la variable `AUTO_PUBLISH` sea `true`; si se desactiva se usa el entorno con aprobación humana `stable-signing`; la protección de rama, la identidad OIDC y los controles técnicos son los mismos en ambos modos) re-verifica el conjunto final: clasificación estática y evidencia dinámica.
3. Firma el checkpoint del registro, escribe el manifiesto (`scripts/seal.py`), lo firma y genera la prueba de inclusión.
4. Empaqueta: `tar -czf rules-release.tar.gz -C dist rules manifest.json`.
5. Comprueba los artefactos exactos, crea la release como **borrador**, adjunta todos los archivos y solo entonces la hace pública. {{ev:EV-YC-45}}

## Cómo funciona por dentro

**`manifest.json`.** Claves reales de la última release leída: `created_at`, `evidence`, `files`, `log`, `rejected`, `rules_root`, `schema`, `sources`, `stats`, `status`, `validation`. `files` da `path`, `sha256` y `bytes` de cada archivo; `rules_root` es la raíz Merkle de esa lista (ver [Transparencia](ES-YARA-Transparency)); `log` copia origen, tamaño y raíz del registro (`macguard-rules-log v1`); `stats` son recuentos derivados de los propios archivos. Se escribe con claves ordenadas y sin espacios. `seal.py` se niega a sellar si falta evidencia dinámica o no corresponde a este conjunto. {{ev:EV-YC-45}}

**Qué se firma y con qué.** `cosign sign-blob --yes --bundle` firma dos archivos: `manifest.json` y `checkpoint.txt`. Sin clave guardada: GitHub entrega un token OIDC que nombra al workflow, Fulcio emite un certificado de vida corta ligado a esa identidad y la firma se registra en Rekor, el registro público de Sigstore. Identidad esperada: `https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main`; emisor `https://token.actions.githubusercontent.com`. El paquete no se firma por separado: lo cubre el manifiesto firmado, porque lista el SHA-256 de cada archivo. {{ev:EV-YC-46}}

{{diagram:sigstore-sequence}}

**¿Existen atestaciones?** Un *attestation* en el sentido de GitHub/SLSA es una declaración firmada sobre **cómo** se construyó un artefacto (in-toto). Este repositorio **no las produce**: no hay en `.github/workflows/` ningún paso de atestación ni `slsa` (búsqueda de `attest` y `slsa`), y la documentación del sitio lo declara como límite. Lo que existe en su lugar: (1) firmas Sigstore de dos blobs; (2) el campo `evidence` dentro del manifiesto firmado (`candidate_run_id`, `candidate_workflow_sha`, `publish_run_url` y la medición dinámica), que `seal.py` describe como declaración del propio workflow, "no una atestación independiente". Añadir atestaciones SLSA sería un cambio de diseño no programado. {{ev:EV-YC-47}}

**Vínculo con commit y ejecución.** El tag es `rules-AAAAMMDD-<id de ejecución>`; el id es el de la ejecución de `publish.yml`. El manifiesto firmado incluye `evidence.publish_run_url` (esa ejecución), `candidate_run_id` (la ejecución diaria que produjo el candidato) y `candidate_workflow_sha` (commit del workflow del candidato). La identidad del certificado nombra el workflow y la rama, no un commit concreto; el verificador no comprueba un SHA de commit en el certificado (no verificado si el certificado lo incluye). {{ev:EV-YC-48}}

**Cuatro mecanismos que no se intercambian.**

| Mecanismo | Qué prueba | Qué NO prueba |
|---|---|---|
| Hashes (SHA-256) | Que unos bytes son los listados | Quién los listó |
| Sigstore (cosign) | Qué identidad firmó esos bytes y cuándo | Que el proceso de construcción fuera el esperado, ni que el contenido sea bueno |
| Atestación (SLSA/in-toto) | Cómo se construyó (no existe aquí) | n/a: no se produce |
| Registro de transparencia propio | Que una publicación está en un registro solo-añadir y que no se reescribió | Que la regla sea inocua; no es Rekor |

## Cómo comprobarlo tú

```bash
python3 -I scripts/verify_public_release.py --latest
```

Detalles y salida real en [Verificar](ES-YARA-Verify). Código: [publish.yml](https://github.com/MacGuard/macguard-yara-channel/blob/main/.github/workflows/publish.yml), [seal.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/seal.py), [release.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/release.md).

## Límites

- Una firma válida y hashes correctos prueban **quién** publicó exactamente **esos bytes**, no que las reglas sean buenas.
- Cada release es el conjunto completo; una corrección es una release nueva y por convención, los tags no se reutilizan (las releases inmutables de GitHub, que lo impondrían, no están activadas).
- Las releases inmutables de GitHub no están activadas (requiere autorización de una persona); el flujo borrador a público ya es el que ese ajuste exige. {{ev:EV-YC-59}}
- `release.json` es metadato sin firmar; el verificador lo contrasta con los valores firmados.

## Estado

| Capacidad | Estado |
|---|---|
| Release completa con manifiesto y registro firmados con Sigstore | operativo {{ev:EV-YC-03}} |
| Vínculo release a ejecución del workflow dentro del manifiesto | operativo {{ev:EV-YC-48}} |
| Atestaciones GitHub/SLSA | no implementado, no programado {{ev:EV-YC-47}} |
| Releases inmutables de GitHub | no activadas {{ev:EV-YC-59}} |
