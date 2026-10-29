# Laboratorio Sigstore real del checkpoint de evidencia (2026-10-29)

Valida de extremo a extremo, con firma **real** (Sigstore keyless, identidad OIDC de GitHub Actions) el mecanismo de checkpoints de la PR #70 (`gateway/tools/evidence_chain.mjs`, `.github/workflows/evidence-checkpoint.yml`). **No toca producción**: checkpoint sintético (`count`, `head` de un log inventado de 3 líneas), ramas efímeras `exp/sigstore-lab` (borrada), sin secretos, sin D1, sin buckets, sin rama `evidence`, sin `EVIDENCE_MODE`/`EVIDENCE_REFS`, sin cambios en `main`.

## Ejecuciones

| Run | Commit del laboratorio | Resultado | Notas |
|---|---|---|---|
| `40791969186` | `3337c40` | 13/14 comprobaciones PASS, 1 FAIL | El FAIL (C2) fue un **error de mi script**: codifiqué el OID de la extensión de emisor de Fulcio con un byte equivocado (`0x53` en vez de `0x30`). El certificado real era correcto (ver abajo). Sus bundles son los fixtures de `gateway/test/fixtures/evidence-checkpoint-lab/` |
| `40792835425` | `3b71641` | **ALL-AS-REQUIRED** (14 PASS) | Con el OID corregido y el verificador reforzado de #70. Ficheros en `run-40792835425/` |
| `40792835415` | `3b71641` | success | Segundo workflow (`sigstore-lab-other.yml`), firma los mismos bytes con otra identidad |

- Digest SHA-256 del checkpoint firmado: `6896338605effbe8abb01ba2f3f07482df9f40ead09c7b527ed8534f61d54f45` (idéntico en ambas ejecuciones: el fichero está versionado).
- Cosign: `v3.0.6` en los dos runners (el que firma y el que verifica, distintos). Además verificado en local con `v3.1.1` (macOS).
- Rekor (`hashedrekord`): logIndex `3552970264` (run 1) y `3553153190` (run 2), con prueba de inclusión y checkpoint firmado del log en el bundle.
- Certificado (Fulcio, emisor `O=sigstore.dev, CN=sigstore-intermediate`): SAN `URI:https://github.com/MacGuard/macguard-yara-channel/.github/workflows/sigstore-lab.yml@refs/heads/exp/sigstore-lab`; extensión `1.3.6.1.4.1.57264.1.1` = `https://token.actions.githubusercontent.com`; extensión del commit = el del laboratorio; **validez de solo 10 minutos**.

## Comprobaciones (run 40792835425, todas como se exigía)

| Comprobación | Resultado |
|---|---|
| C1 bytes: fichero del repo = firmado = descargado en otro runner = digest dentro del bundle | PASS |
| C2 certificado: SAN exacto, extensión de emisor, entrada Rekor con prueba de inclusión (leído del propio bundle, sin fiarse de cosign) | PASS |
| P1 verificación con identidad e emisor exactos | PASS (rc 0) |
| P2 la firma del *otro* workflow es genuina para *su* identidad (así los rechazos de abajo son por identidad, no por daño) | PASS (rc 0) |
| N1 checkpoint alterado (`count` 3→2) con la firma original | rechazado |
| N2 firma alterada (1 bit dentro del bundle) | rechazado |
| N3 identidad equivocada (el workflow de producción, que no firmó esto) | rechazado |
| N4 emisor no autorizado (`accounts.google.com`) | rechazado |
| N5 firma válida de los mismos bytes por **otro workflow**, verificada contra el autorizado | rechazado |
| N6a evidencia de transparencia ausente (`tlogEntries` vacío) | rechazado |
| N6b ausentes transparencia **y** sellos de tiempo | rechazado |
| N7 certificado de otro workflow insertado en el bundle | rechazado |
| N8 sin bundle (checkpoint sin firmar) | rechazado |
| N9 `head` falsificado con un bundle que no lo cubre | rechazado |

## Lo que esto prueba y lo que no

- **Prueba:** que `cosign` v3 emite y verifica bundles con la identidad del workflow y el emisor de Actions; que el verificador de #70 los exige exactos; que rechaza las 9 manipulaciones; que los bytes firmados y los verificados coinciden criptográficamente en runners distintos; que el bundle contiene una entrada de transparencia con prueba de inclusión.
- **La transparencia importa de verdad:** el certificado dura 10 minutos. Verificado **después** de caducar (00:18Z, certificado caducado a las 00:17:45Z): el verificador del producto con `cosign` real da **OK**; `cosign verify-blob --insecure-ignore-tlog=true` sobre el mismo bundle da **rc=1**. Sin transparencia, una firma keyless no es verificable pasado ese margen. El verificador del producto nunca pasa esa opción.
- **Cosign no es suficiente por sí solo (hallazgo):** la versión inicial de #70 delegaba todo en el código de salida de `cosign`. Se añadieron comprobaciones propias sobre el bundle (digest = SHA-256 del fichero, SAN exacto, emisor exacto en la extensión, entrada de transparencia con prueba de inclusión), cada una con prueba y mutación propias (`gateway/test/evidence_bundle_binding.test.js`, sobre estos bundles reales). No sustituyen a la firma: la comprueba cosign y su fallo es definitivo.
- **No prueba:** la identidad de **producción** (`evidence-checkpoint.yml@refs/heads/main`), que solo puede existir cuando ese workflow se ejecute desde `main` tras fusionar #70 (este laboratorio usó otra identidad y comprobó que la de producción se rechaza); ni la durabilidad de las copias externas del checkpoint; ni que la rama `evidence` real se escriba bien (no existe). Tampoco se ha consultado Rekor en línea de forma independiente: la verificación de inclusión es la que hace `cosign` (offline, con la raíz TUF) sobre la prueba incluida en el bundle.
- Los bundles y el checkpoint publicados aquí son públicos por diseño y sintéticos: solo contienen la identidad del workflow del repositorio, un commit y un log de laboratorio.

## Retirada
Rama `exp/sigstore-lab` y artefactos de los runs eliminados tras copiar aquí lo necesario; se conservan los registros de las ejecuciones en Actions (IDs de arriba).
