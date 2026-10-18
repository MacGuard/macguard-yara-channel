---
title: Firmas con Sigstore
summary: Firma sin clave con la identidad del workflow, y qué se verifica exactamente.
---
## Cómo se firma

No hay clave privada guardada en ningún sitio. Durante `publish.yml`, `cosign sign-blob` pide a GitHub un token OIDC que nombra el workflow, Fulcio emite un certificado de corta duración ligado a esa identidad, la firma se registra en Rekor y todo se guarda en un bundle `.sigstore.json`.

{{diagram:sigstore-sequence}}

## Qué se firma y con qué identidad

| Artefacto | Bundle |
|---|---|
| `manifest.json` | `manifest.sigstore.json` |
| `checkpoint.txt` | `checkpoint.sigstore.json` |

- Identidad del certificado: `{{identity}}`.
- Emisor OIDC: `{{issuer}}`.
- Repositorio del workflow: `{{repo}}` (`--certificate-github-workflow-repository`).

El paquete `rules-release.tar.gz` **no** se firma por separado: está cubierto porque el manifiesto firmado contiene el SHA-256 de cada fichero y `rules_root`, y se comprueba que el paquete contiene exactamente esos ficheros.

## En MacGuard

La app incluye un `cosign` fijado ({{tool.cosign}}, con su SHA-256 comprobado) y una raíz de confianza `trusted_root.json` fijada; verifica sin red con `--trusted-root`. No existe una biblioteca Swift de Sigstore mantenida, por eso se usa cosign (ver `DMGTrustAuditor/DMGTrustAuditor/docs/ADR-0001-sigstore-verification.md`).

> **LÍMITE** **No hay atestaciones SLSA ni in-toto.** Solo se firman dos blobs con Sigstore. Eso prueba qué workflow firmó esos bytes; no prueba por sí solo que el proceso de construcción fuera el esperado más allá de la identidad del workflow.

> **PROPUESTA** Añadir atestaciones de procedencia (SLSA) sería un cambio de diseño; no está implementado ni planificado en este repositorio.
