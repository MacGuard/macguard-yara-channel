# Cómo se enlazan las decisiones multifamilia con los paquetes modulares (2026-10-26)

**Principio:** *consultable* ≠ *aprobado* ≠ *publicado*. Que una familia tenga decenas de miles de registros en el panel no autoriza publicar ninguno. Hoy ninguna familia distinta de YARA tiene pipeline de publicación, y este cambio no la crea.

## Estados y quién los fija

| Estado efectivo | Quién lo fija | Significa |
|---|---|---|
| `RETENIDA` (importado) / `EXPIRED`, calidad `quarantined`/`approved` | la promoción (`intel_promote.py`) | existe y está verificado; nada decidido |
| `QUARANTINED`, `REJECTED`, `RETENIDA` (decidido) | una persona con `intel.decide` | decisión auditada y reversible |
| `APPROVED` | una persona con `intel.approve`, solo si la evidencia lo permite | aprobado para la **próxima** publicación; sigue sin estar publicado |
| `PUBLISHED` | **solo** la pipeline que firma un paquete | distribuido en un release firmado (no existe todavía para estas familias) |

## Contrato con la futura construcción de paquetes

`GET /api/pipeline/intel-approvals[?family=&source=]` (token OIDC de `publish.yml`; 403 para cualquier otro workflow). Devuelve:

- `eligible`: registros `APPROVED` cuya última decisión está **auditada**, sin `held_back` y cuya descarga es publicable y con licencia compatible. La evidencia se **reevalúa al leer**: si cambia, el registro pasa a `blocked` con su causa.
- `blocked`: aprobados que ya no cumplen, con la razón.
- `withdrawn_after_approval`: registros que estuvieron aprobados y ya no lo están; todo paquete que los contuviera debe revocarse.
- `packages`: una entrada por (familia, fuente) = un paquete independiente.

Leerlo **no publica nada**. Un paquete exige además, y por este orden: construcción reproducible por familia y fuente, *quality gates* de esa familia superados (los de Suricata y Sigma siguen `INCONCLUSIVE`/`NOT_RUN`), firma Sigstore propia, attestation que referencie `decision.id`, `request_id` y el hash de la entrada de auditoría, y publicación con revocación posible (lista de revocación firmada que consuma `withdrawn_after_approval` y los rechazos).

## Separación de funciones prevista

- Quien aprueba (`intel.approve`: REVIEWER, ADMIN) no es quien publica (PUBLISHER). Cuando exista el paso de publicación, la identidad que lo ejecute debe ser distinta de la que aprobó ese registro (comprobable: `decision.by_id`).
- ADMIN no se salta las puertas de calidad ni la licencia.

## Siguiente hito

1. Registry modular: un paquete por (familia, fuente) con metadatos tipo TUF y firma Sigstore por paquete; perfiles COMMUNITY / PROTECTION / INTELLIGENCE_FULL como conjuntos de paquetes.
2. Lista de revocación firmada que consuma este snapshot y la política de retiradas YARA.
3. Transparency log con pruebas de inclusión y consistencia y punto de control independiente (Observability V2); hasta entonces la cadena de auditoría es solo una cadena de hashes.
