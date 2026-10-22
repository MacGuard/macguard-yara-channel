# Tecnología: Sigstore

[Inicio](ES-Home) · [Límites](ES-YARA-Limits) · [Tecnología: YARA](ES-Tech-YARA) · [Tecnología: Merkle](ES-Tech-Merkle) · [Archivo histórico](ES-YARA-Archive)

## En 30 segundos

Sigstore es un proyecto abierto para firmar ficheros (releases, binarios, imágenes) y para que cualquiera pueda verificar la firma; los eventos de firma quedan en un registro público auditable {{ev:EV-YC-73}}. Aquí sirve para comprobar que un paquete de reglas lo firmó el flujo de trabajo `publish.yml` y no otro.

## Un ejemplo cotidiano

Es como un sello de lacre que solo existe un instante: quien lo usa demuestra con un documento de identidad quién es, recibe un sello válido unos minutos y luego lo destruye. Más tarde, cualquiera puede comprobar en un libro público que ese sello se usó y quién lo pidió. No dice si lo firmado es bueno.

{{diagram:sigstore-sequence}}

## Paso a paso

1. El flujo `publish.yml` pide a GitHub un token OIDC que nombra al propio flujo.
2. **Fulcio** (la autoridad de certificados) emite un certificado de corta duración que liga esa identidad a una clave efímera.
3. `cosign` firma el fichero y la firma se anota en **Rekor** (el registro de transparencia); todo se guarda en un `.sigstore.json` {{ev:EV-YC-73}}.
4. El cliente verifica el paquete contra la raíz de confianza de Sigstore y **comprueba identidad y emisor**.

## Cómo funciona por dentro

«Sin clave» (*keyless*) significa que nadie guarda una clave de firma de larga duración: el par de claves se descarta tras firmar y la verificación se apoya en el registro {{ev:EV-YC-73}}. En el proyecto, `publish.yml` firma con `cosign sign-blob --bundle` el punto de control del registro y `dist/manifest.json`; `scripts/tlog.py` (`cosign_verifier`) verifica con `cosign verify-blob --bundle`, exigiendo identidad del certificado, emisor OIDC y repositorio del flujo {{ev:EV-YC-69}} {{ev:EV-YC-03}}.

- **Detecta:** un fichero alterado tras firmar, o firmado por otra identidad.
- **No previene:** que el propio flujo de publicación, si estuviera comprometido, firme contenido malo con una firma válida.
- **Coste:** una llamada de red a los servicios de Sigstore al firmar; verificación local con el paquete.

## Quién más lo usa

Ninguna fila implica que estas organizaciones usen MacGuard.

| Quién | Clasificación | Fuente |
|---|---|---|
| Kubernetes: su proceso de release firma binarios (tarballs, SPDX, binarios) con la firma sin clave de cosign | usa la misma tecnología | {{ev:EV-YC-75}} |
| npm: los paquetes publicados con procedencia se firman con los servidores públicos de Sigstore y se registran en un libro público | usa la misma tecnología | {{ev:EV-YC-74}} |

## Cómo comprobarlo tú

```
python3 -m unittest tests.test_seal_evidence tests.test_verify_public_release
python3 scripts/tlog.py verify --identity "<ref del flujo publish>" --repo MacGuard/macguard-yara-channel
```

La segunda orden necesita `cosign` instalado y la identidad exacta del flujo.

## Límites

La firma prueba origen e integridad, no calidad de las reglas. `manifest.evidence` es una declaración del flujo de publicación, no una atestación independiente {{ev:EV-YC-66}}. El verificador del navegador se sirve desde el mismo origen que el paquete (RR-07).

## Estado

| Capacidad | Estado |
|---|---|
| Firma sin clave de checkpoints y manifiestos en cada release | operativo {{ev:EV-YC-03}} |
| Firma Sigstore del manifiesto del archivo histórico | planificado (el archivo no es operativo) {{ev:EV-YC-60}} |
