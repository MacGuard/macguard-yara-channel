# Tecnología: Sigstore

[Inicio](ES-Home) · [Límites](ES-YARA-Limits) · [Tecnología: YARA](ES-Tech-YARA) · [Tecnología: Merkle](ES-Tech-Merkle) · [Archivo histórico](ES-YARA-Archive)

## En 30 segundos

Sigstore firma archivos y deja un registro público de cada firma, que cualquiera puede consultar {{ev:EV-YC-73}}. Aquí permite comprobar qué flujo de trabajo automático (`publish.yml`) publicó un paquete de reglas. Prueba la identidad de ese flujo y que el archivo no cambió; no prueba quién escribió las reglas de terceros ni que sean seguras.

## Un ejemplo cotidiano

Es como un sello de lacre que solo existe un instante. Quien lo pide demuestra con un documento de identidad quién es (el token de identidad del flujo), recibe un sello válido unos minutos (el certificado de corta duración) y luego lo destruye. Cualquiera puede comprobar en un libro público (el registro de transparencia) que ese sello se usó y quién lo pidió. El sello dice qué oficina cerró el sobre y que no se abrió después; no dice quién escribió la carta ni si lo que cuenta es cierto.

{{diagram:sigstore-sequence-1-identity}}

{{diagram:sigstore-sequence-2-record}}

{{diagram:sigstore-sequence-3-verify}}

## Paso a paso

1. El flujo `publish.yml` pide a GitHub un token OIDC que nombra al propio flujo.
2. **Fulcio** (la autoridad de certificados) emite un certificado de corta duración que liga esa identidad a una clave efímera.
3. `cosign` firma el archivo y la firma se anota en **Rekor** (el registro de transparencia); todo se guarda en un `.sigstore.json` {{ev:EV-YC-73}}.
4. El cliente verifica el paquete contra la raíz de confianza de Sigstore y **comprueba identidad y emisor**.

## Cómo funciona por dentro

«Sin clave» (*keyless*) significa que nadie guarda una clave de firma de larga duración: el par de claves se descarta tras firmar y la verificación se apoya en el registro {{ev:EV-YC-73}}. En el proyecto, `publish.yml` firma con `cosign sign-blob --bundle` el punto de control del registro y `dist/manifest.json`; `scripts/tlog.py` (`cosign_verifier`) verifica con `cosign verify-blob --bundle`, exigiendo identidad del certificado, emisor OIDC y repositorio del flujo {{ev:EV-YC-69}} {{ev:EV-YC-03}}.

- **Detecta:** un archivo alterado tras firmar, o firmado por otra identidad.
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

La firma prueba la identidad verificable del flujo de trabajo que publica y la integridad del artefacto firmado, dentro del modelo de confianza de Sigstore. **No** prueba quién escribió las reglas de terceros ni que sean seguras, ni que el contenido sea bueno. Este repositorio no declara atestaciones SLSA ni atestaciones de GitHub. `manifest.evidence` es una declaración del flujo de publicación, no una atestación independiente {{ev:EV-YC-66}}.

## Estado

| Capacidad | Estado |
|---|---|
| Firma sin clave de checkpoints y manifiestos en cada release | publicado {{ev:EV-YC-03}} |
| Firma Sigstore del manifiesto del archivo histórico | planificado (el archivo no es operativo) {{ev:EV-YC-60}} |
