# MacGuard Installer Auditor

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [Firma y notarización](ES-Tech-CodeSigning)

## En 30 segundos

Installer Auditor (en el repositorio, la carpeta `DMGTrustAuditor/`) revisa un instalador o app descargado (`.dmg`, `.pkg`, `.app`) **antes de que lo abras**: mira su firma, su huella (hash), su origen y le pasa reglas YARA (listas de pistas de patrones sospechosos). Tiene tres formas de uso sobre un mismo núcleo: ventana (GUI), línea de comandos (`macguard-audit`) y explorador de terminal (TUI) {{ev:EV-EC-69}}.

Sus reglas vienen del YARA Channel y solo se instalan si pasan todas las verificaciones {{ev:EV-YC-09}}. Cuando no puede decidir dice **desconocido**, nunca "seguro". **No es un antivirus** ni una certificación de ausencia de malware. Estado: **desarrollo**, sin firmar ni notarizar {{ev:EV-EC-68}}.

## Un ejemplo cotidiano

Es como el inspector de una aduana que comprueba el sello del paquete, de dónde viene y lo compara con una lista de rasgos de paquetes problemáticos. Si el paquete no coincide con nada de la lista, no puede asegurar que sea inocuo: solo que no reconoció nada.

## Diagrama

{{diagram:installer-auditor-core}}

## Paso a paso

1. Eliges un archivo (GUI) o ejecutas `macguard-audit scan <ruta>`.
2. El núcleo comprueba firma, hash y estructura del paquete o bundle, y ejecuta heurísticas estáticas (no exhaustivas).
3. Si hay motor y reglas, `YARAEngine` compila y escanea con los ejecutables `yara` y `yarac`.
4. Cada hallazgo recibe un estado: `passed`, `warning`, `failed` o `unknown`. Códigos de salida: 0 (sin fallo confirmado, no es garantía), 2 (una comprobación falló), 3 (argumentos), 4 (falta evidencia o capacidad).
5. Aparte, `update-rules` descarga e instala reglas del canal (ver abajo).

{{diagram:client-update}}

## Cómo funciona por dentro

**Instalar reglas del canal** (`RuleInstaller.install`, `Core/RuleInstaller.swift`) {{ev:EV-EC-70}}:

- Problema: que nadie pueda colar reglas alteradas. Entrada: un origen del canal. Salida: reglas activas o nada.
- Orden de orígenes: primero GitHub Pages, después un espejo en Cloudflare Pages; solo un fallo de red pasa al siguiente, un fallo de verificación nunca {{ev:EV-EC-77}}.
- Descarga con topes de bytes, extracción segura (rechaza enlaces, rutas fuera de sitio y entradas ocultas; topes de 10 000 entradas, 160 MB expandidos, profundidad 16, 60 s), exige que el manifiesto del paquete sea idéntico al firmado, verifica, vuelve a calcular los hashes justo antes de activar y activa con dos renombrados con diario; conserva la versión anterior.
- `ChannelVerifier.verify` comprueba hashes y tamaños, la raíz Merkle de las reglas, la inclusión en el registro de transparencia, el punto de control y que no haya retroceso. Si no hay verificador Sigstore, **no instala nada**.

**Firma Sigstore** (`SigstoreVerifier`, ADR-0001) {{ev:EV-EC-71}}: usa el `cosign` oficial como ayudante (v3.1.1), solo si su SHA-256 coincide con el fijado en el código, con una raíz de confianza incluida y sin red. Exige la identidad del flujo `publish.yml` del repositorio del canal. Una raíz caducada hace fallar la verificación (falla cerrado). El ADR figura "accepted", con revisión humana pendiente.

**Motor YARA** (`YARAEngine`, `docs/ENGINE.md`) {{ev:EV-EC-72}}: **YARA 4.5.8 como ejecutables externos `yara` y `yarac`** (universales arm64 + x86_64, mínimo macOS 13), construidos desde fuente fijada. **YARA-X no se usa**: no aparece en el código del proyecto. Antes de usarlos comprueba hash contra el manifiesto, `codesign --verify --strict`, versión mínima 4.5.0, arquitectura y una regla canario. No hay alternativa por PATH ni Homebrew. Una regla por espacio de nombres; los ficheros que no compilan se nombran y se omiten. Límites actuales de escaneo: 25 000 000 bytes por fichero y 2 000 ficheros por pasada (`maxFileBytes`, `maxFiles`).

**Firma de los propios ejecutables** {{ev:EV-EC-73}}: los ayudantes `yara`/`yarac` se firman **ad hoc** con hardened runtime; la firma Developer ID y la notarización están pendientes de credenciales. Ver [Firma y notarización](ES-Tech-CodeSigning).

## Cómo comprobarlo tú

Con el repo público y Xcode: `cd DMGTrustAuditor/DMGTrustAuditor && xcodegen generate`, luego `xcodebuild -scheme macguard-audit build`; `macguard-audit rules-status` y `macguard-audit verify-rules`. Pruebas: `xcodebuild ... test` como en `.github/workflows/app-tests.yml`. Nada de esto se ejecutó para esta página.

## Pruebas

Recuento estático de `func test`: 105 funciones en 9 archivos (32 TrustAndInstaller, 21 YARAEngine, 11 ContentDetector, 9 AppBundle, 8 ChannelVerifier, 7 ChannelUpdate, 7 DesignSystem, 6 BoundedProcess, 4 Responsiveness) {{ev:EV-EC-74}}. La CI las ejecuta en un runner macOS; no se leyó ningún resultado guardado. `LiveChannelTests` instala desde el canal real con firmas reales, pero solo con `MACGUARD_LIVE=1` (en caso contrario se omite); es una prueba **funcional**.

### Prueba de rendimiento de extremo a extremo con el canal real: PLANIFICADA

**No existe.** Lo más cercano {{ev:EV-EC-75}} {{ev:EV-YC-10}}:

| Qué hay | Por qué no lo es |
|---|---|
| `scripts/macguard_smoke.py` (job `app-compat`, solo informe) | Copia las reglas directamente y escribe un manifiesto falso: **se salta la verificación del canal**; mide tiempos, no la instalación real |
| `scripts/bench.py` | Mide el motor YARA de referencia, no la app |
| `ResponsivenessTests` | Mide bloqueo del hilo de interfaz con reglas sintéticas, sin canal |

Cómo debería probarse: en un runner macOS limpio, con la app y el cosign fijado, instalar desde el canal publicado (`update-rules`) midiendo tiempos de descarga, verificación y activación; después escanear un corpus fijo midiendo tiempo, memoria y fallos, y comprobar que cada paso de verificación se ejecuta de verdad. Los umbrales los fijaría un humano tras medir; un tiempo no sería nunca criterio de PASS.

## Límites

- No es antivirus; "desconocido" no significa seguro; PKG solo se inspecciona parcialmente.
- Sin firma Developer ID ni notarización: Gatekeeper tratará una descarga como no notarizada {{ev:EV-EC-68}}.
- **Documentación obsoleta en la carpeta** {{ev:EV-EC-76}}: `README.md` ("source prototype", "no compilado en macOS", opción "ZIP sin firmar"), `README_V8.md` (actualizaciones desde una rama de GitHub con consentimiento) y `YARA_INTEGRATION.md` (actualizador "experimental", sin motor incluido, límite "40 reglas y 30 ficheros"). El código actual instala solo del canal firmado, incluye motor y tiene CI en macOS; sus límites vienen de `YARAEngine`. `SIGNING.md` sí sigue vigente (no firmado ni notarizado).
- Raíz de confianza de Sigstore: renovarla exige actualizar la app.

## Estado

| Capacidad | Estado |
|---|---|
| GUI, CLI y TUI sobre un núcleo; instalación verificada de reglas; motor YARA 4.5.8 | Implementado, no distribuido (sin build firmada ni tag de app) |
| Firma Developer ID y notarización de la app y ayudantes | Planificado (faltan credenciales) |
| Prueba de rendimiento de extremo a extremo con el canal real | Planificado |
| Verificador Sigstore nativo en Swift | Mencionado como posible; no planificado |

Versión del CLI: `macguard-audit` 0.2.0, esquema JSON 1 {{ev:EV-EC-69}}. Sin fechas.
