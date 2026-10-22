# mgctl: the MacGuard command / el comando de MacGuard

**English first, español después.** Both halves say the same.

---

## English

`mgctl` is the canonical command of the MacGuard suite. It is a **front end**: it parses arguments and delegates every security check to the engines that already exist. It re-implements none of them, and it never prints a success it did not obtain.

### What is real today

| Command | Status | Engine it delegates to |
|---|---|---|
| `mgctl version`, `help`, `doctor` | implemented | mgctl itself (reads the engines' versions) |
| `mgctl scan PATH` | implemented (macOS) | `macguard-audit scan` |
| `mgctl audit file PATH` | **experimental**: 3 of 5 checks | `hash`: mgctl (SHA-256 + SHA-512). `integrity` and `yara`: `macguard-audit scan` (macOS). `provenance`, `vulns`: **no engine yet** (reported `not_implemented`) |
| `mgctl audit --tui` | implemented (macOS, needs a terminal) | `macguard-audit tui` |
| `mgctl evidence verify` | implemented | `scripts/verify_public_release.py` + `cosign` |
| `mgctl intelligence status / update / verify` | implemented (macOS) | `macguard-audit rules-status / update-rules / verify-rules` |
| `mgctl intelligence vulns sources / lookup / assess` | **experimental** | `python3 -m intel vulns sources / lookup / assess`: vulnerability sources of the US, the EU and Spain; per-source exploitation; a Linux package is judged only from the distribution's own data (`NOT_ASSESSED` otherwise, exit 4). Nothing is published. See `docs/intelligence/EU-VULNERABILITIES.md` |
| `mgctl alias status / enable / disable` | implemented | mgctl itself (optional `mg` alias) |
| `mgctl provenance file PATH` | **experimental** | `python3 -m intel provenance file` (package `intel/provenance/`): read-only and offline. Six separate facts (origin, installation, ownership, integrity, confidence, detection) with evidence, absences and limits, as a document that follows `docs/intelligence/schemas/file-provenance.schema.json`. Collectors: Homebrew formula, Homebrew cask, macOS pkgutil/quarantine/code signature/Gatekeeper, pip, APT/dpkg (tested on recorded fixtures only: no Linux host yet), and hash-only for unowned files. `--redact` drops download URLs and quarantine details; `--follow-symlinks` records both paths; with the global `--output DIR` the document is also saved to `DIR/provenance.json` (never overwritten) |
| `inventory`, `provenance --all` (the host-wide scan), `audit system`, `baseline create/verify/diff`, `attest verify`, `report`, `agent status`, `cloud status` | **planned** | none. They exit with code 4 and say so. |

"Planned" is a promise about direction, not a feature: nothing runs and nothing is reported as passed. `mgctl --help` marks them with `x`.

The YARA engine bundled with the Installer Auditor today is classic **YARA 4.5.x**, not YARA-X. The reports name the engine they really used.

### Global options (same meaning everywhere)

`--json` one JSON document on stdout (messages go to stderr) · `--quiet` · `--verbose` · `--no-color` (also `NO_COLOR`, and output that is not a terminal) · `--offline` · `--non-interactive` · `--timeout SECONDS` (default 300, max 3600) · `--max-workers N` (1 to 8, default 2) · `--output DIR` (created with mode 0700, never overwritten) · `--lang en|es` (or `MGCTL_LANG`, `LC_ALL`, `LANG`). `--` ends the options: everything after it is data.

### Exit codes

`0` no confirmed failure (this is **not** a safety guarantee) · `2` a check failed · `3` bad arguments or path · `4` evidence or capability unavailable, planned command, or **partial** result · `130` cancelled by the user.

### Deep audit of a file

```bash
mgctl audit file /usr/local/bin/custom-agent \
  --checks hash,integrity,yara,provenance,vulns \
  --format json \
  --output ./custom-agent-audit/
```

The report (`report.json`, `report.txt`, schema `mgctl.audit-file/1`) has one entry per requested check with a status: `passed`, `warning`, `failed`, `unknown`, `unavailable` (the engine is missing or not ready), `not_implemented` or `not_applicable`. `complete` is true only if every requested check really ran. Today the full five-check request therefore ends with `complete: false` and exit code 4, because provenance and vulnerabilities have no engine. That is deliberate.

Safety rules: only regular files (and bundles/folders for the engine checks); symbolic links are refused unless `--follow-symlinks` (both paths are recorded); paths reach engines as absolute paths and never through a shell; the file is `stat`-ed before and after and its SHA-256 is cross-checked with the engine's, and a file that changed during the analysis makes the result partial; Ctrl-C stops the engine processes mgctl started, writes a report with `status: cancelled`, `complete: false`, and exits 130.

### The interactive explorer (TUI)

`mgctl audit --tui` hands the terminal to the Installer Auditor's explorer (the same engine and the same results as `scan`). It opens only when stdin and stdout are terminals and `--non-interactive` is absent: never from cron, systemd, CI or a pipe (then it exits 4). In the explorer you navigate folders, select an item, read the findings and evidence, and quit with the on-screen key. Export a report from the command line with `mgctl audit file ... --output DIR`. The explorer has no export of its own today.

### Automation examples

```bash
# fail the pipeline when a check fails; treat "unavailable/partial" (4) as a separate decision
mgctl audit file ./build/tool --checks hash,integrity --json --output ./audit || test $? -eq 4

# verify the published rule channel without trusting this machine's installed copy
mgctl evidence verify --latest --json

# offline: verify a folder you downloaded earlier
mgctl evidence verify --directory ./release --offline
```

### Compatibility and deprecation

Nothing was renamed or removed. `macguard-audit` keeps working exactly as before (same commands, JSON schema 1 and exit codes); `mgctl` calls it. Policy: an old command is never removed without (1) an entry in this document, (2) a warning printed for at least two releases, and (3) a release note. JSON documents follow the rule "new fields may be added; existing fields are not renamed or removed without bumping `schemaVersion`". The command tree itself is versioned (`contract`, printed by `mgctl version`) and pinned by a test.

| Old | New | Note |
|---|---|---|
| `macguard-audit scan X` | `mgctl scan X` | same engine and output |
| `macguard-audit update-rules` / `verify-rules` / `rules-status` | `mgctl intelligence update` / `verify` / `status` | |
| `macguard-audit tui` | `mgctl audit --tui` | |
| `python3 scripts/verify_public_release.py` | `mgctl evidence verify` | exit codes are mapped, see below |

`mgctl evidence verify` maps the verifier's codes: 0 → 0; 1 integrity, 2 signature or identity, 3 Merkle → **2**; 4 download, 5 missing dependency, 6 invalid format → **4**. The original code is in the JSON (`verifierExitCode`). A pass proves the publisher's identity and the integrity of the files, not who wrote the third-party rules.

### The optional `mg` alias

`mg` belongs to other software: the *mg* editor ships with macOS, Debian and Homebrew. Therefore:

* installing mgctl **never** creates `mg`;
* `mgctl alias enable [--dir DIR]` creates a symbolic link only on request, in a directory you own (default `~/.local/bin`), only if **no** `mg` exists anywhere on `PATH`, and never overwrites anything; with `--force-conflict` it creates it anyway but warns that the other `mg` keeps priority;
* mgctl never edits `PATH` and never touches files owned by APT, DNF or Homebrew;
* `mgctl alias status` shows what exists; `mgctl alias disable` removes the link, and only if it points to mgctl.

### Architecture

```text
mgctl (parser, help, exit codes)         <- no security logic
 ├─ commands.py   thin handlers
 ├─ services/     audit file orchestration, hashing, alias
 └─ backends.py   locate and call engines (argument lists, no shell, timeouts, cancellable)
        ├─ macguard-audit            Installer Auditor engine and TUI (Swift, macOS)
        └─ verify_public_release.py  independent release verifier (Python)
```

The CLI and the TUI use the same engine, so they produce compatible results. Planned engines (inventory, baselines, attestations, agent, cloud) will plug into `backends.py` and the command tree; the tree is data (`mgctl/tree.py`), so help, the command table above and the snapshot test all come from one place.

### Versioned contracts for MacGuard Cloud (design only)

Every JSON document carries `schemaVersion` and, for reports, a `schema` id (`mgctl.audit-file/1`). A future Cloud integration would consume exactly these documents. **Nothing is sent anywhere**: mgctl has no telemetry and no network code of its own (a test enforces it); the engines it calls may use the network (`intelligence update`, `evidence verify --latest`) and `--offline` forbids that. `mgctl cloud status` is planned and does not exist yet.

### Security properties

Strict argument and path validation (NUL bytes, length, symlinks, special files); no shell and no string interpolation; no privileges (never asks for root); limits on time and parallelism; partial results are labelled; signatures and manifests of rule packages are verified by the engine before it consumes them (`intelligence verify`, `evidence verify`); no secrets are printed.

### Admin notes

Install without root under a prefix you own (see `mgctl-install.md`). Point `MGCTL_AUDIT_BIN` at a specific `macguard-audit` (otherwise it is searched next to `mgctl`, then on `PATH`) and `MGCTL_VERIFIER` at a specific verifier. `mgctl doctor` shows what it found and exits 4 on macOS when the engine is missing.

---

## Español

`mgctl` es el comando canónico de la suite MacGuard. Es un **front end**: interpreta argumentos y delega cada comprobación de seguridad en los motores que ya existen. No reimplementa ninguno y nunca imprime un éxito que no obtuvo.

### Qué es real hoy

| Comando | Estado | Motor en el que delega |
|---|---|---|
| `mgctl version`, `help`, `doctor` | implementado | el propio mgctl |
| `mgctl scan RUTA` | implementado (macOS) | `macguard-audit scan` |
| `mgctl audit file RUTA` | **experimental**: 3 de 5 comprobaciones | `hash`: mgctl (SHA-256 + SHA-512). `integrity` y `yara`: `macguard-audit scan` (macOS). `provenance`, `vulns`: **aún sin motor** (se informan `not_implemented`) |
| `mgctl audit --tui` | implementado (macOS, requiere terminal) | `macguard-audit tui` |
| `mgctl evidence verify` | implementado | `scripts/verify_public_release.py` + `cosign` |
| `mgctl intelligence status / update / verify` | implementado (macOS) | `macguard-audit rules-status / update-rules / verify-rules` |
| `mgctl intelligence vulns sources / lookup / assess` | **experimental** | `python3 -m intel vulns sources / lookup / assess`: fuentes de vulnerabilidades de EE. UU., la UE y España; explotación por fuente; un paquete de Linux se juzga solo con los datos de su distribución (`NOT_ASSESSED` si no, código 4). No se publica nada. Ver `docs/intelligence/EU-VULNERABILITIES.md` |
| `mgctl alias status / enable / disable` | implementado | el propio mgctl (alias opcional `mg`) |
| `mgctl provenance file RUTA` | **experimental** | `python3 -m intel provenance file` (paquete `intel/provenance/`): solo lectura y sin red. Seis hechos separados (origen, instalación, propiedad, integridad, confianza, detección) con evidencias, ausencias y límites, en un documento conforme a `docs/intelligence/schemas/file-provenance.schema.json`. Recolectores: fórmula de Homebrew, cask de Homebrew, pkgutil/cuarentena/firma de código/Gatekeeper de macOS, pip, APT/dpkg (probado solo con grabaciones: aún no hay equipo Linux) y solo hash para archivos sin propietario. `--redact` quita las URL de descarga y los detalles de cuarentena; `--follow-symlinks` registra ambas rutas; con la opción global `--output DIR` el documento también se guarda en `DIR/provenance.json` (nunca se sobrescribe) |
| `inventory`, `provenance --all` (el escaneo de todo el equipo), `audit system`, `baseline create/verify/diff`, `attest verify`, `report`, `agent status`, `cloud status` | **planificado** | ninguno. Terminan con código 4 y lo dicen. |

«Planificado» es una dirección, no una función: no se ejecuta nada y no se informa de nada como superado. `mgctl --help` los marca con `x`.

El motor YARA incluido hoy con el Installer Auditor es **YARA 4.5.x** clásico, no YARA-X. Los informes nombran el motor realmente usado.

### Opciones globales (mismo significado en todos los comandos)

`--json` un documento JSON por stdout (los mensajes van a stderr) · `--quiet` · `--verbose` · `--no-color` (también `NO_COLOR` y la salida que no es un terminal) · `--offline` · `--non-interactive` · `--timeout SEGUNDOS` (300 por defecto, máx. 3600) · `--max-workers N` (1 a 8, 2 por defecto) · `--output DIR` (se crea con modo 0700, nunca se sobrescribe) · `--lang en|es` (o `MGCTL_LANG`, `LC_ALL`, `LANG`). `--` termina las opciones: lo que sigue son datos.

### Códigos de salida

`0` ningún fallo confirmado (**no** es una garantía de seguridad) · `2` una comprobación falló · `3` argumentos o ruta no válidos · `4` evidencia o capacidad no disponible, comando planificado o resultado **parcial** · `130` cancelado por la persona usuaria.

### Auditoría profunda de un archivo

El comando y el informe son los del apartado en inglés. Cada comprobación pedida tiene un estado: `passed`, `warning`, `failed`, `unknown`, `unavailable` (el motor falta o no está listo), `not_implemented` o `not_applicable`. `complete` es verdadero solo si todas las comprobaciones pedidas se ejecutaron de verdad. Hoy, pedir las cinco termina con `complete: false` y código 4, porque procedencia y vulnerabilidades no tienen motor. Es deliberado.

Reglas de seguridad: solo archivos normales (y paquetes/carpetas para las comprobaciones del motor); los enlaces simbólicos se rechazan salvo `--follow-symlinks` (se registran ambas rutas); las rutas llegan a los motores como rutas absolutas y nunca por un shell; el archivo se consulta con `stat` antes y después, su SHA-256 se contrasta con el del motor y un archivo que cambia durante el análisis deja el resultado parcial; Ctrl-C detiene los procesos de motor que mgctl lanzó, escribe un informe con `status: cancelled`, `complete: false` y sale con 130.

### El explorador interactivo (TUI)

`mgctl audit --tui` cede el terminal al explorador del Installer Auditor (el mismo motor y los mismos resultados que `scan`). Solo se abre si stdin y stdout son terminales y no hay `--non-interactive`: nunca desde cron, systemd, CI o una tubería (entonces sale con 4). En el explorador se navega por carpetas, se selecciona un elemento, se leen hallazgos y evidencias y se sale con la tecla indicada en pantalla. Para exportar, usa `mgctl audit file ... --output DIR`; el explorador no exporta por sí mismo hoy.

### Compatibilidad y deprecación

No se ha renombrado ni retirado nada. `macguard-audit` funciona exactamente como antes (mismos comandos, JSON esquema 1 y códigos de salida); `mgctl` lo llama. Política: un comando antiguo no se retira sin (1) constar en este documento, (2) mostrar un aviso durante al menos dos releases y (3) una nota de versión. Los documentos JSON siguen la regla «se pueden añadir campos; los existentes no se renombran ni se eliminan sin subir `schemaVersion`». El propio árbol de comandos está versionado (`contract`, que muestra `mgctl version`) y fijado por una prueba. La tabla de equivalencias está en la sección inglesa.

### El alias opcional `mg`

`mg` pertenece a otro software: el editor *mg* viene con macOS, Debian y Homebrew. Por eso: instalar mgctl **nunca** crea `mg`; `mgctl alias enable [--dir DIR]` crea un enlace simbólico solo si lo pides, en un directorio tuyo (por defecto `~/.local/bin`), solo si **no** existe ningún `mg` en el `PATH` y sin sobrescribir nada; con `--force-conflict` lo crea igualmente pero avisa de que el otro `mg` conserva la prioridad; mgctl nunca edita el `PATH` ni toca archivos de APT, DNF o Homebrew; `mgctl alias status` muestra lo que existe y `mgctl alias disable` retira el enlace, solo si apunta a mgctl.

### Arquitectura, contratos con MacGuard Cloud y seguridad

Ver el apartado inglés: el parser no contiene lógica de seguridad; los comandos son manejadores finos; los servicios orquestan; `backends.py` localiza y llama a los motores (listas de argumentos, sin shell, con plazo y cancelables). Cada documento JSON lleva `schemaVersion` y, los informes, un identificador `schema` (`mgctl.audit-file/1`); una futura integración con Cloud consumiría exactamente esos documentos. **No se envía nada a ningún sitio**: mgctl no tiene telemetría ni código de red propio (una prueba lo exige); los motores que llama pueden usar la red (`intelligence update`, `evidence verify --latest`) y `--offline` lo prohíbe. `mgctl cloud status` es una función planificada que aún no existe.
