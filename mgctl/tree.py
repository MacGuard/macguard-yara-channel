"""The command tree: the single source of truth for parsing, help (ES/EN) and the implemented/experimental/planned table.

status: implemented  = delegates to a real, tested engine
        experimental = real but covers only part of the contract (the help says which part)
        planned      = no engine exists yet; the command refuses with exit code 4 and never simulates success
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

EXIT_CODES = [
    (0, {"en": "no confirmed failure (this is NOT a safety guarantee)", "es": "ningún fallo confirmado (NO es una garantía de seguridad)"}),
    (2, {"en": "a check failed", "es": "una comprobación falló"}),
    (3, {"en": "bad arguments or path", "es": "argumentos o ruta no válidos"}),
    (4, {"en": "evidence or capability unavailable, planned command, or partial result", "es": "evidencia o capacidad no disponible, comando planificado o resultado parcial"}),
    (130, {"en": "cancelled by the user (nothing is reported as complete)", "es": "cancelado por la persona usuaria (nada se informa como completo)"}),
]


@dataclass
class Opt:
    flags: Tuple[str, ...]
    help: Dict[str, str]
    metavar: Optional[str] = None      # None = boolean flag
    default: Optional[str] = None
    choices: Optional[Tuple[str, ...]] = None


@dataclass
class Cmd:
    path: Tuple[str, ...]
    status: str
    summary: Dict[str, str]
    handler: Optional[str] = None      # name of the function in mgctl.commands; None for pure groups
    positionals: List[Tuple[str, bool, Dict[str, str]]] = field(default_factory=list)   # (name, required, help)
    options: List[Opt] = field(default_factory=list)
    examples: List[Tuple[str, Dict[str, str]]] = field(default_factory=list)
    related: List[str] = field(default_factory=list)
    detail: Dict[str, str] = field(default_factory=dict)
    needs: Dict[str, str] = field(default_factory=dict)


def _o(flags, en, es, metavar=None, default=None, choices=None):
    return Opt(tuple(flags.split()), {"en": en, "es": es}, metavar, default, choices)


GLOBAL_OPTS = [
    _o("--json", "Print one JSON document on standard output (messages go to standard error).", "Imprime un único documento JSON por la salida estándar (los mensajes van al error estándar)."),
    _o("--quiet -q", "Print only what is needed; errors still go to standard error.", "Imprime solo lo imprescindible; los errores siguen en el error estándar."),
    _o("--verbose -v", "Explain which engine is called and with which arguments.", "Explica qué motor se llama y con qué argumentos."),
    _o("--no-color", "Never use colour or ANSI sequences (also honoured: NO_COLOR, and output that is not a terminal).", "No usa nunca color ni secuencias ANSI (también se respeta NO_COLOR y la salida que no es un terminal)."),
    _o("--offline", "Never use the network; commands that need it stop with exit code 4.", "No usa nunca la red; los comandos que la necesitan terminan con el código 4."),
    _o("--non-interactive", "Never ask questions or open a full-screen interface.", "No hace preguntas ni abre interfaces de pantalla completa."),
    _o("--timeout", "Seconds allowed for each engine call (default 300, maximum 3600).", "Segundos permitidos para cada llamada a un motor (por defecto 300, máximo 3600).", "SECONDS", "300"),
    _o("--max-workers", "Parallel jobs where a command has independent checks (1 to 8, default 2).", "Trabajos en paralelo cuando un comando tiene comprobaciones independientes (1 a 8, por defecto 2).", "N", "2"),
    _o("--output -o", "Directory where a command writes its report files (created if absent, never overwritten).", "Directorio donde un comando escribe sus informes (se crea si no existe, nunca se sobrescribe).", "DIR"),
    _o("--lang", "Help and messages language: en or es (default: from MGCTL_LANG, LC_ALL or LANG).", "Idioma de la ayuda y los mensajes: en o es (por defecto: MGCTL_LANG, LC_ALL o LANG).", "en|es", None, ("en", "es")),
]

_PLANNED_NOTE = {"en": "PLANNED: no engine exists for this command yet. It exits with code 4 and never reports success.",
                 "es": "PLANIFICADO: todavía no existe un motor para este comando. Termina con el código 4 y nunca informa de éxito."}

def _planned(path, en, es, **kw):
    return Cmd(tuple(path.split()), "planned", {"en": en, "es": es}, "planned", detail=_PLANNED_NOTE, **kw)


COMMANDS: List[Cmd] = [
    Cmd(("version",), "implemented", {"en": "Print the mgctl version, the contract version and the engines found.", "es": "Muestra la versión de mgctl, la del contrato y los motores encontrados."}, "version",
        examples=[("mgctl version", {"en": "Human-readable.", "es": "Legible."}), ("mgctl version --json", {"en": "Machine-readable.", "es": "Para máquinas."})]),
    Cmd(("help",), "implemented", {"en": "Show help for a command, for example: mgctl help audit file.", "es": "Muestra la ayuda de un comando, por ejemplo: mgctl help audit file."}, "help",
        positionals=[("command", False, {"en": "Command words to explain.", "es": "Palabras del comando a explicar."})]),
    Cmd(("doctor",), "implemented", {"en": "Check this machine: Python, engines, name conflicts for the optional alias, terminal.", "es": "Revisa esta máquina: Python, motores, conflictos de nombre del alias opcional, terminal."}, "doctor",
        examples=[("mgctl doctor", {"en": "Never changes anything.", "es": "No cambia nada."})], related=["version", "alias status"]),
    Cmd(("scan",), "implemented", {"en": "Audit one installer, application or file with the Installer Auditor engine (macOS).", "es": "Audita un instalador, aplicación o archivo con el motor del Installer Auditor (macOS)."}, "scan",
        positionals=[("path", True, {"en": "File or bundle to audit. It is never executed.", "es": "Archivo o paquete a auditar. Nunca se ejecuta."})],
        options=[_o("--format", "text (default) or json.", "text (por defecto) o json.", "text|json", "text", ("text", "json")),
                 _o("--recursive", "When PATH is a folder, audit the recognised items inside it.", "Si PATH es una carpeta, audita los elementos reconocidos que contiene."),
                 _o("--follow-symlinks", "Audit the target of a symbolic link (links are refused by default).", "Audita el destino de un enlace simbólico (por defecto se rechazan).")],
        examples=[("mgctl scan ~/Downloads/App.dmg", {"en": "Audit a disk image.", "es": "Audita una imagen de disco."}), ("mgctl scan App.pkg --json", {"en": "JSON for a pipeline.", "es": "JSON para un pipeline."})],
        related=["audit file", "intelligence status"], needs={"en": "macOS and the macguard-audit engine (set MGCTL_AUDIT_BIN or put it on PATH).", "es": "macOS y el motor macguard-audit (MGCTL_AUDIT_BIN o en el PATH)."},
        detail={"en": "Exit code 2 when a check failed. No finding means 'nothing confirmed', never 'safe'.", "es": "Código 2 si una comprobación falló. Sin hallazgos significa 'nada confirmado', nunca 'seguro'."}),
    _planned("inventory", "List what is installed on this system.", "Lista lo instalado en este sistema.", options=[_o("--all", "Everything the future engine can see.", "Todo lo que el futuro motor pueda ver.")]),
    Cmd(("provenance",), "planned", {"en": "Investigate where files and packages come from (one file today; the host-wide scan is planned).", "es": "Investiga el origen de archivos y paquetes (un archivo hoy; el escaneo de todo el equipo está planificado)."}, "planned",
        options=[_o("--all", "All installed items (PLANNED: exits with code 4).", "Todos los elementos instalados (PLANIFICADO: termina con el código 4).")],
        detail={"en": "'mgctl provenance file PATH' is experimental and works today. 'mgctl provenance --all' (the host-wide scan) is PLANNED: no engine exists for it, it exits with code 4 and never reports success.",
                "es": "'mgctl provenance file RUTA' es experimental y funciona hoy. 'mgctl provenance --all' (el escaneo de todo el equipo) está PLANIFICADO: no existe motor, termina con el código 4 y nunca informa de éxito."}),
    Cmd(("provenance", "file"), "experimental", {"en": "Where did this file come from? Six separate facts (origin, installation, ownership, integrity, confidence, detection) with the evidence behind each.", "es": "¿De dónde viene este archivo? Seis hechos separados (origen, instalación, propiedad, integridad, confianza, detección) con la evidencia de cada uno."}, "provenance_file",
        positionals=[("path", True, {"en": "File (or .app bundle) to investigate. It is read, never executed. Symbolic links are refused unless --follow-symlinks.", "es": "Archivo (o paquete .app) a investigar. Se lee, nunca se ejecuta. Los enlaces simbólicos se rechazan salvo --follow-symlinks."})],
        options=[_o("--redact", "Drop download URLs, the quarantine agent/time and command lines from the output (query strings are always removed).", "Quita las URL de descarga, el agente/hora de cuarentena y las líneas de comandos de la salida (las cadenas de consulta siempre se quitan).",),
                 _o("--follow-symlinks", "Investigate the target of a symbolic link (both paths are recorded).", "Investiga el destino de un enlace simbólico (se registran ambas rutas).")],
        examples=[("mgctl provenance file /usr/local/Cellar/jq/1.8.2/bin/jq", {"en": "Homebrew formula: ownership from the receipt, integrity UNKNOWN or partial (Homebrew keeps no per-file hash).", "es": "Fórmula de Homebrew: propiedad según el recibo, integridad desconocida o parcial (Homebrew no guarda hash por archivo)."}),
                  ("mgctl provenance file ./tool --json --output ./prov/", {"en": "Schema document in JSON; also written to ./prov/provenance.json (never overwritten).", "es": "Documento del esquema en JSON; también se escribe en ./prov/provenance.json (nunca se sobrescribe)."})],
        related=["audit file", "scan"],
        needs={"en": "Python 3.9+ and the intel package. Offline: it never uses the network. macOS and Linux (the dpkg collector is tested on recorded fixtures only).", "es": "Python 3.9+ y el paquete intel. Sin red: nunca la usa. macOS y Linux (el recolector dpkg solo se ha probado con grabaciones)."},
        detail={"en": "UNKNOWN is a result, never 'safe'. A hash alone is not integrity (it needs a reference). A path (for example a Cellar directory) is not evidence of origin. Exit 0 means a document was produced, even if everything is UNKNOWN; exit 3 bad path; exit 4 unsupported OS.",
                "es": "UNKNOWN es un resultado, nunca 'seguro'. Un hash solo no es integridad (hace falta una referencia). Una ruta (por ejemplo un directorio Cellar) no es evidencia de origen. Código 0 significa que se produjo un documento, aunque todo sea UNKNOWN; 3 ruta no válida; 4 sistema no compatible."}),
    Cmd(("audit",), "implemented", {"en": "Audits: one file, the whole system (planned), or the full-screen explorer.", "es": "Auditorías: un archivo, el sistema completo (planificado) o el explorador de pantalla completa."}, "audit_group",
        options=[_o("--tui", "Open the interactive explorer (needs a terminal, never opens by itself).", "Abre el explorador interactivo (requiere terminal, nunca se abre solo).")],
        examples=[("mgctl audit --tui", {"en": "Interactive explorer.", "es": "Explorador interactivo."})], related=["audit file", "audit system"]),
    Cmd(("audit", "file"), "experimental", {"en": "Deep audit of one file: hashes, integrity, YARA, provenance, vulnerabilities (3 of 5 checks exist today).", "es": "Auditoría profunda de un archivo: hashes, integridad, YARA, procedencia, vulnerabilidades (hoy existen 3 de 5)."}, "audit_file",
        positionals=[("path", True, {"en": "File to audit. Symbolic links are refused unless --follow-symlinks.", "es": "Archivo a auditar. Los enlaces simbólicos se rechazan salvo --follow-symlinks."})],
        options=[_o("--checks", "Comma list from hash,integrity,yara,provenance,vulns (default: all five).", "Lista separada por comas de hash,integrity,yara,provenance,vulns (por defecto: las cinco).", "LIST", "hash,integrity,yara,provenance,vulns"),
                 _o("--format", "text (default) or json (same as --json).", "text (por defecto) o json (igual que --json).", "text|json", "text", ("text", "json")),
                 _o("--follow-symlinks", "Audit the target of a symbolic link (both paths are recorded).", "Audita el destino de un enlace simbólico (se registran ambas rutas).")],
        examples=[("mgctl audit file /usr/local/bin/custom-agent --checks hash,integrity,yara,provenance,vulns --format json --output ./custom-agent-audit/", {"en": "The full contract; provenance and vulns report not_implemented.", "es": "El contrato completo; provenance y vulns informan not_implemented."}),
                  ("mgctl audit file ./tool --checks hash", {"en": "Only SHA-256 and SHA-512.", "es": "Solo SHA-256 y SHA-512."})],
        related=["scan", "intelligence verify"],
        needs={"en": "hash works everywhere. integrity and yara need macOS and macguard-audit. provenance and vulns have no engine yet: they are reported as not_implemented, never as passed.", "es": "hash funciona en todas partes. integrity y yara necesitan macOS y macguard-audit. provenance y vulns aún no tienen motor: se informan como not_implemented, nunca como superadas."},
        detail={"en": "The YARA engine bundled today is classic YARA, not YARA-X; the report names the engine it really used. If the file changes while it is analysed the result is marked partial. Ctrl-C writes a report with complete=false.",
                "es": "El motor YARA incluido hoy es YARA clásico, no YARA-X; el informe indica el motor realmente usado. Si el archivo cambia durante el análisis el resultado se marca parcial. Ctrl-C escribe un informe con complete=false."}),
    _planned("audit system", "Audit the whole system.", "Audita el sistema completo.", options=[_o("--full", "Every available check.", "Todas las comprobaciones disponibles.")]),
    Cmd(("baseline",), "planned", {"en": "System baselines.", "es": "Líneas base del sistema."}, "group"),
    _planned("baseline create", "Record a baseline of the system.", "Registra una línea base del sistema."),
    _planned("baseline verify", "Verify the system against a baseline.", "Verifica el sistema contra una línea base."),
    _planned("baseline diff", "Show differences against a baseline.", "Muestra diferencias frente a una línea base."),
    Cmd(("evidence",), "implemented", {"en": "Evidence of published releases.", "es": "Evidencia de las releases publicadas."}, "group"),
    Cmd(("evidence", "verify"), "implemented", {"en": "Independently verify a public YARA release (signatures, hashes, Merkle proofs).", "es": "Verifica de forma independiente una release pública de YARA (firmas, hashes, pruebas Merkle)."}, "evidence_verify",
        options=[_o("--latest", "The newest release (resolved once, then pinned).", "La release más reciente (se resuelve una vez y se fija)."),
                 _o("--tag", "A specific release tag.", "Una etiqueta de release concreta.", "TAG"),
                 _o("--directory", "A folder that already holds the release files (works offline).", "Una carpeta que ya contiene los archivos de la release (funciona sin red).", "DIR")],
        examples=[("mgctl evidence verify --latest", {"en": "Needs the network and cosign.", "es": "Requiere red y cosign."}), ("mgctl evidence verify --directory ./release --offline", {"en": "Offline.", "es": "Sin red."})],
        needs={"en": "scripts/verify_public_release.py (set MGCTL_VERIFIER, or run from a checkout) and cosign.", "es": "scripts/verify_public_release.py (MGCTL_VERIFIER, o ejecutar desde un checkout) y cosign."},
        detail={"en": "Exit codes of the verifier are passed through: 1 integrity, 2 signature or identity, 3 Merkle, 4 download, 5 missing dependency, 6 invalid format. A pass proves the publisher identity and the integrity of the files, not who wrote the third-party rules.",
                "es": "Se reenvían los códigos del verificador: 1 integridad, 2 firma o identidad, 3 Merkle, 4 descarga, 5 dependencia ausente, 6 formato no válido. Superarlo prueba la identidad del publicador y la integridad de los archivos, no quién escribió las reglas de terceros."}),
    Cmd(("attest",), "planned", {"en": "Attestations.", "es": "Atestaciones."}, "group"),
    _planned("attest verify", "Verify build attestations (none are produced today).", "Verifica atestaciones de compilación (hoy no se produce ninguna)."),
    Cmd(("intelligence",), "implemented", {"en": "The signed YARA rule channel installed on this Mac.", "es": "El canal firmado de reglas YARA instalado en este Mac."}, "group"),
    Cmd(("intelligence", "status"), "implemented", {"en": "Installed rules, verifier, trust state and YARA engine.", "es": "Reglas instaladas, verificador, estado de confianza y motor YARA."}, "intelligence_status",
        needs={"en": "macOS and macguard-audit.", "es": "macOS y macguard-audit."}),
    Cmd(("intelligence", "update"), "implemented", {"en": "Download, verify and install the signed rules.", "es": "Descarga, verifica e instala las reglas firmadas."}, "intelligence_update",
        options=[_o("--yes", "Consent to the download without a question (required with --non-interactive).", "Consiente la descarga sin preguntar (obligatorio con --non-interactive).")],
        needs={"en": "macOS, macguard-audit and the network. Refused with --offline.", "es": "macOS, macguard-audit y red. Se rechaza con --offline."}),
    Cmd(("intelligence", "verify"), "implemented", {"en": "Re-verify the installed rules: signatures, hashes, log inclusion, no extra files.", "es": "Reverifica las reglas instaladas: firmas, hashes, inclusión en el registro, sin archivos de más."}, "intelligence_verify",
        needs={"en": "macOS and macguard-audit. Works offline.", "es": "macOS y macguard-audit. Funciona sin red."}),
    _planned("report", "Produce a report (pdf or json).", "Genera un informe (pdf o json).", options=[_o("--format", "pdf or json.", "pdf o json.", "pdf|json", None, ("pdf", "json"))]),
    Cmd(("agent",), "planned", {"en": "The MacGuard Agent.", "es": "El agente de MacGuard."}, "group"),
    _planned("agent status", "Status of the MacGuard Agent (does not exist yet).", "Estado del agente de MacGuard (todavía no existe)."),
    Cmd(("cloud",), "planned", {"en": "MacGuard Cloud.", "es": "MacGuard Cloud."}, "group"),
    _planned("cloud status", "Status of MacGuard Cloud (does not exist yet; no data is ever sent by default).", "Estado de MacGuard Cloud (todavía no existe; por defecto nunca se envían datos)."),
    Cmd(("intelligence", "channels"), "implemented", {"en": "Honest status of every intelligence channel (operational, experimental, planned).", "es": "Estado honesto de cada canal de inteligencia (operativo, experimental, planificado)."}, "intelligence_channels",
        examples=[("mgctl intelligence channels --json", {"en": "Machine-readable.", "es": "Para máquinas."})], detail={"en": "The YARA channel is operational (classic YARA, not YARA-X). IOC is experimental: the code and tests exist but no live source is cleared for redistribution.", "es": "El canal YARA es operativo (YARA clásico, no YARA-X). IOC es experimental: existen el código y las pruebas, pero ninguna fuente real está autorizada para redistribuirse."}),
    Cmd(("intelligence", "sources"), "implemented", {"en": "The source registry: licence and redistribution status of every upstream source.", "es": "El registro de fuentes: licencia y estado de redistribución de cada fuente de origen."}, "intelligence_sources"),
    Cmd(("intelligence", "catalog"), "experimental", {"en": "The signed global catalog that pins the exact version of every channel.", "es": "El catálogo global firmado que fija la versión exacta de cada canal."}, "group"),
    Cmd(("intelligence", "catalog", "verify"), "experimental", {"en": "Verify a catalog and every channel it pins: hashes, Merkle roots, states, rollback, signature.", "es": "Verifica un catálogo y cada canal que fija: hashes, raíces Merkle, estados, retroceso, firma."}, "intelligence_catalog_verify",
        positionals=[("catalog", True, {"en": "Path of catalog.json.", "es": "Ruta de catalog.json."})],
        options=[_o("--root", "Folder with <channel>/<version>/manifest.json and the artifacts.", "Carpeta con <canal>/<versión>/manifest.json y los artefactos.", "DIR"),
                 _o("--bundle", "Sigstore bundle of the catalog (with --identity and --issuer), or a key bundle (with --key).", "Bundle Sigstore del catálogo (con --identity y --issuer), o bundle de clave (con --key).", "FILE"),
                 _o("--identity", "Expected signing workflow identity.", "Identidad esperada del flujo de trabajo firmante.", "ID"), _o("--issuer", "Expected OIDC issuer.", "Emisor OIDC esperado.", "URL"),
                 _o("--key", "Public key to pin (offline or test deployments).", "Clave pública a fijar (despliegues sin red o de pruebas).", "PUB"), _o("--signature", "Detached signature (older cosign).", "Firma separada (cosign antiguo).", "FILE"),
                 _o("--previous", "The previous catalog you trust (chain check).", "El catálogo anterior de confianza (comprobación de cadena).", "FILE"), _o("--min-version", "Newest catalog version you already trust (rollback protection).", "Versión de catálogo más reciente que ya consideras de confianza (protección contra retroceso).", "N"),
                 _o("--allow-draft", "Accept channels that are not approved (never for production).", "Acepta canales no aprobados (nunca en producción).")],
        needs={"en": "Python and, for the signature, cosign. Works offline.", "es": "Python y, para la firma, cosign. Funciona sin red."},
        detail={"en": "Without a signature the result is 'consistent, signature not checked' (exit 4): files match the catalog, but nothing proves who published them. Exit 2 = integrity, signature or policy failure (revoked, draft, rollback).",
                "es": "Sin firma el resultado es 'consistente, firma no comprobada' (código 4): los archivos coinciden con el catálogo, pero nada prueba quién los publicó. Código 2 = fallo de integridad, de firma o de política (revocado, borrador, retroceso)."}),
    Cmd(("intelligence", "vulns"), "experimental", {"en": "Vulnerability sources from the US, the EU and Spain (CISA, ENISA EUVD, CERT-EU).", "es": "Fuentes de vulnerabilidades de EE. UU., la UE y España (CISA, ENISA EUVD, CERT-EU)."}, "group"),
    Cmd(("intelligence", "vulns", "sources"), "experimental", {"en": "Vulnerability sources with region, redistribution status and whether an adapter exists.", "es": "Fuentes de vulnerabilidades con región, estado de redistribución y si existe adaptador."}, "intelligence_vulns_sources",
        examples=[("mgctl intelligence vulns sources --json", {"en": "Machine-readable.", "es": "Para máquinas."})],
        detail={"en": "Nothing is published from these sources: none is both cleared by the registry and confirmed by the owner.", "es": "No se publica nada de estas fuentes: ninguna está a la vez autorizada por el registro y confirmada por el propietario."}),
    Cmd(("intelligence", "vulns", "lookup"), "experimental", {"en": "Find a CVE, EUVD or GHSA identifier in a merged view and show what each source says.", "es": "Busca un identificador CVE, EUVD o GHSA en una vista fusionada y muestra lo que dice cada fuente."}, "intelligence_vulns_lookup",
        positionals=[("id", True, {"en": "CVE-YYYY-NNNN, EUVD-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx.", "es": "CVE-AAAA-NNNN, EUVD-AAAA-NNNN o GHSA-xxxx-xxxx-xxxx."})],
        options=[_o("--merged", "merged.json made by 'python3 -m intel vulns merge'.", "merged.json generado por 'python3 -m intel vulns merge'.", "FILE")],
        detail={"en": "Exploitation is shown per source. A critical score is severity, not exploitation. Exit 2 = identifier not found.", "es": "La explotación se muestra por fuente. Una puntuación crítica es severidad, no explotación. Código 2 = identificador no encontrado."}),
    Cmd(("intelligence", "vulns", "assess"), "experimental", {"en": "Is this Linux package affected? Answers only from the distribution's own advisory data.", "es": "¿Está afectado este paquete de Linux? Responde solo con los datos de aviso de la propia distribución."}, "intelligence_vulns_assess",
        positionals=[("cve", True, {"en": "The CVE to assess.", "es": "El CVE a evaluar."})],
        options=[_o("--package", "Package name as the distribution calls it.", "Nombre del paquete tal como lo llama la distribución.", "NAME"), _o("--installed", "Installed package version (dpkg order).", "Versión instalada del paquete (orden dpkg).", "VERSION"),
                 _o("--distro", "Distribution id, for example debian.", "Id de la distribución, por ejemplo debian.", "ID"), _o("--release", "Release, for example bookworm.", "Versión de la distribución, por ejemplo bookworm.", "NAME"),
                 _o("--rows", "A macguard.distro-fixes/1 file with the distribution's data.", "Un fichero macguard.distro-fixes/1 con los datos de la distribución.", "FILE"), _o("--scheme", "Version scheme: dpkg (implemented) or rpm (not implemented: NOT_ASSESSED).", "Esquema de versiones: dpkg (implementado) o rpm (no implementado: NOT_ASSESSED).", "SCHEME", "dpkg", ["dpkg", "rpm"])],
        needs={"en": "Python. Works offline.", "es": "Python. Funciona sin red."},
        detail={"en": "Exit 0 = patched or not affected; 2 = affected and unpatched; 4 = NOT_ASSESSED (no distribution data, an unknown version scheme or contradictory data). Not assessed is not 'safe'. Upstream version ranges are never used for Linux packages because distributions backport fixes. Exploitation is a separate question.",
                "es": "Código 0 = parcheado o no afectado; 2 = afectado sin parche; 4 = NOT_ASSESSED (sin datos de la distribución, esquema de versiones desconocido o datos contradictorios). No evaluado no significa 'seguro'. Los rangos de versión del proveedor no se usan nunca para paquetes Linux porque las distribuciones reaplican correcciones. La explotación es otra pregunta."}),
    Cmd(("alias",), "implemented", {"en": "Optional short alias 'mg' (never created by installation).", "es": "Alias corto opcional 'mg' (la instalación nunca lo crea)."}, "group"),
    Cmd(("alias", "status"), "implemented", {"en": "Say whether 'mg' exists on PATH and whether it is ours.", "es": "Indica si 'mg' existe en el PATH y si es nuestro."}, "alias_status"),
    Cmd(("alias", "enable"), "implemented", {"en": "Create the 'mg' symlink in a directory you name, only if no 'mg' exists anywhere on PATH.", "es": "Crea el enlace 'mg' en un directorio que indiques, solo si no existe ningún 'mg' en el PATH."}, "alias_enable",
        options=[_o("--dir", "Directory for the link (default ~/.local/bin). It must already exist and be writable.", "Directorio del enlace (por defecto ~/.local/bin). Debe existir y ser escribible.", "DIR"),
                 _o("--force-conflict", "Create it even if another 'mg' is on PATH (it will NOT take priority; PATH is never changed).", "Lo crea aunque haya otro 'mg' en el PATH (NO tendrá prioridad; el PATH nunca se modifica).")],
        detail={"en": "mgctl never edits PATH, never replaces an existing mg and never touches files managed by APT, DNF or Homebrew. Remove it with: mgctl alias disable.", "es": "mgctl nunca edita el PATH, nunca reemplaza un mg existente ni toca archivos gestionados por APT, DNF o Homebrew. Se retira con: mgctl alias disable."}),
    Cmd(("alias", "disable"), "implemented", {"en": "Remove the 'mg' link, but only if it points to mgctl.", "es": "Retira el enlace 'mg', pero solo si apunta a mgctl."}, "alias_disable",
        options=[_o("--dir", "Directory that holds the link (default ~/.local/bin).", "Directorio que contiene el enlace (por defecto ~/.local/bin).", "DIR")]),
]

BY_PATH = {c.path: c for c in COMMANDS}


def children(path: Tuple[str, ...]):
    n = len(path)
    return [c for c in COMMANDS if len(c.path) == n + 1 and c.path[:n] == path]
