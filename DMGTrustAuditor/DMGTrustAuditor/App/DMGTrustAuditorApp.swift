import SwiftUI
import AppKit

// Interface rules (see DESIGN_RULES.md): headers carry the heading trait, status is never color-only,
// text uses semantic styles so it follows Dynamic Type, spacing/colors come from DesignSystem tokens,
// appearance and language follow the system unless the user overrides the language.
// Motion policy: this app uses no animation on purpose, so there is nothing to reduce.

@main struct DMGTrustAuditorApp: App {
    var body: some Scene {
        WindowGroup { AuditorView().frame(minWidth: 900, minHeight: 640) }
            .defaultSize(width: 980, height: 720)
    }
}

/// Info button whose accessible name is always the subject it explains, never a bare "info".
struct InfoButton: View {
    let what: String
    let help: String
    let action: () -> Void
    var body: some View {
        Button(action: action) { Image(systemName: "info.circle") }
            .buttonStyle(.plain)
            .help(help)
            .accessibilityLabel(what)
            .accessibilityHint(help)
    }
}

struct AuditorView: View {
    @StateObject private var yara = YARARuleManager.shared
    @State private var showRulePrompt = false
    @State private var showRuleResult = false
    @State private var spanish = AppLanguage.isSpanish
    @State private var selection = 0
    @State private var file: URL?
    @State private var name = ""
    @State private var team = ""
    @State private var bundle = ""
    @State private var sha = ""
    @State private var source = ""
    @State private var busy = false
    @State private var report: AuditReport?
    @State private var showResult = false
    @State private var helpTopic: HelpTopic?
    private func tr(_ es: String, _ en: String) -> String { spanish ? es : en }
    private var engineText: String {
        guard let e = yara.engineSummary else { return tr("Comprobando el motor YARA…", "Checking the YARA engine…") }
        return e.ready ? "YARA \(e.version) · \(yara.installedCount) \(tr("reglas", "rules"))" : tr("Motor YARA no disponible", "YARA engine unavailable")
    }
    private var rulesStatus: String {
        yara.checking ? tr("Comprobando…", "Checking…")
            : (yara.updateAvailable ? tr("Nueva versión disponible", "New revision available") : tr("Sin actualizaciones confirmadas", "No confirmed update"))
    }
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: MGSpacing.md) {
                Label("DMG Trust Auditor", systemImage: "checkmark.shield.fill")
                    .font(MGTypography.sectionTitle).foregroundStyle(.primary).padding(.bottom, MGSpacing.lg)
                sidebar(tr("Analizar archivo", "Analyze file"), icon: "doc.viewfinder", index: 0)
                sidebar(tr("Resultados", "Results"), icon: "checkmark.shield", index: 1)
                Spacer()
                Label(tr("Auditoría local", "Local auditing"), systemImage: "lock.shield")
                    .font(MGTypography.caption).foregroundStyle(.secondary)
                Label(engineText, systemImage: yara.engineSummary?.ready == true ? "checkmark.seal" : (yara.engineSummary == nil ? "hourglass" : "exclamationmark.triangle"))
                    .font(MGTypography.caption).foregroundStyle(.secondary)
                    .help(yara.engineSummary?.ready == true ? tr("Motor verificado: hashes, firma, versión, arquitectura y autoprueba.", "Engine verified: hashes, signature, version, architecture and self-test.") : (yara.engineSummary?.reason ?? ""))
            }
            .padding(MGSpacing.lg).frame(width: 200, alignment: .leading)
            .background(MGColor.Surface.subtle)
            .accessibilityElement(children: .contain)
            .accessibilityLabel(tr("Navegación", "Navigation"))
            Divider()
            ScrollView {
            VStack(alignment: .leading, spacing: MGSpacing.lg) {
                HStack(alignment: .top) {
                    MGScreenHeader(
                        title: selection == 0 ? tr("Analizar archivo", "Analyze file") : tr("Resultados", "Results"),
                        summary: tr("Verifica procedencia, firma, paquetes y riesgos antes de instalar", "Check provenance, signatures, packages and risks before installing"))
                    Picker(tr("Idioma", "Language"), selection: $spanish) { Text("Español").tag(true); Text("English").tag(false) }
                        .pickerStyle(.segmented).labelsHidden().frame(width: 175)
                        .accessibilityLabel(tr("Idioma de la interfaz", "Interface language"))
                        .onChange(of: spanish) { AppLanguage.set(spanish: $0) }
                }
                if selection == 0 {
                MGInfoCard {
                    HStack {
                        MGSectionHeader(title: tr("Reglas YARA", "YARA rules"),
                                        subtitle: tr("Reglas locales: \(yara.installedCount) · \(rulesStatus)", "Local rule files: \(yara.installedCount) · \(rulesStatus)")) { EmptyView() }
                        Spacer()
                        InfoButton(what: tr("Información sobre las reglas YARA", "About the YARA rules"),
                                   help: tr("Origen, verificación y límites de las reglas", "Origin, verification and limits of the rules")) { showRulePrompt = true }
                        MGSecondaryButton(yara.updateAvailable ? tr("Actualizar reglas", "Update rules") : tr("Buscar actualizaciones", "Check updates")) {
                            if yara.updateAvailable { showRulePrompt = true } else { yara.checkForUpdates() }
                        }
                        .keyboardShortcut("r")
                        .disabled(yara.downloading || yara.checking)
                    }
                    if yara.downloading {
                        ProgressView(value: yara.progress, total: 1)
                            .accessibilityLabel(tr("Progreso de la descarga", "Download progress"))
                            .accessibilityValue("\(Int(yara.progress * 100)) %")
                        Text(tr("Descargando y validando reglas… \(Int(yara.progress * 100)) %", "Downloading and validating rules… \(Int(yara.progress * 100)) %")).font(MGTypography.caption)
                    }
                    Text(tr("Se comprueban nuevas versiones en segundo plano al abrir. La descarga requiere consentimiento. Las reglas comunitarias no tienen manifiesto firmado y no sustituyen un antivirus.", "Checks for new revisions in the background at launch. Downloads require consent. Community rules lack a signed manifest and are not an antivirus replacement."))
                        .font(MGTypography.caption).foregroundStyle(.secondary)
                }

                MGInfoCard {
                    MGSectionHeader(title: tr("Archivo que se analizará", "File to inspect")) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(file?.path ?? tr("Ningún archivo seleccionado (también puedes arrastrarlo aquí)", "No file selected (you can also drop it here)")).lineLimit(2).textSelection(.enabled)
                                if let file { Text(tr("Detectado: ", "Detected: ") + AuditEngine.label(ContentDetector.detect(file).kind)).font(MGTypography.caption).foregroundStyle(.secondary) }
                            }
                            Spacer()
                            MGPrimaryButton(tr("Seleccionar archivo…", "Select file…")) { choose() }
                                .keyboardShortcut("o")
                        }
                    }
                }
                .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                    guard let p = providers.first else { return false }
                    _ = p.loadObject(ofClass: URL.self) { url, _ in
                        guard let url else { return }
                        DispatchQueue.main.async { self.file = url; self.report = nil }   // dropped items are only read, never opened
                    }
                    return true
                }
                MGInfoCard {
                    MGSectionHeader(title: tr("Referencias independientes (opcionales)", "Independent references (optional)")) {
                        field(tr("Nombre de la aplicación", "Application name"), $name,
                              tr("Nombre publicado por el fabricante. Compruébalo en su web oficial.", "Name published by the vendor. Check its official website."), nil)
                        field("Team ID", $team,
                              tr("Identificador observado en la firma. Apple explica cómo localizar el Team ID propio, pero NO publica un directorio universal de fabricantes.", "Identifier observed in the signature. Apple explains how to locate your own Team ID, but does NOT provide a universal vendor directory."), "https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/")
                        field("Bundle ID", $bundle,
                              tr("Identificador CFBundleIdentifier. Verifica su atribución con el desarrollador.", "CFBundleIdentifier. Verify attribution with the developer."), "https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifier")
                        field("SHA-256", $sha,
                              tr("Busca el SHA-256 publicado en la web oficial del desarrollador o en una publicación autenticada. Apple no ofrece hashes de todas las aplicaciones.", "Find the SHA-256 on the vendor's official website or an authenticated release. Apple does not publish hashes for every app."), nil)
                        field(tr("URL oficial de referencia", "Official reference URL"), $source,
                              tr("Introduce la URL HTTPS del fabricante. Se consultará AASA del dominio. Si enlazas directamente a un manifiesto .sha256, .sha256sum o checksums, se intentará localizar el hash del nombre exacto del DMG. No hay un directorio oficial universal de hashes.", "Enter the publisher HTTPS URL. AASA will be queried on that domain. A direct .sha256, .sha256sum or checksums manifest URL can be used to look up the exact DMG filename. There is no universal official hash directory."), nil)
                    }
                }
                HStack {
                    MGPrimaryButton(tr("Verificar", "Verify")) { verify() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(file == nil || busy)
                    MGProgressIndicator(isActive: busy)
                        .accessibilityLabel(tr("Analizando archivo", "Analyzing file"))
                    Spacer()
                    Text(tr("No ejecuta instaladores ni aplicaciones", "Does not execute installers or applications")).font(MGTypography.caption).foregroundStyle(.secondary)
                }
                }
                if let report, selection == 0 {
                    MGInfoCard {
                        HStack {
                            Text(tr("Última auditoría: \(report.score)/10", "Last audit: \(report.score)/10"))
                            Spacer()
                            MGSecondaryButton(tr("Ver resultados", "View results")) { showResult = true }
                        }
                    }
                }
                if selection == 1 {
                    if let report { results(report) } else {
                        MGInfoCard {
                            MGSectionHeader(title: tr("Todavía no hay resultados", "No results yet"),
                                            subtitle: tr("Selecciona un archivo en «Analizar archivo» y pulsa Verificar.", "Select a file under “Analyze file” and press Verify.")) { EmptyView() }
                        }
                    }
                }
            }.padding(MGSpacing.lg)
            }.background(MGColor.Surface.canvas)
        }
        .onAppear { yara.checkForUpdates() }
        .onChange(of: yara.updateAvailable) { available in
            if available && !yara.downloading { showRulePrompt = true }
        }
        .confirmationDialog(tr("Nueva versión de reglas YARA disponible", "New YARA rule revision available"), isPresented: $showRulePrompt, titleVisibility: .visible) {
            Button(tr("Actualizar reglas", "Update rules")) { startRuleUpdate() }
            Button(tr("Ahora no", "Not now"), role: .cancel) { }
        } message: {
            Text(tr("Puedes seguir usando las reglas locales. Las nuevas vienen del canal MacGuard y solo se instalan si su firma, sus hashes y su inclusión en el registro de transparencia se verifican. La actualización es opcional.", "You can keep using the local rules. New ones come from the MacGuard channel and are installed only if their signature, hashes and transparency log inclusion verify. Updating is optional."))
        }
        .alert(tr("Actualización de YARA", "YARA update"), isPresented: $showRuleResult) {
            Button(tr("Aceptar", "OK"), role: .cancel) { }
        } message: { Text(yara.message) }
        .sheet(isPresented: $showResult) {
            if let report {
                ScrollView { results(report).padding(MGSpacing.lg) }
                    .frame(minWidth: 780, minHeight: 600)
                    .toolbar { ToolbarItem(placement: .cancellationAction) {
                        Button(tr("Cerrar", "Close")) { showResult = false }.keyboardShortcut(.cancelAction)
                    }}
            }
        }
        .alert(item: $helpTopic) { topic in
            if let url = topic.url, let parsed = URL(string: url) {
                return Alert(title: Text(topic.title), message: Text(topic.description + "\n\n" + url), primaryButton: .default(Text(tr("Abrir fuente oficial", "Open official source"))) { NSWorkspace.shared.open(parsed) }, secondaryButton: .cancel(Text(tr("Cerrar", "Close"))))
            }
            return Alert(title: Text(topic.title), message: Text(topic.description), dismissButton: .default(Text(tr("Aceptar", "OK"))))
        }
    }
    private func startRuleUpdate() {
        yara.update { _ in showRuleResult = true }
    }
    private func sidebar(_ title: String, icon: String, index: Int) -> some View {
        Button { selection = index } label: {
            Label(title, systemImage: icon).font(selection == index ? MGTypography.bodySecondary.weight(.semibold) : MGTypography.bodySecondary)
                .frame(maxWidth: .infinity, alignment: .leading).padding(MGSpacing.sm + MGSpacing.xxs)
                .background(selection == index ? MGColor.Surface.overlaySelected : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selection == index ? [.isSelected] : [])
    }
    @ViewBuilder private func field(_ title: String, _ value: Binding<String>, _ help: String, _ link: String?) -> some View {
        HStack(alignment: .center) {
            Text(title).frame(width: 185, alignment: .leading)
            TextField(title, text: value).textFieldStyle(.roundedBorder)
            InfoButton(what: tr("Información sobre: ", "Information about: ") + title,
                       help: help + (link == nil ? "" : "\n" + link!)) {
                helpTopic = HelpTopic(title: title, description: help, url: link)
            }
        }
    }
    private func choose() {
        // Any supported container: .app bundles are packages, so they are selectable as single items.
        let panel = NSOpenPanel(); panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.message = tr("Elige un DMG, PKG, .app, ZIP, TAR, Mach-O, script, ISO o workflow. No se ejecutará.", "Choose a DMG, PKG, .app, ZIP, TAR, Mach-O, script, ISO or workflow. It will not be run.")
        if panel.runModal() == .OK { file = panel.url; report = nil }
    }
    private func verify() {
        guard let file else { return }
        busy = true; report = nil
        let input = AuditInput(file: file, expectedName: name, expectedTeam: team.trimmingCharacters(in: .whitespacesAndNewlines), expectedBundle: bundle.trimmingCharacters(in: .whitespacesAndNewlines), expectedSHA: sha, sourceURL: source)
        DispatchQueue.global(qos: .userInitiated).async {
            let output = AuditEngine.audit(input)
            DispatchQueue.main.async { self.report = output; self.busy = false; self.showResult = true; self.selection = 1 }
        }
    }
    @ViewBuilder private func results(_ report: AuditReport) -> some View {
        MGInfoCard {
            HStack {
                MGSectionHeader(title: tr("Resultado de auditoría", "Audit results"),
                                subtitle: tr("Puntuación heurística; no es probabilidad de ausencia de malware.", "Heuristic score; not a probability of being malware-free.")) { EmptyView() }
                Spacer()
                Text("\(report.score)/10").font(MGTypography.metric)
                    .accessibilityLabel(tr("Puntuación \(report.score) de 10", "Score \(report.score) out of 10"))
            }
            Text(tr("Formato: ", "Format: ") + report.kind + " · " + report.coverage).font(MGTypography.caption).foregroundStyle(.secondary)
            let counts = Dictionary(grouping: report.findings, by: \.state).mapValues(\.count)
            Text(tr("Evidencia: \(counts[.passed] ?? 0) correctas · \(counts[.failed] ?? 0) fallidas · \(counts[.warning] ?? 0) advertencias · \(counts[.unknown] ?? 0) sin verificar", "Evidence: \(counts[.passed] ?? 0) passed · \(counts[.failed] ?? 0) failed · \(counts[.warning] ?? 0) warnings · \(counts[.unknown] ?? 0) unknown"))
                .font(MGTypography.caption).foregroundStyle(.secondary)
            ProgressView(value: Double(report.score), total: 10).tint(report.score >= 9 ? MGHealthStatus.protected.tint : report.score >= 5 ? MGHealthStatus.degraded.tint : MGHealthStatus.failed.tint)
                .accessibilityHidden(true)   // the score is already announced in words above
            MGSectionHeader(title: tr("Evidencias verificadas y pendientes", "Verified and outstanding evidence")) { EmptyView() }
                .padding(.top, MGSpacing.sm)
            ForEach(report.findings) { finding in
                Divider()
                HStack(alignment: .top) {
                    MGStatusBadge(status: status(finding.state), text: label(finding.state))
                        .frame(width: 130, alignment: .leading)
                    VStack(alignment: .leading, spacing: MGSpacing.xs) {
                        Text(finding.title).fontWeight(.medium)
                        Text(finding.detail).font(MGTypography.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    InfoButton(what: tr("Información sobre: ", "Information about: ") + finding.title,
                               help: tr("Qué significa esta prueba y cómo interpretarla", "What this check means and how to interpret it")) {
                        helpTopic = FindingHelp.topic(finding.title, spanish: spanish)
                    }
                }
            }
            HStack {
                MGSecondaryButton(tr("Exportar JSON…", "Export JSON…")) { export(report, json: true) }
                MGSecondaryButton(tr("Exportar TXT…", "Export TXT…")) { export(report, json: false) }
            }
        }
    }
    private func status(_ s: AuditState) -> MGHealthStatus {
        switch s { case .passed: return .protected; case .warning: return .degraded; case .failed: return .failed; case .unknown: return .unknown }
    }
    private func label(_ s: AuditState) -> String {
        switch s { case .passed: return tr("Correcto", "Passed"); case .warning: return tr("Revisar", "Review"); case .failed: return tr("Fallo", "Failed"); case .unknown: return tr("Sin verificar", "Unknown") }
    }
    private func export(_ report: AuditReport, json: Bool) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "DMGTrustAudit." + (json ? "json" : "txt")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if json {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
            if let data = try? encoder.encode(report) { try? data.write(to: url, options: .atomic) }
        } else {
            let lines = (["DMG Trust Auditor | \(report.score)/10", report.file, "Not a malware-free certification."] + report.findings.map { "[\($0.state.rawValue)] \($0.title): \($0.detail)" }).joined(separator: "\n")
            try? lines.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

struct HelpTopic: Identifiable {
    let id = UUID()
    let title: String
    let description: String
    let url: String?
}


// Educational explanations shown alongside individual audit findings.
// A successful check is evidence, not proof of malware-free software.
enum FindingHelp {
    static func topic(_ title: String, spanish: Bool) -> HelpTopic {
        let t = title.lowercased()
        let info: (String, String, String?)
        if t.contains("bundle") {
            info = ("Bundle ID", spanish ? "Identificador lógico de la aplicación (CFBundleIdentifier). Distingue aplicaciones, pero puede copiarse: no prueba por sí solo quién las ha publicado." : "Logical app identifier (CFBundleIdentifier). It identifies apps but can be copied; it is not proof of publisher identity.", "https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifier")
        } else if t.contains("team") || t.contains("developer id") || t.contains("certificate") || t.contains("certificado") {
            info = ("Developer ID / Team ID", spanish ? "El Team ID identifica al equipo Apple Developer asociado a una firma. Comprueba la validez criptográfica y contrasta la identidad con una referencia independiente; Apple no publica un directorio completo de todos los fabricantes." : "The Team ID identifies the Apple Developer team associated with a signature. Verify cryptographic validity and compare the publisher against an independent source; Apple has no comprehensive public vendor directory.", "https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/")
        } else if t.contains("sha") || t.contains("hash") || t.contains("checksum") {
            info = ("SHA-256", spanish ? "Huella criptográfica del archivo. Una coincidencia solo acredita integridad frente a una referencia auténtica; busca el hash en el sitio oficial del fabricante o en una publicación firmada. Apple no mantiene una base universal de hashes de DMG." : "Cryptographic fingerprint. A match establishes integrity only against an authenticated reference; obtain it from the vendor's official site or signed release. Apple has no universal DMG hash database.", nil)
        } else if t.contains("dmg") || t.contains("mount") || t.contains("montaje") {
            info = ("DMG", spanish ? "Una imagen de disco de macOS. Se comprueba su estructura y, cuando corresponde, se monta solo lectura para inventariar archivos. La integridad estructural no demuestra ausencia de malware." : "A macOS disk image. Its structure is checked and, when applicable, mounted read-only to inventory files. Structural integrity does not prove it is malware-free.", "https://support.apple.com/guide/disk-utility/welcome/mac")
        } else if t.contains("aasa") || t.contains("domain association") {
            info = ("AASA", spanish ? "Archivo apple-app-site-association publicado por un dominio para declarar asociaciones con aplicaciones y Universal Links. Es evidencia auxiliar; no autentica por sí mismo un instalador macOS." : "apple-app-site-association is a domain-hosted file for app associations and Universal Links. It is supporting evidence, not proof of macOS installer authenticity.", "https://developer.apple.com/documentation/xcode/supporting-associated-domains")
        } else if t.contains("pkg") || t.contains("script") || t.contains("payload") {
            info = ("PKG / Installer", spanish ? "Un PKG puede instalar archivos y ejecutar scripts con permisos elevados. Esta versión solo inspecciona parcialmente scripts y cargas comprimidas; no ejecuta el instalador. Un resultado sin detecciones NO equivale a seguro." : "A PKG can install files and run scripts with elevated privileges. This version only partially inspects scripts and compressed payloads; it never executes the installer. No detections does NOT mean safe.", "https://developer.apple.com/documentation/installer_js")
        } else if t.contains("notar") || t.contains("stapl") || t.contains("gatekeeper") {
            info = ("Gatekeeper / Notarization", spanish ? "Gatekeeper evalúa políticas de ejecución; la notarización indica que Apple procesó el software mediante su servicio. Un ticket no adjunto no implica ausencia de notarización. Ninguna de estas comprobaciones garantiza ausencia de malware." : "Gatekeeper evaluates execution policy; notarization indicates Apple's service processed the software. A missing stapled ticket does not prove it is unnotarized. Neither guarantees absence of malware.", "https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution")
        } else if t.contains("runtime") || t.contains("entitlement") || t.contains("permiso") {
            info = ("Hardened Runtime / Entitlements", spanish ? "Hardened Runtime limita ciertas técnicas de modificación e inyección de código. Los entitlements habilitan excepciones y capacidades especiales; deben revisarse según el comportamiento legítimo de la aplicación." : "Hardened Runtime restricts certain code injection and modification techniques. Entitlements grant exceptions and special capabilities and must be reviewed against the app's legitimate behavior.", "https://developer.apple.com/documentation/security/hardened-runtime")
        } else if t.contains("signature") || t.contains("firma") || t.contains("nested") {
            info = ("Code signing", spanish ? "La firma protege la integridad del código y lo vincula a una identidad de certificado. Deben verificarse también componentes anidados; una firma válida no garantiza que el código sea benigno." : "A code signature protects code integrity and binds it to a certificate identity. Nested components also need verification; a valid signature does not mean the code is benign.", "https://developer.apple.com/documentation/security/code-signing-services")
        } else if t.contains("architecture") || t.contains("arquitectura") {
            info = ("Architectures", spanish ? "Las arquitecturas Mach-O indican si el ejecutable incluye x86_64 (Intel) o arm64 (Apple Silicon). Universal incluye ambas. No es una prueba de seguridad." : "Mach-O architectures indicate x86_64 (Intel) and arm64 (Apple Silicon). Universal includes both. This is not a security check.", nil)
        } else if t.contains("malware") {
            info = ("Static malware triage", spanish ? "Busca indicadores estáticos limitados. No incluye un antivirus completo, ejecución en sandbox ni análisis dinámico. Los falsos positivos y negativos son posibles." : "Limited static indicators are inspected. This is not a full antivirus, sandbox, or dynamic malware analysis. False positives and negatives are possible.", nil)
        } else {
            info = (title, spanish ? "Esta comprobación aporta evidencia parcial. Abre el informe técnico para ver qué se ejecutó y qué queda pendiente. Un resultado desconocido no equivale a fallo ni a prueba superada." : "This check provides partial evidence. Review the technical report for what ran and what remains unverified. Unknown is neither failure nor pass.", nil)
        }
        return HelpTopic(title: info.0, description: info.1, url: info.2)
    }
}
