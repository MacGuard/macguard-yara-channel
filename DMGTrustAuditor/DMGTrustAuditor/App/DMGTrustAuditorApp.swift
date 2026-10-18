import SwiftUI
import AppKit
import MacGuardDesignKit

@main struct DMGTrustAuditorApp: App {
    var body: some Scene { WindowGroup { AuditorView().frame(minWidth: 790, minHeight: 680) } }
}

struct AuditorView: View {
    @StateObject private var yara = YARARuleManager.shared
    @State private var showRulePrompt = false
    @State private var showRuleResult = false
    @State private var spanish = true
    @State private var darkMode = false
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
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                Label("DMG Trust Auditor", systemImage: "checkmark.shield.fill")
                    .font(.headline).foregroundStyle(.primary).padding(.bottom, 16)
                sidebar(tr("Analizar archivo", "Analyze file"), icon: "doc.viewfinder", index: 0)
                sidebar(tr("Resultados", "Results"), icon: "checkmark.shield", index: 1)
                Spacer()
                Label(tr("Auditoría local", "Local auditing"), systemImage: "lock.shield")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(18).frame(width: 190, alignment: .leading)
            .background(MGColor.Surface.subtle)
            Divider()
            ScrollView {
            VStack(alignment: .leading, spacing: MGSpacing.lg) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("DMG Trust Auditor").font(.largeTitle.bold())
                        Text(tr("Verifica procedencia, firma, paquetes y riesgos antes de instalar", "Check provenance, signatures, packages and risks before installing")).foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing) {
                        Picker("Language", selection: $spanish) { Text("Español").tag(true); Text("English").tag(false) }.pickerStyle(.segmented).frame(width: 175)
                        Toggle(tr("Modo oscuro", "Dark mode"), isOn: $darkMode).toggleStyle(.switch).font(.caption)
                    }
                }
                if selection == 0 {
                MGInfoCard {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(tr("Reglas YARA", "YARA rules")).font(.headline)
                            Text(tr("Reglas locales: \(yara.installedCount) · \(yara.checking ? "Comprobando…" : (yara.updateAvailable ? "Nueva versión disponible" : "Sin actualizaciones confirmadas"))", "Local rule files: \(yara.installedCount) · \(yara.checking ? "Checking…" : (yara.updateAvailable ? "New revision available" : "No confirmed update"))"))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { showRulePrompt = true } label: { Image(systemName: "info.circle") }.buttonStyle(.plain)
                        MGSecondaryButton(yara.updateAvailable ? tr("Actualizar reglas", "Update rules") : tr("Buscar actualizaciones", "Check updates")) {
                            if yara.updateAvailable { showRulePrompt = true } else { yara.checkForUpdates() }
                        }
                            .disabled(yara.downloading || yara.checking)
                    }
                    if yara.downloading {
                        ProgressView(value: yara.progress, total: 1)
                        Text(tr("Descargando y validando reglas… \(Int(yara.progress * 100)) %", "Downloading and validating rules… \(Int(yara.progress * 100)) %")).font(.caption)
                    }
                    Text(tr("Se comprueban nuevas versiones en segundo plano al abrir. La descarga requiere consentimiento. Las reglas comunitarias no tienen manifiesto firmado y no sustituyen un antivirus.", "Checks for new revisions in the background at launch. Downloads require consent. Community rules lack a signed manifest and are not an antivirus replacement."))
                        .font(.caption).foregroundStyle(.secondary)
                }

                MGInfoCard {
                    Text(tr("Archivo que se analizará", "File to inspect")).font(.headline)
                    HStack {
                        Text(file?.path ?? tr("Ningún archivo seleccionado", "No file selected")).lineLimit(2).textSelection(.enabled)
                        Spacer()
                        MGPrimaryButton(tr("Seleccionar DMG", "Select DMG")) { choose() }
                    }
                }
                MGInfoCard {
                    Text(tr("Referencias independientes (opcionales)", "Independent references (optional)")).font(.headline)
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
                HStack {
                    MGPrimaryButton(tr("Verificar", "Verify")) { verify() }
                        .disabled(file == nil || busy)
                    MGProgressIndicator(isActive: busy)
                    Spacer()
                    Text(tr("No ejecuta instaladores ni aplicaciones", "Does not execute installers or applications")).font(.caption).foregroundStyle(.secondary)
                }
                }
                if let report {
                    MGInfoCard {
                        HStack {
                            Text(tr("Última auditoría: \(report.score)/10", "Last audit: \(report.score)/10"))
                            Spacer()
                            MGSecondaryButton(tr("Ver resultados", "View results")) { showResult = true }
                        }
                    }
                }
                if selection == 1, let report {
                    results(report)
                }
            }.padding(MGSpacing.lg)
            }.background(MGColor.Surface.canvas)
        }
        .onAppear { yara.checkForUpdates() }
        .onChange(of: yara.updateAvailable) { available in
            if available && !yara.downloading { showRulePrompt = true }
        }
        .confirmationDialog(tr("Nueva versión de reglas YARA disponible", "New YARA rule revision available"), isPresented: $showRulePrompt) {
            Button(tr("Sí, actualizar", "Yes, update")) { startRuleUpdate() }
            Button(tr("No, ahora no", "No, not now"), role: .cancel) { }
        } message: {
            Text(tr("Puedes continuar usando las reglas locales. Las reglas proceden de GitHub comunitario mediante HTTPS y revisión fijada; NO existe firma criptográfica independiente del manifiesto. La actualización es opcional.", "You can keep using local rules. Community rules are fetched over HTTPS at a pinned GitHub revision, but no independently signed manifest exists. Updating is optional."))
        }
        .alert(tr("Actualización de YARA", "YARA update"), isPresented: $showRuleResult) {
            Button("OK", role: .cancel) { }
        } message: { Text(yara.message) }
        .preferredColorScheme(darkMode ? .dark : .light)
        .frame(minWidth: 900, minHeight: 680)
        .sheet(isPresented: $showResult) {
            if let report {
                ScrollView { results(report).padding(MGSpacing.lg) }
                    .frame(minWidth: 780, minHeight: 600)
                    .toolbar { ToolbarItem(placement: .confirmationAction) {
                        Button(tr("Cerrar", "Close")) { showResult = false }
                    }}
            }
        }
        .alert(item: $helpTopic) { topic in
            if let url = topic.url, let parsed = URL(string: url) {
                return Alert(title: Text(topic.title), message: Text(topic.description + "\n\n" + url), primaryButton: .default(Text(tr("Abrir fuente oficial", "Open official source"))) { NSWorkspace.shared.open(parsed) }, secondaryButton: .cancel(Text(tr("Cerrar", "Close"))))
            }
            return Alert(title: Text(topic.title), message: Text(topic.description), dismissButton: .default(Text("OK")))
        }
    }
    private func startRuleUpdate() {
        yara.update { _ in showRuleResult = true }
    }
    private func sidebar(_ title: String, icon: String, index: Int) -> some View {
        Button { selection = index } label: {
            Label(title, systemImage: icon).font(.subheadline.weight(selection == index ? .semibold : .regular))
                .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                .background(selection == index ? MGColor.Surface.overlaySelected : Color.clear)
                .cornerRadius(8)
        }.buttonStyle(.plain)
    }
    @ViewBuilder private func field(_ title: String, _ value: Binding<String>, _ help: String, _ link: String?) -> some View {
        HStack(alignment: .center) {
            Text(title).frame(width: 185, alignment: .leading)
            TextField(title, text: value).textFieldStyle(.roundedBorder)
            Button { helpTopic = HelpTopic(title: title, description: help, url: link) } label: {
                Image(systemName: "info.circle")
            }
            .buttonStyle(.plain)
            .help(help + (link == nil ? "" : "\n" + link!))
            .accessibilityLabel(help)
        }
    }
    private func choose() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.init(filenameExtension: "dmg")!]; panel.canChooseDirectories = false
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
                VStack(alignment: .leading) {
                    Text(tr("Resultado de auditoría", "Audit results")).font(.title2.bold())
                    Text(tr("Puntuación heurística; no es probabilidad de ausencia de malware.", "Heuristic score; not a probability of being malware-free.")).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text("\(report.score)/10").font(.system(size: 38, weight: .bold, design: .rounded))
            }
            Text(tr("Evidencia: \(report.findings.filter { $0.state == .passed }.count) correctas · \(report.findings.filter { $0.state == .failed }.count) fallidas · \(report.findings.filter { $0.state == .warning }.count) advertencias · \(report.findings.filter { $0.state == .unknown }.count) sin verificar", "Evidence: \(report.findings.filter { $0.state == .passed }.count) passed · \(report.findings.filter { $0.state == .failed }.count) failed · \(report.findings.filter { $0.state == .warning }.count) warnings · \(report.findings.filter { $0.state == .unknown }.count) unknown"))
                .font(.caption).foregroundStyle(.secondary)
            ProgressView(value: Double(report.score), total: 10).tint(report.score >= 9 ? MGHealthStatus.protected.tint : report.score >= 5 ? MGHealthStatus.degraded.tint : MGHealthStatus.failed.tint)
            Text(tr("Evidencias verificadas y pendientes", "Verified and outstanding evidence"))
                .font(.headline).padding(.top, 8)
            ForEach(report.findings) { finding in
                Divider()
                HStack(alignment: .top) {
                    MGStatusBadge(status: status(finding.state), text: label(finding.state))
                        .frame(width: 115, alignment: .leading)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(finding.title).fontWeight(.medium)
                        Text(finding.detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    Button { helpTopic = FindingHelp.topic(finding.title, spanish: spanish) } label: {
                        Image(systemName: "info.circle").font(.body)
                    }
                    .buttonStyle(.plain)
                    .help(tr("Qué significa esta prueba y cómo interpretarla", "What this check means and how to interpret it"))
                    .accessibilityLabel(tr("Información sobre: ", "Information about: ") + finding.title)
                }
            }
            HStack {
                MGSecondaryButton(tr("Exportar JSON", "Export JSON")) { export(report, json: true) }
                MGSecondaryButton(tr("Exportar TXT", "Export TXT")) { export(report, json: false) }
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
