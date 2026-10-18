import Foundation
import CryptoKit

/// Rules come from the MacGuard channel only. A release is installed when, and only when, `ChannelVerifier`
/// accepts it: signed manifest and checkpoint, every file hash, the rules root and the log inclusion proof.
/// Anything else leaves the installed rules untouched. User consent is required before any download.
final class YARARuleManager: NSObject, ObservableObject {
    static let shared = YARARuleManager()
    static let defaultChannelBase = URL(string: "https://macguard.github.io/macguard-yara-channel/")!
    let channelBase: URL
    @Published private(set) var downloading = false
    @Published private(set) var checking = false
    @Published private(set) var progress: Double = 0
    @Published private(set) var message = ""
    @Published private(set) var lastUpdate: Date?
    @Published private(set) var availableRevision: String?
    @Published private(set) var updateAvailable = false
    @Published private(set) var installedCount = 0
    /// True only when the last `update` installed a verified release.
    private(set) var lastResultOK = false
    private let customRulesDirectory: URL?
    private let customTrustStore: TrustStore?
    private let signatureCheck: ChannelVerifier.SignatureCheck?
    private let signatureReason: String
    private let extraBases: [URL]
    private(set) lazy var installer: RuleInstaller = RuleInstaller(
        channelBases: [channelBase] + extraBases, rulesDirectory: rulesDirectory, signatureCheck: signatureCheck,
        signatureUnavailableReason: signatureReason, trustStore: customTrustStore ?? FileTrustStore.default)
    private var updateTask: Task<Void, Never>?

    /// `signatureCheck` defaults to the bundled, pinned Sigstore verifier. Without one no release is accepted.
    init(channelBase: URL = YARARuleManager.defaultChannelBase,
         extraBases: [URL] = [],
         rulesDirectory: URL? = nil,
         trustStore: TrustStore? = nil,
         signatureCheck: ChannelVerifier.SignatureCheck? = nil,
         useStandardVerifier: Bool = true) {
        self.channelBase = channelBase
        self.extraBases = extraBases
        self.customRulesDirectory = rulesDirectory
        self.customTrustStore = trustStore
        if let signatureCheck { self.signatureCheck = signatureCheck; self.signatureReason = "" }
        else if useStandardVerifier { let std = SigstoreVerifier.standard(); self.signatureCheck = std.check; self.signatureReason = std.reason }
        else { self.signatureCheck = nil; self.signatureReason = "no verifier configured" }
        super.init()
        lastUpdate = UserDefaults.standard.object(forKey: "yaraLastUpdate") as? Date
        try? FileManager.default.createDirectory(at: self.rulesDirectory, withIntermediateDirectories: true)
        installer.recoverIfNeeded()
        installStarterRulesIfNeeded()
        refreshInstalledCount()
    }
    var rulesDirectory: URL {
        customRulesDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("DMGTrustAuditor/YARARules", isDirectory: true)
    }
    var isOutdated: Bool { updateAvailable || lastUpdate == nil }
    var engineURL: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/yara") }
    var engineReady: Bool {
        FileManager.default.isExecutableFile(atPath: engineURL.path) &&
        AuditEngine.command("/usr/bin/codesign", ["--verify", "--strict", engineURL.path]).0 == 0
    }
    func refreshInstalledCount() {
        DispatchQueue.global(qos: .utility).async {
            let n = self.ruleFiles().count
            DispatchQueue.main.async { self.installedCount = n }
        }
    }
    func ruleFiles() -> [URL] {
        guard let en = FileManager.default.enumerator(at: rulesDirectory, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) else { return [] }
        return en.compactMap { $0 as? URL }.filter { ["yar", "yara"].contains($0.pathExtension.lowercased()) && !$0.pathComponents.contains("quarantine") }
    }
    func installStarterRulesIfNeeded() {
        let file = rulesDirectory.appendingPathComponent("starter-local.yar")
        guard !FileManager.default.fileExists(atPath: file.path) else { return }
        let content = """
        // Local heuristic signatures; hits are triage indicators, not malware verdicts.
        rule DMGTA_Suspicious_Pipe_To_Shell {
          meta: severity = "review" source = "DMG Trust Auditor starter"
          strings: $a = "curl " ascii nocase $b = "| sh" ascii nocase $c = "| bash" ascii nocase
          condition: $a and ($b or $c)
        }
        rule DMGTA_Gatekeeper_Disable {
          meta: severity = "review" source = "DMG Trust Auditor starter"
          strings: $a = "spctl --master-disable" ascii nocase
          condition: $a
        }
        """
        try? content.write(to: file, atomically: true, encoding: .utf8)
    }

    struct Failure: Error { let es: String; let en: String; var detail: String? }
    private func get(_ name: String, limit: Int, timeout: TimeInterval = 10) async throws -> Data {
        try await installer.fetchData(name, limit: Int64(limit), timeout: timeout)
    }
    private func publish(_ work: @escaping () -> Void) { DispatchQueue.main.async(execute: work) }

    /// Reads `latest.json` only to decide whether something new exists. Nothing is trusted until `update` verifies it.
    func checkForUpdates() {
        guard !checking && !downloading else { return }
        checking = true
        Task {
            do {
                let data = try await get("latest.json", limit: 100_000, timeout: 5)
                guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let root = obj["rules_root"] as? String, root.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
                else { throw Failure(es: "La información de la nueva versión no es válida. No se ha cambiado nada.", en: "The new revision information is not valid. Nothing was changed.") }
                publish {
                    self.availableRevision = root
                    self.updateAvailable = root != UserDefaults.standard.string(forKey: "yaraInstalledRulesRoot")
                    self.checking = false
                }
            } catch {
                let f = error as? Failure
                // Build the text off the main thread: the first localizedDescription of a URLError loads
                // localisation resources and used to stall the UI for ~0.4 s when the prompt appeared.
                let text = f.map { AppLanguage.tr($0.es, $0.en) } ?? AppLanguage.failure("No se pudo comprobar si hay reglas nuevas. Se siguen usando las reglas actuales.", "Could not check for new rules. The current rules stay in use.", detail: error.localizedDescription)
                publish {
                    self.message = text
                    self.checking = false
                }
            }
        }
    }

    func update(completion: @escaping (String) -> Void) {
        guard !downloading else { return }
        guard availableRevision != nil else {
            message = AppLanguage.tr("Aún no hay una versión verificada. Busca actualizaciones primero.", "There is no verified revision yet. Check for updates first.")
            completion(message); return
        }
        downloading = true; progress = 0
        message = AppLanguage.tr("Descargando las reglas del canal MacGuard…", "Downloading the rules from the MacGuard channel…")
        updateTask = Task {
            var result: String; var ok = false; var root: String?
            do {
                (result, root) = try await install()
                ok = true
            } catch let f as Failure {
                result = AppLanguage.failure(f.es + " Se conservan las reglas anteriores.", f.en + " The previous rules were kept.", detail: f.detail ?? "")
            } catch {
                result = AppLanguage.failure("La actualización ha fallado y se conservan las reglas anteriores.", "The update failed and the previous rules were kept.", detail: error.localizedDescription)
            }
            publish {
                self.downloading = false; self.message = result; self.lastResultOK = ok
                if ok {
                    self.lastUpdate = Date(); self.updateAvailable = false
                    UserDefaults.standard.set(self.lastUpdate, forKey: "yaraLastUpdate")
                    UserDefaults.standard.set(root, forKey: "yaraInstalledRulesRoot")
                    self.refreshInstalledCount()
                }
                completion(result)
            }
        }
    }

    /// Cancels a running update; the installed rules are untouched.
    func cancelUpdate() { updateTask?.cancel() }

    private func install() async throws -> (String, String) {
        let summary = try await installer.install(progress: { p in self.publish { self.progress = p } })
        return (AppLanguage.tr("Reglas instaladas: \(summary.fileCount) ficheros verificados (firma, hashes e inclusión en el registro de transparencia). No garantizan la ausencia de malware.",
                               "Rules installed: \(summary.fileCount) verified files (signature, hashes and transparency log inclusion). They do not guarantee the absence of malware."), summary.rulesRoot)
    }

    /// Re-verifies the rules installed on disk (signatures, hashes, no extra files).
    func verifyInstalled() throws -> ChannelVerifier.Summary { try installer.verifyInstalled() }

    /// Kept for tests of the archive policy; the installer uses the same extractor.
    func extractSafely(_ tarball: URL, into stage: URL) throws { try installer.extract(tarball, into: stage) }
}

// A YARA hit is a triage indicator, never an automatic malware verdict.
enum YARAScanner {
    static func inspect(_ candidates: [URL]) -> [AuditFinding] {
        let manager = YARARuleManager.shared
        // Only the signed, bundled scanner may be invoked. No Homebrew/PATH fallback.
        let engine = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/yara").path
        guard FileManager.default.isExecutableFile(atPath: engine) else {
            return [AuditFinding(title: "YARA engine unavailable", detail: "This build has no bundled YARA engine; scan skipped. Use a release with the engine included. No Homebrew installation is required.", state: .unknown, weight: 0)]
        }
        let verified = AuditEngine.command("/usr/bin/codesign", ["--verify", "--strict", engine])
        guard verified.0 == 0 else {
            return [AuditFinding(title: "YARA engine signature invalid", detail: "The bundled scanner failed code-signature verification; scan blocked.", state: .failed, weight: 0)]
        }
        let rules = manager.ruleFiles()
        guard !rules.isEmpty else { return [AuditFinding(title: "YARA rules", detail: "No rules installed.", state: .unknown, weight: 0)] }
        var findings: [AuditFinding] = []
        var tested = 0; var errors = 0; var hits = 0
        for rule in rules.prefix(40) {
            for file in candidates.prefix(30) {
                guard let attrs = try? FileManager.default.attributesOfItem(atPath: file.path),
                      let size = attrs[.size] as? NSNumber, size.int64Value <= 25_000_000 else { continue }
                let output = AuditEngine.command(engine, ["--timeout=5", rule.path, file.path])
                if output.0 == 0 {
                    tested += 1
                    if !output.1.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        hits += 1
                        if hits <= 30 { findings.append(AuditFinding(title: "YARA match", detail: "Rule file: \(rule.lastPathComponent), file: \(file.lastPathComponent). \(output.1.prefix(250))", state: .warning, weight: 0)) }
                    }
                } else { errors += 1 }
            }
        }
        findings.append(AuditFinding(title: "YARA scan coverage", detail: "\(tested) rule/file checks, \(hits) matches, \(errors) errors. Limits: first 40 rules and 30 files, max 25 MB/file; no recursive PKG payload extraction. A clean result does not prove safety.", state: errors > 0 || hits > 0 ? .warning : .unknown, weight: 0))
        return findings
    }
}
