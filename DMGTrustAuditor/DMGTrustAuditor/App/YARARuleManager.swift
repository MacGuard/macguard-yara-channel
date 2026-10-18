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
    private let maxArchiveBytes = 60 * 1024 * 1024
    private let maxExpandedBytes: Int64 = 160 * 1024 * 1024
    private let maxFiles = 10_000
    private let signatureCheck: ChannelVerifier.SignatureCheck?
    private let customRulesDirectory: URL?

    /// `signatureCheck` defaults to cosign when it is installed. Without a Sigstore verifier no release is accepted.
    init(channelBase: URL = YARARuleManager.defaultChannelBase,
         rulesDirectory: URL? = nil,
         signatureCheck: ChannelVerifier.SignatureCheck? = ChannelVerifier.findCosign().map { ChannelVerifier.cosignCheck(cosign: $0) }) {
        self.channelBase = channelBase
        self.customRulesDirectory = rulesDirectory
        self.signatureCheck = signatureCheck
        super.init()
        lastUpdate = UserDefaults.standard.object(forKey: "yaraLastUpdate") as? Date
        try? FileManager.default.createDirectory(at: self.rulesDirectory, withIntermediateDirectories: true)
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
    private static func session(timeout: TimeInterval) -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = timeout; c.timeoutIntervalForResource = timeout * 4
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: c)
    }
    private func get(_ name: String, limit: Int, timeout: TimeInterval = 10) async throws -> Data {
        let url = channelBase.appendingPathComponent(name)
        var request = URLRequest(url: url); request.setValue("DMGTrustAuditor/9.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await Self.session(timeout: timeout).data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url?.host == channelBase.host, data.count <= limit
        else { throw Failure(es: "El canal de reglas no respondió como se esperaba (\(name)). No se ha cambiado nada.", en: "The rules channel did not answer as expected (\(name)). Nothing was changed.") }
        return data
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
                publish {
                    self.message = f.map { AppLanguage.tr($0.es, $0.en) } ?? AppLanguage.failure("No se pudo comprobar si hay reglas nuevas. Se siguen usando las reglas actuales.", "Could not check for new rules. The current rules stay in use.", detail: error.localizedDescription)
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
        Task {
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
                self.downloading = false; self.message = result
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

    /// Download, extract in a private folder, verify, and only then swap the rules in.
    private func install() async throws -> (String, String) {
        guard let signatureCheck else {
            throw Failure(es: "Este equipo no puede comprobar la firma de las reglas (falta cosign), así que no se instala nada.", en: "This computer cannot verify the rules signature (cosign is missing), so nothing is installed.")
        }
        let fm = FileManager.default
        let base = rulesDirectory.deletingLastPathComponent()
        let stage = base.appendingPathComponent("stage-\(UUID().uuidString)", isDirectory: true)
        defer { try? fm.removeItem(at: stage) }
        try fm.createDirectory(at: stage.appendingPathComponent("logs"), withIntermediateDirectories: true)

        let archive = try await get("rules-release.tar.gz", limit: maxArchiveBytes, timeout: 30)
        publish { self.progress = 0.4 }
        for (name, limit) in [("manifest.json", 5_000_000), ("manifest.sigstore.json", 200_000), ("inclusion-proof.json", 200_000),
                              ("logs/checkpoint.txt", 10_000), ("logs/checkpoint.sigstore.json", 200_000)] {
            try await get(name, limit: limit).write(to: stage.appendingPathComponent(name))
        }
        publish { self.progress = 0.6 }

        let tarFile = stage.appendingPathComponent("rules-release.tar.gz")
        try archive.write(to: tarFile)
        try extractSafely(tarFile, into: stage)
        // The tarball's own manifest must be the one that was signed and published on the site.
        let siteManifest = try Data(contentsOf: stage.appendingPathComponent("manifest.json"))
        let tarManifest = try await get("manifest.json", limit: 5_000_000)
        guard siteManifest == tarManifest else { throw Failure(es: "El paquete de reglas no coincide con el manifiesto firmado.", en: "The rules package does not match the signed manifest.") }
        publish { self.progress = 0.8 }

        let summary: ChannelVerifier.Summary
        do { summary = try ChannelVerifier(signatureCheck: signatureCheck).verify(directory: stage) }
        catch let f as ChannelVerifier.Failure { throw Failure(es: "La verificación de la release ha fallado: no es de fiar.", en: "Release verification failed: it cannot be trusted.", detail: f.reason) }

        let current = rulesDirectory.appendingPathComponent("community")
        let backup = base.appendingPathComponent("community-backup-\(UUID().uuidString)")
        if fm.fileExists(atPath: current.path) { try fm.moveItem(at: current, to: backup) }
        do { try fm.moveItem(at: stage.appendingPathComponent("rules"), to: current); try? fm.removeItem(at: backup) }
        catch { if fm.fileExists(atPath: backup.path) { try? fm.moveItem(at: backup, to: current) }; throw error }
        return (AppLanguage.tr("Reglas instaladas: \(summary.fileCount) ficheros verificados (firma, hashes e inclusión en el registro de transparencia). No garantizan la ausencia de malware.",
                               "Rules installed: \(summary.fileCount) verified files (signature, hashes and transparency log inclusion). They do not guarantee the absence of malware."), summary.rulesRoot)
    }

    /// The archive is untrusted until verified: reject traversal, links and oversized content before and after extraction.
    func extractSafely(_ tarball: URL, into stage: URL) throws {
        let bad = Failure(es: "El paquete de reglas no es seguro.", en: "The rules package is not safe.")
        let listing = AuditEngine.command("/usr/bin/tar", ["-tvzf", tarball.path])
        guard listing.0 == 0, listing.1.utf8.count < 4_000_000 else { throw bad }
        let lines = listing.1.split(separator: "\n").map(String.init)
        guard lines.count <= maxFiles else { throw bad }
        for line in lines {
            guard let kind = line.first, kind == "-" || kind == "d" else { throw bad }   // no symlinks, hardlinks or devices
            let name = line.split(separator: " ", omittingEmptySubsequences: true).dropFirst(8).joined(separator: " ")
            let parts = name.split(separator: "/").map(String.init)
            guard !name.hasPrefix("/"), !name.contains("\\"), !parts.contains(".."), name == "manifest.json" || name.hasPrefix("rules") else { throw bad }
        }
        let out = AuditEngine.command("/usr/bin/tar", ["-xzf", tarball.path, "-C", stage.path, "--no-same-owner", "--no-same-permissions"])
        guard out.0 == 0 else { throw bad }
        var total: Int64 = 0
        for case let url as URL in fm_enumerator(stage) {
            let v = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            if v.isSymbolicLink == true { throw bad }
            total += Int64(v.fileSize ?? 0)
            if total > maxExpandedBytes { throw bad }
        }
    }
    private func fm_enumerator(_ url: URL) -> FileManager.DirectoryEnumerator {
        FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey], options: [])!
    }
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
