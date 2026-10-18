import Foundation
import CryptoKit

// v8: checks the upstream revision asynchronously on every launch, with an ETag cache.
// This is a COMMUNITY channel over HTTPS, NOT a signed MacGuard rules feed.
// User consent is mandatory before any archive download; no silent activation.
final class YARARuleManager: NSObject, ObservableObject, URLSessionDownloadDelegate {
    static let shared = YARARuleManager()
    @Published private(set) var downloading = false
    @Published private(set) var checking = false
    @Published private(set) var progress: Double = 0
    @Published private(set) var message = ""
    @Published private(set) var lastUpdate: Date?
    @Published private(set) var availableRevision: String?
    @Published private(set) var updateAvailable = false
    private var completion: ((String) -> Void)?
    private var session: URLSession?
    private var targetRevision: String?
    private let maxArchiveBytes: Int64 = 60 * 1024 * 1024
    private let maxExpandedBytes: Int64 = 160 * 1024 * 1024
    private let maxRules = 160
    private let repositoryAPI = URL(string: "https://api.github.com/repos/Neo23x0/signature-base/commits/master")!

    private override init() {
        super.init()
        lastUpdate = UserDefaults.standard.object(forKey: "yaraLastUpdate") as? Date
        try? FileManager.default.createDirectory(at: rulesDirectory, withIntermediateDirectories: true)
        installStarterRulesIfNeeded()
    }
    var rulesDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("DMGTrustAuditor/YARARules", isDirectory: true)
    }
    var isOutdated: Bool { updateAvailable || lastUpdate == nil }
    var installedCount: Int { ruleFiles().count }
    var engineURL: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/yara") }
    var engineReady: Bool {
        FileManager.default.isExecutableFile(atPath: engineURL.path) &&
        AuditEngine.command("/usr/bin/codesign", ["--verify", "--strict", engineURL.path]).0 == 0
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
    // Nonblocking check on EVERY launch; timeout does not delay the app UI.
    func checkForUpdates() {
        guard !checking && !downloading else { return }
        checking = true
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 3
        config.timeoutIntervalForResource = 4
        let etag = UserDefaults.standard.string(forKey: "yaraUpstreamETag")
        var request = URLRequest(url: repositoryAPI)
        request.setValue("DMGTrustAuditor/8.0", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        URLSession(configuration: config).dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                defer { self.checking = false }
                if let error { self.message = AppLanguage.failure("No se pudo comprobar si hay reglas nuevas. Se siguen usando las reglas actuales.", "Could not check for new rules. The current rules stay in use.", detail: error.localizedDescription); return }
                guard let response = response as? HTTPURLResponse else { self.message = AppLanguage.tr("El servidor devolvió una respuesta no válida. Se siguen usando las reglas actuales.", "The server returned an invalid response. The current rules stay in use."); return }
                if response.statusCode == 304 {
                    if let revision = UserDefaults.standard.string(forKey: "yaraKnownUpstreamRevision") {
                        self.availableRevision = revision
                        self.updateAvailable = revision != UserDefaults.standard.string(forKey: "yaraInstalledRevision")
                    }
                    return
                }
                guard response.statusCode == 200, response.url?.host == "api.github.com",
                      let data, data.count < 100_000,
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let revision = obj["sha"] as? String,
                      revision.range(of: "^[a-fA-F0-9]{40}$", options: .regularExpression) != nil else {
                    self.message = AppLanguage.tr("No se pudo verificar la información de la nueva versión. No se ha cambiado nada.", "The new revision information could not be verified. Nothing was changed."); return
                }
                if let newETag = response.value(forHTTPHeaderField: "ETag") {
                    UserDefaults.standard.set(newETag, forKey: "yaraUpstreamETag")
                }
                UserDefaults.standard.set(revision, forKey: "yaraKnownUpstreamRevision")
                self.availableRevision = revision
                self.updateAvailable = revision != UserDefaults.standard.string(forKey: "yaraInstalledRevision")
            }
        }.resume()
    }
    func update(completion: @escaping (String) -> Void) {
        guard !downloading else { return }
        guard let revision = availableRevision,
              revision.range(of: "^[a-fA-F0-9]{40}$", options: .regularExpression) != nil else {
            message = AppLanguage.tr("Aún no hay una versión verificada. Busca actualizaciones primero.", "There is no verified revision yet. Check for updates first.")
            completion(message); return
        }
        guard engineReady else {
            message = AppLanguage.tr("Falta el motor YARA firmado incluido en la app, así que no se pueden validar ni activar reglas. Usa la versión oficial de la app.", "The signed YARA engine bundled with the app is missing, so rules cannot be validated or activated. Use the official app release.")
            completion(message); return
        }
        targetRevision = revision
        self.completion = completion
        downloading = true; progress = 0; message = AppLanguage.tr("Descargando la versión fijada de las reglas…", "Downloading the pinned rules revision…")
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForResource = 120
        let s = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        session = s
        let archive = URL(string: "https://codeload.github.com/Neo23x0/signature-base/zip/\(revision)")!
        s.downloadTask(with: archive).resume()
    }
    private func finish(_ result: String, success: Bool) {
        DispatchQueue.main.async {
            self.downloading = false
            self.message = result
            if success {
                self.lastUpdate = Date()
                self.updateAvailable = false
                UserDefaults.standard.set(self.lastUpdate, forKey: "yaraLastUpdate")
                UserDefaults.standard.set(self.targetRevision, forKey: "yaraInstalledRevision")
            }
            self.completion?(result)
            self.completion = nil
            self.session?.finishTasksAndInvalidate(); self.session = nil
        }
    }
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        guard let revision = targetRevision else { finish(AppLanguage.tr("Falta la versión fijada de las reglas. No se ha cambiado nada.", "The pinned rules revision is missing. Nothing was changed."), success: false); return }
        let fm = FileManager.default
        let base = rulesDirectory.deletingLastPathComponent()
        let stage = base.appendingPathComponent("stage-\(UUID().uuidString)")
        let incoming = base.appendingPathComponent("incoming-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: stage); try? fm.removeItem(at: incoming) }
        guard let response = downloadTask.response as? HTTPURLResponse,
              response.statusCode == 200, response.url?.host == "codeload.github.com" else {
            finish(AppLanguage.tr("La descarga no vino del servidor esperado o la respuesta no fue válida. Las reglas no han cambiado.", "The download did not come from the expected server or the response was invalid. The rules were not changed."), success: false); return
        }
        guard let bytes = (try? fm.attributesOfItem(atPath: location.path)[.size] as? NSNumber)?.int64Value,
              bytes > 0 && bytes <= maxArchiveBytes else {
            finish(AppLanguage.tr("El archivo descargado supera el tamaño máximo permitido. Las reglas no han cambiado.", "The downloaded archive exceeds the maximum allowed size. The rules were not changed."), success: false); return
        }
        do {
            try fm.createDirectory(at: stage, withIntermediateDirectories: true)
            try fm.createDirectory(at: incoming, withIntermediateDirectories: true)
            // Reject traversal paths before extraction. Archive metadata is untrusted.
            let listing = AuditEngine.command("/usr/bin/unzip", ["-Z", "-1", location.path])
            guard listing.0 == 0 && listing.1.utf8.count < 2_000_000 else {
                throw NSError(domain: "YARA", code: 7, userInfo: [NSLocalizedDescriptionKey: "Cannot inspect archive entries"])
            }
            let paths = listing.1.split(separator: "\n").map(String.init)
            guard paths.count <= 10000 && paths.allSatisfy({ item in
                !item.hasPrefix("/") && !item.contains("\\") && !item.split(separator: "/").contains("..") &&
                item.hasPrefix("signature-base-\(revision)/")
            }) else {
                throw NSError(domain: "YARA", code: 8, userInfo: [NSLocalizedDescriptionKey: "Unsafe archive paths"])
            }
            // Archive extraction occurs in a unique private staging folder, never in the app bundle.
            let unzip = AuditEngine.command("/usr/bin/ditto", ["-x", "-k", location.path, stage.path])
            guard unzip.0 == 0 else { throw NSError(domain: "YARA", code: 1, userInfo: [NSLocalizedDescriptionKey: "Archive extraction failed"]) }
            let root = stage.appendingPathComponent("signature-base-\(revision)")
            let source = root.appendingPathComponent("yara")
            guard fm.fileExists(atPath: source.path) else { throw NSError(domain: "YARA", code: 2, userInfo: [NSLocalizedDescriptionKey: "Missing YARA rules directory"]) }
            let all = (fm.enumerator(at: stage, includingPropertiesForKeys: [.isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey], options: [])?.allObjects as? [URL] ?? [])
            var total: Int64 = 0
            for entry in all {
                let values = try entry.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey])
                if values.isSymbolicLink == true { throw NSError(domain: "YARA", code: 3, userInfo: [NSLocalizedDescriptionKey: "Archive contains symlinks"]) }
                if values.isRegularFile == true { total += Int64(values.fileSize ?? 0) }
                if total > maxExpandedBytes || all.count > 10000 { throw NSError(domain: "YARA", code: 4, userInfo: [NSLocalizedDescriptionKey: "Expanded archive exceeds limits"]) }
            }
            let candidates = all.filter { $0.path.hasPrefix(source.path + "/") && ["yar", "yara"].contains($0.pathExtension.lowercased()) }.sorted { $0.path < $1.path }
            guard !candidates.isEmpty else { throw NSError(domain: "YARA", code: 5, userInfo: [NSLocalizedDescriptionKey: "No rules found"]) }
            let probe = incoming.appendingPathComponent("empty-test-input")
            try Data().write(to: probe)
            var valid = 0; var rejected = 0
            // Every activated rule is syntax-tested with the signed bundled engine.
            for (index, rule) in candidates.prefix(maxRules).enumerated() {
                let data = try Data(contentsOf: rule)
                guard data.count <= 1_000_000 else { rejected += 1; continue }
                let candidate = incoming.appendingPathComponent("rule-\(index).yar")
                try data.write(to: candidate)
                let check = AuditEngine.command(engineURL.path, ["--timeout=5", candidate.path, probe.path])
                if check.0 == 0 { valid += 1 } else { rejected += 1; try? fm.removeItem(at: candidate) }
                DispatchQueue.main.async { self.progress = 0.8 + 0.19 * Double(index + 1) / Double(min(candidates.count, self.maxRules)) }
            }
            try? fm.removeItem(at: probe)
            guard valid > 0 else { throw NSError(domain: "YARA", code: 6, userInfo: [NSLocalizedDescriptionKey: "No rules passed engine validation; previous rules preserved"]) }
            let current = rulesDirectory.appendingPathComponent("community")
            let backup = base.appendingPathComponent("community-backup-\(UUID().uuidString)")
            if fm.fileExists(atPath: current.path) { try fm.moveItem(at: current, to: backup) }
            do { try fm.moveItem(at: incoming, to: current); try? fm.removeItem(at: backup) }
            catch { if fm.fileExists(atPath: backup.path) { try? fm.moveItem(at: backup, to: current) }; throw error }
            finish(AppLanguage.tr("Reglas instaladas: \(valid) ficheros compatibles (\(rejected) rechazados; \(max(0, candidates.count-maxRules)) sin evaluar). Proceden de GitHub por HTTPS y no tienen un manifiesto firmado; no garantizan la ausencia de malware.", "Rules installed: \(valid) compatible files (\(rejected) rejected; \(max(0, candidates.count-maxRules)) not assessed). They come from GitHub over HTTPS without a signed manifest; they do not guarantee the absence of malware."), success: true)
        } catch { finish(AppLanguage.failure("La actualización ha fallado y se conservan las reglas anteriores.", "The update failed and the previous rules were kept.", detail: error.localizedDescription), success: false) }
    }
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        DispatchQueue.main.async {
            self.progress = totalBytesExpectedToWrite > 0 ? min(0.8, 0.8 * Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)) : 0
        }
        if totalBytesWritten > maxArchiveBytes { downloadTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(AppLanguage.failure("La descarga ha fallado y se conservan las reglas actuales.", "The download failed and the current rules were kept.", detail: error.localizedDescription), success: false) }
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
