import Foundation
import CryptoKit

/// Transactional installer for the signed rules channel:
///   latest.json -> download -> staging -> safe extraction -> verification -> atomic activation.
///
/// Guarantees (each one has a test in ChannelUpdateTests / RuleInstallerTests):
///  * the live rules are replaced only by a release that passed signature, hashes, rules_root, log inclusion,
///    anti-rollback and log-consistency checks; any failure leaves the live rules untouched;
///  * one update at a time across threads and processes (flock);
///  * activation is two renames inside one volume, journalled, and `recoverIfNeeded()` restores the previous
///    version if the process died between them;
///  * downloads are streamed to disk with a hard byte cap, extraction has entry/size/depth/time caps;
///  * the previous version is kept in `ChannelState/previous` after every successful update.
final class RuleInstaller {
    typealias Failure = YARARuleManager.Failure

    struct Limits {
        var maxArchiveBytes: Int64 = 60 * 1024 * 1024
        var maxLogBytes: Int64 = 20 * 1024 * 1024
        var archive = ArchiveLimits(maxEntries: 10_000, maxExpandedBytes: 160 * 1024 * 1024, maxPathDepth: 16, maxNameBytes: 512, maxArchiveBytes: 60 * 1024 * 1024, timeout: 60)
    }

    let channelBases: [URL]
    let rulesDirectory: URL
    let stateDirectory: URL
    let signatureCheck: ChannelVerifier.SignatureCheck?
    let signatureUnavailableReason: String
    let trustStore: TrustStore
    let limits: Limits
    /// Free bytes on the volume; injectable so disk-full handling can be tested.
    var availableSpace: () -> Int64 = {
        let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return (try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]))?.volumeAvailableCapacityForImportantUsage ?? Int64.max
    }
    /// Test hook: called after the first rename of the activation, to simulate a crash.
    var afterFirstRename: (() throws -> Void)?

    var liveDirectory: URL { rulesDirectory.appendingPathComponent("community", isDirectory: true) }
    var previousDirectory: URL { stateDirectory.appendingPathComponent("previous", isDirectory: true) }
    private var journalURL: URL { stateDirectory.appendingPathComponent("journal.json") }
    private var lockURL: URL { stateDirectory.appendingPathComponent("update.lock") }

    init(channelBases: [URL], rulesDirectory: URL, signatureCheck: ChannelVerifier.SignatureCheck?, signatureUnavailableReason: String = "",
         trustStore: TrustStore, limits: Limits = Limits()) {
        self.channelBases = channelBases; self.rulesDirectory = rulesDirectory
        self.stateDirectory = rulesDirectory.deletingLastPathComponent().appendingPathComponent("ChannelState", isDirectory: true)
        self.signatureCheck = signatureCheck; self.signatureUnavailableReason = signatureUnavailableReason
        self.trustStore = trustStore; self.limits = limits
    }

    // MARK: Locking
    private final class Lock {
        let fd: Int32
        init?(path: String) { fd = open(path, O_CREAT | O_RDWR, 0o600); if fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0 { if fd >= 0 { close(fd) }; return nil } }
        deinit { flock(fd, LOCK_UN); close(fd) }
    }

    // MARK: Recovery
    /// Safe to call at any time; does nothing while another update holds the lock.
    func recoverIfNeeded() {
        let fm = FileManager.default
        try? fm.createDirectory(at: stateDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard let lock = Lock(path: lockURL.path) else { return }
        _ = lock
        if fm.fileExists(atPath: journalURL.path) {
            if !fm.fileExists(atPath: liveDirectory.path), fm.fileExists(atPath: previousDirectory.path) {
                try? fm.moveItem(at: previousDirectory, to: liveDirectory)   // died between the two renames: go back
            }
            try? fm.removeItem(at: journalURL)
        }
        for item in (try? fm.contentsOfDirectory(at: stateDirectory, includingPropertiesForKeys: nil)) ?? [] where item.lastPathComponent.hasPrefix("stage-") {
            try? fm.removeItem(at: item)
        }
    }

    // MARK: Network
    private final class Download: NSObject, URLSessionDownloadDelegate {
        let limit: Int64; let dest: URL; var exceeded = false; var failure: Error?
        var cont: CheckedContinuation<Void, Error>?
        init(limit: Int64, dest: URL) { self.limit = limit; self.dest = dest }
        func urlSession(_ s: URLSession, downloadTask t: URLSessionDownloadTask, didWriteData _: Int64, totalBytesWritten w: Int64, totalBytesExpectedToWrite e: Int64) {
            if w > limit || e > limit { exceeded = true; t.cancel() }
        }
        func urlSession(_ s: URLSession, downloadTask t: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
            do {
                if let http = t.response as? HTTPURLResponse, http.statusCode != 200 { failure = URLError(.badServerResponse); return }
                try? FileManager.default.removeItem(at: dest)
                try FileManager.default.moveItem(at: location, to: dest)
            } catch { failure = error }
        }
        func urlSession(_ s: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
            if exceeded { cont?.resume(throwing: URLError(.dataLengthExceedsMaximum)) }
            else if let error { cont?.resume(throwing: error) }
            else if let failure { cont?.resume(throwing: failure) }
            else { cont?.resume() }
            cont = nil
        }
    }

    struct NetworkFailure: Error { let name: String; let underlying: Error }

    func fetch(_ name: String, from base: URL, to dest: URL, limit: Int64, timeout: TimeInterval = 15) async throws {
        let url = base.appendingPathComponent(name)
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = timeout; c.timeoutIntervalForResource = timeout * 8
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        var request = URLRequest(url: url); request.setValue("DMGTrustAuditor/9.0", forHTTPHeaderField: "User-Agent")
        let delegate = Download(limit: limit, dest: dest)
        let session = URLSession(configuration: c, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let task = session.downloadTask(with: request)
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (k: CheckedContinuation<Void, Error>) in delegate.cont = k; task.resume() }
            } onCancel: { task.cancel() }
        } catch { throw NetworkFailure(name: name, underlying: error) }
        // The final URL after redirects must stay on the channel's host.
        if let final = task.response?.url, final.host != base.host { try? FileManager.default.removeItem(at: dest); throw NetworkFailure(name: name, underlying: URLError(.badURL)) }
    }

    func fetchData(_ name: String, limit: Int64, timeout: TimeInterval = 10) async throws -> Data {
        var last: Error?
        for base in channelBases {
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("fetch-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: tmp) }
            do { try await fetch(name, from: base, to: tmp, limit: limit, timeout: timeout); return try Data(contentsOf: tmp) }
            catch { last = error }
        }
        throw Failure(es: "El canal de reglas no respondió como se esperaba (\(name)). No se ha cambiado nada.", en: "The rules channel did not answer as expected (\(name)). Nothing was changed.", detail: last.map { "\($0)" })
    }

    // MARK: Install
    struct Installed { let summary: ChannelVerifier.Summary }

    func install(progress: @escaping (Double) -> Void = { _ in }) async throws -> ChannelVerifier.Summary {
        let fm = FileManager.default
        try fm.createDirectory(at: stateDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard let lock = Lock(path: lockURL.path) else {
            throw Failure(es: "Ya hay otra actualización de reglas en curso. Espera a que termine.", en: "Another rules update is already running. Wait for it to finish.")
        }
        _ = lock
        recoverUnderLock()
        guard let signatureCheck else {
            throw Failure(es: "Este equipo no puede comprobar la firma de las reglas (falta el verificador Sigstore incluido), así que no se instala nada.", en: "This computer cannot verify the rules signature (the bundled Sigstore verifier is missing), so nothing is installed.", detail: signatureUnavailableReason)
        }
        let need = limits.maxArchiveBytes + limits.archive.maxExpandedBytes * 2
        if availableSpace() < need {
            throw Failure(es: "No hay espacio libre suficiente en el disco para actualizar las reglas. Se conservan las anteriores.", en: "There is not enough free disk space to update the rules. The previous ones were kept.")
        }
        let prior: TrustState?
        do { prior = try trustStore.load() }
        catch { throw Failure(es: "El estado de confianza guardado está dañado; no se instala nada hasta repararlo.", en: "The saved trust state is damaged; nothing is installed until it is repaired.", detail: "\(error)") }

        var lastNetwork: Error?
        for base in channelBases {
            let stage = stateDirectory.appendingPathComponent("stage-\(UUID().uuidString)", isDirectory: true)
            defer { try? fm.removeItem(at: stage) }
            do {
                try fm.createDirectory(at: stage.appendingPathComponent("logs"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                return try await installFrom(base, stage: stage, prior: prior, signatureCheck: signatureCheck, progress: progress)
            } catch let e as NetworkFailure {
                lastNetwork = e   // try the next authorized origin; verification failures never fall through
            }
        }
        throw Failure(es: "No se pudo descargar la release del canal. Se conservan las reglas anteriores.", en: "The release could not be downloaded from the channel. The previous rules were kept.", detail: lastNetwork.map { "\($0)" })
    }

    private func recoverUnderLock() {
        let fm = FileManager.default
        if fm.fileExists(atPath: journalURL.path) {
            if !fm.fileExists(atPath: liveDirectory.path), fm.fileExists(atPath: previousDirectory.path) { try? fm.moveItem(at: previousDirectory, to: liveDirectory) }
            try? fm.removeItem(at: journalURL)
        }
        for item in (try? fm.contentsOfDirectory(at: stateDirectory, includingPropertiesForKeys: nil)) ?? [] where item.lastPathComponent.hasPrefix("stage-") { try? fm.removeItem(at: item) }
    }

    private func installFrom(_ base: URL, stage: URL, prior: TrustState?, signatureCheck: @escaping ChannelVerifier.SignatureCheck, progress: (Double) -> Void) async throws -> ChannelVerifier.Summary {
        let fm = FileManager.default
        let tarball = stage.appendingPathComponent("rules-release.tar.gz")
        try await fetch("rules-release.tar.gz", from: base, to: tarball, limit: limits.maxArchiveBytes, timeout: 30)
        progress(0.4)
        for (name, limit) in [("manifest.json", Int64(5_000_000)), ("manifest.sigstore.json", 200_000), ("inclusion-proof.json", 200_000),
                              ("logs/checkpoint.txt", 10_000), ("logs/checkpoint.sigstore.json", 200_000), ("logs/log.jsonl", limits.maxLogBytes)] {
            try await fetch(name, from: base, to: stage.appendingPathComponent(name), limit: limit)
        }
        try Task.checkCancellation()
        progress(0.6)

        // The tarball is a transport for the rules only; it is unpacked into its own folder, never over the signed files.
        let unpacked = stage.appendingPathComponent("unpacked", isDirectory: true)
        try extract(tarball, into: unpacked)
        let siteManifest = try Data(contentsOf: stage.appendingPathComponent("manifest.json"))
        guard (try? Data(contentsOf: unpacked.appendingPathComponent("manifest.json"))) == siteManifest else {
            throw Failure(es: "El paquete de reglas no coincide con el manifiesto firmado.", en: "The rules package does not match the signed manifest.")
        }
        try fm.moveItem(at: unpacked.appendingPathComponent("rules"), to: stage.appendingPathComponent("rules"))
        progress(0.8)
        try Task.checkCancellation()

        let verifier = ChannelVerifier(signatureCheck: signatureCheck)
        let logData = try? Data(contentsOf: stage.appendingPathComponent("logs/log.jsonl"))
        let summary: ChannelVerifier.Summary
        do { summary = try verifier.verify(directory: stage, prior: prior, logData: logData) }
        catch let f as ChannelVerifier.Failure { throw Failure(es: "La verificación de la release ha fallado: no es de fiar.", en: "Release verification failed: it cannot be trusted.", detail: f.reason) }

        // Everything the app trusts now lives in a private folder; build the final layout there.
        let community = stage.appendingPathComponent("community", isDirectory: true)
        try fm.moveItem(at: stage.appendingPathComponent("rules"), to: community)
        let meta = community.appendingPathComponent(".release", isDirectory: true)
        try fm.createDirectory(at: meta.appendingPathComponent("logs"), withIntermediateDirectories: true)
        for name in ["manifest.json", "manifest.sigstore.json", "inclusion-proof.json", "logs/checkpoint.txt", "logs/checkpoint.sigstore.json"] {
            try fm.copyItem(at: stage.appendingPathComponent(name), to: meta.appendingPathComponent(name))
        }
        // Re-hash right before activation: what is activated is what was verified (no check/use gap).
        do { try verifier.recheckFiles(manifestAt: meta.appendingPathComponent("manifest.json"), rulesDirectory: community) }
        catch let f as ChannelVerifier.Failure { throw Failure(es: "Las reglas cambiaron durante la instalación. Se conservan las anteriores.", en: "The rules changed during installation. The previous ones were kept.", detail: f.reason) }
        try Task.checkCancellation()

        // The log head is evidence even if activation fails below, so remember it first.
        try trustStore.save(TrustState(origin: ChannelVerifier.logOrigin, size: summary.logSize, root: summary.logRoot, rulesRoot: summary.rulesRoot, updatedAt: Date()))
        try activate(community)
        progress(1)
        return summary
    }

    /// Two renames inside one volume, with a journal so a crash between them is undone on the next start.
    private func activate(_ newLive: URL) throws {
        let fm = FileManager.default
        try Data("{\"phase\":\"swap\"}".utf8).write(to: journalURL, options: .atomic)
        if fm.fileExists(atPath: previousDirectory.path) { try fm.removeItem(at: previousDirectory) }
        let hadLive = fm.fileExists(atPath: liveDirectory.path)
        if hadLive { try fm.moveItem(at: liveDirectory, to: previousDirectory) }
        do {
            try afterFirstRename?()
            try fm.moveItem(at: newLive, to: liveDirectory)
        } catch {
            if hadLive, !fm.fileExists(atPath: liveDirectory.path) { try? fm.moveItem(at: previousDirectory, to: liveDirectory) }
            try? fm.removeItem(at: journalURL)
            throw error
        }
        try? fm.removeItem(at: journalURL)
    }

    /// Extraction plus the release layout policy: only `manifest.json` and `rules/`, no hidden entries, no links.
    func extract(_ tarball: URL, into dir: URL) throws {
        let bad = Failure(es: "El paquete de reglas descargado no es seguro y se ha rechazado.", en: "The downloaded rules package is not safe and was rejected.")
        do {
            let r = try ArchiveExtractor.extract(tarball, into: dir, limits: limits.archive, cancelled: { Task.isCancelled })
            if !r.removedLinks.isEmpty { throw Failure(es: bad.es, en: bad.en, detail: "archive contained links") }
        } catch let f as ArchiveExtractor.Failure { throw Failure(es: bad.es, en: bad.en, detail: f.reason) }
        // Only these two top-level entries are allowed.
        let top = Set((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [])
        guard top == ["manifest.json", "rules"] else { throw Failure(es: bad.es, en: bad.en, detail: "unexpected top-level entries: \(top.sorted())") }
        guard let en = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil) else { return }
        for case let u as URL in en where u.lastPathComponent.hasPrefix(".") { throw Failure(es: bad.es, en: bad.en, detail: "hidden entry \(u.lastPathComponent)") }
    }

    // MARK: Installed state
    /// Re-verifies what is installed on disk: signed manifest and checkpoint, every file hash, no extra rule files,
    /// and that the log head is not newer than... (the trust state may be ahead; the installed head may never be ahead of it).
    func verifyInstalled() throws -> ChannelVerifier.Summary {
        guard let signatureCheck else { throw ChannelVerifier.Failure(reason: "no Sigstore verifier available: \(signatureUnavailableReason)") }
        let meta = liveDirectory.appendingPathComponent(".release", isDirectory: true)
        guard FileManager.default.fileExists(atPath: meta.appendingPathComponent("manifest.json").path) else {
            throw ChannelVerifier.Failure(reason: "no verified channel release is installed (only local starter rules, if any)")
        }
        let summary = try ChannelVerifier(signatureCheck: signatureCheck).verify(directory: meta, rulesDirectory: liveDirectory, allowExtraRuleFiles: false)
        if let trust = try trustStore.load(), summary.logSize > trust.size {
            throw ChannelVerifier.Failure(reason: "installed release is newer than the trusted log head (trust state was reset or tampered with)")
        }
        return summary
    }
}
