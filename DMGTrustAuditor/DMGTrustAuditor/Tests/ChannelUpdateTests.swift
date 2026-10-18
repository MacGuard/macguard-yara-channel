import XCTest
@testable import DMGTrustAuditor

/// Runs the manager against a real local HTTP server serving a sample channel layout.
final class ChannelUpdateTests: XCTestCase {
    var root: URL!, site: URL!, support: URL!
    var server: Process?
    var port = 0

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("cu-\(UUID().uuidString)", isDirectory: true)
        site = root.appendingPathComponent("site"); support = root.appendingPathComponent("support/YARARules")
        let release = root.appendingPathComponent("release")
        try FileManager.default.createDirectory(at: site.appendingPathComponent("logs"), withIntermediateDirectories: true)
        try buildSampleRelease(in: release)
        try AuditEngine.run("/usr/bin/tar", ["-czf", site.appendingPathComponent("rules-release.tar.gz").path, "-C", release.path, "rules", "manifest.json"])
        for f in ["manifest.json", "manifest.sigstore.json", "inclusion-proof.json"] { try FileManager.default.copyItem(at: release.appendingPathComponent(f), to: site.appendingPathComponent(f)) }
        for f in ["checkpoint.txt", "checkpoint.sigstore.json", "log.jsonl"] { try FileManager.default.copyItem(at: release.appendingPathComponent("logs/\(f)"), to: site.appendingPathComponent("logs/\(f)")) }
        let m = try JSONSerialization.jsonObject(with: Data(contentsOf: site.appendingPathComponent("manifest.json"))) as! [String: Any]
        try JSONSerialization.data(withJSONObject: ["schema": 1, "rules_root": m["rules_root"]!]).write(to: site.appendingPathComponent("latest.json"))
        port = Int.random(in: 20000...40000)
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-m", "http.server", "\(port)", "--bind", "127.0.0.1", "--directory", site.path]
        p.standardOutput = Pipe(); p.standardError = Pipe()
        try p.run(); server = p
        let up = expectation(description: "server up")
        DispatchQueue.global().async {
            for _ in 0..<250 { if (try? Data(contentsOf: URL(string: "http://127.0.0.1:\(self.port)/latest.json")!)) != nil { up.fulfill(); return }; Thread.sleep(forTimeInterval: 0.1) }
        }
        wait(for: [up], timeout: 30)
    }
    override func tearDownWithError() throws { server?.terminate(); try? FileManager.default.removeItem(at: root) }

    func manager(check: @escaping ChannelVerifier.SignatureCheck, trust: TrustStore = MemoryTrustStore()) -> YARARuleManager {
        YARARuleManager(channelBase: URL(string: "http://127.0.0.1:\(port)/")!, rulesDirectory: support, trustStore: trust, signatureCheck: check)
    }
    func checkAndUpdate(_ m: YARARuleManager) -> String {
        let checked = expectation(description: "checked")
        m.checkForUpdates()
        DispatchQueue.global().async { for _ in 0..<80 where m.checking || !m.updateAvailable { Thread.sleep(forTimeInterval: 0.1) }; checked.fulfill() }
        wait(for: [checked], timeout: 10)
        var result = ""
        let done = expectation(description: "updated")
        m.update { result = $0; done.fulfill() }
        wait(for: [done], timeout: 20)
        return result
    }
    var installed: URL { support.appendingPathComponent("community/src/x.yar") }

    func testProductionManagerUsesGitHubPagesFirstThenTheCloudflareMirror() {
        let hosts = YARARuleManager.shared.installer.channelBases.map { $0.host ?? "" }
        XCTAssertEqual(hosts, ["macguard.github.io", "macguard-rules.pages.dev"])
        XCTAssertTrue(YARARuleManager.shared.installer.channelBases.allSatisfy { $0.scheme == "https" })
    }

    func testVerifiedReleaseIsInstalled() {
        UserDefaults.standard.removeObject(forKey: "yaraInstalledRulesRoot")
        let m = manager { _, _ in nil }
        XCTAssertTrue(checkAndUpdateWithAvailability(m).contains("1"), "update message should report installed files")
        XCTAssertTrue(FileManager.default.fileExists(atPath: installed.path))
    }
    private func checkAndUpdateWithAvailability(_ m: YARARuleManager) -> String { checkAndUpdate(m) }

    func testBadSignatureInstallsNothing() {
        UserDefaults.standard.removeObject(forKey: "yaraInstalledRulesRoot")
        let m = manager { _, _ in "certificate identity mismatch" }
        let msg = checkAndUpdate(m)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path), msg)
    }
    func testMissingVerifierInstallsNothing() {
        UserDefaults.standard.removeObject(forKey: "yaraInstalledRulesRoot")
        let m = YARARuleManager(channelBase: URL(string: "http://127.0.0.1:\(port)/")!, rulesDirectory: support, trustStore: MemoryTrustStore(), signatureCheck: nil, useStandardVerifier: false)
        _ = checkAndUpdate(m)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path))
    }
    func testTarballThatDoesNotMatchTheSignedManifestIsRejected() throws {
        UserDefaults.standard.removeObject(forKey: "yaraInstalledRulesRoot")
        // Tamper with the rule inside the tarball while the signed manifest stays the same.
        let bad = root.appendingPathComponent("bad"); try FileManager.default.createDirectory(at: bad, withIntermediateDirectories: true)
        try AuditEngine.run("/usr/bin/tar", ["-xzf", site.appendingPathComponent("rules-release.tar.gz").path, "-C", bad.path])
        try Data("rule x { condition: false }".utf8).write(to: bad.appendingPathComponent("rules/src/x.yar"))
        try AuditEngine.run("/usr/bin/tar", ["-czf", site.appendingPathComponent("rules-release.tar.gz").path, "-C", bad.path, "rules", "manifest.json"])
        let m = manager { _, _ in nil }
        _ = checkAndUpdate(m)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path))
    }
    func testArchiveWithSymlinkOrTraversalIsRefused() throws {
        let m = manager { _, _ in nil }
        let evil = root.appendingPathComponent("evil"); try FileManager.default.createDirectory(at: evil.appendingPathComponent("rules"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: evil.appendingPathComponent("rules/link").path, withDestinationPath: "/etc/passwd")
        try Data("{}".utf8).write(to: evil.appendingPathComponent("manifest.json"))
        let tar = root.appendingPathComponent("evil.tar.gz")
        try AuditEngine.run("/usr/bin/tar", ["-czf", tar.path, "-C", evil.path, "rules", "manifest.json"])
        let stage = root.appendingPathComponent("stage"); try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: true)
        XCTAssertThrowsError(try m.extractSafely(tar, into: stage))
        XCTAssertFalse(FileManager.default.fileExists(atPath: stage.appendingPathComponent("rules/link").path))
        // A path outside rules/ is refused too.
        try Data("x".utf8).write(to: evil.appendingPathComponent("other.txt"))
        let tar2 = root.appendingPathComponent("evil2.tar.gz")
        try AuditEngine.run("/usr/bin/tar", ["-czf", tar2.path, "-C", evil.path, "other.txt"])
        XCTAssertThrowsError(try m.extractSafely(tar2, into: stage))
    }
}

/// Opt-in end to end check against the live site with the real cosign: MACGUARD_LIVE=1.
final class LiveChannelTests: XCTestCase {
    func testLiveChannelInstallsWithRealSignatures() throws {
        guard ProcessInfo.processInfo.environment["MACGUARD_LIVE"] == "1", SigstoreVerifier.standard().check != nil else { throw XCTSkip("set MACGUARD_LIVE=1 and install cosign") }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("live-\(UUID().uuidString)/YARARules")
        defer { try? FileManager.default.removeItem(at: dir.deletingLastPathComponent()) }
        UserDefaults.standard.removeObject(forKey: "yaraInstalledRulesRoot")
        let m = YARARuleManager(rulesDirectory: dir, trustStore: MemoryTrustStore())
        let checked = expectation(description: "checked"); m.checkForUpdates()
        DispatchQueue.global().async { for _ in 0..<100 where m.checking || !m.updateAvailable { Thread.sleep(forTimeInterval: 0.1) }; checked.fulfill() }
        wait(for: [checked], timeout: 20)
        var result = ""; let done = expectation(description: "updated"); m.update { result = $0; done.fulfill() }
        wait(for: [done], timeout: 240)
        XCTAssertTrue(result.contains("1184"), result)
        XCTAssertGreaterThan(m.ruleFiles().count, 1000)
    }
}
