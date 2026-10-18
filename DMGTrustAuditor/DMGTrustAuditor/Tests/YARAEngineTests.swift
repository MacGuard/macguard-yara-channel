import XCTest
@testable import DMGTrustAuditor

/// Tests of the engine that ships with MacGuard, with the real binaries built by Scripts/build-yara-engine.sh.
/// Set MACGUARD_YARA_DIR (TEST_RUNNER_MACGUARD_YARA_DIR for xcodebuild) to that build. Without it these tests are SKIPPED and the
/// skip is reported: a skipped test proves nothing about the engine.
final class YARAEngineTests: XCTestCase {
    private var tmp: URL!
    override func setUpWithError() throws { tmp = FileManager.default.temporaryDirectory.appendingPathComponent("ye-\(UUID().uuidString)", isDirectory: true); try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true) }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: tmp); YARAEngine.reset() }

    private func engineDir() throws -> URL {
        guard let d = ProcessInfo.processInfo.environment["MACGUARD_YARA_DIR"] else { throw XCTSkip("MACGUARD_YARA_DIR is not set: build the engine with Scripts/build-yara-engine.sh") }
        return URL(fileURLWithPath: d)
    }
    private func engine() throws -> YARAEngine.Located {
        let s = YARAEngine.verify(try engineDir()); return try XCTUnwrap(s.located, "the engine under test is not trustworthy: \(s.reason)")
    }
    private func copyEngine() throws -> URL {
        let dst = tmp.appendingPathComponent("engine-copy"); try FileManager.default.copyItem(at: try engineDir(), to: dst); return dst
    }
    private func manifest(_ dir: URL) throws -> [String: Any] { try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("engine-manifest.json"))) as! [String: Any] }
    private func write(_ m: [String: Any], _ dir: URL) throws { try JSONSerialization.data(withJSONObject: m).write(to: dir.appendingPathComponent("engine-manifest.json")) }
    private func rulesDir(_ files: [String: String]) throws -> YARAEngine.RuleSet {
        let d = tmp.appendingPathComponent("rules-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        for (n, t) in files { try FileManager.default.createDirectory(at: d.appendingPathComponent(n).deletingLastPathComponent(), withIntermediateDirectories: true); try t.write(to: d.appendingPathComponent(n), atomically: true, encoding: .utf8) }
        return YARAEngine.ruleSet(in: d)
    }
    private func sample(_ text: String, name: String = UUID().uuidString) throws -> URL { let u = tmp.appendingPathComponent(name); try text.write(to: u, atomically: true, encoding: .utf8); return u }
    private func scan(_ files: [URL], _ rules: YARAEngine.RuleSet, timeout: TimeInterval = 120) throws -> YARAEngine.Outcome {
        try XCTUnwrap(YARAEngine.scan(files, rules: rules, engine: try engine(), cacheDirectory: tmp.appendingPathComponent("cache"), timeout: timeout))
    }

    // MARK: trust in the engine itself
    func testTheBuiltEngineIsTrustedAndSelfTested() throws {
        let e = try engine()
        XCTAssertTrue(YARAEngine.versionAtLeast(e.manifest.version.split(separator: ".").compactMap { Int($0) }, YARAEngine.minimumVersion))
        XCTAssertTrue(e.manifest.architectures.contains(YARAEngine.currentArchitecture()), e.manifest.architectures)
    }
    func testTheEngineIsUniversalForIntelAndAppleSilicon() throws {
        let e = try engine(); let archs = AuditEngine.command("/usr/bin/lipo", ["-archs", e.yara.path]).1
        XCTAssertTrue(archs.contains("arm64") && archs.contains("x86_64"), "universal binary expected, got: \(archs)")
        XCTAssertTrue(AuditEngine.command("/usr/bin/lipo", ["-archs", e.yarac.path]).1.contains("x86_64"))
        XCTAssertEqual(AuditEngine.command("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", e.yara.path]).0, 0)
        XCTAssertTrue(AuditEngine.command("/usr/bin/codesign", ["-d", "--verbose=2", e.yara.path]).1.contains("runtime"), "hardened runtime flag")
    }
    func testAnEngineBinaryChangedAfterTheBuildIsRefused() throws {
        let dir = try copyEngine(); let h = try FileHandle(forWritingTo: dir.appendingPathComponent("yara")); try h.seekToEnd(); try h.write(contentsOf: Data([0])); try h.close()
        let s = YARAEngine.verify(dir); XCTAssertFalse(s.ready); XCTAssertTrue(s.reason.contains("do not match"), s.reason)
    }
    func testAnUnsignedEngineIsRefusedEvenWithAMatchingManifest() throws {
        let dir = try copyEngine(); _ = AuditEngine.command("/usr/bin/codesign", ["--remove-signature", dir.appendingPathComponent("yara").path])
        var m = try manifest(dir); m["yara_sha256"] = AuditEngine.sha256(of: dir.appendingPathComponent("yara")); try write(m, dir)
        let s = YARAEngine.verify(dir); XCTAssertFalse(s.ready); XCTAssertTrue(s.reason.contains("code signature"), s.reason)
    }
    func testAnOldOrMislabelledVersionIsRefused() throws {
        let dir = try copyEngine(); var m = try manifest(dir); m["version"] = "3.11.0"; try write(m, dir)
        let s = YARAEngine.verify(dir); XCTAssertFalse(s.ready); XCTAssertTrue(s.reason.contains("version"), s.reason)
    }
    func testAnEngineWithoutOurArchitectureIsRefused() throws {
        let dir = try copyEngine(); var m = try manifest(dir); m["architectures"] = "ppc64"; try write(m, dir)
        XCTAssertTrue(YARAEngine.verify(dir).reason.contains("slice"))
    }
    func testAMissingEngineIsReportedNotReplacedByAnotherOne() {
        let s = YARAEngine.verify(tmp); XCTAssertFalse(s.ready); XCTAssertTrue(s.reason.contains("not both present"), s.reason)
        let findings = YARAScanner.inspect([], status: s)
        XCTAssertEqual(findings.first?.title, "YARA engine unavailable"); XCTAssertEqual(findings.first?.state, .unknown)
    }
    func testADamagedEngineBlocksTheScanInsteadOfSkippingIt() throws {
        let dir = try copyEngine(); let h = try FileHandle(forWritingTo: dir.appendingPathComponent("yarac")); try h.seekToEnd(); try h.write(contentsOf: Data([1])); try h.close()
        let findings = YARAScanner.inspect([], status: YARAEngine.verify(dir)); XCTAssertEqual(findings.first?.state, .failed); XCTAssertTrue(findings.first?.title.contains("failed verification") == true)
    }

    func testVerifyingTheEngineNeverBlocksTheMainThread() throws {
        _ = try engine(); YARAEngine.reset()
        RunLoop.main.run(until: Date().addingTimeInterval(1.5))   // let the host app's own start-up settle
        var last = Date(), worst: TimeInterval = 0
        let timer = Timer.scheduledTimer(withTimeInterval: 0.01, repeats: true) { _ in let n = Date(); worst = max(worst, n.timeIntervalSince(last)); last = n }
        last = Date()
        let m = YARARuleManager(channelBase: URL(string: "http://127.0.0.1:9/")!, rulesDirectory: tmp.appendingPathComponent("rm/YARARules"), trustStore: MemoryTrustStore(), signatureCheck: nil, useStandardVerifier: false)
        RunLoop.main.run(until: Date().addingTimeInterval(4)); timer.invalidate()
        XCTAssertLessThan(worst, 0.25, "main thread stalled \(worst) s while the engine was verified")
        XCTAssertEqual(m.engineSummary?.ready, true, "the verified engine must be published to the UI")
    }

    // MARK: scanning
    func testAMatchIsFoundAndACleanFileIsNot() throws {
        let rules = try rulesDir(["a.yar": "rule HitMe { strings: $a = \"NEEDLE-123\" condition: $a }"])
        let out = try scan([try sample("xx NEEDLE-123 yy", name: "hit.txt"), try sample("nothing", name: "miss.txt")], rules)
        XCTAssertEqual(out.matches.map(\.rule), ["HitMe"]); XCTAssertTrue(out.matches[0].target.hasSuffix("hit.txt")); XCTAssertEqual(out.scanned, 2); XCTAssertTrue(out.errors.isEmpty, "\(out.errors)")
    }
    func testTheSameRuleNameInTwoFilesLoadsAndBothMatch() throws {
        let rules = try rulesDir(["a.yar": "rule SAME { strings: $a = \"AAA\" condition: $a }", "b.yar": "rule SAME { strings: $a = \"BBB\" condition: $a }"])
        let out = try scan([try sample("AAA"), try sample("BBB")], rules); XCTAssertEqual(out.matches.count, 2); XCTAssertEqual(out.ruleFiles, 2); XCTAssertTrue(out.skippedRules.isEmpty)
    }
    func testDependenciesComeFromTheSignedManifest() throws {
        let d = tmp.appendingPathComponent("rel"); let live = d.appendingPathComponent("community"); try FileManager.default.createDirectory(at: live.appendingPathComponent(".release"), withIntermediateDirectories: true)
        try "private rule Base { strings: $a = \"MZ-ish\" condition: $a }".write(to: live.appendingPathComponent("base.yar"), atomically: true, encoding: .utf8)
        try "rule Uses { condition: Base }".write(to: live.appendingPathComponent("uses.yar"), atomically: true, encoding: .utf8)
        let m: [String: Any] = ["rules_root": "abc", "files": [["path": "rules/base.yar"], ["path": "rules/uses.yar", "depends_on": ["rules/base.yar"]]]]
        try JSONSerialization.data(withJSONObject: m).write(to: live.appendingPathComponent(".release/manifest.json"))
        let out = try scan([try sample("this has MZ-ish inside")], YARAEngine.ruleSet(in: d))
        XCTAssertTrue(out.matches.contains { $0.rule == "Uses" }, "\(out.matches) \(out.skippedRules)")
    }
    func testOneBrokenRuleFileDoesNotDisableScanningAndIsReported() throws {
        let rules = try rulesDir(["good.yar": "rule Good { strings: $a = \"OKOK\" condition: $a }", "bad.yar": "rule Bad { condition: $missing }"])
        let out = try scan([try sample("OKOK")], rules); XCTAssertEqual(out.matches.map(\.rule), ["Good"]); XCTAssertEqual(out.skippedRules, ["bad.yar"]); XCTAssertEqual(out.ruleFiles, 1)
        let f = YARAScanner.inspect([try sample("OKOK")], rulesDirectory: rules.files[0].deletingLastPathComponent(), status: YARAEngine.verify(try engineDir()), cacheDirectory: tmp.appendingPathComponent("c2"))
        XCTAssertTrue(f.contains { $0.title == "YARA scan coverage" && $0.state == .warning && $0.detail.contains("do not compile") })
    }
    func testTheEngineMessageNamesTheFileThatFailsToCompile() {
        XCTAssertEqual(YARAEngine.failingPath(in: "error: rule \"X\" in /tmp/a b/rules/bad.yar(12): undefined identifier \"y\""), "/tmp/a b/rules/bad.yar")
        XCTAssertNil(YARAEngine.failingPath(in: "something else"))
    }
    func testManyBrokenFilesAmongHundredsAreDroppedQuicklyAndTheRestStillMatch() throws {
        var files: [String: String] = [:]
        for i in 0..<300 { files["ok\(i).yar"] = "rule OK\(i) { strings: $a = \"tok\(i)x\" condition: $a }" }
        for i in 0..<12 { files["bad\(i).yar"] = "rule BAD\(i) { condition: $nope }" }
        let rules = try rulesDir(files); let t0 = Date()
        let out = try scan([try sample("tok7x and tok250x")], rules)
        XCTAssertEqual(Set(out.matches.map(\.rule)), ["OK7", "OK250"]); XCTAssertEqual(out.skippedRules.count, 12); XCTAssertEqual(out.ruleFiles, 300)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 60)
    }
    func testTheCompiledSetIsReusedAndRebuiltWhenARuleChanges() throws {
        let rules = try rulesDir(["a.yar": "rule A { strings: $a = \"ONE\" condition: $a }"]); let s = try sample("ONE TWO")
        XCTAssertFalse(try scan([s], rules).reusedCache); XCTAssertTrue(try scan([s], rules).reusedCache)
        try "rule A { strings: $a = \"TWO\" condition: $a }".write(to: rules.files[0], atomically: true, encoding: .utf8)
        let changed = YARAEngine.ruleSet(in: rules.files[0].deletingLastPathComponent()); XCTAssertNotEqual(changed.key, rules.key); XCTAssertFalse(try scan([s], changed).reusedCache)
    }
    func testAHugeFileIsNotScannedAndTheSkipIsReported() throws {
        let rules = try rulesDir(["a.yar": "rule A { condition: true }"]); let big = tmp.appendingPathComponent("big.bin"); FileManager.default.createFile(atPath: big.path, contents: nil)
        let h = try FileHandle(forWritingTo: big); try h.truncate(atOffset: UInt64(YARAEngine.maxFileBytes) + 1); try h.close()
        let out = try scan([big], rules); XCTAssertEqual(out.scanned, 0); XCTAssertEqual(out.skippedLarge, ["big.bin"])
    }
    func testARuleThatBlocksTheEngineCannotHangTheCaller() throws {
        let slow = "rule S { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( i != j and uint8(i) == 1 and uint8(j) == 2 and false ) ) }"
        let rules = try rulesDir(["slow.yar": slow]); let big = tmp.appendingPathComponent("rand.bin"); try Data((0..<300_000).map { _ in UInt8.random(in: 0...255) }).write(to: big)
        let t0 = Date(); let out = try scan([big], rules, timeout: 4)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 30, "the scan must be cut off, not wait for the rule"); XCTAssertTrue(out.timedOut || !out.errors.isEmpty, "the incomplete scan must be visible")
    }
    func testTheAuditReportsAMatchWithTheEngineAndNoLongerSaysUnknownForAMissingEngine() throws {
        let rules = try rulesDir(["a.yar": "rule Canary { strings: $a = \"AUDIT-CANARY\" condition: $a }"])
        let f = YARAScanner.inspect([try sample("data AUDIT-CANARY data", name: "doc.txt")], rulesDirectory: rules.files[0].deletingLastPathComponent(), status: YARAEngine.verify(try engineDir()), cacheDirectory: tmp.appendingPathComponent("c3"))
        XCTAssertTrue(f.contains { $0.title == "YARA match: Canary" && $0.state == .warning }); XCTAssertFalse(f.contains { $0.title == "YARA engine unavailable" })
        let clean = YARAScanner.inspect([try sample("nothing here")], rulesDirectory: rules.files[0].deletingLastPathComponent(), status: YARAEngine.verify(try engineDir()), cacheDirectory: tmp.appendingPathComponent("c3"))
        XCTAssertEqual(clean.last?.state, .passed); XCTAssertTrue(clean.last?.detail.contains("does not prove safety") == true)
    }
    func testAFileOfAnUnknownTypeIsStillScannedByYARA() throws {
        let dir = YARARuleManager.shared.rulesDirectory.appendingPathComponent("community/test-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "rule Unknown_Canary { strings: $a = \"UNKNOWN-TYPE-CANARY\" condition: $a }".write(to: dir.appendingPathComponent("u.yar"), atomically: true, encoding: .utf8)
        let f = try sample("plain data UNKNOWN-TYPE-CANARY plain data", name: "blob.dat")
        let r = AuditEngine.audit(AuditInput(file: f, expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: ""))
        XCTAssertEqual(r.kind, "unknown"); XCTAssertTrue(r.findings.contains { $0.title == "YARA match: Unknown_Canary" }, r.findings.map(\.title).joined(separator: ", "))
    }
    func testAScriptWithATriggerStringIsMatchedThroughTheWholeAuditEngine() throws {
        // end to end through AuditEngine.audit with the shared rules directory of this process
        let dir = YARARuleManager.shared.rulesDirectory.appendingPathComponent("community/test-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "rule E2E_Canary { strings: $a = \"E2E-CANARY-STRING\" condition: $a }".write(to: dir.appendingPathComponent("e2e.yar"), atomically: true, encoding: .utf8)
        let script = try sample("#!/bin/sh\n# E2E-CANARY-STRING\necho hi\n", name: "run.sh")
        let r = AuditEngine.audit(AuditInput(file: script, expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: ""))
        XCTAssertTrue(r.findings.contains { $0.title == "YARA match: E2E_Canary" }, r.findings.map(\.title).joined(separator: ", "))
    }
}
