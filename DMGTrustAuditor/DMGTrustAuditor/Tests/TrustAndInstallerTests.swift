import XCTest
import CryptoKit
@testable import DMGTrustAuditor

private func hex(_ s: String) -> Data { ChannelVerifier.data(hex: s)! }

/// Merkle consistency and anti-rollback policy. Vectors are produced by scripts/tlog.py.
final class ConsistencyTests: XCTestCase {
    private let leaves = (0..<7).map { ChannelVerifier.leafHash(Data("entry-\($0)".utf8)) }

    func testConsistencyMatchesPythonVectors() {
        let root7 = ChannelVerifier.root(leaves)
        let r3 = hex("a64bf26e09128f6fe2fe6f8b2d8c801e166b57c047a7cd9b2b809e7a96a2f1cb")
        let p3 = ["049d7dcdb56bcfebd313304c9839f196a3d4b6ef3bdc0b08298f93ac8191f0a8", "27479b6ab321d2ee477452f68ba527748e863cafe8fbd1df2bf89d1570d1b697",
                  "2f27a5082c1d42afa488ac350a9fc4390c084f54f71ecdff859e98db8429b479", "e429c5b5ccaa9523c37297f1846766f903137e82195c5199e6be57130d1006c8"].map(hex)
        XCTAssertTrue(ChannelVerifier.verifyConsistency(first: 3, second: 7, firstRoot: r3, secondRoot: root7, proof: p3))
        XCTAssertEqual(ChannelVerifier.consistencyProof(first: 3, leaves: leaves), p3)
        let r4 = hex("256b9e8825e5d370a4ae005d0901ea291977e2927f5cf8e3e72660dd09519edb")
        XCTAssertTrue(ChannelVerifier.verifyConsistency(first: 4, second: 7, firstRoot: r4, secondRoot: root7, proof: [hex("e429c5b5ccaa9523c37297f1846766f903137e82195c5199e6be57130d1006c8")]))
    }
    func testEverySizePairVerifiesAndTamperingFails() {
        let many = (0..<20).map { ChannelVerifier.leafHash(Data("e\($0)".utf8)) }
        for n in 1...20 { for m in 1...n {
            let a = ChannelVerifier.root(Array(many[..<m])), b = ChannelVerifier.root(Array(many[..<n]))
            let proof = ChannelVerifier.consistencyProof(first: m, leaves: Array(many[..<n]))
            XCTAssertTrue(ChannelVerifier.verifyConsistency(first: m, second: n, firstRoot: a, secondRoot: b, proof: proof), "\(m)->\(n)")
            if m < n {
                XCTAssertFalse(ChannelVerifier.verifyConsistency(first: m, second: n, firstRoot: ChannelVerifier.leafHash(Data("forged".utf8)), secondRoot: b, proof: proof), "forged old root \(m)->\(n)")
                XCTAssertFalse(ChannelVerifier.verifyConsistency(first: m, second: n, firstRoot: a, secondRoot: ChannelVerifier.leafHash(Data("forged".utf8)), proof: proof), "forged new root \(m)->\(n)")
            }
        } }
    }

    private func lines(_ n: Int, fork: Int? = nil) -> [Data] { (0..<n).map { Data(($0 == fork ? "forked-\($0)" : "line-\($0)").utf8) } }
    private func state(_ n: Int, fork: Int? = nil) -> TrustState {
        TrustState(origin: ChannelVerifier.logOrigin, size: n, root: ChannelVerifier.hex(ChannelVerifier.root(lines(n, fork: fork).map(ChannelVerifier.leafHash))), rulesRoot: "r", updatedAt: Date())
    }
    private func check(_ prior: TrustState?, size: Int, log: [Data]?, fork: Int? = nil) throws {
        let ls = lines(size, fork: fork)
        try ChannelVerifier.checkAgainstPrior(prior, origin: ChannelVerifier.logOrigin, size: size, root: ChannelVerifier.root(ls.map(ChannelVerifier.leafHash)), logLines: log ?? ls)
    }
    private func reason(_ f: () throws -> Void) -> String { do { try f(); return "" } catch { return (error as? ChannelVerifier.Failure)?.reason ?? "\(error)" } }

    func testFirstUseGrowthAndSameHeadAreAccepted() throws {
        try check(nil, size: 5, log: nil)
        try check(state(5), size: 5, log: nil)
        try check(state(5), size: 9, log: nil)
    }
    func testRollbackIsRefused() {
        XCTAssertTrue(reason { try check(state(9), size: 5, log: nil) }.contains("rollback"))
    }
    func testForkAtSameSizeIsRefused() {
        XCTAssertTrue(reason { try check(state(5), size: 5, log: nil, fork: 2) }.contains("fork"))
    }
    func testGrowthFromAForkedHistoryIsRefused() {
        XCTAssertTrue(reason { try check(state(5, fork: 1), size: 9, log: nil) }.contains("fork"))
    }
    func testGrowthWithoutThePublishedLogIsRefused() {
        let r = reason { try ChannelVerifier.checkAgainstPrior(self.state(5), origin: ChannelVerifier.logOrigin, size: 9, root: Data(repeating: 1, count: 32), logLines: nil) }
        XCTAssertTrue(r.contains("log"), r)
    }
    func testLogThatDoesNotHashToTheSignedRootIsRefused() {
        let r = reason { try ChannelVerifier.checkAgainstPrior(nil, origin: ChannelVerifier.logOrigin, size: 3, root: Data(repeating: 7, count: 32), logLines: self.lines(3)) }
        XCTAssertTrue(r.contains("does not hash"), r)
    }
    func testOriginChangeIsRefused() {
        var s = state(5); s.origin = "someone else"
        XCTAssertTrue(reason { try check(s, size: 5, log: nil) }.contains("origin"))
    }

    // MARK: FileTrustStore
    func testTrustStorePersistsWithPrivatePermissionsAndRefusesCorruption() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ts-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FileTrustStore(url: dir.appendingPathComponent("ChannelState/trust.json"))
        XCTAssertNil(try store.load())
        try store.save(state(4)); try store.save(state(6))
        XCTAssertEqual(try store.load()?.size, 6)
        let mode = (try FileManager.default.attributesOfItem(atPath: store.url.path)[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(mode, 0o600)
        let dmode = (try FileManager.default.attributesOfItem(atPath: store.url.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(dmode, 0o700)
        try Data("not json".utf8).write(to: store.url)
        XCTAssertThrowsError(try store.load())       // never silently reset to trust-on-first-use
    }
}

/// Archive limits against hostile input, with real archives built by the system tools.
final class ArchiveExtractorTests: XCTestCase {
    var dir: URL!
    override func setUpWithError() throws { dir = FileManager.default.temporaryDirectory.appendingPathComponent("ax-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true) }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }
    private func tarOf(_ build: (URL) throws -> Void, flags: String = "-czf") throws -> URL {
        let src = dir.appendingPathComponent("src-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try build(src)
        let out = dir.appendingPathComponent("a-\(UUID().uuidString).tgz")
        try AuditEngine.run("/usr/bin/tar", [flags, out.path, "-C", src.path, "."])
        return out
    }
    private func extract(_ a: URL, _ limits: ArchiveLimits = ArchiveLimits()) throws -> ArchiveExtractor.Result {
        try ArchiveExtractor.extract(a, into: dir.appendingPathComponent("out-\(UUID().uuidString)"), limits: limits)
    }
    private func refusal(_ a: URL, _ l: ArchiveLimits = ArchiveLimits()) -> String { do { _ = try extract(a, l); return "" } catch { return (error as? ArchiveExtractor.Failure)?.reason ?? "\(error)" } }

    func testNormalArchiveExtracts() throws {
        let a = try tarOf { try "hi".write(to: $0.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8) }
        XCTAssertEqual(try extract(a).expandedBytes, 2)
    }
    func testZipIsReadToo() throws {
        let src = dir.appendingPathComponent("z"); try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try "hi".write(to: src.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        let zip = dir.appendingPathComponent("a.zip")
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/zip"); p.arguments = ["-qr", zip.path, "a.txt"]; p.currentDirectoryURL = src
        try p.run(); p.waitUntilExit()
        XCTAssertEqual(try extract(zip).entries, 1)
    }
    func testEntryCountLimit() throws {
        let a = try tarOf { for i in 0..<30 { try "x".write(to: $0.appendingPathComponent("f\(i)"), atomically: true, encoding: .utf8) } }
        var l = ArchiveLimits(); l.maxEntries = 10
        XCTAssertTrue(refusal(a, l).contains("entries"))
    }
    func testDeclaredSizeLimit() throws {
        let a = try tarOf { try Data(repeating: 0, count: 200_000).write(to: $0.appendingPathComponent("big")) }
        var l = ArchiveLimits(); l.maxExpandedBytes = 50_000
        XCTAssertTrue(refusal(a, l).contains("size"))
    }
    func testDecompressionBombIsStopped() throws {
        let a = try tarOf { try Data(count: 40_000_000).write(to: $0.appendingPathComponent("zeros")) }   // ~40 KB gzipped
        XCTAssertLessThan((try FileManager.default.attributesOfItem(atPath: a.path)[.size] as! NSNumber).intValue, 200_000)
        var l = ArchiveLimits(); l.maxExpandedBytes = 1_000_000
        XCTAssertFalse(refusal(a, l).isEmpty)
    }
    func testDepthLimit() throws {
        let a = try tarOf { var u = $0; for i in 0..<12 { u = u.appendingPathComponent("d\(i)") }; try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true); try "x".write(to: u.appendingPathComponent("f"), atomically: true, encoding: .utf8) }
        var l = ArchiveLimits(); l.maxPathDepth = 5
        XCTAssertTrue(refusal(a, l).contains("deep"))
    }
    func testEscapingSymlinkIsRemovedAndReported() throws {
        let a = try tarOf { try FileManager.default.createSymbolicLink(atPath: $0.appendingPathComponent("evil").path, withDestinationPath: "/etc/passwd"); try "ok".write(to: $0.appendingPathComponent("ok"), atomically: true, encoding: .utf8) }
        let out = dir.appendingPathComponent("o")
        let r = try ArchiveExtractor.extract(a, into: out)
        XCTAssertEqual(r.removedLinks.count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.appendingPathComponent("evil").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: out.appendingPathComponent("ok").path))
    }
    func testListingChecksRejectTraversalAbsoluteAndDevices() {
        let l = ArchiveLimits()
        XCTAssertThrowsError(try ArchiveExtractor.checkName("../x", limits: l))
        XCTAssertThrowsError(try ArchiveExtractor.checkName("a/../../x", limits: l))
        XCTAssertThrowsError(try ArchiveExtractor.checkName("/etc/passwd", limits: l))
        XCTAssertNoThrow(try ArchiveExtractor.checkName("a/b.txt", limits: l))
        XCTAssertThrowsError(try ArchiveExtractor.checkListing("crw-r--r--  0 root wheel 0 Jan  1 00:00 dev", limits: l))
    }
    func testCorruptArchiveIsRefused() throws {
        let bad = dir.appendingPathComponent("bad.tgz"); try Data(repeating: 0x41, count: 5000).write(to: bad)
        XCTAssertFalse(refusal(bad).isEmpty)
        let a = try tarOf { try Data(count: 100_000).write(to: $0.appendingPathComponent("f")) }
        let cut = dir.appendingPathComponent("cut.tgz"); try Data(contentsOf: a).prefix(80).write(to: cut)
        XCTAssertFalse(refusal(cut).isEmpty)   // incomplete download
    }
    func testGunzipCap() throws {
        let raw = dir.appendingPathComponent("zeros"); try Data(count: 5_000_000).write(to: raw)
        try AuditEngine.run("/usr/bin/gzip", ["-k", raw.path])
        var l = ArchiveLimits(); l.maxExpandedBytes = 1_000_000
        XCTAssertThrowsError(try ArchiveExtractor.gunzip(dir.appendingPathComponent("zeros.gz"), to: dir.appendingPathComponent("o"), limits: l))
        XCTAssertEqual(try ArchiveExtractor.gunzip(dir.appendingPathComponent("zeros.gz"), to: dir.appendingPathComponent("o2")), 5_000_000)
    }
}

/// Failure matrix for the transactional installer. A real local HTTP server serves a sample channel.
extension ChannelUpdateTests {
    private func liveIntact(_ msg: String = "") { XCTAssertTrue(FileManager.default.fileExists(atPath: installed.path), "previous rules must still be live. \(msg)") }
    private func firstInstall(trust: TrustStore = MemoryTrustStore()) -> (YARARuleManager, String) {
        let m = manager(check: { _, _ in nil }, trust: trust)
        let msg = checkAndUpdate(m); return (m, msg)
    }

    func testSecondInstallKeepsThePreviousVersionAndTrustAdvances() throws {
        let trust = MemoryTrustStore()
        let (m, _) = firstInstall(trust: trust)
        XCTAssertEqual(trust.state?.size, 3)
        XCTAssertTrue(FileManager.default.fileExists(atPath: m.installer.liveDirectory.appendingPathComponent(".release/manifest.json").path))
        _ = checkAndUpdateAgain(m)          // same release again: the head is equal, which is allowed
        XCTAssertTrue(FileManager.default.fileExists(atPath: m.installer.previousDirectory.appendingPathComponent("src/x.yar").path))
        liveIntact()
    }
    func checkAndUpdateAgain(_ m: YARARuleManager) -> String {
        let done = expectation(description: "again"); var r = ""
        DispatchQueue.main.async { m.checkForUpdates() }
        DispatchQueue.global().async { Thread.sleep(forTimeInterval: 1); DispatchQueue.main.async { m.update { r = $0; done.fulfill() } } }
        wait(for: [done], timeout: 30); return r
    }
    func testOlderCheckpointIsRejectedAndLiveRulesStay() throws {
        let trust = MemoryTrustStore()
        _ = firstInstall(trust: trust)
        let newer = TrustState(origin: ChannelVerifier.logOrigin, size: 50, root: String(repeating: "ab", count: 32), rulesRoot: "x", updatedAt: Date())
        trust.state = newer
        let m = manager(check: { _, _ in nil }, trust: trust)
        let msg = checkAndUpdateAgain(m)
        XCTAssertTrue(msg.lowercased().contains("rollback") || msg.contains("trusted"), msg)
        XCTAssertEqual(trust.state, newer, "trust state must not move backwards")
        liveIntact(msg)
    }
    func testForkedHeadIsRejected() throws {
        let trust = MemoryTrustStore(TrustState(origin: ChannelVerifier.logOrigin, size: 3, root: String(repeating: "cd", count: 32), rulesRoot: "x", updatedAt: Date()))
        let m = manager(check: { _, _ in nil }, trust: trust)
        let msg = checkAndUpdate(m)
        XCTAssertTrue(msg.lowercased().contains("fork"), msg)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path))
    }
    func testDamagedTrustStateBlocksInstallation() throws {
        struct Broken: TrustStore { func load() throws -> TrustState? { throw FileTrustStore.Corrupt(reason: "x") }; func save(_ s: TrustState) throws {} }
        let m = manager(check: { _, _ in nil }, trust: Broken())
        _ = checkAndUpdate(m)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path))
    }
    func testCorruptTarballKeepsPreviousRules() throws {
        _ = firstInstall()
        try Data(repeating: 0x42, count: 4000).write(to: site.appendingPathComponent("rules-release.tar.gz"))
        let m = manager(check: { _, _ in nil })
        _ = checkAndUpdateAgain(m)
        liveIntact()
    }
    func testNetworkLossKeepsPreviousRules() throws {
        _ = firstInstall()
        server?.terminate(); server?.waitUntilExit()
        let m = manager(check: { _, _ in nil })
        let done = expectation(description: "u"); var r = ""
        m.checkForUpdates(); Thread.sleep(forTimeInterval: 0.5)
        m.update { r = $0; done.fulfill() }
        wait(for: [done], timeout: 30)
        liveIntact(r)
    }
    func testDiskFullIsRefusedBeforeAnythingChanges() async throws {
        let m = manager(check: { _, _ in nil })
        m.installer.availableSpace = { 1024 }
        do { _ = try await m.installer.install(); XCTFail("should refuse") } catch let f as YARARuleManager.Failure { XCTAssertTrue(f.en.contains("disk space")) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path))
    }
    func testSecondConcurrentUpdateIsRefused() async throws {
        let m = manager(check: { _, _ in nil })
        try FileManager.default.createDirectory(at: m.installer.stateDirectory, withIntermediateDirectories: true)
        let fd = open(m.installer.stateDirectory.appendingPathComponent("update.lock").path, O_CREAT | O_RDWR, 0o600)
        XCTAssertEqual(flock(fd, LOCK_EX | LOCK_NB), 0)
        defer { flock(fd, LOCK_UN); close(fd) }
        do { _ = try await m.installer.install(); XCTFail("must not run concurrently") } catch let f as YARARuleManager.Failure { XCTAssertTrue(f.en.contains("Another rules update")) }
    }
    func testCancellationLeavesPreviousRules() async throws {
        let m = manager(check: { _, _ in nil })
        let t = Task { try await m.installer.install() }
        t.cancel()
        _ = try? await t.value
        XCTAssertFalse(FileManager.default.fileExists(atPath: m.installer.stateDirectory.path + "/journal.json"))
    }
    func testCrashBetweenTheTwoRenamesIsRolledBack() async throws {
        let (m, _) = firstInstall()
        liveIntact()
        // Second update "crashes" after moving the live folder away.
        let m2 = manager(check: { _, _ in nil })
        struct Boom: Error {}
        m2.installer.afterFirstRename = { throw Boom() }
        let done = expectation(description: "u")
        m2.checkForUpdates(); try await Task.sleep(nanoseconds: 800_000_000)
        m2.update { _ in done.fulfill() }
        await fulfillment(of: [done], timeout: 30)
        liveIntact("an interrupted swap must restore the previous version")
        // And the same state left behind by a real crash (journal present, live missing) is repaired at start.
        let fm = FileManager.default
        try fm.moveItem(at: m.installer.liveDirectory, to: m.installer.previousDirectory)
        try Data("{}".utf8).write(to: m.installer.stateDirectory.appendingPathComponent("journal.json"))
        m.installer.recoverIfNeeded()
        liveIntact("recoverIfNeeded must restore the previous version")
        XCTAssertFalse(fm.fileExists(atPath: m.installer.stateDirectory.appendingPathComponent("journal.json").path))
    }
    func testInstalledRulesCanBeReverifiedAndTamperingIsDetected() throws {
        let (m, _) = firstInstall()
        XCTAssertEqual(try m.verifyInstalled().fileCount, 1)
        try Data("rule x { condition: false }".utf8).write(to: installed)
        XCTAssertThrowsError(try m.verifyInstalled())
        try Data("rule x { condition: true }".utf8).write(to: installed)
        XCTAssertNoThrow(try m.verifyInstalled())
        try Data("rule evil { condition: true }".utf8).write(to: m.installer.liveDirectory.appendingPathComponent("evil.yar"))
        XCTAssertThrowsError(try m.verifyInstalled()) { XCTAssertTrue(($0 as? ChannelVerifier.Failure)?.reason.contains("not in the signed manifest") == true) }
    }
    func testNoVerifierMeansNothingInstalledAndAReason() async throws {
        let m = YARARuleManager(channelBase: URL(string: "http://127.0.0.1:\(port)/")!, rulesDirectory: support, trustStore: MemoryTrustStore(), signatureCheck: nil, useStandardVerifier: false)
        do { _ = try await m.installer.install(); XCTFail() } catch let f as YARARuleManager.Failure { XCTAssertTrue(f.en.contains("Sigstore")) }
    }
}
