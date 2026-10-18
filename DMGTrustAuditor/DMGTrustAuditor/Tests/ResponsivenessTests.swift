import XCTest
@testable import DMGTrustAuditor

/// The reported freeze: the app hung when the rules-update prompt appeared. These tests keep the main thread honest:
/// a heartbeat timer on the main run loop must never stall while the manager initialises, checks for updates (reachable,
/// unreachable, slow) or counts thousands of rule files.
final class ResponsivenessTests: XCTestCase {
    private var root: URL!
    override func setUpWithError() throws {
        // The test host is the real app: let its own window/SwiftUI start-up finish so only our code is measured.
        RunLoop.main.run(until: Date().addingTimeInterval(2))
        root = FileManager.default.temporaryDirectory.appendingPathComponent("resp-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true) }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    /// Largest gap between main-run-loop heartbeats while `work` runs; `work` may kick off async activity.
    private func maxMainThreadGap(during seconds: TimeInterval, _ work: () -> Void) -> TimeInterval {
        var last = Date(), worst: TimeInterval = 0, worstAt: TimeInterval = 0
        let start = Date()
        let timer = Timer.scheduledTimer(withTimeInterval: 0.01, repeats: true) { _ in let now = Date(); let g = now.timeIntervalSince(last); if g > worst { worst = g; worstAt = now.timeIntervalSince(start) }; last = now }
        last = Date(); work()
        defer { if worst > 0.25 { print("STALL \(worst) s at +\(worstAt) s") } }
        RunLoop.main.run(until: Date().addingTimeInterval(seconds))
        worst = max(worst, Date().timeIntervalSince(last) > 0.5 ? Date().timeIntervalSince(last) : 0)
        timer.invalidate(); return worst
    }
    private func manyRules(_ n: Int) throws -> URL {
        let dir = root.appendingPathComponent("support/YARARules/community/src", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for i in 0..<n { try Data("rule r\(i) { condition: true }".utf8).write(to: dir.appendingPathComponent("r\(i).yar")) }
        return root.appendingPathComponent("support/YARARules")
    }

    func testStartupWithSixThousandRulesDoesNotBlockTheMainThread() throws {
        let rules = try manyRules(6000)
        var manager: YARARuleManager?
        let gap = maxMainThreadGap(during: 3) {
            manager = YARARuleManager(channelBase: URL(string: "http://127.0.0.1:9/")!, rulesDirectory: rules, trustStore: MemoryTrustStore(), signatureCheck: nil, useStandardVerifier: false)
        }
        XCTAssertLessThan(gap, 0.25, "main thread stalled for \(gap) s during start-up")
        XCTAssertEqual(manager?.installedCount, 6001, "background count must still arrive (6000 + starter rules)")
    }
    func testUpdateCheckAgainstAnUnreachableServerKeepsTheUIResponsive() {
        let m = YARARuleManager(channelBase: URL(string: "http://127.0.0.1:9/")!, rulesDirectory: root.appendingPathComponent("a/YARARules"), trustStore: MemoryTrustStore(), signatureCheck: nil, useStandardVerifier: false)
        let gap = maxMainThreadGap(during: 3) { m.checkForUpdates() }
        XCTAssertLessThan(gap, 0.25)
        XCTAssertFalse(m.checking, "the check must finish and clear its busy flag")
        XCTAssertFalse(m.message.isEmpty, "the failure must be explained to the user")
    }
    func testASlowServerDoesNotFreezeTheUIAndTheCheckTimesOut() throws {
        // A TCP listener that accepts and never answers.
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        let port = Int.random(in: 41000...45000)
        p.arguments = ["-c", "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',\(port)));s.listen(5)\nc=[]\nwhile True:\n c.append(s.accept()[0])"]
        p.standardOutput = Pipe(); p.standardError = Pipe(); try p.run(); defer { p.terminate() }
        Thread.sleep(forTimeInterval: 1)
        let m = YARARuleManager(channelBase: URL(string: "http://127.0.0.1:\(port)/")!, rulesDirectory: root.appendingPathComponent("b/YARARules"), trustStore: MemoryTrustStore(), signatureCheck: nil, useStandardVerifier: false)
        let t0 = Date()
        let gap = maxMainThreadGap(during: 8) { m.checkForUpdates() }
        XCTAssertLessThan(gap, 0.25)
        XCTAssertFalse(m.checking, "a silent server must not leave the app 'checking' forever")
        XCTAssertLessThan(Date().timeIntervalSince(t0), 12)
    }
    func testAuditOfALargeFolderRunsOffTheMainThread() throws {
        let app = root.appendingPathComponent("Big.app/Contents/MacOS"); try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/echo"), to: app.appendingPathComponent("tool"))
        try ("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>tool</string><key>CFBundleIdentifier</key><string>x.y</string></dict></plist>").write(to: root.appendingPathComponent("Big.app/Contents/Info.plist"), atomically: true, encoding: .utf8)
        let res = root.appendingPathComponent("Big.app/Contents/Resources"); try FileManager.default.createDirectory(at: res, withIntermediateDirectories: true)
        for i in 0..<3000 { try Data("x".utf8).write(to: res.appendingPathComponent("f\(i).txt")) }
        var done = false
        let gap = maxMainThreadGap(during: 20) {
            DispatchQueue.global().async { _ = AuditEngine.audit(AuditInput(file: self.root.appendingPathComponent("Big.app"), expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: "")); DispatchQueue.main.async { done = true } }
        }
        XCTAssertLessThan(gap, 0.25); XCTAssertTrue(done, "audit did not finish in time")
    }
}
