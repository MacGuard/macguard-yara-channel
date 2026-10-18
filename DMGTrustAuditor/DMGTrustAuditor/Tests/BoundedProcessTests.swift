import XCTest
@testable import DMGTrustAuditor

final class BoundedProcessTests: XCTestCase {
    func testCapturesOutputAndStatus() {
        let r = BoundedProcess.run("/bin/echo", ["hello"])
        XCTAssertEqual(r.status, 0); XCTAssertEqual(r.output, "hello\n"); XCTAssertFalse(r.timedOut)
    }
    func testTimeoutKillsTheChild() {
        let t0 = Date()
        let r = BoundedProcess.run("/bin/sleep", ["30"], timeout: 0.5)
        XCTAssertTrue(r.timedOut)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 5)
    }
    func testOutputIsCappedWithoutDeadlock() {
        let r = BoundedProcess.run("/usr/bin/yes", [], timeout: 1, maxOutput: 10_000)
        XCTAssertTrue(r.truncated); XCTAssertLessThanOrEqual(r.output.utf8.count, 10_000)
    }
    func testCancellation() {
        var calls = 0
        let r = BoundedProcess.run("/bin/sleep", ["30"], timeout: 30, cancelled: { calls += 1; return calls > 5 })
        XCTAssertFalse(r.timedOut); XCTAssertNotEqual(r.status, 0)
    }
    func testMissingExecutable() {
        XCTAssertEqual(BoundedProcess.run("/nonexistent/tool", []).status, -1)
    }
}
