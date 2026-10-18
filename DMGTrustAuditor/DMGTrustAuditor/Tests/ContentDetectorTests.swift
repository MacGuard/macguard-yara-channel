import XCTest
@testable import DMGTrustAuditor

/// Samples are real files built with the system tools, not hand-written byte stubs.
final class ContentDetectorTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ctd-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    @discardableResult
    private func run(_ tool: String, _ args: [String], cwd: URL? = nil) throws -> String {
        let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
        if let cwd { p.currentDirectoryURL = cwd }
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        try p.run()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, "\(tool) failed: \(out)")
        return out
    }
    private func payload() throws -> URL {
        let src = dir.appendingPathComponent("payload", isDirectory: true)
        try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try "hello".write(to: src.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        return src
    }
    private func detect(_ url: URL) -> ContentDetection { ContentDetector.detect(url) }

    func testDMG() throws {
        let dmg = dir.appendingPathComponent("sample.dmg")
        try run("/usr/bin/hdiutil", ["create", "-srcfolder", try payload().path, "-format", "UDZO", "-quiet", dmg.path])
        XCTAssertEqual(detect(dmg), ContentDetection(kind: .dmg, extensionMismatch: nil))
    }
    func testDMGWithWrongExtensionIsStillDMG() throws {
        let dmg = dir.appendingPathComponent("sample.dmg")
        try run("/usr/bin/hdiutil", ["create", "-srcfolder", try payload().path, "-format", "UDZO", "-quiet", dmg.path])
        let renamed = dir.appendingPathComponent("installer.zip")
        try FileManager.default.moveItem(at: dmg, to: renamed)
        XCTAssertEqual(detect(renamed), ContentDetection(kind: .dmg, extensionMismatch: ".zip"))
    }
    func testISO() throws {
        let iso = dir.appendingPathComponent("sample.iso")
        try run("/usr/bin/hdiutil", ["makehybrid", "-iso", "-quiet", "-o", iso.path, try payload().path])
        XCTAssertEqual(detect(iso).kind, .iso)
    }
    func testFlatPKG() throws {
        let pkg = dir.appendingPathComponent("sample.pkg")
        try run("/usr/bin/pkgbuild", ["--nopayload", "--identifier", "com.example.t", "--version", "1", pkg.path])
        XCTAssertEqual(detect(pkg), ContentDetection(kind: .pkg, extensionMismatch: nil))
    }
    func testZipTarAndTarGz() throws {
        _ = try payload()
        let zip = dir.appendingPathComponent("s.zip")
        try run("/usr/bin/zip", ["-qr", zip.path, "payload"], cwd: dir)
        XCTAssertEqual(detect(zip).kind, .zip)
        let tar = dir.appendingPathComponent("s.tar")
        try run("/usr/bin/tar", ["-cf", tar.path, "payload"], cwd: dir)
        XCTAssertEqual(detect(tar).kind, .tar)
        let tgz = dir.appendingPathComponent("s.tar.gz")
        try run("/usr/bin/tar", ["-czf", tgz.path, "payload"], cwd: dir)
        XCTAssertEqual(detect(tgz).kind, .tarGzip)
        let tgz2 = dir.appendingPathComponent("s.tgz")
        try FileManager.default.copyItem(at: tgz, to: tgz2)
        XCTAssertEqual(detect(tgz2).kind, .tarGzip)
        let bare = dir.appendingPathComponent("notes.gz")
        try FileManager.default.copyItem(at: tgz, to: bare)
        XCTAssertEqual(detect(bare).kind, .gzip)
    }
    func testMachOWithoutExtension() throws {
        let bin = dir.appendingPathComponent("tool")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: bin)
        XCTAssertEqual(detect(bin), ContentDetection(kind: .machO, extensionMismatch: nil))
    }
    func testJavaClassIsNotMachO() throws {
        let cls = dir.appendingPathComponent("A.class")
        try Data([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34] + [UInt8](repeating: 0, count: 64)).write(to: cls)
        XCTAssertNotEqual(detect(cls).kind, .machO)
    }
    func testScripts() throws {
        func make(_ name: String, _ text: String) throws -> URL {
            let u = dir.appendingPathComponent(name); try text.write(to: u, atomically: true, encoding: .utf8); return u
        }
        XCTAssertEqual(detect(try make("a.sh", "echo hi\n")).kind, .script(.shell))
        XCTAssertEqual(detect(try make("a.command", "#!/bin/bash\necho\n")).kind, .script(.shell))
        XCTAssertEqual(detect(try make("noext", "#!/usr/bin/env python3\nprint(1)\n")).kind, .script(.python))
        XCTAssertEqual(detect(try make("a.rb", "puts 1\n")).kind, .script(.ruby))
        XCTAssertEqual(detect(try make("a.js", "console.log(1)\n")).kind, .script(.javascript))
        XCTAssertEqual(detect(try make("a.applescript", "display dialog \"x\"\n")).kind, .script(.appleScript))
        XCTAssertEqual(detect(try make("plain.txt", "just text\n")).kind, .unknown)
    }
    func testCompiledAppleScript() throws {
        let src = dir.appendingPathComponent("s.applescript"); try "return 1".write(to: src, atomically: true, encoding: .utf8)
        let out = dir.appendingPathComponent("s.scpt")
        try run("/usr/bin/osacompile", ["-o", out.path, src.path])
        XCTAssertEqual(detect(out).kind, .appleScriptCompiled)
    }
    func testBundlesAreDetectedByDirectory() throws {
        for (name, kind) in [("X.app", ContentKind.app), ("X.mpkg", .mpkg), ("X.workflow", .workflow)] {
            let u = dir.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
            XCTAssertEqual(detect(u).kind, kind)
        }
    }
    func testEmptyAndMissingFilesAreUnknown() throws {
        let empty = dir.appendingPathComponent("empty"); FileManager.default.createFile(atPath: empty.path, contents: Data())
        XCTAssertEqual(detect(empty).kind, .unknown)
        XCTAssertEqual(detect(dir.appendingPathComponent("missing")).kind, .unknown)
    }
}
