import Foundation

/// Command line front end. All checks come from the shared `Core` engine; nothing here re-implements a security check.
enum CLI {
    enum Exit { static let ok: Int32 = 0, failed: Int32 = 2, usage: Int32 = 3, unavailable: Int32 = 4 }

    static func out(_ s: String) { FileHandle.standardOutput.write(Data((s + "\n").utf8)) }
    static func err(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }
    static func expand(_ p: String) -> URL { URL(fileURLWithPath: (p as NSString).expandingTildeInPath) }

    static func json(_ object: Encodable) -> String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; e.dateEncodingStrategy = .iso8601
        func enc<T: Encodable>(_ v: T) -> String { (try? e.encode(v)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}" }
        return enc(AnyEncodable(object))
    }
    struct AnyEncodable: Encodable { let v: Encodable; init(_ v: Encodable) { self.v = v }; func encode(to e: Encoder) throws { try v.encode(to: e) } }

    struct ScanOutput: Encodable { let schemaVersion: Int; let tool: String; let version: String; let results: [AuditReport] }
    struct StatusOutput: Encodable {
        let schemaVersion: Int; let installedFiles: Int; let verifiedRelease: Bool; let rulesRoot: String?; let logSize: Int?
        let trustedLogSize: Int?; let sigstoreVerifier: Bool; let sigstoreDetail: String; let yaraEngine: Bool; let note: String
    }
    struct VerifyOutput: Encodable { let schemaVersion: Int; let ok: Bool; let files: Int?; let rulesRoot: String?; let logSize: Int?; let error: String? }
    struct UpdateOutput: Encodable { let schemaVersion: Int; let ok: Bool; let updated: Bool; let message: String }

    static func usage() {
        out("""
        MACGUARD INSTALLER AUDITOR — \(ToolInfo.name) \(ToolInfo.version)

        Examines installers and applications without running them. Ayuda / Help:

        COMMANDS / COMANDOS
          scan <path> [--format text|json] [--sha256 HEX] [--team ID] [--bundle ID] [--name TEXT] [--recursive]
              Audit a DMG, PKG/MPKG, APP, ZIP, TAR/TGZ, GZ, ISO, Mach-O, script, .scpt or .workflow.
          formats                        List supported formats and how deep each analysis goes.
          update-rules [--yes] [--format json]
                                         Download, verify and install the signed YARA rules (asks first unless --yes).
          verify-rules [--format json]   Re-verify the installed rules: signatures, hashes, log inclusion, no extra files.
          rules-status [--format json]   Installed rules, verifier availability and trust state.
          hash <path>                    SHA-256 of a file.
          signature <path>               codesign verification.
          identity team-id|bundle-id <path>
          explain team-id|bundle-id|dmg|pkg|yara
          tui [folder]                   Full-screen file explorer (interactive terminal required).
          version | help

        EXIT CODES
          0 no confirmed failure (NOT a safety guarantee)   2 a check failed
          3 bad arguments or path                           4 evidence or capability unavailable
        JSON output carries "schemaVersion": \(ToolInfo.jsonSchema); see CLI/README.md.
        """)
    }

    static func main(_ args: [String]) -> Int32 {
        guard let cmd = args.first else { usage(); return Exit.usage }
        let rest = Array(args.dropFirst())
        switch cmd {
        case "help", "--help", "-h": usage(); return Exit.ok
        case "version", "--version": out("\(ToolInfo.name) \(ToolInfo.version)"); return Exit.ok
        case "scan": return scan(rest)
        case "formats": return formats()
        case "update-rules": return updateRules(rest)
        case "verify-rules": return verifyRules(rest)
        case "rules-status": return rulesStatus(rest)
        case "tui": return TUI.run(start: rest.first)
        case "hash":
            guard let p = rest.first, let h = AuditEngine.sha256(of: expand(p)) else { err("Cannot hash path"); return Exit.usage }
            out("SHA-256: \(h)"); return Exit.ok
        case "signature":
            guard let p = rest.first else { usage(); return Exit.usage }
            let r = AuditEngine.command("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", expand(p).path])
            out(r.1.isEmpty ? (r.0 == 0 ? "Signature verified" : "Signature not verified") : r.1)
            return r.0 == 0 ? Exit.ok : Exit.failed
        case "identity":
            guard rest.count >= 2, ["team-id", "bundle-id"].contains(rest[0]) else { usage(); return Exit.usage }
            let prefix = rest[0] == "team-id" ? "TeamIdentifier=" : "Identifier="
            let path = expand(rest[1]).path
            guard FileManager.default.fileExists(atPath: path) else { err("Path not found"); return Exit.usage }
            let d = AuditEngine.command("/usr/bin/codesign", ["-dv", "--verbose=4", path]).1
            guard let v = d.split(separator: "\n").map(String.init).first(where: { $0.hasPrefix(prefix) }) else { err("Identity unavailable; not inferred"); return Exit.unavailable }
            out(String(v.dropFirst(prefix.count))); return Exit.ok
        case "explain":
            let topics = ["team-id": "Team ID identifies a signing team; vendor attribution needs independent evidence.",
                          "bundle-id": "Bundle ID identifies an app but is not proof of ownership.",
                          "dmg": "DMG is a disk image. Valid structure does not prove malware absence.",
                          "pkg": "PKG installers may contain scripts; signature alone is insufficient.",
                          "yara": "YARA matches patterns. No match does not prove safety."]
            guard let t = rest.first.flatMap({ topics[$0] }) else { usage(); return Exit.usage }
            out(t); return Exit.ok
        default: err("Unknown command: \(cmd)"); usage(); return Exit.usage
        }
    }

    // MARK: scan
    static func scan(_ a: [String]) -> Int32 {
        guard let path = a.first, !path.hasPrefix("-") else { usage(); return Exit.usage }
        var format = "text", sha = "", team = "", bundle = "", name = "", recursive = false, i = 1
        while i < a.count {
            switch a[i] {
            case "--format": i += 1; if i < a.count { format = a[i] }
            case "--sha256": i += 1; if i < a.count { sha = a[i] }
            case "--team": i += 1; if i < a.count { team = a[i] }
            case "--bundle": i += 1; if i < a.count { bundle = a[i] }
            case "--name": i += 1; if i < a.count { name = a[i] }
            case "--recursive": recursive = true
            default: err("Unknown option: \(a[i])"); return Exit.usage
            }
            i += 1
        }
        guard ["text", "json"].contains(format) else { usage(); return Exit.usage }
        let url = expand(path)
        guard FileManager.default.fileExists(atPath: url.path) else { err("Path not found"); return Exit.usage }
        var targets = [url]
        var isDir: ObjCBool = false; FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir)
        if recursive, isDir.boolValue, ContentDetector.detect(url).kind == .unknown {
            targets = AuditEngine.regularFiles((FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey], options: [.skipsPackageDescendants])?.allObjects as? [URL]) ?? [])
                .filter { ContentDetector.detect($0).kind != .unknown }.prefix(500).map { $0 }
        }
        let reports = targets.map { AuditEngine.audit(AuditInput(file: $0, expectedName: name, expectedTeam: team, expectedBundle: bundle, expectedSHA: sha, sourceURL: "")) }
        if format == "json" {
            out(json(ScanOutput(schemaVersion: ToolInfo.jsonSchema, tool: ToolInfo.name, version: ToolInfo.version, results: reports)))
        } else {
            for r in reports { out(Render.text(r)) }
        }
        return reports.contains { $0.findings.contains { $0.state == .failed } } ? Exit.failed : Exit.ok
    }

    static func formats() -> Int32 {
        let rows: [(String, String)] = [
            ("dmg", "partial: hdiutil verify, read-only mount, apps/pkgs/scripts/nested archives (2 levels)"),
            ("iso", "partial: read-only mount and the same tree inspection"),
            ("pkg / mpkg", "partial: signature, expanded metadata, Scripts and Payload opened and scanned statically"),
            ("app", "partial: signature, identity, entitlements, Gatekeeper, notarization ticket"),
            ("zip / tar / tar.gz / gz", "partial: safe extraction with entry, size, depth and time limits, then tree inspection"),
            ("mach-o", "partial: signature, identity, architectures, entitlements, Gatekeeper"),
            ("sh / py / rb / js", "limited: pattern scan of the source, never executed"),
            ("scpt", "limited: decompiled with osadecompile and scanned, never executed"),
            ("workflow", "limited: Automator actions and embedded scripts read, never run"),
            ("other", "not supported: reported UNKNOWN, never assumed safe")]
        for r in rows { out("\(r.0.padding(toLength: 26, withPad: " ", startingAt: 0)) \(r.1)") }
        out("\nNo format has complete coverage. YARA runs only with a signed bundled engine; otherwise it is reported UNKNOWN.")
        return Exit.ok
    }

    // MARK: rules
    static func manager() -> YARARuleManager { YARARuleManager.shared }

    static func rulesStatus(_ a: [String]) -> Int32 {
        let m = manager()
        let v = try? m.verifyInstalled()
        let trust = (try? m.installer.trustStore.load()) ?? nil
        let sig = SigstoreVerifier.locate()
        let status = StatusOutput(schemaVersion: ToolInfo.jsonSchema, installedFiles: m.ruleFiles().count, verifiedRelease: v != nil,
                                  rulesRoot: v?.rulesRoot, logSize: v?.logSize, trustedLogSize: trust?.size, sigstoreVerifier: sig.0 != nil,
                                  sigstoreDetail: sig.0 != nil ? "pinned cosign and trusted root found" : sig.1, yaraEngine: m.engineReady,
                                  note: "Verified means the installed files match a signed, logged release. It does not mean the rules or scanned files are safe.")
        if a.contains("json") || a == ["--format", "json"] { out(json(status)) } else {
            out("Installed rule files : \(status.installedFiles)")
            out("Verified release     : \(status.verifiedRelease ? "yes (rules_root \(status.rulesRoot ?? "")…, log size \(status.logSize ?? 0))" : "no")")
            out("Trusted log size     : \(status.trustedLogSize.map(String.init) ?? "none yet")")
            out("Sigstore verifier    : \(status.sigstoreVerifier ? "available" : "UNAVAILABLE — " + status.sigstoreDetail)")
            out("YARA engine          : \(status.yaraEngine ? "bundled and signed" : "not available (scans report UNKNOWN)")")
        }
        return Exit.ok
    }

    static func verifyRules(_ a: [String]) -> Int32 {
        let asJSON = a == ["--format", "json"]
        do {
            let s = try manager().verifyInstalled()
            if asJSON { out(json(VerifyOutput(schemaVersion: ToolInfo.jsonSchema, ok: true, files: s.fileCount, rulesRoot: s.rulesRoot, logSize: s.logSize, error: nil))) }
            else { out("OK: \(s.fileCount) files match the signed manifest; rules_root \(s.rulesRoot); log size \(s.logSize).") }
            return Exit.ok
        } catch {
            let reason = (error as? ChannelVerifier.Failure)?.reason ?? "\(error)"
            if asJSON { out(json(VerifyOutput(schemaVersion: ToolInfo.jsonSchema, ok: false, files: nil, rulesRoot: nil, logSize: nil, error: reason))) } else { err("NOT VERIFIED: \(reason)") }
            return reason.contains("no Sigstore verifier") || reason.contains("no verified channel release") ? Exit.unavailable : Exit.failed
        }
    }

    static func updateRules(_ a: [String]) -> Int32 {
        let asJSON = a.contains("json")
        if !a.contains("--yes") {
            guard isatty(STDIN_FILENO) != 0 else { err("Refusing to download without consent: pass --yes in scripts."); return Exit.usage }
            FileHandle.standardError.write(Data("Download and verify the signed rules from \(YARARuleManager.defaultChannelBase.absoluteString)? [y/N] ".utf8))
            guard (readLine() ?? "").lowercased().hasPrefix("y") else { err("Cancelled; nothing changed."); return Exit.ok }
        }
        let m = manager()
        let sem = DispatchSemaphore(value: 0)
        var code = Exit.failed
        var message = ""
        m.checkForUpdates()
        // checkForUpdates/update publish on the main queue, so wait on a background thread and spin the main run loop.
        DispatchQueue.global().async {
            for _ in 0..<400 { if !m.checking { break }; Thread.sleep(forTimeInterval: 0.05) }
            DispatchQueue.main.async {
                guard m.availableRevision != nil else { message = m.message; code = Exit.unavailable; sem.signal(); return }
                m.update { msg in message = msg; code = m.lastResultOK ? Exit.ok : Exit.failed; sem.signal() }
            }
        }
        while sem.wait(timeout: .now() + 0.05) == .timedOut { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        if asJSON { out(json(UpdateOutput(schemaVersion: ToolInfo.jsonSchema, ok: code == Exit.ok, updated: code == Exit.ok, message: message))) } else { out(message) }
        return code
    }
}

enum Render {
    static func text(_ r: AuditReport) -> String {
        var s = "\n\(r.file) [\(r.kind)]  score \(r.score)/10  blockers \(r.blockers)\n  coverage: \(r.coverage)\n"
        for f in r.findings { s += "  [\(f.state.rawValue.uppercased())] \(f.title): \(f.detail.replacingOccurrences(of: "\n", with: " ").prefix(220))\n" }
        return s + "  \(r.assessmentNote)"
    }
}
