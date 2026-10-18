import Foundation
import CryptoKit

struct AuditInput {
    let file: URL
    let expectedName: String
    let expectedTeam: String
    let expectedBundle: String
    let expectedSHA: String
    let sourceURL: String
}

enum AuditState: String, Codable { case passed, warning, failed, unknown }
struct AuditFinding: Identifiable, Codable {
    var id = UUID()
    /// `id` is a view identity only; it is not part of the exported report so JSON output is stable.
    private enum CodingKeys: String, CodingKey { case title, detail, state, weight }
    let title: String
    let detail: String
    let state: AuditState
    let weight: Int
}
struct AuditReport: Codable {
    var schemaVersion = 1
    var kind = "unknown"
    var sha256 = ""
    var coverage = ""
    let file: String
    let timestamp: Date
    let findings: [AuditFinding]
    let score: Int
    let blockers: Int
    let evidenceURL: String
    let assessmentNote: String
}

enum AuditEngine {
    @discardableResult
    static func run(_ path: String, _ args: [String]) throws -> String {
        let r = command(path, args)
        guard r.0 == 0 else { throw NSError(domain: "AuditEngine", code: Int(r.0), userInfo: [NSLocalizedDescriptionKey: r.1]) }
        return r.1
    }
    /// Every helper tool runs with a timeout and an output cap so hostile input cannot hang the caller.
    static func command(_ path: String, _ args: [String], timeout: TimeInterval = 120) -> (Int32, String) {
        let r = BoundedProcess.run(path, args, timeout: timeout)
        return (r.timedOut ? -2 : r.status, r.timedOut ? "Timed out after \(Int(timeout)) s" : r.output)
    }
    static func sha256(of url: URL) -> String? {
        guard let f = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? f.close() }
        var h = SHA256()
        while true {
            guard let d = try? f.read(upToCount: 1 << 20) else { return nil }
            if d.isEmpty { break }
            h.update(data: d)
        }
        return h.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Collects findings for one audit.
    final class Collector {
        var findings: [AuditFinding] = []
        var observedBundle = ""; var observedTeam = ""
        func add(_ title: String, _ detail: String, _ state: AuditState, _ weight: Int) {
            findings.append(AuditFinding(title: title, detail: detail, state: state, weight: weight))
        }
    }

    static func audit(_ input: AuditInput, cancelled: (() -> Bool)? = nil) -> AuditReport {
        let c = Collector()
        let fm = FileManager.default
        guard fm.fileExists(atPath: input.file.path) else {
            c.add("Input file", "File not found.", .failed, 10)
            return report(input, c, kind: "missing", sha: "")
        }
        let detection = ContentDetector.detect(input.file)
        let kind = detection.kind
        if let mismatch = detection.extensionMismatch {
            c.add("File type vs name", "The content is \(label(kind)) but the name ends in \(mismatch).", .warning, 3)
        }
        if !input.sourceURL.isEmpty {
            let url = URL(string: input.sourceURL)
            if let url, url.scheme == "https", url.host != nil, url.user == nil, url.password == nil {
                c.add("Reference URL / URL de referencia", "User supplied: \(url.absoluteString). This URL is NOT independently authenticated or checked against the publisher.", .unknown, 0)
            } else {
                c.add("Reference URL / URL de referencia", "Invalid or non-HTTPS reference URL; use an independently verified publisher website.", .warning, 0)
            }
        }
        var isDir: ObjCBool = false; fm.fileExists(atPath: input.file.path, isDirectory: &isDir)
        let actualSHA = isDir.boolValue ? "" : (sha256(of: input.file) ?? "")
        let expectedSHA = input.expectedSHA.lowercased().filter { !$0.isWhitespace }
        if isDir.boolValue {
            c.add("SHA-256", "Bundles and folders have no single file hash; verify the container they were distributed in.", .unknown, 18)
        } else if expectedSHA.isEmpty { c.add("SHA-256", "Calculated: \(actualSHA). No independent reference supplied.", .unknown, 18) }
        else if expectedSHA.count != 64 || expectedSHA.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789abcdef").inverted) != nil {
            c.add("SHA-256", "Expected SHA-256 is malformed.", .failed, 18)
        } else { c.add("SHA-256", "Calculated: \(actualSHA)", actualSHA == expectedSHA ? .passed : .failed, 18) }

        let temp = fm.temporaryDirectory.appendingPathComponent("dmgtrust-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: temp, withIntermediateDirectories: true)
        var keepTemp = false
        defer { if !keepTemp { try? fm.removeItem(at: temp) } }

        switch kind {
        case .dmg, .iso:
            keepTemp = auditDiskImage(input, kind: kind, temp: temp, c, cancelled)
        case .app:
            if c.observedBundle.isEmpty { _ = analyzeApp(input.file, input, c) }
            inspectBundle(input.file, input: input, temp: temp, depth: 0, c, cancelled)
            let urls = (fm.enumerator(at: input.file, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey], options: [])?.allObjects as? [URL]) ?? []
            c.findings.append(contentsOf: YARAScanner.inspect(regularFiles(urls)))
        case .pkg, .mpkg:
            c.findings.append(contentsOf: PackageAndMalwareInspector.inspect(packages: [input.file], looseScripts: [], workspace: temp))
            inspectPackagePayloads(temp, c, cancelled)
        case .zip, .tar, .tarGzip:
            auditArchive(input.file, temp: temp, depth: 0, c, cancelled)
        case .gzip:
            let out = temp.appendingPathComponent("decompressed")
            do {
                let n = try ArchiveExtractor.gunzip(input.file, to: out)
                c.add("Archive extraction", "Single-file gzip expanded to \(n) bytes in a private folder (nothing was run).", .passed, 6)
                auditArchive(out, temp: temp.appendingPathComponent("inner"), depth: 1, c, cancelled, treatAsPlainFile: true)
            } catch { c.add("Archive extraction", "Refused: \((error as? ArchiveExtractor.Failure)?.reason ?? error.localizedDescription)", .failed, 6) }
        case .machO:
            analyzeMachO(input.file, c)
            c.findings.append(contentsOf: YARAScanner.inspect([input.file]))
        case .script(let language):
            c.findings.append(PackageAndMalwareInspector.scanScript(input.file, label: "Script (\(language.rawValue))"))
            c.add("Script scope", "The script was read, never executed. A clean pattern scan does not prove it is safe.", .unknown, 0)
            c.findings.append(contentsOf: YARAScanner.inspect([input.file]))
        case .appleScriptCompiled:
            auditCompiledAppleScript(input.file, temp: temp, c)
            c.findings.append(contentsOf: YARAScanner.inspect([input.file]))
        case .workflow:
            auditWorkflow(input.file, c)
        case .unknown:
            c.add("File type", "Unsupported or unrecognized format; it is not assumed safe and was not analyzed.", .unknown, 25)
        }
        c.findings.append(contentsOf: ExternalEvidence.inspect(input, observedBundle: c.observedBundle, observedTeam: c.observedTeam))
        return report(input, c, kind: label(kind), sha: actualSHA)
    }

    static func label(_ k: ContentKind) -> String {
        switch k {
        case .dmg: return "dmg"; case .pkg: return "pkg"; case .mpkg: return "mpkg"; case .app: return "app"
        case .zip: return "zip"; case .tar: return "tar"; case .tarGzip: return "tar.gz"; case .gzip: return "gzip"
        case .machO: return "mach-o"; case .script(let l): return "script:\(l.rawValue)"; case .workflow: return "workflow"
        case .appleScriptCompiled: return "scpt"; case .iso: return "iso"; case .unknown: return "unknown"
        }
    }

    static func regularFiles(_ urls: [URL]) -> [URL] {
        urls.filter { url in
            guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else { return false }
            return v.isRegularFile == true && v.isSymbolicLink != true
        }
    }

    // MARK: Disk images (DMG, ISO)
    /// Returns true when the temp directory must be kept because the volume could not be detached.
    private static func auditDiskImage(_ input: AuditInput, kind: ContentKind, temp: URL, _ c: Collector, _ cancelled: (() -> Bool)?) -> Bool {
        let file = input.file.path
        if case .dmg = kind {
            let verify = command("/usr/bin/hdiutil", ["verify", file])
            c.add("DMG structure", String(verify.1.suffix(500)), verify.0 == 0 ? .passed : .failed, 8)
            let sig = command("/usr/bin/codesign", ["--verify", "--verbose=2", file])
            c.add("DMG signature", String(sig.1.suffix(400)), sig.0 == 0 ? .passed : .unknown, 5)
            guard verify.0 == 0 else { return false }
        }
        let mount = temp.appendingPathComponent("mount", isDirectory: true)
        do { try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true) }
        catch { c.add("Mount", error.localizedDescription, .failed, 10); return false }
        let attach = command("/usr/bin/hdiutil", ["attach", file, "-readonly", "-nobrowse", "-noautoopen", "-noverify", "-mountpoint", mount.path])
        guard attach.0 == 0 else { c.add("Read-only mount", attach.1, .failed, 10); return false }
        let tree = inspectTree(mount, input: input, temp: temp, depth: 0, c, cancelled)
        _ = tree
        let detached = command("/usr/bin/hdiutil", ["detach", mount.path])
        return detached.0 != 0   // never delete an attached volume
    }

    // MARK: Shared tree inspection (mounted volume or extracted archive)
    @discardableResult
    static func inspectTree(_ root: URL, input: AuditInput, temp: URL, depth: Int, _ c: Collector, _ cancelled: (() -> Bool)?) -> Int {
        let urls = (FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])?.allObjects as? [URL]) ?? []
        let apps = urls.filter { $0.pathExtension.lowercased() == "app" && !$0.pathComponents.dropLast().contains(where: { $0.hasSuffix(".app") }) }
        let pkgs = urls.filter { ["pkg", "mpkg"].contains($0.pathExtension.lowercased()) }
        let scripts = urls.filter { ["command", "sh", "bash", "zsh", "scpt", "applescript", "workflow"].contains($0.pathExtension.lowercased()) }
        if !scripts.isEmpty {
            c.add("Loose scripts / Scripts sueltos", "Found \(scripts.count) potential scripts or command files; they are read, never executed. Examples: \(scripts.prefix(5).map(\.lastPathComponent).joined(separator: ", "))", .warning, 8)
        }
        c.findings.append(contentsOf: PackageAndMalwareInspector.inspect(packages: pkgs, looseScripts: scripts, workspace: temp))
        c.findings.append(contentsOf: YARAScanner.inspect(regularFiles(urls)))
        if apps.isEmpty && pkgs.isEmpty { c.add("Application bundles", "No .app or .pkg found. Other payload types require manual inspection.", .unknown, 25) }
        for app in apps.prefix(15) { _ = analyzeApp(app, input, c) }
        for app in apps.prefix(3) { inspectBundle(app, input: input, temp: temp.appendingPathComponent("bundle-\(app.lastPathComponent)"), depth: depth + 1, c, cancelled) }
        if apps.count > 15 { c.add("Inspection coverage", "More than 15 apps; some were not assessed.", .warning, 8) }
        if depth < 2 {
            let nested = urls.filter { u in
                guard (try? u.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true else { return false }
                if case .zip = ContentDetector.detect(u).kind { return true }
                if case .tarGzip = ContentDetector.detect(u).kind { return true }
                if case .tar = ContentDetector.detect(u).kind { return true }
                return false
            }
            for (i, archive) in nested.prefix(5).enumerated() {
                auditArchive(archive, temp: temp.appendingPathComponent("nested-\(depth)-\(i)"), depth: depth + 1, c, cancelled)
            }
            if nested.count > 5 { c.add("Nested archive coverage", "\(nested.count) nested archives found; only the first 5 were opened.", .warning, 4) }
        }
        return apps.count
    }

    // MARK: Archives
    static func auditArchive(_ archive: URL, temp: URL, depth: Int, _ c: Collector, _ cancelled: (() -> Bool)?, treatAsPlainFile: Bool = false) {
        let name = archive.lastPathComponent
        if treatAsPlainFile {
            let kind = ContentDetector.detect(archive).kind
            switch kind {
            case .tar, .zip, .tarGzip: break
            default:
                c.add("Decompressed content", "Content is \(label(kind)); inspecting it directly.", .unknown, 0)
                let inner = AuditInput(file: archive, expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: "")
                let sub = audit(inner, cancelled: cancelled)
                c.findings.append(contentsOf: sub.findings.filter { $0.title != "SHA-256" })
                return
            }
        }
        let dest = temp.appendingPathComponent("extracted", isDirectory: true)
        do {
            let r = try ArchiveExtractor.extract(archive, into: dest, cancelled: cancelled)
            c.add("Archive extraction: \(name)", "\(r.entries) entries, \(r.expandedBytes) bytes extracted into a private folder; nothing was run." + (r.removedLinks.isEmpty ? "" : " Removed \(r.removedLinks.count) link(s) that left the folder: \(r.removedLinks.prefix(3).joined(separator: "; ")).") , r.removedLinks.isEmpty ? .passed : .warning, 6)
            let input = AuditInput(file: archive, expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: "")
            inspectTree(dest, input: input, temp: temp, depth: depth, c, cancelled)
        } catch {
            c.add("Archive extraction: \(name)", "Refused: \((error as? ArchiveExtractor.Failure)?.reason ?? error.localizedDescription). Contents were not analyzed.", .failed, 6)
        }
    }

    /// PKG `Payload` and `Scripts` members are cpio/gzip archives; open them like any archive and scan what is inside.
    static func inspectPackagePayloads(_ temp: URL, _ c: Collector, _ cancelled: (() -> Bool)?) {
        let fm = FileManager.default
        guard let en = fm.enumerator(at: temp, includingPropertiesForKeys: [.isRegularFileKey], options: []) else { return }
        let members = en.compactMap { $0 as? URL }.filter { ["Payload", "Scripts"].contains($0.lastPathComponent) &&
            (try? $0.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true }
        for (i, member) in members.prefix(20).enumerated() {
            let dest = temp.appendingPathComponent("pkg-member-\(i)", isDirectory: true)
            do {
                let r = try ArchiveExtractor.extract(member, into: dest, cancelled: cancelled)
                c.add("PKG \(member.lastPathComponent) opened", "\(r.entries) entries extracted (never executed).", .passed, 0)
                let urls = (fm.enumerator(at: dest, includingPropertiesForKeys: nil, options: [])?.allObjects as? [URL]) ?? []
                let files = regularFiles(urls)
                for script in files.filter({ ContentDetector.detect($0).kind != .unknown }).prefix(100) {
                    switch ContentDetector.detect(script).kind {
                    case .script: c.findings.append(PackageAndMalwareInspector.scanScript(script, label: "PKG \(member.lastPathComponent) script: \(script.lastPathComponent)"))
                    case .machO: analyzeMachO(script, c, quiet: true)
                    default: break
                    }
                }
                c.findings.append(contentsOf: YARAScanner.inspect(files))
            } catch {
                c.add("PKG \(member.lastPathComponent) opened", "Not opened: \((error as? ArchiveExtractor.Failure)?.reason ?? error.localizedDescription).", .warning, 0)
            }
        }
    }

    // MARK: Code
    static func analyzeMachO(_ url: URL, _ c: Collector, quiet: Bool = false) {
        let name = url.lastPathComponent
        let sig = command("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", url.path])
        c.add("Code signature: \(name)", String(sig.1.suffix(500)), sig.0 == 0 ? .passed : (quiet ? .warning : .failed), quiet ? 2 : 20)
        let details = command("/usr/bin/codesign", ["-dv", "--verbose=4", url.path]).1
        let authorities = details.components(separatedBy: "\n").filter { $0.hasPrefix("Authority=") }
        let team = details.components(separatedBy: "\n").first(where: { $0.hasPrefix("TeamIdentifier=") })?.replacingOccurrences(of: "TeamIdentifier=", with: "") ?? ""
        if c.observedTeam.isEmpty && team != "not set" { c.observedTeam = team }
        if !quiet {
            c.add("Signing identity: \(name)", "Team ID: \(team.isEmpty ? "none" : team). Authorities: \(authorities.joined(separator: " | ")). A certificate assertion, not a match to the publisher.", sig.0 == 0 && !team.isEmpty && team != "not set" ? .unknown : .warning, 10)
            c.add("Hardened Runtime: \(name)", details.contains("runtime") ? "Runtime flag present" : "Runtime flag not established", details.contains("runtime") ? .passed : .warning, 5)
            let ent = command("/usr/bin/codesign", ["-d", "--entitlements", "-", url.path]).1
            let sensitive = ["com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.get-task-allow"].filter { ent.contains($0) }
            c.add("Sensitive entitlements: \(name)", sensitive.isEmpty ? "No listed high-interest entitlements in the displayed output. NOT a full entitlement review." : "Manual review: \(sensitive.joined(separator: ", "))", sensitive.isEmpty ? .unknown : .warning, 5)
            let gate = command("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=4", url.path])
            c.add("Gatekeeper: \(name)", String(gate.1.suffix(400)), gate.0 == 0 ? .passed : .warning, 9)
        }
        let arch = command("/usr/bin/lipo", ["-archs", url.path])
        c.add("Architectures: \(name)", arch.1.trimmingCharacters(in: .whitespacesAndNewlines), arch.0 == 0 ? .passed : .warning, 3)
    }

    @discardableResult
    static func analyzeApp(_ app: URL, _ input: AuditInput, _ c: Collector) -> (bundle: String, team: String) {
        let name = app.lastPathComponent
        let plist = app.appendingPathComponent("Contents/Info.plist")
        let info = NSDictionary(contentsOf: plist) as? [String: Any] ?? [:]
        let bundle = info["CFBundleIdentifier"] as? String ?? ""
        if c.observedBundle.isEmpty { c.observedBundle = bundle }
        let execName = info["CFBundleExecutable"] as? String ?? ""
        let signature = command("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", app.path])
        c.add("Code signature: \(name)", String(signature.1.suffix(600)), signature.0 == 0 ? .passed : .failed, 20)
        let details = command("/usr/bin/codesign", ["-dv", "--verbose=4", app.path]).1
        let authorities = details.components(separatedBy: "\n").filter { $0.hasPrefix("Authority=") }
        let developerID = authorities.contains { $0.contains("Developer ID Application:") }
        c.add("Developer ID / Identidad de firma", "Certificate chain labels: \(authorities.joined(separator: " | ")). Developer ID is a certificate assertion, not an independent match to the publisher's website.", developerID && signature.0 == 0 ? .passed : .warning, 10)
        let nested = command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", app.path])
        c.add("Nested code / Código anidado", "Secondary deep verification (not a replacement for individual verification): \(String(nested.1.suffix(400)))", nested.0 == 0 ? .passed : .failed, 8)
        let team = details.components(separatedBy: "\n").first(where: { $0.hasPrefix("TeamIdentifier=") })?.replacingOccurrences(of: "TeamIdentifier=", with: "") ?? ""
        if c.observedTeam.isEmpty { c.observedTeam = team }
        if input.expectedTeam.isEmpty { c.add("Developer Team ID", "Observed: \(team). Independently verify its owner.", .unknown, 16) }
        else { c.add("Developer Team ID", "Observed: \(team)", team == input.expectedTeam ? .passed : .failed, 16) }
        if input.expectedBundle.isEmpty { c.add("Bundle identifier", "Observed: \(bundle)", .unknown, 4) }
        else { c.add("Bundle identifier", "Observed: \(bundle)", bundle == input.expectedBundle ? .passed : .failed, 4) }
        if let v = info["CFBundleShortVersionString"] as? String { c.add("Bundle version", "Observed: \(v)", .unknown, 0) }
        if !input.expectedName.isEmpty { c.add("Application name", name, name.localizedCaseInsensitiveContains(input.expectedName) ? .passed : .warning, 2) }
        c.add("Hardened Runtime", details.contains("flags=0x") && details.contains("runtime") ? "Runtime flag present" : "Runtime flag not established", details.contains("runtime") ? .passed : .warning, 5)
        let gate = command("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=4", app.path])
        c.add("Gatekeeper", String(gate.1.suffix(700)), gate.0 == 0 ? .passed : .warning, 9)
        let entitlements = command("/usr/bin/codesign", ["-d", "--entitlements", "-", app.path])
        let sensitive = ["com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.get-task-allow"]
        let detected = sensitive.filter { entitlements.1.contains($0) }
        c.add("Sensitive entitlements / Permisos sensibles", detected.isEmpty ? "No listed high-interest entitlements found in displayed output. This is NOT a full entitlement security review." : "Manual review: \(detected.joined(separator: ", "))", detected.isEmpty ? .unknown : .warning, 5)
        let staple = command("/usr/bin/xcrun", ["stapler", "validate", app.path])
        c.add("Stapled notarization ticket", String(staple.1.suffix(700)), staple.0 == 0 ? .passed : .unknown, 7)
        if !execName.isEmpty {
            let binary = app.appendingPathComponent("Contents/MacOS/\(execName)")
            let arch = command("/usr/bin/lipo", ["-archs", binary.path])
            c.add("Architectures", arch.1.trimmingCharacters(in: .whitespacesAndNewlines), arch.0 == 0 ? .passed : .warning, 3)
        }
        c.add("Entitlements review", "Full entitlement, binary and behavior review not performed.", .unknown, 5)
        return (bundle, team)
    }

    // MARK: Automation formats
    static func auditCompiledAppleScript(_ url: URL, temp: URL, _ c: Collector) {
        // osadecompile reads the compiled script and prints source; it does not run it.
        let r = BoundedProcess.run("/usr/bin/osadecompile", [url.path], timeout: 30, maxOutput: 2_000_000)
        if r.status == 0, !r.output.isEmpty {
            c.findings.append(PackageAndMalwareInspector.scanText(r.output, label: "Compiled AppleScript (decompiled)"))
            c.add("AppleScript scope", "The script was decompiled for reading and never executed.", .unknown, 0)
        } else {
            c.add("Compiled AppleScript", "Could not be decompiled (\(r.output.prefix(120))); manual review required.", .unknown, 10)
        }
    }

    static func auditWorkflow(_ url: URL, _ c: Collector) {
        let doc = url.appendingPathComponent("Contents/document.wflow")
        guard let plist = NSDictionary(contentsOf: doc) as? [String: Any], let actions = plist["actions"] as? [[String: Any]] else {
            c.add("Automator workflow", "No readable Contents/document.wflow; manual review required.", .unknown, 10); return
        }
        var texts: [String] = []; var kinds: [String] = []
        for a in actions {
            guard let action = a["action"] as? [String: Any] else { continue }
            if let n = action["AMName"] as? String { kinds.append(n) }
            if let p = action["ActionParameters"] as? [String: Any] {
                for key in ["COMMAND_STRING", "source", "script"] { if let t = p[key] as? String { texts.append(t) } }
            }
        }
        c.add("Automator workflow", "\(actions.count) action(s): \(Set(kinds).sorted().joined(separator: ", ")). Actions were read, never run.", .unknown, 0)
        let risky = kinds.filter { $0.contains("Shell Script") || $0.contains("AppleScript") || $0.contains("JavaScript") }
        if !risky.isEmpty { c.add("Workflow runs code", "Contains script actions: \(Set(risky).sorted().joined(separator: ", ")).", .warning, 8) }
        if !texts.isEmpty { c.findings.append(PackageAndMalwareInspector.scanText(texts.joined(separator: "\n"), label: "Workflow embedded scripts")) }
        c.findings.append(contentsOf: YARAScanner.inspect(regularFiles((FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil, options: [])?.allObjects as? [URL]) ?? [])))
    }

    private static func report(_ input: AuditInput, _ c: Collector, kind: String, sha: String) -> AuditReport {
        let findings = c.findings
        let total = findings.reduce(0) { $0 + $1.weight }
        let earned = findings.filter { $0.state == .passed }.reduce(0) { $0 + $1.weight }
        let blockers = findings.filter { $0.state == .failed }.count
        var score = total == 0 ? 1 : max(1, min(10, Int((Double(earned) / Double(total) * 9.0 + 1.0).rounded())))
        if blockers > 0 { score = min(score, 3) }
        let critical = findings.contains { f in
            f.state == .failed && (f.title.hasPrefix("SHA-256") || f.title.hasPrefix("Code signature") || f.title.hasPrefix("Nested code") || f.title.hasPrefix("Developer Team ID") || f.title == "DMG structure" || f.title.hasPrefix("Archive extraction"))
        }
        if critical { score = min(score, 2) }
        var r = AuditReport(file: input.file.path, timestamp: Date(), findings: findings, score: score, blockers: blockers, evidenceURL: input.sourceURL, assessmentNote: "Heuristic verification coverage, not a malware-free probability. Unknown evidence earns zero; signature, integrity and identity contradictions impose score caps. Gatekeeper success and a stapled ticket do not independently prove vendor ownership. Missing stapling does not prove missing notarization.")
        r.kind = kind; r.sha256 = sha
        r.coverage = coverageNote(kind)
        return r
    }

    static func coverageNote(_ kind: String) -> String {
        switch kind {
        case "dmg", "iso": return "partial: image verified and mounted read-only; apps, packages, scripts and nested archives (2 levels) inspected statically"
        case "pkg", "mpkg": return "partial: signature, expanded metadata, Scripts and Payload members opened and scanned statically"
        case "app": return "partial: signature, identity, entitlements, Gatekeeper; binaries not behavior-analyzed"
        case "zip", "tar", "tar.gz", "gzip": return "partial: safely extracted with limits; contents inspected statically"
        case "mach-o": return "partial: signature, identity, architectures, entitlements; no disassembly"
        case "workflow", "scpt": return "limited: actions or decompiled source read statically"
        case let k where k.hasPrefix("script"): return "limited: pattern scan of the source; no execution"
        default: return "none: format not supported"
        }
    }
}
