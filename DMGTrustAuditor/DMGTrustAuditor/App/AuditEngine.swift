import Foundation

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
    let title: String
    let detail: String
    let state: AuditState
    let weight: Int
}
struct AuditReport: Codable {
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
    static func command(_ path: String, _ args: [String]) -> (Int32, String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { return (-1, error.localizedDescription) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }
    static func audit(_ input: AuditInput) -> AuditReport {
        var findings: [AuditFinding] = []
        func add(_ title: String, _ detail: String, _ state: AuditState, _ weight: Int) {
            findings.append(AuditFinding(title: title, detail: detail, state: state, weight: weight))
        }
        let file = input.file.path
        guard FileManager.default.fileExists(atPath: file), input.file.pathExtension.lowercased() == "dmg" else {
            add("DMG file", "File not found or not a .dmg", .failed, 10)
            return report(input, findings)
        }
        if !input.sourceURL.isEmpty {
            let url = URL(string: input.sourceURL)
            if let url, url.scheme == "https", url.host != nil, url.user == nil, url.password == nil {
                add("Reference URL / URL de referencia", "User supplied: \(url.absoluteString). This URL is NOT independently authenticated or checked against the publisher.", .unknown, 0)
            } else {
                add("Reference URL / URL de referencia", "Invalid or non-HTTPS reference URL; use an independently verified publisher website.", .warning, 0)
            }
        }
        let sha = command("/usr/bin/shasum", ["-a", "256", file])
        let actualSHA = sha.1.components(separatedBy: .whitespacesAndNewlines).first ?? ""
        let expectedSHA = input.expectedSHA.lowercased().filter { !$0.isWhitespace }
        if expectedSHA.isEmpty { add("SHA-256", "Calculated: \(actualSHA). No independent reference supplied.", .unknown, 18) }
        else if expectedSHA.count != 64 || expectedSHA.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789abcdef").inverted) != nil {
            add("SHA-256", "Expected SHA-256 is malformed.", .failed, 18)
        } else { add("SHA-256", "Calculated: \(actualSHA)", actualSHA == expectedSHA ? .passed : .failed, 18) }
        let verify = command("/usr/bin/hdiutil", ["verify", file])
        add("DMG structure", String(verify.1.suffix(500)), verify.0 == 0 ? .passed : .failed, 8)
        let dmgSignature = command("/usr/bin/codesign", ["--verify", "--verbose=2", file])
        add("DMG signature", String(dmgSignature.1.suffix(400)), dmgSignature.0 == 0 ? .passed : .unknown, 5)
        guard verify.0 == 0 else { return report(input, findings) }
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("dmgtrust-\(UUID().uuidString)", isDirectory: true)
        let mount = temp.appendingPathComponent("mount", isDirectory: true)
        do { try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true) }
        catch { add("Mount", error.localizedDescription, .failed, 10); return report(input, findings) }
        let attach = command("/usr/bin/hdiutil", ["attach", file, "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount.path])
        guard attach.0 == 0 else {
            add("Read-only mount", attach.1, .failed, 10)
            try? FileManager.default.removeItem(at: temp)
            return report(input, findings)
        }
        defer {
            let detached = command("/usr/bin/hdiutil", ["detach", mount.path])
            if detached.0 == 0 { try? FileManager.default.removeItem(at: temp) }
            // Preserve mount and temporary directory if detach fails; never delete an attached volume.
        }
        let urls = (FileManager.default.enumerator(at: mount, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])?.allObjects as? [URL]) ?? []
        let apps = urls.filter { $0.pathExtension.lowercased() == "app" && !$0.pathComponents.dropLast().contains(where: { $0.hasSuffix(".app") }) }
        let pkgs = urls.filter { $0.pathExtension.lowercased() == "pkg" }
        let otherInstallers = urls.filter { ["command", "sh", "bash", "zsh", "scpt", "applescript", "workflow"].contains($0.pathExtension.lowercased()) }
        if !otherInstallers.isEmpty {
            add("Loose scripts / Scripts sueltos", "Found \(otherInstallers.count) potential scripts or command files; content is NOT executed or reviewed. Examples: \(otherInstallers.prefix(5).map(\.lastPathComponent).joined(separator: ", "))", .warning, 8)
        }
        findings.append(contentsOf: PackageAndMalwareInspector.inspect(packages: pkgs, looseScripts: otherInstallers, workspace: temp))
        let scanFiles = urls.filter { url in
            guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else { return false }
            return v.isRegularFile == true && v.isSymbolicLink != true
        }
        findings.append(contentsOf: YARAScanner.inspect(scanFiles))
        if apps.isEmpty { add("Application bundles", "No .app found. Other payload types require manual inspection.", .unknown, 25) }
        var observedBundle = ""
        var observedTeam = ""
        for app in apps.prefix(15) {
            let name = app.lastPathComponent
            let plist = app.appendingPathComponent("Contents/Info.plist")
            let info = NSDictionary(contentsOf: plist) as? [String: Any] ?? [:]
            let bundle = info["CFBundleIdentifier"] as? String ?? ""
            if observedBundle.isEmpty { observedBundle = bundle }
            let execName = info["CFBundleExecutable"] as? String ?? ""
            let signature = command("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", app.path])
            add("Code signature: \(name)", String(signature.1.suffix(600)), signature.0 == 0 ? .passed : .failed, 20)
            let details = command("/usr/bin/codesign", ["-dv", "--verbose=4", app.path]).1
            let authorities = details.components(separatedBy: "\n").filter { $0.hasPrefix("Authority=") }
            let developerID = authorities.contains { $0.contains("Developer ID Application:") }
            add("Developer ID / Identidad de firma", "Certificate chain labels: \(authorities.joined(separator: " | ")). Developer ID is a certificate assertion, not an independent match to the publisher's website.", developerID && signature.0 == 0 ? .passed : .warning, 10)
            let nested = command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", app.path])
            add("Nested code / Código anidado", "Secondary deep verification (not a replacement for individual verification): \(String(nested.1.suffix(400)))", nested.0 == 0 ? .passed : .failed, 8)
            let team = details.components(separatedBy: "\n").first(where: { $0.hasPrefix("TeamIdentifier=") })?.replacingOccurrences(of: "TeamIdentifier=", with: "") ?? ""
            if observedTeam.isEmpty { observedTeam = team }
            if input.expectedTeam.isEmpty { add("Developer Team ID", "Observed: \(team). Independently verify its owner.", .unknown, 16) }
            else { add("Developer Team ID", "Observed: \(team)", team == input.expectedTeam ? .passed : .failed, 16) }
            if input.expectedBundle.isEmpty { add("Bundle identifier", "Observed: \(bundle)", .unknown, 4) }
            else { add("Bundle identifier", "Observed: \(bundle)", bundle == input.expectedBundle ? .passed : .failed, 4) }
            if !input.expectedName.isEmpty { add("Application name", name, name.localizedCaseInsensitiveContains(input.expectedName) ? .passed : .warning, 2) }
            add("Hardened Runtime", details.contains("flags=0x") && details.contains("runtime") ? "Runtime flag present" : "Runtime flag not established", details.contains("runtime") ? .passed : .warning, 5)
            let gate = command("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=4", app.path])
            add("Gatekeeper", String(gate.1.suffix(700)), gate.0 == 0 ? .passed : .warning, 9)
            let entitlements = command("/usr/bin/codesign", ["-d", "--entitlements", "-", app.path])
            let sensitive = ["com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.get-task-allow"]
            let detected = sensitive.filter { entitlements.1.contains($0) }
            add("Sensitive entitlements / Permisos sensibles", detected.isEmpty ? "No listed high-interest entitlements found in displayed output. This is NOT a full entitlement security review." : "Manual review: \(detected.joined(separator: ", "))", detected.isEmpty ? .unknown : .warning, 5)
            let staple = command("/usr/bin/xcrun", ["stapler", "validate", app.path])
            add("Stapled notarization ticket", String(staple.1.suffix(700)), staple.0 == 0 ? .passed : .unknown, 7)
            if !execName.isEmpty {
                let binary = app.appendingPathComponent("Contents/MacOS/\(execName)")
                let arch = command("/usr/bin/lipo", ["-archs", binary.path])
                add("Architectures", arch.1.trimmingCharacters(in: .whitespacesAndNewlines), arch.0 == 0 ? .passed : .warning, 3)
            }
            add("Entitlements review", "Full entitlement, binary and behavior review not performed.", .unknown, 5)
        }
        if apps.count > 15 { add("Inspection coverage", "More than 15 apps; some were not assessed.", .warning, 8) }
        findings.append(contentsOf: ExternalEvidence.inspect(input, observedBundle: observedBundle, observedTeam: observedTeam))
        return report(input, findings)
    }
    private static func report(_ input: AuditInput, _ findings: [AuditFinding]) -> AuditReport {
        let total = findings.reduce(0) { $0 + $1.weight }
        let earned = findings.filter { $0.state == .passed }.reduce(0) { $0 + $1.weight }
        let blockers = findings.filter { $0.state == .failed }.count
        var score = total == 0 ? 1 : max(1, min(10, Int((Double(earned) / Double(total) * 9.0 + 1.0).rounded())))
        if blockers > 0 { score = min(score, 3) }
        let critical = findings.contains { f in
            f.state == .failed && (f.title.hasPrefix("SHA-256") || f.title.hasPrefix("Code signature") || f.title.hasPrefix("Nested code") || f.title.hasPrefix("Developer Team ID") || f.title == "DMG structure")
        }
        if critical { score = min(score, 2) }
        return AuditReport(file: input.file.path, timestamp: Date(), findings: findings, score: score, blockers: blockers, evidenceURL: input.sourceURL, assessmentNote: "Heuristic verification coverage, not a malware-free probability. Unknown evidence earns zero; signature, integrity and identity contradictions impose score caps. Gatekeeper success and a stapled ticket do not independently prove vendor ownership. Missing stapling does not prove missing notarization.")
    }
}
