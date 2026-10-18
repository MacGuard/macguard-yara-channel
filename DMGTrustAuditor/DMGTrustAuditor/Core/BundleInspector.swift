import Foundation

/// Static inspection of an application bundle (`.app`). An `.app` can be the program itself or an installer
/// (it may carry packages, scripts, a privileged helper, nested archives). Nothing here launches the bundle:
/// files are read, Mach-O files are examined with codesign/lipo/nm, and scripts are pattern-scanned.
extension AuditEngine {
    struct BundleLimits { var maxEntries = 30_000; var machO = 25; var scripts = 60; var packages = 5; var archives = 3 }

    static func inspectBundle(_ app: URL, input: AuditInput, temp: URL, depth: Int, _ c: Collector, _ cancelled: (() -> Bool)?, limits: BundleLimits = BundleLimits()) {
        let fm = FileManager.default
        let name = app.lastPathComponent
        let infoURL = app.appendingPathComponent("Contents/Info.plist")
        let info = NSDictionary(contentsOf: infoURL) as? [String: Any]
        guard let info else {
            c.add("Bundle structure: \(name)", "Contents/Info.plist is missing or unreadable; this is not a well-formed application bundle.", .warning, 6); return
        }
        let version = info["CFBundleShortVersionString"] as? String ?? "", build = info["CFBundleVersion"] as? String ?? ""
        let execName = info["CFBundleExecutable"] as? String ?? ""
        let minOS = info["LSMinimumSystemVersion"] as? String ?? ""
        let mainExec = app.appendingPathComponent("Contents/MacOS/\(execName)")
        let execKind = execName.isEmpty ? ContentKind.unknown : ContentDetector.detect(mainExec).kind
        var structure = "Version \(version.isEmpty ? "not declared" : version)\(build.isEmpty ? "" : " (build \(build))"); minimum macOS \(minOS.isEmpty ? "not declared" : minOS); executable \(execName.isEmpty ? "not declared" : execName) is \(label(execKind))."
        var structureState = AuditState.unknown
        if execName.isEmpty || !fm.fileExists(atPath: mainExec.path) { structure += " The declared executable is missing."; structureState = .warning }
        else if execKind != .machO && !{ if case .script = execKind { return true }; return false }() { structure += " The executable is neither Mach-O nor a script."; structureState = .warning }
        c.add("Bundle structure: \(name)", structure, structureState, 3)

        // Certificate chain with fingerprints, from the signature itself.
        let certDir = temp.appendingPathComponent("certs-\(UUID().uuidString)"); try? fm.createDirectory(at: certDir, withIntermediateDirectories: true)
        _ = BoundedProcess.run("/usr/bin/codesign", ["-d", "--extract-certificates=\(certDir.path)/c", app.path], timeout: 30)
        var chain: [String] = []
        for i in 0..<6 {
            let f = certDir.appendingPathComponent("c\(i)")
            guard fm.fileExists(atPath: f.path) else { break }
            let r = BoundedProcess.run("/usr/bin/openssl", ["x509", "-inform", "der", "-in", f.path, "-noout", "-subject", "-enddate", "-fingerprint", "-sha256"], timeout: 15, maxOutput: 8000)
            let lines = r.output.split(separator: "\n").map(String.init)
            let subject = lines.first(where: { $0.hasPrefix("subject=") })?.replacingOccurrences(of: "subject=", with: "").trimmingCharacters(in: .whitespaces) ?? "?"
            let end = lines.first(where: { $0.hasPrefix("notAfter=") })?.replacingOccurrences(of: "notAfter=", with: "") ?? "?"
            let fp = lines.first(where: { $0.lowercased().contains("fingerprint") })?.split(separator: "=").last.map(String.init)?.replacingOccurrences(of: ":", with: "").lowercased() ?? "?"
            chain.append("[\(i)] \(subject) · expires \(end) · SHA-256 \(fp)")
        }
        try? fm.removeItem(at: certDir)
        c.add("Certificate chain: \(name)", chain.isEmpty ? "No certificate chain could be extracted (unsigned, ad-hoc signed, or unreadable)." : chain.joined(separator: "\n"), .unknown, 0)

        // Walk the bundle without following links.
        var machO: [URL] = [], scripts: [URL] = [], pkgs: [URL] = [], archives: [URL] = [], nestedBundles: [String] = [], plists: [URL] = []
        var seen = 0, truncated = false
        if let en = fm.enumerator(at: app, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey], options: []) {
            for case let u as URL in en {
                seen += 1
                if seen > limits.maxEntries { truncated = true; break }
                if cancelled?() == true { break }
                let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey])
                if v?.isSymbolicLink == true { continue }
                let ext = u.pathExtension.lowercased()
                if v?.isDirectory == true {
                    if ["app", "framework", "xpc", "appex", "bundle", "plugin", "kext", "systemextension"].contains(ext), u != app { nestedBundles.append(String(u.path.dropFirst(app.path.count + 1))) }
                    if ["pkg", "mpkg"].contains(ext) { pkgs.append(u) }
                    continue
                }
                guard v?.isRegularFile == true else { continue }
                if ext == "plist" && (u.path.contains("LaunchDaemons") || u.path.contains("LaunchAgents")) { plists.append(u) }
                if ext == "pkg" { pkgs.append(u); continue }
                switch ContentDetector.detect(u).kind {
                case .machO: machO.append(u)
                case .script: scripts.append(u)
                case .appleScriptCompiled: scripts.append(u)
                case .zip, .tar, .tarGzip: archives.append(u)
                case .dmg: archives.append(u)
                default: break
                }
            }
        }
        var inventory = "\(seen) entries; \(machO.count) Mach-O file(s), \(scripts.count) script(s), \(pkgs.count) package(s), \(archives.count) archive/image(s), \(nestedBundles.count) nested bundle(s)."
        if truncated { inventory += " Inventory stopped at \(limits.maxEntries) entries." }
        c.add("Bundle contents: \(name)", inventory, truncated ? .warning : .unknown, 0)

        // Mach-O files other than the main executable (already covered by the app signature checks).
        let others = machO.filter { $0.standardizedFileURL != mainExec.standardizedFileURL }
        for url in others.prefix(limits.machO) { analyzeMachO(url, c, quiet: true) }
        if others.count > limits.machO { c.add("Mach-O coverage", "\(others.count) additional Mach-O files; the first \(limits.machO) were checked.", .warning, 3) }

        for s in scripts.prefix(limits.scripts) {
            let rel = String(s.path.dropFirst(app.path.count + 1))
            if case .appleScriptCompiled = ContentDetector.detect(s).kind { auditCompiledAppleScript(s, temp: temp, c) }
            else { c.findings.append(PackageAndMalwareInspector.scanScript(s, label: "Bundle script: \(rel)")) }
        }
        if scripts.count > limits.scripts { c.add("Script coverage", "\(scripts.count) scripts; the first \(limits.scripts) were read.", .warning, 3) }

        if !pkgs.isEmpty {
            let ws = temp.appendingPathComponent("bundle-pkgs"); try? fm.createDirectory(at: ws, withIntermediateDirectories: true)
            c.findings.append(contentsOf: PackageAndMalwareInspector.inspect(packages: Array(pkgs.prefix(limits.packages)), looseScripts: [], workspace: ws))
            inspectPackagePayloads(ws, c, cancelled)
        }
        if depth < 2 {
            for (i, a) in archives.prefix(limits.archives).enumerated() where ContentDetector.detect(a).kind != .dmg {
                auditArchive(a, temp: temp.appendingPathComponent("bundle-archive-\(i)"), depth: depth + 1, c, cancelled)
            }
            if archives.contains(where: { ContentDetector.detect($0).kind == .dmg }) {
                c.add("Embedded disk image", "The bundle contains a disk image; it was not mounted from inside the bundle. Audit it separately.", .warning, 3)
            }
        }

        // Installer role: evidence only, never a verdict.
        var evidence: [String] = []
        let lower = name.lowercased()
        if lower.contains("install") || lower.contains("setup") || lower.contains("uninstall") { evidence.append("the bundle name suggests an installer") }
        if !pkgs.isEmpty { evidence.append("it carries \(pkgs.count) installer package(s)") }
        if !archives.isEmpty { evidence.append("it carries archives or disk images") }
        let helperDir = app.appendingPathComponent("Contents/Library/LaunchServices")
        let helpers = (try? fm.contentsOfDirectory(atPath: helperDir.path)) ?? []
        var privileged = false
        if info["SMPrivilegedExecutables"] != nil { evidence.append("Info.plist declares SMPrivilegedExecutables (privileged helper)"); privileged = true }
        if !helpers.isEmpty { evidence.append("Contents/Library/LaunchServices holds helper tool(s): \(helpers.prefix(3).joined(separator: ", "))"); privileged = true }
        if !plists.isEmpty { evidence.append("it bundles \(plists.count) launchd property list(s)") }
        if execKind == .machO {
            let nm = BoundedProcess.run("/usr/bin/nm", ["-u", mainExec.path], timeout: 20, maxOutput: 400_000).output
            for (sym, text) in [("SMJobBless", "uses SMJobBless to install a privileged helper"), ("AuthorizationExecuteWithPrivileges", "calls AuthorizationExecuteWithPrivileges"), ("SMAppService", "uses SMAppService to register login items or daemons")] where nm.contains(sym) {
                evidence.append(text); if sym != "SMAppService" { privileged = true }
            }
        }
        c.add("Installer role (heuristic): \(name)", evidence.isEmpty ? "No installer indicators found. This does not exclude that the program installs things." : "Indicators: " + evidence.joined(separator: "; ") + ". These show what the bundle can do, not what it did.", privileged ? .warning : .unknown, privileged ? 4 : 0)
    }
}
