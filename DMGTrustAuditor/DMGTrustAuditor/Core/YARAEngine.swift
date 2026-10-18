import Foundation
import CryptoKit

/// The YARA engine that ships with MacGuard (Contents/Helpers in the app, next to the CLI otherwise).
///
/// An engine directory is trusted only when ALL of these hold: it has `yara`, `yarac` and `engine-manifest.json`; the
/// SHA-256 of both binaries equals the manifest; both pass `codesign --verify --strict`; the version is at least
/// `minimumVersion`; the binary contains the CPU architecture we run on; and a self-test (compile a canary rule, scan a canary
/// file, expect the match) succeeds. There is no PATH or Homebrew fallback: a missing or damaged engine is reported, never replaced.
enum YARAEngine {
    static let minimumVersion = [4, 5, 0]
    static let selfTestRule = "rule MacGuard_SelfTest { strings: $a = \"MACGUARD-ENGINE-SELFTEST\" condition: $a }\n"

    struct Manifest: Decodable { let version: String; let architectures: String; let yara_sha256: String; let yarac_sha256: String; let minimum_macos: String? }
    struct Located { let directory: URL; let manifest: Manifest; var yara: URL { directory.appendingPathComponent("yara") }; var yarac: URL { directory.appendingPathComponent("yarac") } }
    struct Status { let located: Located?; let reason: String
        var ready: Bool { located != nil }
        var version: String { located?.manifest.version ?? "" }
        var architectures: String { located?.manifest.architectures ?? "" } }

    static func candidateDirectories(bundle: Bundle = .main, environment: [String: String] = ProcessInfo.processInfo.environment) -> [URL] {
        var dirs = [bundle.bundleURL.appendingPathComponent("Contents/Helpers")]
        let exe = URL(fileURLWithPath: CommandLine.arguments.first ?? "").resolvingSymlinksInPath().deletingLastPathComponent()
        dirs += [exe, exe.appendingPathComponent("engine"), exe.deletingLastPathComponent().appendingPathComponent("libexec/macguard")]
        if let d = environment["MACGUARD_YARA_DIR"] { dirs.append(URL(fileURLWithPath: d)) }   // development and tests; the same checks apply
        return dirs
    }

    static func currentArchitecture() -> String {
        #if arch(arm64)
        return "arm64"
        #else
        return "x86_64"
        #endif
    }

    private static func parseVersion(_ s: String) -> [Int] { s.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) } }
    static func versionAtLeast(_ v: [Int], _ min: [Int]) -> Bool { for i in 0..<max(v.count, min.count) { let a = i < v.count ? v[i] : 0, b = i < min.count ? min[i] : 0; if a != b { return a > b } }; return true }

    /// Checks one directory completely. Returns the reason when it is not trustworthy.
    static func verify(_ dir: URL) -> Status {
        let fm = FileManager.default
        let yara = dir.appendingPathComponent("yara"), yarac = dir.appendingPathComponent("yarac"), mf = dir.appendingPathComponent("engine-manifest.json")
        guard fm.isExecutableFile(atPath: yara.path), fm.isExecutableFile(atPath: yarac.path) else { return Status(located: nil, reason: "yara and yarac are not both present in \(dir.path)") }
        guard let data = try? Data(contentsOf: mf), let manifest = try? JSONDecoder().decode(Manifest.self, from: data) else { return Status(located: nil, reason: "engine-manifest.json is missing or unreadable in \(dir.path)") }
        guard AuditEngine.sha256(of: yara) == manifest.yara_sha256, AuditEngine.sha256(of: yarac) == manifest.yarac_sha256 else { return Status(located: nil, reason: "the engine binaries do not match engine-manifest.json (modified after the build)") }
        for bin in [yara, yarac] {
            let r = BoundedProcess.run("/usr/bin/codesign", ["--verify", "--strict", bin.path], timeout: 30)
            if r.status != 0 { return Status(located: nil, reason: "\(bin.lastPathComponent) has no valid code signature: \(r.output.prefix(120))") }
        }
        guard manifest.architectures.split(separator: " ").map(String.init).contains(currentArchitecture()) else { return Status(located: nil, reason: "the engine has no \(currentArchitecture()) slice (it has \(manifest.architectures))") }
        let ver = BoundedProcess.run(yara.path, ["--version"], timeout: 15)
        guard ver.status == 0, versionAtLeast(parseVersion(ver.output), minimumVersion), ver.output.trimmingCharacters(in: .whitespacesAndNewlines) == manifest.version || parseVersion(ver.output) == parseVersion(manifest.version) else {
            return Status(located: nil, reason: "engine version \(ver.output.trimmingCharacters(in: .whitespacesAndNewlines)) is not the manifest version \(manifest.version) or is older than \(minimumVersion.map(String.init).joined(separator: "."))")
        }
        let located = Located(directory: dir, manifest: manifest)
        if let why = selfTest(located) { return Status(located: nil, reason: "self-test failed: \(why)") }
        return Status(located: located, reason: "")
    }

    private static func selfTest(_ e: Located) -> String? {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("yara-selftest-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        do {
            try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            try selfTestRule.write(to: tmp.appendingPathComponent("t.yar"), atomically: true, encoding: .utf8)
            try "harmless\nMACGUARD-ENGINE-SELFTEST\n".write(to: tmp.appendingPathComponent("hit.txt"), atomically: true, encoding: .utf8)
            try "nothing here\n".write(to: tmp.appendingPathComponent("miss.txt"), atomically: true, encoding: .utf8)
        } catch { return error.localizedDescription }
        let c = BoundedProcess.run(e.yarac.path, [tmp.appendingPathComponent("t.yar").path, tmp.appendingPathComponent("t.yarc").path], timeout: 30)
        guard c.status == 0 else { return "could not compile the canary rule: \(c.output.prefix(100))" }
        let hit = BoundedProcess.run(e.yara.path, ["-C", tmp.appendingPathComponent("t.yarc").path, tmp.appendingPathComponent("hit.txt").path], timeout: 30)
        let miss = BoundedProcess.run(e.yara.path, ["-C", tmp.appendingPathComponent("t.yarc").path, tmp.appendingPathComponent("miss.txt").path], timeout: 30)
        guard hit.output.contains("MacGuard_SelfTest") else { return "the canary file did not match" }
        guard miss.status == 0, !miss.output.contains("MacGuard_SelfTest") else { return "the clean file matched or the scan failed" }
        return nil
    }

    private static let lock = NSLock()
    private static var cached: Status?
    /// First trustworthy directory among the candidates; cached for the life of the process (a damaged engine is re-checked by `reset()`).
    static func status(bundle: Bundle = .main, environment: [String: String] = ProcessInfo.processInfo.environment) -> Status {
        lock.lock(); defer { lock.unlock() }
        if let cached { return cached }
        var reasons: [String] = []
        for dir in candidateDirectories(bundle: bundle, environment: environment) where FileManager.default.fileExists(atPath: dir.appendingPathComponent("yara").path) {
            let s = verify(dir); if s.ready { cached = s; return s }; reasons.append(s.reason)
        }
        let s = Status(located: nil, reason: reasons.isEmpty ? "no YARA engine found next to MacGuard" : reasons.joined(separator: "; "))
        cached = s; return s
    }
    static func reset() { lock.lock(); cached = nil; lock.unlock() }

    // MARK: Rule set
    struct RuleSet { let files: [URL]; let dependencies: [String: [String]]; let key: String; let skipped: [String] }

    /// Rule files under `directory`, with their dependencies taken from the signed manifest stored beside the rules (`.release/manifest.json`).
    static func ruleSet(in directory: URL) -> RuleSet {
        let fm = FileManager.default
        var files: [URL] = []
        if let en = fm.enumerator(at: directory, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) {
            for case let u as URL in en where ["yar", "yara"].contains(u.pathExtension.lowercased()) && !u.pathComponents.contains("quarantine") { files.append(u.resolvingSymlinksInPath()) }   // canonical paths: /var and /private/var must not differ between the file list and the dependency map
        }
        files.sort { $0.path < $1.path }
        var deps: [String: [String]] = [:]
        var rootKey = ""
        let live = directory.appendingPathComponent("community").resolvingSymlinksInPath()
        if let data = try? Data(contentsOf: live.appendingPathComponent(".release/manifest.json")), let m = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            rootKey = (m["rules_root"] as? String) ?? ""
            for f in (m["files"] as? [[String: Any]]) ?? [] {
                guard let p = f["path"] as? String, let d = f["depends_on"] as? [String], !d.isEmpty else { continue }
                let rel = p.hasPrefix("rules/") ? String(p.dropFirst(6)) : p
                deps[live.appendingPathComponent(rel).path] = d.map { live.appendingPathComponent($0.hasPrefix("rules/") ? String($0.dropFirst(6)) : $0).path }
            }
        }
        var h = SHA256(); h.update(data: Data(rootKey.utf8))
        for f in files { let a = (try? fm.attributesOfItem(atPath: f.path)) ?? [:]; h.update(data: Data("\(f.path)|\((a[.size] as? NSNumber) ?? 0)|\(((a[.modificationDate] as? Date)?.timeIntervalSince1970) ?? 0)\n".utf8)) }
        return RuleSet(files: files, dependencies: deps, key: h.finalize().prefix(12).map { String(format: "%02x", $0) }.joined(), skipped: [])
    }
    static func closure(_ path: String, _ deps: [String: [String]], _ seen: inout [String], _ visiting: inout Set<String>) {
        if seen.contains(path) || visiting.contains(path) { return }
        visiting.insert(path); for d in deps[path] ?? [] { closure(d, deps, &seen, &visiting) }; visiting.remove(path); seen.append(path)
    }

    /// `error: rule "X" in /path/file.yar(12): ...` -> /path/file.yar
    static func failingPath(in output: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: #"in (/[^\n]*?)\(\d+\)"#), let m = re.firstMatch(in: output, range: NSRange(output.startIndex..., in: output)), let r = Range(m.range(at: 1), in: output) else { return nil }
        return String(output[r])
    }

    struct Compiled { let url: URL; let ruleFiles: Int; let skipped: [String]; let reused: Bool }

    /// One namespace per rule file (plus copies of what it needs): upstream sources define the same rule name in many files.
    /// If the whole set does not compile on this engine, the files that do not compile alone are left out and reported, so one
    /// damaged rule never disables scanning.
    static func compile(_ e: Located, rules: RuleSet, cacheDirectory: URL, timeout: TimeInterval = 180) -> Compiled? {
        let fm = FileManager.default
        try? fm.createDirectory(at: cacheDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let out = cacheDirectory.appendingPathComponent("\(rules.key)-\(e.manifest.version).yarc"), skipFile = out.appendingPathExtension("skipped")
        if fm.fileExists(atPath: out.path) { return Compiled(url: out, ruleFiles: rules.files.count, skipped: ((try? String(contentsOf: skipFile))?.split(separator: "\n").map(String.init)) ?? [], reused: true) }
        guard !rules.files.isEmpty else { return nil }
        func args(_ files: [URL]) -> [String] {
            var a = ["-w", "-d", "filepath=", "-d", "filename=", "-d", "extension=", "-d", "filetype=", "-d", "owner=", "-d", "md5="]
            for (i, f) in files.enumerated() { var seen: [String] = [], visiting = Set<String>(); closure(f.path, rules.dependencies, &seen, &visiting); for p in seen { a.append("ns\(i):\(p)") } }
            return a
        }
        let tmp = cacheDirectory.appendingPathComponent("tmp-\(UUID().uuidString).yarc")
        var r = BoundedProcess.run(e.yarac.path, args(rules.files) + [tmp.path], timeout: timeout, maxOutput: 200_000)
        var skipped: [String] = [], used = rules.files
        // The engine names the file it rejects; drop that file (and whatever depends on it) and try again. Only if the message cannot be
        // understood do we fall back to compiling file by file.
        var rounds = 0
        while r.status != 0, rounds < 40 {
            rounds += 1
            guard let bad = failingPath(in: r.output) else { break }
            let before = used.count
            used = used.filter { f in var seen: [String] = [], v = Set<String>(); closure(f.path, rules.dependencies, &seen, &v); if seen.contains(bad) { skipped.append(f.lastPathComponent); return false }; return true }
            if used.count == before || used.isEmpty { break }
            r = BoundedProcess.run(e.yarac.path, args(used) + [tmp.path], timeout: timeout, maxOutput: 200_000)
        }
        if r.status != 0 {
            skipped = []; var good: [URL] = []
            for f in rules.files {
                let one = BoundedProcess.run(e.yarac.path, args([f]) + [FileManager.default.temporaryDirectory.appendingPathComponent("one-\(UUID().uuidString).yarc").path], timeout: 20, maxOutput: 20_000)
                if one.status == 0 { good.append(f) } else { skipped.append(f.lastPathComponent) }
            }
            used = good; r = BoundedProcess.run(e.yarac.path, args(good) + [tmp.path], timeout: timeout, maxOutput: 200_000)
            guard r.status == 0, !good.isEmpty else { try? fm.removeItem(at: tmp); return nil }
        }
        try? fm.removeItem(at: out); guard (try? fm.moveItem(at: tmp, to: out)) != nil else { return nil }
        try? skipped.joined(separator: "\n").write(to: skipFile, atomically: true, encoding: .utf8)
        return Compiled(url: out, ruleFiles: used.count, skipped: skipped, reused: false)
    }

    // MARK: Scan
    struct Match: Equatable { let rule: String; let ruleFile: String; let target: String }
    struct Outcome { let matches: [Match]; let scanned: Int; let skippedLarge: [String]; let errors: [String]; let warnings: [String]; let timedOut: Bool; let ruleFiles: Int; let skippedRules: [String]; let version: String; let reusedCache: Bool }

    static let maxFileBytes: Int64 = 25_000_000, maxFiles = 2_000

    static func scan(_ files: [URL], rules: RuleSet, engine e: Located, cacheDirectory: URL, timeout: TimeInterval = 300, cancelled: (() -> Bool)? = nil) -> Outcome? {
        guard let compiled = compile(e, rules: rules, cacheDirectory: cacheDirectory) else { return nil }
        var targets: [URL] = [], large: [String] = []
        for f in files.prefix(maxFiles) {
            let size = ((try? FileManager.default.attributesOfItem(atPath: f.path))?[.size] as? NSNumber)?.int64Value ?? 0
            if size > maxFileBytes { large.append(f.lastPathComponent) } else { targets.append(f) }
        }
        guard !targets.isEmpty else { return Outcome(matches: [], scanned: 0, skippedLarge: large, errors: [], warnings: [], timedOut: false, ruleFiles: compiled.ruleFiles, skippedRules: compiled.skipped, version: e.manifest.version, reusedCache: compiled.reused) }
        let list = FileManager.default.temporaryDirectory.appendingPathComponent("yara-list-\(UUID().uuidString).txt"); defer { try? FileManager.default.removeItem(at: list) }
        try? targets.map(\.path).joined(separator: "\n").write(to: list, atomically: true, encoding: .utf8)
        // `-e` prints namespace:rule, `-p 1` keeps it single-threaded and predictable, `--timeout` bounds each file inside the engine.
        let r = BoundedProcess.run(e.yara.path, ["-C", "-p", "1", "-e", "--timeout=10", "--scan-list", compiled.url.path, list.path], timeout: timeout, maxOutput: 4_000_000, cancelled: cancelled)
        var matches: [Match] = [], errors: [String] = [], warnings: [String] = []
        for line in r.output.split(separator: "\n") {
            let s = String(line)
            if s.hasPrefix("warning: ") { warnings.append(String(s.prefix(200))); continue }
            if s.hasPrefix("error") { errors.append(String(s.prefix(200))); continue }
            guard let space = s.firstIndex(of: " ") else { continue }
            let id = String(s[..<space]), target = String(s[s.index(after: space)...])
            let parts = id.split(separator: ":", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { continue }
            matches.append(Match(rule: parts[1], ruleFile: parts[0], target: target))
        }
        if r.status != 0 && !r.timedOut && errors.isEmpty { errors.append("the engine exited with status \(r.status)") }
        return Outcome(matches: matches, scanned: targets.count, skippedLarge: large, errors: errors, warnings: warnings, timedOut: r.timedOut, ruleFiles: compiled.ruleFiles, skippedRules: compiled.skipped, version: e.manifest.version, reusedCache: compiled.reused)
    }
}

/// A YARA hit is a triage indicator, never an automatic malware verdict. A clean result does not prove safety.
enum YARAScanner {
    static func inspect(_ candidates: [URL], rulesDirectory: URL? = nil, status: YARAEngine.Status? = nil, cacheDirectory: URL? = nil, cancelled: (() -> Bool)? = nil) -> [AuditFinding] {
        let engine = status ?? YARAEngine.status()
        guard let located = engine.located else {
            let damaged = engine.reason.contains("do not match") || engine.reason.contains("code signature") || engine.reason.contains("self-test")
            return [AuditFinding(title: damaged ? "YARA engine failed verification" : "YARA engine unavailable", detail: engine.reason + (damaged ? " Scan blocked." : " The scan was not performed."), state: damaged ? .failed : .unknown, weight: 0)]
        }
        let manager = YARARuleManager.shared
        let dir = rulesDirectory ?? manager.rulesDirectory
        let rules = YARAEngine.ruleSet(in: dir)
        guard !rules.files.isEmpty else { return [AuditFinding(title: "YARA rules", detail: "No rules are installed; engine \(located.manifest.version) is ready.", state: .unknown, weight: 0)] }
        let cache = cacheDirectory ?? dir.deletingLastPathComponent().appendingPathComponent("ChannelState/compiled", isDirectory: true)
        guard let out = YARAEngine.scan(candidates, rules: rules, engine: located, cacheDirectory: cache, cancelled: cancelled) else {
            return [AuditFinding(title: "YARA rules could not be compiled", detail: "No installed rule compiled with engine \(located.manifest.version).", state: .failed, weight: 0)]
        }
        var findings: [AuditFinding] = []
        var seen = Set<String>()
        for m in out.matches.prefix(60) where seen.insert(m.rule + "|" + m.target).inserted {
            findings.append(AuditFinding(title: "YARA match: \(m.rule)", detail: "File: \((m.target as NSString).lastPathComponent). Rule set: \(m.ruleFile). A match is a triage indicator, not a malware verdict.", state: .warning, weight: 0))
        }
        if out.matches.count > 60 { findings.append(AuditFinding(title: "YARA matches truncated", detail: "\(out.matches.count) matches; the first 60 are listed.", state: .warning, weight: 0)) }
        let problems = out.errors.count + (out.timedOut ? 1 : 0)
        var detail = "Engine YARA \(out.version) (\(located.manifest.architectures)); \(out.scanned) file(s) scanned with \(out.ruleFiles) rule file(s); \(out.matches.count) match(es)."
        if !out.skippedLarge.isEmpty { detail += " \(out.skippedLarge.count) file(s) over \(YARAEngine.maxFileBytes / 1_000_000) MB were not scanned." }
        if !out.skippedRules.isEmpty { detail += " \(out.skippedRules.count) rule file(s) do not compile with this engine and were left out: \(out.skippedRules.prefix(3).joined(separator: ", "))." }
        if out.timedOut { detail += " The scan hit its time limit and is incomplete." }
        if !out.errors.isEmpty { detail += " Engine errors: \(out.errors.prefix(2).joined(separator: " | "))" }
        if !out.warnings.isEmpty { detail += " \(out.warnings.count) slow-rule warning(s) from the engine (e.g. \(out.warnings[0].dropFirst(9).prefix(90)))" }
        detail += " A clean result does not prove safety."
        findings.append(AuditFinding(title: "YARA scan coverage", detail: detail, state: problems > 0 || !out.skippedRules.isEmpty || !out.skippedLarge.isEmpty ? .warning : (out.matches.isEmpty ? .passed : .warning), weight: out.matches.isEmpty && problems == 0 ? 6 : 0))
        return findings
    }
}
