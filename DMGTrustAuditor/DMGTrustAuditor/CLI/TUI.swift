import Foundation
import Darwin

/// Full-screen terminal explorer. It only chooses what to scan; every verdict comes from `AuditEngine`.
/// Keys: arrows/jk move, Enter/→ open or scan, ←/Backspace parent, b history back, f filter, / path, s scan, H help, Q quit.
enum TUI {
    private static var saved = termios()
    private static var rawOn = false
    private static var color = false

    private static func enableRaw() {
        tcgetattr(STDIN_FILENO, &saved)
        var t = saved
        t.c_lflag &= ~tcflag_t(ECHO | ICANON)
        withUnsafeMutablePointer(to: &t.c_cc) { $0.withMemoryRebound(to: cc_t.self, capacity: Int(NCCS)) { $0[Int(VMIN)] = 0; $0[Int(VTIME)] = 2 } }
        tcsetattr(STDIN_FILENO, TCSANOW, &t); rawOn = true
        write("\u{1B}[?1049h\u{1B}[?25l")
    }
    private static func disableRaw() {
        guard rawOn else { return }
        tcsetattr(STDIN_FILENO, TCSANOW, &saved); rawOn = false
        write("\u{1B}[0m\u{1B}[?25h\u{1B}[?1049l")
    }
    private static func write(_ s: String) { FileHandle.standardOutput.write(Data(s.utf8)) }
    private static func c(_ code: String) -> String { color ? "\u{1B}[\(code)m" : "" }

    enum Key: Equatable { case up, down, left, right, enter, back, esc, char(Character), none }
    private static func readKey() -> Key {
        var b: UInt8 = 0
        guard read(STDIN_FILENO, &b, 1) == 1 else { return .none }
        switch b {
        case 27:
            var s1: UInt8 = 0, s2: UInt8 = 0
            guard read(STDIN_FILENO, &s1, 1) == 1, s1 == 91 || s1 == 79, read(STDIN_FILENO, &s2, 1) == 1 else { return .esc }
            switch s2 { case 65: return .up; case 66: return .down; case 67: return .right; case 68: return .left; default: return .esc }
        case 10, 13: return .enter
        case 127, 8: return .back
        default: return .char(Character(UnicodeScalar(b)))
        }
    }
    private static func size() -> (w: Int, h: Int) {
        var ws = winsize()
        if ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0, ws.ws_col > 0 { return (Int(ws.ws_col), Int(ws.ws_row)) }
        return (Int(ProcessInfo.processInfo.environment["COLUMNS"] ?? "") ?? 100, Int(ProcessInfo.processInfo.environment["LINES"] ?? "") ?? 28)
    }
    private static func trim(_ s: String, _ n: Int) -> String { s.count <= n ? s : String(s.prefix(max(1, n - 1))) + "…" }
    private static func isDir(_ u: URL) -> Bool { var b: ObjCBool = false; return FileManager.default.fileExists(atPath: u.path, isDirectory: &b) && b.boolValue }

    static func listing(_ folder: URL, filter: String) -> [URL] {
        let items = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])) ?? []
        return items.filter { filter.isEmpty || $0.lastPathComponent.localizedCaseInsensitiveContains(filter) }.sorted {
            let a = isDir($0) && $0.pathExtension != "app", b = isDir($1) && $1.pathExtension != "app"
            if a != b { return a }
            return $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending
        }
    }

    private final class Job {
        var report: AuditReport?; var cancelled = false; let started = Date()
    }

    static func run() -> Int32 {
        guard isatty(STDIN_FILENO) != 0, isatty(STDOUT_FILENO) != 0 else {
            CLI.err("The TUI needs an interactive terminal. Use 'macguard-audit scan PATH --format json' in scripts.")
            return CLI.Exit.unavailable
        }
        let env = ProcessInfo.processInfo.environment
        color = env["NO_COLOR"] == nil && (env["TERM"] ?? "dumb") != "dumb"
        signal(SIGINT) { _ in TUI.disableRaw(); exit(130) }
        signal(SIGTERM) { _ in TUI.disableRaw(); exit(143) }
        enableRaw(); defer { disableRaw() }

        var folder = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        if !isDir(folder) { folder = FileManager.default.homeDirectoryForCurrentUser }
        var history: [URL] = []
        var sel = 0, offset = 0, filter = "", message = "Pick an installer or app. Nothing is executed."
        var report: AuditReport?, scroll = 0

        func prompt(_ label: String) -> String {
            disableRaw(); write("\n\(label): "); let v = readLine() ?? ""; enableRaw(); return v
        }
        func go(_ u: URL) { history.append(folder); folder = u; sel = 0; offset = 0; filter = "" }
        func scanWithProgress(_ u: URL) {
            let job = Job()
            DispatchQueue.global(qos: .userInitiated).async {
                job.report = AuditEngine.audit(AuditInput(file: u, expectedName: "", expectedTeam: "", expectedBundle: "", expectedSHA: "", sourceURL: ""), cancelled: { job.cancelled })
            }
            let frames = Array("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"); var n = 0
            while job.report == nil {
                let (w, _) = size()
                write("\u{1B}[2J\u{1B}[H\(c("1;96"))MACGUARD INSTALLER AUDITOR\(c("0"))\n\n  \(frames[n % frames.count]) Scanning \(trim(u.lastPathComponent, w - 20))  \(Int(Date().timeIntervalSince(job.started))) s\n  Esc cancels. The file is read, never run.\n")
                n += 1
                if readKey() == .esc { job.cancelled = true; message = "Scan cancelled."; break }
            }
            if let r = job.report { report = r; scroll = 0 }
            else { Thread.sleep(forTimeInterval: 0.3) }
        }

        while true {
            let (w0, h) = size(); let w = max(60, min(140, w0))
            if let r = report {
                var lines = ["\(c("96"))\(trim(r.file, w - 4))\(c("0"))", "Format: \(r.kind)   Score: \(r.score)/10   Blockers: \(r.blockers)", "Coverage: \(r.coverage)", ""]
                for f in r.findings {
                    let col = f.state == .passed ? "92" : f.state == .failed ? "91" : f.state == .warning ? "93" : "90"
                    lines.append("\(c(col))[\(f.state.rawValue.uppercased())]\(c("0")) \(trim(f.title, w - 14))")
                    lines.append("    \(c("90"))\(trim(f.detail.replacingOccurrences(of: "\n", with: " "), w - 8))\(c("0"))")
                }
                let page = max(5, h - 5); scroll = max(0, min(scroll, max(0, lines.count - page)))
                write("\u{1B}[2J\u{1B}[H\(c("1;96"))RESULT\(c("0"))  (↑↓ scroll · e export JSON · Esc back · Q quit)\n")
                for l in lines.dropFirst(scroll).prefix(page) { write(l + "\n") }
                write("\n\(c("90"))\(trim(r.assessmentNote, w - 2))\(c("0"))\n")
                switch readKey() {
                case .up: scroll -= 1
                case .down: scroll += 1
                case .esc, .back, .left: report = nil
                case .char("q"), .char("Q"): return CLI.Exit.ok
                case .char("e"):
                    let path = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("macguard-report-\(Int(Date().timeIntervalSince1970)).json")
                    try? Data(CLI.json(CLI.ScanOutput(schemaVersion: ToolInfo.jsonSchema, tool: ToolInfo.name, version: ToolInfo.version, results: [r])).utf8).write(to: path)
                    message = "Saved \(path.lastPathComponent) in your home folder."; report = nil
                default: break
                }
                continue
            }
            let files = listing(folder, filter: filter)
            if sel >= files.count { sel = max(0, files.count - 1) }
            let visible = max(5, h - 9)
            if sel < offset { offset = sel }
            if sel >= offset + visible { offset = sel - visible + 1 }
            write("\u{1B}[2J\u{1B}[H\(c("1;97;44")) MACGUARD INSTALLER AUDITOR · FILE EXPLORER \(c("0"))\n")
            write("\(c("96")) \(trim(folder.path, w - 4))\(c("0"))\(filter.isEmpty ? "" : "   filter: \(filter)")\n")
            write(String(repeating: "─", count: w - 2) + "\n")
            if files.isEmpty { write("  (empty / vacío)\n") }
            for i in offset..<min(files.count, offset + visible) {
                let u = files[i]; let kind = isDir(u) && u.pathExtension != "app" ? "▣" : "▪"
                let tag = isDir(u) && u.pathExtension != "app" ? "" : "  \(AuditEngine.label(ContentDetector.detect(u).kind))"
                let line = " \(kind) \(trim(u.lastPathComponent, w - 24))\(c("90"))\(tag)"
                write(i == sel ? "\(c("7"))\(line.padding(toLength: max(line.count, w - 2), withPad: " ", startingAt: 0))\(c("0"))\n" : "\(line)\(c("0"))\n")
            }
            write("\n\(c("90"))\(files.count) items · \(trim(message, w - 20))\(c("0"))\n")
            write("↑↓ move · Enter open/scan · ← parent · b back · f filter · / path · s scan · H help · Q quit\n")
            switch readKey() {
            case .up, .char("k"): sel = max(0, sel - 1)
            case .down, .char("j"): sel = min(max(0, files.count - 1), sel + 1)
            case .left, .back: go(folder.deletingLastPathComponent())
            case .char("b"): if let last = history.popLast() { folder = last; sel = 0; offset = 0; filter = "" }
            case .char("f"): filter = prompt("Filter (empty clears)"); sel = 0; offset = 0
            case .char("/"):
                let u = CLI.expand(prompt("Path"))
                if isDir(u) { go(u) } else if FileManager.default.fileExists(atPath: u.path) { scanWithProgress(u) } else { message = "Path not found." }
            case .enter, .right, .char("s"):
                guard files.indices.contains(sel) else { break }
                let u = files[sel]
                if isDir(u) && u.pathExtension != "app" && ContentDetector.detect(u).kind == .unknown { go(u) } else { scanWithProgress(u) }
            case .char("H"), .char("h"), .char("?"):
                write("\u{1B}[2J\u{1B}[H" + """
                MACGUARD TUI — HELP / AYUDA

                ↑ ↓ / j k  move          Enter / →  open folder or scan file
                ← / ⌫      parent        b  previous folder      f  filter by name      /  type a path
                s          scan item     H  this help            Q  quit

                Nothing under inspection is launched. UNKNOWN never means safe.
                YARA without a signed engine is reported UNKNOWN.

                Press any key.
                """)
                while readKey() == .none {}
            case .char("q"), .char("Q"), .esc: return CLI.Exit.ok
            default: break
            }
        }
    }
}
