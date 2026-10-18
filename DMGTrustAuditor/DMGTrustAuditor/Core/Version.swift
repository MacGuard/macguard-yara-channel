import Foundation
enum ToolInfo {
    static let name = "macguard-audit"
    static let version = "0.2.0"
    /// Bump when the JSON output changes incompatibly. Documented in CLI/README.md.
    static let jsonSchema = 1
}

/// Where MacGuard keeps rules, the compiled cache and the channel trust state. `MACGUARD_DATA_DIR` redirects it (tests, CI, sandboxed runs).
enum AppPaths {
    static var dataRoot: URL {
        if let d = ProcessInfo.processInfo.environment["MACGUARD_DATA_DIR"], !d.isEmpty { return URL(fileURLWithPath: d, isDirectory: true) }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("DMGTrustAuditor", isDirectory: true)
    }
}
