import Foundation
import CryptoKit

/// Sigstore verification for the shipping app and the CLI.
///
/// Decision (docs/ADR-0001): no maintained Swift Sigstore client exists, and hand-writing Fulcio chain, SCT and Rekor
/// checks would be home-grown cryptography. The app therefore ships the official `cosign` client (sigstore-go based)
/// as a helper and the Sigstore public-good `trusted_root.json` as its trust anchor. Both are pinned by SHA-256 in this
/// source file, and cosign runs with `--trusted-root`, so no TUF or network access is needed to verify.
///
/// What cosign checks for each bundle: signature over the exact bytes, Fulcio certificate chain to the trusted root,
/// certificate validity at the signed time, Rekor inclusion (signed entry timestamp / inclusion proof), and the
/// expected workflow identity, OIDC issuer and source repository passed below.
enum SigstoreVerifier {
    /// SHA-256 of cosign binaries this build trusts to run.
    static let pinnedCosign: [String: String] = [
        "f5430359e5442bfcfe38310f4e6ce9e235bf36c2b917639c2f30b942e6f236e1": "cosign v3.1.1 darwin/amd64",
    ]
    /// SHA-256 of the trusted root shipped with this build. Refreshing it is an app update (see Scripts/refresh-trusted-root.sh).
    static let pinnedTrustedRoots: [String: String] = [
        "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66": "sigstore public-good trusted_root.json (2026-10-18)",
    ]

    struct Located { let cosign: URL; let trustedRoot: URL }

    static func sha256(_ url: URL) -> String? { AuditEngine.sha256(of: url) }

    /// Finds a pinned cosign and trusted root. Search order: app bundle, next to the executable, `MACGUARD_SIGSTORE_DIR`,
    /// then the usual Homebrew locations. A file whose hash is not pinned is never used, wherever it lives.
    static func locate(bundle: Bundle = .main, environment: [String: String] = ProcessInfo.processInfo.environment) -> (Located?, String) {
        var cosignCandidates: [URL] = [bundle.bundleURL.appendingPathComponent("Contents/Helpers/cosign")]
        var rootCandidates: [URL] = []
        if let r = bundle.url(forResource: "trusted_root", withExtension: "json", subdirectory: "sigstore") { rootCandidates.append(r) }
        let exeDir = URL(fileURLWithPath: CommandLine.arguments.first ?? "").deletingLastPathComponent()
        for dir in [exeDir, exeDir.appendingPathComponent("sigstore"), exeDir.deletingLastPathComponent().appendingPathComponent("libexec/macguard")] {
            cosignCandidates.append(dir.appendingPathComponent("cosign")); rootCandidates.append(dir.appendingPathComponent("trusted_root.json"))
        }
        if let d = environment["MACGUARD_SIGSTORE_DIR"] {
            let dir = URL(fileURLWithPath: d)
            cosignCandidates.append(dir.appendingPathComponent("cosign")); rootCandidates.append(dir.appendingPathComponent("trusted_root.json"))
        }
        cosignCandidates += ["/opt/homebrew/bin/cosign", "/usr/local/bin/cosign"].map { URL(fileURLWithPath: $0) }
        let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/sigstore/trusted_root.json")
        rootCandidates.append(repoRoot)

        var why: [String] = []
        let cosign = cosignCandidates.first { url in
            guard FileManager.default.isExecutableFile(atPath: url.path) else { return false }
            guard let h = sha256(url), pinnedCosign[h] != nil else { why.append("\(url.path) is not a pinned cosign build"); return false }
            return true
        }
        let root = rootCandidates.first { url in
            guard FileManager.default.fileExists(atPath: url.path) else { return false }
            guard let h = sha256(url), pinnedTrustedRoots[h] != nil else { why.append("\(url.path) is not the pinned trusted root"); return false }
            return true
        }
        guard let cosign else { return (nil, "no pinned cosign found. " + why.joined(separator: "; ")) }
        guard let root else { return (nil, "no pinned Sigstore trusted root found. " + why.joined(separator: "; ")) }
        return (Located(cosign: cosign, trustedRoot: root), "")
    }

    /// The signature check used to accept rules. Returns nil for a valid signature by the authorized workflow.
    static func check(_ located: Located) -> ChannelVerifier.SignatureCheck {
        { blob, bundle in
            guard FileManager.default.fileExists(atPath: bundle.path) else { return "signature bundle is missing" }
            let r = BoundedProcess.run(located.cosign.path, [
                "verify-blob", "--bundle", bundle.path, "--trusted-root", located.trustedRoot.path,
                "--certificate-identity", ChannelVerifier.identity,
                "--certificate-oidc-issuer", ChannelVerifier.issuer,
                "--certificate-github-workflow-repository", ChannelVerifier.repository,
                blob.path], timeout: 30, maxOutput: 20_000)
            if r.status == 0 && !r.timedOut { return nil }
            if r.timedOut { return "Sigstore verification timed out" }
            return r.output.split(separator: "\n").last.map(String.init) ?? "Sigstore verification failed"
        }
    }

    /// A ready check, or nil plus the reason when this installation cannot verify (fail closed).
    static func standard() -> (check: ChannelVerifier.SignatureCheck?, reason: String) {
        let (loc, why) = locate()
        guard let loc else { return (nil, why) }
        return (check(loc), "")
    }
}
