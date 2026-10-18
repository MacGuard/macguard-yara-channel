import Foundation
import CryptoKit

/// Verifies a downloaded rules release the way the channel documents it: signatures, file hashes,
/// rules root, and the log inclusion proof. Signature checking is injected because Sigstore bundle
/// validation (Fulcio chain, Rekor) is delegated to `cosign` in this harness.
struct ChannelVerifier {
    static let identity = "https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main"
    static let issuer = "https://token.actions.githubusercontent.com"
    static let repository = "MacGuard/macguard-yara-channel"
    static let logOrigin = "macguard-rules-log v1"

    /// Returns nil when `bundle` is a valid signature of `blob` by the expected workflow identity; otherwise a reason.
    typealias SignatureCheck = (_ blob: URL, _ bundle: URL) -> String?

    struct Summary: Equatable { let fileCount: Int; let rulesRoot: String; let logSize: Int }
    struct Failure: Error, Equatable { let reason: String }

    let signatureCheck: SignatureCheck

    // MARK: Merkle (RFC 6962 / 9162)
    static func leafHash(_ data: Data) -> Data { Data(SHA256.hash(data: Data([0x00]) + data)) }
    static func nodeHash(_ l: Data, _ r: Data) -> Data { Data(SHA256.hash(data: Data([0x01]) + l + r)) }

    static func root(_ leaves: [Data]) -> Data {
        switch leaves.count {
        case 0: return Data(SHA256.hash(data: Data()))
        case 1: return leaves[0]
        default:
            var k = 1; while k * 2 < leaves.count { k *= 2 }
            return nodeHash(root(Array(leaves[..<k])), root(Array(leaves[k...])))
        }
    }

    static func rulesRoot(_ files: [(path: String, sha256: String)]) -> String {
        let leaves = files.sorted { $0.path < $1.path }.map { leafHash(Data("\($0.path)\0\($0.sha256)".utf8)) }
        return hex(root(leaves))
    }

    static func verifyInclusion(index: Int, size: Int, leaf: Data, proof: [Data], root: Data) -> Bool {
        guard index >= 0, index < size else { return false }
        var fn = index, sn = size - 1, r = leaf
        for p in proof {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                r = nodeHash(p, r)
                if fn & 1 == 0 { while fn & 1 == 0 && fn != 0 { fn >>= 1; sn >>= 1 } }
            } else {
                r = nodeHash(r, p)
            }
            fn >>= 1; sn >>= 1
        }
        return sn == 0 && r == root
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    static func data(hex s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var out = Data(); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); guard let b = UInt8(s[i..<j], radix: 16) else { return nil }; out.append(b); i = j }
        return out
    }

    // MARK: Release
    /// `directory` holds manifest.json, manifest.sigstore.json, inclusion-proof.json, rules/ and logs/checkpoint.*
    func verify(directory d: URL) throws -> Summary {
        func fail(_ s: String) -> Failure { Failure(reason: s) }
        let manifestURL = d.appendingPathComponent("manifest.json")
        if let e = signatureCheck(manifestURL, d.appendingPathComponent("manifest.sigstore.json")) { throw fail("manifest signature: \(e)") }
        guard let manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any],
              let files = manifest["files"] as? [[String: Any]], let claimedRoot = manifest["rules_root"] as? String,
              let log = manifest["log"] as? [String: Any], let logSize = log["size"] as? Int, let logRoot = log["root"] as? String
        else { throw fail("manifest is malformed") }

        var entries: [(path: String, sha256: String)] = []
        for f in files {
            guard let path = f["path"] as? String, let sha = f["sha256"] as? String else { throw fail("manifest file entry is malformed") }
            let std = d.appendingPathComponent(path).standardizedFileURL
            guard !path.hasPrefix("/"), !path.contains(".."), std.path.hasPrefix(d.standardizedFileURL.path + "/") else { throw fail("unsafe path \(path)") }
            guard let bytes = try? Data(contentsOf: std), Self.hex(Data(SHA256.hash(data: bytes))) == sha else { throw fail("\(path) does not match the manifest") }
            entries.append((path, sha))
        }
        guard Self.rulesRoot(entries) == claimedRoot else { throw fail("rules_root does not match the file list") }

        let cp = d.appendingPathComponent("logs/checkpoint.txt")
        if let e = signatureCheck(cp, d.appendingPathComponent("logs/checkpoint.sigstore.json")) { throw fail("checkpoint signature: \(e)") }
        let lines = try String(contentsOf: cp, encoding: .utf8).components(separatedBy: "\n")
        guard lines.count == 4, lines[3] == "", lines[0] == Self.logOrigin, let size = Int(lines[1]), let cpRoot = Data(base64Encoded: lines[2])
        else { throw fail("checkpoint is malformed") }
        guard size == logSize, Self.hex(cpRoot) == logRoot else { throw fail("manifest log head differs from the signed checkpoint") }

        guard let proof = try JSONSerialization.jsonObject(with: Data(contentsOf: d.appendingPathComponent("inclusion-proof.json"))) as? [String: Any],
              let index = proof["index"] as? Int, let pSize = proof["size"] as? Int, let pRoot = proof["root"] as? String,
              let entry = proof["entry"] as? String, let hashes = proof["proof"] as? [String]
        else { throw fail("inclusion proof is malformed") }
        guard pSize == size, pRoot == Self.hex(cpRoot) else { throw fail("proof is for a different checkpoint") }
        guard let logged = try JSONSerialization.jsonObject(with: Data(entry.utf8)) as? [String: Any],
              logged["event"] as? String == "candidate.accepted",
              (logged["details"] as? [String: Any])?["rules_root"] as? String == claimedRoot
        else { throw fail("logged entry does not match the manifest rules_root") }
        let path = hashes.compactMap { Self.data(hex: $0) }
        guard path.count == hashes.count,
              Self.verifyInclusion(index: index, size: size, leaf: Self.leafHash(Data(entry.utf8)), proof: path, root: cpRoot)
        else { throw fail("inclusion proof does not verify") }
        return Summary(fileCount: entries.count, rulesRoot: claimedRoot, logSize: size)
    }

    // MARK: cosign-backed signature check (harness only; the shipping app needs a native Sigstore verifier)
    static func cosignCheck(cosign: URL) -> SignatureCheck {
        { blob, bundle in
            guard FileManager.default.fileExists(atPath: bundle.path) else { return "signature bundle is missing" }
            let p = Process(); p.executableURL = cosign
            p.arguments = ["verify-blob", "--bundle", bundle.path, "--certificate-identity", identity,
                           "--certificate-oidc-issuer", issuer, "--certificate-github-workflow-repository", repository, blob.path]
            let err = Pipe(); p.standardError = err; p.standardOutput = Pipe()
            do { try p.run() } catch { return "cosign could not be started" }
            p.waitUntilExit()
            if p.terminationStatus == 0 { return nil }
            let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            return text.split(separator: "\n").last.map(String.init) ?? "cosign verification failed"
        }
    }
    static func findCosign() -> URL? {
        ["/opt/homebrew/bin/cosign", "/usr/local/bin/cosign"].map { URL(fileURLWithPath: $0) }.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }
}
