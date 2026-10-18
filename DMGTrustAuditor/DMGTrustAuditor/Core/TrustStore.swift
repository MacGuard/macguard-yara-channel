import Foundation
import CryptoKit

/// The newest transparency-log head this installation has verified. Kept across launches so an
/// older or forked checkpoint can be refused (anti-rollback). It is evidence, not a secret.
struct TrustState: Codable, Equatable {
    var schema = 1
    var origin: String
    var size: Int
    var root: String          // hex Merkle root at `size`
    var rulesRoot: String     // rules_root of the last release verified against that head
    var updatedAt: Date
}

protocol TrustStore {
    func load() throws -> TrustState?
    func save(_ state: TrustState) throws
}

/// JSON file with 0600 permissions in a 0700 directory, replaced atomically.
/// A damaged file is an error, never a silent reset to "trust on first use".
struct FileTrustStore: TrustStore {
    let url: URL
    struct Corrupt: Error, Equatable { let reason: String }

    static var `default`: FileTrustStore {
        FileTrustStore(url: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("DMGTrustAuditor/ChannelState/trust.json"))
    }
    func load() throws -> TrustState? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let data = try Data(contentsOf: url)
        guard let state = try? JSONDecoder.iso.decode(TrustState.self, from: data), state.schema == 1,
              state.size >= 0, state.root.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
        else { throw Corrupt(reason: "trust state at \(url.path) is damaged; refusing to reset it silently") }
        return state
    }
    func save(_ state: TrustState) throws {
        let fm = FileManager.default
        let dir = url.deletingLastPathComponent()
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let tmp = dir.appendingPathComponent("trust.json.tmp-\(UUID().uuidString)")
        try JSONEncoder.iso.encode(state).write(to: tmp, options: [.atomic])
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        let fd = open(tmp.path, O_RDONLY); if fd >= 0 { fsync(fd); close(fd) }
        if fm.fileExists(atPath: url.path) { _ = try fm.replaceItemAt(url, withItemAt: tmp) } else { try fm.moveItem(at: tmp, to: url) }
    }
}

final class MemoryTrustStore: TrustStore {
    var state: TrustState?
    init(_ s: TrustState? = nil) { state = s }
    func load() throws -> TrustState? { state }
    func save(_ s: TrustState) throws { state = s }
}

extension JSONEncoder { static var iso: JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys, .prettyPrinted]; return e } }
extension JSONDecoder { static var iso: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d } }

// MARK: Log consistency (RFC 9162 §2.1.4)
extension ChannelVerifier {
    /// Verifies that the tree of `second` leaves with root `secondRoot` extends the tree of `first` leaves with `firstRoot`.
    static func verifyConsistency(first: Int, second: Int, firstRoot: Data, secondRoot: Data, proof: [Data]) -> Bool {
        if first > second || first < 0 { return false }
        if first == second { return proof.isEmpty && firstRoot == secondRoot }
        if first == 0 { return proof.isEmpty }
        var p = proof
        if first & (first - 1) == 0 { p.insert(firstRoot, at: 0) }
        if p.isEmpty { return false }
        var fn = first - 1, sn = second - 1
        while fn & 1 == 1 { fn >>= 1; sn >>= 1 }
        var fr = p[0], sr = p[0]
        for c in p.dropFirst() {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                fr = nodeHash(c, fr); sr = nodeHash(c, sr)
                if fn & 1 == 0 { while fn & 1 == 0 && fn != 0 { fn >>= 1; sn >>= 1 } }
            } else {
                sr = nodeHash(sr, c)
            }
            fn >>= 1; sn >>= 1
        }
        return sn == 0 && fr == firstRoot && sr == secondRoot
    }

    /// Builds the consistency proof from the full leaf list (the client holds the public log), then verifies it
    /// against both roots, so the check does not depend on trusting a server-made proof.
    static func consistencyProof(first: Int, leaves: [Data]) -> [Data] {
        func sub(_ m: Int, _ d: ArraySlice<Data>, _ complete: Bool) -> [Data] {
            let n = d.count
            if m == n { return complete ? [] : [root(Array(d))] }
            var k = 1; while k * 2 < n { k *= 2 }
            let mid = d.startIndex + k
            if m <= k { return sub(m, d[d.startIndex..<mid], complete) + [root(Array(d[mid...]))] }
            return sub(m - k, d[mid...], false) + [root(Array(d[d.startIndex..<mid]))]
        }
        return sub(first, leaves[...], true)
    }

    /// Decides whether a signed checkpoint (`size`, `root`) may replace what this installation already trusts.
    /// `logLines` is the public log; it is required whenever the tree grew, and is checked leaf by leaf.
    static func checkAgainstPrior(_ prior: TrustState?, origin: String, size: Int, root: Data, logLines: [Data]?) throws {
        func fail(_ s: String) -> Failure { Failure(reason: s) }
        if let logLines {
            guard logLines.count >= size else { throw fail("the published log has \(logLines.count) entries but the checkpoint claims \(size)") }
            let leaves = logLines.prefix(size).map(leafHash)
            guard self.root(Array(leaves)) == root else { throw fail("the published log does not hash to the signed checkpoint root") }
        }
        guard let prior else { return }
        guard prior.origin == origin else { throw fail("log origin changed from \(prior.origin) to \(origin)") }
        guard let priorRoot = data(hex: prior.root) else { throw fail("stored trust state is malformed") }
        if size < prior.size { throw fail("rollback: checkpoint size \(size) is older than the trusted size \(prior.size)") }
        if size == prior.size {
            guard root == priorRoot else { throw fail("fork: a different root at the already trusted size \(size)") }
            return
        }
        guard let logLines else { throw fail("the log must be available to prove it extends the trusted size \(prior.size)") }
        let leaves = logLines.prefix(size).map(leafHash)
        guard self.root(Array(leaves.prefix(prior.size))) == priorRoot else { throw fail("fork: the log no longer contains the trusted state at size \(prior.size)") }
        let proof = consistencyProof(first: prior.size, leaves: Array(leaves))
        guard verifyConsistency(first: prior.size, second: size, firstRoot: priorRoot, secondRoot: root, proof: proof)
        else { throw fail("consistency proof between sizes \(prior.size) and \(size) does not verify") }
    }
}
