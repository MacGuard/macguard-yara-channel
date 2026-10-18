import XCTest
import CryptoKit
@testable import DMGTrustAuditor

/// Vectors come from scripts/tlog.py so both implementations are held to the same Merkle definition.
final class ChannelVerifierTests: XCTestCase {
    private var dir: URL!
    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("cv-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("rules"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("logs"), withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    func testMerkleMatchesPythonVectors() {
        let leaves = (0..<7).map { ChannelVerifier.leafHash(Data("entry-\($0)".utf8)) }
        XCTAssertEqual(ChannelVerifier.hex(leaves[3]), "27479b6ab321d2ee477452f68ba527748e863cafe8fbd1df2bf89d1570d1b697")
        let root = ChannelVerifier.root(leaves)
        XCTAssertEqual(ChannelVerifier.hex(root), "9139601cc1ca8ab2a7a0c2c134c04845f2b1ba549a83d6c845cfcda439cc585d")
        let proof = ["049d7dcdb56bcfebd313304c9839f196a3d4b6ef3bdc0b08298f93ac8191f0a8", "2f27a5082c1d42afa488ac350a9fc4390c084f54f71ecdff859e98db8429b479",
                     "e429c5b5ccaa9523c37297f1846766f903137e82195c5199e6be57130d1006c8"].map { ChannelVerifier.data(hex: $0)! }
        XCTAssertTrue(ChannelVerifier.verifyInclusion(index: 3, size: 7, leaf: leaves[3], proof: proof, root: root))
        XCTAssertFalse(ChannelVerifier.verifyInclusion(index: 2, size: 7, leaf: leaves[3], proof: proof, root: root))
        XCTAssertFalse(ChannelVerifier.verifyInclusion(index: 3, size: 7, leaf: leaves[3], proof: Array(proof.dropLast()), root: root))
        XCTAssertFalse(ChannelVerifier.verifyInclusion(index: 3, size: 7, leaf: ChannelVerifier.leafHash(Data("forged".utf8)), proof: proof, root: root))
    }

    func testRulesRootIsOrderIndependentAndMatchesPython() {
        let a = [(path: "b", sha256: "22"), (path: "a", sha256: "11")]
        XCTAssertEqual(ChannelVerifier.rulesRoot(a), "bf065e6a50ad5249e45a076c5414c5d673116aa809c28363ebb1c2209f4dd66b")
        XCTAssertEqual(ChannelVerifier.rulesRoot(a), ChannelVerifier.rulesRoot(a.reversed()))
    }

    private func makeRelease(tamperRule: Bool = false) throws -> (verifier: ChannelVerifier, rules: URL) {
        try buildSampleRelease(in: dir, tamperRule: tamperRule)
        return (ChannelVerifier(signatureCheck: { _, _ in nil }), dir)
    }

    func testValidReleasePasses() throws {
        let r = try makeRelease()
        let s = try r.verifier.verify(directory: r.rules)
        XCTAssertEqual(s.fileCount, 1); XCTAssertEqual(s.logSize, 3)
    }
    func testTamperedRuleIsRejected() throws {
        let r = try makeRelease(tamperRule: true)
        XCTAssertThrowsError(try r.verifier.verify(directory: r.rules)) { XCTAssertTrue(($0 as? ChannelVerifier.Failure)?.reason.contains("does not match") == true) }
    }
    func testBadSignatureIsRejected() throws {
        let r = try makeRelease()
        let bad = ChannelVerifier(signatureCheck: { _, _ in "certificate identity mismatch" })
        XCTAssertThrowsError(try bad.verify(directory: r.rules)) { XCTAssertTrue(($0 as? ChannelVerifier.Failure)?.reason.contains("signature") == true) }
    }
    func testProofForDifferentRulesRootIsRejected() throws {
        let r = try makeRelease()
        let url = dir.appendingPathComponent("inclusion-proof.json")
        var doc = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        doc["entry"] = (doc["entry"] as! String).replacingOccurrences(of: "candidate.accepted", with: "candidate.rejected")
        try JSONSerialization.data(withJSONObject: doc).write(to: url)
        XCTAssertThrowsError(try r.verifier.verify(directory: r.rules))
    }
    func testManifestPathEscapingTheReleaseFolderIsRejected() throws {
        let r = try makeRelease()
        let url = dir.appendingPathComponent("manifest.json")
        var m = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        m["files"] = [["path": "../outside.yar", "sha256": "00"]]
        try JSONSerialization.data(withJSONObject: m).write(to: url)
        XCTAssertThrowsError(try r.verifier.verify(directory: r.rules)) { XCTAssertTrue(($0 as? ChannelVerifier.Failure)?.reason.contains("unsafe path") == true) }
    }
    /// End to end against the real published release, when the machine has cosign and network.
    func testRealPublishedReleaseIfAvailable() throws {
        guard let located = SigstoreVerifier.locate().0, let rel = ProcessInfo.processInfo.environment["MACGUARD_RELEASE_DIR"] else {
            throw XCTSkip("set MACGUARD_RELEASE_DIR to a downloaded release and install cosign")
        }
        let s = try ChannelVerifier(signatureCheck: SigstoreVerifier.check(located)).verify(directory: URL(fileURLWithPath: rel))
        XCTAssertGreaterThan(s.fileCount, 0)
    }
}

/// Builds a complete sample release (3-entry log) in `dir`; the caller supplies the signature check.
func buildSampleRelease(in dir: URL, tamperRule: Bool = false) throws {
    try FileManager.default.createDirectory(at: dir.appendingPathComponent("logs"), withIntermediateDirectories: true)
    let rule = Data("rule x { condition: true }".utf8)
    let rulePath = "rules/src/x.yar"
    try FileManager.default.createDirectory(at: dir.appendingPathComponent("rules/src"), withIntermediateDirectories: true)
    try rule.write(to: dir.appendingPathComponent(rulePath))
    let sha = ChannelVerifier.hex(Data(SHA256.hash(data: rule)))
    let rr = ChannelVerifier.rulesRoot([(rulePath, sha)])
    let entry = "{\"details\":{\"rules_root\":\"\(rr)\"},\"event\":\"candidate.accepted\",\"seq\":1}"
    let logLines = ["{\"event\":\"sources.fetched\",\"seq\":0}", entry, "{\"event\":\"release.approved\",\"seq\":2}"]
    try (logLines.joined(separator: "\n") + "\n").write(to: dir.appendingPathComponent("logs/log.jsonl"), atomically: true, encoding: .utf8)
    let leaves = logLines.map { ChannelVerifier.leafHash(Data($0.utf8)) }
    let root = ChannelVerifier.root(leaves)
    let path = [leaves[0], leaves[2]]   // index 1 of 3: left sibling 0, then the right subtree {2}
    let manifest: [String: Any] = ["files": [["path": rulePath, "sha256": sha]], "rules_root": rr,
                                   "log": ["origin": ChannelVerifier.logOrigin, "size": 3, "root": ChannelVerifier.hex(root)]]
    try JSONSerialization.data(withJSONObject: manifest).write(to: dir.appendingPathComponent("manifest.json"))
    try Data("{}".utf8).write(to: dir.appendingPathComponent("manifest.sigstore.json"))
    try Data("{}".utf8).write(to: dir.appendingPathComponent("logs/checkpoint.sigstore.json"))
    try "\(ChannelVerifier.logOrigin)\n3\n\(root.base64EncodedString())\n".write(to: dir.appendingPathComponent("logs/checkpoint.txt"), atomically: true, encoding: .utf8)
    let proofDoc: [String: Any] = ["index": 1, "size": 3, "root": ChannelVerifier.hex(root), "entry": entry, "proof": path.map(ChannelVerifier.hex)]
    try JSONSerialization.data(withJSONObject: proofDoc).write(to: dir.appendingPathComponent("inclusion-proof.json"))
    if tamperRule { try Data("rule x { condition: false }".utf8).write(to: dir.appendingPathComponent(rulePath)) }
}

