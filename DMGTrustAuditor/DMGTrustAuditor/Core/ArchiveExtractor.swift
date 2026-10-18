import Foundation

/// Extracts untrusted archives (zip, tar, tar.gz, gzip, and PKG payloads in cpio form) into a private
/// directory without executing anything. bsdtar reads all of these. Safety is enforced three times:
/// the listing is checked before extraction, the extraction runs with a timeout and a live size watch,
/// and the resulting tree is re-checked (no links leaving the directory, no devices, size and count caps).
struct ArchiveLimits: Equatable {
    var maxEntries = 20_000
    var maxExpandedBytes: Int64 = 1_073_741_824      // 1 GiB
    var maxPathDepth = 32
    var maxNameBytes = 1024
    var maxArchiveBytes: Int64 = 4_294_967_296        // 4 GiB compressed input
    var timeout: TimeInterval = 120
}

enum ArchiveExtractor {
    struct Failure: Error, Equatable { let reason: String }
    static let tar = "/usr/bin/tar"

    struct Result: Equatable { let entries: Int; let expandedBytes: Int64; let removedLinks: [String] }

    static func extract(_ archive: URL, into dest: URL, limits: ArchiveLimits = ArchiveLimits(),
                        cancelled: (() -> Bool)? = nil) throws -> Result {
        let fm = FileManager.default
        if let size = (try? fm.attributesOfItem(atPath: archive.path))?[.size] as? NSNumber, size.int64Value > limits.maxArchiveBytes {
            throw Failure(reason: "archive larger than \(limits.maxArchiveBytes) bytes")
        }
        // 1. Inspect the listing without writing anything.
        let listing = BoundedProcess.run(tar, ["-tvf", archive.path], timeout: limits.timeout, maxOutput: 16_000_000, cancelled: cancelled)
        if listing.timedOut { throw Failure(reason: "listing timed out (possible decompression bomb)") }
        guard listing.status == 0 else { throw Failure(reason: "not a readable archive: \(listing.output.prefix(200))") }
        if listing.truncated { throw Failure(reason: "listing too large") }
        try checkListing(listing.output, limits: limits)

        // 2. Extract with a live size watch. bsdtar refuses absolute paths and ".." unless -P is given.
        try fm.createDirectory(at: dest, withIntermediateDirectories: true)
        var lastCheck = Date.distantPast; var exceeded = false
        let watch: () -> Bool = {
            if cancelled?() == true { return true }
            if Date().timeIntervalSince(lastCheck) > 0.25 {
                lastCheck = Date()
                if treeSize(dest, stopAfter: limits.maxExpandedBytes) > limits.maxExpandedBytes { exceeded = true; return true }
            }
            return false
        }
        let out = BoundedProcess.run(tar, ["-xf", archive.path, "-C", dest.path, "--no-same-owner", "--no-same-permissions"],
                                     timeout: limits.timeout, maxOutput: 100_000, cancelled: watch)
        if exceeded { throw Failure(reason: "expanded size exceeds \(limits.maxExpandedBytes) bytes") }
        if out.timedOut { throw Failure(reason: "extraction timed out") }
        guard out.status == 0 else { throw Failure(reason: "extraction failed: \(out.output.prefix(200))") }

        // 3. Re-check what actually landed on disk.
        return try sanitize(dest, limits: limits)
    }

    /// Pure check of `tar -tv` output; exposed for tests.
    static func checkListing(_ text: String, limits: ArchiveLimits) throws {
        var count = 0; var total: Int64 = 0
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            count += 1
            if count > limits.maxEntries { throw Failure(reason: "more than \(limits.maxEntries) entries") }
            guard let type = line.first else { continue }
            guard "-dlh".contains(type) else { throw Failure(reason: "special file entry (type \(type)) is not allowed") }
            let parts = line.split(separator: " ", maxSplits: 8, omittingEmptySubsequences: true)
            guard parts.count >= 9 else { throw Failure(reason: "unparseable listing line") }
            var name = String(parts[8])
            if let r = name.range(of: " -> ") { name = String(name[..<r.lowerBound]) }
            if let r = name.range(of: " link to ") { name = String(name[..<r.lowerBound]) }
            try checkName(name, limits: limits)
            total += Int64(parts[4]) ?? 0
            if total > limits.maxExpandedBytes { throw Failure(reason: "declared expanded size exceeds \(limits.maxExpandedBytes) bytes") }
        }
    }
    static func checkName(_ name: String, limits: ArchiveLimits) throws {
        let comps = name.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        if name.hasPrefix("/") { throw Failure(reason: "absolute path in archive: \(name.prefix(80))") }
        if comps.contains("..") { throw Failure(reason: "path traversal in archive: \(name.prefix(80))") }
        if name.contains("\\") || name.contains("\0") { throw Failure(reason: "illegal character in archive path") }
        if comps.count > limits.maxPathDepth || name.utf8.count > limits.maxNameBytes { throw Failure(reason: "path too deep or too long") }
    }

    static func treeSize(_ root: URL, stopAfter: Int64) -> Int64 {
        var total: Int64 = 0
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.fileSizeKey, .isSymbolicLinkKey], options: []) else { return 0 }
        for case let u as URL in en {
            let v = try? u.resourceValues(forKeys: [.fileSizeKey, .isSymbolicLinkKey])
            if v?.isSymbolicLink == true { continue }
            total += Int64(v?.fileSize ?? 0)
            if total > stopAfter { return total }
        }
        return total
    }

    /// Removes links that leave `root` or point at absolute paths; verifies counts and sizes.
    static func sanitize(_ root: URL, limits: ArchiveLimits) throws -> Result {
        let fm = FileManager.default
        let rootPath = root.resolvingSymlinksInPath().standardizedFileURL.path
        var entries = 0; var bytes: Int64 = 0; var removed: [String] = []
        guard let en = fm.enumerator(at: root, includingPropertiesForKeys: [.isSymbolicLinkKey, .isRegularFileKey, .isDirectoryKey, .fileSizeKey], options: []) else { return Result(entries: 0, expandedBytes: 0, removedLinks: []) }
        var links: [URL] = []
        for case let u as URL in en {
            entries += 1
            if entries > limits.maxEntries { throw Failure(reason: "more than \(limits.maxEntries) entries after extraction") }
            let v = try u.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .isDirectoryKey, .fileSizeKey])
            if v.isSymbolicLink == true { links.append(u); continue }
            if v.isRegularFile != true && v.isDirectory != true { throw Failure(reason: "special file found after extraction") }
            bytes += Int64(v.fileSize ?? 0)
            if bytes > limits.maxExpandedBytes { throw Failure(reason: "expanded size exceeds limit") }
        }
        for link in links {
            let target = (try? fm.destinationOfSymbolicLink(atPath: link.path)) ?? ""
            let resolved = target.hasPrefix("/") ? URL(fileURLWithPath: target) : link.deletingLastPathComponent().appendingPathComponent(target)
            let std = resolved.standardizedFileURL.path
            if target.hasPrefix("/") || !(std == rootPath || std.hasPrefix(rootPath + "/")) {
                try? fm.removeItem(at: link)
                removed.append("\(link.lastPathComponent) -> \(target)")
            }
        }
        return Result(entries: entries, expandedBytes: bytes, removedLinks: removed)
    }

    /// Single-file gzip (not a tarball): decompress with a hard byte cap.
    static func gunzip(_ file: URL, to out: URL, limits: ArchiveLimits = ArchiveLimits()) throws -> Int64 {
        FileManager.default.createFile(atPath: out.path, contents: nil)
        let handle = try FileHandle(forWritingTo: out); defer { try? handle.close() }
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-dc", file.path]
        p.standardOutput = handle; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
        try p.run()
        let deadline = Date().addingTimeInterval(limits.timeout); var exceeded = false
        while p.isRunning {
            let size = ((try? FileManager.default.attributesOfItem(atPath: out.path))?[.size] as? NSNumber)?.int64Value ?? 0
            if size > limits.maxExpandedBytes { exceeded = true; p.terminate(); break }
            if Date() > deadline { p.terminate(); throw Failure(reason: "gzip timed out") }
            Thread.sleep(forTimeInterval: 0.05)
        }
        p.waitUntilExit()
        let finalSize = ((try? FileManager.default.attributesOfItem(atPath: out.path))?[.size] as? NSNumber)?.int64Value ?? 0
        if finalSize > limits.maxExpandedBytes { exceeded = true }   // a fast stream can finish between two polls
        if exceeded { try? FileManager.default.removeItem(at: out); throw Failure(reason: "gzip expands beyond \(limits.maxExpandedBytes) bytes") }
        guard p.terminationStatus == 0 else { throw Failure(reason: "gzip stream is corrupt") }
        return ((try? FileManager.default.attributesOfItem(atPath: out.path))?[.size] as? NSNumber)?.int64Value ?? 0
    }
}
