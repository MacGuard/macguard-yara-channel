import Foundation

/// What an input file really is, decided from its content first and its name second.
enum ContentKind: Equatable {
    case dmg
    case pkg
    case mpkg
    case app
    case zip
    case tar
    case tarGzip
    case gzip
    case machO
    case script(ScriptLanguage)
    case workflow
    case appleScriptCompiled
    case iso
    case unknown
}

enum ScriptLanguage: String, Equatable {
    case shell, python, javascript, ruby, appleScript, other
}

struct ContentDetection: Equatable {
    let kind: ContentKind
    /// Set when the file name suggests a different kind than the content shows (e.g. a ".dmg" that is a zip).
    let extensionMismatch: String?
}

enum ContentDetector {
    private static let machOMagics: Set<UInt32> = [0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE]
    private static let fatMagics: Set<UInt32> = [0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA]

    static func detect(_ url: URL) -> ContentDetection {
        let ext = url.pathExtension.lowercased()
        let isDirectory = (try? url.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
        if isDirectory {
            switch ext {
            case "app": return ContentDetection(kind: .app, extensionMismatch: nil)
            case "mpkg", "pkg": return ContentDetection(kind: .mpkg, extensionMismatch: nil)
            case "workflow": return ContentDetection(kind: .workflow, extensionMismatch: nil)
            default: return ContentDetection(kind: .unknown, extensionMismatch: nil)
            }
        }
        guard let kind = sniff(url, ext: ext) else { return ContentDetection(kind: .unknown, extensionMismatch: nil) }
        return ContentDetection(kind: kind, extensionMismatch: mismatch(kind: kind, ext: ext))
    }

    private static func sniff(_ url: URL, ext: String) -> ContentKind? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        guard size > 0 else { return nil }
        func read(at offset: UInt64, count: Int) -> [UInt8] {
            guard offset < size, (try? handle.seek(toOffset: offset)) != nil else { return [] }
            return [UInt8](((try? handle.read(upToCount: count)) ?? Data()))
        }
        let head = read(at: 0, count: 512)
        func starts(_ bytes: [UInt8]) -> Bool { head.count >= bytes.count && Array(head.prefix(bytes.count)) == bytes }

        if starts([0x78, 0x61, 0x72, 0x21]) { return .pkg }                       // "xar!" flat installer package
        if starts([0x50, 0x4B, 0x03, 0x04]) || starts([0x50, 0x4B, 0x05, 0x06]) { return .zip }
        if starts([0x1F, 0x8B]) {
            let isTarGz = ext == "tgz" || (ext == "gz" && url.deletingPathExtension().pathExtension.lowercased() == "tar")
            return isTarGz ? .tarGzip : .gzip   // a gzip stream cannot be told from tar.gz without decompressing it
        }
        if read(at: 257, count: 5) == Array("ustar".utf8) { return .tar }
        if head.count >= 4 {
            let be = head.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            if machOMagics.contains(be) { return .machO }
            if fatMagics.contains(be) {
                // 0xCAFEBABE is also the Java class magic; a fat header has a small architecture count.
                let count = head.count >= 8 ? head[4...7].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } : 0
                let littleCount = head.count >= 8 ? head[4...7].reversed().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } : 0
                if (1...30).contains(count) || (1...30).contains(littleCount) { return .machO }
            }
        }
        if starts(Array("FasdUAS".utf8)) { return .appleScriptCompiled }
        if read(at: 0x8001, count: 5) == Array("CD001".utf8) { return .iso }
        // UDIF disk images end with a 512-byte "koly" trailer.
        if size >= 512, read(at: size - 512, count: 4) == Array("koly".utf8) { return .dmg }
        if starts([0x23, 0x21]) { return .script(language(shebang: head, ext: ext)) }   // "#!"
        switch ext {
        case "sh", "command", "bash", "zsh": return .script(.shell)
        case "py": return .script(.python)
        case "js": return .script(.javascript)
        case "rb": return .script(.ruby)
        case "applescript": return .script(.appleScript)
        default: return nil
        }
    }

    private static func language(shebang head: [UInt8], ext: String) -> ScriptLanguage {
        let line = String(decoding: head.prefix(while: { $0 != 0x0A }), as: UTF8.self).lowercased()
        if line.contains("python") { return .python }
        if line.contains("ruby") { return .ruby }
        if line.contains("node") || line.contains("osascript -l javascript") { return .javascript }
        if line.contains("osascript") { return .appleScript }
        if line.contains("sh") { return .shell }
        switch ext { case "py": return .python; case "rb": return .ruby; case "js": return .javascript; default: return .other }
    }

    private static func mismatch(kind: ContentKind, ext: String) -> String? {
        guard !ext.isEmpty else { return nil }
        let expected: [String]
        switch kind {
        case .dmg: expected = ["dmg", "sparseimage", "sparsebundle"]
        case .pkg: expected = ["pkg", "mpkg"]
        case .zip: expected = ["zip", "ipa", "jar", "docx", "xlsx", "pptx"]
        case .tar: expected = ["tar"]
        case .tarGzip: expected = ["gz", "tgz"]
        case .gzip: expected = ["gz", "tgz"]
        case .iso: expected = ["iso", "cdr"]
        case .appleScriptCompiled: expected = ["scpt"]
        case .machO, .script, .app, .mpkg, .workflow, .unknown: return nil   // Mach-O and scripts legitimately carry any or no extension.
        }
        return expected.contains(ext) ? nil : ".\(ext)"
    }
}
