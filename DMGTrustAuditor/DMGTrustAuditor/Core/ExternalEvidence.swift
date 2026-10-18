import Foundation

// Network evidence is advisory. AASA is an association claim hosted by a domain,
// NOT proof of a macOS download's provenance or the current Apple Team ID.
enum ExternalEvidence {
    static func inspect(_ input: AuditInput, observedBundle: String, observedTeam: String) -> [AuditFinding] {
        var output: [AuditFinding] = []
        func add(_ title: String, _ detail: String, _ state: AuditState, _ weight: Int = 0) {
            output.append(AuditFinding(title: title, detail: detail, state: state, weight: weight))
        }
        guard !input.sourceURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            add("Official publisher reference / Fuente del fabricante", "No verified official publisher URL provided. Automatic publisher hash lookup is not possible without a trusted source.", .unknown)
            return output
        }
        guard let supplied = URL(string: input.sourceURL), supplied.scheme?.lowercased() == "https",
              let host = supplied.host, !host.isEmpty, supplied.user == nil, supplied.password == nil else {
            add("Publisher URL", "Only an HTTPS URL without embedded credentials is accepted.", .warning)
            return output
        }
        // Explicitly prevent local-network SSRF and arbitrary hostnames, including IP literals.
        let lowerHost = host.lowercased()
        let labels = lowerHost.split(separator: ".")
        guard labels.count >= 2, !lowerHost.hasSuffix(".local"), !lowerHost.hasSuffix(".internal"),
              !lowerHost.hasSuffix(".localhost"), lowerHost != "localhost",
              labels.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") } }),
              !labels.allSatisfy({ $0.allSatisfy(\.isNumber) }), supplied.port == nil else {
            add("Publisher URL", "Local, IP-like, or nonstandard publisher host blocked. No network request performed.", .warning)
            return output
        }
        add("Publisher identity / Identidad del fabricante", "Reference host: \(lowerHost). Domain ownership and relationship to the signer MUST be established independently. HTTPS alone is insufficient.", .unknown)
        // No generic official SHA index exists. Only attempt an explicit checksum URL
        // on the user-supplied publisher host; never infer a hash from search snippets.
        output.append(contentsOf: officialHash(input, host: lowerHost))
        guard let aasa = URL(string: "https://\(lowerHost)/.well-known/apple-app-site-association") else { return output }
        let semaphore = DispatchSemaphore(value: 0)
        var data: Data?
        var response: URLResponse?
        var requestError: Error?
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 7
        config.timeoutIntervalForResource = 9
        config.httpMaximumConnectionsPerHost = 1
        let session = URLSession(configuration: config, delegate: NoRedirectDelegate(), delegateQueue: nil)
        var req = URLRequest(url: aasa); req.httpMethod = "GET"; req.setValue("application/json", forHTTPHeaderField: "Accept")
        let task = session.dataTask(with: req) { body, reply, error in
            data = body; response = reply; requestError = error; semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + 11) == .timedOut { task.cancel(); add("AASA", "Request timed out. No identity conclusion.", .unknown); return output }
        session.invalidateAndCancel()
        guard requestError == nil, let http = response as? HTTPURLResponse, http.statusCode == 200,
              let body = data, body.count <= 1_000_000 else {
            add("AASA", "Not accessible, oversized, or HTTP error; AASA is optional and absence is not suspicious.", .unknown)
            return output
        }
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            add("AASA", "Response was not valid JSON.", .unknown); return output
        }
        var ids: [String] = []
        if let applinks = json["applinks"] as? [String: Any] {
            if let details = applinks["details"] as? [[String: Any]] {
                for detail in details {
                    if let id = detail["appID"] as? String { ids.append(id) }
                    if let array = detail["appIDs"] as? [String] { ids.append(contentsOf: array) }
                }
            }
            if let apps = applinks["apps"] as? [String] { ids.append(contentsOf: apps) }
        }
        ids = Array(Set(ids)).sorted()
        let matched = !observedBundle.isEmpty && ids.contains { $0.hasSuffix("." + observedBundle) }
        let suffixNote = observedTeam.isEmpty ? "" : " Observed signing Team ID: \(observedTeam); AASA prefix need not equal current Team ID."
        add("AASA domain association", "Fetched \(aasa.absoluteString). \(ids.count) application identifiers. Bundle suffix match: \(matched ? "yes" : "no"). This is an iOS/universal-links domain assertion, NOT macOS DMG authenticity proof.\(suffixNote)", matched ? .warning : .unknown)
        add("Official SHA-256 discovery", "Not inferred from arbitrary web text. Provide the vendor-published hash in the SHA-256 field and independently authenticate the publication. No guessed hashes or search-engine snippets are accepted.", .unknown)
        return output
    }
    private static func officialHash(_ input: AuditInput, host: String) -> [AuditFinding] {
        // The URL must be provided explicitly: no guessed paths, no site crawling.
        guard let reference = URL(string: input.sourceURL),
              reference.pathExtension.lowercased() == "sha256" ||
              reference.pathExtension.lowercased() == "sha256sum" ||
              reference.lastPathComponent.lowercased().contains("checksums") else {
            return [AuditFinding(title: "Official hash lookup / Hash oficial", detail: "No authenticated checksum manifest URL supplied. No universal Apple hash database exists. Open the publisher's official downloads/release page and provide its SHA-256 or a direct HTTPS checksum manifest URL in the reference field.", state: .unknown, weight: 0)]
        }
        guard reference.host?.lowercased() == host else { return [] }
        let result = fetchText(reference)
        guard let content = result else {
            return [AuditFinding(title: "Official hash lookup / Hash oficial", detail: "Checksum manifest unavailable, invalid, oversized or redirected. Confirm the publisher URL manually.", state: .unknown, weight: 0)]
        }
        let filename = input.file.lastPathComponent
        let candidates = content.components(separatedBy: .newlines).filter { $0.contains(filename) }
        let hashes = candidates.flatMap { line -> [String] in
            let pattern = #"(?i)\b[a-f0-9]{64}\b"#
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            return regex.matches(in: line, range: range).compactMap { match in
                Range(match.range, in: line).map { String(line[$0]).lowercased() }
            }
        }
        guard hashes.count == 1 else {
            return [AuditFinding(title: "Official hash lookup / Hash oficial", detail: "Manifest read from \(reference.absoluteString), but no unique SHA-256 for exact filename \(filename). Manual verification required.", state: .unknown, weight: 0)]
        }
        let calculated = AuditEngine.command("/usr/bin/shasum", ["-a", "256", input.file.path]).1.components(separatedBy: .whitespacesAndNewlines).first ?? ""
        return [AuditFinding(title: "Publisher checksum / Hash del fabricante", detail: "Manifest \(reference.absoluteString); exact filename \(filename); expected \(hashes[0]); actual \(calculated). Publisher-domain ownership must still be authenticated independently.", state: hashes[0] == calculated ? .passed : .failed, weight: 18)]
    }
    private static func fetchText(_ url: URL) -> String? {
        let semaphore = DispatchSemaphore(value: 0)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 6
        config.timeoutIntervalForResource = 8
        let session = URLSession(configuration: config, delegate: NoRedirectDelegate(), delegateQueue: nil)
        var body: Data?; var status = 0
        let task = session.dataTask(with: url) { data, response, _ in
            body = data; status = (response as? HTTPURLResponse)?.statusCode ?? 0
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + 9) == .timedOut { task.cancel(); session.invalidateAndCancel(); return nil }
        session.invalidateAndCancel()
        guard status == 200, let body, body.count <= 256_000 else { return nil }
        return String(data: body, encoding: .utf8)
    }
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
