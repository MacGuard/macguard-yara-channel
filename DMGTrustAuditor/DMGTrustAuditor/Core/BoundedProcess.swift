import Foundation

/// Runs a helper tool on untrusted input with a wall-clock timeout and an output cap.
/// Output is drained while the process runs, so a chatty child can never fill the pipe and hang us,
/// and the call never blocks forever: on timeout the child is terminated (then killed).
enum BoundedProcess {
    struct Result: Equatable {
        let status: Int32
        let output: String
        let timedOut: Bool
        let truncated: Bool
    }

    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 60, maxOutput: Int = 1_000_000,
                    cancelled: (() -> Bool)? = nil) -> Result {
        let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
        p.standardInput = FileHandle.nullDevice
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { return Result(status: -1, output: error.localizedDescription, timedOut: false, truncated: false) }

        let lock = NSLock(); var buffer = Data(); var truncated = false
        let reader = DispatchGroup(); reader.enter()
        DispatchQueue.global(qos: .utility).async {
            let h = pipe.fileHandleForReading
            while true {
                let chunk = h.availableData
                if chunk.isEmpty { break }
                lock.lock()
                if buffer.count < maxOutput { buffer.append(chunk.prefix(maxOutput - buffer.count)) }
                if buffer.count >= maxOutput { truncated = true }
                lock.unlock()
            }
            reader.leave()
        }
        let deadline = Date().addingTimeInterval(timeout)
        var timedOut = false
        while p.isRunning {
            if Date() > deadline || cancelled?() == true { timedOut = Date() > deadline; p.terminate(); break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        if p.isRunning {
            let grace = Date().addingTimeInterval(1)
            while p.isRunning && Date() < grace { Thread.sleep(forTimeInterval: 0.02) }
            if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        }
        p.waitUntilExit()
        _ = reader.wait(timeout: .now() + 2)
        lock.lock(); defer { lock.unlock() }
        return Result(status: p.terminationStatus, output: String(decoding: buffer, as: UTF8.self), timedOut: timedOut, truncated: truncated)
    }
}
