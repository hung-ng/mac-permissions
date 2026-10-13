import Foundation
import Darwin

final class Session {
    let lock = NSLock()
    let id: String
    let spec: [String: Any]
    let pid: Int32
    let tty: Bool
    var input: Int32
    let output: Int32
    var events: [[String: Any]] = []
    var next = 0
    var exitCode: Int?
    var bytes = 0
    var problem: String?
    var observedAncestry: [[String: Any]] = []
    var stderrSample = Data()
    let inputLock = NSLock()
    let started = Date().timeIntervalSince1970

    init(id: String, spec: [String: Any]) throws {
        let terminal = spec["tty"] as? Bool ?? false
        self.id = id; self.spec = spec; tty = terminal
        let tool = spec["tool"] as! [String: Any], path = tool["path"] as! String
        let args = [spec["argv0"] as? String ?? path] + (spec["args"] as! [String])
        let env = (spec["env"] as! [String: String]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
        let argv = args.map { strdup($0) } + [nil], envp = env.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        var process: Int32 = 0, stdinFD: Int32 = -1, stdoutFD: Int32 = -1, stderrFD: Int32 = -1
        let error = argv.withUnsafeBufferPointer { a in envp.withUnsafeBufferPointer { e in
            mp_spawn(path, a.baseAddress, e.baseAddress, spec["cwd"] as! String, terminal ? 1 : 0,
                     Int32(spec["rows"] as? Int ?? 24), Int32(spec["cols"] as? Int ?? 80), &process, &stdinFD, &stdoutFD, &stderrFD)
        }}
        guard error == 0 else { try fail("Launch failed: \(String(cString: strerror(error)))") }
        pid = process; input = stdinFD; output = stdoutFD
        observedAncestry = ancestry(pid)
        let group = DispatchGroup()
        for (fd, stream) in [(stdoutFD, "stdout"), (stderrFD, "stderr")] where fd >= 0 {
            group.enter()
            DispatchQueue.global().async { [self] in
                defer { close(fd); group.leave() }
                var buffer = [UInt8](repeating: 0, count: 32768)
                while true {
                    let count = read(fd, &buffer, buffer.count)
                    if count < 0 && errno == EINTR { continue }
                    if count <= 0 { break }
                    append(Data(buffer.prefix(count)), stream: stream)
                }
            }
        }
        DispatchQueue.global().async { [self] in
            let status = Int(mp_wait(pid))
            // Kill remaining members of this process group so inherited pipes cannot hang completion.
            kill(-pid, SIGTERM)
            group.wait()
            inputLock.lock(); if input >= 0 { close(input); input = -1 }; inputLock.unlock()
            lock.lock(); exitCode = status; lock.unlock()
        }
    }
    func append(_ data: Data, stream: String) {
        lock.lock(); defer { lock.unlock() }
        if bytes + data.count > 16 * 1024 * 1024 {
            problem = "Output exceeded the 16 MiB unacknowledged buffer. The session was cancelled; output is incomplete."
            kill(-pid, SIGKILL); return
        }
        events.append(["seq": next, "stream": stream, "data": data.base64EncodedString()]); next += 1; bytes += data.count
        if stream == "stderr" && stderrSample.count < 8192 { stderrSample.append(data.prefix(8192 - stderrSample.count)) }
    }
    func poll(after: Int) throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        let oldest = events.first?["seq"] as? Int ?? next
        guard after >= oldest, after <= next else { try fail("Output cursor is no longer available. Only one output consumer is supported.") }
        // The client acknowledges everything before its cursor. Keep the newest batch for retries.
        events.removeAll { event in
            if (event["seq"] as! Int) < after {
                bytes -= Data(base64Encoded: event["data"] as! String)!.count; return true
            }; return false
        }
        let batch = Array(events.prefix(32))
        let cursor = batch.last.map { ($0["seq"] as! Int) + 1 } ?? after
        var result: [String: Any] = ["id": id, "events": batch, "next": cursor, "pid": pid,
            "ancestry": observedAncestry, "tty": tty, "started": started]
        if let exitCode { result["exitCode"] = exitCode; result["complete"] = cursor == next }
        if let problem { result["problem"] = problem }
        if let exitCode, exitCode != 0 {
            let sample = String(decoding: stderrSample, as: UTF8.self).lowercased()
            result["diagnostic"] = ["classification": "failed-operation-cause-uncertain", "exitCode": exitCode,
                "permissionHint": sample.contains("operation not permitted") || sample.contains("permission denied"),
                "explanation": "The target process failed. stderr text is a hint, not proof of TCC attribution. Reproduce the exact protected operation after repair."] as [String: Any]
        }
        return result
    }
    func writeInput(_ data: Data, eof: Bool) throws {
        inputLock.lock(); defer { inputLock.unlock() }
        guard input >= 0 else { try fail("Input is closed") }
        // Writes run outside the API queue and may wait for the target to consume input.
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < data.count {
                let count = write(input, bytes.baseAddress!.advanced(by: offset), data.count - offset)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { try fail("Target input closed") }; offset += count
            }
        }
        if eof {
            if tty { var eot: UInt8 = 4; _ = write(input, &eot, 1) }
            else { close(input); input = -1 }
        }
    }
    func cancel() {
        lock.lock(); let active = exitCode == nil; lock.unlock()
        guard active else { return }
        kill(-pid, SIGTERM); DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [self] in
        lock.lock(); let running = exitCode == nil; lock.unlock(); if running { kill(-pid, SIGKILL) }
    }}
    func resize(rows: Int, cols: Int) throws {
        guard tty, rows > 0, cols > 0, rows <= 1000, cols <= 1000 else { try fail("Invalid terminal size") }
        inputLock.lock(); defer { inputLock.unlock() }
        guard input >= 0, mp_resize(input, Int32(rows), Int32(cols)) == 0 else { try fail("Terminal is closed") }
        kill(-pid, SIGWINCH)
    }
}
