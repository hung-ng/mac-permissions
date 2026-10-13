import Foundation
import Darwin
import Security

final class Core {
    let queue = DispatchQueue(label: "dev.macpermissions.core")
    let ownerToken: String
    let launcherToken: String
    let state: URL
    let port: Int
    var requests: [String: [String: Any]] = [:]
    var sessions: [String: Session] = [:]
    var permissionEvidence: [String: Any] = ["fullDiskAccess": "unverified", "appManagement": "unverified"]
    let helperIdentity: [String: Any]

    init(state: URL, port: Int) throws {
        self.state = state; self.port = port
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var st = stat()
        guard lstat(state.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == getuid(), st.st_mode & 0o077 == 0 else { try fail("State directory must be owned by this user, mode 0700, and not a symlink") }
        ownerToken = try Core.token(state.appendingPathComponent("owner.token"))
        launcherToken = try Core.token(state.appendingPathComponent("launcher.token"))
        helperIdentity = try identity(Bundle.main.executableURL!.path)
    }
    static func token(_ url: URL) throws -> String {
        let fd = open(url.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd >= 0 {
            var bytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { close(fd); try fail("Random generation failed") }
            let value = bytes.map { String(format: "%02x", $0) }.joined()
            let data = Data((value + "\n").utf8)
            let count = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }; close(fd)
            guard count == data.count else { try fail("Could not write credential") }; return value
        }
        guard errno == EEXIST else { try fail("Could not create credential") }
        let readFD = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard readFD >= 0 else { try fail("Could not open credential") }
        defer { close(readFD) }
        var st = stat()
        guard fstat(readFD, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid(), st.st_mode & 0o077 == 0, st.st_size <= 256 else { try fail("Credential must be a private regular file owned by this user") }
        var bytes = [UInt8](repeating: 0, count: 256)
        let count = read(readFD, &bytes, 256)
        guard count > 0 else { try fail("Empty credential") }
        let value = String(decoding: bytes.prefix(count), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.count == 64, value.allSatisfy({ $0.isHexDigit }) else { try fail("Invalid credential") }; return value
    }
    func role(_ bearer: String) -> String? {
        func equal(_ a: String, _ b: String) -> Bool {
            let aa = Array(a.utf8), bb = Array(b.utf8)
            guard aa.count == bb.count else { return false }
            return zip(aa, bb).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
        }
        if equal(bearer, ownerToken) { return "owner" }; if equal(bearer, launcherToken) { return "launcher" }; return nil
    }
    func audit(_ action: String, id: String, fingerprint: String) {
        // Keep arguments, environment values, input, output, and credentials out of the audit file.
        let event: [String: Any] = ["time": Date().timeIntervalSince1970, "action": action, "request": id, "fingerprint": fingerprint]
        let path = state.appendingPathComponent("audit.jsonl").path
        let fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd >= 0 { if let data = try? jsonData(event) { _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }; _ = write(fd, "\n", 1) }; close(fd) }
    }
    func normalize(_ body: [String: Any]) throws -> [String: Any] {
        let operation = body["operation"] as? String ?? "launch"
        guard ["launch", "probe", "read-fixture", "app-management-fixture"].contains(operation) else { try fail("Unsupported operation") }
        if operation == "app-management-fixture" {
            guard let path = body["path"] as? String else { try fail("Fixture app path required") }
            let bundlePath = try canonical(path)
            guard URL(fileURLWithPath: bundlePath).lastPathComponent.hasPrefix("MacPermissionsFixture-"), bundlePath.hasSuffix(".app"),
                  let info = NSDictionary(contentsOfFile: bundlePath + "/Contents/Info.plist"),
                  (info["CFBundleIdentifier"] as? String)?.hasPrefix("dev.macpermissions.fixture.") == true else { try fail("Use a disposable app created by scripts/create-fixture.py") }
            return ["operation": operation, "path": bundlePath,
                    "marker": bundlePath + "/Contents/Resources/mac-permissions-marker",
                    "expectedContents": "mac-permissions app fixture v1\n", "newContents": "mac-permissions app fixture v2\n"]
        }
        if operation != "launch" {
            guard let path = body["path"] as? String, path.hasPrefix("/"), !path.utf8.contains(0) else { try fail("Absolute path required") }
            if operation == "read-fixture" {
                guard URL(fileURLWithPath: path).lastPathComponent == "probe.txt", path.contains("/MacPermissionsFixture-") else { try fail("Read operation is limited to an owner-created probe.txt fixture") }
            }
            return ["operation": operation, "path": path]
        }
        guard let path = body["executable"] as? String, let args = body["args"] as? [String], let cwd = body["cwd"] as? String,
              let env = body["env"] as? [String: String] else { try fail("executable, args, cwd and env are required") }
        guard args.count <= 4096, !args.contains(where: { $0.utf8.contains(0) }), env.count <= 4096,
              !env.contains(where: { $0.key.isEmpty || $0.key.contains("=") || $0.key.utf8.contains(0) || $0.value.utf8.contains(0) }) else { try fail("Invalid arguments or environment") }
        let tool = try identity(path), directory = try canonical(cwd)
        let argv0 = body["argv0"] as? String ?? path
        guard !argv0.utf8.contains(0) else { try fail("Invalid argv0") }
        let rows = body["rows"] as? Int ?? 24, cols = body["cols"] as? Int ?? 80
        guard (1...1000).contains(rows), (1...1000).contains(cols) else { try fail("Terminal dimensions must be between 1 and 1000") }
        var st = stat()
        guard stat(directory, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { try fail("Working directory is not a directory") }
        var result: [String: Any] = ["operation": operation, "requestedExecutable": path, "argv0": argv0, "tool": tool, "args": args, "cwd": directory,
             "env": env, "tty": body["tty"] as? Bool ?? false, "rows": rows, "cols": cols]
        if let evidence = body["failure"] as? [String: Any] { result["reportedFailure"] = evidence }
        if let context = body["context"] as? [String: Any] {
            result["reportedLaunchContext"] = context
            if let pid = context["launcherPID"] as? Int32, pid > 0 { result["observedLauncherAncestry"] = ancestry(pid) }
        }
        return result
    }
    func view(_ request: [String: Any], owner: Bool) -> [String: Any] {
        var result = request
        if result["state"] as? String == "pending", (result["expires"] as? Double ?? 0) < Date().timeIntervalSince1970 { result["state"] = "expired" }
        if let id = request["id"] as? String, let session = sessions[id] {
            session.lock.lock()
            if let code = session.exitCode {
                if result["state"] as? String == "running" { result["state"] = code == 0 ? "succeeded" : "failed" }
                result["exitCode"] = code
                result["diagnostic"] = ["classification": code == 0 ? "operation-succeeded" : "failed-operation-cause-uncertain",
                    "explanation": "This is the target process's exit status. Full Disk Access and App Management remain unverified for operations it did not perform."]
            }
            if let problem = session.problem { result["problem"] = problem }
            session.lock.unlock()
        }
        if !owner, var spec = result["spec"] as? [String: Any] { spec.removeValue(forKey: "env"); result["spec"] = spec }
        return result
    }
    func handle(method: String, path: String, query: [String: String], body: [String: Any], role: String) throws -> [String: Any] {
        let owner = role == "owner"
        if method == "GET", path == "/v1/status" {
            return ["version": 1, "helper": helperIdentity, "ancestry": ancestry(getpid()), "permissions": permissionEvidence,
               "bundlePath": Bundle.main.bundleURL.path, "suggestedProbePath": NSHomeDirectory() + "/Library/Mail", "port": port,
               "consent": "Initial macOS grants require the owner in the remote Mac's GUI. Product approvals only authorize use of existing access."]
        }
        if method == "POST", path == "/v1/reports" {
            guard requests.count < 500, let pid = body["pid"] as? Int32, pid > 0, let targetPath = body["path"] as? String,
                  targetPath.hasPrefix("/"), let error = body["errno"] as? Int, error > 0 else { try fail("Report requires pid, absolute path, and failing errno") }
            let id = UUID().uuidString.lowercased(), now = Date().timeIntervalSince1970
            let spec: [String: Any] = ["operation": "reported-failure", "path": targetPath, "reportedErrno": error,
                 "reportedOperation": body["operation"] as? String ?? "unknown", "observedAncestry": ancestry(pid),
                 "classification": "reported-failure-cause-uncertain", "explanation": "The session service reported this error. Process ancestry is observed now; the failing operation and privacy cause have not been independently verified."]
            let fingerprint = digest(try jsonData(spec))
            let report: [String: Any] = ["id": id, "state": "reported", "spec": spec, "created": now, "fingerprint": fingerprint]
            requests[id] = report; audit("reported", id: id, fingerprint: fingerprint); return report
        }
        if method == "POST", path == "/v1/requests" {
            guard requests.count < 500 else { try fail("Request limit reached. Restart the helper after active sessions finish.") }
            let spec = try normalize(body), id = UUID().uuidString.lowercased(), now = Date().timeIntervalSince1970
            let fingerprint = digest(try jsonData(spec))
            let request: [String: Any] = ["id": id, "spec": spec, "fingerprint": fingerprint, "state": "pending", "created": now, "expires": now + 600]
            requests[id] = request; audit("requested", id: id, fingerprint: fingerprint); return view(request, owner: owner)
        }
        if method == "GET", path == "/v1/requests", owner {
            return ["requests": requests.values.sorted { ($0["created"] as! Double) > ($1["created"] as! Double) }.map { view($0, owner: true) }]
        }
        let parts = path.split(separator: "/").map(String.init)
        guard parts.count >= 3, parts[0] == "v1", parts[1] == "requests", let stored = requests[parts[2]] else { try fail("Unknown route or request") }
        let id = parts[2]
        if method == "GET", parts.count == 3 { return view(stored, owner: owner) }
        let action = parts.count == 4 ? parts[3] : ""
        if method == "GET", action == "events", let session = sessions[id] { return try session.poll(after: Int(query["after"] ?? "0") ?? -1) }
        if method == "POST", action == "cancel" {
            sessions[id]?.cancel(); requests[id]?["state"] = "cancelled"; audit("cancelled", id: id, fingerprint: stored["fingerprint"] as! String); return ["ok": true]
        }
        if method == "POST", action == "resize", let session = sessions[id] {
            try session.resize(rows: body["rows"] as? Int ?? 0, cols: body["cols"] as? Int ?? 0); return ["ok": true]
        }
        guard method == "POST", owner, ["approve", "deny", "retry"].contains(action) else { try fail("Owner approval required or unsupported action") }
        guard body["fingerprint"] as? String == stored["fingerprint"] as? String else { try fail("Approval fingerprint does not match this operation") }
        if action == "deny" {
            guard ["pending", "blocked"].contains(stored["state"] as? String ?? "") else { try fail("Only pending or blocked requests can be denied. Cancel a running tool to stop it.") }
            requests[id]?["state"] = "denied"; audit("denied", id: id, fingerprint: stored["fingerprint"] as! String); return ["ok": true]
        }
        if action == "retry" {
            guard stored["state"] as? String == "blocked", stored["spec"] as? [String: Any] != nil else { try fail("Only a blocked protected operation can be retried. Launch retries need a new approval.") }
        } else {
            guard stored["state"] as? String == "pending", stored["expires"] as! Double > Date().timeIntervalSince1970 else { try fail("Approval expired or already used") }
        }
        let spec = stored["spec"] as! [String: Any], operation = spec["operation"] as! String
        if operation == "launch" {
            let tool = spec["tool"] as! [String: Any]
            guard let current = try? identity(spec["requestedExecutable"] as! String) else {
                requests[id]?["state"] = "tool-changed"; try fail("Executable changed or disappeared after request. Submit again after repair.")
            }
            guard current["path"] as? String == tool["path"] as? String, current["sha256"] as? String == tool["sha256"] as? String else {
                requests[id]?["state"] = "tool-changed"; try fail("Executable changed after request. Submit again and approve the updated binary.")
            }
            let session = try Session(id: id, spec: spec); sessions[id] = session; requests[id]?["state"] = "running"
            requests[id]?["pid"] = session.pid; requests[id]?["actualAncestry"] = session.observedAncestry
        } else {
            let path = spec["path"] as! String
            if operation == "app-management-fixture" {
                let marker = spec["marker"] as! String
                let fd = open(marker, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
                var code = fd < 0 ? errno : 0
                if fd >= 0 {
                    var st = stat(), buffer = [UInt8](repeating: 0, count: 256)
                    let valid = fstat(fd, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG && st.st_uid == getuid() && st.st_size <= 256
                    let count = valid ? read(fd, &buffer, buffer.count) : -1
                    let expected = spec["expectedContents"] as! String
                    if count < 0 || String(decoding: buffer.prefix(max(0, count)), as: UTF8.self) != expected { code = EINVAL }
                    else {
                        let data = Data((spec["newContents"] as! String).utf8)
                        if lseek(fd, 0, SEEK_SET) < 0 { code = errno }
                        else { let written = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
                            if written != data.count { code = errno == 0 ? EIO : errno }
                            else if ftruncate(fd, off_t(data.count)) != 0 || fsync(fd) != 0 { code = errno }
                        }
                    }
                    close(fd)
                }
                let result: [String: Any] = ["path": marker, "operation": "update-disposable-app-resource", "errno": code,
                   "classification": code == 0 ? "operation-succeeded-permission-unverified" : "confirmed-failure-cause-uncertain",
                   "explanation": code == 0 ? "The helper changed the disposable app's resource file. This verifies this update operation, not a global App Management grant. The fixture's signature is now invalid and the fixture can be removed." : "The disposable app update failed. Check the errno and repair App Management on the remote desktop if that is the cause, then retry.",
                   "ancestry": ancestry(getpid()), "time": Date().timeIntervalSince1970]
                requests[id]?["state"] = code == 0 ? "succeeded" : "blocked"; requests[id]?["result"] = result
                permissionEvidence["appManagement"] = ["status": "grant-unverified", "lastOperation": result]
                audit(action, id: id, fingerprint: stored["fingerprint"] as! String); return view(requests[id]!, owner: owner)
            }
            var result = probe(path)
            if operation == "read-fixture", result["errno"] as? Int32 == 0 {
                let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                if fd >= 0 {
                    var st = stat(), buffer = [UInt8](repeating: 0, count: 256)
                    let valid = fstat(fd, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG && st.st_uid == getuid() && st.st_size <= 256
                    let count = valid ? read(fd, &buffer, buffer.count) : -1; close(fd)
                    if count >= 0 { result["data"] = Data(buffer.prefix(count)).base64EncodedString(); result["operation"] = "read-owner-fixture" }
                    else { result["classification"] = "unverified"; result["explanation"] = "Fixture must be a regular file owned by this user, at most 256 bytes."; result["errno"] = EINVAL }
                } else { result = probe(path) }
            }
            let success = result["errno"] as? Int32 == 0
            requests[id]?["state"] = success ? "succeeded" : "blocked"; requests[id]?["result"] = result
            permissionEvidence["fullDiskAccess"] = ["status": "unverified-global", "lastOperation": result]
        }
        audit(action, id: id, fingerprint: stored["fingerprint"] as! String)
        return view(requests[id]!, owner: owner)
    }
}
