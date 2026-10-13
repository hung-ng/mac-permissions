import Foundation
import Darwin
import CryptoKit
import Security

enum Failure: Error, CustomStringConvertible {
    case message(String)
    var description: String { switch self { case .message(let text): return text } }
}
func fail(_ text: String) throws -> Never { throw Failure.message(text) }
func jsonData(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]) }
func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func fileDigest(_ path: String) throws -> String {
    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { try? file.close() }
    var hash = SHA256()
    while let bytes = try file.read(upToCount: 1024 * 1024), !bytes.isEmpty { hash.update(data: bytes) }
    return hash.finalize().map { String(format: "%02x", $0) }.joined()
}
func canonical(_ path: String) throws -> String {
    guard path.hasPrefix("/"), !path.utf8.contains(0), let value = realpath(path, nil) else { try fail("Path must be absolute and exist: \(path)") }
    defer { free(value) }
    return String(cString: value)
}
func identity(_ path: String) throws -> [String: Any] {
    let resolved = try canonical(path)
    var st = stat()
    guard stat(resolved, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, access(resolved, X_OK) == 0 else { try fail("Executable must be a regular executable file") }
    var info: [String: Any] = ["path": resolved, "sha256": try fileDigest(resolved), "device": st.st_dev, "inode": st.st_ino]
    var code: SecStaticCode?
    if SecStaticCodeCreateWithPath(URL(fileURLWithPath: resolved) as CFURL, [], &code) == errSecSuccess, let code {
        var values: CFDictionary?
        if SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &values) == errSecSuccess, let data = values as? [String: Any] {
            info["signingIdentifier"] = data[kSecCodeInfoIdentifier as String] ?? "unknown"
            info["teamID"] = data[kSecCodeInfoTeamIdentifier as String] ?? "none"
            info["signatureValid"] = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess
            info["adHoc"] = ((data[kSecCodeInfoFlags as String] as? UInt32 ?? 0) & 2) != 0
        }
        var requirement: SecRequirement?
        var text: CFString?
        if SecCodeCopyDesignatedRequirement(code, [], &requirement) == errSecSuccess, let requirement,
           SecRequirementCopyString(requirement, [], &text) == errSecSuccess { info["designatedRequirement"] = text as String? }
    }
    return info
}
func ancestry(_ pid: Int32) -> [[String: Any]] {
    var result: [[String: Any]] = [], current = pid, seen = Set<Int32>()
    for _ in 0..<20 {
        if current < 1 || seen.contains(current) { break }; seen.insert(current)
        var buffer = [CChar](repeating: 0, count: 4096)
        let size = mp_path(current, &buffer, Int32(buffer.count))
        let parent = mp_parent(current)
        result.append(["pid": current, "ppid": parent, "executable": size > 0 ? String(cString: buffer) : "unavailable"])
        if current == 1 { break }; current = parent
    }
    return result
}
func probe(_ path: String) -> [String: Any] {
    // Opening a directory without enumerating it keeps the probe away from personal data.
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    let code = fd < 0 ? errno : 0
    if fd >= 0 { close(fd) }
    let classification: String
    let explanation: String
    switch code {
    case 0: classification = "operation-succeeded"; explanation = "This helper can open this exact path now. This does not prove access for a target tool or every protected location."
    case EPERM: classification = "confirmed-denial-cause-uncertain"; explanation = "The open failed with EPERM. macOS privacy controls or endpoint security may be responsible. Full Disk Access is a repair hypothesis for a protected path."
    case EACCES: classification = "confirmed-denial-cause-uncertain"; explanation = "The open failed with EACCES. Check Unix permissions and ACLs before assuming a privacy grant is missing."
    case ENOENT: classification = "unverified"; explanation = "The path is absent or hidden in this context. This is not evidence of a missing privacy grant."
    default: classification = "unverified"; explanation = "The open failed. The error does not establish a privacy cause."
    }
    return ["path": path, "operation": "open-readonly-no-content", "errno": code, "error": String(cString: strerror(code)),
            "classification": classification, "explanation": explanation, "ancestry": ancestry(getpid()), "time": Date().timeIntervalSince1970]
}
