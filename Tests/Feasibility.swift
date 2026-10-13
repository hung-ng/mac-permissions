import Foundation
import AppKit
import Darwin

let args = CommandLine.arguments
guard args.count == 5 else { exit(64) }
let fixture = args[1], probe = args[2], output = args[3], mode = args[4]
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let fd = open(fixture, O_RDONLY | O_NOFOLLOW)
let code = fd < 0 ? errno : 0
if fd >= 0 { close(fd) }
let child = Process()
child.executableURL = URL(fileURLWithPath: probe)
child.arguments = [fixture]
let pipe = Pipe()
child.standardOutput = pipe
do {
    try child.run()
    let result = pipe.fileHandleForReading.readDataToEndOfFile()
    child.waitUntilExit()
    let report: [String: Any] = ["mode": mode, "helperPID": getpid(), "helperPPID": getppid(),
        "helperOpenErrno": code, "child": String(data: result, encoding: .utf8) ?? "", "childExit": child.terminationStatus,
        "bundle": Bundle.main.bundleIdentifier ?? "none"]
    let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
    try data.write(to: URL(fileURLWithPath: output), options: .atomic)
} catch { fputs("\(error)\n", stderr); exit(1) }
