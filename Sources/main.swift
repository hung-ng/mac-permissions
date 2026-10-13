import Foundation
import AppKit
import Darwin

signal(SIGPIPE, SIG_IGN)
umask(0o077)
let args = CommandLine.arguments
func option(_ key: String) -> String? {
    guard let index = args.firstIndex(of: key), index + 1 < args.count else { return nil }; return args[index + 1]
}
let state = URL(fileURLWithPath: option("--state-dir") ?? NSHomeDirectory() + "/Library/Application Support/MacPermissions")
let port = Int(option("--port") ?? "43187") ?? 0
guard port > 1024, port <= 65535 else { fputs("Invalid port\n", stderr); exit(64) }
do {
    let app = NSApplication.shared
    app.setActivationPolicy(args.contains("--headless") ? .prohibited : .accessory)
    let core = try Core(state: state, port: port)
    let server = try HTTPServer(core: core)
    server.start()
    let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    signal(SIGTERM, SIG_IGN)
    termination.setEventHandler {
        core.queue.sync { core.sessions.values.forEach { $0.cancel() } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { exit(0) }
    }
    termination.resume()
    print("Mac Permissions helper listening on 127.0.0.1:\(port). Credentials are in \(state.path).")
    var window: NSWindow?
    if !args.contains("--headless") {
        let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 580, height: 330), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Mac Permissions helper"
        let text = NSTextField(wrappingLabelWithString: "The helper is running on this Mac.\n\nInitial Full Disk Access requires the owner here, in System Settings → Privacy & Security → Full Disk Access. Add this app and enable it. Restart the helper if macOS asks.\n\nApprovals in your local controller authorize specific operations. They do not grant macOS privacy consent. App Management remains unverified until a real protected update or delete succeeds.\n\nController connection: 127.0.0.1:\(port) through your existing authenticated connection.")
        text.frame = NSRect(x: 24, y: 86, width: 532, height: 222); panel.contentView?.addSubview(text)
        let fda = NSButton(title: "Open Full Disk Access", target: nil, action: nil)
        fda.frame = NSRect(x: 24, y: 28, width: 220, height: 32)
        let reveal = NSButton(title: "Show this app in Finder", target: nil, action: nil)
        reveal.frame = NSRect(x: 260, y: 28, width: 240, height: 32)
        class Actions: NSObject {
            @objc func settings() { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!) }
            @objc func reveal() { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }
        }
        let actions = Actions()
        fda.target = actions; fda.action = #selector(Actions.settings)
        reveal.target = actions; reveal.action = #selector(Actions.reveal)
        panel.contentView?.addSubview(fda); panel.contentView?.addSubview(reveal)
        panel.center(); panel.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps: true); window = panel
        withExtendedLifetime((server, core, window, actions, termination)) { app.run() }
    } else { withExtendedLifetime((server, core, termination)) { app.run() } }
} catch { fputs("\(error)\n", stderr); exit(1) }
