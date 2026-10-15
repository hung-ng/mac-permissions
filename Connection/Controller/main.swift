import Foundation
import AppKit
import WebKit
import UniformTypeIdentifiers
import Darwin

umask(0o077)
let args = CommandLine.arguments
func option(_ key: String) -> String? { guard let index = args.firstIndex(of: key), index + 1 < args.count else { return nil }; return args[index + 1] }

final class Controller: NSObject, NSApplicationDelegate, WKScriptMessageHandlerWithReply, WKNavigationDelegate {
    var client: PinnedClient?
    var window: NSWindow!
    var web: WKWebView!
    var caption: NSTextField!
    var connected = false
    var pendingProfile: String?
    let saved = URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support/MacPermissionsController/connection.macpermissions")
    func applicationDidFinishLaunching(_ notification: Notification) {
        let configuration = WKWebViewConfiguration()
        configuration.userContentController.addScriptMessageHandler(self, contentWorld: .page, name: "nativeAPI")
        configuration.userContentController.addUserScript(WKUserScript(source: "window.nativeController=true;", injectionTime: .atDocumentStart, forMainFrameOnly: true))
        web = WKWebView(frame: .zero, configuration: configuration); web.navigationDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1060, height: 800), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Mac Permissions"
        window.minSize = NSSize(width: 550, height: 450)
        let root = NSView(); window.contentView = root
        let button = NSButton(title: "Open connection file…", target: self, action: #selector(chooseProfile))
        button.translatesAutoresizingMaskIntoConstraints = false
        caption = NSTextField(labelWithString: "Import the private connection file exported by your Mac mini.")
        caption.lineBreakMode = .byTruncatingMiddle; caption.translatesAutoresizingMaskIntoConstraints = false
        web.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(button); root.addSubview(caption); root.addSubview(web)
        NSLayoutConstraint.activate([
            button.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16), button.topAnchor.constraint(equalTo: root.topAnchor, constant: 12),
            caption.leadingAnchor.constraint(equalTo: button.trailingAnchor, constant: 16), caption.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16), caption.centerYAnchor.constraint(equalTo: button.centerYAnchor),
            web.leadingAnchor.constraint(equalTo: root.leadingAnchor), web.trailingAnchor.constraint(equalTo: root.trailingAnchor), web.topAnchor.constraint(equalTo: button.bottomAnchor, constant: 12), web.bottomAnchor.constraint(equalTo: root.bottomAnchor)
        ])
        let menu = NSMenu(), appMenu = NSMenu(), item = NSMenuItem()
        appMenu.addItem(withTitle: "Open connection file…", action: #selector(chooseProfile), keyEquivalent: "o").target = self
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Quit Mac Permissions", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(item); menu.setSubmenu(appMenu, for: item); NSApplication.shared.mainMenu = menu
        window.center(); window.makeKeyAndOrderFront(nil)
        if !args.contains("--smoke") { NSApplication.shared.activate(ignoringOtherApps: true) }
        do {
            if let path = option("--profile") ?? pendingProfile { try importProfile(path, persist: !args.contains("--smoke")) }
            else if FileManager.default.fileExists(atPath: saved.path) { try importProfile(saved.path, persist: false) }
            else { showSetup("Open the private connection file from your mini. Tailscale must be connected on both Macs.") }
        } catch { showSetup(String(describing: error)) }
        if args.contains("--smoke") { DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [self] in smoke() } }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        guard let first = filenames.first else { return }
        // AppKit can deliver document events before applicationDidFinishLaunching.
        guard web != nil, caption != nil else { pendingProfile = first; sender.reply(toOpenOrPrint: .success); return }
        do { try importProfile(first, persist: !args.contains("--smoke")); sender.reply(toOpenOrPrint: .success) }
        catch { showSetup(String(describing: error)); sender.reply(toOpenOrPrint: .failure) }
    }
    @objc func chooseProfile() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.message = "Choose the private connection file exported on your Mac mini. It contains an owner credential."
        panel.allowedContentTypes = [UTType(filenameExtension: "macpermissions") ?? .json, .json]
        panel.beginSheetModal(for: window) { [self] response in
            guard response == .OK, let url = panel.url else { return }
            do { try importProfile(url.path, persist: true) } catch { showSetup(String(describing: error)) }
        }
    }
    func showSetup(_ text: String) {
        connected = false; caption?.stringValue = text
        let page = "<!doctype html><html><meta name='viewport' content='width=device-width'><style>body{font:17px system-ui;background:#141819;color:#edf0e9;padding:48px;line-height:1.7}h1{font-size:32px}p{max-width:650px}</style><h1>Connect to your Mac mini</h1><p>Use Open connection file to import the private file from the mini. The app verifies the mini's TLS certificate and the approved helper binary before it allows actions.</p><p>Keep Tailscale connected on both Macs. You do not need Python, SSH, or Full Disk Access on this MacBook.</p></html>"
        web?.loadHTMLString(page, baseURL: nil)
    }
    func importProfile(_ path: String, persist: Bool) throws {
        if persist { try makeImportedFilePrivate(path) }
        let profile = try ConnectionProfile(path: path)
        let newClient = PinnedClient(profile: profile)
        client?.close(); client = newClient; connected = false
        if persist {
            let parent = saved.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let data = try privateData(path)
            try data.write(to: saved, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: saved.path)
        }
        caption.stringValue = "\(profile.name) · \(profile.endpoint.absoluteString) · certificate \(profile.certificateSHA256.prefix(12))"
        guard let html = Bundle.main.url(forResource: "controller", withExtension: "html") else { try connectionFail("Missing controller interface") }
        web.loadHTMLString(try String(contentsOf: html, encoding: .utf8), baseURL: nil)
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // The native API bridge is available only to our own static page.
        let url = navigationAction.request.url
        decisionHandler(url == nil || url?.absoluteString == "about:blank" ? .allow : .cancel)
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage,
                               replyHandler: @escaping (Any?, String?) -> Void) {
        guard message.frameInfo.isMainFrame, message.webView === web, let value = message.body as? [String: Any], let path = value["path"] as? String,
              let client else { replyHandler(nil, "Import a mini connection file first"); return }
        let finish: (Result<[String: Any], Error>) -> Void = { result in
            DispatchQueue.main.async { switch result { case .success(let data): replyHandler(data, nil); case .failure(let error): replyHandler(nil, String(describing: error)) } }
        }
        if path == "status" {
            client.check { [weak self] result in
                DispatchQueue.main.async {
                    guard let self, self.client === client else { finish(.failure(ConnectionFailure.message("Connection file changed. Verify the new mini first."))); return }
                    switch result {
                    case .failure(let error): self.connected = false; finish(.failure(error))
                    case .success(let data): self.connected = true; finish(.success(data["helper"] as! [String: Any]))
                    }
                }
            }; return
        }
        guard connected else { replyHandler(nil, "Verify the mini connection before using actions"); return }
        if path == "requests", value["body"] == nil { client.call("GET", "/v1/requests", completion: finish); return }
        if path == "probe" {
            client.call("GET", "/v1/status") { result in
                switch result {
                case .failure(let error): finish(.failure(error))
                case .success(let status):
                    guard let path = status["suggestedProbePath"] as? String else { finish(.failure(ConnectionFailure.message("Missing remote probe path"))); return }
                    client.call("POST", "/v1/requests", body: ["operation": "probe", "path": path], completion: finish)
                }
            }; return
        }
        guard path == "action", let body = value["body"] as? [String: Any], let id = body["id"] as? String, UUID(uuidString: id) != nil,
              let action = body["action"] as? String, ["approve", "deny", "retry", "cancel"].contains(action), let fingerprint = body["fingerprint"] as? String else {
            replyHandler(nil, "Unsupported controller action"); return
        }
        // Recheck the paired helper before sending an approval. Never repeat a mutation automatically.
        client.call("GET", "/v1/status") { result in
            switch result {
            case .failure(let error): finish(.failure(error))
            case .success: client.call("POST", "/v1/requests/\(id.lowercased())/\(action)", body: ["fingerprint": fingerprint], completion: finish)
            }
        }
    }
    func smoke() {
        if let id = option("--approve-test-request") {
            guard UUID(uuidString: id) != nil else { exit(1) }
            web.callAsyncJavaScript("const r=(await api('requests')).requests.find(r=>r.id===id);if(!r||r.spec.operation!=='probe')throw Error('Only a harmless test probe can be approved in smoke mode');await api('action',{id:r.id,fingerprint:r.fingerprint,action:'approve'});await refresh();return true;", arguments: ["id": id.lowercased()], in: nil, in: .page) { [self] result in
                if case .failure(let error) = result { fputs("Native UI approval failed: \(error)\n", stderr); exit(1) }
                snapshotSmoke()
            }; return
        }
        snapshotSmoke()
    }
    func snapshotSmoke() {
        web.evaluateJavaScript("({connected:document.querySelector('#connection')?.textContent,error:document.querySelector('#error')?.textContent,requests:document.querySelectorAll('article').length,ready:document.readyState,native:window.nativeController===true})") { [self] value, error in
            if let error { fputs("Native UI smoke failed: \(error)\n", stderr); exit(1) }
            if let data = value as? [String: Any], let bytes = try? encodedJSON(data) { print(String(decoding: bytes, as: UTF8.self)) }
            guard let output = option("--snapshot") else { exit(connected ? 0 : 1) }
            web.takeSnapshot(with: nil) { [self] image, error in
                guard error == nil, let image, let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff), let png = rep.representation(using: .png, properties: [:]) else {
                    fputs("Native snapshot failed\n", stderr); exit(1)
                }
                do { try png.write(to: URL(fileURLWithPath: output)); exit(connected ? 0 : 1) }
                catch { fputs("\(error)\n", stderr); exit(1) }
            }
        }
    }
}

func headlessApprove(profilePath: String, requestID: String) -> Never {
    guard let uuid = UUID(uuidString: requestID) else {
        fputs("The test request ID is not a UUID\n", stderr); exit(1)
    }
    do {
        let client = PinnedClient(profile: try ConnectionProfile(path: profilePath))
        let group = DispatchSemaphore(value: 0)
        var code: Int32 = 1
        func finish(_ result: Result<[String: Any], Error>) {
            switch result {
            case .failure(let error): fputs("\(error)\n", stderr)
            case .success(let value):
                guard let bytes = try? encodedJSON(value) else { fputs("Cannot encode approval result\n", stderr); break }
                print(String(decoding: bytes, as: UTF8.self)); code = 0
            }
            group.signal()
        }
        client.check { checkResult in
            switch checkResult {
            case .failure(let error): finish(.failure(error))
            case .success:
                client.call("GET", "/v1/requests") { result in
                    switch result {
                    case .failure(let error): finish(.failure(error))
                    case .success(let value):
                        guard let requests = value["requests"] as? [[String: Any]],
                              let request = requests.first(where: { ($0["id"] as? String) == uuid.uuidString.lowercased() }),
                              request["state"] as? String == "pending",
                              let spec = request["spec"] as? [String: Any], spec["operation"] as? String == "probe",
                              let fingerprint = request["fingerprint"] as? String else {
                            finish(.failure(ConnectionFailure.message("Only a pending harmless probe can be approved by this test command"))); return
                        }
                        client.call("POST", "/v1/requests/\(uuid.uuidString.lowercased())/approve", body: ["fingerprint": fingerprint], completion: finish)
                    }
                }
            }
        }
        guard group.wait(timeout: .now() + 25) == .success else {
            fputs("Native approval timed out\n", stderr); client.close(); exit(1)
        }
        client.close(); exit(code)
    } catch {
        fputs("\(error)\n", stderr); exit(1)
    }
}

if !args.contains("--smoke"), let requestID = option("--approve-test-request") {
    guard let profilePath = option("--profile") else { fputs("--profile is required\n", stderr); exit(1) }
    headlessApprove(profilePath: profilePath, requestID: requestID)
}

if args.contains("--check") {
    do {
        guard let path = option("--profile") else { try connectionFail("--profile is required") }
        let client = PinnedClient(profile: try ConnectionProfile(path: path)), group = DispatchSemaphore(value: 0)
        var code: Int32 = 1
        client.check { result in
            switch result {
            case .success(let data): if let bytes = try? encodedJSON(data) { print(String(decoding: bytes, as: UTF8.self)); code = 0 }
            case .failure(let error): fputs("\(error)\n", stderr)
            }; group.signal()
        }
        guard group.wait(timeout: .now() + 25) == .success else { fputs("Connection check timed out\n", stderr); exit(1) }
        client.close(); exit(code)
    } catch { fputs("\(error)\n", stderr); exit(1) }
}
let application = NSApplication.shared
application.setActivationPolicy(args.contains("--smoke") ? .prohibited : .regular)
let delegate = Controller(); application.delegate = delegate
withExtendedLifetime(delegate) { application.run() }
