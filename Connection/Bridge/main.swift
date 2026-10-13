import Foundation
import Network
import AppKit
import Security
import Darwin

signal(SIGPIPE, SIG_IGN)
umask(0o077)
let args = CommandLine.arguments
func option(_ key: String) -> String? { guard let index = args.firstIndex(of: key), index + 1 < args.count else { return nil }; return args[index + 1] }

final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
final class Bridge {
    let listener: NWListener
    let queue = DispatchQueue(label: "dev.macpermissions.bridge")
    let helper: URL
    let hosts: Set<String>
    let session: URLSession
    let redirects = NoRedirect()
    let config: [String: Any]
    var active = 0
    init(path: String) throws {
        config = try privateJSON(path)
        guard config["version"] as? Int == 1, let bind = config["bind"] as? String, let address = IPv4Address(bind),
              let port = config["port"] as? Int, (1025...65535).contains(port),
              let helperPort = config["helperPort"] as? Int, (1025...65535).contains(helperPort),
              let identityPath = config["identityPath"] as? String, let password = config["identityPassword"] as? String,
              let names = config["hosts"] as? [String], !names.isEmpty else { try connectionFail("Invalid bridge configuration") }
        helper = URL(string: "http://127.0.0.1:\(helperPort)")!; hosts = Set(names.map { $0.lowercased() })
        let identityData = try privateData(identityPath)
        var imported: CFArray?
        let options: [String: Any] = [kSecImportExportPassphrase as String: password, kSecImportToMemoryOnly as String: true]
        let result = SecPKCS12Import(identityData as CFData, options as CFDictionary, &imported)
        guard result == errSecSuccess, let items = imported as? [[String: Any]], let item = items.first,
              let raw = item[kSecImportItemIdentity as String], CFGetTypeID(raw as CFTypeRef) == SecIdentityGetTypeID(),
              let tlsIdentity = sec_identity_create(raw as! SecIdentity) else { try connectionFail("Cannot import TLS identity into memory, OSStatus \(result)") }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, tlsIdentity)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        let parameters = NWParameters(tls: tls, tcp: .init())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(address), port: NWEndpoint.Port(rawValue: UInt16(port))!)
        listener = try NWListener(using: parameters)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]; configuration.httpCookieStorage = nil; configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 10; configuration.timeoutIntervalForResource = 12
        session = URLSession(configuration: configuration, delegate: redirects, delegateQueue: nil)
        listener.newConnectionHandler = { [self] connection in
            guard active < 64 else { connection.cancel(); return }; active += 1
            connection.stateUpdateHandler = { [self] state in if case .cancelled = state { active -= 1 } }
            connection.start(queue: queue)
            let reader = IncomingConnection(connection) { [self] request, reply in forward(request, reply: reply) }
            reader.readNext(); queue.asyncAfter(deadline: .now() + 15) { connection.cancel() }
        }
        listener.stateUpdateHandler = { state in
            if case .failed(let error) = state { fputs("TLS bridge failed: \(error)\n", stderr); exit(1) }
        }
    }
    func forward(_ request: IncomingRequest, reply: @escaping (Int, Data) -> Void) {
        func reject(_ status: Int, _ text: String) { reply(status, (try? encodedJSON(["error": text])) ?? Data()) }
        guard request.headers["origin"] == nil else { reject(403, "Connect with the native controller, not a browser"); return }
        guard let host = request.headers["host"]?.lowercased(), let components = URLComponents(string: "https://" + host),
              let name = components.host, hosts.contains(name), components.user == nil, components.password == nil,
              components.port == config["port"] as? Int, components.path.isEmpty else { reject(403, "Unexpected destination Host"); return }
        guard let authorization = request.headers["authorization"], authorization.hasPrefix("Bearer "),
              authorization.count == 71, authorization.dropFirst(7).allSatisfy({ $0.isHexDigit }) else { reject(401, "Authentication required"); return }
        guard let target = URLComponents(string: request.target), target.scheme == nil, target.host == nil, target.fragment == nil,
              target.path.hasPrefix("/v1/"), ["/v1/status", "/v1/requests", "/v1/reports"].contains(target.path) || target.path.range(of: "^/v1/requests/[a-f0-9-]{36}(/(approve|deny|retry|cancel|resize|input|events))?$", options: .regularExpression) != nil,
              let url = URL(string: helper.absoluteString + request.target), url.host == "127.0.0.1", url.port == helper.port else { reject(404, "Unsupported helper route"); return }
        var upstream = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        upstream.httpMethod = request.method; upstream.httpBody = request.body.isEmpty ? nil : request.body
        upstream.setValue(authorization, forHTTPHeaderField: "Authorization"); upstream.setValue("application/json", forHTTPHeaderField: "Content-Type")
        session.dataTask(with: upstream) { data, response, error in
            guard error == nil, let response = response as? HTTPURLResponse, let data, data.count <= 8 * 1024 * 1024 else {
                reject(503, "The mini helper is unavailable. Start its app through LaunchServices; the bridge does not grant privacy access."); return
            }
            guard response.statusCode < 300 || response.statusCode >= 400 else { reject(502, "Helper redirects are refused"); return }
            reply(response.statusCode, data)
        }.resume()
    }
    func start() { listener.start(queue: queue) }
}

do {
    let savedConfig = URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support/MacPermissionsBridge/bridge.json")
    let configPath = option("--config") ?? savedConfig.path
    let application = NSApplication.shared
    application.setActivationPolicy(args.contains("--headless") ? .prohibited : .accessory)
    let bridge = try Bridge(path: configPath); bridge.start()
    if option("--config") != nil && !args.contains("--headless") {
        try FileManager.default.createDirectory(at: savedConfig.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try privateData(configPath).write(to: savedConfig, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: savedConfig.path)
    }
    print("TLS bridge listening on \(bridge.config["bind"]!):\(bridge.config["port"]!).")
    var window: NSWindow?
    if !args.contains("--headless") {
        let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 300), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Mac Permissions connection"
        let label = NSTextField(wrappingLabelWithString: "Encrypted connection is running on \(bridge.config["bind"]!):\(bridge.config["port"]!).\n\nCopy the private connection file to your MacBook using AirDrop or your existing secure transfer. Open it in Mac Permissions.\n\nThis bridge forwards authenticated requests to the existing helper. The helper keeps its own FDA execution context. No SSH or session manager replacement is required.\n\nQuit this app to stop accepting connections.")
        label.frame = NSRect(x: 24, y: 68, width: 512, height: 210); panel.contentView?.addSubview(label)
        let stop = NSButton(title: "Stop connections", target: application, action: #selector(NSApplication.terminate(_:)))
        stop.frame = NSRect(x: 24, y: 20, width: 180, height: 32); panel.contentView?.addSubview(stop)
        panel.center(); panel.makeKeyAndOrderFront(nil); window = panel
    }
    withExtendedLifetime((bridge, window)) { application.run() }
} catch { fputs("\(error)\n", stderr); exit(1) }
