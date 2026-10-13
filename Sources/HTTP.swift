import Foundation
import Network

final class HTTPServer {
    let core: Core
    let listener: NWListener
    let queue = DispatchQueue(label: "dev.macpermissions.http")
    init(core: Core) throws {
        self.core = core
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: UInt16(core.port))!)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [self] connection in
            connection.start(queue: queue)
            let reader = HTTPRequestReader(connection: connection, server: self)
            reader.receive()
            queue.asyncAfter(deadline: .now() + 15) { connection.cancel() }
        }
        listener.stateUpdateHandler = { state in
            if case .failed(let error) = state { fputs("Listener failed: \(error)\n", stderr); exit(1) }
        }
    }
    func start() { listener.start(queue: queue) }
    func dispatch(method: String, target: String, headers: [String: String], data: Data, reply: @escaping (Int, [String: Any]) -> Void) {
        guard headers["origin"] == nil else { reply(403, ["error": "Browser connections to the helper are disabled. Use the local controller."]); return }
        guard let host = headers["host"], host.range(of: "^(127\\.0\\.0\\.1|localhost)(:[0-9]+)?$", options: .regularExpression) != nil else { reply(403, ["error": "Loopback Host required"]); return }
        guard let auth = headers["authorization"], auth.hasPrefix("Bearer "), let role = core.role(String(auth.dropFirst(7))) else { reply(401, ["error": "Authentication required"]); return }
        guard let components = URLComponents(string: target), components.scheme == nil, components.host == nil else { reply(400, ["error": "Invalid target"]); return }
        var query: [String: String] = [:]
        for item in components.queryItems ?? [] { query[item.name] = item.value }
        let body: [String: Any]
        do { body = data.isEmpty ? [:] : (try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]) }
        catch { reply(400, ["error": "JSON object required"]); return }
        let path = components.path
        DispatchQueue.global().async { [self] in
            do {
                // Input can block behind a slow tool. Keep it outside the serialized approval queue.
                if method == "POST", path.hasSuffix("/input") {
                    let parts = path.split(separator: "/")
                    guard parts.count == 4, parts[0] == "v1", parts[1] == "requests",
                          let session = core.queue.sync(execute: { core.sessions[String(parts[2])] }) else { try fail("Unknown session") }
                    guard let encoded = body["data"] as? String, let input = Data(base64Encoded: encoded), input.count <= 65536 else { try fail("Invalid input") }
                    try session.writeInput(input, eof: body["eof"] as? Bool ?? false); reply(200, ["ok": true]); return
                }
                let result = try core.queue.sync { try core.handle(method: method, path: path, query: query, body: body, role: role) }
                reply(200, result)
            } catch { reply(409, ["error": String(describing: error)]) }
        }
    }
}
final class HTTPRequestReader {
    let connection: NWConnection
    let server: HTTPServer
    var buffer = Data()
    var finished = false
    init(connection: NWConnection, server: HTTPServer) { self.connection = connection; self.server = server }
    func respond(_ status: Int, _ value: [String: Any]) {
        let body = (try? jsonData(value)) ?? Data("{}".utf8)
        let header = Data("HTTP/1.1 \(status) Response\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n".utf8)
        connection.send(content: header + body, completion: .contentProcessed { [self] _ in connection.cancel() })
    }
    func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] bytes, _, complete, error in
            if let bytes { buffer.append(bytes) }
            if buffer.count > 512 * 1024 { respond(413, ["error": "Request too large"]); return }
            if let range = buffer.range(of: Data("\r\n\r\n".utf8)) {
                guard range.lowerBound < 16384, let header = String(data: buffer[..<range.lowerBound], encoding: .utf8) else { respond(400, ["error": "Invalid headers"]); return }
                let lines = header.components(separatedBy: "\r\n"), first = lines[0].split(separator: " ")
                guard first.count == 3, first[2] == "HTTP/1.1", ["GET", "POST"].contains(String(first[0])) else { respond(400, ["error": "Unsupported HTTP request"]); return }
                var headers: [String: String] = [:]
                for line in lines.dropFirst() {
                    guard let colon = line.firstIndex(of: ":") else { respond(400, ["error": "Invalid header"]); return }
                    let key = line[..<colon].lowercased()
                    guard headers[key] == nil else { respond(400, ["error": "Duplicate header"]); return }
                    headers[key] = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                }
                guard headers["transfer-encoding"] == nil, let length = Int(headers["content-length"] ?? "0"), length >= 0, length <= 500000 else { respond(400, ["error": "Invalid body length"]); return }
                let start = range.upperBound
                if buffer.count >= start + length {
                    guard buffer.count == start + length else { respond(400, ["error": "Pipelining unsupported"]); return }
                    finished = true
                    server.dispatch(method: String(first[0]), target: String(first[1]), headers: headers, data: Data(buffer[start...])) { [self] status, value in respond(status, value) }; return
                }
            }
            if complete || error != nil { connection.cancel(); return }
            receive()
        }
    }
}
