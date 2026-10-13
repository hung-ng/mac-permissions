import Foundation
import Network

struct IncomingRequest {
    let method: String
    let target: String
    let headers: [String: String]
    let body: Data
}
final class IncomingConnection {
    let connection: NWConnection
    var buffer = Data()
    var answered = false
    let handler: (IncomingRequest, @escaping (Int, Data) -> Void) -> Void
    init(_ connection: NWConnection, handler: @escaping (IncomingRequest, @escaping (Int, Data) -> Void) -> Void) {
        self.connection = connection; self.handler = handler
    }
    func answer(_ status: Int, _ data: Data) {
        let header = Data("HTTP/1.1 \(status) Response\r\nContent-Type: application/json\r\nContent-Length: \(data.count)\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".utf8)
        connection.send(content: header + data, completion: .contentProcessed { [self] _ in connection.cancel() })
    }
    func reject(_ status: Int, _ reason: String) { answer(status, (try? encodedJSON(["error": reason])) ?? Data()) }
    func readNext() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] bytes, _, complete, error in
            if let bytes { buffer.append(bytes) }
            guard buffer.count <= 512 * 1024 else { reject(413, "Request too large"); return }
            if let split = buffer.range(of: Data("\r\n\r\n".utf8)) {
                guard split.lowerBound < 16384, let text = String(data: buffer[..<split.lowerBound], encoding: .utf8) else { reject(400, "Invalid headers"); return }
                let lines = text.components(separatedBy: "\r\n"), first = lines[0].split(separator: " ")
                guard first.count == 3, first[2] == "HTTP/1.1", ["GET", "POST"].contains(String(first[0])) else { reject(400, "Unsupported request"); return }
                var headers: [String: String] = [:]
                for line in lines.dropFirst() {
                    guard let colon = line.firstIndex(of: ":") else { reject(400, "Invalid header"); return }
                    let key = line[..<colon].lowercased()
                    guard headers[key] == nil else { reject(400, "Duplicate header"); return }
                    headers[key] = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                }
                guard headers["transfer-encoding"] == nil, let length = Int(headers["content-length"] ?? "0"), length >= 0, length <= 500000 else { reject(400, "Invalid body length"); return }
                let bodyStart = split.upperBound
                if buffer.count >= bodyStart + length {
                    guard buffer.count == bodyStart + length else { reject(400, "Pipelining is disabled"); return }
                    answered = true
                    handler(IncomingRequest(method: String(first[0]), target: String(first[1]), headers: headers, body: Data(buffer[bodyStart...]))) { [self] status, data in answer(status, data) }; return
                }
            } else if buffer.count > 16384 { reject(400, "Headers too large"); return }
            if complete || error != nil { connection.cancel(); return }
            readNext()
        }
    }
}
