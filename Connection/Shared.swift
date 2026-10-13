import Foundation
import Security
import CryptoKit
import Darwin

enum ConnectionFailure: Error, CustomStringConvertible {
    case message(String)
    var description: String { switch self { case .message(let value): return value } }
}
func connectionFail(_ text: String) throws -> Never { throw ConnectionFailure.message(text) }
func encodedJSON(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

func privateData(_ path: String, maximum: Int = 65536) throws -> Data {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { try connectionFail("Cannot open private connection file: \(String(cString: strerror(errno)))") }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(), info.st_mode & 0o077 == 0,
          info.st_size > 0, info.st_size <= maximum else { try connectionFail("Connection files must belong to you, be mode 0600, and be at most \(maximum) bytes") }
    var data = Data(), buffer = [UInt8](repeating: 0, count: 8192)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count < 0 && errno == EINTR { continue }
        guard count >= 0 else { try connectionFail("Cannot read connection file") }
        if count == 0 { break }; data.append(contentsOf: buffer.prefix(count))
        guard data.count <= maximum else { try connectionFail("Connection file is too large") }
    }
    return data
}
func privateJSON(_ path: String) throws -> [String: Any] {
    guard let value = try JSONSerialization.jsonObject(with: privateData(path)) as? [String: Any] else { try connectionFail("JSON object required") }
    return value
}
func makeImportedFilePrivate(_ path: String) throws {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { try connectionFail("Cannot open the selected connection file") }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(), info.st_size <= 65536 else {
        try connectionFail("Choose a regular connection file that belongs to you")
    }
    guard fchmod(fd, 0o600) == 0 else { try connectionFail("Cannot make the selected connection file private") }
}

struct ConnectionProfile {
    let endpoint: URL
    let token: String
    let certificate: SecCertificate
    let certificateSHA256: String
    let helperSHA256: String
    let name: String
    let profileID: String
    init(path: String) throws {
        let value = try privateJSON(path)
        guard value["version"] as? Int == 1, let text = value["endpoint"] as? String,
              let url = URL(string: text), let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "https", components.host != nil, components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil, ["", "/"].contains(components.path),
              let token = value["ownerToken"] as? String, token.count == 64, token.allSatisfy({ $0.isHexDigit }),
              let certificateText = value["certificateDER"] as? String, let der = Data(base64Encoded: certificateText),
              let certificate = SecCertificateCreateWithData(nil, der as CFData), let fingerprint = value["certificateSHA256"] as? String,
              sha256(der) == fingerprint, let helper = value["helperSHA256"] as? String, helper.count == 64,
              let id = value["profileID"] as? String, UUID(uuidString: id) != nil else { try connectionFail("Invalid connection profile. Export a new one on the mini.") }
        endpoint = url; self.token = token; self.certificate = certificate; certificateSHA256 = fingerprint
        helperSHA256 = helper; name = value["name"] as? String ?? components.host!; profileID = id
    }
}

final class PinnedClient: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    let profile: ConnectionProfile
    lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.httpCookieStorage = nil; configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 7; configuration.timeoutIntervalForResource = 10
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()
    init(profile: ConnectionProfile) { self.profile = profile }
    func close() { session.invalidateAndCancel() }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust, let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first, sha256(SecCertificateCopyData(leaf) as Data) == profile.certificateSHA256,
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [profile.certificate] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess, SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func call(_ method: String, _ path: String, body: [String: Any]? = nil,
              completion: @escaping (Result<[String: Any], Error>) -> Void) {
        guard path.hasPrefix("/v1/"), !path.contains("#"), !path.contains("\r"), !path.contains("\n"),
              let url = URL(string: profile.endpoint.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path),
              url.host == profile.endpoint.host, url.port == profile.endpoint.port, url.scheme == "https" else {
            completion(.failure(ConnectionFailure.message("Invalid API route"))); return
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        request.httpMethod = method; request.setValue("Bearer " + profile.token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body { do { request.httpBody = try encodedJSON(body) } catch { completion(.failure(error)); return } }
        session.dataTask(with: request) { data, response, error in
            if let error { completion(.failure(ConnectionFailure.message("Connection failed: \(error.localizedDescription). Check Tailscale, the mini bridge, and the certificate profile."))); return }
            guard let response = response as? HTTPURLResponse, let data, data.count <= 8 * 1024 * 1024,
                  let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { completion(.failure(ConnectionFailure.message("Invalid server response"))); return }
            guard response.statusCode == 200 else { completion(.failure(ConnectionFailure.message(value["error"] as? String ?? "Request rejected, HTTP \(response.statusCode)"))); return }
            if path == "/v1/status" {
                guard let helper = value["helper"] as? [String: Any], helper["sha256"] as? String == self.profile.helperSHA256 else {
                    completion(.failure(ConnectionFailure.message("The helper binary changed. Review the update and export a new connection file on the mini."))); return
                }
            }
            completion(.success(value))
        }.resume()
    }
    func check(completion: @escaping (Result<[String: Any], Error>) -> Void) {
        call("GET", "/v1/status") { result in
            switch result {
            case .failure: completion(result)
            case .success(let status):
                self.call("GET", "/v1/requests") { owner in
                    switch owner {
                    case .failure(let error): completion(.failure(ConnectionFailure.message("Owner view unavailable: \(error). Export an owner connection file from the mini.")))
                    case .success(let requests):
                        completion(.success(["connected": true, "endpoint": self.profile.endpoint.absoluteString,
                            "certificateSHA256": self.profile.certificateSHA256, "helper": status,
                            "requestCount": (requests["requests"] as? [Any])?.count ?? 0]))
                    }
                }
            }
        }
    }
}
