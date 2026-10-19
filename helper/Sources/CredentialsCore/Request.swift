import Foundation

public struct HTTPRequest: Codable, Sendable {
  public var method: String
  public var url: String
  public var headers: [String: String]?
  public var body: String?
  public var authHeader: String?
  public var authPrefix: String?
}

public struct HTTPResponse: Codable, Sendable {
  public var status: Int
  public var contentType: String?
  public var body: String
  public var isTruncated: Bool
  public var redacted: [String]
  public var unavailable: [String]
}

final class RedirectRefusal: NSObject, URLSessionTaskDelegate, Sendable {
  func urlSession(
    _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest
  ) async -> URLRequest? {
    nil
  }
}

public enum Requester {
  public static let bodyLimit = 1_000_000

  static func isAllowed(host: String, patterns: [String]) -> Bool {
    patterns.isEmpty
      || patterns.map { $0.lowercased() }.contains { pattern in
        if pattern.hasPrefix("*.") {
          let parent = String(pattern.dropFirst(2))
          return host == parent || host.hasSuffix("." + parent)
        }
        return host == pattern
      }
  }

  public static func validate(_ request: HTTPRequest, credential: Credential) throws -> URL {
    guard let url = URL(string: request.url), url.scheme?.lowercased() == "https",
      let host = url.host?.lowercased()
    else {
      throw CredentialError("invalid-url", "Use an absolute https URL.")
    }
    guard isAllowed(host: host, patterns: credential.hosts) else {
      throw CredentialError(
        "host-not-allowed",
        "This credential may only reach: \(credential.hosts.joined(separator: ", ")).")
    }
    return url
  }

  public static func send(
    _ request: HTTPRequest, credential: Credential, value: String, redactor: Redactor,
    unavailable: [String]
  ) async throws -> HTTPResponse {
    let url = try validate(request, credential: credential)
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = request.method.uppercased()
    urlRequest.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    urlRequest.httpShouldHandleCookies = false
    for (field, text) in request.headers ?? [:] {
      urlRequest.setValue(text, forHTTPHeaderField: field)
    }
    let prefix = request.authPrefix ?? "Bearer "
    urlRequest.setValue(prefix + value, forHTTPHeaderField: request.authHeader ?? "Authorization")
    if let body = request.body { urlRequest.httpBody = Data(body.utf8) }
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.httpCookieStorage = nil
    configuration.urlCredentialStorage = nil
    let session = URLSession(configuration: configuration)
    defer { session.invalidateAndCancel() }
    let (data, response) = try await session.data(for: urlRequest, delegate: RedirectRefusal())
    let http = response as? HTTPURLResponse
    let redaction = redactor.redact(String(decoding: data, as: UTF8.self))
    let utf8 = Array(redaction.text.utf8)
    let isTruncated = utf8.count > bodyLimit
    let contentType = http?.value(forHTTPHeaderField: "Content-Type").map { redactor.redact($0).text }
    return HTTPResponse(
      status: http?.statusCode ?? 0, contentType: contentType,
      body: isTruncated ? String(decoding: utf8.prefix(bodyLimit), as: UTF8.self) : redaction.text,
      isTruncated: isTruncated, redacted: redaction.names, unavailable: unavailable)
  }
}
