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

  public static func validate(_ request: HTTPRequest, credential: Credential) throws -> URL {
    guard let url = URL(string: request.url), url.scheme?.lowercased() == "https",
      let host = url.host?.lowercased()
    else {
      throw CredentialError("invalid-url", "Use an absolute https URL.")
    }
    let hosts = credential.hosts.map { $0.lowercased() }
    let isAllowed = hosts.isEmpty || hosts.contains { host == $0 || host.hasSuffix("." + $0) }
    guard isAllowed else {
      throw CredentialError(
        "host-not-allowed",
        "This credential may only reach: \(credential.hosts.joined(separator: ", ")).")
    }
    return url
  }

  public static func send(
    _ request: HTTPRequest, credential: Credential, value: String, redactor: Redactor
  ) async throws -> HTTPResponse {
    let url = try validate(request, credential: credential)
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = request.method.uppercased()
    for (field, text) in request.headers ?? [:] {
      urlRequest.setValue(text, forHTTPHeaderField: field)
    }
    let prefix = request.authPrefix ?? "Bearer "
    urlRequest.setValue(prefix + value, forHTTPHeaderField: request.authHeader ?? "Authorization")
    if let body = request.body { urlRequest.httpBody = Data(body.utf8) }
    let (data, response) = try await URLSession.shared.data(
      for: urlRequest, delegate: RedirectRefusal())
    let http = response as? HTTPURLResponse
    let isTruncated = data.count > bodyLimit
    let text = String(decoding: data.prefix(bodyLimit), as: UTF8.self)
    let redaction = redactor.redact(text)
    return HTTPResponse(
      status: http?.statusCode ?? 0,
      contentType: http?.value(forHTTPHeaderField: "Content-Type"),
      body: redaction.text, isTruncated: isTruncated, redacted: redaction.names)
  }
}
