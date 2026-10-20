import Foundation

public struct HTTPRequest: Codable, Sendable {
  public var method: String
  public var url: String
  public var headers: [String: String]?
  public var body: String?
  public var authHeader: String?
  public var authPrefix: String?
  public var outputFile: String?
}

public struct HTTPResponse: Codable, Sendable {
  public var status: Int
  public var contentType: String?
  public var body: String?
  public var outputFile: String?
  public var byteCount: Int?
  public var isTruncated: Bool
  public var redacted: [String]
  public var unavailable: [String]
}

final class RedirectRefusal: NSObject, URLSessionTaskDelegate, Sendable {
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
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
    unavailable: [String], cwd: String? = nil
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
    if let outputFile = request.outputFile {
      do {
        guard unavailable.isEmpty else {
          throw CredentialError(
            "redaction-unavailable", "Could not check every credential; no file was saved.")
        }
        let file = try ResponseFile(path: outputFile, cwd: cwd, redactor: redactor, value: value)
        let (bytes, response) = try await session.bytes(
          for: urlRequest, delegate: RedirectRefusal())
        return try await save(bytes, response: response, to: file, redactor: redactor, value: value)
      } catch let error as CredentialError {
        throw error
      } catch is CancellationError {
        throw CredentialError("request-cancelled", "The request was cancelled; no file was saved.")
      } catch {
        throw CredentialError("request-failed", "The request failed; no file was saved.")
      }
    }
    let (data, response) = try await session.data(for: urlRequest, delegate: RedirectRefusal())
    let http = response as? HTTPURLResponse
    let redaction = redactor.redact(String(decoding: data, as: UTF8.self))
    let utf8 = Array(redaction.text.utf8)
    let isTruncated = utf8.count > bodyLimit
    let contentType = http?.value(forHTTPHeaderField: "Content-Type").map {
      redactor.redact($0).text
    }
    return HTTPResponse(
      status: http?.statusCode ?? 0, contentType: contentType,
      body: isTruncated ? String(decoding: utf8.prefix(bodyLimit), as: UTF8.self) : redaction.text,
      isTruncated: isTruncated, redacted: redaction.names, unavailable: unavailable)
  }

  static func save<Bytes: AsyncSequence>(
    _ bytes: Bytes, response: URLResponse, to file: ResponseFile, redactor: Redactor, value: String
  ) async throws -> HTTPResponse where Bytes.Element == UInt8 {
    guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
      throw CredentialError(
        "http-error", "The server did not return a successful response; no file was saved.")
    }
    guard response.expectedContentLength <= ResponseFile.limit else {
      throw CredentialError("response-too-large", "The response exceeds the 100 MiB file limit.")
    }
    var chunk = Data()
    chunk.reserveCapacity(ResponseFile.chunkSize)
    for try await byte in bytes {
      try Task.checkCancellation()
      chunk.append(byte)
      if chunk.count == ResponseFile.chunkSize {
        try file.append(chunk)
        chunk.removeAll(keepingCapacity: true)
      }
    }
    try Task.checkCancellation()
    try file.append(chunk)
    let encoding = http.value(forHTTPHeaderField: "Content-Encoding")?.lowercased()
    if encoding == nil || encoding == "identity", response.expectedContentLength >= 0,
      file.byteCount != response.expectedContentLength
    {
      throw CredentialError(
        "incomplete-response", "The response was incomplete; no file was saved.")
    }
    let activeRedactor = Redactor(values: [("request-key", value)], minimumLength: 1)
    let contentType = http.value(forHTTPHeaderField: "Content-Type").map {
      activeRedactor.redact(redactor.redact($0).text).text
    }
    try file.publish()
    return HTTPResponse(
      status: http.statusCode, contentType: contentType, outputFile: file.path,
      byteCount: file.byteCount, isTruncated: false, redacted: [], unavailable: [])
  }
}
