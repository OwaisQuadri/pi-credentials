import Foundation
import Testing

@testable import CredentialsCore

private let fakeKey = "fixture-secret-1234"
private let fileRedactor = Redactor(values: [("key", fakeKey), ("other", "another-fixture-secret")])

private func temporaryDirectory() throws -> URL {
  let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
  return directory
}

private func save(
  _ bytes: [UInt8], directory: URL, status: Int = 200, headers: [String: String] = [:],
  isInterrupted: Bool = false
) async throws -> HTTPResponse {
  let file = try ResponseFile(
    path: "media.bin", cwd: directory.path, redactor: fileRedactor, value: fakeKey)
  let stream = AsyncThrowingStream<UInt8, Error> { continuation in
    for byte in bytes { continuation.yield(byte) }
    if isInterrupted {
      continuation.finish(throwing: URLError(.networkConnectionLost))
    } else {
      continuation.finish()
    }
  }
  let response = HTTPURLResponse(
    url: URL(string: "https://api.example.test/media")!, statusCode: status,
    httpVersion: "HTTP/1.1", headerFields: headers)!
  return try await Requester.save(
    stream, response: response, to: file, redactor: fileRedactor, value: fakeKey)
}

@Test func responseFilesPreserveInvalidUTF8BeyondTheTextLimit() throws {
  let directory = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: directory) }
  let chunk = Data(repeating: 0xff, count: ResponseFile.chunkSize - 4) + Data([0, 0x80, 0xfe, 1])
  do {
    let file = try ResponseFile(
      path: "media.bin", cwd: directory.path, redactor: fileRedactor, value: fakeKey)
    for _ in 0..<17 { try file.append(chunk) }
    #expect(file.byteCount > Requester.bodyLimit)
    #expect(!FileManager.default.fileExists(atPath: file.path))
    try file.publish()
    let saved = try Data(contentsOf: URL(fileURLWithPath: file.path))
    #expect(saved == (0..<17).reduce(into: Data()) { data, _ in data.append(chunk) })
    let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
  }
  #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["media.bin"])
}

@Test func fileStreamResponsesReturnRedactedMetadataWithoutBodyBytes() async throws {
  let directory = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: directory) }
  let response = try await save(
    [0, 0xff, 0x80], directory: directory,
    headers: ["Content-Type": "application/" + fakeKey, "Content-Length": "3"])
  #expect(
    try Data(contentsOf: directory.appendingPathComponent("media.bin")) == Data([0, 0xff, 0x80]))
  #expect(response.status == 200 && response.byteCount == 3 && response.body == nil)
  #expect(response.contentType == "application/[cred:key]")
  #expect(response.outputFile == directory.appendingPathComponent("media.bin").path)
  let json = try JSONEncoder().encode(response)
  let object = try JSONSerialization.jsonObject(with: json) as! [String: Any]
  #expect(object["body"] == nil)
  #expect(!String(decoding: json, as: UTF8.self).contains(fakeKey))
}

@Test func responseFilesRefuseCredentialsAcrossChunksIncludingEncodedAndShortKeys() throws {
  let directory = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: directory) }
  let forms = fileRedactor.forms.map(\.text) + ["tiny", Data("tiny".utf8).base64EncodedString()]
  for form in forms {
    do {
      let file = try ResponseFile(
        path: "media.bin", cwd: directory.path, redactor: fileRedactor, value: "tiny")
      let bytes = Data(form.utf8)
      let split = bytes.count / 2
      try file.append(Data(repeating: 0xff, count: ResponseFile.chunkSize) + bytes.prefix(split))
      try file.append(bytes.suffix(bytes.count - split))
      Issue.record("A credential was accepted")
    } catch let error as CredentialError {
      #expect(error.code == "credential-in-response")
      #expect(!error.description.contains(form))
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
  }
}

@Test func responseFilesRefuseExistingPathsSymlinksAndPublicationRaces() throws {
  let directory = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: directory) }
  let existing = directory.appendingPathComponent("existing")
  try Data("original".utf8).write(to: existing)
  try FileManager.default.createSymbolicLink(
    atPath: directory.path + "/link", withDestinationPath: existing.path)
  try FileManager.default.createSymbolicLink(
    atPath: directory.path + "/dangling", withDestinationPath: directory.path + "/missing")
  try FileManager.default.createSymbolicLink(
    atPath: directory.path + "/parent", withDestinationPath: directory.path)
  for path in [
    "existing", "link", "dangling", "parent/media", "../media", ".", "", "bad\0path",
    fakeKey + ".bin",
  ] {
    #expect(throws: CredentialError.self) {
      _ = try ResponseFile(path: path, cwd: directory.path, redactor: fileRedactor, value: fakeKey)
    }
  }
  do {
    _ = try ResponseFile(
      path: "dir/./file", cwd: directory.path, redactor: fileRedactor, value: "dir/file")
    Issue.record("A normalized path exposed a credential")
  } catch let error as CredentialError {
    #expect(error.code == "invalid-output-file")
  }
  do {
    let file = try ResponseFile(
      path: "race", cwd: directory.path, redactor: fileRedactor, value: fakeKey)
    try file.append(Data("new".utf8))
    try FileManager.default.createSymbolicLink(
      atPath: directory.path + "/race", withDestinationPath: existing.path)
    #expect(throws: CredentialError.self) { try file.publish() }
  }
  #expect(try Data(contentsOf: existing) == Data("original".utf8))
  #expect(
    try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == [
      "dangling", "existing", "link", "parent", "race",
    ])
}

@Test func fileStreamsRefuseErrorsIncompleteBodiesOversizeAndUnavailableRedaction() async throws {
  let directory = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: directory) }
  for (status, headers, expected) in [
    (401, [:], "http-error"),
    (302, ["Location": "https://other.example.test/"], "http-error"),
    (200, ["Content-Length": "10"], "incomplete-response"),
    (200, ["Content-Length": String(ResponseFile.limit + 1)], "response-too-large"),
  ] {
    do {
      _ = try await save([1, 2], directory: directory, status: status, headers: headers)
      Issue.record("An unsuccessful response was saved")
    } catch let error as CredentialError {
      #expect(error.code == expected)
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
  }
  await #expect(throws: URLError.self) {
    _ = try await save(
      Array(repeating: 0xff, count: ResponseFile.chunkSize + 1), directory: directory,
      isInterrupted: true)
  }
  await #expect(throws: CredentialError.self) {
    _ = try await Requester.send(
      HTTPRequest(method: "GET", url: "https://api.example.test/", outputFile: "media.bin"),
      credential: Credential(description: "fixture", kind: .apiKey, service: "fixture"),
      value: fakeKey,
      redactor: fileRedactor, unavailable: ["other"], cwd: directory.path)
  }
  #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
}

@Test func responseFilesBoundUnknownLengthBodiesAndCleanUpCancelledStreams() async throws {
  let directory = try temporaryDirectory()
  defer { try? FileManager.default.removeItem(at: directory) }
  do {
    let file = try ResponseFile(
      path: "media.bin", cwd: directory.path, redactor: fileRedactor, value: fakeKey)
    let chunk = Data(repeating: 0xff, count: 1024 * 1024)
    for _ in 0..<100 { try file.append(chunk) }
    #expect(file.byteCount == ResponseFile.limit)
    #expect(throws: CredentialError.self) { try file.append(Data([1])) }
  }
  let task = Task {
    withUnsafeCurrentTask { $0?.cancel() }
    return try await save([1, 2, 3], directory: directory)
  }
  await #expect(throws: CancellationError.self) { try await task.value }
  #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
}
