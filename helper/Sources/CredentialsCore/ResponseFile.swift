import Darwin
import Foundation

final class ResponseFile {
  static let limit = 100 * 1024 * 1024
  static let chunkSize = 64 * 1024

  let path: String
  private let directory: Int32
  private let stagingDirectory: Int32
  private let stagingName: String
  private let descriptor: Int32
  private let name: String
  private let needles: [Data]
  private let overlap: Int
  private var pending = Data()
  private(set) var byteCount = 0

  init(path: String, cwd: String?, redactor: Redactor, value: String) throws {
    let forms = redactor.forms + Redactor(values: [("request-key", value)], minimumLength: 1).forms
    needles = Array(Set(forms.map { Data($0.text.utf8) }))
    overlap = max((needles.map(\.count).max() ?? 1) - 1, 0)
    guard !path.isEmpty, !path.contains("\0"), !path.hasSuffix("/"),
      !needles.contains(where: { Data(path.utf8).range(of: $0) != nil })
    else {
      throw CredentialError("invalid-output-file", "Use a new file path without credentials.")
    }
    let absolute: String
    if path.hasPrefix("/") {
      absolute = path
    } else {
      guard let cwd, cwd.hasPrefix("/"), !cwd.contains("\0") else {
        throw CredentialError(
          "invalid-output-file", "A project directory is required for relative output files.")
      }
      absolute = cwd + "/" + path
    }
    guard !needles.contains(where: { Data(absolute.utf8).range(of: $0) != nil }) else {
      throw CredentialError("invalid-output-file", "Use a file path without credentials.")
    }
    let parts = absolute.split(separator: "/").map(String.init)
    guard let name = parts.last, name != ".", !parts.contains("..") else {
      throw CredentialError("invalid-output-file", "Use a file path without parent traversal.")
    }
    let normalized = "/" + parts.filter { $0 != "." }.joined(separator: "/")
    self.name = name
    self.path = normalized
    guard !needles.contains(where: { Data(normalized.utf8).range(of: $0) != nil }) else {
      throw CredentialError("invalid-output-file", "Use a file path without credentials.")
    }
    var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parent >= 0 else { throw Self.fileError() }
    do {
      for part in parts.dropLast() where part != "." {
        let next = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard next >= 0 else { throw Self.fileError() }
        close(parent)
        parent = next
      }
      var info = stat()
      guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
        throw Self.fileError()
      }
      let stagingName = ".pi-credentials-" + UUID().uuidString
      guard mkdirat(parent, stagingName, 0o700) == 0 else { throw Self.fileError() }
      let staging = openat(parent, stagingName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard staging >= 0 else {
        unlinkat(parent, stagingName, AT_REMOVEDIR)
        throw Self.fileError()
      }
      let file = openat(
        staging, "body", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
      guard file >= 0 else {
        close(staging)
        unlinkat(parent, stagingName, AT_REMOVEDIR)
        throw Self.fileError()
      }
      directory = parent
      stagingDirectory = staging
      self.stagingName = stagingName
      descriptor = file
    } catch {
      close(parent)
      throw error
    }
  }

  deinit {
    close(descriptor)
    unlinkat(stagingDirectory, "body", 0)
    close(stagingDirectory)
    unlinkat(directory, stagingName, AT_REMOVEDIR)
    close(directory)
  }

  static func fileError() -> CredentialError {
    CredentialError(
      "output-file-refused",
      "Could not create a new output file. Existing paths and symlinks are refused.")
  }

  func append(_ data: Data) throws {
    guard data.count <= Self.limit - byteCount else {
      throw CredentialError("response-too-large", "The response exceeds the 100 MiB file limit.")
    }
    byteCount += data.count
    pending.append(data)
    guard !needles.contains(where: { pending.range(of: $0) != nil }) else {
      throw CredentialError(
        "credential-in-response", "The response contains a credential; no file was saved.")
    }
    let count = max(pending.count - overlap, 0)
    try write(Data(pending.prefix(count)))
    pending = Data(pending.suffix(pending.count - count))
  }

  private func write(_ data: Data) throws {
    try data.withUnsafeBytes { bytes in
      var offset = 0
      while offset < bytes.count {
        let written = Darwin.write(
          descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
        if written < 0 && errno == EINTR { continue }
        guard written > 0 else { throw Self.fileError() }
        offset += written
      }
    }
  }

  func publish() throws {
    try Task.checkCancellation()
    try write(pending)
    guard fsync(descriptor) == 0 else { throw Self.fileError() }
    try Task.checkCancellation()
    guard renameatx_np(stagingDirectory, "body", directory, name, UInt32(RENAME_EXCL)) == 0 else {
      throw Self.fileError()
    }
  }
}
