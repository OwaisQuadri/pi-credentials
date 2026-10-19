import CryptoKit
import Darwin
import Foundation

public struct LeakFindings: Codable, Equatable, Sendable {
  public var names: [String] = []
  public var unknown: [String: String] = [:]
  public var registered: [String: String]? = nil
  public var values: [String: String]? = nil

  public var isEmpty: Bool { names.isEmpty && unknown.isEmpty }
}

public struct LeakScanner: Sendable {
  public struct KeyFormat: Sendable {
    public let prefix: String
    let minimumLength: Int
  }

  public static let keyFormats = [
    KeyFormat(prefix: "sk-or-v1-", minimumLength: 40),
    KeyFormat(prefix: "sk-ant-", minimumLength: 30),
    KeyFormat(prefix: "sk-proj-", minimumLength: 30),
    KeyFormat(prefix: "sk-", minimumLength: 32),
    KeyFormat(prefix: "lin_api_", minimumLength: 30),
    KeyFormat(prefix: "github_pat_", minimumLength: 40),
    KeyFormat(prefix: "ghp_", minimumLength: 30),
    KeyFormat(prefix: "gho_", minimumLength: 30),
    KeyFormat(prefix: "xoxb-", minimumLength: 30),
    KeyFormat(prefix: "xoxp-", minimumLength: 30),
  ]

  let redactor: Redactor
  let needles: [(bytes: [UInt8], name: String)]
  let valueFingerprints: [String: String]
  public let signature: String

  public init(redactor: Redactor) {
    self.redactor = redactor
    needles = redactor.forms.map { (Array($0.text.utf8), String($0.label.dropFirst(6).dropLast())) }
    let forms = Dictionary(grouping: needles, by: \.name).mapValues { group in
      group.map { String(decoding: $0.bytes, as: UTF8.self) }.sorted().joined(separator: "\n")
    }
    let fingerprints = forms.mapValues(Self.fingerprint)
    valueFingerprints = fingerprints
    signature = Self.fingerprint(fingerprints.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "\n"))
  }

  static func isTokenByte(_ byte: UInt8) -> Bool {
    (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) || byte == 45
      || byte == 95
  }

  static let placeholderWords = ["example", "placeholder", "redacted", "dummy"]
  static let placeholderMarks = ["xxxx", "0000", "1234", "abcd", "your", "test", "fake", "sample", "here"]

  static func isPlaceholder(_ token: String, prefix: String) -> Bool {
    let body = token.dropFirst(prefix.count).lowercased()
    guard Set(body).count >= 12, !placeholderWords.contains(where: { body.contains($0) }) else { return true }
    let segments = body.split(whereSeparator: { $0 == "-" || $0 == "_" })
    return segments.contains { segment in
      segment.count <= 16 && placeholderMarks.contains { segment.contains($0) }
    }
  }

  static func isBoundary(_ buffer: UnsafeRawBufferPointer, before start: Int) -> Bool {
    guard start > 0, isTokenByte(buffer[start - 1]) else { return true }
    let isEscape = [UInt8(ascii: "n"), UInt8(ascii: "r"), UInt8(ascii: "t")].contains(buffer[start - 1])
    return isEscape && start > 1 && buffer[start - 2] == UInt8(ascii: "\\")
  }

  public static func fingerprint(_ token: String) -> String {
    SHA256.hash(data: Data(token.utf8)).prefix(6).map { String(format: "%02x", $0) }.joined()
  }

  static func occurrences(of needle: [UInt8], in buffer: UnsafeRawBufferPointer) -> [Int] {
    guard let base = buffer.baseAddress, !needle.isEmpty else { return [] }
    var offsets: [Int] = []
    var offset = 0
    while offset < buffer.count,
      let found = needle.withUnsafeBytes({
        memmem(base + offset, buffer.count - offset, $0.baseAddress, needle.count)
      })
    {
      let position = base.distance(to: UnsafeRawPointer(found))
      offsets.append(position)
      offset = position + 1
    }
    return offsets
  }

  func tokens(in data: Data) -> [(token: String, prefix: String)] {
    data.withUnsafeBytes { buffer in
      var seen: [(range: Range<Int>, token: String, prefix: String)] = []
      var covered = IndexSet()
      for format in Self.keyFormats {
        for start in Self.occurrences(of: Array(format.prefix.utf8), in: buffer) where !covered.contains(start) {
          guard Self.isBoundary(buffer, before: start) else { continue }
          var end = start + format.prefix.utf8.count
          while end < buffer.count && Self.isTokenByte(buffer[end]) { end += 1 }
          guard end - start >= format.minimumLength, end - start <= 256 else { continue }
          let token = String(decoding: buffer[start..<end], as: UTF8.self)
          guard !Self.isPlaceholder(token, prefix: format.prefix) else { continue }
          seen.append((start..<end, token, format.prefix))
          covered.insert(integersIn: start..<end)
        }
      }
      return seen.sorted { $0.range.lowerBound < $1.range.lowerBound }.map { ($0.token, $0.prefix) }
    }
  }

  static let scrubbedMark = Array("[cred-scrubbed:".utf8)
  static let unknownMark = Array("[cred:unknown-".utf8)

  func scrubbedLabels(in data: Data) -> (names: [String], unknown: [String: String]) {
    data.withUnsafeBytes { buffer in
      var names: [String] = []
      var unknown: [String: String] = [:]
      for (mark, isUnknown) in [(Self.scrubbedMark, false), (Self.unknownMark, true)] {
        for start in Self.occurrences(of: mark, in: buffer) {
          var end = start + mark.count
          while end < buffer.count && end - start < 128 && buffer[end] != UInt8(ascii: "]") { end += 1 }
          guard end < buffer.count, buffer[end] == UInt8(ascii: "]") else { continue }
          let body = String(decoding: buffer[(start + mark.count)..<end], as: UTF8.self)
          if !isUnknown {
            if !names.contains(body) { names.append(body) }
          } else if let format = Self.keyFormats.first(where: { body.hasPrefix($0.prefix) }) {
            let fingerprint = String(body.dropFirst(format.prefix.count))
            if fingerprint.count == 12 && fingerprint.allSatisfy(\.isHexDigit) {
              unknown[fingerprint] = format.prefix
            }
          }
        }
      }
      return (names, unknown)
    }
  }

  public func scan(_ data: Data) -> LeakFindings {
    var findings = LeakFindings()
    let labels = scrubbedLabels(in: data)
    findings.names = labels.names
    findings.unknown = labels.unknown
    data.withUnsafeBytes { buffer in
      for needle in needles where findings.values?[needle.name] == nil {
        guard let base = buffer.baseAddress else { break }
        let isFound = needle.bytes.withUnsafeBytes {
          memmem(base, buffer.count, $0.baseAddress, needle.bytes.count) != nil
        }
        if isFound {
          if !findings.names.contains(needle.name) { findings.names.append(needle.name) }
          findings.values = (findings.values ?? [:]).merging([needle.name: valueFingerprints[needle.name] ?? ""]) { current, _ in current }
        }
      }
    }
    for (token, prefix) in tokens(in: data) {
      let owner = needles.first { needle in
        let text = String(decoding: needle.bytes, as: UTF8.self)
        return token.contains(text) || text.contains(token)
      }
      if let owner {
        findings.registered = (findings.registered ?? [:]).merging([Self.fingerprint(token): owner.name]) { _, new in new }
      } else {
        findings.unknown[Self.fingerprint(token)] = prefix
      }
    }
    findings.names.sort()
    return findings
  }

  public func scrub(_ data: Data) -> Data {
    var text = redactor.redact(String(decoding: data, as: UTF8.self), labelPrefix: "cred-scrubbed").text
    var replaced = Set<String>()
    for (token, prefix) in tokens(in: Data(text.utf8)) where replaced.insert(token).inserted {
      text = text.replacingOccurrences(of: token, with: "[cred:unknown-\(prefix)\(Self.fingerprint(token))]")
    }
    return Data(text.utf8)
  }
}

public func standardPath(_ path: String) -> String { (path as NSString).standardizingPath }

public func isSessionFile(_ path: String) -> Bool { path.hasSuffix(".jsonl") }

public func addingSessionRoot(_ candidate: String?, to roots: [String], defaultRoot: String) -> [String] {
  var kept = roots.filter { $0.hasPrefix("/") && $0 != "/" }
  guard let candidate, candidate.hasPrefix("/") else { return kept }
  let root = standardPath(candidate)
  let isCovered = ([defaultRoot] + kept).contains { root == $0 || root.hasPrefix($0 + "/") }
  if root != "/" && !isCovered { kept.append(root) }
  return kept
}

public struct ScanEntry: Codable, Sendable {
  public var mtime: Double
  public var findings: LeakFindings
  public var firstSeen: [String: Double]?

  static func keys(_ findings: LeakFindings) -> [String] {
    findings.names.map { nameKey($0, findings) } + findings.unknown.keys.map { "key:" + $0 }
      + (findings.registered ?? [:]).keys.map { "key:" + $0 }
  }

  public init(mtime: Double, findings: LeakFindings, previous: ScanEntry?) {
    self.mtime = mtime
    var carried = findings
    for (fingerprint, owner) in previous?.findings.registered ?? [:] where carried.unknown[fingerprint] != nil {
      carried.registered = (carried.registered ?? [:]).merging([fingerprint: owner]) { current, _ in current }
    }
    self.findings = carried
    let earlier = previous.map { Set(Self.keys($0.findings)) } ?? []
    var seen: [String: Double] = [:]
    for key in Self.keys(carried) {
      seen[key] = previous?.firstSeen?[key] ?? (earlier.contains(key) ? previous?.mtime : nil) ?? mtime
    }
    firstSeen = seen
  }

  public static func nameKey(_ name: String, _ findings: LeakFindings) -> String {
    "name:\(name):\(findings.values?[name] ?? "")"
  }

  public func seen(_ key: String) -> Double { firstSeen?[key] ?? mtime }
}
