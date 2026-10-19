import CredentialsCore
import Foundation

struct ScanEntry: Codable {
  var mtime: Double
  var findings: LeakFindings
  var firstSeen: [String: Double]?

  static func keys(_ findings: LeakFindings) -> [String] {
    findings.names.map { "name:" + $0 } + findings.unknown.keys.map { "key:" + $0 }
  }

  init(mtime: Double, findings: LeakFindings, previous: ScanEntry?) {
    self.mtime = mtime
    self.findings = findings
    let earlier = previous.map { Set(Self.keys($0.findings)) } ?? []
    var seen: [String: Double] = [:]
    for key in Self.keys(findings) {
      seen[key] = previous?.firstSeen?[key] ?? (earlier.contains(key) ? previous?.mtime : nil) ?? mtime
    }
    firstSeen = seen
  }

  func seen(_ key: String) -> Double { firstSeen?[key] ?? mtime }
}

struct ScanState: Codable {
  var lastScan: Double?
  var files: [String: ScanEntry] = [:]
  var roots: [String]?
}

struct LeakReport: Encodable {
  struct Known: Encodable {
    var name: String
    var rotation: String?
    var sessions: Int
    var last: String
  }
  struct Unknown: Encodable {
    var fingerprint: String
    var prefix: String
    var sessions: Int
    var last: String
  }
  var leaks: [Known]
  var unknown: [Unknown]
  var scanned: Int
}

func standardPath(_ path: String) -> String { (path as NSString).standardizingPath }

func sessionsRoot() -> String {
  standardPath(
    (ProcessInfo.processInfo.environment["PI_CODING_AGENT_DIR"] ?? NSHomeDirectory() + "/.pi/agent")
      + "/sessions")
}

func scanStatePath() -> String { credDirectory() + "/scan.json" }

func loadScanState() -> ScanState {
  guard let data = FileManager.default.contents(atPath: scanStatePath()),
    let state = try? JSONDecoder().decode(ScanState.self, from: data)
  else { return ScanState() }
  return state
}

func saveScanState(_ state: ScanState) throws {
  let path = scanStatePath()
  let data = try JSONEncoder().encode(state)
  try data.write(to: URL(fileURLWithPath: path), options: .atomic)
  chmod(path, 0o600)
}

func modificationTime(_ path: String) -> Double? {
  var info = stat()
  guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
  return Double(info.st_mtimespec.tv_sec) + Double(info.st_mtimespec.tv_nsec) / 1e9
}

struct FileIdentity: Equatable {
  var size: off_t
  var seconds: Int
  var nanoseconds: Int
  var inode: ino_t

  var mtime: Double { Double(seconds) + Double(nanoseconds) / 1e9 }
}

func fileIdentity(_ path: String) -> FileIdentity? {
  var info = stat()
  guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
  return FileIdentity(
    size: info.st_size, seconds: info.st_mtimespec.tv_sec, nanoseconds: info.st_mtimespec.tv_nsec,
    inode: info.st_ino)
}

func scannerFor(_ catalog: Catalog) -> LeakScanner {
  LeakScanner(redactor: Redactor(values: redactionValues(catalog).values))
}

func scanSessions(_ catalog: Catalog, isFull: Bool, extraRoot: String?) throws -> (state: ScanState, scanned: Int) {
  var state = loadScanState()
  let scanner = scannerFor(catalog)
  let started = Date().timeIntervalSince1970
  let since = isFull ? nil : state.lastScan
  var roots = [sessionsRoot()] + (state.roots ?? [])
  if let extraRoot, !roots.contains(where: { standardPath(extraRoot) == $0 || standardPath(extraRoot).hasPrefix($0 + "/") }) {
    roots.append(standardPath(extraRoot))
    state.roots = (state.roots ?? []) + [standardPath(extraRoot)]
  }
  var scanned = 0
  var present = Set<String>()
  for root in roots {
    let enumerator = FileManager.default.enumerator(atPath: root)
    while let relative = enumerator?.nextObject() as? String {
      let path = root + "/" + relative
      guard !present.contains(path), let mtime = modificationTime(path) else { continue }
      present.insert(path)
      if let since, mtime < since { continue }
      guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { continue }
      scanned += 1
      let findings = scanner.scan(data)
      state.files[path] =
        findings.isEmpty ? nil : ScanEntry(mtime: mtime, findings: findings, previous: state.files[path])
    }
  }
  state.files = state.files.filter { present.contains($0.key) }
  state.lastScan = started
  try saveScanState(state)
  return (state, scanned)
}

func report(_ state: ScanState, catalog: Catalog, scanned: Int) -> LeakReport {
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withFullDate]
  formatter.timeZone = .current
  var known: [String: (count: Int, last: Double)] = [:]
  var unknown: [String: (prefix: String, count: Int, last: Double)] = [:]
  for entry in state.files.values {
    for name in entry.findings.names where catalog.credentials[name] != nil {
      if let rotated = catalog.credentials[name]?.rotatedAt, entry.seen("name:" + name) < rotated { continue }
      let current = known[name] ?? (0, 0)
      known[name] = (current.count + 1, max(current.last, entry.mtime))
    }
    for (fingerprint, prefix) in entry.findings.unknown {
      if let dismissed = catalog.dismissed?[fingerprint], entry.seen("key:" + fingerprint) < dismissed { continue }
      let current = unknown[fingerprint] ?? (prefix, 0, 0)
      unknown[fingerprint] = (prefix, current.count + 1, max(current.last, entry.mtime))
    }
  }
  func day(_ time: Double) -> String { formatter.string(from: Date(timeIntervalSince1970: time)) }
  return LeakReport(
    leaks: known.sorted { $0.key < $1.key }.map {
      LeakReport.Known(
        name: $0.key, rotation: catalog.credentials[$0.key]?.rotation, sessions: $0.value.count,
        last: day($0.value.last))
    },
    unknown: unknown.sorted { $0.key < $1.key }.map {
      LeakReport.Unknown(
        fingerprint: $0.key, prefix: $0.value.prefix, sessions: $0.value.count, last: day($0.value.last))
    },
    scanned: scanned)
}

let activeWindow: Double = 600

func scrubSessions(_ catalog: Catalog, excluding excluded: String?) throws -> (rewritten: Int, skipped: Int) {
  var state = loadScanState()
  let scanner = scannerFor(catalog)
  var rewritten = 0
  var skipped = 0
  let cutoff = Date().timeIntervalSince1970 - activeWindow
  let excludedPath = excluded.map(standardPath)
  for (path, _) in state.files where path != excludedPath {
    guard let before = fileIdentity(path), before.mtime < cutoff else {
      skipped += 1
      continue
    }
    guard let data = FileManager.default.contents(atPath: path) else { continue }
    let scrubbed = scanner.scrub(data)
    if scrubbed != data {
      let temporary = path + ".pi-credentials-\(UUID().uuidString)"
      let attributes = try FileManager.default.attributesOfItem(atPath: path)
      try scrubbed.write(to: URL(fileURLWithPath: temporary), options: .withoutOverwriting)
      if let permissions = attributes[.posixPermissions] as? NSNumber {
        chmod(temporary, mode_t(permissions.uint16Value))
      }
      if let modified = attributes[.modificationDate] {
        try? FileManager.default.setAttributes([.modificationDate: modified], ofItemAtPath: temporary)
      }
      guard fileIdentity(path) == before else {
        unlink(temporary)
        skipped += 1
        continue
      }
      guard rename(temporary, path) == 0 else {
        unlink(temporary)
        throw CredentialError("scrub-failed", "Could not rewrite \(path).")
      }
      rewritten += 1
    }
    let findings = modificationTime(path).map { mtime in
      (mtime, scanner.scan(FileManager.default.contents(atPath: path) ?? Data()))
    }
    state.files[path] = findings.flatMap {
      $0.1.isEmpty ? nil : ScanEntry(mtime: $0.0, findings: $0.1, previous: state.files[path])
    }
  }
  try saveScanState(state)
  return (rewritten, skipped)
}
