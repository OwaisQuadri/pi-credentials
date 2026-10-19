import CredentialsCore
import Foundation

struct ScanState: Codable {
  var lastScan: Double?
  var files: [String: ScanEntry] = [:]
  var roots: [String]?
  var signature: String?
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

func modificationTime(_ path: String) -> Double? { fileIdentity(path)?.mtime }

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

func scannerFor(_ catalog: Catalog) -> (scanner: LeakScanner, unavailable: [String]) {
  let values = redactionValues(catalog)
  return (LeakScanner(redactor: Redactor(values: values.values)), values.unavailable)
}

func scanSessions(_ catalog: Catalog, isFull: Bool, extraRoot: String?) throws -> (state: ScanState, scanned: Int) {
  var state = loadScanState()
  let (scanner, unavailable) = scannerFor(catalog)
  let started = Date().timeIntervalSince1970
  let isComplete = unavailable.isEmpty
  let since = isFull || (isComplete && state.signature != scanner.signature) ? nil : state.lastScan
  if isComplete { state.signature = scanner.signature }
  let known = Set(state.roots ?? [])
  state.roots = addingSessionRoot(extraRoot, to: state.roots ?? [], defaultRoot: sessionsRoot())
  let roots = [sessionsRoot()] + (state.roots ?? [])
  var scanned = 0
  var present = Set<String>()
  var missing: [String] = []
  for (index, root) in roots.enumerated() {
    guard FileManager.default.fileExists(atPath: root), let enumerator = FileManager.default.enumerator(atPath: root)
    else {
      missing.append(root)
      continue
    }
    let rootSince = index == 0 || known.contains(root) ? since : nil
    while let relative = enumerator.nextObject() as? String {
      if index > 0, (enumerator.fileAttributes?[.type] as? FileAttributeType) == .typeDirectory {
        enumerator.skipDescendants()
      }
      let path = root + "/" + relative
      guard isSessionFile(path), !present.contains(path), let mtime = modificationTime(path) else { continue }
      present.insert(path)
      if let rootSince, mtime < rootSince { continue }
      guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { continue }
      scanned += 1
      var findings = scanner.scan(data)
      for name in state.files[path]?.findings.names ?? [] where unavailable.contains(name) && !findings.names.contains(name) {
        findings.names.append(name)
        if let value = state.files[path]?.findings.values?[name] {
          findings.values = (findings.values ?? [:]).merging([name: value]) { current, _ in current }
        }
      }
      findings.names.sort()
      state.files[path] =
        findings.isEmpty ? nil : ScanEntry(mtime: mtime, findings: findings, previous: state.files[path])
    }
  }
  state.files = state.files.filter { path, _ in
    present.contains(path) || missing.contains { path.hasPrefix($0 + "/") }
  }
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
      if let rotated = catalog.credentials[name]?.rotatedAt, entry.seen(ScanEntry.nameKey(name, entry.findings)) < rotated { continue }
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
  let scanner = scannerFor(catalog).scanner
  var rewritten = 0
  var skipped = 0
  let cutoff = Date().timeIntervalSince1970 - activeWindow
  let excludedPath = excluded.map(standardPath)
  for (path, _) in state.files where path != excludedPath && isSessionFile(path) {
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
