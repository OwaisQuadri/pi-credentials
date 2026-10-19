import CredentialsCore
import Darwin
import Foundation

struct Input: Decodable {
  var name: String?
  var scope: String?
  var cwd: String?
  var service: String?
  var account: String?
  var value: String?
  var kind: Kind?
  var description: String?
  var hosts: [String]?
  var apps: [String]?
  var rotation: String?
  var patterns: [String]?
  var isValueDeleted: Bool?
  var request: HTTPRequest?
  var text: String?
  var session: String?
}

struct Listing: Encodable {
  var name: String
  var description: String
  var kind: Kind
  var hosts: [String]
  var apps: [String]
  var rotation: String?
  var grants: [String]
  var isGranted: Bool
}

func emit<T: Encodable>(_ value: T) {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys]
  let data = (try? encoder.encode(value)) ?? Data("{}".utf8)
  FileHandle.standardOutput.write(data + Data("\n".utf8))
}

func required<T>(_ value: T?, _ field: String) throws -> T {
  guard let value else { throw CredentialError("missing-field", "Provide '\(field)'.") }
  return value
}

func remotes(at directory: String?) -> [String] {
  guard let directory else { return [] }
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = ["-C", directory, "remote", "-v"]
  let pipe = Pipe()
  process.standardOutput = pipe
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return [] }
  let data = pipe.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else { return [] }
  let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
  return Array(Set(lines.compactMap { $0.split(separator: "\t").dropFirst().first }
    .map { String($0.split(separator: " ").first ?? "") }))
}

func logUse(_ input: Input, groups: [String], action: String, target: String, result: String) {
  let root =
    ProcessInfo.processInfo.environment["PI_CODING_AGENT_DIR"]
    ?? NSHomeDirectory() + "/.pi/agent"
  let directory = root + "/cred"
  mkdir(directory, 0o700)
  let entry: [String: String] = [
    "time": ISO8601DateFormatter().string(from: Date()), "credential": input.name ?? "",
    "action": action, "target": target, "groups": groups.joined(separator: " "),
    "session": input.session ?? "", "result": result,
  ]
  guard var line = try? JSONSerialization.data(withJSONObject: entry, options: [.sortedKeys])
  else { return }
  line.append(UInt8(ascii: "\n"))
  let descriptor = open(directory + "/usage.jsonl", O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0o600)
  guard descriptor >= 0 else { return }
  defer { close(descriptor) }
  fchmod(descriptor, 0o600)
  _ = line.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
}

func redactionValues(_ catalog: Catalog) -> (values: [(name: String, value: String)], unavailable: [String]) {
  var values: [(String, String)] = []
  var unavailable: [String] = []
  for (name, credential) in catalog.credentials.sorted(by: { $0.key < $1.key })
  where Redactor.redactedKinds.contains(credential.kind) {
    if let value = try? Keychain.value(of: credential) {
      values.append((name, value))
    } else {
      unavailable.append(name)
    }
  }
  return (values, unavailable)
}

func applyMetadata(_ input: Input, to credential: inout Credential) throws {
  if let description = input.description {
    try Catalog.validatePlain(description, field: "description")
    credential.description = description
  }
  if let kind = input.kind { credential.kind = kind }
  if let hosts = input.hosts {
    let lowered = hosts.map { $0.lowercased() }
    try Catalog.validateHosts(lowered)
    credential.hosts = lowered
  }
  if let apps = input.apps {
    try Catalog.validateApps(apps)
    credential.apps = apps
  }
  if let rotation = input.rotation {
    try Catalog.validatePlain(rotation, field: "rotation")
    let isLink =
      rotation.hasPrefix("https://") && URL(string: rotation)?.host != nil
      && !rotation.contains(where: \.isWhitespace)
    guard rotation.isEmpty || isLink else {
      throw CredentialError("invalid-rotation", "Use an https link for rotation.")
    }
    credential.rotation = rotation.isEmpty ? nil : rotation
  }
}

func summary(_ credential: Credential) -> String {
  let hosts = credential.hosts.isEmpty ? "any host" : credential.hosts.joined(separator: ", ")
  let rotation = credential.rotation.map { "; rotation link \($0)" } ?? ""
  return "\(credential.kind.rawValue), \(credential.kind == .apiKey ? hosts : "no hosts"); "
    + "\(credential.description.debugDescription)\(rotation)"
}

func run(_ command: String, _ input: Input) async throws {
  var catalog = try Keychain.loadCatalog()
  let projectRemotes = remotes(at: input.cwd)
  let projectGroups = catalog.groups(forRemotes: projectRemotes)
  switch command {
  case "list":
    let listings = catalog.credentials.sorted { $0.key < $1.key }.map { name, credential in
      Listing(
        name: name, description: credential.description, kind: credential.kind,
        hosts: credential.hosts, apps: credential.apps, rotation: credential.rotation,
        grants: credential.grants, isGranted: catalog.isGranted(name, remotes: projectRemotes))
    }
    struct Output: Encodable {
      var credentials: [Listing]
      var groups: [String: [String]]
      var projectGroups: [String]
    }
    emit(Output(credentials: listings, groups: catalog.groups, projectGroups: projectGroups))

  case "register", "add":
    let name = try required(input.name, "name")
    try Catalog.validateName(name)
    guard catalog.credentials[name] == nil else {
      throw CredentialError("exists", "'\(name)' is already registered. Use edit.")
    }
    var credential = Credential(
      description: try required(input.description, "description"),
      kind: try required(input.kind, "kind"), service: "")
    try applyMetadata(input, to: &credential)
    if command == "register" {
      let service = try required(input.service, "service")
      try Catalog.validatePlain(service, field: "service")
      let account: String
      do {
        account = try Keychain.resolveAccount(service: service, account: input.account)
      } catch let error as CredentialError where error.code == "keychain-missing" {
        account = try Keychain.resolveAccount(
          service: Keychain.stagingPrefix + service, account: input.account)
      }
      try Catalog.validatePlain(account, field: "account")
      try Keychain.authenticateOwner(
        reason: "take over Keychain item '\(service)' (account '\(account)') as '\(name)': \(summary(credential))")
      try Keychain.adopt(service: service, account: account)
      credential.service = service
      credential.account = account
    } else {
      let value = try required(input.value, "value")
      guard !value.isEmpty else { throw CredentialError("missing-field", "Provide a value.") }
      if let service = input.service { try Catalog.validatePlain(service, field: "service") }
      credential.service = input.service ?? "pi-credentials/\(name)"
      credential.account = name
      try Keychain.authenticateOwner(reason: "store a new credential '\(name)': \(summary(credential))")
      try Keychain.add(service: credential.service, account: name, data: Data(value.utf8))
    }
    catalog.credentials[name] = credential
    try Keychain.saveCatalog(catalog)
    emit(["stored": name])

  case "edit":
    let name = try required(input.name, "name")
    let before = try catalog.credential(name)
    var credential = before
    try applyMetadata(input, to: &credential)
    var changes: [String] = []
    if before.kind != credential.kind {
      changes.append("kind \(before.kind.rawValue) → \(credential.kind.rawValue) (now \(summary(credential)))")
    }
    if before.hosts != credential.hosts {
      changes.append("hosts [\(before.hosts.joined(separator: ", "))] → [\(credential.hosts.joined(separator: ", "))]" + (credential.hosts.isEmpty ? " (any host)" : ""))
    }
    if before.apps != credential.apps {
      changes.append("apps [\(before.apps.joined(separator: ", "))] → [\(credential.apps.joined(separator: ", "))]")
    }
    if before.description != credential.description {
      changes.append("description → \(credential.description)")
    }
    if before.rotation != credential.rotation {
      changes.append("rotation link → \(credential.rotation ?? "none")")
    }
    try Keychain.authenticateOwner(
      reason: "edit '\(name)': \(changes.isEmpty ? "no changes" : changes.joined(separator: "; "))")
    catalog.credentials[name] = credential
    try Keychain.saveCatalog(catalog)
    emit(["edited": name])

  case "grant", "revoke":
    let name = try required(input.name, "name")
    let scope = try required(input.scope, "scope")
    var credential = try catalog.credential(name)
    guard scope == Catalog.globalScope || catalog.groups[scope] != nil else {
      throw CredentialError("unknown-scope", "Use 'global' or a defined project group.")
    }
    let target = scope == Catalog.globalScope
      ? "every project"
      : "project group '\(scope)' (\(catalog.groups[scope, default: []].joined(separator: ", ")))"
    try Keychain.authenticateOwner(
      reason: command == "grant" ? "let agents use '\(name)' in \(target): \(summary(credential))" : "stop agents using '\(name)' in \(target)")
    credential.grants.removeAll { $0 == scope }
    if command == "grant" { credential.grants.append(scope) }
    catalog.credentials[name] = credential
    try Keychain.saveCatalog(catalog)
    emit([command == "grant" ? "granted" : "revoked": "\(name) \(scope)"])

  case "group":
    let name = try required(input.name, "name")
    try Catalog.validateName(name)
    guard name != Catalog.globalScope else {
      throw CredentialError("invalid-name", "'global' is reserved.")
    }
    let patterns = try required(input.patterns, "patterns").compactMap(Catalog.normalizeRemote)
    try Catalog.validatePatterns(patterns)
    let users = catalog.credentials.filter { $0.value.grants.contains(name) }.keys.sorted()
    try Keychain.authenticateOwner(
      reason: patterns.isEmpty
        ? "remove project group '\(name)' and its grants"
        : "set project group '\(name)' to \(patterns.joined(separator: ", ")); granted: \(users.isEmpty ? "none" : users.joined(separator: ", "))")
    if patterns.isEmpty {
      catalog.groups[name] = nil
      for key in catalog.credentials.keys { catalog.credentials[key]?.grants.removeAll { $0 == name } }
    } else {
      catalog.groups[name] = patterns
    }
    try Keychain.saveCatalog(catalog)
    emit(["group": name])

  case "delete":
    let name = try required(input.name, "name")
    let credential = try catalog.credential(name)
    let isValueDeleted = input.isValueDeleted ?? false
    try Keychain.authenticateOwner(
      reason: isValueDeleted
        ? "delete '\(name)' and its Keychain item '\(credential.service)'"
        : "unregister '\(name)' and keep Keychain item '\(credential.service)'")
    if isValueDeleted {
      let account = try credential.account ?? Keychain.resolveAccount(service: credential.service, account: nil)
      try Keychain.delete(service: credential.service, account: account)
    }
    catalog.credentials[name] = nil
    try Keychain.saveCatalog(catalog)
    emit(["deleted": name])

  case "request":
    let name = try required(input.name, "name")
    let host = (try? required(input.request, "request")).flatMap { URL(string: $0.url)?.host } ?? "?"
    func refuse(_ error: CredentialError) -> CredentialError {
      logUse(input, groups: projectGroups, action: "request", target: host, result: error.code)
      return error
    }
    guard let credential = catalog.credentials[name] else {
      throw refuse(CredentialError("unknown-credential", "No registered credential is named '\(name)'."))
    }
    guard catalog.isGranted(name, remotes: projectRemotes) else {
      throw refuse(
        CredentialError(
          "not-granted",
          "'\(name)' is not granted for this project. Ask the user to run: \(catalog.grantFix(name, remotes: projectRemotes))"))
    }
    guard credential.kind == .apiKey else {
      throw refuse(CredentialError("wrong-kind", "'\(name)' is a \(credential.kind.rawValue), not an api-key."))
    }
    let request = try required(input.request, "request")
    do {
      let value = try Keychain.value(of: credential)
      let redaction = redactionValues(catalog)
      let response = try await Requester.send(
        request, credential: credential, value: value,
        redactor: Redactor(values: redaction.values + [(name, value)]), unavailable: redaction.unavailable)
      logUse(input, groups: projectGroups, action: "request", target: host, result: String(response.status))
      emit(response)
    } catch let error as CredentialError {
      throw refuse(error)
    } catch {
      logUse(input, groups: projectGroups, action: "request", target: host, result: "error")
      throw error
    }

  case "redact":
    let redaction = redactionValues(catalog)
    let result = Redactor(values: redaction.values).redact(try required(input.text, "text"))
    struct Output: Encodable {
      var text: String
      var redacted: [String]
      var unavailable: [String]
    }
    emit(Output(text: result.text, redacted: result.names, unavailable: redaction.unavailable))

  default:
    throw CredentialError("unknown-command", "Unknown command '\(command)'.")
  }
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 1 else {
  FileHandle.standardError.write(Data("usage: pi-credentials-helper <command> < request.json\n".utf8))
  exit(2)
}
do {
  let data = FileHandle.standardInput.readDataToEndOfFile()
  let input = try JSONDecoder().decode(Input.self, from: data.isEmpty ? Data("{}".utf8) : data)
  try await run(arguments[0], input)
} catch let error as CredentialError {
  emit(["error": ["code": error.code, "message": error.description]])
  exit(1)
} catch {
  emit(["error": ["code": "failed", "message": String(describing: error)]])
  exit(1)
}
