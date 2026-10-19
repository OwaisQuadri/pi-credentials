import CredentialsCore
import Foundation

struct Input: Decodable {
  var name: String?
  var scope: String?
  var remotes: [String]?
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

func logUse(_ input: Input, action: String, target: String, result: String) {
  let root =
    ProcessInfo.processInfo.environment["PI_CODING_AGENT_DIR"]
    ?? NSHomeDirectory() + "/.pi/agent"
  let directory = URL(fileURLWithPath: root).appendingPathComponent("cred")
  try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  let file = directory.appendingPathComponent("usage.jsonl")
  let entry: [String: String] = [
    "time": ISO8601DateFormatter().string(from: Date()), "credential": input.name ?? "",
    "action": action, "target": target, "remotes": (input.remotes ?? []).joined(separator: " "),
    "session": input.session ?? "", "result": result,
  ]
  guard var line = try? JSONSerialization.data(withJSONObject: entry, options: [.sortedKeys])
  else { return }
  line.append(Data("\n".utf8))
  if let handle = try? FileHandle(forWritingTo: file) {
    _ = try? handle.seekToEnd()
    try? handle.write(contentsOf: line)
    try? handle.close()
  } else {
    try? line.write(to: file)
  }
}

func allValues(_ catalog: Catalog) -> [(name: String, value: String)] {
  catalog.credentials.sorted { $0.key < $1.key }.compactMap { name, credential in
    (try? Keychain.value(of: credential)).map { (name, $0) }
  }
}

func applyMetadata(_ input: Input, to credential: inout Credential) {
  if let description = input.description { credential.description = description }
  if let kind = input.kind { credential.kind = kind }
  if let hosts = input.hosts { credential.hosts = hosts }
  if let apps = input.apps { credential.apps = apps }
  if let rotation = input.rotation { credential.rotation = rotation.isEmpty ? nil : rotation }
}

func run(_ command: String, _ input: Input) async throws {
  var catalog = try Keychain.loadCatalog()
  let remotes = input.remotes ?? []
  switch command {
  case "list":
    let listings = catalog.credentials.sorted { $0.key < $1.key }.map { name, credential in
      Listing(
        name: name, description: credential.description, kind: credential.kind,
        hosts: credential.hosts, apps: credential.apps, rotation: credential.rotation,
        grants: credential.grants, isGranted: catalog.isGranted(name, remotes: remotes))
    }
    struct Output: Encodable {
      var credentials: [Listing]
      var groups: [String: [String]]
      var projectGroups: [String]
    }
    emit(
      Output(
        credentials: listings, groups: catalog.groups,
        projectGroups: catalog.groups(forRemotes: remotes)))

  case "register", "add":
    let name = try required(input.name, "name")
    try Catalog.validateName(name)
    guard catalog.credentials[name] == nil else {
      throw CredentialError("exists", "'\(name)' is already registered. Use edit.")
    }
    var credential = Credential(
      description: try required(input.description, "description"),
      kind: try required(input.kind, "kind"), service: "")
    applyMetadata(input, to: &credential)
    try Keychain.authenticateOwner(reason: "add the credential '\(name)' to pi-credentials")
    if command == "register" {
      let service = try required(input.service, "service")
      let account = try Keychain.resolveAccount(service: service, account: input.account)
      try Keychain.adopt(service: service, account: account)
      credential.service = service
      credential.account = account
    } else {
      let value = try required(input.value, "value")
      guard !value.isEmpty else { throw CredentialError("missing-field", "Provide a value.") }
      credential.service = input.service ?? "pi-credentials/\(name)"
      credential.account = name
      try Keychain.add(service: credential.service, account: name, data: Data(value.utf8))
    }
    catalog.credentials[name] = credential
    try Keychain.saveCatalog(catalog)
    emit(["stored": name])

  case "edit":
    let name = try required(input.name, "name")
    var credential = try catalog.credential(name)
    applyMetadata(input, to: &credential)
    try Keychain.authenticateOwner(reason: "edit the credential '\(name)'")
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
    let verb = command == "grant" ? "grant '\(name)' to \(scope)" : "revoke '\(name)' from \(scope)"
    try Keychain.authenticateOwner(reason: verb)
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
    try Keychain.authenticateOwner(
      reason: patterns.isEmpty ? "remove the project group '\(name)'" : "set the project group '\(name)'")
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
      reason: isValueDeleted ? "delete '\(name)' and its Keychain value" : "unregister '\(name)'")
    if isValueDeleted {
      let account = try credential.account ?? Keychain.resolveAccount(service: credential.service, account: nil)
      try Keychain.delete(service: credential.service, account: account)
    }
    catalog.credentials[name] = nil
    try Keychain.saveCatalog(catalog)
    emit(["deleted": name])

  case "request":
    let name = try required(input.name, "name")
    let credential = try catalog.credential(name)
    guard catalog.isGranted(name, remotes: remotes) else {
      throw CredentialError(
        "not-granted",
        "'\(name)' is not granted for this project. Ask the user to run: \(catalog.grantFix(name, remotes: remotes))")
    }
    guard credential.kind == .apiKey else {
      throw CredentialError("wrong-kind", "'\(name)' is a \(credential.kind.rawValue), not an api-key.")
    }
    let request = try required(input.request, "request")
    let host = URL(string: request.url)?.host ?? "?"
    do {
      let value = try Keychain.value(of: credential)
      let response = try await Requester.send(
        request, credential: credential, value: value,
        redactor: Redactor(values: allValues(catalog)))
      logUse(input, action: "request", target: host, result: String(response.status))
      emit(response)
    } catch {
      logUse(input, action: "request", target: host, result: "error")
      throw error
    }

  case "redact":
    let result = Redactor(values: allValues(catalog)).redact(try required(input.text, "text"))
    struct Output: Encodable {
      var text: String
      var redacted: [String]
    }
    emit(Output(text: result.text, redacted: result.names))

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
