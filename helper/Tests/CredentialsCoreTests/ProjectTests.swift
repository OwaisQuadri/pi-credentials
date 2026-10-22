import Foundation
import Testing

@testable import CredentialsCore

@Test func legacyCatalogDoesNotEnrollRepositories() throws {
  let original = Catalog(
    credentials: [
      "key": Credential(description: "", kind: .apiKey, service: "fixture", grants: ["work"])
    ],
    groups: ["work": ["example.test/org/*"]])
  var json = try #require(
    JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
  json.removeValue(forKey: "projects")
  let decoded = try JSONDecoder().decode(
    Catalog.self, from: JSONSerialization.data(withJSONObject: json))
  #expect(decoded == original)
  #expect(decoded.projects.isEmpty)
  #expect(
    decoded.isGranted("key", remotes: ["https://example.test/org/app"], repository: "/fixture/.git")
  )
  #expect(!decoded.isGranted("key", remotes: [], repository: "/fixture/.git"))
}

@Test func projectRenameAndMembershipRemovalPreserveGrantProvenance() throws {
  var catalog = Catalog(
    credentials: [
      "key": Credential(description: "", kind: .apiKey, service: "fixture"),
      "global": Credential(description: "", kind: .apiKey, service: "fixture", grants: ["global"]),
      "group": Credential(description: "", kind: .apiKey, service: "fixture", grants: ["work"]),
    ], groups: ["work": ["example.test/org/*"]])
  let id = try catalog.applyProjectChange(.create(name: "Readable name")) { _ in }
  #expect(UUID(uuidString: id) != nil)
  catalog.credentials["key"]!.grants = [Catalog.projectScope(id)]
  let repository = "/fixture/.git"
  #expect(!catalog.isGranted("key", remotes: [], repository: repository))
  _ = try catalog.applyProjectChange(.membership(id: id, repository: repository, isAdded: true)) {
    reason in
    #expect(reason.contains("key"))
    #expect(reason.contains(repository))
  }
  _ = try catalog.applyProjectChange(.rename(id: id, name: "Renamed project")) { _ in }
  #expect(catalog.projects[id]?.name == "Renamed project")
  #expect(catalog.isGranted("key", remotes: [], repository: repository))
  #expect(
    catalog.grantFix("key", remotes: [], repository: repository) == "/cred grant key project:\(id)")
  #expect(catalog.projectID(forScope: Catalog.projectScope(id)) == id)
  #expect(catalog.projectID(forScope: "project:missing") == nil)
  #expect(!catalog.isGranted("key", remotes: ["Renamed project"]))
  let restored = try JSONDecoder().decode(Catalog.self, from: JSONEncoder().encode(catalog))
  #expect(restored.isGranted("key", remotes: [], repository: repository))
  let other = try catalog.applyProjectChange(.create(name: "Other")) { _ in }
  _ = try catalog.applyProjectChange(.membership(id: other, repository: repository, isAdded: true))
  { _ in }
  catalog.credentials["key"]!.grants.append(Catalog.projectScope(other))
  catalog.credentials["global"]!.grants.append(Catalog.projectScope(id))
  catalog.credentials["group"]!.grants.append(Catalog.projectScope(id))
  let grants = catalog.credentials
  _ = try catalog.applyProjectChange(.membership(id: id, repository: repository, isAdded: false)) {
    _ in
  }
  #expect(catalog.isGranted("key", remotes: [], repository: repository))
  _ = try catalog.applyProjectChange(.membership(id: other, repository: repository, isAdded: false))
  { _ in }
  #expect(!catalog.isGranted("key", remotes: [], repository: repository))
  #expect(catalog.isGranted("global", remotes: [], repository: repository))
  #expect(
    catalog.isGranted("group", remotes: ["https://example.test/org/app"], repository: repository))
  #expect(catalog.credentials == grants)
  #expect(try JSONDecoder().decode(Catalog.self, from: JSONEncoder().encode(catalog)) == catalog)
}

@Test func deniedProjectMembershipDoesNotChangeCatalog() throws {
  var catalog = Catalog()
  let id = try catalog.applyProjectChange(.create(name: "Project")) { _ in }
  let before = catalog
  #expect(throws: CredentialError("auth-denied", "fixture")) {
    try catalog.applyProjectChange(.membership(id: id, repository: "/fixture/.git", isAdded: true))
    { _ in
      throw CredentialError("auth-denied", "fixture")
    }
  }
  #expect(catalog == before)
  #expect(throws: (any Error).self) {
    try catalog.applyProjectChange(.rename(id: id, name: "spoof\nname")) { _ in
      Issue.record("Invalid names must not reach approval")
    }
  }
  #expect(catalog == before)
}

@Test func worktreesShareMembershipButSeparateRepositoriesDoNot() throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: root) }
  func git(_ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = arguments
    process.environment = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("GIT_") }
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 0)
  }
  let main = root.appendingPathComponent("main").path
  let worktree = root.appendingPathComponent("worktree").path
  let separate = root.appendingPathComponent("separate").path
  try git(["init", main])
  try git([
    "-C", main, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit",
    "--allow-empty", "-m", "fixture",
  ])
  try git(["-C", main, "worktree", "add", "--detach", worktree])
  try git(["clone", main, separate])
  let identity = try Repository.identity(at: main)
  #expect(try Repository.identity(at: worktree) == identity)
  #expect(try Repository.identity(at: separate) != identity)
  let link = root.appendingPathComponent("link").path
  try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: worktree)
  #expect(try Repository.identity(at: link) == identity)
  #expect(throws: (any Error).self) { try Repository.identity(at: root.path) }
}
