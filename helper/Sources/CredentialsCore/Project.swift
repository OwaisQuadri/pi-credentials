import Foundation

public struct Project: Codable, Equatable, Sendable {
  public var name: String
  public var repositories: [String]

  public init(name: String, repositories: [String] = []) {
    self.name = name
    self.repositories = repositories
  }
}

public enum ProjectChange {
  case create(name: String)
  case rename(id: String, name: String)
  case membership(id: String, repository: String, isAdded: Bool)
}

extension Catalog {
  public static func projectScope(_ id: String) -> String { "project:" + id }

  public func projectID(forScope scope: String) -> String? {
    guard scope.hasPrefix("project:") else { return nil }
    let id = String(scope.dropFirst("project:".count))
    return projects[id] == nil ? nil : id
  }

  public func project(_ id: String) throws -> Project {
    guard let project = projects[id] else {
      throw CredentialError(
        "unknown-project", "No project has identifier '\(id)'. Use /project list.")
    }
    return project
  }

  public func projectIDs(forRepository repository: String?) -> [String] {
    guard let repository else { return [] }
    return projects.keys.sorted().filter { projects[$0]!.repositories.contains(repository) }
  }

  public mutating func applyProjectChange(
    _ change: ProjectChange, authenticateOwner: (String) throws -> Void
  ) throws -> String {
    let id: String
    var updated: Project
    let reason: String
    switch change {
    case .create(let name):
      id = UUID().uuidString.lowercased()
      updated = Project(name: name)
      reason = "create project \(name.debugDescription) (\(id)); no repositories or grants"
    case .rename(let projectID, let name):
      id = projectID
      updated = try project(id)
      reason =
        "rename project \(updated.name.debugDescription) (\(id)) to \(name.debugDescription); keep membership and grants"
      updated.name = name
    case .membership(let projectID, let repository, let isAdded):
      id = projectID
      updated = try project(id)
      try Self.validatePlain(repository, field: "repository")
      guard repository.hasPrefix("/"), !repository.isEmpty else {
        throw CredentialError("invalid-repository", "Use the canonical Git common-directory path.")
      }
      let granted = credentials.keys.sorted().filter {
        credentials[$0]!.grants.contains(Self.projectScope(id))
      }
      reason =
        "\(isAdded ? "add" : "remove") repository \(repository.debugDescription) \(isAdded ? "to" : "from") project \(updated.name.debugDescription) (\(id)); project credentials: \(granted.isEmpty ? "none" : granted.joined(separator: ", ")); independent grants stay unchanged"
      updated.repositories.removeAll { $0 == repository }
      if isAdded { updated.repositories.append(repository) }
      updated.repositories.sort()
    }
    try Self.validatePlain(updated.name, field: "project-name")
    let name = updated.name.trimmingCharacters(in: .whitespaces)
    guard !name.isEmpty else {
      throw CredentialError("invalid-project-name", "Give the project a readable name.")
    }
    updated.name = name
    try authenticateOwner(reason)
    projects[id] = updated
    return id
  }
}
