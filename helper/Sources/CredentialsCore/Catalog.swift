import Foundation

public struct CredentialError: Error, CustomStringConvertible, Equatable {
  public let code: String
  public let description: String

  public init(_ code: String, _ description: String) {
    self.code = code
    self.description = description
  }
}

public enum Kind: String, Codable, CaseIterable, Sendable {
  case apiKey = "api-key"
  case password
  case appPassword = "app-password"
  case passcode
}

public struct Credential: Codable, Equatable, Sendable {
  public var description: String
  public var kind: Kind
  public var service: String
  public var account: String?
  public var hosts: [String]
  public var apps: [String]
  public var rotation: String?
  public var grants: [String]

  public init(
    description: String, kind: Kind, service: String, account: String? = nil,
    hosts: [String] = [], apps: [String] = [], rotation: String? = nil, grants: [String] = []
  ) {
    self.description = description
    self.kind = kind
    self.service = service
    self.account = account
    self.hosts = hosts
    self.apps = apps
    self.rotation = rotation
    self.grants = grants
  }
}

public struct Catalog: Codable, Equatable, Sendable {
  public static let globalScope = "global"

  public var credentials: [String: Credential] = [:]
  public var groups: [String: [String]] = [:]

  public init(credentials: [String: Credential] = [:], groups: [String: [String]] = [:]) {
    self.credentials = credentials
    self.groups = groups
  }

  public static func validateName(_ name: String) throws {
    let isValid =
      !name.isEmpty && name.count <= 64
      && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-_.".contains($0)) }
    guard isValid else {
      throw CredentialError("invalid-name", "Use 1 to 64 letters, digits, '-', '_', or '.'.")
    }
  }

  public func credential(_ name: String) throws -> Credential {
    guard let credential = credentials[name] else {
      throw CredentialError("unknown-credential", "No registered credential is named '\(name)'.")
    }
    return credential
  }

  public func groups(forRemotes remotes: [String]) -> [String] {
    let normalized = remotes.compactMap(Self.normalizeRemote)
    return groups.keys.sorted().filter { group in
      groups[group, default: []].contains { pattern in
        normalized.contains { Self.isMatch(pattern: pattern.lowercased(), remote: $0) }
      }
    }
  }

  public func isGranted(_ name: String, remotes: [String]) -> Bool {
    guard let credential = credentials[name] else { return false }
    if credential.grants.contains(Self.globalScope) { return true }
    let projectGroups = Set(groups(forRemotes: remotes))
    return credential.grants.contains { projectGroups.contains($0) }
  }

  public func grantFix(_ name: String, remotes: [String]) -> String {
    if let group = groups(forRemotes: remotes).first {
      return "/cred grant \(name) \(group)"
    }
    return "/cred grant \(name) global, or add a project group for this repository"
  }

  public static func normalizeRemote(_ remote: String) -> String? {
    var text = remote.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !text.isEmpty else { return nil }
    if let range = text.range(of: "://") {
      text = String(text[range.upperBound...])
      if let at = text.firstIndex(of: "@"), at < (text.firstIndex(of: "/") ?? text.endIndex) {
        text = String(text[text.index(after: at)...])
      }
    } else if let at = text.firstIndex(of: "@"), let colon = text.firstIndex(of: ":"), at < colon {
      text = String(text[text.index(after: at)..<colon]) + "/" + text[text.index(after: colon)...]
    }
    if text.hasSuffix(".git") { text.removeLast(4) }
    while text.hasSuffix("/") { text.removeLast() }
    return text
  }

  static func isMatch(pattern: String, remote: String) -> Bool {
    let patternParts = pattern.split(separator: "/", omittingEmptySubsequences: false)
    let remoteParts = remote.split(separator: "/", omittingEmptySubsequences: false)
    guard patternParts.count == remoteParts.count else { return false }
    return zip(patternParts, remoteParts).allSatisfy { $0 == "*" || $0 == $1 }
  }
}
