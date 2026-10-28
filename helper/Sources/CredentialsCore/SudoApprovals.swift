import Foundation

public struct SudoApprovals: Sendable {
  private struct Scope: Hashable, Sendable {
    var name: String
    var cwd: String
    var target: String?
  }

  private let isSession: Bool
  private var session: String?
  private var approved: [Scope: Credential] = [:]

  public init(isSession: Bool) { self.isSession = isSession }

  public mutating func authorize(
    name: String, credential: Credential, session: String?, cwd: String?, target: String?,
    reason: String, authenticate: (String) throws -> Void
  ) throws {
    guard isSession else {
      try authenticate(reason)
      return
    }
    guard let session, !session.isEmpty, let cwd, cwd.hasPrefix("/") else {
      throw CredentialError("invalid-session", "Session root approval requires a session identifier and an absolute working directory.")
    }
    guard self.session == nil || self.session == session else {
      throw CredentialError("invalid-session", "Root approval cannot move to another Pi session.")
    }
    self.session = session
    let scope = Scope(
      name: name, cwd: URL(fileURLWithPath: cwd).resolvingSymlinksInPath().path, target: target)
    if approved[scope] == credential { return }
    let destination = target.map { "SSH \($0.debugDescription)" } ?? "this Mac"
    let subject = "allow root commands with \(name.debugDescription) on \(destination), in \(scope.cwd.debugDescription), for this Pi session"
    guard subject.count <= 400 else {
      throw CredentialError("approval-too-long", "The root session scope is too long to show in full.")
    }
    do {
      try authenticate(subject)
    } catch {
      approved.removeAll()
      throw error
    }
    approved[scope] = credential
  }
}
