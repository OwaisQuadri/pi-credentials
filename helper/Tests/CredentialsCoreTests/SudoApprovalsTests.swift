import Foundation
import Testing

@testable import CredentialsCore

private func passwordCredential() -> Credential {
  Credential(description: "Root test", kind: .password, service: "test", grants: ["global"])
}

@Test func rootApprovalIsReusedOnlyForTheSameLiveSessionAndScope() throws {
  var approvals = SudoApprovals(isSession: true)
  let credential = passwordCredential()
  var prompts: [String] = []
  func authorize(name: String = "test", cwd: String = "/", target: String? = "server") throws {
    try approvals.authorize(
      name: name, credential: credential, session: "session-one", cwd: cwd, target: target,
      reason: "first command", authenticate: { prompts.append($0) })
  }
  try authorize()
  try authorize()
  #expect(prompts.count == 1)
  #expect(prompts[0].contains("Pi session"))
  #expect(prompts[0].contains("\"test\""))
  #expect(prompts[0].contains("SSH \"server\""))
  try authorize(target: nil)
  try authorize(target: "other-server")
  try authorize(name: "other-credential")
  try authorize(cwd: "/tmp")
  #expect(prompts.count == 5)
  #expect(throws: CredentialError.self) {
    try approvals.authorize(
      name: "test", credential: credential, session: "session-two", cwd: "/", target: "server",
      reason: "other session", authenticate: { prompts.append($0) })
  }
  #expect(prompts.count == 5)
}

@Test func rootApprovalDoesNotCacheRefusalOrSurviveMetadataChangeOrNewHelper() throws {
  var approvals = SudoApprovals(isSession: true)
  var credential = passwordCredential()
  var attempts = 0
  #expect(throws: CredentialError.self) {
    try approvals.authorize(
      name: "test", credential: credential, session: "one", cwd: "/", target: nil,
      reason: "command", authenticate: { _ in
        attempts += 1
        throw CredentialError("auth-denied", "Denied")
      })
  }
  try approvals.authorize(
    name: "test", credential: credential, session: "one", cwd: "/", target: nil,
    reason: "retry", authenticate: { _ in attempts += 1 })
  #expect(attempts == 2)
  credential.grants = ["project:changed"]
  try approvals.authorize(
    name: "test", credential: credential, session: "one", cwd: "/", target: nil,
    reason: "changed grant", authenticate: { _ in attempts += 1 })
  #expect(attempts == 3)
  approvals = SudoApprovals(isSession: true)
  try approvals.authorize(
    name: "test", credential: credential, session: "one", cwd: "/", target: nil,
    reason: "new helper", authenticate: { _ in attempts += 1 })
  #expect(attempts == 4)
}

@Test func declinedRootAuthenticationClearsEveryEarlierScope() throws {
  var approvals = SudoApprovals(isSession: true)
  let credential = passwordCredential()
  var prompts = 0
  func authorize(target: String, isDenied: Bool = false) throws {
    try approvals.authorize(
      name: "test", credential: credential, session: "one", cwd: "/", target: target,
      reason: "command", authenticate: { _ in
        prompts += 1
        if isDenied { throw CredentialError("auth-denied", "Denied") }
      })
  }
  try authorize(target: "one")
  try authorize(target: "two")
  #expect(throws: CredentialError.self) {
    try authorize(target: "three", isDenied: true)
  }
  try authorize(target: "one")
  try authorize(target: "two")
  try authorize(target: "one")
  #expect(prompts == 5)
}

@Test func oneShotRootApprovalStillAuthenticatesEachCommand() throws {
  var approvals = SudoApprovals(isSession: false)
  var prompts: [String] = []
  for _ in 0..<2 {
    try approvals.authorize(
      name: "test", credential: passwordCredential(), session: nil, cwd: nil, target: nil,
      reason: "exact command", authenticate: { prompts.append($0) })
  }
  #expect(prompts == ["exact command", "exact command"])
}

@Test func rootSessionRefusesMissingIdentityAndUnshowableScope() throws {
  var approvals = SudoApprovals(isSession: true)
  var prompts = 0
  let invalid: [(String?, String?)] = [(nil, "/"), ("", "/"), ("one", nil), ("one", "relative")]
  for (session, cwd) in invalid {
    #expect(throws: CredentialError.self) {
      try approvals.authorize(
        name: "test", credential: passwordCredential(), session: session, cwd: cwd, target: nil,
        reason: "command", authenticate: { _ in prompts += 1 })
    }
  }
  #expect(throws: CredentialError.self) {
    try approvals.authorize(
      name: "test", credential: passwordCredential(), session: "one", cwd: "/",
      target: String(repeating: "x", count: 500), reason: "command",
      authenticate: { _ in prompts += 1 })
  }
  #expect(prompts == 0)
}
