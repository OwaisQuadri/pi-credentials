import Foundation
import Testing

@testable import CredentialsCore

let catalog = Catalog(
  credentials: [
    "tracker": Credential(
      description: "", kind: .apiKey, service: "s", hosts: ["api.tracker.example"],
      grants: ["work"]),
    "models": Credential(description: "", kind: .apiKey, service: "s", grants: ["global"]),
  ],
  groups: ["work": ["github.com/work-org/*"]])

@Test func grantsFollowRemoteGroupsAndRejectOtherProjects() {
  for remote in [
    "git@github.com:Work-Org/app.git", "https://github.com/work-org/app", "ssh://git@github.com/work-org/app/",
  ] {
    #expect(catalog.isGranted("tracker", remotes: [remote]))
  }
  for remote in [
    "https://github.com/work-org-evil/app", "https://github.com/work-org/app/extra",
    "https://github.com.evil/work-org/app", "https://github.com/other/work-org",
  ] {
    #expect(!catalog.isGranted("tracker", remotes: [remote]))
  }
  #expect(!catalog.isGranted("tracker", remotes: []))
  #expect(catalog.isGranted("models", remotes: []))
  #expect(!catalog.isGranted("missing", remotes: ["https://github.com/work-org/app"]))
}

@Test func requestsRefuseHostsOutsideTheAllowList() throws {
  let credential = try catalog.credential("tracker")
  func check(_ url: String) -> String? {
    let request = HTTPRequest(method: "GET", url: url)
    do {
      _ = try Requester.validate(request, credential: credential)
      return nil
    } catch let error as CredentialError {
      return error.code
    } catch {
      return "other"
    }
  }
  #expect(check("https://api.tracker.example/graphql") == nil)
  #expect(check("https://eu.api.tracker.example/graphql") == nil)
  #expect(check("https://api.tracker.example.evil/graphql") == "host-not-allowed")
  #expect(check("https://evilapi.tracker.example/") == "host-not-allowed")
  #expect(check("http://api.tracker.example/graphql") == "invalid-url")
  #expect(check("not a url") == "invalid-url")
}

@Test func redactionCoversPlainAndEncodedForms() {
  let secret = "sk-or-v1/abc+def?=="
  let redactor = Redactor(values: [("models", secret), ("pin", "123")])
  let base64 = Data(secret.utf8).base64EncodedString()
  let urlSafe = base64.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
  let percent = secret.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
  for form in [secret, base64, urlSafe, percent] {
    let result = redactor.redact("before \(form) after")
    #expect(result.text == "before [cred:models] after")
    #expect(result.names == ["models"])
  }
  #expect(redactor.redact("code 123").text == "code 123")
}
