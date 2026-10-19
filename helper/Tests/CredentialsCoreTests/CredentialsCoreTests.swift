import Foundation
import Testing

@testable import CredentialsCore

let catalog = Catalog(
  credentials: [
    "tracker": Credential(
      description: "", kind: .apiKey, service: "s", hosts: ["api.tracker.example", "*.eu.example"],
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
    do {
      _ = try Requester.validate(HTTPRequest(method: "GET", url: url), credential: credential)
      return nil
    } catch let error as CredentialError {
      return error.code
    } catch {
      return "other"
    }
  }
  #expect(check("https://api.tracker.example/graphql") == nil)
  #expect(check("https://eu.example/") == nil)
  #expect(check("https://a.b.eu.example/") == nil)
  #expect(check("https://sub.api.tracker.example/graphql") == "host-not-allowed")
  #expect(check("https://api.tracker.example.evil/graphql") == "host-not-allowed")
  #expect(check("https://evileu.example/") == "host-not-allowed")
  #expect(check("http://api.tracker.example/graphql") == "invalid-url")
  #expect(check("not a url") == "invalid-url")
}

@Test func promptTextRejectsSpoofedMetadata() {
  for hosts in [["api.example.com", "*.example.org"]] {
    #expect((try? Catalog.validateHosts(hosts)) != nil)
  }
  for hosts in [["a] → [b"], ["x.example\nevil"], ["a.example\n"], ["*evil"], Array(repeating: "a.example", count: 17)] {
    #expect((try? Catalog.validateHosts(hosts)) == nil)
  }
  #expect((try? Catalog.validatePatterns(["github.com/org/*"])) != nil)
  #expect((try? Catalog.validatePatterns(["github.com/org/*; granted: none"])) == nil)
  #expect((try? Catalog.validatePlain("ok", field: "service")) != nil)
  #expect((try? Catalog.validatePlain("a\nb", field: "service")) == nil)
  #expect((try? Catalog.validatePlain("a\u{2028}b", field: "service")) == nil)
}

@Test func redactionCoversPlainAndEncodedForms() {
  let secret = "sk-or-v1/abc+dé ~x=="
  let redactor = Redactor(values: [("models", secret), ("pin", "1234567")])
  let base64 = Data(secret.utf8).base64EncodedString()
  let urlSafe = base64.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
  let strict = "sk-or-v1%2Fabc%2Bd%C3%A9%20~x%3D%3D"
  let forms = [
    secret, base64, urlSafe, strict, Redactor.lowercaseEscapes(strict),
    strict.replacingOccurrences(of: "%20", with: "+"), secret.replacingOccurrences(of: "/", with: "\\/"),
    Redactor.lowercaseEscapes(strict).replacingOccurrences(of: "%20", with: "+"),
  ] + [base64].filter { $0.contains("/") }.map { $0.replacingOccurrences(of: "/", with: "\\/") }
  for form in forms {
    let result = redactor.redact("before \(form) after")
    #expect(result.text == "before [cred:models] after", "form: \(form)")
    #expect(result.names == ["models"])
  }
  #expect(redactor.redact("code 1234567").text == "code 1234567")
}
