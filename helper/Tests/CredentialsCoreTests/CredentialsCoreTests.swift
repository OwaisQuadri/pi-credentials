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
  #expect(
    (try? Catalog.validatePlain("a" + String(repeating: "\u{0301}", count: 300), field: "service")) == nil)
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

@Test func leakScanFindsRegisteredAndUnknownKeysOnly() {
  let registered = "sk-or-v1-Zq8Wm3Rt7Yp2Lk5Hn9Bv4Cx6Dj1Fg0Ss8Ee3Aa7Uu2Ii5Oo9"
  let unknown = "lin_api_Q7mZr2Kp9Lw4Vx8Nb3Jt6Hc1Fd5Gs0YeUi"
  let scanner = LeakScanner(redactor: Redactor(values: [("router", registered)]))
  let encoded = Data(registered.utf8).base64EncodedString()
  let text = "{\"text\":\"\(encoded) and \(registered) then \(unknown); task-sk-" + String(repeating: "x", count: 40) + "\"}"
  let findings = scanner.scan(Data(text.utf8))
  #expect(findings.names == ["router"])
  #expect(findings.unknown == [LeakScanner.fingerprint(unknown): "lin_api_"])
  #expect(findings.registered == [LeakScanner.fingerprint(registered): "router"])
  let scrubbed = String(decoding: scanner.scrub(Data(text.utf8)), as: UTF8.self)
  #expect(!scrubbed.contains(registered) && !scrubbed.contains(encoded) && !scrubbed.contains(unknown))
  let rescanned = scanner.scan(Data(scrubbed.utf8))
  #expect(rescanned.names == findings.names && rescanned.unknown == findings.unknown)
  #expect(scanner.scan(Data("no keys here: sk-short".utf8)).isEmpty)
}

@Test func leakScanSkipsPlaceholderKeys() {
  let scanner = LeakScanner(redactor: Redactor(values: []))
  for text in ["sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "sk-proj-your-key-goes-here-1234567890abcdefgh", "ghp_" + String(repeating: "A", count: 36)] {
    #expect(scanner.scan(Data(text.utf8)).isEmpty, "\(text)")
  }
  let real = "sk-ant-api03-Q7mZr2Kp9Lw4testVx8Nb3Jt6Hc1Fd5Gs0YeUiR4oP"
  #expect(scanner.scan(Data(real.utf8)).unknown == [LeakScanner.fingerprint(real): "sk-ant-"])
}

@Test func leakScanFindsKeysAfterEscapedLineBreaks() {
  let scanner = LeakScanner(redactor: Redactor(values: []))
  let key = "sk-ant-api03-Q7mZr2Kp9Lw4Vx8Nb3Jt6Hc1Fd5Gs0YeUiR4oP"
  for escape in ["\\n", "\\r", "\\t"] {
    let text = "{\"text\":\"key:\(escape)\(key)\"}"
    #expect(scanner.scan(Data(text.utf8)).unknown == [LeakScanner.fingerprint(key): "sk-ant-"], "\(escape)")
    #expect(!String(decoding: scanner.scrub(Data(text.utf8)), as: UTF8.self).contains(key))
  }
  #expect(scanner.scan(Data("{\"text\":\"plainsk-ant-api03-Q7mZr2Kp9Lw4Vx8Nb3Jt6Hc1Fd5\"}".utf8)).isEmpty)
}

@Test func scanEntryKeepsFirstSeenWhenRegisteredValueBecomesUnknown() {
  let fingerprint = "0123456789ab"
  var before = LeakFindings()
  before.registered = [fingerprint: "router"]
  let first = ScanEntry(mtime: 100, findings: before, previous: nil)
  var after = LeakFindings()
  after.unknown = [fingerprint: "sk-or-v1-"]
  let second = ScanEntry(mtime: 500, findings: after, previous: first)
  #expect(second.seen("key:" + fingerprint) == 100)
  #expect(second.findings.registered == [fingerprint: "router"])
}

@Test func sessionRootsRejectEmptyRelativeAndCoveredFolders() {
  let base = "/Users/u/.pi/agent/sessions"
  #expect(addingSessionRoot("", to: [], defaultRoot: base).isEmpty)
  #expect(addingSessionRoot("relative/dir", to: [""], defaultRoot: base).isEmpty)
  #expect(addingSessionRoot(base + "/--cwd--", to: [], defaultRoot: base).isEmpty)
  #expect(addingSessionRoot("/tmp/s/", to: [""], defaultRoot: base) == ["/tmp/s"])
  #expect(isSessionFile("/a/b.jsonl") && !isSessionFile("/a/.env") && !isSessionFile("/a/b.jsonl.pi-credentials-X"))
}
