import AppKit
import ApplicationServices
import CredentialsCore
import Foundation

struct ProcessResult: Encodable {
  var status: Int32
  var stdout: String
  var stderr: String
  var isTruncated: Bool
  var isTimedOut: Bool
}

let outputLimit = 1_000_000

final class DataBox: @unchecked Sendable {
  var data = Data()
}

func runProcess(
  _ executable: String, _ arguments: [String], input: Data, cwd: String?, timeout: TimeInterval,
  redactor: Redactor
) throws -> ProcessResult {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: executable)
  process.arguments = arguments
  if let cwd { process.currentDirectoryURL = URL(fileURLWithPath: cwd) }
  let stdin = Pipe()
  let stdout = Pipe()
  let stderr = Pipe()
  process.standardInput = stdin
  process.standardOutput = stdout
  process.standardError = stderr
  try process.run()
  stdin.fileHandleForWriting.write(input)
  try? stdin.fileHandleForWriting.close()
  let group = DispatchGroup()
  let outBox = DataBox()
  let errBox = DataBox()
  for (pipe, box) in [(stdout, outBox), (stderr, errBox)] {
    group.enter()
    let handle = pipe.fileHandleForReading
    DispatchQueue.global().async {
      box.data = handle.readDataToEndOfFile()
      group.leave()
    }
  }
  let isTimedOut = group.wait(timeout: .now() + timeout) == .timedOut
  if isTimedOut {
    process.terminate()
    group.wait()
  }
  process.waitUntilExit()
  let outData = outBox.data
  let errData = errBox.data
  func text(_ data: Data) -> (String, Bool) {
    let redacted = redactor.redact(String(decoding: data, as: UTF8.self)).text
    let bytes = Data(redacted.utf8)
    guard bytes.count > outputLimit else { return (redacted, false) }
    return (String(decoding: bytes.prefix(outputLimit), as: UTF8.self), true)
  }
  let (out, isOutTruncated) = text(outData)
  let (err, isErrTruncated) = text(errData)
  return ProcessResult(
    status: process.terminationStatus, stdout: out, stderr: err,
    isTruncated: isOutTruncated || isErrTruncated, isTimedOut: isTimedOut)
}

let notarySubcommands: Set<String> = ["submit", "info", "wait", "log", "history"]

func notarize(_ arguments: [String], value: String, cwd: String?, redactor: Redactor) throws
  -> ProcessResult
{
  guard let subcommand = arguments.first, notarySubcommands.contains(subcommand) else {
    throw CredentialError(
      "invalid-arguments", "Start with one of: \(notarySubcommands.sorted().joined(separator: ", ")).")
  }
  let forbidden = ["--password", "-p", "--keychain-profile", "--keychain", "--key", "--key-id", "--issuer"]
  guard !arguments.contains(where: { argument in forbidden.contains { argument == $0 || argument.hasPrefix($0 + "=") } }),
    arguments.contains("--apple-id"), arguments.contains("--team-id")
  else {
    throw CredentialError(
      "invalid-arguments", "Pass --apple-id and --team-id. The helper supplies the password.")
  }
  return try runProcess(
    "/usr/bin/xcrun", ["notarytool"] + arguments, input: Data((value + "\n").utf8), cwd: cwd,
    timeout: 3600, redactor: redactor)
}

func runSudo(_ command: [String], value: String, cwd: String?, timeout: TimeInterval, redactor: Redactor)
  throws -> ProcessResult
{
  guard let first = command.first, !first.isEmpty else {
    throw CredentialError("missing-field", "Provide the command to run as an argument list.")
  }
  return try runProcess(
    "/usr/bin/sudo", ["-S", "-k", "-p", "", "--"] + command, input: Data((value + "\n").utf8),
    cwd: cwd, timeout: timeout, redactor: redactor)
}

func describeCommand(_ command: [String]) -> String {
  command.map { argument in
    argument.allSatisfy({ $0.isLetter || $0.isNumber || "-_./=:@%+,".contains($0) })
      ? argument : argument.debugDescription
  }.joined(separator: " ")
}

func typeValue(_ value: String, into app: String, credential: Credential, isActivating: Bool, isReturnPressed: Bool)
  throws -> String
{
  let isAllowed =
    credential.apps.isEmpty
    || credential.apps.contains { $0.caseInsensitiveCompare(app) == .orderedSame }
  guard isAllowed else {
    throw CredentialError(
      "app-not-allowed", "Typing is limited to: \(credential.apps.joined(separator: ", ")).")
  }
  guard AXIsProcessTrusted() else {
    throw CredentialError(
      "accessibility-required",
      "Allow \(CommandLine.arguments[0]) in System Settings > Privacy & Security > Accessibility, then try again.")
  }
  guard
    let target = NSWorkspace.shared.runningApplications.first(where: {
      $0.bundleIdentifier?.caseInsensitiveCompare(app) == .orderedSame
        || $0.localizedName?.caseInsensitiveCompare(app) == .orderedSame
    })
  else {
    throw CredentialError("app-not-running", "No running app matches '\(app)'.")
  }
  if isActivating {
    target.activate()
    let deadline = Date().addingTimeInterval(3)
    while NSWorkspace.shared.frontmostApplication?.processIdentifier != target.processIdentifier,
      Date() < deadline
    {
      RunLoop.current.run(until: Date().addingTimeInterval(0.05))
    }
    guard NSWorkspace.shared.frontmostApplication?.processIdentifier == target.processIdentifier else {
      throw CredentialError("focus-failed", "'\(app)' did not come to the front.")
    }
  }
  let source = CGEventSource(stateID: .hidSystemState)
  func post(_ event: CGEvent?) {
    guard let event else { return }
    if isActivating { event.post(tap: .cghidEventTap) } else { event.postToPid(target.processIdentifier) }
    usleep(8000)
  }
  for character in value {
    let units = Array(String(character).utf16)
    for isDown in [true, false] {
      let event = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: isDown)
      event?.keyboardSetUnicodeString(stringLength: units.count, unicodeString: units)
      post(event)
    }
  }
  if isReturnPressed {
    post(CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true))
    post(CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false))
  }
  return target.bundleIdentifier ?? target.localizedName ?? app
}

let envKinds: Set<Kind> = [.apiKey, .appPassword]

func isEnvFileName(_ path: String) -> Bool {
  let base = (path as NSString).lastPathComponent
  return base == ".env" || (base.hasPrefix(".env.") && !base.contains("/"))
}

func isIgnoredByGit(_ path: String) -> Bool {
  let directory = (path as NSString).deletingLastPathComponent
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = ["-C", directory, "check-ignore", "-q", "--no-index", path]
  process.standardOutput = FileHandle.nullDevice
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return false }
  process.waitUntilExit()
  return process.terminationStatus == 0
}

func isInsideGitRepository(_ directory: String) -> Bool {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = ["-C", directory, "rev-parse", "--is-inside-work-tree"]
  process.standardOutput = FileHandle.nullDevice
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return false }
  process.waitUntilExit()
  return process.terminationStatus == 0
}

func envLine(_ name: String, _ value: String) -> String {
  let isPlain = value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "_-./+=:@".contains($0)) }
  if isPlain { return "\(name)=\(value)" }
  let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
    .replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "$", with: "\\$")
  return "\(name)=\"\(escaped)\""
}

func writeEnvFile(_ path: String, lines: [String]) throws {
  let directory = (path as NSString).deletingLastPathComponent
  let temporary = directory + "/.pi-credentials-\(UUID().uuidString).tmp"
  let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
  guard descriptor >= 0 else {
    throw CredentialError("write-failed", "Could not write in \(directory): \(String(cString: strerror(errno))).")
  }
  let data = Data((lines.joined(separator: "\n") + "\n").utf8)
  let written = data.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
  close(descriptor)
  guard written == data.count, rename(temporary, path) == 0 else {
    unlink(temporary)
    throw CredentialError("write-failed", "Could not write \(path).")
  }
}
