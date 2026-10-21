import AppKit
import ApplicationServices
import CredentialsCore
import Foundation
import Security

struct ProcessResult: Encodable {
  var status: Int32
  var stdout: String
  var stderr: String
  var isTruncated: Bool
  var isTimedOut: Bool
}

let outputLimit = 1_000_000

final class Cancellation: @unchecked Sendable {
  static let shared = Cancellation()
  private let lock = NSLock()
  private var isCancelledValue = false
  private var isExitAllowedValue = true
  private var requestCancellation: (@Sendable () -> Void)?

  var isCancelled: Bool {
    lock.lock()
    defer { lock.unlock() }
    return isCancelledValue
  }

  func cancel() {
    lock.lock()
    isCancelledValue = true
    let isExitAllowed = isExitAllowedValue
    let cancelRequest = requestCancellation
    lock.unlock()
    cancelRequest?()
    if isExitAllowed { _exit(130) }
  }

  private func setRequestCancellation(_ action: (@Sendable () -> Void)?, isExitAllowed: Bool) {
    lock.lock()
    isExitAllowedValue = isExitAllowed
    requestCancellation = action
    let isCancelled = isCancelledValue
    lock.unlock()
    if isCancelled { action?() }
  }

  func guardedRequest<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) async throws
    -> T
  {
    setRequestCancellation(nil, isExitAllowed: false)
    defer { setRequestCancellation(nil, isExitAllowed: true) }
    let task = Task { try await body() }
    setRequestCancellation({ task.cancel() }, isExitAllowed: false)
    return try await task.value
  }

  func guarded<T>(_ body: () throws -> T) rethrows -> T {
    lock.lock()
    isExitAllowedValue = false
    let isCancelled = isCancelledValue
    lock.unlock()
    defer {
      lock.lock()
      isExitAllowedValue = true
      lock.unlock()
    }
    if isCancelled { _exit(130) }
    return try body()
  }
}

func installCancellation() -> [DispatchSourceSignal] {
  signal(SIGPIPE) { _ in }
  return [SIGTERM, SIGINT, SIGHUP].map { number in
    signal(number) { _ in }
    let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
    source.setEventHandler { Cancellation.shared.cancel() }
    source.resume()
    return source
  }
}

final class OutputBuffer: @unchecked Sendable {
  private let lock = NSLock()
  private var data = Data()
  private var isOverflowed = false
  let limit: Int
  let finished = DispatchSemaphore(value: 0)

  init(limit: Int) { self.limit = limit }

  func append(_ chunk: Data) {
    lock.lock()
    defer { lock.unlock() }
    let room = limit - data.count
    if chunk.count > room {
      data.append(chunk.prefix(max(room, 0)))
      isOverflowed = true
    } else {
      data.append(chunk)
    }
  }

  var snapshot: (data: Data, isOverflowed: Bool) {
    lock.lock()
    defer { lock.unlock() }
    return (data, isOverflowed)
  }
}

func runProcess(
  _ executable: String, _ arguments: [String], input: Data?, cwd: String?, timeout: TimeInterval,
  redactor: Redactor, isCancellable: Bool = true, stop: ((pid_t, Int32) -> Void)? = nil,
  normalizeStatus: ((Int32, Process.TerminationReason) -> Int32)? = nil
) throws -> ProcessResult {
  if isCancellable && Cancellation.shared.isCancelled {
    throw CredentialError("cancelled", "The action was cancelled.")
  }
  let process = Process()
  process.executableURL = URL(fileURLWithPath: executable)
  process.arguments = arguments
  if let cwd { process.currentDirectoryURL = URL(fileURLWithPath: cwd) }
  let stdin = Pipe()
  let outputs = [Pipe(), Pipe()]
  let buffers = [0, 1].map { _ in OutputBuffer(limit: outputLimit + redactor.longestForm) }
  process.standardInput = input == nil ? FileHandle.nullDevice : stdin
  process.standardOutput = outputs[0]
  process.standardError = outputs[1]
  for (pipe, buffer) in zip(outputs, buffers) {
    pipe.fileHandleForReading.readabilityHandler = { handle in
      let chunk = handle.availableData
      if chunk.isEmpty {
        handle.readabilityHandler = nil
        buffer.finished.signal()
      } else {
        buffer.append(chunk)
      }
    }
  }
  let exited = DispatchSemaphore(value: 0)
  process.terminationHandler = { _ in exited.signal() }
  try process.run()
  if let input {
    let writer = stdin.fileHandleForWriting
    DispatchQueue.global().async {
      try? writer.write(contentsOf: input)
      try? writer.close()
    }
  }
  let deadline = Date().addingTimeInterval(timeout)
  var isTimedOut = false
  while exited.wait(timeout: .now() + 0.2) == .timedOut {
    let isCancelled = isCancellable && Cancellation.shared.isCancelled
    guard isCancelled || Date() >= deadline else { continue }
    isTimedOut = !isCancelled
    let pid = process.processIdentifier
    if let stop { stop(pid, SIGTERM) } else { process.terminate() }
    if exited.wait(timeout: .now() + 3) == .timedOut {
      if let stop { stop(pid, SIGKILL) } else { kill(pid, SIGKILL) }
      _ = exited.wait(timeout: .now() + 3)
    }
    break
  }
  var isDrained = true
  for buffer in buffers where buffer.finished.wait(timeout: .now() + 2) == .timedOut {
    isDrained = false
  }
  if !isDrained {
    for pipe in outputs { pipe.fileHandleForReading.readabilityHandler = nil }
  }
  func text(_ buffer: OutputBuffer) -> (String, Bool) {
    let (data, isOverflowed) = buffer.snapshot
    let redacted = redactor.redact(String(decoding: data, as: UTF8.self)).text
    let bytes = Data(redacted.utf8)
    guard bytes.count > outputLimit || isOverflowed || !isDrained else { return (redacted, false) }
    return (String(decoding: bytes.prefix(outputLimit), as: UTF8.self), true)
  }
  let (out, isOutTruncated) = text(buffers[0])
  let (err, isErrTruncated) = text(buffers[1])
  let status: Int32
  if process.isRunning {
    status = -1
  } else if let normalizeStatus {
    status = normalizeStatus(process.terminationStatus, process.terminationReason)
  } else {
    status = process.terminationStatus
  }
  return ProcessResult(
    status: status, stdout: out, stderr: err,
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

let securePath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]

func isRootProtected(_ path: String) -> Bool {
  var current = path
  while true {
    var info = stat()
    guard lstat(current, &info) == 0, info.st_uid == 0, info.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
      return false
    }
    if current == "/" { return true }
    current = (current as NSString).deletingLastPathComponent
    if current.isEmpty { current = "/" }
  }
}

func realPath(_ path: String) -> String? {
  guard let pointer = realpath(path, nil) else { return nil }
  defer { free(pointer) }
  return String(cString: pointer)
}

func resolveProgram(_ program: String) throws -> String {
  if program.hasPrefix("/") {
    guard let resolved = realPath(program), FileManager.default.isExecutableFile(atPath: resolved),
      isRootProtected(resolved)
    else {
      throw CredentialError(
        "invalid-arguments",
        "\(program) must be an executable that root owns, in directories that only root can change.")
    }
    return resolved
  }
  guard !program.contains("/"),
    let found = securePath.map({ $0 + "/" + program }).first(where: FileManager.default.isExecutableFile)
  else {
    throw CredentialError(
      "invalid-arguments",
      "'\(program)' is not in \(securePath.joined(separator: ":")). Pass the program's absolute path.")
  }
  return found
}

func processTree(_ root: pid_t, redactor: Redactor) -> [pid_t] {
  var found = [root]
  var index = 0
  while index < found.count && found.count < 4096 {
    let parent = found[index]
    index += 1
    guard
      let result = try? runProcess(
        "/usr/bin/pgrep", ["-P", String(parent)], input: nil, cwd: nil, timeout: 5, redactor: redactor,
        isCancellable: false)
    else { continue }
    for line in result.stdout.split(separator: "\n") {
      if let child = pid_t(line.trimmingCharacters(in: .whitespaces)), !found.contains(child) { found.append(child) }
    }
  }
  return found
}

func runSudo(_ command: [String], value: String, cwd: String?, timeout: TimeInterval, redactor: Redactor)
  throws -> ProcessResult
{
  defer {
    _ = try? runProcess(
      "/usr/bin/sudo", ["-k"], input: nil, cwd: nil, timeout: 10, redactor: redactor, isCancellable: false)
  }
  let validation = try runProcess(
    "/usr/bin/sudo", ["-S", "-v", "-p", ""], input: Data((value + "\n").utf8), cwd: cwd, timeout: 60,
    redactor: redactor)
  guard !Cancellation.shared.isCancelled else {
    throw CredentialError("cancelled", "The action was cancelled before the command ran.")
  }
  guard !validation.isTimedOut else {
    throw CredentialError("sudo-timeout", "sudo did not finish checking the password within 60 seconds.")
  }
  guard validation.status == 0 else {
    throw CredentialError("sudo-refused", "sudo did not accept the password.")
  }
  let result = try runProcess(
    "/usr/bin/sudo", ["-n", "--"] + command, input: nil, cwd: cwd, timeout: timeout, redactor: redactor,
    stop: { pid, number in
      let tree = processTree(pid, redactor: redactor)
      for target in tree { kill(target, number) }
      let targets = tree.map(String.init)
      _ = try? runProcess(
        "/usr/bin/sudo", ["-S", "-p", "", "--", "/bin/kill", "-\(number)"] + targets,
        input: Data((value + "\n").utf8), cwd: nil, timeout: 30, redactor: redactor, isCancellable: false)
    })
  if result.status == 1 && result.stderr.hasPrefix("sudo: a password is required") {
    throw CredentialError(
      "sudo-no-timestamp",
      "sudo did not keep the approval between steps. Check timestamp_timeout in sudoers; it must be above 0.")
  }
  return result
}

func runSSHSudo(
  _ command: SSHSudoCommand, value: String, cwd: String?, timeout: TimeInterval, redactor: Redactor
) throws -> ProcessResult {
  try runProcess(
    "/usr/bin/ssh", command.sshArguments, input: Data((value + "\n").utf8), cwd: cwd,
    timeout: timeout, redactor: redactor, normalizeStatus: SSHSudoCommand.normalizedStatus)
}

func describeCommand(_ command: [String]) -> String {
  command.map { argument in
    let isPlain =
      !argument.isEmpty
      && argument.unicodeScalars.allSatisfy {
        $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "-_./=:@%+,".unicodeScalars.contains($0))
      }
    if isPlain { return argument }
    let escaped = argument.unicodeScalars.map { scalar -> String in
      if scalar == "\"" || scalar == "\\" { return "\\" + String(scalar) }
      if scalar.isASCII && scalar.value >= 32 && scalar.value < 127 { return String(scalar) }
      return "\\u{\(String(scalar.value, radix: 16))}"
    }.joined()
    return "\"\(escaped)\""
  }.joined(separator: " ")
}

func isAppleSigned(_ pid: pid_t, identifier: String) -> Bool {
  var code: SecCode?
  let attributes = [kSecGuestAttributePid: pid] as CFDictionary
  guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
    return false
  }
  var requirement: SecRequirement?
  let text = "anchor apple generic and identifier \(identifier.debugDescription)"
  guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess
  else { return false }
  return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
}

func frontmostPid() -> pid_t? {
  let system = AXUIElementCreateSystemWide()
  var focused: CFTypeRef?
  guard AXUIElementCopyAttributeValue(system, kAXFocusedApplicationAttribute as CFString, &focused) == .success,
    let focused, CFGetTypeID(focused) == AXUIElementGetTypeID()
  else { return NSWorkspace.shared.frontmostApplication?.processIdentifier }
  var pid: pid_t = 0
  AXUIElementGetPid(focused as! AXUIElement, &pid)
  return pid
}

func typeValue(
  _ value: String, name: String, into app: String, credential: Credential, isActivating: Bool, isReturnPressed: Bool
)
  throws -> String
{
  guard AXIsProcessTrusted() else {
    throw CredentialError(
      "accessibility-required",
      "Allow \(CommandLine.arguments[0]) in System Settings > Privacy & Security > Accessibility, then try again.")
  }
  let matches = NSWorkspace.shared.runningApplications.filter {
    $0.bundleIdentifier?.caseInsensitiveCompare(app) == .orderedSame
      || $0.localizedName?.caseInsensitiveCompare(app) == .orderedSame
  }
  guard let target = matches.first else {
    throw CredentialError("app-not-running", "No running app matches '\(app)'.")
  }
  guard matches.count == 1 else {
    throw CredentialError("app-ambiguous", "\(matches.count) running apps match '\(app)'. Use a bundle identifier.")
  }
  let identity = target.bundleIdentifier ?? ""
  guard !credential.apps.isEmpty else {
    throw CredentialError(
      "apps-required", "Typing needs an allowed-apps list. Ask the user to run: /cred edit \(name) and set apps.")
  }
  guard credential.apps.contains(where: { $0.caseInsensitiveCompare(identity) == .orderedSame }) else {
    throw CredentialError(
      "app-not-allowed", "'\(identity)' is not in the allowed apps: \(credential.apps.joined(separator: ", ")).")
  }
  guard isAppleSigned(target.processIdentifier, identifier: identity) else {
    throw CredentialError("app-unsigned", "'\(identity)' does not have a valid Apple-issued signature.")
  }
  if isActivating {
    target.activate()
    let deadline = Date().addingTimeInterval(3)
    var isReopened = false
    while frontmostPid() != target.processIdentifier, Date() < deadline {
      if !isReopened, Date() > deadline.addingTimeInterval(-2), let url = target.bundleURL {
        isReopened = true
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: url, configuration: configuration)
      }
      RunLoop.current.run(until: Date().addingTimeInterval(0.05))
    }
  }
  let source = CGEventSource(stateID: .hidSystemState)
  func post(_ event: CGEvent?) throws {
    guard let event else { return }
    if isActivating && frontmostPid() != target.processIdentifier {
      throw CredentialError("focus-lost", "'\(identity)' lost focus, so typing stopped.")
    }
    event.postToPid(target.processIdentifier)
    usleep(8000)
  }
  let digitKeys: [Character: CGKeyCode] = [
    "0": 29, "1": 18, "2": 19, "3": 20, "4": 21, "5": 23, "6": 22, "7": 26, "8": 28, "9": 25,
  ]
  for character in value {
    let units = Array(String(character).utf16)
    for isDown in [true, false] {
      let event = CGEvent(keyboardEventSource: source, virtualKey: digitKeys[character] ?? 0, keyDown: isDown)
      event?.keyboardSetUnicodeString(stringLength: units.count, unicodeString: units)
      try post(event)
    }
  }
  if isReturnPressed {
    try post(CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true))
    try post(CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false))
  }
  return identity.isEmpty ? (target.localizedName ?? app) : identity
}

let envKinds: Set<Kind> = [.apiKey, .appPassword]
let templateSuffixes = [".example", ".sample", ".template", ".dist"]

func isEnvFileName(_ path: String) -> Bool {
  let base = (path as NSString).lastPathComponent.lowercased()
  guard base == ".env" || base.hasPrefix(".env.") else { return false }
  return !templateSuffixes.contains { base.hasSuffix($0) }
}

func git(_ directory: String, _ arguments: [String]) -> Int32 {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = ["-C", directory] + arguments
  process.standardOutput = FileHandle.nullDevice
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return -1 }
  process.waitUntilExit()
  return process.terminationStatus
}

func requireUncommittable(_ path: String) throws {
  let directory = (path as NSString).deletingLastPathComponent
  guard git(directory, ["rev-parse", "--is-inside-work-tree"]) == 0 else { return }
  guard git(directory, ["ls-files", "--error-unmatch", "--", path]) != 0 else {
    throw CredentialError("tracked", "Git tracks \(path). Remove it from the index first: git rm --cached.")
  }
  guard git(directory, ["check-ignore", "-q", "--", path]) == 0 else {
    throw CredentialError("not-ignored", "Git does not ignore \(path). Add it to .gitignore first.")
  }
}

func envLine(_ name: String, _ value: String) -> String {
  let isPlain = value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "_-./+=:@".contains($0)) }
  if isPlain { return "\(name)=\(value)" }
  if !value.contains("'") && !value.contains("\n") { return "\(name)='\(value)'" }
  let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
    .replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "$", with: "\\$")
    .replacingOccurrences(of: "`", with: "\\`").replacingOccurrences(of: "\n", with: "\\n")
  return "\(name)=\"\(escaped)\""
}

func mergeEnvFile(_ path: String, lines: [(name: String, line: String)]) throws {
  var info = stat()
  if lstat(path, &info) == 0 && (info.st_mode & S_IFMT) != S_IFREG {
    throw CredentialError("invalid-path", "\(path) exists and is not a regular file.")
  }
  let existing = (FileManager.default.contents(atPath: path)).map { String(decoding: $0, as: UTF8.self) } ?? ""
  let managed = Set(lines.map(\.name))
  var output = existing.split(separator: "\n", omittingEmptySubsequences: false).map(String.init).filter { line in
    let key = line.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "export ", with: "")
      .split(separator: "=", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) }
    return key.map { !managed.contains($0) } ?? true
  }
  while output.last == "" { output.removeLast() }
  output += lines.map(\.line)
  let directory = (path as NSString).deletingLastPathComponent
  let temporary = directory + "/.pi-credentials-\(UUID().uuidString).tmp"
  let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
  guard descriptor >= 0 else {
    throw CredentialError("write-failed", "Could not write in \(directory): \(String(cString: strerror(errno))).")
  }
  let data = Data((output.joined(separator: "\n") + "\n").utf8)
  let written = data.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
  close(descriptor)
  guard written == data.count, rename(temporary, path) == 0 else {
    unlink(temporary)
    throw CredentialError("write-failed", "Could not write \(path).")
  }
}
