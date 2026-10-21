import Foundation
import Testing

@testable import CredentialsCore

@Test func remoteTargetCannotInjectSSHOptions() throws {
  for target in ["", "-host", "user@", "@host", "a@b@c", "host:22", "[::1]", "ssh://host", "host/path", "host%h", "a b", "a\n", "a;id", "é", String(repeating: "a", count: 256)] {
    #expect(throws: CredentialError.self) { try SSHSudoCommand(target: target, arguments: ["/bin/true"]) }
  }
  for arguments in [[], ["id"], ["/bin/id", "bad\0arg"]] {
    #expect(throws: CredentialError.self) { try SSHSudoCommand(target: "host", arguments: arguments) }
  }
  let command = try SSHSudoCommand(target: "_user@host-alias.example", arguments: ["/bin/id"])
  let expected = [
    "BatchMode=yes", "PreferredAuthentications=publickey", "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no", "NumberOfPasswordPrompts=0", "StrictHostKeyChecking=yes",
    "VerifyHostKeyDNS=no", "UpdateHostKeys=no", "RequestTTY=no", "StdinNull=no",
    "SessionType=default", "ForkAfterAuthentication=no", "RemoteCommand=none",
    "PermitLocalCommand=no", "ForwardAgent=no", "ClearAllForwardings=yes", "ControlMaster=no",
    "ControlPath=none", "ControlPersist=no",
  ]
  #expect(Array(command.sshArguments.dropLast(2)) == ["-T"] + expected.flatMap { ["-o", $0] })
  #expect(command.sshArguments.dropLast().last == command.target)
}

@Test func signalledSSHStatusCannotMasqueradeAsRemoteExitNine() throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: directory) }
  for (script, reason, expectedStatus) in [
    ("exit 9", Process.TerminationReason.exit, Int32(9)),
    ("kill -KILL $$", Process.TerminationReason.uncaughtSignal, Int32(-1)),
  ] {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-f", "-c", script]
    process.environment = ["HOME": directory.path, "ZDOTDIR": directory.path, "PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 9)
    #expect(process.terminationReason == reason)
    #expect(SSHSudoCommand.normalizedStatus(process.terminationStatus, terminationReason: process.terminationReason) == expectedStatus)
  }
}

@Test func remoteArgvCannotExecuteSyntaxOrReadLeftoverValidationInput() throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: directory) }
  let sudo = directory.appendingPathComponent("sudo")
  let recorder = directory.appendingPathComponent("record")
  let output = directory.appendingPathComponent("output")
  let parents = directory.appendingPathComponent("parents")
  let injection = directory.appendingPathComponent("injected")
  try """
    #!/bin/zsh -f
    printf '%s\\n' "$PPID" >> "$PARENTS"
    case "$1 $2" in
      '-n -k') [ "$MODE" != invalidation ] ;;
      '-S -v')
        [ "$MODE" != refusal ] || exit 1
        if [ "$MODE" = consuming ]; then cat >/dev/null; fi ;;
      '-n --') shift 2; "$@" ;;
      *) exit 99 ;;
    esac
    """.write(to: sudo, atomically: true, encoding: .utf8)
  try """
    #!/bin/zsh -f
    printf '%s\\0' "$@" > "$OUTPUT"
    if IFS= read -r leftover; then exit 90; fi
    for descriptor in 3 4 5 6 7 8 9; do
      if (eval "IFS= read -r leftover <&$descriptor") 2>/dev/null; then exit 91; fi
    done
    exit 37
    """.write(to: recorder, atomically: true, encoding: .utf8)
  for url in [sudo, recorder] {
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
  }
  let arguments = [recorder.path, "", "apostrophe'", "line\nbreak", "$HOME", "$(touch \(injection.path))", "`id`", "\\", "; & | > < *"]
  let command = try SSHSudoCommand(target: "fixture", arguments: arguments)
  let text = try #require(command.sshArguments.last).replacingOccurrences(of: "/usr/bin/sudo", with: sudo.path)
  for mode in ["consuming", "cached", "refusal", "invalidation"] {
    try? FileManager.default.removeItem(at: output)
    try? FileManager.default.removeItem(at: parents)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-f", "-c", text]
    process.environment = ["MODE": mode, "OUTPUT": output.path, "PARENTS": parents.path, "PATH": "/usr/bin:/bin", "HOME": directory.path, "ZDOTDIR": directory.path]
    let input = Pipe()
    process.standardInput = input
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    try input.fileHandleForWriting.write(contentsOf: Data("synthetic-password\n".utf8))
    try input.fileHandleForWriting.close()
    process.waitUntilExit()
    if mode == "consuming" || mode == "cached" {
      #expect(process.terminationStatus == 37)
      #expect(try Data(contentsOf: output) == Data((arguments.dropFirst().joined(separator: "\0") + "\0").utf8))
    } else {
      #expect(process.terminationStatus != 0)
      #expect(!FileManager.default.fileExists(atPath: output.path))
    }
    let identities = try String(contentsOf: parents, encoding: .utf8).split(separator: "\n")
    #expect(Set(identities).count == 1)
    #expect(!FileManager.default.fileExists(atPath: injection.path))
  }
}
