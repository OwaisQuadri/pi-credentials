import Foundation

public struct SSHSudoCommand: Sendable {
  public let target: String
  public let arguments: [String]

  public init(target: String, arguments: [String]) throws {
    guard target.utf8.count <= 255,
      target.range(of: "^(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]*$", options: .regularExpression) != nil,
      target.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 32 && $0.value < 127 })
    else {
      throw CredentialError("invalid-arguments", "Provide an SSH alias or host, optionally prefixed with user@; ports belong in trusted SSH configuration.")
    }
    guard let program = arguments.first, program.hasPrefix("/"),
      arguments.allSatisfy({ !$0.contains("\0") })
    else {
      throw CredentialError("invalid-arguments", "Provide an absolute remote program path and arguments without NUL.")
    }
    self.target = target
    self.arguments = arguments
  }

  public var sshArguments: [String] {
    let options = [
      "BatchMode=yes", "PreferredAuthentications=publickey", "PasswordAuthentication=no",
      "KbdInteractiveAuthentication=no", "NumberOfPasswordPrompts=0", "StrictHostKeyChecking=yes",
      "VerifyHostKeyDNS=no", "UpdateHostKeys=no", "RequestTTY=no", "StdinNull=no",
      "SessionType=default", "ForkAfterAuthentication=no", "RemoteCommand=none",
      "PermitLocalCommand=no", "ForwardAgent=no", "ClearAllForwardings=yes", "ControlMaster=no",
      "ControlPath=none", "ControlPersist=no",
    ]
    let script = """
      cd / </dev/null || exit 1
      trap 'status=$?; trap - 0; /usr/bin/sudo -n -k </dev/null; exit "$status"' 0
      trap 'exit 129' HUP
      trap 'exit 130' INT
      trap 'exit 143' TERM
      /usr/bin/sudo -n -k </dev/null || exit 1
      /usr/bin/sudo -S -v -p '' || exit 1
      /usr/bin/sudo -n -- \(arguments.map(Self.quote).joined(separator: " ")) </dev/null
      status=$?
      exit "$status"
      """
    return ["-T"] + options.flatMap { ["-o", $0] }
      + [target, "/bin/sh -c " + Self.quote(script)]
  }

  private static func quote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
  }
}
