import Foundation

public enum Repository {
  public static func identity(at directory: String) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = [
      "-C", directory, "rev-parse", "--path-format=absolute", "--git-common-dir",
    ]
    process.environment = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("GIT_") }
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0, var path = String(data: data, encoding: .utf8) else {
      throw CredentialError("not-repository", "Choose a directory inside a Git repository.")
    }
    if path.hasSuffix("\n") { path.removeLast() }
    guard path.hasPrefix("/") else {
      throw CredentialError(
        "invalid-repository", "Git did not return an absolute common-directory path.")
    }
    let identity = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    try Catalog.validatePlain(identity, field: "repository")
    return identity
  }
}
