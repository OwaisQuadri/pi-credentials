// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "pi-credentials",
  platforms: [.macOS(.v14)],
  products: [.executable(name: "pi-credentials-helper", targets: ["Helper"])],
  targets: [
    .target(name: "CredentialsCore", path: "helper/Sources/CredentialsCore"),
    .executableTarget(
      name: "Helper", dependencies: ["CredentialsCore"], path: "helper/Sources/Helper"),
    .testTarget(
      name: "CredentialsCoreTests", dependencies: ["CredentialsCore"],
      path: "helper/Tests/CredentialsCoreTests"),
  ]
)
