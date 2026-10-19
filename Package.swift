// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "pi-credentials",
  platforms: [.macOS(.v14)],
  products: [.executable(name: "pi-credentials-helper", targets: ["Helper"])],
  targets: [
    .executableTarget(name: "Helper", path: "helper/Sources/Helper")
  ]
)
