import Foundation
import LocalAuthentication
import Security

enum ProbeResult: String {
  case readable, interactionRequired = "interaction-required", missing, failed
}

func probe(service: String) -> (ProbeResult, Int) {
  let context = LAContext()
  context.interactionNotAllowed = true
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecReturnData as String: true,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecUseAuthenticationContext as String: context,
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  switch status {
  case errSecSuccess:
    return (.readable, (item as? Data)?.count ?? 0)
  case errSecInteractionNotAllowed, errSecAuthFailed:
    return (.interactionRequired, 0)
  case errSecItemNotFound:
    return (.missing, 0)
  default:
    return (.failed, Int(status))
  }
}

func spikeCreate(service: String) -> OSStatus {
  var bytes = [UInt8](repeating: 0, count: 16)
  _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: "spike",
    kSecValueData as String: Data(bytes),
  ]
  return SecItemAdd(query as CFDictionary, nil)
}

let arguments = CommandLine.arguments.dropFirst()
if arguments.first == "spike-create", arguments.count == 2, let service = arguments.last {
  print("{\"created\":\(spikeCreate(service: service))}")
  exit(0)
}
guard arguments.first == "probe", arguments.count == 2, let service = arguments.last else {
  FileHandle.standardError.write(Data("usage: pi-credentials-helper probe <service>\n".utf8))
  exit(2)
}
let (result, detail) = probe(service: service)
print("{\"service\":\"\(service)\",\"result\":\"\(result.rawValue)\",\"detail\":\(detail)}")
