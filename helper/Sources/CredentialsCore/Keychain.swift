import Foundation
import LocalAuthentication
import Security

public enum Keychain {
  static let catalogService = "pi-credentials.catalog"
  static let catalogAccount = "catalog"
  static let stagingPrefix = "pi-credentials.staging."

  static func baseQuery(service: String, account: String?) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
    ]
    if let account { query[kSecAttrAccount as String] = account }
    return query
  }

  static func failure(_ status: OSStatus, _ action: String) -> CredentialError {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? "status \(status)"
    if status == errSecItemNotFound {
      return CredentialError("keychain-missing", "\(action): Keychain item not found.")
    }
    if status == errSecUserCanceled || status == errSecAuthFailed {
      return CredentialError("keychain-denied", "\(action): access was denied.")
    }
    return CredentialError("keychain-failed", "\(action): \(message)")
  }

  public static func resolveAccount(service: String, account: String?) throws -> String {
    var query = baseQuery(service: service, account: account)
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
      throw failure(status, "Find '\(service)'")
    }
    guard items.count == 1 else {
      throw CredentialError(
        "keychain-ambiguous",
        "\(items.count) Keychain items use service '\(service)'. Name the account.")
    }
    return items[0][kSecAttrAccount as String] as? String ?? ""
  }

  public static func read(service: String, account: String) throws -> Data {
    var query = baseQuery(service: service, account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else {
      throw failure(status, "Read '\(service)'")
    }
    return data
  }

  public static func write(service: String, account: String, data: Data) throws {
    var query = baseQuery(service: service, account: account)
    let status = SecItemUpdate(
      query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecSuccess { return }
    guard status == errSecItemNotFound else { throw failure(status, "Update '\(service)'") }
    query[kSecValueData as String] = data
    let addStatus = SecItemAdd(query as CFDictionary, nil)
    guard addStatus == errSecSuccess else { throw failure(addStatus, "Add '\(service)'") }
  }

  public static func delete(service: String, account: String) throws {
    let status = SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw failure(status, "Delete '\(service)'")
    }
  }

  public static func add(service: String, account: String, data: Data) throws {
    var query = baseQuery(service: service, account: account)
    query[kSecValueData as String] = data
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw failure(status, "Add '\(service)'") }
  }

  public static func adopt(service: String, account: String) throws {
    let value = try read(service: service, account: account)
    let staging = stagingPrefix + service
    try delete(service: staging, account: account)
    try add(service: staging, account: account, data: value)
    try delete(service: service, account: account)
    try add(service: service, account: account, data: value)
    try delete(service: staging, account: account)
  }

  public static func loadCatalog() throws -> Catalog {
    do {
      let data = try read(service: catalogService, account: catalogAccount)
      return try JSONDecoder().decode(Catalog.self, from: data)
    } catch let error as CredentialError where error.code == "keychain-missing" {
      return Catalog()
    }
  }

  public static func saveCatalog(_ catalog: Catalog) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    try write(service: catalogService, account: catalogAccount, data: encoder.encode(catalog))
  }

  public static func value(of credential: Credential) throws -> String {
    let account = try credential.account ?? resolveAccount(service: credential.service, account: nil)
    let data = try read(service: credential.service, account: account)
    guard let text = String(data: data, encoding: .utf8) else {
      throw CredentialError("keychain-encoding", "The stored value is not UTF-8 text.")
    }
    return text
  }

  public static func authenticateOwner(reason: String) throws {
    let context = LAContext()
    var policyError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
      throw CredentialError(
        "auth-unavailable", policyError?.localizedDescription ?? "Owner authentication is unavailable.")
    }
    let semaphore = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var outcome: Error?
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { isSuccess, error in
      if !isSuccess { outcome = error ?? CredentialError("auth-denied", "Authentication failed.") }
      semaphore.signal()
    }
    semaphore.wait()
    if outcome != nil {
      throw CredentialError("auth-denied", "Touch ID or password confirmation was not given.")
    }
  }
}
