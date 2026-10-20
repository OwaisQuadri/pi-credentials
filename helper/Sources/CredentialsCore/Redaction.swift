import Foundation

public struct Redactor: Sendable {
  public static let minimumLength = 8
  public static let redactedKinds: Set<Kind> = [.apiKey, .appPassword]

  let forms: [(text: String, label: String)]

  public var longestForm: Int { forms.map { $0.text.utf8.count }.max() ?? 0 }

  public init(values: [(name: String, value: String)]) {
    self.init(values: values, minimumLength: Self.minimumLength)
  }

  init(values: [(name: String, value: String)], minimumLength: Int) {
    var forms: [(String, String)] = []
    let unreserved = CharacterSet(
      charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    for (name, value) in values where !value.isEmpty && value.count >= minimumLength {
      let label = "[cred:\(name)]"
      let base64 = Data(value.utf8).base64EncodedString()
      let unpadded = base64.trimmingCharacters(in: CharacterSet(charactersIn: "="))
      let urlSafe = unpadded.replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
      let percent = value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
      let lower = Self.lowercaseEscapes(percent)
      let encoded = [
        value, base64, unpadded, urlSafe, percent, lower,
        percent.replacingOccurrences(of: "%20", with: "+"),
        lower.replacingOccurrences(of: "%20", with: "+"),
      ]
      let escaped = encoded.filter { $0.contains("/") }.map {
        $0.replacingOccurrences(of: "/", with: "\\/")
      }
      for form in Set(encoded + escaped) { forms.append((form, label)) }
    }
    self.forms = forms.sorted { $0.0.count > $1.0.count }
  }

  static func lowercaseEscapes(_ text: String) -> String {
    var output = ""
    var remaining = 0
    for character in text {
      if character == "%" {
        remaining = 2
        output.append(character)
      } else if remaining > 0 {
        remaining -= 1
        output.append(Character(character.lowercased()))
      } else {
        output.append(character)
      }
    }
    return output
  }

  public func redact(_ text: String, labelPrefix: String = "cred") -> (
    text: String, names: [String]
  ) {
    var output = text
    var names: [String] = []
    for (form, label) in forms where output.contains(form) {
      let name = String(label.dropFirst(6).dropLast())
      output = output.replacingOccurrences(of: form, with: "[\(labelPrefix):\(name)]")
      if !names.contains(name) { names.append(name) }
    }
    return (output, names)
  }
}
