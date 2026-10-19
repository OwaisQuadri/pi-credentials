import Foundation

public struct Redactor: Sendable {
  public static let minimumLength = 4

  let forms: [(text: String, label: String)]

  public init(values: [(name: String, value: String)]) {
    var forms: [(String, String)] = []
    for (name, value) in values where value.count >= Self.minimumLength {
      let label = "[cred:\(name)]"
      let base64 = Data(value.utf8).base64EncodedString()
      let unpadded = base64.trimmingCharacters(in: CharacterSet(charactersIn: "="))
      let urlSafe = unpadded.replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
      let percent = value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
      for form in [value, base64, unpadded, urlSafe, percent] {
        forms.append((form, label))
      }
    }
    self.forms = forms.sorted { $0.0.count > $1.0.count }
  }

  public func redact(_ text: String) -> (text: String, names: [String]) {
    var output = text
    var names: [String] = []
    for (form, label) in forms where output.contains(form) {
      output = output.replacingOccurrences(of: form, with: label)
      let name = String(label.dropFirst(6).dropLast())
      if !names.contains(name) { names.append(name) }
    }
    return (output, names)
  }
}
