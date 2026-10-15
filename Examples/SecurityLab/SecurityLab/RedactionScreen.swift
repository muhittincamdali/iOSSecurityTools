import iOSSecurityTools
import SwiftUI

/// Redacts a log line as you type, and shows the fixed-length masks.
struct RedactionScreen: View {
    private static let sample = """
        POST /v1/login {"email":"alice@example.com","password":"hunter2"}
        Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig
        paid with 4242 4242 4242 4242, ref 98431
        """

    @State private var text = Self.sample
    private let redactor = SensitiveDataRedactor()

    var body: some View {
        Form {
            Section("Log text") {
                TextEditor(text: $text)
                    .font(.caption.monospaced())
                    .frame(minHeight: 110)
                    .autocorrectionDisabled()
            }
            Section("Redacted") {
                Text(redactor.redact(text))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
            Section("Masks") {
                LabeledContent("Card", value: Mask.cardNumber("4242 4242 4242 4242"))
                LabeledContent("Email", value: Mask.email("alice@example.com"))
                LabeledContent("IBAN", value: Mask.trailing("DE89370400440532013000"))
                LabeledContent("Short PIN", value: Mask.trailing("4921"))
            }
        }
    }
}
