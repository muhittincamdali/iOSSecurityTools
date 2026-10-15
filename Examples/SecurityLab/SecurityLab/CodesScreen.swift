import iOSSecurityTools
import SwiftUI

/// Shows the current TOTP code of a demo secret and checks typed codes.
struct CodesScreen: View {
    private static let demoURI = "otpauth://totp/Security%20Lab:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Security%20Lab"

    @State private var uriText = demoURI
    @State private var attempt = ""
    @State private var result: String?

    private var parsed: Result<OTPAuthURI, OTPError> {
        Result { () throws(OTPError) in try OTPAuthURI(parsing: uriText) }
    }

    var body: some View {
        Form {
            Section("otpauth URI") {
                TextField("otpauth://totp/…", text: $uriText, axis: .vertical)
                    .font(.caption.monospaced())
                    .autocorrectionDisabled()
            }
            switch parsed {
            case .success(let uri):
                if case .totp(let totp) = uri.kind {
                    Section(uri.issuer ?? uri.account) {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            CodeView(totp: totp, date: context.date, account: uri.account)
                        }
                    }
                    Section("Check a code") {
                        TextField("6 digits", text: $attempt)
                            .font(.body.monospaced())
                        Button("Verify") {
                            result = ((try? totp.verify(attempt)) ?? false) ? "Valid code" : "Not valid now"
                        }
                        .disabled(attempt.isEmpty)
                        if let result {
                            Text(result)
                        }
                    }
                } else {
                    Text("This screen shows time-based (totp) URIs.")
                }
            case .failure(let error):
                Text(error.localizedDescription)
                    .foregroundStyle(.red)
            }
        }
        .privacyShield()
    }
}

private struct CodeView: View {
    let totp: TOTP
    let date: Date
    let account: String

    var body: some View {
        let code = (try? totp.code(at: date)) ?? ""
        let remaining = (try? totp.secondsRemaining(at: date)) ?? 0
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(grouped(code))
                    .font(.system(size: 40, weight: .semibold, design: .monospaced))
                    .contentTransition(.numericText())
                Text(account)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            ZStack {
                Circle()
                    .stroke(.quaternary, lineWidth: 5)
                Circle()
                    .trim(from: 0, to: Double(remaining) / Double(totp.period))
                    .stroke(.tint, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text("\(remaining)")
                    .font(.callout.monospacedDigit())
            }
            .frame(width: 48, height: 48)
            .accessibilityLabel("\(remaining) seconds left")
        }
        .padding(.vertical, 4)
    }

    private func grouped(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return code.prefix(3) + " " + code.suffix(3)
    }
}
