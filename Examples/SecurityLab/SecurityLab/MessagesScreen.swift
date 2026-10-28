import iOSSecurityTools
import SwiftUI

/// Seals a message to this device's public key and opens it, signs it, and checks a signed token.
struct MessagesScreen: View {
    private static let keychain = Keychain(service: "io.github.muhittincamdali.SecurityLab.messages")

    @State private var message = ""
    @State private var publicKey: Data?
    @State private var envelope: Data?
    @State private var opened: String?
    @State private var signatureStatus: String?
    @State private var tokenStatus: String?
    @State private var errorText: String?

    var body: some View {
        Form {
            Section {
                TextField("A message for this device", text: $message)
                Button("Seal and open", action: sealAndOpen)
                    .disabled(message.isEmpty)
                if let publicKey {
                    LabeledContent("Device public key", value: hex(publicKey.prefix(8)) + " …")
                        .font(.caption.monospaced())
                }
                if let envelope {
                    LabeledContent("Envelope", value: "\(envelope.count) bytes")
                    Text(hex(envelope.prefix(24)) + " …")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                if let opened {
                    LabeledContent("Opened", value: opened)
                }
            } header: {
                Text("End-to-end encryption")
            } footer: {
                Text("HPKE to an X25519 key created in the keychain on first use.")
            }

            Section {
                Button("Sign and verify", action: signAndVerify)
                    .disabled(message.isEmpty)
                if let signatureStatus {
                    Text(signatureStatus)
                }
                Button("Issue and verify a token", action: issueAndVerifyToken)
                if let tokenStatus {
                    Text(tokenStatus)
                        .font(.callout)
                }
            } header: {
                Text("Signatures")
            } footer: {
                Text("Ed25519 signatures and an EdDSA JSON Web Token, checked with the public key only.")
            }

            if let errorText {
                Section {
                    Text(errorText)
                        .foregroundStyle(.red)
                }
            }
        }
        .privacyShield()
        .task {
            guard LaunchOptions.isDemo, envelope == nil else { return }
            message = "Door code 4831"
            sealAndOpen()
            signAndVerify()
            issueAndVerifyToken()
        }
    }

    private func sealAndOpen() {
        run {
            let deviceKey = try Self.keychain.keyAgreementKey(forKey: "device")
            publicKey = deviceKey.publicKey.rawRepresentation
            let recipient = try PublicKeyCipher.publicKey(rawRepresentation: deviceKey.publicKey.rawRepresentation)
            let sealed = try PublicKeyCipher.seal(message, to: recipient)
            envelope = sealed
            opened = try PublicKeyCipher.openString(sealed, using: deviceKey)
        }
    }

    private func signAndVerify() {
        run {
            let signingKey = try Self.keychain.signingKey(forKey: "author")
            let data = Data(message.utf8)
            let signature = try signingKey.signature(for: data)
            let verifier = try VerifyingKey(pemRepresentation: signingKey.publicKey.pemRepresentation)
            let original = verifier.isValidSignature(signature, for: data)
            let changed = verifier.isValidSignature(signature, for: Data((message + "!").utf8))
            signatureStatus = "Original: \(original ? "valid" : "invalid") · Changed: \(changed ? "valid" : "invalid")"
        }
    }

    private func issueAndVerifyToken() {
        run {
            let signingKey = try Self.keychain.signingKey(forKey: "author")
            let token = try JWTSigner(signingKey: signingKey).sign(JWTClaims(
                issuer: "security-lab", subject: "device-42", audience: ["ios-app"],
                expiration: Date().addingTimeInterval(600), issuedAt: Date()
            ))
            let verifier = try JWTVerifier(publicKey: signingKey.publicKey, issuer: "security-lab", audience: "ios-app")
            let claims = try verifier.verify(token)
            tokenStatus = "\(token.utf8.count)-byte EdDSA token, subject \(claims.subject ?? "none"), valid for 10 minutes"
        }
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    private func run(_ action: () throws -> Void) {
        do {
            try action()
            errorText = nil
        } catch {
            errorText = error.localizedDescription
        }
    }
}
