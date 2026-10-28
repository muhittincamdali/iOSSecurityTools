// The code samples of README.md. The README copies them from this file; the example app and the
// package's tests (through the symlink Tests/iOSSecurityToolsTests/ReadmeExamples.swift) compile
// it, and ReadmeExamplesTests runs the samples that need no user interaction.
import Foundation
import iOSSecurityTools
import SwiftUI

// MARK: - Quick start

struct ContentView: View {
    @State private var status = "Nothing stored yet"

    var body: some View {
        VStack(spacing: 16) {
            Text(status)
            Button("Encrypt and store a note") {
                do {
                    let keychain = Keychain(service: "QuickStart")
                    let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "notes-key"))
                    try keychain.set(cipher.encrypt("Meet at 7 pm"), forKey: "note")

                    let stored = try keychain.data(forKey: "note") ?? Data()
                    status = "Decrypted: \(try cipher.decryptString(stored))"
                } catch {
                    status = error.localizedDescription
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .privacyShield()
    }
}

// MARK: - Keychain

func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}

func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}

// MARK: - Encryption

func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}

func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}

// MARK: - One-time passwords

func oneTimePasswordSample() throws -> Bool {
    let scanned = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    let uri = try OTPAuthURI(parsing: scanned)
    guard case .totp(let totp) = uri.kind else { return false }

    let code = try totp.code()                    // six digits, new every 30 seconds
    let secondsLeft = try totp.secondsRemaining()
    print("\(uri.issuer ?? ""): \(code), \(secondsLeft) s left")
    return try totp.verify(code)                   // also accepts the previous and next code
}

// MARK: - Certificate pinning

func pinnedSessionSample() throws -> URLSession {
    let policy = try PinningPolicy([
        PinnedDomain("letsencrypt.org", pins: [
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",   // ISRG Root X1
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",   // ISRG Root X2
        ], includesSubdomains: true),
    ])
    return URLSession.pinned(policy: policy) { failure in
        print("Blocked: \(failure.localizedDescription)")
    }
}

// MARK: - Integrity

func integritySample() -> IntegrityReport {
    let report = IntegrityInspector().inspect()
    if report.hasFindings(in: [.jailbreak, .injectedLibraries]) {
        // Add friction: ask for the passcode again, lower limits, flag the session on the server.
    }
    for finding in report.findings {
        print(finding)   // for example "Running in the simulator"
    }
    return report
}

// MARK: - Redaction

struct LoginRequest: Codable {
    var username: String
    @Redacted var password: String
}

func redactionSample() -> (request: String, log: String) {
    let request = LoginRequest(username: "alice", password: "hunter2")
    let printed = "\(request)"   // LoginRequest(username: "alice", _password: <redacted>)

    let redactor = SensitiveDataRedactor()
    let log = redactor.redact("charged 4242 4242 4242 4242 to alice@example.com, token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln")
    // "charged •••• 4242 to a•••@example.com, token=[redacted]"
    return (printed, log)
}

// MARK: - End-to-end encryption

func endToEndSample() throws -> String {
    // On the receiving device: create a key pair once and publish the 32-byte public key.
    let deviceKey = PublicKeyCipher.PrivateKey()   // or Keychain.keyAgreementKey(forKey:)
    let published = deviceKey.publicKey.rawRepresentation

    // On any sender, your server included: no shared secret needed.
    let recipient = try PublicKeyCipher.publicKey(rawRepresentation: published)
    let envelope = try PublicKeyCipher.seal("See you at 7", to: recipient)

    // Back on the device: only its private key opens the envelope.
    return try PublicKeyCipher.openString(envelope, using: deviceKey)   // "See you at 7"
}

// MARK: - Signatures

func signatureSample() throws -> Bool {
    let signingKey = SigningKey()                     // Ed25519; SigningKey(algorithm: .p256) for P-256
    let export = Data("orders.csv contents".utf8)
    let signature = try signingKey.signature(for: export)

    // Anyone with the public key (raw, DER or PEM) can check the file.
    let publicKey = try VerifyingKey(pemRepresentation: signingKey.publicKey.pemRepresentation)
    return publicKey.isValidSignature(signature, for: export)   // true
}

// MARK: - Signed tokens

func tokenSample() throws -> String? {
    // Your server signs the token; here a key made in place stands in for it.
    let serverKey = SigningKey()
    let token = try JWTSigner(signingKey: serverKey).sign(JWTClaims(
        issuer: "https://auth.example.com", subject: "user-42", audience: ["ios-app"],
        expiration: Date().addingTimeInterval(600)
    ))

    // The app checks the signature, the algorithm, exp, nbf, iss and aud before trusting it.
    let verifier = try JWTVerifier(publicKey: serverKey.publicKey,
                                   issuer: "https://auth.example.com", audience: "ios-app")
    return try verifier.verify(token).subject   // "user-42"
}

// MARK: - Secure Enclave

func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}

// MARK: - Biometrics

#if os(iOS) || os(macOS) || os(visionOS)
func biometricSample() async -> String {
    let authenticator = BiometricAuthenticator()
    guard case .available(let kind) = authenticator.availability() else {
        return "Biometry is not available"
    }
    do {
        try await authenticator.authenticate(reason: "Show your saved cards")
        return "Confirmed with \(kind)"
    } catch {
        return error.localizedDescription   // canceled, failed, locked out, ...
    }
}
#endif
