import iOSSecurityTools
import SwiftUI

/// Stores an encrypted note in the keychain and keeps a PIN as a salted hash.
struct VaultScreen: View {
    private static let keychain = Keychain(service: "io.github.muhittincamdali.SecurityLab.vault")

    @State private var note = ""
    @State private var envelope: Data?
    @State private var decrypted: String?
    @State private var pin = ""
    @State private var pinAttempt = ""
    @State private var pinStatus: String?
    @State private var errorText: String?

    var body: some View {
        Form {
            Section {
                TextField("A note to keep secret", text: $note)
                Button("Encrypt and save", action: save)
                    .disabled(note.isEmpty)
                if let envelope {
                    LabeledContent("Stored bytes", value: "\(envelope.count)")
                    Text(envelope.prefix(24).map { String(format: "%02x", $0) }.joined(separator: " ") + " …")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                if let decrypted {
                    LabeledContent("Read back", value: decrypted)
                }
            } header: {
                Text("Encrypted note")
            } footer: {
                Text("AES-256-GCM with a key created in the keychain on first use.")
            }

            Section {
                SecureField("New PIN", text: $pin)
                Button("Save PIN hash", action: savePIN)
                    .disabled(pin.isEmpty)
                SecureField("Enter the PIN", text: $pinAttempt)
                Button("Check PIN", action: checkPIN)
                    .disabled(pinAttempt.isEmpty)
                if let pinStatus {
                    Text(pinStatus)
                }
            } header: {
                Text("App lock PIN")
            } footer: {
                Text("Only a PBKDF2 hash with a random salt is stored.")
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
            note = "Locker code 0417"
            save()
            pin = "4921"
            savePIN()
            pinAttempt = "4921"
            checkPIN()
        }
    }

    private func save() {
        run {
            let cipher = try DataCipher(key: Self.keychain.symmetricKey(forKey: "note-key"))
            try Self.keychain.set(cipher.encrypt(note), forKey: "note")
            let stored = try Self.keychain.data(forKey: "note") ?? Data()
            envelope = stored
            decrypted = try cipher.decryptString(stored)
        }
    }

    private func savePIN() {
        run {
            try Self.keychain.set(PasswordHash.make(for: pin), forKey: "pin-hash")
            pinStatus = "PIN hash saved"
            pin = ""
        }
    }

    private func checkPIN() {
        run {
            guard let stored = try Self.keychain.string(forKey: "pin-hash") else {
                pinStatus = "Save a PIN first"
                return
            }
            pinStatus = try PasswordHash.verify(pinAttempt, against: stored) ? "PIN matches" : "Wrong PIN"
        }
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
