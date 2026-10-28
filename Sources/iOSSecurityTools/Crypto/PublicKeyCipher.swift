import CryptoKit
import Foundation

/// Encrypts data to a public key with HPKE (RFC 9180), so that only the holder of the matching
/// private key can read it.
///
/// Use it for end-to-end encryption: each device creates a key pair once, publishes the public
/// key, and anyone — your server included — can seal a message that only that device opens. The
/// sender needs no secret and no prior contact.
///
/// ```swift
/// // On the receiving device, once:
/// let deviceKey = try Keychain(service: "com.example.chat").keyAgreementKey(forKey: "device")
/// let published = deviceKey.publicKey.rawRepresentation          // 32 bytes, upload it
///
/// // On any sender:
/// let recipient = try PublicKeyCipher.publicKey(rawRepresentation: published)
/// let envelope = try PublicKeyCipher.seal("See you at 7", to: recipient)
///
/// // Back on the receiving device:
/// let text = try PublicKeyCipher.openString(envelope, using: deviceKey)
/// ```
///
/// The suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, run by CryptoKit.
/// Each envelope uses a fresh ephemeral key. Envelope layout (version 1), lengths in bytes:
///
/// | Version | Mode | Encapsulated key | Ciphertext       | Tag |
/// | ------- | ---- | ---------------- | ---------------- | --- |
/// | 1       | 1    | 32               | plaintext length | 16  |
///
/// The two header bytes are part of the HPKE `info`, so they cannot be changed without failing
/// decryption.
///
/// What it does not do: it does not tell the recipient who sent the message (use
/// ``seal(_:to:from:authenticating:)-(DataProtocol,_,_,_)`` or sign the message with a
/// ``SigningKey``), it does not stop an attacker from replaying an envelope (put a message
/// number in the associated data and check it), and a stolen recipient private key opens every
/// envelope ever sealed to it.
public enum PublicKeyCipher {
    /// How an envelope was sealed.
    public enum Mode: UInt8, Sendable, Hashable, CaseIterable {
        /// Anyone with the public key could have sealed it (HPKE base mode).
        case anonymous = 1
        /// Sealed with the sender's private key as well (HPKE auth mode); only opens with the
        /// sender's public key.
        case authenticated = 2
    }

    /// A recipient's private key: CryptoKit's X25519 key, named here so that code using this
    /// type needs no `import CryptoKit`. `PrivateKey()` creates a random one.
    public typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
    /// A recipient's public key, 32 bytes in ``publicKey(rawRepresentation:)``.
    public typealias PublicKey = Curve25519.KeyAgreement.PublicKey

    /// The envelope format version this type writes.
    public static let formatVersion: UInt8 = 1
    /// The size of an envelope that holds an empty plaintext: 2 header bytes, the 32-byte
    /// encapsulated key and the 16-byte tag.
    public static let overhead = 2 + 32 + 16

    private static let ciphersuite = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly
    private static let infoPrefix = Data("iOSSecurityTools.PublicKeyCipher".utf8)

    /// Reads a recipient's X25519 public key from its 32 raw bytes.
    ///
    /// - Throws: ``CipherError/invalidParameter(_:)`` for any other length.
    public static func publicKey(rawRepresentation: some ContiguousBytes) throws(CipherError) -> Curve25519.KeyAgreement.PublicKey {
        let bytes = rawRepresentation.withUnsafeBytes { Data($0) }
        guard let key = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: bytes) else {
            throw .invalidParameter("\(bytes.count) bytes are not an X25519 public key; 32 are required.")
        }
        return key
    }

    /// Encrypts data to a recipient's public key.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - recipient: The recipient's public key.
    ///   - associatedData: Data that is authenticated but not encrypted, such as a conversation
    ///     identifier and a message number. Opening must pass the same bytes.
    /// - Returns: An envelope, ``overhead`` bytes longer than the plaintext.
    /// - Throws: ``CipherError/encryptionFailed(_:)`` when CryptoKit cannot encrypt, for example
    ///   for a low-order public key.
    public static func seal(
        _ plaintext: some DataProtocol,
        to recipient: Curve25519.KeyAgreement.PublicKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> Data {
        let header = Data([formatVersion, Mode.anonymous.rawValue])
        do {
            var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: ciphersuite, info: infoPrefix + header)
            let ciphertext = try sender.seal(plaintext, authenticating: associatedData)
            return header + sender.encapsulatedKey + ciphertext
        } catch {
            throw .encryptionFailed(String(describing: error))
        }
    }

    /// Encrypts data to a recipient's public key and authenticates it with the sender's private
    /// key (HPKE auth mode).
    ///
    /// The recipient opens it with
    /// ``open(_:using:from:authenticating:)`` and the sender's public key, which proves that the
    /// envelope was sealed with the sender's private key — or with the recipient's own private
    /// key, since both can compute the same secret. That makes it proof for the recipient only,
    /// not for a third party: to prove authorship to others, sign the message with a
    /// ``SigningKey``.
    ///
    /// - Throws: ``CipherError/encryptionFailed(_:)`` when CryptoKit cannot encrypt.
    public static func seal(
        _ plaintext: some DataProtocol,
        to recipient: Curve25519.KeyAgreement.PublicKey,
        from sender: Curve25519.KeyAgreement.PrivateKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> Data {
        let header = Data([formatVersion, Mode.authenticated.rawValue])
        do {
            var context = try HPKE.Sender(recipientKey: recipient, ciphersuite: ciphersuite, info: infoPrefix + header, authenticatedBy: sender)
            let ciphertext = try context.seal(plaintext, authenticating: associatedData)
            return header + context.encapsulatedKey + ciphertext
        } catch {
            throw .encryptionFailed(String(describing: error))
        }
    }

    /// Encrypts the UTF-8 bytes of a string to a recipient's public key.
    public static func seal(
        _ string: String,
        to recipient: Curve25519.KeyAgreement.PublicKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> Data {
        try seal(Data(string.utf8), to: recipient, authenticating: associatedData)
    }

    /// Encrypts the UTF-8 bytes of a string to a recipient's public key and authenticates it with
    /// the sender's private key.
    public static func seal(
        _ string: String,
        to recipient: Curve25519.KeyAgreement.PublicKey,
        from sender: Curve25519.KeyAgreement.PrivateKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> Data {
        try seal(Data(string.utf8), to: recipient, from: sender, authenticating: associatedData)
    }

    /// Decrypts an envelope sealed with ``seal(_:to:authenticating:)-(DataProtocol,_,_)``.
    ///
    /// - Parameters:
    ///   - envelope: The envelope.
    ///   - privateKey: The recipient's private key.
    ///   - associatedData: The associated data passed to `seal`.
    /// - Throws: ``CipherError/malformedEnvelope(_:)`` for data too short to be an envelope, an
    ///   unknown version or an envelope that needs the sender's public key, and
    ///   ``CipherError/authenticationFailed`` when the key, the associated data or any byte does
    ///   not match.
    public static func open(
        _ envelope: Data,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> Data {
        let parts = try split(envelope, expecting: .anonymous)
        do {
            var context = try HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: infoPrefix + parts.header, encapsulatedKey: parts.encapsulatedKey)
            return try context.open(parts.ciphertext, authenticating: associatedData)
        } catch {
            throw .authenticationFailed
        }
    }

    /// Decrypts an envelope sealed with ``seal(_:to:from:authenticating:)-(DataProtocol,_,_,_)``
    /// and checks that it was sealed with the private key of `sender`.
    ///
    /// - Throws: The errors of ``open(_:using:authenticating:)``;
    ///   ``CipherError/authenticationFailed`` also when the envelope was sealed by another sender.
    public static func open(
        _ envelope: Data,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        from sender: Curve25519.KeyAgreement.PublicKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> Data {
        let parts = try split(envelope, expecting: .authenticated)
        do {
            var context = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: ciphersuite,
                info: infoPrefix + parts.header,
                encapsulatedKey: parts.encapsulatedKey,
                authenticatedBy: sender
            )
            return try context.open(parts.ciphertext, authenticating: associatedData)
        } catch {
            throw .authenticationFailed
        }
    }

    /// Decrypts an envelope and reads the plaintext as UTF-8 text.
    ///
    /// - Throws: The errors of ``open(_:using:authenticating:)``, or ``CipherError/invalidUTF8``.
    public static func openString(
        _ envelope: Data,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> String {
        let data = try open(envelope, using: privateKey, authenticating: associatedData)
        guard let string = String(data: data, encoding: .utf8) else { throw .invalidUTF8 }
        return string
    }

    /// Decrypts a sender-authenticated envelope and reads the plaintext as UTF-8 text.
    ///
    /// - Throws: The errors of ``open(_:using:from:authenticating:)``, or
    ///   ``CipherError/invalidUTF8``.
    public static func openString(
        _ envelope: Data,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        from sender: Curve25519.KeyAgreement.PublicKey,
        authenticating associatedData: some DataProtocol = Data()
    ) throws(CipherError) -> String {
        let data = try open(envelope, using: privateKey, from: sender, authenticating: associatedData)
        guard let string = String(data: data, encoding: .utf8) else { throw .invalidUTF8 }
        return string
    }

    /// Returns how an envelope was sealed, or nil when it is not an envelope this version reads.
    /// It tells the recipient which `open` to call; it is not authenticated until that call
    /// succeeds.
    public static func mode(of envelope: Data) -> Mode? {
        guard envelope.count >= overhead, envelope[envelope.startIndex] == formatVersion else { return nil }
        return Mode(rawValue: envelope[envelope.startIndex + 1])
    }

    private struct Parts {
        let header: Data
        let encapsulatedKey: Data
        let ciphertext: Data
    }

    private static func split(_ envelope: Data, expecting mode: Mode) throws(CipherError) -> Parts {
        let bytes = [UInt8](envelope)
        guard bytes.count >= overhead else {
            throw .malformedEnvelope("\(bytes.count) bytes is shorter than the \(overhead)-byte minimum.")
        }
        guard bytes[0] == formatVersion else {
            throw .malformedEnvelope("Unknown format version \(bytes[0]).")
        }
        guard let envelopeMode = Mode(rawValue: bytes[1]) else {
            throw .malformedEnvelope("Unknown mode \(bytes[1]).")
        }
        guard envelopeMode == mode else {
            switch envelopeMode {
            case .authenticated:
                throw .malformedEnvelope("The envelope is authenticated by its sender; open it with the sender's public key.")
            case .anonymous:
                throw .malformedEnvelope("The envelope has no sender authentication; open it without a sender key.")
            }
        }
        return Parts(header: Data(bytes[0..<2]), encapsulatedKey: Data(bytes[2..<34]), ciphertext: Data(bytes[34...]))
    }
}
