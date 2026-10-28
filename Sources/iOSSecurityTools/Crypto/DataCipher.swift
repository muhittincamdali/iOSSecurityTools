import CryptoKit
import Foundation

/// Encrypts and authenticates data with a 256-bit key, in a self-describing format.
///
/// The output of ``encrypt(_:authenticating:)-(DataProtocol,_)`` — the *envelope* — holds everything
/// ``decrypt(_:authenticating:)`` needs besides the key: a format version, the algorithm, a fresh
/// random nonce, the ciphertext and the authentication tag. Changing any byte of it, or using a
/// different key, makes decryption throw ``CipherError/authenticationFailed`` instead of returning
/// wrong data.
///
/// ```swift
/// let key = DataCipher.generateKey()
/// let cipher = try DataCipher(key: key)
/// let envelope = try cipher.encrypt(Data("card ending 4242".utf8))
/// let plaintext = try cipher.decrypt(envelope)
/// ```
///
/// Envelope layout (version 1), all lengths in bytes:
///
/// | Version | Algorithm | Nonce | Ciphertext       | Tag |
/// | ------- | --------- | ----- | ---------------- | --- |
/// | 1       | 1         | 12    | plaintext length | 16  |
///
/// The two header bytes are authenticated together with the optional associated data, so a
/// header cannot be swapped without failing the tag check.
public struct DataCipher: Sendable {
    /// An authenticated encryption algorithm.
    public enum Algorithm: UInt8, Sendable, Hashable, CaseIterable {
        /// AES-256 in Galois/Counter Mode, hardware-accelerated on Apple silicon.
        case aes256GCM = 1
        /// ChaCha20-Poly1305 (RFC 8439).
        case chaChaPoly = 2
    }

    /// The envelope format version this type writes.
    public static let formatVersion: UInt8 = 1
    /// The size of an envelope that holds an empty plaintext: 2 header bytes, a 12-byte nonce and
    /// a 16-byte tag. Every envelope is this much longer than its plaintext.
    public static let overhead = 2 + 12 + 16

    /// The algorithm ``encrypt(_:authenticating:)-(DataProtocol,_)`` uses.
    public let algorithm: Algorithm
    private let key: SymmetricKey

    /// Creates a cipher.
    ///
    /// - Parameters:
    ///   - key: A 256-bit key, from ``generateKey()``, ``Keychain/symmetricKey(forKey:)``,
    ///     ``KeyDerivation`` or ``PasswordKeyDerivation``.
    ///   - algorithm: The algorithm for new envelopes. ``decrypt(_:authenticating:)`` reads either
    ///     algorithm, so you can change it later without re-encrypting old data.
    /// - Throws: ``CipherError/invalidKeySize(_:)`` for a key that is not 256 bits.
    public init(key: SymmetricKey, algorithm: Algorithm = .aes256GCM) throws(CipherError) {
        guard key.bitCount == 256 else {
            throw .invalidKeySize(key.bitCount)
        }
        self.key = key
        self.algorithm = algorithm
    }

    /// Returns a new random 256-bit key.
    public static func generateKey() -> SymmetricKey {
        SymmetricKey(size: .bits256)
    }

    /// Encrypts data into an envelope.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - associatedData: Data that is authenticated but not encrypted, such as a record
    ///     identifier. Decryption must pass the same bytes. This binds the envelope to its
    ///     context, so it cannot be copied into another record.
    public func encrypt(_ plaintext: some DataProtocol, authenticating associatedData: some DataProtocol = Data()) throws(CipherError) -> Data {
        let header = Data([Self.formatVersion, algorithm.rawValue])
        let authenticated = header + Data(associatedData)
        do {
            switch algorithm {
            case .aes256GCM:
                let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: authenticated)
                return header + Data(box.nonce) + box.ciphertext + box.tag
            case .chaChaPoly:
                let box = try ChaChaPoly.seal(plaintext, using: key, nonce: ChaChaPoly.Nonce(), authenticating: authenticated)
                return header + Data(box.nonce) + box.ciphertext + box.tag
            }
        } catch {
            throw .encryptionFailed(String(describing: error))
        }
    }

    /// Encrypts the UTF-8 bytes of a string into an envelope.
    public func encrypt(_ string: String, authenticating associatedData: some DataProtocol = Data()) throws(CipherError) -> Data {
        try encrypt(Data(string.utf8), authenticating: associatedData)
    }

    /// Decrypts an envelope made by ``encrypt(_:authenticating:)-(DataProtocol,_)`` with the same key.
    ///
    /// - Parameters:
    ///   - envelope: The envelope.
    ///   - associatedData: The associated data passed to ``encrypt(_:authenticating:)-(DataProtocol,_)``.
    /// - Throws: ``CipherError/malformedEnvelope(_:)`` for data too short to be an envelope or
    ///   with an unknown version or algorithm, and ``CipherError/authenticationFailed`` when the
    ///   key, the associated data or any byte of the envelope does not match.
    public func decrypt(_ envelope: Data, authenticating associatedData: some DataProtocol = Data()) throws(CipherError) -> Data {
        let bytes = [UInt8](envelope)
        guard bytes.count >= Self.overhead else {
            throw .malformedEnvelope("\(bytes.count) bytes is shorter than the \(Self.overhead)-byte minimum.")
        }
        guard bytes[0] == Self.formatVersion else {
            throw .malformedEnvelope("Unknown format version \(bytes[0]).")
        }
        guard let envelopeAlgorithm = Algorithm(rawValue: bytes[1]) else {
            throw .malformedEnvelope("Unknown algorithm \(bytes[1]).")
        }
        let authenticated = Data(bytes[0..<2]) + Data(associatedData)
        let nonce = Data(bytes[2..<14])
        let ciphertext = Data(bytes[14..<(bytes.count - 16)])
        let tag = Data(bytes[(bytes.count - 16)...])
        do {
            switch envelopeAlgorithm {
            case .aes256GCM:
                let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
                return try AES.GCM.open(box, using: key, authenticating: authenticated)
            case .chaChaPoly:
                let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
                return try ChaChaPoly.open(box, using: key, authenticating: authenticated)
            }
        } catch {
            throw .authenticationFailed
        }
    }

    /// Decrypts an envelope and reads the plaintext as UTF-8 text.
    ///
    /// - Throws: The errors of ``decrypt(_:authenticating:)``, or ``CipherError/invalidUTF8``.
    public func decryptString(_ envelope: Data, authenticating associatedData: some DataProtocol = Data()) throws(CipherError) -> String {
        let data = try decrypt(envelope, authenticating: associatedData)
        guard let string = String(data: data, encoding: .utf8) else { throw .invalidUTF8 }
        return string
    }
}

/// An error from ``DataCipher``, ``PublicKeyCipher``, ``MessageAuthenticator``, ``KeyDerivation``,
/// ``PasswordKeyDerivation`` or ``PasswordHash``.
public enum CipherError: Error, Hashable, Sendable, LocalizedError {
    /// The key has this many bits instead of 256.
    case invalidKeySize(Int)
    /// The data is not an envelope this version can read.
    case malformedEnvelope(String)
    /// The key, the associated data or the envelope does not match: the data was changed or
    /// belongs to another key.
    case authenticationFailed
    /// The decrypted bytes are not UTF-8 text.
    case invalidUTF8
    /// CryptoKit could not encrypt.
    case encryptionFailed(String)
    /// A parameter is outside its accepted range.
    case invalidParameter(String)
    /// An encoded password hash could not be read.
    case malformedHash(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let bits):
            "The key has \(bits) bits; 256 are required."
        case .malformedEnvelope(let reason):
            "The data is not a valid envelope. \(reason)"
        case .authenticationFailed:
            "The data could not be decrypted: it was changed, or the key or associated data is different."
        case .invalidUTF8:
            "The decrypted data is not UTF-8 text."
        case .encryptionFailed(let reason):
            "Encryption failed: \(reason)"
        case .invalidParameter(let reason):
            reason
        case .malformedHash(let reason):
            "The password hash is not valid. \(reason)"
        }
    }
}
