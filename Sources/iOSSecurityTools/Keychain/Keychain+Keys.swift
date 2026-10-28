import CryptoKit
import Foundation
import Security

extension Keychain {
    /// Returns the 256-bit key stored under a key name, creating and storing a random one the first
    /// time.
    ///
    /// Two threads that call it at the same time get the same key: the first one stores its key,
    /// and the second one finds that key instead of replacing it.
    ///
    /// ```swift
    /// let key = try Keychain(service: "com.example.app").symmetricKey(forKey: "notes")
    /// let cipher = try DataCipher(key: key)
    /// ```
    ///
    /// - Throws: ``KeychainError``, or ``KeychainError/unexpectedData`` when the stored value is
    ///   not 32 bytes.
    public func symmetricKey(forKey key: String) throws(KeychainError) -> SymmetricKey {
        if let existing = try data(forKey: key) {
            return try Self.symmetricKey(from: existing)
        }
        let candidate = DataCipher.generateKey().withUnsafeBytes { Data($0) }
        if try add(candidate, forKey: key) {
            return SymmetricKey(data: candidate)
        }
        guard let stored = try data(forKey: key) else { throw .unexpectedData }
        return try Self.symmetricKey(from: stored)
    }

    private static func symmetricKey(from data: Data) throws(KeychainError) -> SymmetricKey {
        guard data.count == 32 else { throw .unexpectedData }
        return SymmetricKey(data: data)
    }
}

extension Keychain {
    /// Returns the X25519 private key stored under a key name, creating and storing a random one
    /// the first time. Use it with ``PublicKeyCipher`` to receive end-to-end encrypted messages,
    /// or with ``KeyDerivation/sharedKey(privateKey:peerPublicKey:salt:info:outputByteCount:)-(Curve25519.KeyAgreement.PrivateKey,_,_,_,_)``.
    ///
    /// ```swift
    /// let deviceKey = try Keychain(service: "com.example.chat").keyAgreementKey(forKey: "device")
    /// upload(deviceKey.publicKey.rawRepresentation)
    /// ```
    ///
    /// Two threads that call it at the same time get the same key.
    ///
    /// - Throws: ``KeychainError``, or ``KeychainError/unexpectedData`` when the stored value is
    ///   not a 32-byte key.
    public func keyAgreementKey(forKey key: String) throws(KeychainError) -> Curve25519.KeyAgreement.PrivateKey {
        let stored = try storedOrCreated(forKey: key) {
            Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        }
        guard let privateKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: stored) else {
            throw .unexpectedData
        }
        return privateKey
    }

    /// Returns the signing key stored under a key name, creating and storing a random one of the
    /// given algorithm the first time.
    ///
    /// The stored value records the algorithm, so asking for a key with a different algorithm
    /// than the one stored throws instead of reading the bytes as another kind of key.
    ///
    /// - Throws: ``KeychainError``, or ``KeychainError/unexpectedData`` when the stored value is
    ///   not a signing key of `algorithm`.
    public func signingKey(forKey key: String, algorithm: SignatureAlgorithm = .ed25519) throws(KeychainError) -> SigningKey {
        let tag = Self.signingKeyTag(algorithm)
        let stored = try storedOrCreated(forKey: key) {
            Data([tag]) + SigningKey(algorithm: algorithm).rawRepresentation
        }
        guard stored.count == 33, stored.first == tag,
              let signingKey = try? SigningKey(rawRepresentation: stored.dropFirst(), algorithm: algorithm) else {
            throw .unexpectedData
        }
        return signingKey
    }

    private static func signingKeyTag(_ algorithm: SignatureAlgorithm) -> UInt8 {
        switch algorithm {
        case .ed25519: 1
        case .p256: 2
        }
    }

    /// Returns the value under `key`, or adds `make()` and returns it; when another thread adds a
    /// value first, returns that one.
    private func storedOrCreated(forKey key: String, make: () -> Data) throws(KeychainError) -> Data {
        if let existing = try data(forKey: key) {
            return existing
        }
        let candidate = make()
        if try add(candidate, forKey: key) {
            return candidate
        }
        guard let stored = try data(forKey: key) else { throw .unexpectedData }
        return stored
    }
}
