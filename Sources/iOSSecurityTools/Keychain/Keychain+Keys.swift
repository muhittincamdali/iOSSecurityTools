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
