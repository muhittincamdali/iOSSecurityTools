import Foundation

extension Keychain {
    // MARK: - Strings and Codable values

    /// Stores a string as UTF-8 under a key.
    public func set(_ string: String, forKey key: String, protection: KeychainProtection? = nil) throws(KeychainError) {
        try set(Data(string.utf8), forKey: key, protection: protection)
    }

    /// Returns the string stored under a key, or `nil` if there is none.
    ///
    /// - Throws: ``KeychainError/unexpectedData`` if the stored bytes are not UTF-8.
    public func string(forKey key: String, prompt: String? = nil) throws(KeychainError) -> String? {
        guard let data = try data(forKey: key, prompt: prompt) else { return nil }
        guard let string = String(data: data, encoding: .utf8) else { throw .unexpectedData }
        return string
    }

    /// Stores an `Encodable` value as JSON under a key.
    public func setValue(_ value: some Encodable, forKey key: String, protection: KeychainProtection? = nil) throws(KeychainError) {
        let data: Data
        do {
            data = try JSONEncoder().encode(value)
        } catch {
            throw .encodingFailed(String(describing: error))
        }
        try set(data, forKey: key, protection: protection)
    }

    /// Returns the `Decodable` value stored as JSON under a key, or `nil` if there is none.
    ///
    /// - Throws: ``KeychainError/decodingFailed(_:)`` if the stored JSON does not match `type`.
    public func value<Value: Decodable>(_ type: Value.Type, forKey key: String, prompt: String? = nil) throws(KeychainError) -> Value? {
        guard let data = try data(forKey: key, prompt: prompt) else { return nil }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw .decodingFailed(String(describing: error))
        }
    }
}
