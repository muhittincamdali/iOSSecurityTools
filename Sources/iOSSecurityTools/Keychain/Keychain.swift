import Foundation
import Security
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

#if os(macOS)
private let loginKeychainLock = NSLock()
#endif

/// Stores small secrets — tokens, passwords, keys — as generic-password items in the keychain.
///
/// Each value is stored under a key inside a service, so one app can keep several independent
/// stores. Values stay on the device after the app is deleted only if the user restores a backup;
/// they are encrypted by the system and, with the default accessibility, readable only after the
/// device has been unlocked once since it started.
///
/// ```swift
/// let keychain = Keychain(service: "com.example.app.credentials")
/// try keychain.set("s3cr3t-refresh-token", forKey: "refreshToken")
/// let token = try keychain.string(forKey: "refreshToken")   // "s3cr3t-refresh-token"
/// try keychain.removeValue(forKey: "refreshToken")
/// ```
///
/// All methods are synchronous and safe to call from any thread. A value protected with
/// ``KeychainProtection`` can show a Face ID, Touch ID or passcode prompt while it is read, so
/// read those values off the main thread.
public struct Keychain: Sendable {
    /// The longest key accepted, in UTF-8 bytes.
    public static let maximumKeyLength = 1024

    /// The name that groups this store's items (`kSecAttrService`).
    public let service: String
    /// The keychain access group shared with other apps or extensions, or `nil` for the app's
    /// default group.
    public let accessGroup: String?
    /// When the stored values can be read.
    public let accessibility: KeychainAccessibility
    /// Whether values sync to the user's other devices through iCloud Keychain.
    public let isSynchronizable: Bool
    /// Whether macOS uses the data protection keychain, as iOS always does.
    ///
    /// Apple recommends the data protection keychain for new code. It needs an app signed with a
    /// team (the `application-identifier` or `keychain-access-groups` entitlement); a command-line
    /// tool or an ad-hoc signed app gets ``KeychainError/missingEntitlement``. Set it to `false` to
    /// use the user's login keychain instead. The value has no effect on other platforms.
    public let usesDataProtectionKeychain: Bool

    /// Creates a store for one service.
    ///
    /// - Parameters:
    ///   - service: A name for the store, such as your bundle identifier plus a suffix.
    ///   - accessGroup: A keychain access group listed in the app's entitlements, to share the
    ///     values with an extension or another app from the same team.
    ///   - accessibility: When values can be read. The default suits most tokens.
    ///   - synchronizable: `true` to sync through iCloud Keychain. It needs an accessibility
    ///     without `ThisDeviceOnly`.
    ///   - usesDataProtectionKeychain: See ``usesDataProtectionKeychain``.
    public init(
        service: String,
        accessGroup: String? = nil,
        accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly,
        synchronizable: Bool = false,
        usesDataProtectionKeychain: Bool = true
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.accessibility = accessibility
        self.isSynchronizable = synchronizable
        self.usesDataProtectionKeychain = usesDataProtectionKeychain
    }

    // MARK: - Data

    /// Stores data under a key, replacing any value already stored there.
    ///
    /// - Parameters:
    ///   - data: The value.
    ///   - key: A non-empty key of at most ``maximumKeyLength`` UTF-8 bytes.
    ///   - protection: Require Face ID, Touch ID or the passcode to read the value, or `nil`.
    ///     Protected values cannot be synchronizable.
    /// - Throws: ``KeychainError``.
    public func set(_ data: Data, forKey key: String, protection: KeychainProtection? = nil) throws(KeychainError) {
        try validate(key: key)
        if protection != nil && isSynchronizable {
            throw .invalidConfiguration("A value that requires authentication cannot sync through iCloud Keychain.")
        }
        var attributes = try query(forKey: key)
        attributes[kSecValueData as String] = data
        if let protection {
            attributes[kSecAttrAccessControl as String] = try accessControl(for: protection)
        } else {
            attributes[kSecAttrAccessible as String] = accessibility.secValue
        }

        let status = serialized { SecItemAdd(attributes as CFDictionary, nil) }
        guard status == errSecDuplicateItem else {
            try check(status)
            return
        }

        if protection == nil {
            var match = try query(forKey: key)
            disallowInteraction(in: &match)
            let changes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessibility.secValue,
            ]
            let updateStatus = serialized { SecItemUpdate(match as CFDictionary, changes as CFDictionary) }
            // An existing protected item cannot be changed without authenticating; replacing it
            // does not need authentication, and the caller asked for an unprotected value.
            guard updateStatus == errSecInteractionNotAllowed || updateStatus == errSecAuthFailed else {
                try check(updateStatus)
                return
            }
        }
        try removeValue(forKey: key)
        try check(serialized { SecItemAdd(attributes as CFDictionary, nil) })
    }

    /// Returns the data stored under a key, or `nil` if there is none.
    ///
    /// - Parameters:
    ///   - key: The key.
    ///   - prompt: The reason shown in the Face ID, Touch ID or passcode prompt when the value was
    ///     stored with a ``KeychainProtection``. Ignored for unprotected values, and on tvOS and
    ///     watchOS, which show the system's own text.
    /// - Throws: ``KeychainError``; ``KeychainError/userCanceled`` when the user dismisses the
    ///   prompt.
    public func data(forKey key: String, prompt: String? = nil) throws(KeychainError) -> Data? {
        try validate(key: key)
        var match = try query(forKey: key)
        match[kSecReturnData as String] = true
        match[kSecMatchLimit as String] = kSecMatchLimitOne
        #if canImport(LocalAuthentication) && !os(tvOS) && !os(watchOS)
        if let prompt, !prompt.isEmpty {
            let context = LAContext()
            context.localizedReason = prompt
            match[kSecUseAuthenticationContext as String] = context
        }
        #endif

        var result: CFTypeRef?
        let status = serialized { SecItemCopyMatching(match as CFDictionary, &result) }
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = result as? Data else { throw .unexpectedData }
        return data
    }

    /// Stores data only if the key has no value yet. Returns `false` when a value exists.
    func add(_ data: Data, forKey key: String) throws(KeychainError) -> Bool {
        try validate(key: key)
        var attributes = try query(forKey: key)
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = accessibility.secValue
        let status = serialized { SecItemAdd(attributes as CFDictionary, nil) }
        if status == errSecDuplicateItem { return false }
        try check(status)
        return true
    }

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

    // MARK: - Keys

    /// Returns whether a value is stored under a key, without asking the user to authenticate.
    public func contains(_ key: String) throws(KeychainError) -> Bool {
        try validate(key: key)
        var match = try query(forKey: key)
        match[kSecReturnAttributes as String] = true
        match[kSecMatchLimit as String] = kSecMatchLimitOne
        disallowInteraction(in: &match)
        var result: CFTypeRef?
        let status = serialized { SecItemCopyMatching(match as CFDictionary, &result) }
        switch status {
        case errSecSuccess, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        default:
            try check(status)
            return false
        }
    }

    /// Returns the keys stored in this service, sorted.
    public func keys() throws(KeychainError) -> [String] {
        var match = try query(forKey: nil)
        match[kSecReturnAttributes as String] = true
        match[kSecMatchLimit as String] = kSecMatchLimitAll
        disallowInteraction(in: &match)
        var result: CFTypeRef?
        let status = serialized { SecItemCopyMatching(match as CFDictionary, &result) }
        if status == errSecItemNotFound { return [] }
        try check(status)
        guard let items = result as? [[String: Any]] else { throw .unexpectedData }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }

    /// Removes the value stored under a key. Removing a key that has no value is not an error.
    public func removeValue(forKey key: String) throws(KeychainError) {
        try validate(key: key)
        let match = try query(forKey: key)
        let status = serialized { SecItemDelete(match as CFDictionary) }
        guard status != errSecItemNotFound else { return }
        try check(status)
    }

    /// Removes every value in this service.
    public func removeAll() throws(KeychainError) {
        // Deleting by key rather than with one service-wide query: the macOS login keychain
        // deletes only the first item that matches a query.
        for key in try keys() {
            try removeValue(forKey: key)
        }
    }

    // MARK: - Queries

    private func validate(key: String) throws(KeychainError) {
        guard !key.isEmpty, key.utf8.count <= Self.maximumKeyLength else {
            throw .invalidKey(key.isEmpty ? "The key is empty." : "The key is longer than \(Self.maximumKeyLength) bytes.")
        }
    }

    private func query(forKey key: String?) throws(KeychainError) -> [String: Any] {
        guard !service.isEmpty else {
            throw .invalidConfiguration("The service name is empty.")
        }
        if isSynchronizable && accessibility.isThisDeviceOnly {
            throw .invalidConfiguration("\(accessibility) values never leave the device, so they cannot sync through iCloud Keychain.")
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        // Without the attribute a query matches only items that do not sync, which keeps a
        // synchronizable store and a local one with the same service apart.
        if isSynchronizable { query[kSecAttrSynchronizable as String] = true }
        if let key { query[kSecAttrAccount as String] = key }
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        #if os(macOS)
        if usesDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        } else if isSynchronizable {
            throw .invalidConfiguration("iCloud Keychain sync needs the data protection keychain on macOS.")
        }
        #endif
        return query
    }

    private func disallowInteraction(in query: inout [String: Any]) {
        #if canImport(LocalAuthentication) && !os(tvOS)
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        #endif
    }

    private func accessControl(for protection: KeychainProtection) throws(KeychainError) -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, accessibility.secValue, protection.flags, &error) else {
            let description = error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown error"
            throw .invalidConfiguration("The access control could not be created: \(description)")
        }
        return control
    }

    /// Runs a Security framework call, one at a time when it goes to the macOS login keychain.
    ///
    /// Concurrent calls into the login keychain from one process can deadlock inside the
    /// Security framework; the data protection keychain has no such problem.
    private func serialized(_ call: () -> OSStatus) -> OSStatus {
        #if os(macOS)
        if !usesDataProtectionKeychain {
            loginKeychainLock.lock()
            defer { loginKeychainLock.unlock() }
            return call()
        }
        #endif
        return call()
    }

    private func check(_ status: OSStatus) throws(KeychainError) {
        guard status != errSecSuccess else { return }
        throw KeychainError(status: status)
    }
}
