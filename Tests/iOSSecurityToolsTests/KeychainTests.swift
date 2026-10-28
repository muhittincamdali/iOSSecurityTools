import Foundation
import Testing
@testable import iOSSecurityTools

/// Chooses a keychain the test process can write to.
///
/// The keychain needs an entitlement that a test bundle without a host app lacks: on the iOS
/// simulator every call fails with `errSecMissingEntitlement`, and on macOS the data protection
/// keychain does too. On macOS the tests fall back to the login keychain. Where no keychain is
/// writable the suites are skipped with the reason in the log; the example app's test target runs
/// keychain round trips inside a signed app on the simulator.
enum KeychainTestSupport {
    static let probe: Result<Bool, KeychainError> = {
        var lastError = KeychainError.unexpectedData
        for candidate in [true, false] {
            let keychain = Keychain(service: "iOSSecurityToolsTests.probe.\(UUID().uuidString)", usesDataProtectionKeychain: candidate)
            do {
                try keychain.set(Data([1]), forKey: "probe")
                try keychain.removeValue(forKey: "probe")
                return .success(candidate)
            } catch {
                lastError = error as? KeychainError ?? .unexpectedData
            }
        }
        return .failure(lastError)
    }()

    static var usesDataProtectionKeychain: Bool? { try? probe.get() }

    static var isAvailable: Bool { usesDataProtectionKeychain != nil }

    /// Why the keychain suites are skipped, for the test log.
    static var unavailableReason: Comment {
        guard case .failure(let error) = probe else { return "" }
        return Comment(rawValue: "No writable keychain in this test process: \(error) (\(error.localizedDescription))")
    }

    static func makeKeychain(
        accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly,
        synchronizable: Bool = false
    ) -> Keychain {
        Keychain(
            service: "iOSSecurityToolsTests.\(UUID().uuidString)",
            accessibility: accessibility,
            synchronizable: synchronizable,
            usesDataProtectionKeychain: usesDataProtectionKeychain ?? true
        )
    }
}

@Suite("Keychain", .enabled(if: KeychainTestSupport.isAvailable, KeychainTestSupport.unavailableReason), .serialized)
struct KeychainTests {
    let keychain = KeychainTestSupport.makeKeychain()

    @Test("stores, reads and removes data")
    func dataRoundTrip() throws {
        defer { try? keychain.removeAll() }
        let secret = Data([0x00, 0xFF, 0x10, 0x80])
        try keychain.set(secret, forKey: "blob")
        #expect(try keychain.data(forKey: "blob") == secret)
        try keychain.removeValue(forKey: "blob")
        #expect(try keychain.data(forKey: "blob") == nil)
    }

    @Test("setting a key again replaces the value")
    func replacesValue() throws {
        defer { try? keychain.removeAll() }
        try keychain.set("first", forKey: "token")
        try keychain.set("second", forKey: "token")
        #expect(try keychain.string(forKey: "token") == "second")
        #expect(try keychain.keys() == ["token"])
    }

    @Test("a missing key reads as nil and removing it is not an error")
    func missingKey() throws {
        #expect(try keychain.data(forKey: "missing") == nil)
        #expect(try keychain.string(forKey: "missing") == nil)
        #expect(try !keychain.contains("missing"))
        try keychain.removeValue(forKey: "missing")
    }

    @Test("Codable values round-trip as JSON")
    func codableRoundTrip() throws {
        struct Session: Codable, Equatable {
            var accessToken: String
            var expiresAt: Date
        }
        defer { try? keychain.removeAll() }
        let session = Session(accessToken: "abc", expiresAt: Date(timeIntervalSince1970: 1_800_000_000))
        try keychain.setValue(session, forKey: "session")
        #expect(try keychain.value(Session.self, forKey: "session") == session)
        #expect(throws: KeychainError.self) {
            try keychain.value([Int].self, forKey: "session")
        }
    }

    @Test("non-UTF-8 bytes do not read as a string")
    func nonUTF8() throws {
        defer { try? keychain.removeAll() }
        try keychain.set(Data([0xC3, 0x28]), forKey: "bytes")
        #expect(throws: KeychainError.unexpectedData) {
            try keychain.string(forKey: "bytes")
        }
    }

    @Test("keys lists only this service, sorted, and removeAll empties it")
    func keysAndRemoveAll() throws {
        let other = KeychainTestSupport.makeKeychain()
        defer {
            try? keychain.removeAll()
            try? other.removeAll()
        }
        try keychain.set("1", forKey: "b")
        try keychain.set("2", forKey: "a")
        try keychain.set("3", forKey: "c")
        try other.set("x", forKey: "a")

        #expect(try keychain.keys() == ["a", "b", "c"])
        #expect(try keychain.contains("b"))
        try keychain.removeAll()
        #expect(try keychain.keys().isEmpty)
        #expect(try other.string(forKey: "a") == "x")
    }

    @Test("Unicode keys and an empty value are stored as given")
    func unicodeKeyAndEmptyValue() throws {
        defer { try? keychain.removeAll() }
        try keychain.set(Data(), forKey: "şifre-🔑")
        #expect(try keychain.data(forKey: "şifre-🔑") == Data())
        #expect(try keychain.keys() == ["şifre-🔑"])
    }
}

@Suite("Keychain validation")
struct KeychainValidationTests {
    @Test("empty and oversized keys are rejected before the keychain is called")
    func invalidKeys() {
        let keychain = Keychain(service: "iOSSecurityToolsTests.validation")
        let longKey = String(repeating: "k", count: Keychain.maximumKeyLength + 1)
        for key in ["", longKey] {
            #expect {
                try keychain.set("value", forKey: key)
            } throws: { error in
                guard case .invalidKey = error as? KeychainError else { return false }
                return true
            }
            #expect(throws: KeychainError.self) { try keychain.data(forKey: key) }
            #expect(throws: KeychainError.self) { try keychain.removeValue(forKey: key) }
        }
    }

    @Test("an empty service name is rejected")
    func emptyService() {
        #expect {
            try Keychain(service: "").set("value", forKey: "key")
        } throws: { error in
            guard case .invalidConfiguration = error as? KeychainError else { return false }
            return true
        }
    }

    @Test("synchronizable stores reject ThisDeviceOnly accessibility", arguments: KeychainAccessibility.allCases.filter(\.isThisDeviceOnly))
    func synchronizableThisDeviceOnly(accessibility: KeychainAccessibility) {
        let keychain = Keychain(service: "iOSSecurityToolsTests.sync", accessibility: accessibility, synchronizable: true)
        #expect {
            try keychain.set("value", forKey: "key")
        } throws: { error in
            guard case .invalidConfiguration = error as? KeychainError else { return false }
            return true
        }
    }

    @Test("synchronizable stores reject protected values")
    func synchronizableProtected() {
        let keychain = Keychain(service: "iOSSecurityToolsTests.sync", accessibility: .afterFirstUnlock, synchronizable: true)
        #expect {
            try keychain.set("value", forKey: "key", protection: .userPresence)
        } throws: { error in
            guard case .invalidConfiguration = error as? KeychainError else { return false }
            return true
        }
    }

    @Test("OSStatus values map to named errors")
    func statusMapping() {
        #expect(KeychainError(status: errSecMissingEntitlement) == .missingEntitlement)
        #expect(KeychainError(status: errSecInteractionNotAllowed) == .interactionNotAllowed)
        #expect(KeychainError(status: errSecUserCanceled) == .userCanceled)
        #expect(KeychainError(status: errSecAuthFailed) == .authenticationFailed)
        #expect(KeychainError(status: errSecDecode) == .unhandled(errSecDecode))
        #expect(KeychainError.unhandled(errSecDecode).errorDescription?.isEmpty == false)
    }

    @Test("protection levels are distinct")
    func protectionLevels() {
        let levels: Set<KeychainProtection> = [.userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode]
        #expect(levels.count == 4)
    }
}

@Suite("Keychain symmetric keys", .enabled(if: KeychainTestSupport.isAvailable, KeychainTestSupport.unavailableReason))
struct KeychainSymmetricKeyTests {
    @Test("creates a key once and returns the same key afterwards")
    func createsOnce() throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        let first = try keychain.symmetricKey(forKey: "master")
        let second = try keychain.symmetricKey(forKey: "master")
        #expect(first == second)
        #expect(first.bitCount == 256)
    }

    @Test("concurrent first calls agree on one key")
    func concurrentCreation() async throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        let keys = try await withThrowingTaskGroup(of: Data.self) { group in
            for _ in 0..<8 {
                group.addTask { try keychain.symmetricKey(forKey: "shared").withUnsafeBytes { Data($0) } }
            }
            return try await group.reduce(into: Set<Data>()) { $0.insert($1) }
        }
        #expect(keys.count == 1)
    }

    @Test("a stored value of the wrong size is not used as a key")
    func wrongSize() throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        try keychain.set(Data(count: 16), forKey: "short")
        #expect(throws: KeychainError.unexpectedData) { try keychain.symmetricKey(forKey: "short") }
    }
}

@Suite("Keychain key agreement and signing keys", .enabled(if: KeychainTestSupport.isAvailable, KeychainTestSupport.unavailableReason))
struct KeychainAsymmetricKeyTests {
    @Test("creates an X25519 key once and returns the same key afterwards")
    func keyAgreementKey() throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        let first = try keychain.keyAgreementKey(forKey: "device")
        let second = try keychain.keyAgreementKey(forKey: "device")
        #expect(first.rawRepresentation == second.rawRepresentation)
        let envelope = try PublicKeyCipher.seal("hello", to: first.publicKey)
        #expect(try PublicKeyCipher.openString(envelope, using: second) == "hello")
    }

    @Test("creates a signing key of each algorithm once")
    func signingKey() throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        for algorithm in SignatureAlgorithm.allCases {
            let first = try keychain.signingKey(forKey: "sign-\(algorithm.rawValue)", algorithm: algorithm)
            let second = try keychain.signingKey(forKey: "sign-\(algorithm.rawValue)", algorithm: algorithm)
            #expect(first.algorithm == algorithm)
            #expect(first.publicKey == second.publicKey)
            let data = Data("challenge".utf8)
            #expect(second.publicKey.isValidSignature(try first.signature(for: data), for: data))
        }
    }

    @Test("concurrent first calls agree on one signing key")
    func concurrentCreation() async throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        let keys = try await withThrowingTaskGroup(of: Data.self) { group in
            for _ in 0..<8 {
                group.addTask { try keychain.signingKey(forKey: "shared").publicKey.rawRepresentation }
            }
            return try await group.reduce(into: Set<Data>()) { $0.insert($1) }
        }
        #expect(keys.count == 1)
    }

    @Test("does not read a key stored for another algorithm or of the wrong size")
    func mismatches() throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        _ = try keychain.signingKey(forKey: "ed", algorithm: .ed25519)
        #expect(throws: KeychainError.unexpectedData) { try keychain.signingKey(forKey: "ed", algorithm: .p256) }
        try keychain.set(Data(count: 16), forKey: "short")
        #expect(throws: KeychainError.unexpectedData) { try keychain.keyAgreementKey(forKey: "short") }
        #expect(throws: KeychainError.unexpectedData) { try keychain.signingKey(forKey: "short") }
        // A P-256 private key must be below the curve order.
        try keychain.set(Data([2]) + Data(repeating: 0xFF, count: 32), forKey: "out-of-range")
        #expect(throws: KeychainError.unexpectedData) { try keychain.signingKey(forKey: "out-of-range", algorithm: .p256) }
    }
}
