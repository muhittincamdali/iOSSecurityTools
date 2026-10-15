import Foundation
import Testing
@testable import iOSSecurityTools

/// Chooses a keychain the test process can write to.
///
/// The iOS simulator gives test bundles a data protection keychain. On macOS that keychain needs
/// a signed app with a team, which `swift test` does not have, so the tests fall back to the
/// login keychain there. When neither works (for example a locked login keychain on a build
/// machine), the keychain suites are skipped; CI runs them on the iOS simulator.
enum KeychainTestSupport {
    static let usesDataProtectionKeychain: Bool? = {
        for candidate in [true, false] {
            let keychain = Keychain(service: "iOSSecurityToolsTests.probe.\(UUID().uuidString)", usesDataProtectionKeychain: candidate)
            do {
                try keychain.set(Data([1]), forKey: "probe")
                try keychain.removeValue(forKey: "probe")
                return candidate
            } catch {
                continue
            }
        }
        return nil
    }()

    static var isAvailable: Bool { usesDataProtectionKeychain != nil }

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

@Suite("Keychain", .enabled(if: KeychainTestSupport.isAvailable, "No writable keychain in this test process"), .serialized)
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
