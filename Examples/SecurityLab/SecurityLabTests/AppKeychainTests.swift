import Foundation
import iOSSecurityTools
import Testing
@testable import SecurityLab

/// Runs inside SecurityLab.app on the simulator, where the keychain is available.
@Suite("Keychain inside the app")
struct AppKeychainTests {
    @Test("the app process can use the data protection keychain")
    func keychainIsAvailable() {
        #expect(KeychainTestSupport.usesDataProtectionKeychain == true)
    }

    @Test("the README keychain sample returns the stored token")
    func readmeKeychainSample() throws {
        #expect(try keychainSample() == "r-7f3a9c")
    }

    @Test("the quick start stores and reads back an encrypted note")
    func quickStartFlow() throws {
        let keychain = Keychain(service: "SecurityLabTests.quickStart.\(UUID().uuidString)")
        defer { try? keychain.removeAll() }
        let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "notes-key"))
        try keychain.set(cipher.encrypt("Meet at 7 pm"), forKey: "note")
        let stored = try #require(try keychain.data(forKey: "note"))
        #expect(try cipher.decryptString(stored) == "Meet at 7 pm")
        #expect(try keychain.keys() == ["note", "notes-key"])
    }
}
