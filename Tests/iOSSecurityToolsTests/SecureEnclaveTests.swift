import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SecureEnclaveKey on devices without a Secure Enclave", .enabled(if: !SecureEnclaveKey.isAvailable))
struct SecureEnclaveUnavailableTests {
    @Test("creating or restoring a key throws unavailable")
    func unavailable() {
        #expect(throws: SecureEnclaveError.unavailable) { try SecureEnclaveKey() }
        #expect(throws: SecureEnclaveError.unavailable) { try SecureEnclaveKey(dataRepresentation: Data(count: 32)) }
    }
}

@Suite("SecureEnclaveKey", .enabled(if: SecureEnclaveKey.isAvailable, "This machine has no Secure Enclave"))
struct SecureEnclaveKeyTests {
    @Test("signatures verify with the public key and fail for other data")
    func signAndVerify() throws {
        let key = try SecureEnclaveKey()
        let challenge = Data("login-challenge-7f3a".utf8)
        let signature = try key.signature(for: challenge)
        #expect(key.isValidSignature(signature, for: challenge))
        #expect(!key.isValidSignature(signature, for: Data("other".utf8)))
        #expect(!key.isValidSignature(Data([0x30, 0x00]), for: challenge))

        // A server that only has the DER public key verifies the same signature.
        let serverKey = try P256.Signing.PublicKey(derRepresentation: key.publicKeyDER)
        #expect(serverKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: signature), for: challenge))
        #expect(key.publicKeyX963.count == 65)
    }

    @Test("a restored key signs with the same private key")
    func restore() throws {
        let key = try SecureEnclaveKey()
        let restored = try SecureEnclaveKey(dataRepresentation: key.dataRepresentation)
        #expect(restored == key)
        let signature = try restored.signature(for: Data("x".utf8))
        #expect(key.isValidSignature(signature, for: Data("x".utf8)))
    }

    @Test("data that is not a Secure Enclave key is rejected", arguments: [Data(), Data(count: 32), Data(repeating: 0xFF, count: 300)])
    func invalidData(data: Data) {
        #expect(throws: SecureEnclaveError.invalidKeyData) { try SecureEnclaveKey(dataRepresentation: data) }
    }

    @Test("two keys are different")
    func distinct() throws {
        #expect(try SecureEnclaveKey().publicKeyX963 != SecureEnclaveKey().publicKeyX963)
    }

    @Test("the keychain creates the key once and returns it afterwards", .enabled(if: KeychainTestSupport.isAvailable))
    func keychainStorage() throws {
        let keychain = KeychainTestSupport.makeKeychain()
        defer { try? keychain.removeAll() }
        let first = try keychain.secureEnclaveKey(forKey: "device")
        let second = try keychain.secureEnclaveKey(forKey: "device")
        #expect(first == second)

        try keychain.set(Data(count: 16), forKey: "broken")
        #expect(throws: SecureEnclaveError.invalidKeyData) { try keychain.secureEnclaveKey(forKey: "broken") }
    }
}
