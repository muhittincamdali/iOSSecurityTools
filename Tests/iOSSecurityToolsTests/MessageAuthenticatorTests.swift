import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("MessageAuthenticator")
struct MessageAuthenticatorTests {
    let key = SymmetricKey(data: Data(hex: "0102030405060708090a0b0c0d0e0f10111213141516171819"))
    let data = Data(repeating: 0xCD, count: 50)

    @Test("matches RFC 4231 test case 4", arguments: [
        (MessageAuthenticator.Algorithm.sha256, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (.sha384, "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"),
        (.sha512, "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),
    ])
    func rfc4231(algorithm: MessageAuthenticator.Algorithm, expected: String) throws {
        let authenticator = try MessageAuthenticator(key: key, algorithm: algorithm)
        #expect(authenticator.hexCode(for: data) == expected)
        #expect(authenticator.code(for: data).count == algorithm.codeByteCount)
        #expect(authenticator.isValid(Data(hex: expected), for: data))
        #expect(authenticator.isValid(hexCode: expected, for: data))
        #expect(authenticator.isValid(hexCode: expected.uppercased(), for: data))
    }

    @Test("rejects a changed message or code")
    func rejectsChanges() throws {
        let authenticator = try MessageAuthenticator(key: key)
        let code = authenticator.code(for: data)
        #expect(!authenticator.isValid(code, for: data.dropLast()))
        for index in code.indices {
            var changed = code
            changed[index] ^= 0x80
            #expect(!authenticator.isValid(changed, for: data))
        }
    }

    @Test("returns false for codes of the wrong length or with stray characters")
    func malformedCodes() throws {
        let authenticator = try MessageAuthenticator(key: key)
        let hex = authenticator.hexCode(for: data)
        #expect(!authenticator.isValid(Data(), for: data))
        #expect(!authenticator.isValid(authenticator.code(for: data).prefix(16), for: data))
        #expect(!authenticator.isValid(authenticator.code(for: data) + Data([0]), for: data))
        for text in ["", "sha256=" + hex, " " + hex, hex + "\n", String(hex.dropLast()) + "g", String(hex.dropLast()), String(hex.dropLast(2)) + "é"] {
            #expect(!authenticator.isValid(hexCode: text, for: data))
        }
    }

    @Test("refuses keys shorter than 128 bits")
    func shortKeys() throws {
        #expect(throws: CipherError.invalidParameter("An HMAC key must have at least 128 bits, not 120.")) {
            try MessageAuthenticator(key: SymmetricKey(data: Data(count: 15)))
        }
        #expect(throws: CipherError.self) { try MessageAuthenticator(key: SymmetricKey(data: Data())) }
        _ = try MessageAuthenticator(key: SymmetricKey(data: Data(count: 16)))
    }

    @Test("decodes and encodes hexadecimal exactly")
    func hexadecimal() {
        #expect(Hexadecimal.encode(Data([0x00, 0x0F, 0xA0, 0xFF])) == "000fa0ff")
        #expect(Hexadecimal.decode("000FA0ff") == Data([0x00, 0x0F, 0xA0, 0xFF]))
        #expect(Hexadecimal.decode("") == Data())
        for text in ["0", "0g", "+1", "١٢"] {
            #expect(Hexadecimal.decode(text) == nil)
        }
    }
}
