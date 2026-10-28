import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

/// Low-order X25519 points (RFC 7748 §6.1): a shared secret with them is all zeros.
let lowOrderPoints = [
    Data(count: 32),
    Data([1] + [UInt8](repeating: 0, count: 31)),
    Data(hex: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
]

@Suite("KeyDerivation.sharedKey")
struct KeyAgreementTests {
    @Test("matches X25519 and HKDF-SHA256 computed by OpenSSL for the RFC 7748 keys")
    func rfc7748Interoperability() throws {
        // scripts/make-interop-vectors.mjs: the shared secret is the one in RFC 7748 §6.1.
        let alice = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let bob = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        #expect(bob.publicKey.rawRepresentation == Data(hex: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        let key = try KeyDerivation.sharedKey(privateKey: alice, peerPublicKey: bob.publicKey, salt: Data("salt-1".utf8), info: Data("sync v1".utf8))
        #expect(key.withUnsafeBytes { Data($0) } == Data(hex: "abd2f792182261e2048f8e5fa67918d41a8152a680644db071f02945dc867f17"))
    }

    @Test("gives both sides the same key and different keys for different labels")
    func bothSides() throws {
        let phone = Curve25519.KeyAgreement.PrivateKey()
        let watch = Curve25519.KeyAgreement.PrivateKey()
        let info = Data("sync v1".utf8)
        let phoneKey = try KeyDerivation.sharedKey(privateKey: phone, peerPublicKey: watch.publicKey, info: info)
        let watchKey = try KeyDerivation.sharedKey(privateKey: watch, peerPublicKey: phone.publicKey, info: info)
        #expect(phoneKey == watchKey)
        let other = try KeyDerivation.sharedKey(privateKey: phone, peerPublicKey: watch.publicKey, info: Data("backup v1".utf8))
        #expect(other != phoneKey)
        let cipher = try DataCipher(key: watchKey)
        #expect(try DataCipher(key: phoneKey).decryptString(cipher.encrypt("hello")) == "hello")
    }

    @Test("works with P-256 keys")
    func p256() throws {
        let first = P256.KeyAgreement.PrivateKey()
        let second = P256.KeyAgreement.PrivateKey()
        let info = Data("p256".utf8)
        #expect(try KeyDerivation.sharedKey(privateKey: first, peerPublicKey: second.publicKey, info: info)
            == KeyDerivation.sharedKey(privateKey: second, peerPublicKey: first.publicKey, info: info))
    }

    @Test("rejects a P-256 peer key that is not on the curve")
    func p256OffCurve() throws {
        // CryptoKit's raw initializer does not check the point; the key agreement must.
        let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: Data(repeating: 0x11, count: 64))
        #expect(throws: CipherError.self) {
            try KeyDerivation.sharedKey(privateKey: P256.KeyAgreement.PrivateKey(), peerPublicKey: peer, info: Data())
        }
    }

    @Test("rejects low-order peer keys, which give an all-zero secret", arguments: lowOrderPoints)
    func lowOrder(point: Data) throws {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: point)
        #expect(throws: CipherError.self) {
            try KeyDerivation.sharedKey(privateKey: Curve25519.KeyAgreement.PrivateKey(), peerPublicKey: peer, info: Data())
        }
    }

    @Test("rejects output sizes outside 16 to 8160 bytes", arguments: [Int.min, -1, 0, 15, 8161, Int.max])
    func outputSize(count: Int) {
        let key = Curve25519.KeyAgreement.PrivateKey()
        #expect(throws: CipherError.self) {
            try KeyDerivation.sharedKey(privateKey: key, peerPublicKey: Curve25519.KeyAgreement.PrivateKey().publicKey, info: Data(), outputByteCount: count)
        }
    }
}
