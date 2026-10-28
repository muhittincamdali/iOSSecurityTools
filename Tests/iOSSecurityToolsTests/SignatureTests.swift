import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

/// Vectors from scripts/make-interop-vectors.mjs, made with Node's crypto (OpenSSL).
private enum SignatureVectors {
    static let message = Data("Signed by another implementation".utf8)
    /// RFC 8032 §7.1 test 1: secret key and public key.
    static let ed25519Seed = Data(hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    static let ed25519Public = Data(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    static let ed25519PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
    static let ed25519Signature = Data(hex: "c11cc09b7cf80578358199fc344effac8082d19e99b01cf100d77f5d2df92d96833c546161ae9e15ab606fd6ce536d6143ee866d31323874dbf1c9e135adf608")
    static let p256Scalar = Data(hex: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    static let p256DER = Data(hex: "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
    static let p256SignatureRaw = Data(hex: "a4f548b00b4d879cc0007080371a60b6113c1b387326a52ea521dfa726326ae3f0551ca8fce121f7e8f586ede516818c5a10a6b5d67b66f312ae1a9b466c2f7a")
    static let p256SignatureDER = Data(hex: "3045022100a5dfc70a81204d7d92b064559a99c40e02fca9cab93c6ca5381ed5d122a73b640220233ce22ff8e2bddb8562b5b5f9fa42aa903843e7b48b53e605f4c02793d966bd")
}

@Suite("SigningKey and VerifyingKey")
struct SignatureTests {
    @Test("signs and verifies with both algorithms", arguments: SignatureAlgorithm.allCases)
    func roundTrip(algorithm: SignatureAlgorithm) throws {
        let key = SigningKey(algorithm: algorithm)
        #expect(key.algorithm == algorithm)
        for length in [0, 1, 64, 10_000] {
            let data = Data(repeating: 0x5A, count: length)
            let signature = try key.signature(for: data)
            #expect(signature.count == 64)
            #expect(key.publicKey.isValidSignature(signature, for: data))
        }
    }

    @Test("rejects a changed message, a changed signature and another key", arguments: SignatureAlgorithm.allCases)
    func rejectsChanges(algorithm: SignatureAlgorithm) throws {
        let key = SigningKey(algorithm: algorithm)
        let data = Data("transfer 25 EUR".utf8)
        let signature = try key.signature(for: data)
        #expect(!key.publicKey.isValidSignature(signature, for: Data("transfer 95 EUR".utf8)))
        for index in [0, 31, 32, 63] {
            var changed = signature
            changed[index] ^= 0x01
            #expect(!key.publicKey.isValidSignature(changed, for: data))
        }
        #expect(!SigningKey(algorithm: algorithm).publicKey.isValidSignature(signature, for: data))
    }

    @Test("returns false for empty, short and long signatures instead of trapping", arguments: SignatureAlgorithm.allCases)
    func malformedSignatures(algorithm: SignatureAlgorithm) throws {
        let key = SigningKey(algorithm: algorithm)
        let data = Data("x".utf8)
        let signature = try key.signature(for: data)
        for candidate in [Data(), Data(signature.prefix(63)), signature + Data([0]), Data(repeating: 0, count: 64), Data(repeating: 0xFF, count: 64)] {
            #expect(!key.publicKey.isValidSignature(candidate, for: data))
        }
    }

    @Test("reads a key back from its raw bytes", arguments: SignatureAlgorithm.allCases)
    func rawRoundTrip(algorithm: SignatureAlgorithm) throws {
        let key = SigningKey(algorithm: algorithm)
        let restored = try SigningKey(rawRepresentation: key.rawRepresentation, algorithm: algorithm)
        #expect(restored.publicKey == key.publicKey)
        let publicKey = try VerifyingKey(rawRepresentation: key.publicKey.rawRepresentation, algorithm: algorithm)
        #expect(publicKey == key.publicKey)
        #expect(try VerifyingKey(derRepresentation: key.publicKey.derRepresentation) == key.publicKey)
        #expect(try VerifyingKey(pemRepresentation: key.publicKey.pemRepresentation) == key.publicKey)
    }

    @Test("derives the RFC 8032 public key from its secret key")
    func rfc8032PublicKey() throws {
        let key = try SigningKey(rawRepresentation: SignatureVectors.ed25519Seed, algorithm: .ed25519)
        #expect(key.publicKey.rawRepresentation == SignatureVectors.ed25519Public)
    }

    @Test("verifies an Ed25519 signature and reads a PEM key made by OpenSSL")
    func ed25519Interoperability() throws {
        let publicKey = try VerifyingKey(pemRepresentation: SignatureVectors.ed25519PEM)
        #expect(publicKey.algorithm == .ed25519)
        #expect(publicKey.rawRepresentation == SignatureVectors.ed25519Public)
        #expect(publicKey.pemRepresentation + "\n" == SignatureVectors.ed25519PEM)
        #expect(publicKey.isValidSignature(SignatureVectors.ed25519Signature, for: SignatureVectors.message))
    }

    @Test("verifies raw and DER P-256 signatures made by OpenSSL and writes the same DER key")
    func p256Interoperability() throws {
        let publicKey = try VerifyingKey(derRepresentation: SignatureVectors.p256DER)
        #expect(publicKey.algorithm == .p256)
        #expect(publicKey.derRepresentation == SignatureVectors.p256DER)
        #expect(publicKey.isValidSignature(SignatureVectors.p256SignatureRaw, for: SignatureVectors.message))
        #expect(publicKey.isValidSignature(SignatureVectors.p256SignatureDER, for: SignatureVectors.message))
        let signingKey = try SigningKey(rawRepresentation: SignatureVectors.p256Scalar, algorithm: .p256)
        #expect(signingKey.publicKey == publicKey)
    }

    @Test("rejects private keys of the wrong size or out of range")
    func invalidPrivateKeys() {
        for algorithm in SignatureAlgorithm.allCases {
            for length in [0, 31, 33, 64] {
                #expect(throws: SignatureError.self) {
                    try SigningKey(rawRepresentation: Data(repeating: 1, count: length), algorithm: algorithm)
                }
            }
        }
        // P-256 scalars must be in [1, n - 1].
        #expect(throws: SignatureError.self) { try SigningKey(rawRepresentation: Data(count: 32), algorithm: .p256) }
        #expect(throws: SignatureError.self) { try SigningKey(rawRepresentation: Data(repeating: 0xFF, count: 32), algorithm: .p256) }
    }

    @Test("rejects public keys that are not keys")
    func invalidPublicKeys() {
        #expect(throws: SignatureError.self) { try VerifyingKey(rawRepresentation: Data(count: 31), algorithm: .ed25519) }
        // CryptoKit's raw P-256 initializer accepts these points that are not on the curve.
        #expect(throws: SignatureError.self) { try VerifyingKey(rawRepresentation: Data(count: 64), algorithm: .p256) }
        #expect(throws: SignatureError.self) { try VerifyingKey(rawRepresentation: Data(repeating: 0x11, count: 64), algorithm: .p256) }
        #expect(throws: SignatureError.self) { try VerifyingKey(rawRepresentation: Data(count: 65), algorithm: .p256) }
        #expect(throws: SignatureError.self) { try VerifyingKey(derRepresentation: Data()) }
        #expect(throws: SignatureError.self) { try VerifyingKey(derRepresentation: SignatureVectors.p256DER.dropLast()) }
        // An X25519 SubjectPublicKeyInfo (OID 1.3.101.110) is not a signing key.
        let x25519DER = Data(hex: "302a300506032b656e032100") + Data(repeating: 9, count: 32)
        #expect(throws: SignatureError.self) { try VerifyingKey(derRepresentation: x25519DER) }
    }

    @Test("rejects PEM text of another type, bad Base64 or unbounded length")
    func invalidPEM() {
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
        let cases = [
            "",
            "-----BEGIN PUBLIC KEY----------END PUBLIC KEY-----",
            "-----BEGIN PRIVATE KEY-----\n\(body)\n-----END PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----\n\(body.dropLast(4))!!!!\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\n\(body)\n",
            "-----BEGIN PUBLIC KEY-----\n" + String(repeating: "A", count: VerifyingKey.maximumPEMLength) + "\n-----END PUBLIC KEY-----",
        ]
        for text in cases {
            #expect(throws: SignatureError.self) { try VerifyingKey(pemRepresentation: text) }
        }
    }

    @Test("checks Secure Enclave style DER signatures through the wrapped CryptoKit key")
    func wrapsCryptoKitKeys() throws {
        let cryptoKitKey = P256.Signing.PrivateKey()
        let data = Data("challenge".utf8)
        let der = try cryptoKitKey.signature(for: data).derRepresentation
        #expect(VerifyingKey(cryptoKitKey.publicKey).isValidSignature(der, for: data))
        let ed = Curve25519.Signing.PrivateKey()
        #expect(try SigningKey(ed).publicKey == VerifyingKey(ed.publicKey))
    }

    @Test("never prints the private key bytes", arguments: SignatureAlgorithm.allCases)
    func redactedDescription(algorithm: SignatureAlgorithm) {
        let key = SigningKey(algorithm: algorithm)
        let rawHex = key.rawRepresentation.hex
        var dumped = ""
        dump(key, to: &dumped)
        for text in [String(describing: key), String(reflecting: key), "\(key)", dumped] {
            #expect(text.contains("<redacted>") || text.contains(algorithm.rawValue))
            #expect(!text.lowercased().contains(rawHex))
            #expect(!text.contains(key.rawRepresentation.base64EncodedString()))
        }
    }
}
