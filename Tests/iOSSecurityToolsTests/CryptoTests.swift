import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

extension Data {
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

@Suite("DataCipher")
struct DataCipherTests {
    let key = SymmetricKey(data: Data(0..<32))

    @Test("round-trips data with both algorithms", arguments: DataCipher.Algorithm.allCases)
    func roundTrip(algorithm: DataCipher.Algorithm) throws {
        let cipher = try DataCipher(key: key, algorithm: algorithm)
        for length in [0, 1, 15, 16, 17, 1000] {
            let plaintext = Data((0..<length).map { UInt8(truncatingIfNeeded: $0) })
            let envelope = try cipher.encrypt(plaintext)
            #expect(envelope.count == plaintext.count + DataCipher.overhead)
            #expect(envelope[0] == DataCipher.formatVersion)
            #expect(envelope[1] == algorithm.rawValue)
            #expect(try cipher.decrypt(envelope) == plaintext)
        }
    }

    @Test("opens envelopes written by an independent implementation", arguments: [
        (DataCipher.Algorithm.aes256GCM, "0101000102030405060708090a0b026ca07ea98ab27ead36e5e2c59d1d03a3b4fe1491153008500297a5740470de647dcb92dba066f11bca0c3c3ef9c6355d0e50a5c74e8a889de8"),
        (DataCipher.Algorithm.chaChaPoly, "0102000102030405060708090a0bcc957e654578d52597f44d9aec696b0de912cbc7301ac2cd8ef25de51cadd65089ed499d927fc5f1585c0a38f74c7cf65b6e1501e5368de3636a"),
    ])
    func interoperability(algorithm: DataCipher.Algorithm, envelopeHex: String) throws {
        // Made with the Python `cryptography` package (AESGCM, ChaCha20Poly1305): key 00...1f,
        // nonce 00...0b, associated data = the two header bytes followed by "record-42".
        let cipher = try DataCipher(key: key, algorithm: .aes256GCM)
        let plaintext = try cipher.decryptString(Data(hex: envelopeHex), authenticating: Data("record-42".utf8))
        #expect(plaintext == "Envelope written by another implementation")
        #expect(Data(hex: envelopeHex)[1] == algorithm.rawValue)
    }

    @Test("uses a fresh nonce for every envelope")
    func freshNonce() throws {
        let cipher = try DataCipher(key: key)
        let first = try cipher.encrypt("same text")
        let second = try cipher.encrypt("same text")
        #expect(first[2..<14] != second[2..<14])
        #expect(first != second)
    }

    @Test("detects a change to any byte of the envelope")
    func tamperingAnyByte() throws {
        let cipher = try DataCipher(key: key)
        let envelope = try cipher.encrypt(Data("transfer 10 EUR".utf8))
        for index in envelope.indices {
            var tampered = envelope
            tampered[index] ^= 0x01
            #expect(throws: CipherError.self) { try cipher.decrypt(tampered) }
        }
    }

    @Test("a changed algorithm byte fails authentication instead of switching algorithms")
    func swappedAlgorithm() throws {
        let cipher = try DataCipher(key: key, algorithm: .aes256GCM)
        var envelope = try cipher.encrypt(Data("payload".utf8))
        envelope[1] = DataCipher.Algorithm.chaChaPoly.rawValue
        #expect(throws: CipherError.authenticationFailed) { try cipher.decrypt(envelope) }
    }

    @Test("wrong key, wrong associated data and truncation are rejected")
    func wrongInputs() throws {
        let cipher = try DataCipher(key: key)
        let envelope = try cipher.encrypt(Data("note".utf8), authenticating: Data("note-1".utf8))
        #expect(try cipher.decryptString(envelope, authenticating: Data("note-1".utf8)) == "note")

        let otherCipher = try DataCipher(key: DataCipher.generateKey())
        #expect(throws: CipherError.authenticationFailed) { try otherCipher.decrypt(envelope, authenticating: Data("note-1".utf8)) }
        #expect(throws: CipherError.authenticationFailed) { try cipher.decrypt(envelope, authenticating: Data("note-2".utf8)) }
        #expect(throws: CipherError.authenticationFailed) { try cipher.decrypt(envelope) }
        #expect(throws: CipherError.authenticationFailed) { try cipher.decrypt(envelope.dropLast(), authenticating: Data("note-1".utf8)) }
    }

    @Test("short, unversioned and unknown-algorithm data are malformed, not a crash")
    func malformed() throws {
        let cipher = try DataCipher(key: key)
        let inputs: [Data] = [
            Data(),
            Data([1]),
            Data(repeating: 0, count: DataCipher.overhead - 1),
            Data([2, 1]) + Data(repeating: 0, count: 28),
            Data([1, 9]) + Data(repeating: 0, count: 28),
        ]
        for input in inputs {
            #expect {
                try cipher.decrypt(input)
            } throws: { error in
                guard case .malformedEnvelope = error as? CipherError else { return false }
                return true
            }
        }
    }

    @Test("decrypting a slice of a larger buffer works")
    func sliceInput() throws {
        let cipher = try DataCipher(key: key)
        let envelope = try cipher.encrypt(Data("inside".utf8))
        let buffer = Data([0xAA, 0xBB]) + envelope
        #expect(try cipher.decryptString(buffer.dropFirst(2)) == "inside")
    }

    @Test("rejects keys that are not 256 bits", arguments: [128, 192, 512])
    func keySize(bits: Int) {
        #expect(throws: CipherError.invalidKeySize(bits)) {
            try DataCipher(key: SymmetricKey(data: Data(count: bits / 8)))
        }
    }

    @Test("non-UTF-8 plaintext does not decrypt to a string")
    func invalidUTF8() throws {
        let cipher = try DataCipher(key: key)
        let envelope = try cipher.encrypt(Data([0xFF, 0xFE]))
        #expect(throws: CipherError.invalidUTF8) { try cipher.decryptString(envelope) }
    }
}

@Suite("KeyDerivation")
struct KeyDerivationTests {
    @Test("matches RFC 5869 test case 1 (HKDF-SHA256)")
    func rfc5869() throws {
        let inputKey = SymmetricKey(data: Data(repeating: 0x0B, count: 22))
        let key = try KeyDerivation.derive(
            from: inputKey,
            salt: Data(hex: "000102030405060708090a0b0c"),
            info: Data(hex: "f0f1f2f3f4f5f6f7f8f9"),
            outputByteCount: 42
        )
        let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        #expect(key.withUnsafeBytes { Data($0) }.hex == expected)
    }

    @Test("different info labels give different keys")
    func labelsSeparateKeys() throws {
        let master = SymmetricKey(size: .bits256)
        let files = try KeyDerivation.derive(from: master, info: Data("files".utf8))
        let cache = try KeyDerivation.derive(from: master, info: Data("cache".utf8))
        #expect(files != cache)
        #expect(files.bitCount == 256)
    }

    @Test("rejects output sizes outside 16...8160 bytes", arguments: [Int.min, 0, 15, KeyDerivation.maximumOutputByteCount + 1, Int.max])
    func outputSize(count: Int) {
        #expect(throws: CipherError.self) {
            try KeyDerivation.derive(from: SymmetricKey(size: .bits256), info: Data(), outputByteCount: count)
        }
    }
}

@Suite("PasswordKeyDerivation")
struct PasswordKeyDerivationTests {
    let salt = Data("0123456789abcdef".utf8)

    @Test("matches the published PBKDF2-HMAC-SHA256 vector (c = 4096, dkLen = 40)")
    func publishedVector() throws {
        let key = try PasswordKeyDerivation.deriveKey(
            from: "passwordPASSWORDpassword",
            salt: Data("saltSALTsaltSALTsaltSALTsaltSALTsalt".utf8),
            iterations: 4096,
            outputByteCount: 40
        )
        #expect(key.withUnsafeBytes { Data($0) }.hex == "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
    }

    @Test("composed and decomposed accents give the same key")
    func normalization() throws {
        // Reference value: Python hashlib.pbkdf2_hmac("sha256", NFC("päss\u{308}word"), salt, 1000, 32).
        let composed = try PasswordKeyDerivation.deriveKey(from: "p\u{E4}ssword", salt: salt, iterations: 1000)
        let decomposed = try PasswordKeyDerivation.deriveKey(from: "pa\u{308}ssword", salt: salt, iterations: 1000)
        #expect(composed == decomposed)
        #expect(composed.withUnsafeBytes { Data($0) }.hex == "af26ecb819481c23842823e90ef4d596860790f12228e889aaa6062c21c07c5d")
    }

    @Test("rejects out-of-range parameters before deriving")
    func ranges() {
        let tooLongPassword = String(repeating: "a", count: 4097)
        let cases: [(String, Data, Int, Int)] = [
            ("", salt, 1000, 32),
            (tooLongPassword, salt, 1000, 32),
            ("pw", Data(count: 15), 1000, 32),
            ("pw", Data(count: 1025), 1000, 32),
            ("pw", salt, 999, 32),
            ("pw", salt, 10_000_001, 32),
            ("pw", salt, Int.max, 32),
            ("pw", salt, -1, 32),
            ("pw", salt, 1000, 15),
            ("pw", salt, 1000, 65),
        ]
        for (password, salt, iterations, count) in cases {
            #expect(throws: CipherError.self) {
                try PasswordKeyDerivation.deriveKey(from: password, salt: salt, iterations: iterations, outputByteCount: count)
            }
        }
    }
}

@Suite("PasswordHash")
struct PasswordHashTests {
    @Test("verifies the right PIN and rejects others")
    func verify() throws {
        let stored = try PasswordHash.make(for: "4921", iterations: 1000)
        #expect(stored.hasPrefix("$pbkdf2-sha256$i=1000$"))
        #expect(try PasswordHash.verify("4921", against: stored))
        #expect(try !PasswordHash.verify("4920", against: stored))
        #expect(try !PasswordHash.verify("49210", against: stored))
    }

    @Test("a password make(for:) rejects is a wrong entry, not an error")
    func passwordsOutsideTheRange() throws {
        let stored = try PasswordHash.make(for: "4921", iterations: 1000)
        #expect(try !PasswordHash.verify("", against: stored))
        #expect(try !PasswordHash.verify(String(repeating: "a", count: 4097), against: stored))
        #expect(throws: CipherError.self) { try PasswordHash.make(for: "", iterations: 1000) }
        // A malformed hash is still reported, whatever the password.
        #expect(throws: CipherError.self) { try PasswordHash.verify("", against: "not a hash") }
    }

    @Test("salts every hash")
    func salted() throws {
        #expect(try PasswordHash.make(for: "same", iterations: 1000) != PasswordHash.make(for: "same", iterations: 1000))
    }

    @Test("verifies a hash made by another implementation")
    func interoperability() throws {
        // Python: salt = b"0123456789abcdef", hashlib.pbkdf2_hmac("sha256", "pässwörd", salt, 1000, 32),
        // both base64 without padding.
        let salt = Data("0123456789abcdef".utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")
        let hash = Data(hex: "29fc5de205445490145b210cf7f2ae07507469016afaa572ac58b8e109f26789").base64EncodedString().replacingOccurrences(of: "=", with: "")
        let encoded = "$pbkdf2-sha256$i=1000$\(salt)$\(hash)"
        #expect(try PasswordHash.verify("pässwörd", against: encoded))
    }

    @Test("reports hashes made with fewer iterations")
    func rehash() throws {
        let stored = try PasswordHash.make(for: "pw", iterations: 1000)
        #expect(try PasswordHash.needsRehash(stored))
        #expect(try !PasswordHash.needsRehash(stored, iterations: 1000))
    }

    @Test("rejects malformed and hostile encodings without running PBKDF2", arguments: [
        "",
        "pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$argon2id$i=1000$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=999999999999$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=99999999999999999999999$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=-1000$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=+1000$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=01000$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=1000$c2FsdA$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFiY2RlZg$!!!",
        "$pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFiY2RlZg==$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k",
        "$pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFiY2RlZg$KfxeQgVEVJAUWyEM9/KuB1B0aQFq+qVyrFi44Qnyw4k$extra",
    ])
    func malformed(encoded: String) {
        #expect {
            try PasswordHash.verify("pw", against: encoded)
        } throws: { error in
            guard case .malformedHash = error as? CipherError else { return false }
            return true
        }
    }

    @Test("rejects encodings longer than the limit before splitting them")
    func overlong() {
        let encoded = "$pbkdf2-sha256$i=1000$" + String(repeating: "A", count: PasswordHash.maximumEncodedLength)
        #expect(throws: CipherError.self) { try PasswordHash.verify("pw", against: encoded) }
    }
}
