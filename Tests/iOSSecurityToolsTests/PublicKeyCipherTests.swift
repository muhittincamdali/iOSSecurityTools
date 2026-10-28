import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("PublicKeyCipher")
struct PublicKeyCipherTests {
    let recipient = Curve25519.KeyAgreement.PrivateKey()
    let sender = Curve25519.KeyAgreement.PrivateKey()

    @Test("round-trips data of many lengths in both modes")
    func roundTrip() throws {
        for length in [0, 1, 16, 17, 4096] {
            let plaintext = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 7) })
            let anonymous = try PublicKeyCipher.seal(plaintext, to: recipient.publicKey)
            #expect(anonymous.count == plaintext.count + PublicKeyCipher.overhead)
            #expect(anonymous[0] == PublicKeyCipher.formatVersion)
            #expect(PublicKeyCipher.mode(of: anonymous) == .anonymous)
            #expect(try PublicKeyCipher.open(anonymous, using: recipient) == plaintext)

            let authenticated = try PublicKeyCipher.seal(plaintext, to: recipient.publicKey, from: sender)
            #expect(PublicKeyCipher.mode(of: authenticated) == .authenticated)
            #expect(try PublicKeyCipher.open(authenticated, using: recipient, from: sender.publicKey) == plaintext)
        }
    }

    @Test("uses a fresh ephemeral key for every envelope")
    func freshEphemeralKey() throws {
        let first = try PublicKeyCipher.seal("same", to: recipient.publicKey)
        let second = try PublicKeyCipher.seal("same", to: recipient.publicKey)
        #expect(first[2..<34] != second[2..<34])
        #expect(first[34...] != second[34...])
    }

    @Test("reads text and binds the associated data")
    func associatedData() throws {
        let envelope = try PublicKeyCipher.seal("See you at 7", to: recipient.publicKey, authenticating: Data("chat-9#41".utf8))
        #expect(try PublicKeyCipher.openString(envelope, using: recipient, authenticating: Data("chat-9#41".utf8)) == "See you at 7")
        #expect(throws: CipherError.authenticationFailed) {
            try PublicKeyCipher.open(envelope, using: recipient, authenticating: Data("chat-9#42".utf8))
        }
        #expect(throws: CipherError.authenticationFailed) { try PublicKeyCipher.open(envelope, using: recipient) }
    }

    @Test("detects a change to any byte of the envelope")
    func tamper() throws {
        let envelope = try PublicKeyCipher.seal(Data(repeating: 7, count: 40), to: recipient.publicKey)
        for index in envelope.indices {
            var changed = envelope
            changed[index] ^= 0x01
            #expect(throws: CipherError.self) { try PublicKeyCipher.open(changed, using: recipient) }
        }
    }

    @Test("does not open with another private key or a wrong sender")
    func wrongKeys() throws {
        let envelope = try PublicKeyCipher.seal("x", to: recipient.publicKey, from: sender)
        #expect(throws: CipherError.authenticationFailed) {
            try PublicKeyCipher.open(envelope, using: Curve25519.KeyAgreement.PrivateKey(), from: sender.publicKey)
        }
        #expect(throws: CipherError.authenticationFailed) {
            try PublicKeyCipher.open(envelope, using: recipient, from: Curve25519.KeyAgreement.PrivateKey().publicKey)
        }
    }

    @Test("an envelope cannot be opened in the other mode, even with its header byte changed")
    func modeConfusion() throws {
        let authenticated = try PublicKeyCipher.seal("x", to: recipient.publicKey, from: sender)
        #expect(throws: CipherError.self) { try PublicKeyCipher.open(authenticated, using: recipient) }
        var relabeled = authenticated
        relabeled[1] = PublicKeyCipher.Mode.anonymous.rawValue
        #expect(throws: CipherError.authenticationFailed) { try PublicKeyCipher.open(relabeled, using: recipient) }

        let anonymous = try PublicKeyCipher.seal("x", to: recipient.publicKey)
        #expect(throws: CipherError.self) { try PublicKeyCipher.open(anonymous, using: recipient, from: sender.publicKey) }
        var promoted = anonymous
        promoted[1] = PublicKeyCipher.Mode.authenticated.rawValue
        #expect(throws: CipherError.authenticationFailed) { try PublicKeyCipher.open(promoted, using: recipient, from: sender.publicKey) }
    }

    @Test("rejects short envelopes and unknown versions or modes")
    func malformed() throws {
        let envelope = try PublicKeyCipher.seal("x", to: recipient.publicKey)
        for candidate in [Data(), Data(envelope.prefix(PublicKeyCipher.overhead - 1)), Data([2]) + envelope.dropFirst(), Data([1, 0]) + envelope.dropFirst(2), Data([1, 9]) + envelope.dropFirst(2)] {
            #expect(PublicKeyCipher.mode(of: candidate) == nil)
            #expect {
                try PublicKeyCipher.open(candidate, using: recipient)
            } throws: { error in
                if case .malformedEnvelope = error as? CipherError { true } else { false }
            }
        }
    }

    @Test("opens an envelope that is a slice of a larger buffer")
    func sliceIndices() throws {
        let envelope = try PublicKeyCipher.seal("slice", to: recipient.publicKey)
        let buffer = Data([0xAA, 0xBB, 0xCC]) + envelope
        let slice = buffer[3...]
        #expect(PublicKeyCipher.mode(of: slice) == .anonymous)
        #expect(try PublicKeyCipher.openString(slice, using: recipient) == "slice")
    }

    @Test("reads 32-byte public keys and rejects other lengths")
    func publicKeyBytes() throws {
        let key = try PublicKeyCipher.publicKey(rawRepresentation: recipient.publicKey.rawRepresentation)
        #expect(key.rawRepresentation == recipient.publicKey.rawRepresentation)
        for length in [0, 31, 33, 65] {
            #expect(throws: CipherError.self) { try PublicKeyCipher.publicKey(rawRepresentation: Data(count: length)) }
        }
    }

    @Test("refuses to seal to a low-order public key", arguments: lowOrderPoints)
    func lowOrderRecipient(point: Data) throws {
        let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: point)
        #expect(throws: CipherError.self) { try PublicKeyCipher.seal("secret", to: key) }
    }
}
