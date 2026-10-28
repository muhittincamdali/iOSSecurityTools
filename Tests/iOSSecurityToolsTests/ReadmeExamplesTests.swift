import Foundation
import Testing
@testable import iOSSecurityTools

/// Runs the README samples (ReadmeExamples.swift links to the example app's ReadmeSamples.swift)
/// that need no prompt, no network and no user.
@Suite("README samples")
struct ReadmeExamplesTests {
    @Test("encryption round-trips the note")
    func encryption() throws {
        #expect(try encryptionSample() == "Meet at 7 pm")
    }

    @Test("the PIN hash verifies with the default iterations")
    func pinHash() throws {
        #expect(try pinSample())
    }

    @Test("the scanned otpauth URI gives a code that verifies")
    func oneTimePassword() throws {
        #expect(try oneTimePasswordSample())
    }

    @Test("the pinned session is configured with the pinning delegate")
    func pinnedSession() throws {
        let session = try pinnedSessionSample()
        let delegate = try #require(session.delegate as? PinningURLSessionDelegate)
        #expect(delegate.policy.pinnedDomain(for: "www.letsencrypt.org")?.domain == "letsencrypt.org")
        session.invalidateAndCancel()
    }

    @Test("the integrity report lists what ran")
    func integrity() {
        let report = integritySample()
        #expect(report.checksRun.contains(.debugger))
        #expect(report.checksRun.contains(.injectedLibraries))
    }

    @Test("the redaction sample hides the password, card, email and token")
    func redaction() {
        let (request, log) = redactionSample()
        #expect(request == #"LoginRequest(username: "alice", _password: <redacted>)"#)
        #expect(log == "charged •••• 4242 to a•••@example.com, token=[redacted]")
    }

    @Test("the end-to-end sample opens the sealed message")
    func endToEnd() throws {
        #expect(try endToEndSample() == "See you at 7")
    }

    @Test("the signature sample verifies through the PEM key")
    func signature() throws {
        #expect(try signatureSample())
    }

    @Test("the token sample verifies and returns the subject")
    func token() throws {
        #expect(try tokenSample() == "user-42")
    }

    @Test("the keychain sample returns the token", .enabled(if: KeychainTestSupport.usesDataProtectionKeychain == true, "The README sample uses the data protection keychain"))
    func keychain() throws {
        #expect(try keychainSample() == "r-7f3a9c")
    }

    @Test("device binding signs the challenge", .enabled(if: SecureEnclaveKey.isAvailable && KeychainTestSupport.isAvailable))
    func deviceBinding() throws {
        // The sample's keychain uses the data protection keychain; where the tests fall back to the
        // login keychain, sign with a key that is not stored.
        let challenge = Data("challenge".utf8)
        if KeychainTestSupport.usesDataProtectionKeychain == true {
            let result = try #require(try deviceBindingSample(challenge: challenge))
            let key = try SecureEnclaveKey(dataRepresentation: try #require(try Keychain(service: "com.example.app.device").data(forKey: "device-key")))
            #expect(key.publicKeyDER == result.publicKey)
            #expect(key.isValidSignature(result.signature, for: challenge))
            try Keychain(service: "com.example.app.device").removeAll()
        } else {
            let key = try SecureEnclaveKey()
            #expect(key.isValidSignature(try key.signature(for: challenge), for: challenge))
        }
    }
}
