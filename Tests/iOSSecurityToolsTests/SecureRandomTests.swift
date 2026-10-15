import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SecureRandom")
struct SecureRandomTests {
    @Test("returns the requested number of bytes", arguments: [1, 16, 32, 1000, SecureRandom.maximumByteCount])
    func byteCount(count: Int) throws {
        #expect(try SecureRandom.bytes(count: count).count == count)
    }

    @Test("rejects counts outside 1...maximumByteCount", arguments: [Int.min, -1, 0, SecureRandom.maximumByteCount + 1, Int.max])
    func invalidByteCount(count: Int) {
        #expect(throws: SecureRandomError.invalidByteCount(count)) {
            try SecureRandom.bytes(count: count)
        }
    }

    @Test("two 32-byte draws differ")
    func drawsDiffer() throws {
        // A collision between two 256-bit draws has probability 2^-256; equal values mean the
        // generator is not being called.
        #expect(try SecureRandom.bytes(count: 32) != SecureRandom.bytes(count: 32))
    }

    @Test("base64url token has 43 URL-safe characters for 32 bytes")
    func base64URLToken() throws {
        let token = try SecureRandom.token()
        #expect(token.count == 43)
        #expect(token.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        #expect(Base64URL.decode(token)?.count == 32)
    }

    @Test("hex token has two lowercase hex digits per byte")
    func hexToken() throws {
        let token = try SecureRandom.token(byteCount: 16, encoding: .hex)
        #expect(token.count == 32)
        #expect(token.allSatisfy { "0123456789abcdef".contains($0) })
    }

    @Test("token rejects fewer than 16 or more than 1024 bytes", arguments: [-5, 0, 15, 1025])
    func invalidTokenLength(byteCount: Int) {
        #expect(throws: SecureRandomError.invalidByteCount(byteCount)) {
            try SecureRandom.token(byteCount: byteCount)
        }
    }

    @Test("base64url round-trips every length from 0 to 40 bytes")
    func base64URLRoundTrip() throws {
        for length in 0...40 {
            let data = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 250) })
            let encoded = Base64URL.encode(data)
            #expect(!encoded.contains("="))
            #expect(!encoded.contains("+"))
            #expect(!encoded.contains("/"))
            #expect(Base64URL.decode(encoded) == data)
        }
    }

    @Test("base64url decoding rejects other alphabets and impossible lengths", arguments: ["ab+c", "ab/c", "abc=", "a", "abcde", "ab c", "é"])
    func base64URLRejects(text: String) {
        #expect(Base64URL.decode(text) == nil)
    }
}

@Suite("ConstantTime")
struct ConstantTimeTests {
    @Test("equal bytes compare equal")
    func equalBytes() {
        #expect(ConstantTime.isEqual(Data([1, 2, 3]), [UInt8]([1, 2, 3])))
        #expect(ConstantTime.isEqual(Data(), Data()))
    }

    @Test("a difference in any position is found", arguments: 0..<8)
    func differenceAnywhere(position: Int) {
        let base = [UInt8](repeating: 0xAB, count: 8)
        var changed = base
        changed[position] ^= 0x01
        #expect(!ConstantTime.isEqual(base, changed))
    }

    @Test("different lengths are not equal, even when one is a prefix")
    func differentLengths() {
        #expect(!ConstantTime.isEqual([UInt8]([1, 2]), [UInt8]([1, 2, 3])))
        #expect(!ConstantTime.isEqual("12345", "123456"))
    }

    @Test("strings compare their UTF-8 bytes without normalization")
    func stringsWithoutNormalization() {
        #expect(ConstantTime.isEqual("123456", "123456"))
        #expect(!ConstantTime.isEqual("\u{E9}", "e\u{301}"))
    }
}
