import CryptoKit
import Foundation
import Testing
@testable import iOSSecurityTools

/// Tokens from scripts/make-interop-vectors.mjs, signed by Node's crypto (OpenSSL) over
/// `{"iss":"https://auth.example.com","sub":"user-42","aud":["ios-app","web"],"iat":1767225600,
/// "nbf":1767225600,"exp":4102444800,"scope":"read"}`.
private enum JWTVectors {
    static let hsKey = SymmetricKey(data: Data(0..<32))
    static let hs256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLTQyIiwiYXVkIjpbImlvcy1hcHAiLCJ3ZWIiXSwiaWF0IjoxNzY3MjI1NjAwLCJuYmYiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMCwic2NvcGUiOiJyZWFkIn0.myxWOy_eSc1rgaENjbGNrQe36DbmYTJ70SiBvXsNUT4"
    static let es256 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLTQyIiwiYXVkIjpbImlvcy1hcHAiLCJ3ZWIiXSwiaWF0IjoxNzY3MjI1NjAwLCJuYmYiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMCwic2NvcGUiOiJyZWFkIn0.DIU9Z4hX0HNzB3siX0H162IPYQxKwC-1IaQ_m6DnfjUkf6aTTjODHKx3GJIxCRcQItGFXkaM0LUvpFuUYj5-BA"
    static let edDSA = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLTQyIiwiYXVkIjpbImlvcy1hcHAiLCJ3ZWIiXSwiaWF0IjoxNzY3MjI1NjAwLCJuYmYiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMCwic2NvcGUiOiJyZWFkIn0.6Xrgdzr3ElhrNPjKO7dJn9gvVcNjHTnUxvElR1LDyuyfEsbzjAnhNSERQXJQE6ltUMKU3BbT7jNLEhXsiTmICg"
    static let p256Public = Data(hex: "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
    static let ed25519Public = Data(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
}

/// Signs any header and claims text with HS256, to build tokens a correct signer never writes.
private func forge(header: String, claims: String, key: SymmetricKey = JWTVectors.hsKey) -> String {
    let input = Base64URL.encode(Data(header.utf8)) + "." + Base64URL.encode(Data(claims.utf8))
    let code = Data(HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: key))
    return input + "." + Base64URL.encode(code)
}

private let hsHeader = #"{"alg":"HS256"}"#

@Suite("JWTVerifier")
struct JWTVerifierTests {
    let verifier = try! JWTVerifier(key: JWTVectors.hsKey, issuer: "https://auth.example.com", audience: "ios-app")

    private func expectError(_ token: String, using verifier: JWTVerifier? = nil, now: Date = JWTVectors.now, _ matches: (JWTError) -> Bool) {
        #expect {
            try (verifier ?? self.verifier).verify(token, now: now)
        } throws: { error in
            guard let error = error as? JWTError else { return false }
            return matches(error)
        }
    }

    @Test("verifies HS256, ES256 and EdDSA tokens signed by OpenSSL")
    func interoperability() throws {
        let p256 = try JWTVerifier(publicKey: VerifyingKey(derRepresentation: JWTVectors.p256Public), issuer: "https://auth.example.com", audience: "web")
        let ed = try JWTVerifier(publicKey: VerifyingKey(rawRepresentation: JWTVectors.ed25519Public, algorithm: .ed25519), audience: "ios-app")
        for (token, verifier) in [(JWTVectors.hs256, verifier), (JWTVectors.es256, p256), (JWTVectors.edDSA, ed)] {
            let claims = try verifier.verify(token, now: JWTVectors.now)
            #expect(claims.issuer == "https://auth.example.com")
            #expect(claims.subject == "user-42")
            #expect(claims.audience == ["ios-app", "web"])
            #expect(claims.expiration == Date(timeIntervalSince1970: 4_102_444_800))
            #expect(claims.notBefore == Date(timeIntervalSince1970: 1_767_225_600))
            #expect(claims.issuedAt == Date(timeIntervalSince1970: 1_767_225_600))
        }
        struct Scoped: Decodable { let sub: String; let scope: String; let exp: Date }
        let scoped = try verifier.verify(JWTVectors.hs256, as: Scoped.self, now: JWTVectors.now)
        #expect(scoped.scope == "read")
        #expect(scoped.exp == Date(timeIntervalSince1970: 4_102_444_800))
    }

    @Test("rejects a header that names another algorithm than the key's, none included")
    func algorithmMismatch() throws {
        let edVerifier = try JWTVerifier(publicKey: VerifyingKey(rawRepresentation: JWTVectors.ed25519Public, algorithm: .ed25519), audience: "ios-app")
        expectError(JWTVectors.hs256, using: edVerifier) { $0 == .algorithmMismatch(expected: "EdDSA", found: "HS256") }
        expectError(JWTVectors.edDSA) { $0 == .algorithmMismatch(expected: "HS256", found: "EdDSA") }
        let unsigned = Base64URL.encode(Data(#"{"alg":"none"}"#.utf8)) + "." + Base64URL.encode(Data(#"{"exp":4102444800}"#.utf8)) + "."
        expectError(unsigned) { $0 == .algorithmMismatch(expected: "HS256", found: "none") }
        // The classic confusion: HS256 keyed with the public key bytes, sent to a public key verifier.
        let confused = forge(header: hsHeader, claims: #"{"exp":4102444800}"#, key: SymmetricKey(data: JWTVectors.ed25519Public))
        expectError(confused, using: edVerifier) { $0 == .algorithmMismatch(expected: "EdDSA", found: "HS256") }
        expectError(forge(header: #"{"typ":"JWT"}"#, claims: "{}")) { if case .malformed = $0 { true } else { false } }
        expectError(forge(header: #"{"alg":["HS256"]}"#, claims: "{}")) { if case .malformed = $0 { true } else { false } }
    }

    @Test("rejects changed signatures, claims and DER-encoded ES256 signatures")
    func signatures() throws {
        var parts = JWTVectors.hs256.split(separator: ".").map(String.init)
        let changedClaims = Base64URL.encode(Data(#"{"sub":"admin","exp":4102444800}"#.utf8))
        expectError([parts[0], changedClaims, parts[2]].joined(separator: ".")) { $0 == .invalidSignature }
        parts[2] = String(parts[2].dropLast()) + (parts[2].hasSuffix("A") ? "Q" : "A")
        expectError(parts.joined(separator: ".")) { if case .invalidSignature = $0 { true } else if case .malformed = $0 { true } else { false } }
        expectError(forge(header: hsHeader, claims: #"{"exp":4102444800}"#, key: SymmetricKey(data: Data(repeating: 9, count: 32)))) { $0 == .invalidSignature }

        let p256Key = try VerifyingKey(derRepresentation: JWTVectors.p256Public)
        let es = JWTVectors.es256.split(separator: ".").map(String.init)
        let raw = try #require(Base64URL.strictDecode(ArraySlice(es[2].utf8)))
        let der = try P256.Signing.ECDSASignature(rawRepresentation: raw).derRepresentation
        #expect(p256Key.isValidSignature(der, for: Data("\(es[0]).\(es[1])".utf8)))
        let derToken = "\(es[0]).\(es[1]).\(Base64URL.encode(der))"
        expectError(derToken, using: try JWTVerifier(publicKey: p256Key, audience: "web")) { $0 == .invalidSignature }
    }

    @Test("checks exp and nbf with the leeway, failing closed for a NaN clock")
    func times() throws {
        let token = forge(header: hsHeader, claims: #"{"exp":1800000000,"nbf":1799999000}"#)
        let strict = try JWTVerifier(key: JWTVectors.hsKey, leeway: 0)
        #expect(throws: Never.self) { try strict.verify(token, now: Date(timeIntervalSince1970: 1_799_999_999)) }
        #expect(throws: JWTError.expired(Date(timeIntervalSince1970: 1_800_000_000))) { try strict.verify(token, now: Date(timeIntervalSince1970: 1_800_000_000)) }
        #expect(throws: JWTError.notYetValid(Date(timeIntervalSince1970: 1_799_999_000))) { try strict.verify(token, now: Date(timeIntervalSince1970: 1_799_998_999)) }
        let lenient = try JWTVerifier(key: JWTVectors.hsKey, leeway: 60)
        #expect(throws: Never.self) { try lenient.verify(token, now: Date(timeIntervalSince1970: 1_800_000_059)) }
        #expect(throws: JWTError.self) { try lenient.verify(token, now: Date(timeIntervalSince1970: 1_800_000_060)) }
        #expect(throws: Never.self) { try lenient.verify(token, now: Date(timeIntervalSince1970: 1_799_998_940)) }
        for clock in [Double.nan, .infinity, -.infinity] {
            #expect(throws: JWTError.self) { try lenient.verify(token, now: Date(timeIntervalSince1970: clock)) }
        }
    }

    @Test("requires exp unless told otherwise, and rejects dates that are not finite numbers")
    func dateClaims() throws {
        let noExpiration = forge(header: hsHeader, claims: #"{"sub":"x"}"#)
        let verifier = try JWTVerifier(key: JWTVectors.hsKey)
        #expect(throws: JWTError.missingClaim("exp")) { try verifier.verify(noExpiration) }
        #expect(try JWTVerifier(key: JWTVectors.hsKey, requiresExpiration: false).verify(noExpiration).subject == "x")
        for value in [#""4102444800""#, "true", "null", "1e400", "-1e400", "[1]", #"{"t":1}"#] {
            let token = forge(header: hsHeader, claims: #"{"exp":\#(value)}"#)
            #expect(throws: JWTError.self) { try verifier.verify(token) }
            let nbf = forge(header: hsHeader, claims: #"{"exp":4102444800,"nbf":\#(value)}"#)
            #expect(throws: JWTError.self) { try verifier.verify(nbf) }
        }
        // Extreme but finite dates do not trap.
        #expect(throws: Never.self) { try verifier.verify(forge(header: hsHeader, claims: #"{"exp":1.7976931348623157e308,"iat":-1.7976931348623157e308}"#)) }
        #expect(throws: JWTError.self) { try verifier.verify(forge(header: hsHeader, claims: #"{"exp":-9223372036854775809}"#)) }
    }

    @Test("checks the issuer and the audience")
    func issuerAndAudience() throws {
        let wrongIssuer = forge(header: hsHeader, claims: #"{"exp":4102444800,"iss":"https://evil.example","aud":"ios-app"}"#)
        expectError(wrongIssuer) { $0 == .issuerMismatch(expected: "https://auth.example.com", found: "https://evil.example") }
        let noIssuer = forge(header: hsHeader, claims: #"{"exp":4102444800,"aud":"ios-app"}"#)
        expectError(noIssuer) { $0 == .issuerMismatch(expected: "https://auth.example.com", found: nil) }

        let otherAudience = forge(header: hsHeader, claims: #"{"exp":4102444800,"iss":"https://auth.example.com","aud":["web"]}"#)
        expectError(otherAudience) { $0 == .audienceMismatch(expected: "ios-app", found: ["web"]) }
        let anyVerifier = try JWTVerifier(key: JWTVectors.hsKey)
        #expect(throws: JWTError.audienceMismatch(expected: nil, found: ["web"])) { try anyVerifier.verify(otherAudience) }
        let noAudience = forge(header: hsHeader, claims: #"{"exp":4102444800}"#)
        #expect(throws: Never.self) { try anyVerifier.verify(noAudience) }
        for value in ["1", "[1]", #"["ios-app",2]"#, "null", "{}"] {
            let token = forge(header: hsHeader, claims: #"{"exp":4102444800,"iss":"https://auth.example.com","aud":\#(value)}"#)
            #expect(throws: JWTError.self) { try verifier.verify(token) }
        }
        for name in ["iss", "sub", "jti"] {
            #expect(throws: JWTError.self) { try anyVerifier.verify(forge(header: hsHeader, claims: #"{"exp":4102444800,"\#(name)":7}"#)) }
        }
    }

    @Test("rejects repeated member names, crit and JSON that is not an object")
    func structure() throws {
        let verifier = try JWTVerifier(key: JWTVectors.hsKey)
        let cases = [
            forge(header: #"{"alg":"HS256","alg":"none"}"#, claims: #"{"exp":4102444800}"#),
            forge(header: hsHeader, claims: #"{"exp":4102444800,"exp":1}"#),
            forge(header: hsHeader, claims: #"{"exp":4102444800,"sub":"a","sub":"b"}"#),
            forge(header: #"{"alg":"HS256","crit":["exp"]}"#, claims: #"{"exp":4102444800}"#),
            forge(header: hsHeader, claims: "[]"),
            forge(header: hsHeader, claims: "4102444800"),
            forge(header: hsHeader, claims: #"{"exp":4102444800,}"#),
            forge(header: hsHeader, claims: "\u{FEFF}{\"exp\":4102444800}"),
            forge(header: "[]", claims: #"{"exp":4102444800}"#),
        ]
        for token in cases {
            #expect { try verifier.verify(token) } throws: { error in
                if case .malformed = error as? JWTError { true } else { false }
            }
        }
        // Invalid UTF-8 in the claims.
        let input = Base64URL.encode(Data(hsHeader.utf8)) + "." + Base64URL.encode(Data([0x7B, 0xFF, 0x7D]))
        let code = Data(HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: JWTVectors.hsKey))
        #expect(throws: JWTError.self) { try verifier.verify(input + "." + Base64URL.encode(code)) }
    }

    @Test("rejects tokens that are not three canonical Base64URL parts, or too long")
    func encoding() throws {
        let verifier = try JWTVerifier(key: JWTVectors.hsKey)
        let token = forge(header: hsHeader, claims: #"{"exp":4102444800}"#)
        let parts = token.split(separator: ".").map(String.init)
        let cases = [
            "", ".", "..", "a.b", token + ".", token + ".x", " " + token, token + "\n",
            "\(parts[0])=.\(parts[1]).\(parts[2])",
            "\(parts[0]).\(parts[1]).\(parts[2].replacingOccurrences(of: "_", with: "/").replacingOccurrences(of: "-", with: "+"))+",
            ".\(parts[1]).\(parts[2])",
            "\(parts[0])..\(parts[2])",
            "\(parts[0]).\(parts[1]).",
            "\(parts[0]).\(parts[1]).\(parts[2])A",
            // "QR" has unused bits set: it must not decode to the "A" that "QQ" encodes.
            "\(parts[0]).\(parts[1]).\(parts[2].dropLast(2))QR",
            String(repeating: "a", count: JWTVerifier.maximumTokenLength + 1),
        ]
        for text in cases {
            #expect(throws: JWTError.self) { try verifier.verify(text) }
        }
        #expect(Base64URL.strictDecode(ArraySlice("eyJ9".utf8)) == Data(#"{"}"#.utf8))
        #expect(Base64URL.strictDecode(ArraySlice("QQ".utf8)) == Data("A".utf8))
        #expect(Base64URL.strictDecode(ArraySlice("QR".utf8)) == nil)
        #expect(Base64URL.strictDecode(ArraySlice("Q".utf8)) == nil)
        #expect(Base64URL.strictDecode(ArraySlice("".utf8)) == Data())
    }

    @Test("reads a token of exactly the length limit")
    func lengthLimit() throws {
        let verifier = try JWTVerifier(key: JWTVectors.hsKey)
        let empty = forge(header: hsHeader, claims: #"{"exp":4102444800,"p":""}"#)
        // Each 3 bytes of padding text add 4 Base64URL characters.
        let room = (JWTVerifier.maximumTokenLength - empty.utf8.count) / 4 * 3
        let filled = forge(header: hsHeader, claims: #"{"exp":4102444800,"p":"\#(String(repeating: "x", count: room))"}"#)
        #expect(filled.utf8.count <= JWTVerifier.maximumTokenLength)
        #expect(throws: Never.self) { try verifier.verify(filled) }
        let over = forge(header: hsHeader, claims: #"{"exp":4102444800,"p":"\#(String(repeating: "x", count: room + 3))"}"#)
        #expect(throws: JWTError.self) { try verifier.verify(over) }
    }

    @Test("refuses short HS256 keys and leeways out of range")
    func configuration() {
        #expect(throws: JWTError.self) { try JWTVerifier(key: SymmetricKey(data: Data(count: 31))) }
        #expect(throws: JWTError.self) { try JWTSigner(key: SymmetricKey(data: Data(count: 16))) }
        for leeway in [-1, .nan, .infinity, JWTVerifier.maximumLeeway + 1] {
            #expect(throws: JWTError.self) { try JWTVerifier(key: JWTVectors.hsKey, leeway: leeway) }
        }
    }
}

@Suite("JWTSigner")
struct JWTSignerTests {
    @Test("signs tokens that the verifier accepts with every algorithm")
    func roundTrip() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let claims = JWTClaims(issuer: "app", subject: "device-42", audience: ["api"], expiration: now.addingTimeInterval(300), issuedAt: now, tokenID: "n-1")
        let edKey = SigningKey(algorithm: .ed25519)
        let pKey = SigningKey(algorithm: .p256)
        let pairs: [(JWTSigner, JWTVerifier)] = [
            (try JWTSigner(key: JWTVectors.hsKey), try JWTVerifier(key: JWTVectors.hsKey, issuer: "app", audience: "api")),
            (JWTSigner(signingKey: edKey), try JWTVerifier(publicKey: edKey.publicKey, issuer: "app", audience: "api")),
            (JWTSigner(signingKey: pKey), try JWTVerifier(publicKey: pKey.publicKey, issuer: "app", audience: "api")),
        ]
        for (signer, verifier) in pairs {
            #expect(signer.algorithm == verifier.algorithm)
            let token = try signer.sign(claims, keyID: "key-1")
            let verified = try verifier.verify(token, now: now)
            #expect(verified.subject == "device-42")
            #expect(verified.tokenID == "n-1")
            #expect(verified.expiration == claims.expiration)
            let header = try #require(Base64URL.strictDecode(ArraySlice(token.split(separator: ".")[0].utf8)))
            #expect(String(decoding: header, as: UTF8.self) == #"{"alg":"\#(signer.algorithm.rawValue)","kid":"key-1","typ":"JWT"}"#)
        }
    }

    @Test("writes whole-second dates as integers and keeps fractions")
    func numericDates() throws {
        let signer = try JWTSigner(key: JWTVectors.hsKey)
        let token = try signer.sign(JWTClaims(expiration: Date(timeIntervalSince1970: 4_102_444_800), notBefore: Date(timeIntervalSince1970: 1.5)))
        let claims = try #require(Base64URL.strictDecode(ArraySlice(token.split(separator: ".")[1].utf8)))
        #expect(String(decoding: claims, as: UTF8.self) == #"{"exp":4102444800,"nbf":1.5}"#)
        let single = try signer.sign(JWTClaims(audience: ["one"]))
        let singleClaims = try #require(Base64URL.strictDecode(ArraySlice(single.split(separator: ".")[1].utf8)))
        #expect(String(decoding: singleClaims, as: UTF8.self) == #"{"aud":"one"}"#)
    }

    @Test("throws instead of trapping for dates that are not finite and for claims that are not an object")
    func invalidClaims() throws {
        let signer = try JWTSigner(key: JWTVectors.hsKey)
        for seconds in [Double.nan, .infinity, -.infinity] {
            #expect(throws: JWTError.self) { try signer.sign(JWTClaims(expiration: Date(timeIntervalSince1970: seconds))) }
        }
        #expect(throws: JWTError.self) { try signer.sign(["a", "b"]) }
        #expect(throws: JWTError.self) { try signer.sign("text") }
        struct Big: Encodable { let p: String }
        #expect(throws: JWTError.self) { try signer.sign(Big(p: String(repeating: "x", count: JWTVerifier.maximumTokenLength))) }
        #expect(throws: Never.self) { try signer.sign(JWTClaims(expiration: Date(timeIntervalSince1970: 1e300))) }
    }

    @Test("decodes created claims into a custom type")
    func decodeCreated() throws {
        struct Subject: Decodable { let sub: String }
        #expect(try JWTClaims(subject: "s-1").decode(Subject.self).sub == "s-1")
        #expect(throws: JWTError.self) { try JWTClaims().decode(Subject.self) }
    }
}
