import CryptoKit
import Foundation

/// Signs JSON Web Tokens in compact form with `HS256`, `ES256` or `EdDSA`.
///
/// Use it for tokens the app itself issues: a signed request to your server, a proof of
/// possession of a device key, or test fixtures. The algorithm follows the key.
///
/// ```swift
/// let deviceKey = try Keychain(service: "com.example.app").signingKey(forKey: "device")
/// let signer = JWTSigner(signingKey: deviceKey)
/// let token = try signer.sign(JWTClaims(subject: "device-42", audience: ["api"],
///                                       expiration: .now.addingTimeInterval(300), issuedAt: .now))
/// ```
public struct JWTSigner: Sendable {
    private enum Key: Sendable {
        case hmac(MessageAuthenticator)
        case signingKey(SigningKey)
    }

    private let key: Key
    /// The algorithm written into the header.
    public let algorithm: JWTAlgorithm

    /// Creates an `HS256` signer.
    ///
    /// - Throws: ``JWTError/invalidConfiguration(_:)`` for a key shorter than 256 bits.
    public init(key: SymmetricKey) throws(JWTError) {
        guard key.bitCount >= 256, let authenticator = try? MessageAuthenticator(key: key) else {
            throw .invalidConfiguration("An HS256 key must have at least 256 bits, not \(key.bitCount).")
        }
        self.key = .hmac(authenticator)
        algorithm = .hs256
    }

    /// Creates an `ES256` signer for a P-256 key or an `EdDSA` signer for an Ed25519 key.
    public init(signingKey: SigningKey) {
        key = .signingKey(signingKey)
        algorithm = signingKey.algorithm == .p256 ? .es256 : .edDSA
    }

    /// Signs claims: ``JWTClaims`` or any `Encodable` type of your own, whose `Date` values are
    /// written as seconds since 1970.
    ///
    /// - Parameters:
    ///   - claims: The claim set, which must encode as a JSON object.
    ///   - keyID: An optional `kid` header value that tells the verifier which key to use.
    /// - Returns: The compact token, `header.claims.signature`.
    /// - Throws: ``JWTError/claimsCoding(_:)`` when the claims do not encode as an object (or a
    ///   date is not finite) or the token would be longer than
    ///   ``JWTVerifier/maximumTokenLength``, and ``JWTError/invalidConfiguration(_:)`` when the
    ///   key cannot sign.
    public func sign(_ claims: some Encodable, keyID: String? = nil) throws(JWTError) -> String {
        var header = ["alg": algorithm.rawValue, "typ": "JWT"]
        if let keyID { header["kid"] = keyID }
        let headerJSON = try JWTClaims.encoded(header)
        let claimsJSON = try JWTClaims.encoded(claims)
        guard claimsJSON.first == UInt8(ascii: "{") else {
            throw .claimsCoding("The claims must encode as a JSON object.")
        }
        let signingInput = Base64URL.encode(headerJSON) + "." + Base64URL.encode(claimsJSON)
        let signature: Data
        switch key {
        case .hmac(let authenticator):
            signature = authenticator.code(for: Data(signingInput.utf8))
        case .signingKey(let signingKey):
            do {
                signature = try signingKey.signature(for: Data(signingInput.utf8))
            } catch {
                throw .invalidConfiguration(error.localizedDescription)
            }
        }
        let token = signingInput + "." + Base64URL.encode(signature)
        guard token.utf8.count <= JWTVerifier.maximumTokenLength else {
            throw .claimsCoding("The token would be \(token.utf8.count) bytes, more than \(JWTVerifier.maximumTokenLength).")
        }
        return token
    }
}
