import CryptoKit
import Foundation

/// A JSON Web Signature algorithm (RFC 7518 §3.1, RFC 8037).
public enum JWTAlgorithm: String, Sendable, Hashable, CaseIterable, Codable {
    /// HMAC with SHA-256 and a shared key.
    case hs256 = "HS256"
    /// ECDSA with P-256 and SHA-256.
    case es256 = "ES256"
    /// Ed25519.
    case edDSA = "EdDSA"
}

/// Checks the signature and the time and audience claims of a JSON Web Token (RFC 7519) in
/// compact form.
///
/// The verifier holds one key, and the key decides the algorithm: a token whose header names
/// another algorithm — `none`, or `HS256` with a public key — is rejected before anything else
/// is read. The signature is checked before the claims are parsed.
///
/// ```swift
/// let verifier = JWTVerifier(publicKey: try VerifyingKey(pemRepresentation: serverKeyPEM),
///                            issuer: "https://auth.example.com", audience: "ios-app")
/// let claims = try verifier.verify(token)
/// print(claims.subject ?? "")
/// ```
///
/// Rules, all fail-closed:
///
/// - The token is at most ``maximumTokenLength`` bytes, three Base64URL parts with no padding
///   and no other characters.
/// - Header and claims are JSON objects with no repeated member name.
/// - A header with `crit` is rejected; `jku`, `jwk`, `x5u` and `x5c` are never followed: the
///   key is always the one given here.
/// - `exp` is required unless ``requiresExpiration`` is false. `exp`, `nbf` and `iat` must be
///   finite numbers. The token is expired when `now` is at or past `exp` + ``leeway``, and not
///   yet valid when `now` + ``leeway`` is before `nbf`.
/// - With ``issuer`` set, `iss` must equal it. A token with `aud` is accepted only when
///   ``audience`` is set and is one of its values (RFC 7519 §4.1.3).
public struct JWTVerifier: Sendable {
    /// The longest token read, 16 KiB, so that a token from a header or a URL is not decoded and
    /// parsed without bound.
    public static let maximumTokenLength = 16 * 1024
    /// The largest ``leeway`` accepted: 10 minutes.
    public static let maximumLeeway: TimeInterval = 600

    private enum Key: Sendable {
        case hmac(MessageAuthenticator)
        case publicKey(VerifyingKey)
    }

    private let key: Key
    /// The algorithm a token must name, set by the key.
    public let algorithm: JWTAlgorithm
    /// The `iss` value a token must have, or nil to accept any issuer.
    public let issuer: String?
    /// This app's `aud` value. A token with an `aud` claim must list it.
    public let audience: String?
    /// The clock difference allowed for `exp` and `nbf`, in seconds.
    public let leeway: TimeInterval
    /// Whether a token without `exp` is rejected. The default is true: a token that never
    /// expires stays valid when it leaks.
    public let requiresExpiration: Bool

    /// Creates a verifier for `HS256` tokens.
    ///
    /// - Parameters:
    ///   - key: The shared key, at least 256 bits (RFC 7518 §3.2).
    ///   - issuer: The required `iss`, or nil.
    ///   - audience: This app's `aud` value, or nil to reject every token that has an `aud`.
    ///   - leeway: Allowed clock difference, 0 to ``maximumLeeway`` seconds. The default is 60.
    ///   - requiresExpiration: Whether `exp` is required.
    /// - Throws: ``JWTError/invalidConfiguration(_:)`` for a shorter key or a leeway out of
    ///   range.
    public init(
        key: SymmetricKey,
        issuer: String? = nil,
        audience: String? = nil,
        leeway: TimeInterval = 60,
        requiresExpiration: Bool = true
    ) throws(JWTError) {
        guard key.bitCount >= 256, let authenticator = try? MessageAuthenticator(key: key) else {
            throw .invalidConfiguration("An HS256 key must have at least 256 bits, not \(key.bitCount).")
        }
        try self.init(key: .hmac(authenticator), algorithm: .hs256, issuer: issuer, audience: audience, leeway: leeway, requiresExpiration: requiresExpiration)
    }

    /// Creates a verifier for `ES256` (P-256) or `EdDSA` (Ed25519) tokens, chosen by the key.
    ///
    /// - Throws: ``JWTError/invalidConfiguration(_:)`` for a leeway out of range.
    public init(
        publicKey: VerifyingKey,
        issuer: String? = nil,
        audience: String? = nil,
        leeway: TimeInterval = 60,
        requiresExpiration: Bool = true
    ) throws(JWTError) {
        let algorithm: JWTAlgorithm = publicKey.algorithm == .p256 ? .es256 : .edDSA
        try self.init(key: .publicKey(publicKey), algorithm: algorithm, issuer: issuer, audience: audience, leeway: leeway, requiresExpiration: requiresExpiration)
    }

    private init(key: Key, algorithm: JWTAlgorithm, issuer: String?, audience: String?, leeway: TimeInterval, requiresExpiration: Bool) throws(JWTError) {
        guard leeway.isFinite, (0...Self.maximumLeeway).contains(leeway) else {
            throw .invalidConfiguration("The leeway must be 0 to \(Int(Self.maximumLeeway)) seconds.")
        }
        self.key = key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.requiresExpiration = requiresExpiration
    }

    /// Verifies a token and returns its claims.
    ///
    /// - Parameters:
    ///   - token: The compact token, `header.claims.signature`.
    ///   - now: The time to check `exp` and `nbf` against.
    /// - Throws: ``JWTError``; the case says which rule the token broke.
    public func verify(_ token: String, now: Date = Date()) throws(JWTError) -> JWTClaims {
        let parts = try JWTParts(token)
        let header = try JWTParts.object(parts.header, part: "header")
        try checkHeader(header)
        guard isValidSignature(parts.signature, for: parts.signingInput) else {
            throw .invalidSignature
        }
        let claims = try JWTClaims(json: JWTParts.object(parts.claims, part: "claims"), payload: parts.claims)
        try check(claims, now: now)
        return claims
    }

    /// Verifies a token and decodes its claims into your own type, for claims beyond the
    /// registered ones.
    ///
    /// The time and audience rules of ``verify(_:now:)`` apply first.
    public func verify<Claims: Decodable>(_ token: String, as type: Claims.Type, now: Date = Date()) throws(JWTError) -> Claims {
        try verify(token, now: now).decode(type)
    }

    private func checkHeader(_ header: [String: Any]) throws(JWTError) {
        guard let name = header["alg"] as? String else {
            throw .malformed("The header has no alg.")
        }
        guard name == algorithm.rawValue else {
            throw .algorithmMismatch(expected: algorithm.rawValue, found: name)
        }
        guard header["crit"] == nil else {
            throw .malformed("The header has crit parameters, and none are supported.")
        }
    }

    private func isValidSignature(_ signature: Data, for input: Data) -> Bool {
        switch key {
        case .hmac(let authenticator):
            return authenticator.isValid(signature, for: input)
        case .publicKey(let publicKey):
            // JWS signatures are the 64 raw bytes for both algorithms; DER is not JWS.
            return signature.count == 64 && publicKey.isValidSignature(signature, for: input)
        }
    }

    private func check(_ claims: JWTClaims, now: Date) throws(JWTError) {
        let time = now.timeIntervalSince1970
        if let expiration = claims.expiration {
            // Written so that a NaN `now` fails: every comparison with NaN is false.
            guard time < expiration.timeIntervalSince1970 + leeway else { throw .expired(expiration) }
        } else if requiresExpiration {
            throw .missingClaim("exp")
        }
        if let notBefore = claims.notBefore {
            guard time + leeway >= notBefore.timeIntervalSince1970 else { throw .notYetValid(notBefore) }
        }
        if let issuer, claims.issuer != issuer {
            throw .issuerMismatch(expected: issuer, found: claims.issuer)
        }
        if !claims.audience.isEmpty {
            guard let audience, claims.audience.contains(audience) else {
                throw .audienceMismatch(expected: audience, found: claims.audience)
            }
        }
    }
}

/// An error from ``JWTVerifier`` or ``JWTSigner``.
public enum JWTError: Error, Hashable, Sendable, LocalizedError {
    /// The token is not a well-formed compact JWT, or a claim has the wrong type.
    case malformed(String)
    /// The header names another algorithm than the key's.
    case algorithmMismatch(expected: String, found: String)
    /// The signature does not match the key.
    case invalidSignature
    /// The token expired at this date.
    case expired(Date)
    /// The token is valid only from this date.
    case notYetValid(Date)
    /// A required claim is missing.
    case missingClaim(String)
    /// The `iss` claim is not the expected issuer.
    case issuerMismatch(expected: String, found: String?)
    /// The token's `aud` does not list this app's audience, or no audience was set.
    case audienceMismatch(expected: String?, found: [String])
    /// The verifier or signer was set up with a value out of range.
    case invalidConfiguration(String)
    /// The claims could not be encoded or decoded into the requested type.
    case claimsCoding(String)

    public var errorDescription: String? {
        switch self {
        case .malformed(let reason): "The token is not valid. \(reason)"
        case .algorithmMismatch(let expected, let found): "The token uses \(found); \(expected) is required."
        case .invalidSignature: "The token signature does not match the key."
        case .expired(let date): "The token expired at \(date.formatted(.iso8601))."
        case .notYetValid(let date): "The token is valid only from \(date.formatted(.iso8601))."
        case .missingClaim(let name): "The token has no \(name) claim."
        case .issuerMismatch(let expected, let found): "The token issuer is \(found ?? "missing"), not \(expected)."
        case .audienceMismatch(let expected, let found):
            "The token audience \(found) does not include \(expected ?? "this app; no audience was configured")."
        case .invalidConfiguration(let reason): reason
        case .claimsCoding(let reason): "The claims could not be coded. \(reason)"
        }
    }
}
