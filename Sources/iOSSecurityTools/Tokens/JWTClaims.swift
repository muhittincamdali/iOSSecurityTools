import CoreFoundation
import Foundation

/// The registered claims of a JSON Web Token (RFC 7519 §4.1), and the whole claim set as
/// signed.
///
/// ``JWTVerifier`` returns it after the signature and the time and audience checks pass. Read
/// your own claims with ``decode(_:)``. To sign a token, create one and pass it to
/// ``JWTSigner/sign(_:keyID:)``.
public struct JWTClaims: Sendable, Hashable, Encodable {
    /// `iss`: who issued the token.
    public let issuer: String?
    /// `sub`: whom the token is about, such as a user identifier.
    public let subject: String?
    /// `aud`: the recipients the token is for. Empty when the claim is absent.
    public let audience: [String]
    /// `exp`: when the token stops being valid.
    public let expiration: Date?
    /// `nbf`: when the token starts being valid.
    public let notBefore: Date?
    /// `iat`: when the token was issued.
    public let issuedAt: Date?
    /// `jti`: a unique identifier, for detecting a replayed token.
    public let tokenID: String?
    /// The claim set JSON exactly as it was signed. For claims you create, the JSON of the
    /// registered claims.
    public let payload: Data

    /// Creates claims to sign.
    public init(
        issuer: String? = nil,
        subject: String? = nil,
        audience: [String] = [],
        expiration: Date? = nil,
        notBefore: Date? = nil,
        issuedAt: Date? = nil,
        tokenID: String? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.expiration = expiration
        self.notBefore = notBefore
        self.issuedAt = issuedAt
        self.tokenID = tokenID
        payload = Data()
    }

    /// Reads the registered claims of a verified claim set, checking their types.
    init(json: [String: Any], payload: Data) throws(JWTError) {
        issuer = try Self.string(json["iss"], name: "iss")
        subject = try Self.string(json["sub"], name: "sub")
        tokenID = try Self.string(json["jti"], name: "jti")
        expiration = try Self.numericDate(json["exp"], name: "exp")
        notBefore = try Self.numericDate(json["nbf"], name: "nbf")
        issuedAt = try Self.numericDate(json["iat"], name: "iat")
        switch json["aud"] {
        case nil:
            audience = []
        case let single as String:
            audience = [single]
        case let list as [Any]:
            let strings = list.compactMap { $0 as? String }
            guard strings.count == list.count else { throw .malformed("The aud claim lists a value that is not a string.") }
            audience = strings
        default:
            throw .malformed("The aud claim is not a string or a list of strings.")
        }
        self.payload = payload
    }

    /// Decodes the claim set into your own type. Dates are read as seconds since 1970.
    ///
    /// ```swift
    /// struct Session: Decodable { let sub: String; let scope: String }
    /// let session = try claims.decode(Session.self)
    /// ```
    public func decode<Claims: Decodable>(_ type: Claims.Type) throws(JWTError) -> Claims {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do {
            return try decoder.decode(type, from: payload.isEmpty ? Self.encoded(self) : payload)
        } catch let error as JWTError {
            throw error
        } catch {
            throw .claimsCoding(String(describing: error))
        }
    }

    private enum CodingKeys: String, CodingKey {
        case iss, sub, aud, exp, nbf, iat, jti
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(issuer, forKey: .iss)
        try container.encodeIfPresent(subject, forKey: .sub)
        switch audience.count {
        case 0: break
        case 1: try container.encode(audience[0], forKey: .aud)
        default: try container.encode(audience, forKey: .aud)
        }
        try Self.encode(expiration, forKey: .exp, in: &container)
        try Self.encode(notBefore, forKey: .nbf, in: &container)
        try Self.encode(issuedAt, forKey: .iat, in: &container)
        try container.encodeIfPresent(tokenID, forKey: .jti)
    }

    /// NumericDate: whole seconds as an integer, otherwise as a number with a fraction; a date
    /// that is not finite is an error rather than a trap in an integer conversion.
    private static func encode(_ date: Date?, forKey key: CodingKeys, in container: inout KeyedEncodingContainer<CodingKeys>) throws {
        guard let date else { return }
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite else {
            throw EncodingError.invalidValue(date, .init(codingPath: [key], debugDescription: "The \(key.rawValue) date is not finite."))
        }
        if seconds == seconds.rounded(.towardZero), let whole = Int64(exactly: seconds) {
            try container.encode(whole, forKey: key)
        } else {
            try container.encode(seconds, forKey: key)
        }
    }

    static func encoded(_ value: some Encodable) throws(JWTError) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .secondsSince1970
        do {
            return try encoder.encode(value)
        } catch {
            throw .claimsCoding(String(describing: error))
        }
    }

    private static func string(_ value: Any?, name: String) throws(JWTError) -> String? {
        guard let value else { return nil }
        guard let string = value as? String else { throw .malformed("The \(name) claim is not a string.") }
        return string
    }

    /// A JSON number that is not a boolean and is finite; `JSONSerialization` reads `true` as an
    /// `NSNumber` too, and a number beyond `Double` as infinity.
    private static func numericDate(_ value: Any?, name: String) throws(JWTError) -> Date? {
        guard let value else { return nil }
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            throw .malformed("The \(name) claim is not a number.")
        }
        let seconds = number.doubleValue
        guard seconds.isFinite else { throw .malformed("The \(name) claim is not a finite number.") }
        return Date(timeIntervalSince1970: seconds)
    }
}
