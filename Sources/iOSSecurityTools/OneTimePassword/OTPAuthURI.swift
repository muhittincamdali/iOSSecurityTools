import Foundation

/// An `otpauth://` URI, the content of the QR codes that set up authenticator apps.
///
/// The format follows the Key Uri Format that Google Authenticator documents:
///
/// ```text
/// otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
/// ```
///
/// Parsing is strict where a lenient reader could be tricked: a parameter given twice, an issuer
/// in the label that differs from the `issuer` parameter, or a value outside the ranges of
/// ``HOTP`` and ``TOTP`` makes ``init(parsing:)`` throw.
///
/// ```swift
/// let uri = try OTPAuthURI(parsing: scannedText)
/// if case .totp(let totp) = uri.kind {
///     print(uri.issuer ?? "", uri.account, try totp.code())
/// }
/// ```
public struct OTPAuthURI: Sendable, Hashable {
    /// The longest URI ``init(parsing:)`` reads.
    public static let maximumLength = 4096

    /// The generator a URI describes.
    public enum Kind: Sendable, Hashable {
        /// Time-based codes.
        case totp(TOTP)
        /// Counter-based codes, with the initial counter.
        case hotp(HOTP, counter: UInt64)
    }

    /// The generator.
    public let kind: Kind
    /// The account name, such as an email address.
    public let account: String
    /// The service that issued the secret, or `nil`.
    public let issuer: String?

    /// Creates a URI for a generator, to show as a QR code.
    ///
    /// - Throws: ``OTPError/invalidURI(_:)`` for an empty account, or an issuer or account that
    ///   contains a colon.
    public init(kind: Kind, account: String, issuer: String? = nil) throws(OTPError) {
        guard !account.isEmpty else { throw .invalidURI("The account is empty.") }
        guard !account.contains(":"), !(issuer ?? "").contains(":") else {
            throw .invalidURI("The issuer and account cannot contain a colon.")
        }
        self.kind = kind
        self.account = account
        self.issuer = issuer.flatMap { $0.isEmpty ? nil : $0 }
    }

    /// Parses an `otpauth://` URI.
    ///
    /// - Throws: ``OTPError`` describing the first problem found.
    public init(parsing text: String) throws(OTPError) {
        guard text.utf8.count <= Self.maximumLength else {
            throw .invalidURI("It is longer than \(Self.maximumLength) characters.")
        }
        guard let components = URLComponents(string: text),
              components.scheme?.lowercased() == "otpauth",
              let type = components.host?.lowercased()
        else {
            throw .invalidURI("It does not start with otpauth://totp/ or otpauth://hotp/.")
        }

        var parameters: [String: String] = [:]
        for item in components.queryItems ?? [] {
            let name = item.name.lowercased()
            guard parameters[name] == nil else { throw .invalidURI("The parameter \(name) appears twice.") }
            parameters[name] = item.value ?? ""
        }

        let (labelIssuer, account) = try Self.parseLabel(components.path)
        let issuer = parameters["issuer"].flatMap { $0.isEmpty ? nil : $0 }
        if let labelIssuer, let issuer, labelIssuer != issuer {
            throw .invalidURI("The label names \(labelIssuer) but the issuer parameter is \(issuer).")
        }

        guard let secretText = parameters["secret"], !secretText.isEmpty else {
            throw .invalidURI("The secret parameter is missing.")
        }
        guard let secret = Base32.decode(secretText) else { throw .invalidSecret }
        let algorithm = try Self.algorithm(parameters["algorithm"])
        let digits = try Self.integer(parameters["digits"], name: "digits") ?? 6

        switch type {
        case "totp":
            let period = try Self.integer(parameters["period"], name: "period") ?? 30
            kind = .totp(try TOTP(secret: secret, algorithm: algorithm, digits: digits, period: period))
        case "hotp":
            guard let counterText = parameters["counter"], let counter = UInt64(counterText) else {
                throw .invalidURI("An hotp URI needs a counter parameter.")
            }
            kind = .hotp(try HOTP(secret: secret, algorithm: algorithm, digits: digits), counter: counter)
        default:
            throw .invalidURI("The type \(type) is not totp or hotp.")
        }
        self.account = account
        self.issuer = issuer ?? labelIssuer
    }

    /// The URI text, with the secret in unpadded Base32.
    ///
    /// The URI contains the secret: show it as a QR code, and do not log it or send it to
    /// analytics.
    public var uriString: String {
        var components = URLComponents()
        components.scheme = "otpauth"
        let label = issuer.map { "\($0):\(account)" } ?? account
        var items: [URLQueryItem] = []
        switch kind {
        case .totp(let totp):
            components.host = "totp"
            items = Self.commonItems(totp.generator)
            items.append(URLQueryItem(name: "period", value: String(totp.period)))
        case .hotp(let hotp, let counter):
            components.host = "hotp"
            items = Self.commonItems(hotp)
            items.append(URLQueryItem(name: "counter", value: String(counter)))
        }
        if let issuer { items.append(URLQueryItem(name: "issuer", value: issuer)) }
        components.path = "/" + label
        components.queryItems = items
        // URLComponents leaves "+" alone in query values, but many readers decode it as a space.
        components.percentEncodedQuery = components.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        return components.string ?? ""
    }

    private static func commonItems(_ generator: HOTP) -> [URLQueryItem] {
        [
            URLQueryItem(name: "secret", value: Base32.encode(generator.secret)),
            URLQueryItem(name: "algorithm", value: generator.algorithm.rawValue),
            URLQueryItem(name: "digits", value: String(generator.digits)),
        ]
    }

    private static func parseLabel(_ path: String) throws(OTPError) -> (issuer: String?, account: String) {
        // URLComponents.path is already percent-decoded.
        let label = path.hasPrefix("/") ? String(path.dropFirst()) : path
        let parts = label.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        let issuer = parts.count == 2 ? parts[0].trimmingCharacters(in: .whitespaces) : nil
        let account = String(parts.last ?? "").trimmingCharacters(in: .whitespaces)
        guard !account.isEmpty else { throw .invalidURI("The label has no account name.") }
        guard !account.contains(":") else { throw .invalidURI("The label has more than one colon.") }
        return (issuer.flatMap { $0.isEmpty ? nil : $0 }, account)
    }

    private static func algorithm(_ text: String?) throws(OTPError) -> OTPAlgorithm {
        guard let text else { return .sha1 }
        guard let algorithm = OTPAlgorithm(rawValue: text.uppercased()) else {
            throw .invalidURI("The algorithm \(text) is not SHA1, SHA256 or SHA512.")
        }
        return algorithm
    }

    private static func integer(_ text: String?, name: String) throws(OTPError) -> Int? {
        guard let text else { return nil }
        guard text.utf8.count <= 9, text.utf8.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }), let value = Int(text) else {
            throw .invalidURI("The \(name) parameter is not a number.")
        }
        return value
    }
}
