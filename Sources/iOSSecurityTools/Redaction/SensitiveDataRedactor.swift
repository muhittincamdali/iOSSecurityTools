import Foundation

/// Finds card numbers, email addresses, tokens and password fields in free text and hides them,
/// for log messages, crash reports and analytics events.
///
/// ```swift
/// let redactor = SensitiveDataRedactor()
/// redactor.redact(#"POST /login {"user":"alice@example.com","password":"hunter2"}"#)
/// // POST /login {"user":"a•••@example.com","password":"[redacted]"}
/// ```
///
/// What it recognizes:
///
/// - **Card numbers**: 13 to 19 digits that pass the Luhn check, optionally grouped with spaces
///   or hyphens. Shown as `•••• 4242`.
/// - **Email addresses**: shown with ``Mask/email(_:)``.
/// - **JSON Web Tokens**: `eyJ…​.…​.…` — replaced completely.
/// - **Bearer tokens**: the token after `Bearer `.
/// - **Secret fields**: the value after a field name followed by `:` or `=` whose words include
///   `password`, `pass`, `token`, `secret`, `api_key`, `authorization`, `session_id` or a similar
///   word, or that is exactly `session`. JSON (also JSON escaped inside another string), query
///   strings, form fields (`password[]=`, `user[password]=`), headers, `key: value` text, XML
///   elements (`<password>…</password>`) and a percent-encoded `=` or `:` (`password%3D…`) count.
///   Names in `camelCase`, `snake_case`, `kebab-case` and upper case count, with other words
///   around the secret one: `accessToken`, `client_secret`, `SECRET_KEY`, `DB_PASS`,
///   `aws_secret_access_key`, `passwordConfirm`, `password2`. Names that only describe a secret,
///   such as `passwordHint`, `token_type`, `pass_count` or `session_start`, are left alone.
///
/// When two findings partly overlap, such as a token that runs into a card number
/// (`token=abc_4111 1111 1111 1111`), the whole stretch they cover becomes `[redacted]`.
///
/// Text written to get past a filter is normalized before matching: zero-width and other
/// invisible characters, combining marks, full-width letters (`ｐａｓｓｗｏｒｄ`) and digits from
/// other scripts do not hide a value. Scanning and replacing are linear in the length of the text
/// and do not use regular expressions, so no input makes them slow.
///
/// Redaction is a safety net for mistakes, not a reason to log secrets. It cannot recognize a
/// password that is not labelled as one or is labelled with a name it does not know (`pin`,
/// `credentials`), or text that is encoded as a whole, such as base64 or percent-encoded JSON.
public struct SensitiveDataRedactor: Sendable {
    /// The kinds of data to look for.
    public struct Kinds: OptionSet, Sendable, Hashable {
        public let rawValue: Int
        public init(rawValue: Int) { self.rawValue = rawValue }

        /// Payment card numbers that pass the Luhn check.
        public static let cardNumbers = Kinds(rawValue: 1 << 0)
        /// Email addresses.
        public static let emailAddresses = Kinds(rawValue: 1 << 1)
        /// JSON Web Tokens.
        public static let jsonWebTokens = Kinds(rawValue: 1 << 2)
        /// Tokens after the word `Bearer`.
        public static let bearerTokens = Kinds(rawValue: 1 << 3)
        /// Values of fields named like a secret (`password`, `token`, `api_key`, ...).
        public static let secretFields = Kinds(rawValue: 1 << 4)
        /// Everything above.
        public static let all: Kinds = [.cardNumbers, .emailAddresses, .jsonWebTokens, .bearerTokens, .secretFields]
    }

    /// A piece of sensitive data found in a text.
    public struct Match: Sendable, Hashable {
        /// What was found: one of the ``Kinds`` constants, or several of them when findings that
        /// partly overlap were joined into one match. Test it with `contains(_:)`.
        public let kind: Kinds
        /// Where it is in the text.
        public let range: Range<String.Index>
    }

    /// The text that replaces tokens and secret values.
    public static let replacement = "[redacted]"

    /// The words that make a field name secret, in lowercase without `_` or `-`; ``Kinds/secretFields``
    /// also matches them across those separators and camel-case humps (`api_key`, `accessToken`).
    static let secretFieldNames: [[UInt8]] = [
        "authorization", "clientsecret", "refreshtoken", "accesstoken", "privatekey", "secretkey",
        "sessionid", "sessionkey", "passphrase", "password", "idtoken", "apikey", "passwd", "secret",
        "token", "pass", "pwd",
    ].map { Array($0.utf8) }

    /// Field names that hold a secret only when they are the whole name: a `session` cookie holds
    /// the session, while `session_start` or `sessionCount` describe it. `PHPSESSID` and
    /// `JSESSIONID` are the session cookies of PHP and Java servers, whose secret word is not a
    /// word of its own.
    static let wholeSecretFieldNames: Set<[UInt8]> = Set(["session", "phpsessid", "jsessionid"].map { Array($0.utf8) })

    /// Words that, right after a secret word, make the field describe the secret instead of
    /// holding it: `passwordHint`, `token_type`, `token_expires_in`.
    static let describingWords: Set<[UInt8]> = Set([
        "hint", "type", "expiry", "expires", "expiration", "ttl", "lifetime", "length", "policy",
        "url", "uri", "endpoint", "count", "required", "rules", "strength", "changed", "updated",
    ].map { Array($0.utf8) })

    /// The kinds this redactor looks for.
    public let kinds: Kinds

    /// Creates a redactor.
    ///
    /// - Parameter kinds: The kinds of data to look for; all of them by default.
    public init(kinds: Kinds = .all) {
        self.kinds = kinds
    }

    /// Returns the text with every match replaced.
    public func redact(_ text: String) -> String {
        let scalars = Array(text.unicodeScalars)
        let spans = findSpans(in: scalars)
        guard !spans.isEmpty else { return text }
        return Self.replacing(spans, in: scalars)
    }

    /// The scalars with every span replaced; `spans` are in order and do not overlap.
    static func replacing(_ spans: [Span], in scalars: [Unicode.Scalar]) -> String {
        // Appending to a String.UnicodeScalarView piece by piece copies what is already there,
        // which made many matches take quadratic time; collect the scalars and build the
        // string once.
        var output: [Unicode.Scalar] = []
        output.reserveCapacity(scalars.count)
        var position = 0
        for span in spans {
            output.append(contentsOf: scalars[position..<span.start])
            output.append(contentsOf: span.replacement.unicodeScalars)
            position = span.end
        }
        output.append(contentsOf: scalars[position...])
        return String(String.UnicodeScalarView(output))
    }

    /// Returns the sensitive data found in a text, in order, without overlaps.
    public func matches(in text: String) -> [Match] {
        let scalars = Array(text.unicodeScalars)
        let spans = findSpans(in: scalars)
        var indices: [String.Index] = []
        indices.reserveCapacity(scalars.count + 1)
        var index = text.unicodeScalars.startIndex
        while index < text.unicodeScalars.endIndex {
            indices.append(index)
            index = text.unicodeScalars.index(after: index)
        }
        indices.append(text.unicodeScalars.endIndex)
        return spans.map { Match(kind: $0.kind, range: indices[$0.start]..<indices[$0.end]) }
    }

    // MARK: - Scanning

    /// A replacement, in offsets of the original scalars.
    struct Span {
        var start: Int
        var end: Int
        var kind: Kinds
        var replacement: String
    }

    private func findSpans(in scalars: [Unicode.Scalar]) -> [Span] {
        let text = NormalizedText(scalars)
        var found: [Span] = []
        if kinds.contains(.secretFields) { found += text.secretFieldSpans() }
        if kinds.contains(.bearerTokens) { found += text.bearerSpans() }
        if kinds.contains(.jsonWebTokens) { found += text.jsonWebTokenSpans() }
        if kinds.contains(.emailAddresses) { found += text.emailSpans() }
        if kinds.contains(.cardNumbers) { found += text.cardSpans() }

        found.sort { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var result: [Span] = []
        for span in found {
            guard let last = result.last, span.start < last.end else {
                result.append(span)
                continue
            }
            guard span.end > last.end else { continue }
            // The two overlap and neither contains the other ("token=abc_4111 1111 1111 1111"):
            // dropping either would show part of it, so hide both as one region.
            result[result.count - 1] = Span(
                start: last.start, end: span.end, kind: last.kind.union(span.kind), replacement: Self.replacement
            )
        }
        return result
    }
}
