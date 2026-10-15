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
/// - **Secret fields**: the value after `password`, `token`, `secret`, `api_key`, `authorization`
///   and similar names followed by `:` or `=`, in JSON, query strings, headers and `key: value`
///   text, including `camelCase` and `snake_case` forms such as `accessToken` or `client_secret`.
///
/// Text written to get past a filter is normalized before matching: zero-width and other
/// invisible characters, combining marks, full-width letters (`ｐａｓｓｗｏｒｄ`) and digits from
/// other scripts do not hide a value. The scan is linear in the length of the text and does not
/// use regular expressions, so no input makes it slow.
///
/// Redaction is a safety net for mistakes, not a reason to log secrets: it cannot recognize a
/// password that is not labelled as one.
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
        /// What was found; one of the ``Kinds`` constants.
        public let kind: Kinds
        /// Where it is in the text.
        public let range: Range<String.Index>
    }

    /// The text that replaces tokens and secret values.
    public static let replacement = "[redacted]"

    /// The field names whose values ``Kinds/secretFields`` hides, longest first.
    static let secretFieldNames: [[UInt8]] = [
        "authorization", "client_secret", "refresh_token", "access_token", "private_key",
        "password", "id_token", "api-key", "api_key", "apikey", "passwd", "secret", "token", "pwd",
    ].map { Array($0.utf8) }

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
        var output = String.UnicodeScalarView()
        var position = 0
        for span in spans {
            output.append(contentsOf: scalars[position..<span.start])
            output.append(contentsOf: span.replacement.unicodeScalars)
            position = span.end
        }
        output.append(contentsOf: scalars[position...])
        return String(output)
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
        for span in found where span.start >= (result.last?.end ?? 0) {
            result.append(span)
        }
        return result
    }
}
