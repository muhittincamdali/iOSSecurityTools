import Foundation

/// Finds card numbers, bank account numbers, email addresses, tokens and the values of secret
/// keys and hides them, for log messages, crash reports and analytics events.
///
/// ```swift
/// let redactor = SensitiveDataRedactor()
/// redactor.redact(#"POST /login {"user":"alice@example.com","password":"hunter2"}"#)
/// // POST /login {"user":"a•••@example.com","password":"[redacted]"}
/// redactor.redact("login failed user=alice status=401")
/// // login failed user=[redacted]
/// ```
///
/// Redaction is a safety net for mistakes, not a guarantee: keep secrets out of log calls in the
/// first place. The redactor follows one rule: what it does not fully understand is hidden, never
/// shown.
///
/// ## Keys
///
/// Keys are JSON member names, form and multipart field names and query parameter names. Only a
/// plain-ASCII key is compared with the secret names: `A`–`Z`, `a`–`z`, `0`–`9` and the separators
/// `_`, `-`, `.` and space, which are folded away (`PASS-WORD` reads as `password`). **Any other key
/// has its value hidden**, whatever it says: one with a letter outside ASCII (`pаssword` with a
/// Cyrillic `а`, `ｐａｓｓｗｏｒｄ`, `café`), a mark, an invisible format character, mixed scripts, an
/// escape or other punctuation. No list of look-alikes is ever complete, so none is kept.
///
/// A plain key hides its value when it holds a secret word: the list the redaction spec shares
/// between packages (`password`, `passwd`, `pwd`, `secret`, `token`, `access_token`, `api_key`,
/// `key`, `auth`, `authorization`, `cookie`, `session`, `sid`, `otp`, `pin`, `cvv`, `card`, `iban`,
/// `ssn`, `private_key`, `client_secret`, `signature`, …) and this library's extensions
/// (`passphrase`, `passcode`, `credential`, `cvc`, `sessid`, `pin_code`, `verification_code`, …),
/// also in the plural. Words of five or more letters count anywhere in a key (`dbPassword`),
/// shorter ones as a word of it or at its end (`user_pin`, `X-Auth-Key`, `apitoken`), `pass` and
/// `sid` only as a word, and `session` only as the last word. A hidden value is hidden whole: a
/// string, a number, and an array or object with everything in it.
///
/// ## Structured input
///
/// JSON is read with a JSON parser and used only when `JSONSerialization` reads the same tree:
/// keys are compared after their escapes are decoded, at every depth, inside arrays and for every
/// repetition of a key. The output stays valid JSON. URLs are read with `URLComponents` (see
/// ``redact(url:)``), and ``redact(body:contentType:)`` reads JSON, form, multipart and plain-text
/// bodies; a body it cannot parse completely is omitted, and so is one that a common server
/// parser could split into fields differently, such as a multipart body with `--boundary` after
/// a bare LF or a form with a `;`.
///
/// ## Free text
///
/// A log line has no grammar, so its keys are read the other way round, with an allowlist: in
/// `key=value`, `key: value` and `"key":"value"` the value is kept only when the key is plain ASCII
/// and on ``allowedTextKeys``. Strings inside JSON, form values and multipart text parts are free
/// text too. ``redact(_:)`` describes the rule.
///
/// ## Values
///
/// Values are also scanned for:
///
/// - **Card numbers**: 13 to 19 digits that pass the Luhn check, optionally grouped with spaces,
///   tabs or dashes. Shown as `•••• 4242`.
/// - **IBANs**: a country code, two check digits and up to 30 capital letters or digits that pass
///   the mod-97 check, optionally grouped with spaces. Shown as `•••• 3000`.
/// - **Email addresses**: shown with ``Mask/email(_:)``.
/// - **JSON Web Tokens**: `eyJ…​.…​.…`, also glued to a word with `_` or `-`.
/// - **Bearer tokens**: the token after `Bearer `.
/// - **Long tokens**: runs of 32 or more hex digits, and of 32 or more base64 characters with
///   letters and digits. UUIDs and paths are kept.
/// - **Passwords in URLs**: the password in `user:password@host`.
///
/// They are found after Unicode compatibility decomposition without marks, format characters,
/// default-ignorable code points and control characters, so full-width digits, zero-width
/// characters, fillers such as U+3164, `DEL` and Unicode spaces do not hide them. When two
/// findings overlap, the whole stretch they cover becomes `[redacted]`. Scanning takes time linear
/// in the length of the text and uses no regular expressions.
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
        /// Values hidden by their key: secret and non-ASCII keys in structured input, keys that are
        /// not allowed in free text, the query values and path segments that ``redact(url:)`` hides
        /// by its URL rules, and the password in `user:password@host` in text. ``redact(url:)``
        /// drops a URL's user name, password and fragment with or without it.
        public static let secretFields = Kinds(rawValue: 1 << 4)
        /// International bank account numbers that pass the mod-97 check.
        public static let ibans = Kinds(rawValue: 1 << 5)
        /// Runs of 32 or more hexadecimal digits, or of base64 letters and digits.
        public static let longTokens = Kinds(rawValue: 1 << 6)
        /// Everything above.
        public static let all: Kinds = [.cardNumbers, .emailAddresses, .jsonWebTokens, .bearerTokens, .secretFields, .ibans, .longTokens]
    }

    /// A piece of sensitive data found in a text.
    public struct Match: Sendable, Hashable {
        /// What was found: one of the ``Kinds`` constants, or several of them when findings that
        /// partly overlap were joined into one match. Test it with `contains(_:)`.
        public let kind: Kinds
        /// Where it is in the text.
        public let range: Range<String.Index>
    }

    /// How much of a URL is recorded.
    public enum URLDetail: Sendable, Hashable {
        /// Scheme, host, port, path and query, redacted.
        case full
        /// Scheme, host and port only.
        case hostOnly
    }

    /// The text that replaces tokens and secret values.
    public static let replacement = "[redacted]"

    /// The text that replaces a URL path segment that looks like an identifier or a secret.
    public static let identifierPlaceholder = ":id"

    /// What is recorded for a URL that `URLComponents` cannot parse.
    public static let unparsedURL = "<unparsed URL>"

    /// Bodies larger than this are omitted without being parsed: 1 MiB.
    public static let maximumBodySize = 1_048_576

    /// The keys whose values free text keeps: harmless names that logs use for numbers and routes.
    /// The keys passed to the initializer are added to them.
    public static let defaultAllowedTextKeys: [String] = [
        "status", "status_code", "method", "path", "duration", "duration_ms", "count", "size", "bytes",
        "page", "limit", "offset", "attempt", "level",
    ]

    /// The kinds this redactor looks for.
    public let kinds: Kinds

    /// The folded keys whose values free text keeps: ``defaultAllowedTextKeys`` and the keys passed
    /// to the initializer, lowercased and without `_`, `-`, `.` and spaces.
    public let allowedTextKeys: Set<String>

    /// The folded names of the query parameters whose values a URL keeps. Empty by default.
    public let allowedQueryParameters: Set<String>

    /// How much of a URL is recorded.
    public let urlDetail: URLDetail

    /// Creates a redactor.
    ///
    /// - Parameters:
    ///   - kinds: The kinds of data to look for; all of them by default.
    ///   - allowedTextKeys: Keys whose values free text keeps, in addition to
    ///     ``defaultAllowedTextKeys``. A key that is not plain ASCII or names a secret is ignored.
    ///   - allowedQueryParameters: Query parameters whose values URLs keep. A name that is not
    ///     plain ASCII or names a secret is ignored.
    ///   - urlDetail: How much of a URL is recorded.
    public init(kinds: Kinds = .all, allowedTextKeys: [String] = [], allowedQueryParameters: [String] = [], urlDetail: URLDetail = .full) {
        self.kinds = kinds
        self.allowedTextKeys = Self.allowableFolds(Self.defaultAllowedTextKeys + allowedTextKeys)
        self.allowedQueryParameters = Self.allowableFolds(allowedQueryParameters)
        self.urlDetail = urlDetail
    }

    private static func allowableFolds(_ names: [String]) -> Set<String> {
        Set(names.compactMap { FieldName.allowableFold($0.unicodeScalars) })
    }

    /// Returns the text with every match replaced.
    ///
    /// The text is read as free text, on a scanning copy without invisible characters (format
    /// characters, marks, default-ignorable code points such as U+3164, control characters) and
    /// in Unicode compatibility form:
    ///
    /// - **Pairs.** In `key=value`, `key: value`, `key = value` and `"key":"value"` the value is
    ///   kept only when the key is plain ASCII and on ``allowedTextKeys``. Any other value is
    ///   replaced: a quoted one (`"`, `'` or a backtick) up to its closing quote, a JSON object or
    ///   array whole, anything else with the rest of its line, because where it ends cannot be
    ///   told. The separators are `=` and `:`, also as characters whose compatibility form is one
    ///   (`＝`, `：`, `︓`) and as escapes (`%3D`, `&#61;`); a `:` between two digits, as in
    ///   `12:30`, is part of a time. Punctuation and math symbols outside ASCII (`≔`, `꞉`, `→`,
    ///   `·`) separate too, where they follow other text.
    /// - **Secret names without a separator.** A word that holds a secret name hides the rest of
    ///   its line: `password hunter2`, `PIN 1234`, `export AWS_SECRET_ACCESS_KEY …`. Words are read
    ///   after their escapes are decoded, with punctuation inside them (`pass~word`) and a space or
    ///   `|` between two of them (`pass word`) read as a separator, and a letter that has no ASCII
    ///   form (`ɑ`, `ı`) read as any letter.
    /// - **Ambiguity.** A word that mixes scripts (`pаssword` with a Cyrillic `а`) or holds an
    ///   invisible character other than a mark (`pa\u{115F}ssword`, a zero-width space, a control
    ///   character) hides itself and the rest of its line.
    /// - **Values that go on.** A quote that does not close on its line hides the lines up to the
    ///   one where it closes, and that line whole. After a value hidden to the end of its line, the
    ///   lines indented more and the line after a trailing `\` are hidden; so is the next line with
    ///   text when nothing but punctuation followed the name, the line ends open (`(`, `:`, `<key>`,
    ///   `"""`) or it ends at a break other than LF and CRLF.
    /// - **Embedded JSON.** JSON in a line (`{"…`, `[{…`, `["…`, `[[…`) is parsed and redacted by the
    ///   key rule for structured input. JSON that does not parse hides the rest of the line, and the
    ///   lines below until its brackets close.
    /// - **URLs** with a scheme and `//` are recorded as ``redact(url:)`` records them.
    /// - **Values** are scanned for card numbers, IBANs, email addresses and tokens everywhere.
    ///
    /// U+2028, U+2029, U+0085, vertical tab and form feed end a line and are written as line feeds,
    /// so the result breaks lines where the rule did; CR and CRLF end a line too and are kept.
    public func redact(_ text: String) -> String {
        let scalars = Array(text.unicodeScalars)
        let spans = textSpans(in: scalars, compatibility: CompatibilityText())
        guard !spans.isEmpty else { return text }
        return Self.replacing(spans, in: scalars)
    }

    /// Returns the sensitive data found in a text, in order, without overlaps.
    public func matches(in text: String) -> [Match] {
        let scalars = Array(text.unicodeScalars)
        let spans = textSpans(in: scalars, compatibility: CompatibilityText()).filter { !$0.kind.isEmpty }
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

    // MARK: - Spans

    /// A replacement, in offsets of the original scalars. A span without a kind is no finding: it
    /// writes a line separator as a line feed.
    struct Span {
        var start: Int
        var end: Int
        var kind: Kinds
        var replacement: String
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

    /// The spans in order and without overlaps. A span inside a mask (an address, a card number)
    /// turns the mask into ``replacement``, since the mask shows part of what it covers; spans that
    /// partly overlap are joined into one ``replacement``.
    static func merged(_ spans: [Span]) -> [Span] {
        let sorted = spans.sorted { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var result: [Span] = []
        for span in sorted {
            guard let last = result.last, span.start < last.end else {
                result.append(span)
                continue
            }
            guard span.end > last.end else {
                if last.replacement != replacement, !span.kind.isEmpty, span.kind != last.kind {
                    result[result.count - 1] = Span(start: last.start, end: last.end, kind: last.kind.union(span.kind), replacement: replacement)
                }
                continue
            }
            result[result.count - 1] = Span(start: last.start, end: span.end, kind: last.kind.union(span.kind), replacement: replacement)
        }
        return result
    }
}
