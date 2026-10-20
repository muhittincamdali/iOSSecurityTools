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
/// repetition of a key. The output stays valid JSON.
///
/// Some objects carry a field's name in one member and its value in another: HTTP archives write
/// `{"name":"X-Api-Key","value":…}`, JSON Patch (RFC 6902) and SCIM PatchOp (RFC 7644) write
/// `{"op":"replace","path":"/password","value":…}`, forms write `{"label":"Password","input":…}`.
/// Names are classified by default too: the value of a member that holds a name (`name`, `key`,
/// `field`, `label`, `type`, `header`, `param`, `path` with every part between `/`, `id`, `k`,
/// `n`, or a member whose own name is not plain ASCII) is read by the key rule, so non-ASCII
/// names count as secret even when they are written as values: `Şifre`, `ⓟⓘⓝ`, `🔑`, an empty
/// name, or an array or object there. When such a name or a secret one is held, or any member's
/// value is a name that names a secret or cannot be read (`{"type":"password","input":…}`), the
/// values of the other members of the object are hidden whole, apart from the names of pairs
/// (`name`, `key`, `field`, `header`, `param`, `path`, `k`, `n`) and a JSON Patch or SCIM `op`.
/// The second element of a two-element array whose first is such a name is hidden whole
/// (`["Authorization", "…"]`, as fetch headers and `URLSearchParams` entries are written). Form
/// fields, URL query parameters and multipart parts follow the same rule
/// (`label=Password&value=…`).
///
/// URLs are read with `URLComponents` (see ``redact(url:)``), and ``redact(body:contentType:)``
/// reads JSON, form, multipart and plain-text bodies; a body it cannot parse completely is
/// omitted, and so is one that a common server parser could split into fields differently, such
/// as a multipart body with `--boundary` after a bare LF or a form with a `;`.
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
/// - **Email addresses**: a name of letters, marks and digits of any script and `.`, `_`, `%`,
///   `+` and `-` (`ayşe.yılmaz`, `bjørn.dæhlie`, `张伟`), and a domain that ends in two or more
///   letters, also outside ASCII (`例子.中国`). Shown with ``Mask/email(_:)``: the first letter of
///   the name, never the rest.
/// - **JSON Web Tokens**: `eyJ…​.…​.…`, also glued to a word with `_` or `-`.
/// - **Bearer tokens**: the token after `Bearer `.
/// - **Long tokens**: runs of 32 or more hex digits, and of 32 or more base64 characters with
///   letters and digits. UUIDs and paths are kept.
/// - **Passwords in URLs**: the password in `user:password@host`.
///
/// They are found after Unicode compatibility decomposition without marks, format characters,
/// default-ignorable code points and control characters, so full-width digits, zero-width
/// characters, fillers such as U+3164, `DEL` and Unicode spaces do not hide them, and the same way
/// on every path: free text, bodies, JSON strings and names, forms and URLs. Only a letter or
/// digit written in ASCII glues digits or a token to a word (`id4242…`); `é` or `𝐚` before them
/// does not. When two findings overlap, the whole stretch they cover becomes `[redacted]`, and so
/// does a finding that runs over the end of a URL in a line. Scanning takes time linear
/// in the length of the text and uses no regular expressions.
///
/// ## Limits
///
/// Input is read within fixed limits, which bound the stack and the time that hostile input can
/// use:
///
/// - A body larger than ``maximumBodySize`` (1 MiB) is omitted unread.
/// - JSON objects and arrays may be open 64 levels deep in all, counting the levels of every
///   document a JSON string is in: JSON in a string inside one object may open 63 more.
/// - At most four documents are read one inside another. A JSON text, a URL, a body and a
///   multipart part each count: in a JSON body, JSON in a string is the second.
/// - The documents found inside one input read at most four times its length, all together.
///   Each document found in it (JSON in a line or a string, a URL in text, a multipart part)
///   counts its length, and so does each text read inside such a document.
///
/// JSON that goes past a limit is not read. A body is then omitted, and a string or other text
/// inside a document that holds such JSON, or a URL one level too many, is hidden whole, as is
/// a text inside a found document that the reading budget no longer covers. In a log line, JSON
/// nested deeper than 64 levels hides the line from its first bracket, like JSON that does not
/// parse.
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

    /// A URL whose path has more segments than this is recorded with its scheme, host and port
    /// only: 64.
    public static let maximumPathSegments = 64

    /// A URL whose query, or whose path, has more parameters than this is recorded with its
    /// scheme, host and port only: 128.
    public static let maximumQueryParameters = 128

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
        self.allowedTextKeys = Self.defaultAllowedTextFolds.union(Self.allowableFolds(allowedTextKeys))
        self.allowedQueryParameters = Self.allowableFolds(allowedQueryParameters)
        self.urlDetail = urlDetail
    }

    /// A redactor with the allowlists and URL detail of `other` that looks for `kinds`.
    init(_ other: SensitiveDataRedactor, kinds: Kinds) {
        self.kinds = kinds
        self.allowedTextKeys = other.allowedTextKeys
        self.allowedQueryParameters = other.allowedQueryParameters
        self.urlDetail = other.urlDetail
    }

    private static func allowableFolds(_ names: [String]) -> Set<String> {
        Set(names.compactMap { FieldName.allowableFold($0.unicodeScalars) })
    }

    /// The folds of ``defaultAllowedTextKeys``, made once for every redactor.
    private static let defaultAllowedTextFolds = allowableFolds(defaultAllowedTextKeys)

    /// A redactor with the default settings, made once and shared by the readings that need one
    /// inside a redaction: the words of an array element, the value detectors of a path segment.
    /// Making one there for every element or segment folded the default keys again each time,
    /// which took a third of the time of a JSON array of short strings.
    static let standard = SensitiveDataRedactor()

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
    ///   `|` between two of them (`pass word`) read as a separator, and one letter that has no
    ///   ASCII form (`ɑ`, `ı`) read as any letter or, between two letters, as none (`passꞏword`).
    ///   This is a best effort: a name disguised with two or more such letters and written
    ///   without a separator (`pɑsswoʀd hunter2`) is not found.
    /// - **Ambiguity.** A word that mixes scripts (`pаssword` with a Cyrillic `а`) or holds an
    ///   invisible character other than a mark (`pa\u{115F}ssword`, a zero-width space, a control
    ///   character) hides itself and the rest of its line.
    /// - **Values that go on.** A quote that does not close on its line hides the lines up to the
    ///   one where it closes, and that line whole. After a value hidden to the end of its line, the
    ///   lines indented more and the line after a trailing `\` are hidden; so is the next line with
    ///   text when nothing but punctuation followed the name, the line ends open (`(`, `:`, `<key>`,
    ///   `"""`) or it ends at a break other than LF and CRLF.
    /// - **Secret names written as values.** A quoted value that names a secret or cannot be read
    ///   (`name="password"`, `<string name="api_key">`) hides the rest of its line after the
    ///   closing quote. After a key that holds a name (`name=`, `key=`, `label=`, `id=`, … but not
    ///   `path=`, the route of a request) a name that is not plain ASCII counts as secret, as in
    ///   JSON (`label="Пароль"`), and so does JSON there (`name=["pin"]`), to the end of the line
    ///   where it closes when it spans lines. In XML and HTML the other attribute values of its
    ///   start tag are hidden too, and the lines below up to the end of the element and the rest of
    ///   the line where it ends; a secret name in an element's text (`<key>password</key>`) names
    ///   the element after it, also on the lines below, as a property list writes them. An element
    ///   that holds nothing (`<string/>`, `<string></string>`) holds no value, so the text after
    ///   it, or the next line with text that is not markup, is hidden too. A name that is plain
    ///   and not secret keeps what follows it. An unquoted name after such a key
    ///   (`name=password`) names what follows it as a quoted one does.
    /// - **Names inside hidden values.** Each line is read a second time for the names written as
    ///   values in what the first reading hid without reading it, and in quoted values, so a name
    ///   hides what follows it wherever it is on its line: `Content-Disposition: form-data;
    ///   name="pin"` hides the value of `Content-Disposition`, and the name in it the part's value
    ///   below. A secret name in a header of a multipart part written into text hides the part's
    ///   other headers and its value, up to the delimiter line written before the header, or,
    ///   without one, up to a blank line or a line that starts with `--`.
    /// - **Embedded JSON.** JSON in a line (`{"…`, `[{…`, `["…`, `[[…`) is parsed and redacted by the
    ///   key rule for structured input, within the limits listed under "Limits". JSON that does not
    ///   parse hides the rest of the line, and the lines below until its brackets close.
    /// - **URLs** with a scheme and `//` are recorded as ``redact(url:)`` records them.
    /// - **Values** are scanned for card numbers, IBANs, email addresses and tokens everywhere.
    ///
    /// U+2028, U+2029, U+0085, vertical tab and form feed end a line and are written as line feeds,
    /// so the result breaks lines where the rule did; CR and CRLF end a line too and are kept.
    public func redact(_ text: String) -> String {
        redact(text, nesting: .text(length: text.unicodeScalars.count))
    }

    /// Returns the sensitive data found in a text, in order, without overlaps.
    public func matches(in text: String) -> [Match] {
        let scalars = Array(text.unicodeScalars)
        let spans = textSpans(in: scalars, compatibility: CompatibilityText(), nesting: .text(length: scalars.count)).filter { !$0.kind.isEmpty }
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
}
