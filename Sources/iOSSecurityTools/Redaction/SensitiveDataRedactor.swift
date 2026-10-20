import Foundation

/// Finds card numbers, bank account numbers, email addresses, tokens and the values of secret
/// keys and hides them, for log messages, crash reports and analytics events.
///
/// ```swift
/// let redactor = SensitiveDataRedactor()
/// let body = Data(#"{"user":"alice@example.com","password":"hunter2"}"#.utf8)
/// redactor.redact(body: body, contentType: "application/json")
/// // {"user":"a•••@example.com","password":"[redacted]"}
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
/// A log line has no grammar, so it is cut once: **in free text, the first secret name hides
/// everything after it in that text; this over-hides on purpose.** A key that is not on
/// ``allowedTextKeys`` (`x=hunter2`, `Error: …`), a word that cannot be read and a quote or
/// bracket left open cut it too. Strings inside JSON, form values, allowed query values and
/// multipart text parts are free text, each on its own. ``redact(_:)`` describes the rule.
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
/// - JSON in free text is parsed when it is at most 64 Ki scalars long.
///
/// JSON that goes past a limit is not read. A body is then omitted, and a string or other text
/// inside a document that holds such JSON, or a URL one level too many, is hidden whole, as is
/// a text inside a found document that the reading budget no longer covers. In a log line, JSON
/// nested deeper than 64 levels or longer than 64 Ki scalars cuts the line at its first bracket,
/// like JSON that does not parse. Free text is read in one pass that keeps a fixed number of
/// positions, whatever it holds: a megabyte of it takes less than 16 MB more memory.
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

    /// The keys whose values free text reads on by default: harmless names that logs use for a
    /// response status, a request method and route, a duration and a count. The keys passed to the
    /// initializer are added to them.
    public static let defaultAllowedTextKeys: [String] = ["status", "method", "path", "duration_ms", "count"]

    /// The kinds this redactor looks for.
    public let kinds: Kinds

    /// The folded keys whose values free text reads on: ``defaultAllowedTextKeys`` and the keys
    /// passed to the initializer, lowercased and without `_`, `-`, `.` and spaces. After any other
    /// key, free text is cut (see ``redact(_:)``).
    public let allowedTextKeys: Set<String>

    /// The folded names of the query parameters whose values a URL keeps. Empty by default.
    public let allowedQueryParameters: Set<String>

    /// How much of a URL is recorded.
    public let urlDetail: URLDetail

    /// Creates a redactor.
    ///
    /// - Parameters:
    ///   - kinds: The kinds of data to look for; all of them by default.
    ///   - allowedTextKeys: Keys after which free text is read on, in addition to
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

    /// Whether free text is read on after the key `name`: it is plain ASCII, names no secret and
    /// is on ``allowedTextKeys`` once folded.
    func allowsTextKey(_ name: some Collection<Unicode.Scalar>) -> Bool {
        guard let fold = FieldName.allowableFold(name) else { return false }
        return allowedTextKeys.contains(fold)
    }

    /// A redactor with the default settings, made once and shared by the readings that need one
    /// inside a redaction: the words of an array element, the value detectors of a path segment.
    /// Making one there for every element or segment folded the default keys again each time,
    /// which took a third of the time of a JSON array of short strings.
    static let standard = SensitiveDataRedactor()

    /// Returns the text with every match replaced.
    ///
    /// The text is read as free text, which has no grammar, so it follows one rule: **the first
    /// trigger hides everything after it, to the end of the text** — not only the rest of its
    /// line. This hides more than it has to on purpose. A text without a trigger is written as it
    /// is, apart from the card numbers, IBANs, email addresses and tokens in it.
    ///
    /// ```swift
    /// redactor.redact("GET /items status=200 duration_ms=12")    // kept as it is
    /// redactor.redact("login user=bob status=401\nretry 2")      // "login user=[redacted]"
    /// redactor.redact("password hunter2")                         // "password [redacted]"
    /// ```
    ///
    /// The triggers are read on a scanning copy without invisible characters (format characters,
    /// marks, default-ignorable code points such as U+3164, control characters) and in Unicode
    /// compatibility form:
    ///
    /// - **A key that is not allowed.** In `key=value`, `key: value`, `key = value` and
    ///   `"key":"value"` the text is read on only after a key that is plain ASCII and on
    ///   ``allowedTextKeys`` (`status`, `method`, `path`, `duration_ms` and `count` by default).
    ///   Any other key cuts the text at its value, and so does a separator with no key before it
    ///   or a key on the line before its separator. The separators are `=` and `:` and runs of
    ///   them (`:=`, `==`, `=>`); one written another way than in ASCII (`＝`, `：`, `︓`), escaped
    ///   (`%3D`, `&#61;`, `%u003D`) or as punctuation or a math symbol outside ASCII (`≔`, `꞉`, `→`)
    ///   cuts the text there. A `:` between two digits, as in `12:30`, is part of a time.
    /// - **A secret name without a separator.** A word that holds a secret name cuts the text
    ///   after the name: `password hunter2`, `PIN 1234`, `export AWS_SECRET_ACCESS_KEY …`. Words
    ///   are read after their escapes are decoded, with punctuation inside them (`pass~word`) and a
    ///   space or `|` between two of them (`pass word`) read as a separator, and one letter that
    ///   has no ASCII form (`ɑ`, `ı`) read as any letter or, between two letters, as none
    ///   (`passꞏword`). A name disguised with two or more such letters and written without a
    ///   separator (`pɑsswoʀd hunter2`) is not found.
    /// - **A name written as a value.** After an allowed key that holds a name (`id=`, `type=`, …
    ///   but not `path=`, the route of a request), a secret name or one that is not plain ASCII
    ///   cuts the text after it, as in JSON (`type="Пароль"`), and so does JSON there. In markup,
    ///   the text of an element whose tag holds a name (`<key>Şifre</key>`) is read the same way,
    ///   and a trigger inside a start tag cuts the text at its first attribute value.
    /// - **A word that cannot be read.** A word that mixes scripts (`pаssword` with a Cyrillic
    ///   `а`) or holds an invisible character other than a mark (`pa\u{115F}ssword`, a zero-width
    ///   space, a control character) cuts the text where it starts.
    /// - **A quote or bracket that does not close** by the end of the text cuts it after the
    ///   quote or bracket.
    /// - **JSON in the text** (`{"…`, `[{…`, `["…`, `[[…`) is parsed and redacted by the key rule for
    ///   structured input, within the limits listed under "Limits"; its members follow the rule for
    ///   keys, so the text is cut at the value of the first member that is not allowed, or at the
    ///   first value the key rule hides. JSON that does not parse, or is longer than 64 Ki
    ///   scalars, cuts the text at its first bracket.
    ///
    /// **URLs** with a scheme and `//` are recorded as ``redact(url:)`` records them, and the text
    /// is read on after them.
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
