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
/// repetition of a key. The output stays valid JSON. Structured key names are shown and only the
/// values under them are hidden, so a secret written into the name of a member of a body
/// (`{"password hunter2":…}`) shows; in free text such a name is cut where it starts.
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
/// URLs are read with `URLComponents` (see ``redact(url:)``); a host that is not a name of ASCII
/// labels or an address, or in which a value detector finds something, is written as
/// `[redacted]` after the scheme. ``redact(body:contentType:)`` reads JSON, form, multipart and
/// plain-text bodies of up to ``maximumBodySize`` bytes; a body it cannot parse completely is
/// omitted, and so is one that a common server parser could split into fields differently, such
/// as a multipart body with `--boundary` after a bare LF or a form with a `;`. The name of a
/// multipart part header is written only when it is one of the headers a part carries.
///
/// ## Free text
///
/// A log line has no grammar, so it is cut once: **in free text, the first secret name hides
/// everything after it in that text; this over-hides on purpose.** Over-hiding is by design. A
/// key that is not on ``allowedTextKeys`` (`x=hunter2`, `Error: …`), in quotes (`"user": …`) and as
/// the first string of a two-element array (`["user","…"]`) cuts it too, and so does the first
/// character outside a safe alphabet — letters, marks and digits of any script, the ASCII space,
/// tab and line breaks and printable ASCII — such as `꞉`, `≔`, `→`, an emoji or a control
/// character; any escape (`%3D`, `&colon;`, `\075`), which is never decoded — **in free text
/// every backslash escape cuts the text**, a backslash before anything but an ASCII space, tab or
/// line break or the end of the text; and a word longer than 256 characters. **In free text the
/// first markup tag cuts the text** (`<user>…`, `<_id>`, `</a>`, `<!--`), whatever the tag: a
/// `<` cuts it unless an ASCII space, tab, line break or digit, `=` or the end of the text follows
/// it. A quote that does not close on its line cuts it at the quote. No list of look-alike
/// separators is kept. A URL in free text is shown only when it is clean and followed by white
/// space, a line break, the end of the text or one `.`, `,`, `!` or `)` before one of those, and
/// any other URL cuts the text where it starts. Strings
/// inside JSON, form values, allowed query values and multipart text parts are free text, each on
/// its own. ``redact(_:)`` describes the rule.
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
/// - A body larger than ``maximumBodySize`` (256 KiB unless the app sets another) is omitted
///   unread.
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
/// positions, whatever it holds, and no word longer than 256 characters is copied for reading; its
/// scanning copy ends after the line of the first character outside the safe alphabet and the
/// next line that is not blank, the readings of characters outside ASCII are cached in a table of
/// fixed size, and the value detectors look only before the cut and each finding takes 24 bytes:
/// a megabyte of it takes less than 16 MB more memory, also when it is dense with findings or
/// nearly every character in it is a different one, and a body of 256 KiB less than 16 MB. Free text of 256 Mi scalars or more is hidden whole, and a body of 256 MiB or
/// more is omitted, whatever ``maximumBodySize`` says.
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
        /// Values hidden by their key: secret and non-ASCII keys in structured input, free text from
        /// its first trigger on (a key that is not allowed, a character outside the safe alphabet,
        /// an escape, a long word), the hosts, query values and path segments that ``redact(url:)``
        /// hides by its URL rules, and the password in `user:password@host` in text.
        /// ``redact(url:)`` drops a URL's user name, password and fragment with or without it.
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

    /// The default of ``maximumBodySize``: 256 KiB.
    public static let defaultMaximumBodySize = 262_144

    /// A URL whose path has more segments than this is recorded with its scheme, host and port
    /// only: 64.
    public static let maximumPathSegments = 64

    /// A URL whose query has more parameters than this is recorded with its scheme, host and port
    /// only: 128. A path with parameters (`;`) is recorded that way whatever their number.
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

    /// The folded names of the query parameters whose values ``redact(url:)`` keeps. Empty by
    /// default. Free text does not use them: a URL with a query cuts the text where it starts.
    public let allowedQueryParameters: Set<String>

    /// How much of a URL is recorded.
    public let urlDetail: URLDetail

    /// Bodies larger than this many bytes are omitted without being parsed (see
    /// ``redact(body:contentType:)``); ``defaultMaximumBodySize`` unless the initializer is given
    /// another. Reading a body takes memory in proportion to its size: the tests check that a body
    /// of 256 KiB in any shape takes less than 16 MB more, and the worst shapes take about 40
    /// bytes for each byte of the body, so a limit of 1 MiB can take 40 MB.
    public let maximumBodySize: Int

    /// Creates a redactor.
    ///
    /// - Parameters:
    ///   - kinds: The kinds of data to look for; all of them by default.
    ///   - allowedTextKeys: Keys after which free text is read on, in addition to
    ///     ``defaultAllowedTextKeys``. A key that is not plain ASCII or names a secret is ignored.
    ///   - allowedQueryParameters: Query parameters whose values ``redact(url:)`` keeps; free
    ///     text does not use them. A name that is not plain ASCII or names a secret is ignored.
    ///   - urlDetail: How much of a URL is recorded.
    ///   - maximumBodySize: The largest body that is read, in bytes; a larger one is omitted. A
    ///     body of 256 MiB or more is always omitted.
    public init(
        kinds: Kinds = .all, allowedTextKeys: [String] = [], allowedQueryParameters: [String] = [], urlDetail: URLDetail = .full,
        maximumBodySize: Int = defaultMaximumBodySize
    ) {
        self.kinds = kinds
        self.allowedTextKeys = Self.defaultAllowedTextFolds.union(Self.allowableFolds(allowedTextKeys))
        self.allowedQueryParameters = Self.allowableFolds(allowedQueryParameters)
        self.urlDetail = urlDetail
        self.maximumBodySize = maximumBodySize
    }

    /// A redactor with the allowlists and URL detail of `other` that looks for `kinds`.
    init(_ other: SensitiveDataRedactor, kinds: Kinds) {
        self.kinds = kinds
        self.allowedTextKeys = other.allowedTextKeys
        self.allowedQueryParameters = other.allowedQueryParameters
        self.urlDetail = other.urlDetail
        self.maximumBodySize = other.maximumBodySize
    }

    private static func allowableFolds(_ names: [String]) -> Set<String> {
        Set(names.compactMap { FieldName.allowableFold($0.unicodeScalars) })
    }

    /// The folds of ``defaultAllowedTextKeys``, made once for every redactor.
    private static let defaultAllowedTextFolds = allowableFolds(defaultAllowedTextKeys)

    /// Whether free text is read on after the key `name`, the one decision for every key of free
    /// text (`key=value`, a quoted key, a JSON member name or pair in a line): it is plain
    /// ASCII without a space, names no secret and is on ``allowedTextKeys`` once folded. A key
    /// longer than ``PlainName/maximumKeyLength`` is turned down before it is read.
    func allowsTextKey(_ name: some Collection<Unicode.Scalar>) -> Bool {
        guard !name.contains(" "), let fold = FieldName.allowableFold(name) else { return false }
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
    /// Six rules decide where the text is cut, and no list of variants is kept for any of them:
    ///
    /// - **A safe alphabet.** The text is read only as far as it is written in letters, marks and
    ///   digits of any script (the Unicode categories L, M and N), the ASCII space, tab, line feed
    ///   and carriage return, and printable ASCII. The first character outside it cuts the text
    ///   there: punctuation, a symbol or a space outside ASCII (`꞉`, `≔`, `→`, `·`, `＝`, `—`, `€`,
    ///   an emoji, U+00A0, U+2028), a control or format character (a zero-width space, `DEL`) and
    ///   every default-ignorable code point (U+3164). So does a letter or number whose
    ///   compatibility form, which is what the text is read as, is not in the alphabet (`🄁` is
    ///   `0,`, `⑴` is `(1)`, `½` is `1⁄2`). A modifier letter (`ː`, `ー`) is in the alphabet only
    ///   after a letter or digit outside ASCII, as in Japanese or Thai.
    /// - **Escapes.** An escape is never decoded: one that can stand for any character cuts the
    ///   text at the start of the word it is in — `%3D`, `%u003D`, `&#61;`, `&colon;`, `&amp;`, and
    ///   `&` before a letter unless it starts the name of a field before `=` (`&count=3`). In free
    ///   text every backslash escape cuts the text: a backslash does, whatever follows it, unless
    ///   an ASCII space, tab or line break or the end of the text does, so no list of its forms is
    ///   kept (`\075`, `\x3D`, `\x{73}`, `\o{163}`, `\N{…}`, `\q`; `login pa\x{73}sword hunter2`
    ///   keeps `login `). A Windows path is hidden from its first backslash on, by design.
    /// - **Opaque words.** A word longer than 256 characters cuts the text where it starts: it
    ///   cannot be read as a name.
    /// - **The key rule, in every shape.** In `key=value`, `key: value`, `key = value` and
    ///   `"key":"value"` the text is read on only after a key that is plain ASCII and on
    ///   ``allowedTextKeys`` (`status`, `method`, `path`, `duration_ms` and `count` by default).
    ///   Any other key cuts the text at its value, and so does a separator with no key before it
    ///   or a key on the line before its separator. A key in quotes of any kind — `"…":`, `'…'=`
    ///   or in backticks, a `'` opening a quote only at the start of a word — that is not allowed
    ///   cuts the text at its opening quote, so nothing written in the quotes shows (`cache miss
    ///   for "session Qz9Wk7rX": refetching` and `{'status': 200, 'last status': 'x'}` keep
    ///   `cache miss for ` and `{'status': 200, `); a key with a space in it is never allowed. A
    ///   quote glued to the word before it starts no quoted key: the text is cut where that word
    ///   starts (`x"status": 200` keeps nothing).
    ///   The separators are `=` and `:` and runs of
    ///   them (`:=`, `==`, `=>`); a `:` between two digits is part of a number only after a
    ///   number, as in `12:30:45`, `2026-10-19T12:30` and `10.0.0.1:8080`, and after a key that
    ///   ends in digits it is a separator (`user1:2345` cuts at `2345`). JSON in the text follows
    ///   the same rule member by member, a member name that is not allowed cutting it at its
    ///   opening quote, and the first string of a two-element array is a key too
    ///   (`["user","bob"]` cuts at `"user"`).
    /// - **Markup.** In free text the first markup tag cuts the text: markup is never parsed. A
    ///   `<` is a comparison only before an ASCII space, tab or line break, an ASCII digit, `=` or
    ///   the end of the text (`a < b`, `1<2`, `<3`); before anything else it cuts the text there,
    ///   whatever follows — a letter of any script, `_`, `:`, `/`, `!`, `?`, other punctuation or
    ///   a digit outside ASCII (`<user>`, `<_id>`, `</a>`, `<!-- … -->`, `<![CDATA[…]]>`,
    ///   `<?xml …?>`, `<०>`, `x << 1`); no tag is allowed. `login <user>bob</user>` keeps
    ///   `login `.
    /// - **Secret names.** A word that holds a secret name cuts the text after the name, with or
    ///   without a separator: `password hunter2`, `PIN 1234`, `export AWS_SECRET_ACCESS_KEY …`.
    ///   Punctuation inside a word (`pass~word`) and a space or `|` between two words
    ///   (`pass word`) are read as a separator. A word is compared by its ASCII skeleton: every
    ///   letter that has no ASCII form (`ꞏ`, `ı`, `ɑ`) is left out, and what remains is compared
    ///   with the secret names, a plural `s` included (`piꞏn`, `tokeın`, `tokenꞏs`, `keyıs`); a
    ///   name also counts with one of its letters missing where a letter was left out
    ///   (`pɑssword`, `user_pın`). A word of another language that reads as a name this way hides
    ///   what follows it (Turkish `yapın` reads as `pin`), on purpose. A name with two or more of
    ///   its letters replaced so and written without a separator (`pɑsswoʀd hunter2`) is not
    ///   found.
    ///   After an allowed key that holds a name (`id=`, `type=`, … but not `path=`, the route of a
    ///   request), a secret name or one that is not plain ASCII cuts the text after it, as in JSON
    ///   (`type="Пароль"`), and so does JSON there.
    ///
    /// A word that mixes scripts (`pаssword` with a Cyrillic `а`) cuts the text where it starts.
    /// A quote (`"`, a backtick, or `'` at the start of a word) that does not close on its line,
    /// or before the first character outside the safe alphabet, cuts the text at the quote, so a
    /// quoted key with a line break in it shows nothing (`"note\nQx31": 1`); and a bracket that
    /// does not close before the text ends leaves the end of its value unknown, so it cuts the text
    /// after it. JSON in the text (`{"…`, `[{…`, `["…`,
    /// `[[…`) is parsed and redacted by the key rule for structured input, within the limits listed
    /// under "Limits"; JSON that does not parse, or is longer than 64 Ki scalars, cuts the text at
    /// its first bracket.
    ///
    /// **URLs.** A URL in free text is shown only when it is clean — `scheme://host` and an
    /// optional path of ASCII letters, digits, `.`, `_`, `-` and `/` (no `?`, `#`, `;`, `%`, `=`,
    /// `:`, `@` or `\`), whose host and segments name no secret, followed by white space, a line
    /// break, the end of the text or one `.`, `,`, `!` or `)` before one of those — and any other
    /// URL cuts the text where it starts, also one that a quote, a backtick, `>`, `]`, `}` or a
    /// `?`, `#`, `;` or `:` follows (`see https://x.example/a'#token` keeps `see `);
    /// ``allowedQueryParameters`` applies only to ``redact(url:)``. A clean URL is written as
    /// ``redact(url:)`` writes it, so an identifier in its path becomes `:id`
    /// (`GET https://api.example.com/users/12345678 200` keeps
    /// `GET https://api.example.com/users/:id 200`), its last segment is read with the next word
    /// (`…/to ken hunter2`), and one longer than 256 characters cuts the text like any long word.
    /// `see https://x.example/a?page=2 ok` keeps `see `, with `page` allowed or not.
    public func redact(_ text: String) -> String {
        let length = text.unicodeScalars.count
        return redact(text, nesting: .text(length: length), compatibility: CompatibilityText(length: length))
    }

    /// Returns the sensitive data found in a text, in order, without overlaps.
    public func matches(in text: String) -> [Match] {
        var spans = {
            let scalars = Array(text.unicodeScalars)
            return textSpans(in: scalars, compatibility: CompatibilityText(length: scalars.count), nesting: .text(length: scalars.count))
        }()
        spans.removeAll { $0.kind.isEmpty }
        // The spans are in order and do not overlap, so one walk through the scalars finds the
        // index of each start and end; no index is kept for any other scalar.
        let view = text.unicodeScalars
        var current = view.startIndex
        var offset = 0
        func index(at target: Int) -> String.Index {
            current = view.index(current, offsetBy: target - offset)
            offset = target
            return current
        }
        var matches: [Match] = []
        matches.reserveCapacity(spans.count)
        for span in spans {
            let start = index(at: span.start)
            matches.append(Match(kind: span.kind, range: start..<index(at: span.end)))
        }
        return matches
    }
}
