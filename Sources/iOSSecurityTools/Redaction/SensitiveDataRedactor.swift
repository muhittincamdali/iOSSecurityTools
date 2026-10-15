import Foundation

/// Finds card numbers, email addresses, tokens and the values of secret fields and hides them,
/// for log messages, crash reports and analytics events.
///
/// ```swift
/// let redactor = SensitiveDataRedactor()
/// redactor.redact(#"POST /login {"user":"alice@example.com","password":"hunter2"}"#)
/// // POST /login {"user":"a•••@example.com","password":"[redacted]"}
/// ```
///
/// What it recognizes anywhere in a text:
///
/// - **Card numbers**: 13 to 19 digits that pass the Luhn check, optionally grouped with spaces
///   or hyphens. Shown as `•••• 4242`.
/// - **Email addresses**: shown with ``Mask/email(_:)``.
/// - **JSON Web Tokens**: `eyJ…​.…​.…` — replaced completely.
/// - **Bearer tokens**: the token after `Bearer `.
/// - **Secret fields**: the value of a field whose name hides it, described below.
///
/// ## Which names hide a value
///
/// Only plain-ASCII names are compared: names made of `A`–`Z`, `a`–`z`, `0`–`9`, `_` and `-`.
/// `_` and `-` are folded away first, so `pass_word` and `PASS-WORD` read as `password`. A
/// plain name hides its value when one of its words starts a secret word that ends with a word
/// of the name — `password`, `pass`, `pwd`, `token`, `secret`, `api_key`, `authorization`,
/// `session_id` and similar, as in `accessToken`, `client_secret`, `SECRET_KEY`, `DB_PASS`,
/// `aws_secret_access_key` or `password2` — when it contains `password`, `passwd`, `passphrase`
/// or another compound secret word anywhere (`dbpassword`), when it ends in `token`, `secret` or
/// `pwd` (`apitoken`), or when it is `session`, `PHPSESSID` or `JSESSIONID`. Names that only
/// describe a secret, such as `passwordHint`, `token_type`, `pass_count` or `session_start`, are
/// left alone, and so is `pass` inside another word (`bypass`, `passport`, but also `mypass`).
///
/// **Any other name is redacted by default.** A name with a letter outside ASCII, a mark, an
/// invisible format character, mixed scripts, a space, a dot, a bracket, an escape or other
/// punctuation can be written to look like a secret name, and no list of look-alikes is
/// complete, so its value is hidden whatever it says: `pаssword` with a Cyrillic `а`,
/// `pass` and `word` with a zero-width space between them, `pass.word`, `pass%77ord` and
/// `user[name]` all hide their value, and so do `статус` and `café`.
///
/// A hidden value is hidden whole: a string, and an array or object with everything in it.
///
/// ## Structured text
///
/// A text that is a JSON object or array is read with a JSON parser and checked against
/// `JSONSerialization`: names are compared after their escapes are decoded, at every depth,
/// inside arrays and for every repetition of a name, and strings that hold JSON themselves are
/// read too.
///
/// ## Free text
///
/// Everything else, such as a log line, is read with the free-text rule:
///
/// - A field is a name, a separator and a value. Separators are `=` and `:` and runs of them
///   (`:=`, `==`, `::=`, `= =`), `?=`, `!=`, `+=`, `<=`, `>=`, `=>`, characters whose Unicode
///   compatibility form is made of `=` and `:` (`＝`, `：`, `︓`, `⩴`), `≔` and `∶`, and `=` or `:`
///   written as an escape (`%3D`, `%253A`, `&#61;`, `&colon;`, `\u003D`).
/// - The name is the text in the quotes right before the separator (`"password":`, `'token':`,
///   `\"api_key\":`), or the word right before it, back to whitespace, a quote, `,`, `;`, `&`,
///   `?` or another separator; a word that ends in a bracket keeps its brackets (`user[name]`).
///   The words before a plain name, when only whitespace separates them, are read with it when a
///   secret word could start there and end in the name, so `pass word=` and `API key:` hide
///   their value; a word in those that is not plain ASCII could spell anything and counts as a
///   match.
/// - The value is the text in quotes, the text in brackets up to the bracket that closes it, or
///   the word after the separator, up to whitespace, `,`, `;`, `&`, a closing bracket, `<`, a
///   quote or a `:` before whitespace. A quoted part glued to the word (`x='…'`) belongs to it,
///   and after `Bearer`, `Basic` and other authentication schemes the credentials that follow do
///   too. With nothing after the separator on its line, the value is on the next line.
/// - When the rule cannot tell, it hides: a separator with no name before it hides the rest of
///   its line, an unclosed quote hides the rest of the line and an unclosed bracket the rest of
///   the text. After a name that names a secret, punctuation or a symbol outside ASCII
///   (`password꞉…`, `pass·word: …`) is taken as a separator and hides the rest of the line. In
///   `<name …>value</name>` the element name is judged like a field name.
///
/// When two findings partly overlap, such as a token that runs into a card number
/// (`token=abc_4111 1111 1111 1111`), the whole stretch they cover becomes `[redacted]`. Card
/// numbers, email addresses and tokens are found after Unicode compatibility normalization, so
/// full-width digits, zero-width characters and Unicode spaces do not hide them. Scanning and
/// replacing take time linear in the length of the text and do not use regular expressions.
///
/// Redaction is a safety net for mistakes, not a reason to log secrets. It cannot recognize a
/// secret that is not labelled, a plain-ASCII label it does not know (`pin`, `credentials`), or
/// text encoded as a whole, such as base64. In free text it does not read a value separated from
/// its name only by whitespace (`password hunter2`), the words of an unquoted value after the
/// first (`password=hunter 2`), a name split by `,`, `;`, `&`, `=` or `:`, XML `CDATA` sections,
/// attribute values (`<input name="password" value="…">`), operators such as `->`, or a
/// separator that only looks like `=` or `:` after a name written entirely in letters of other
/// scripts. Values of names that are not plain ASCII are hidden even when they hold nothing
/// secret.
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
        /// Values of fields whose name hides them: secret names such as `password`, `token` or
        /// `api_key`, and every name that is not plain ASCII.
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

    /// The words that make a field name secret, in lowercase without `_` or `-`; a plain name
    /// holds one when a word of the name starts it and a word of the name ends it.
    static let secretFieldNames: [[UInt8]] = [
        "authorization", "clientsecret", "refreshtoken", "accesstoken", "privatekey", "secretkey",
        "sessionid", "sessionkey", "passphrase", "password", "idtoken", "apikey", "passwd", "secret",
        "token", "pass", "pwd",
    ].map { Array($0.utf8) }

    /// Secret words that hold a secret wherever they are in a name (`dbpassword`,
    /// `userapikey`): none of them is the start or end of a common word that is not secret.
    static let unboundedSecretFieldNames: Set<[UInt8]> = Set([
        "authorization", "clientsecret", "refreshtoken", "accesstoken", "privatekey", "secretkey",
        "sessionid", "sessionkey", "passphrase", "password", "idtoken", "apikey", "passwd",
    ].map { Array($0.utf8) })

    /// Secret words that hold a secret at the end of a name (`apitoken`, `appsecret`, `dbpwd`),
    /// where they cannot be the start of another word (`tokenizer`, `secretary`).
    static let trailingSecretFieldNames: Set<[UInt8]> = Set(["token", "secret", "pwd"].map { Array($0.utf8) })

    /// Field names that hold a secret only when they are the whole name: a `session` cookie holds
    /// the session, while `session_start` or `sessionCount` describe it. `PHPSESSID` and
    /// `JSESSIONID` are the session cookies of PHP and Java servers.
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
        let spans = spans(in: scalars, compatibility: CompatibilityText())
        guard !spans.isEmpty else { return text }
        return Self.replacing(spans, in: scalars)
    }

    /// Returns the sensitive data found in a text, in order, without overlaps.
    public func matches(in text: String) -> [Match] {
        let scalars = Array(text.unicodeScalars)
        let spans = spans(in: scalars, compatibility: CompatibilityText())
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

    /// The findings in a text, in order and without overlaps. `document` is the text already
    /// read as JSON, when the caller has done that.
    func spans(in scalars: [Unicode.Scalar], compatibility: CompatibilityText, document: JSONDocument? = nil) -> [Span] {
        var found: [Span] = []
        if kinds.contains(.secretFields) {
            if let document = document ?? Self.jsonDocument(scalars) {
                found += document.secretSpans(using: self, compatibility: compatibility)
            } else {
                found += FreeTextFields(scalars: scalars, bounds: scalars.indices, compatibility: compatibility).spans()
            }
        }
        if !kinds.isDisjoint(with: [.bearerTokens, .jsonWebTokens, .emailAddresses, .cardNumbers]) {
            let text = NormalizedText(scalars, compatibility: compatibility)
            if kinds.contains(.bearerTokens) { found += text.bearerSpans() }
            if kinds.contains(.jsonWebTokens) { found += text.jsonWebTokenSpans() }
            if kinds.contains(.emailAddresses) { found += text.emailSpans() }
            if kinds.contains(.cardNumbers) { found += text.cardSpans() }
        }
        return Self.merged(found)
    }

    /// The text read as JSON when it is a JSON object or array.
    private static func jsonDocument(_ scalars: [Unicode.Scalar]) -> JSONDocument? {
        guard let first = scalars.first(where: { ![" ", "\t", "\n", "\r"].contains($0) }), first == "{" || first == "[" else { return nil }
        return JSONDocument(scalars, allowsFragments: false)
    }

    private static func merged(_ spans: [Span]) -> [Span] {
        let sorted = spans.sorted { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var result: [Span] = []
        for span in sorted {
            guard let last = result.last, span.start < last.end else {
                result.append(span)
                continue
            }
            guard span.end > last.end else { continue }
            // The two overlap and neither contains the other ("token=abc_4111 1111 1111 1111"):
            // dropping either would show part of it, so hide both as one region.
            result[result.count - 1] = Span(start: last.start, end: span.end, kind: last.kind.union(span.kind), replacement: replacement)
        }
        return result
    }
}
