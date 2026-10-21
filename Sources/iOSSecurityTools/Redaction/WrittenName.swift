/// Names written as values: the one rule that decides whether a string names a field whose value
/// is hidden. Every path that reads such a name calls ``namesSecret(_:in:compatibility:)``: JSON
/// objects and arrays (in a body, in a line of text, in a JSON string, in a form value, in a URL
/// query, in a multipart part), form fields, URL queries, multipart parts, and quoted values and
/// markup in free text.
///
/// A field that holds a name (`{"label":"Password","value":…}`) is read by the key rule of
/// ``FieldName``, as a key is: its name hides what goes with it unless it is plain ASCII and
/// names no secret. A name in letters outside ASCII (`Şifre`, `Пароль`), in symbols with no letter
/// or digit of their own (`ⓟⓘⓝ`, `🄿🄸🄽`, `🔑`, `𝐩𝐢𝐧`) or with punctuation (`Password:`) counts as
/// secret, whatever it says, and so does a name with a control character in it — a line feed, a
/// carriage return, a tab or any other. Elsewhere a name with a control character in it counts
/// when it names a secret with its control characters left out or read as spaces, and a name of
/// control characters and white space alone counts beside a field (see
/// ``nameNamesSecret(_:byKeyRule:compatibility:)``, the one decision every place makes).
enum WrittenName {
    /// Where a name is written, which decides how it is read.
    enum Place {
        /// The value of the field `field` of an object, a form, a URL query or a multipart body.
        /// When the field holds a name (see ``holdsName(_:)``), the value is read by the key rule;
        /// otherwise it names a secret only when it is a name (see ``isName(_:compatibility:)``)
        /// whose words name a secret or cannot be read, or when it is control characters and
        /// white space alone (see ``isBlankWithControl(_:)``).
        case field([Unicode.Scalar])
        /// The first element of a two-element array, as fetch headers and `URLSearchParams`
        /// entries are written: read by the key rule.
        case pairName
        /// An element of an array: any word of it that names a secret or cannot be read counts.
        case element
        /// A quoted or unquoted value in free text after the allowed key `key`: read by the key rule
        /// when `key` holds a name, and in any case for words that name a secret or cannot be read.
        case quoted(after: [Unicode.Scalar]?)
    }

    /// Whether `value`, written at `place`, names a field whose value is hidden.
    static func namesSecret(_ value: [Unicode.Scalar], in place: Place, compatibility: CompatibilityText) -> Bool {
        switch place {
        case .field(let field):
            if holdsName(field) { return heldNameNamesSecret(value, field: field, compatibility: compatibility) }
            // A name of control characters and spaces alone has no letter or digit, so it is no
            // name to `isName`; it cannot be read, and what it stands for cannot be told.
            if isBlankWithControl(value) { return true }
            return isName(value, compatibility: compatibility) && nameNamesSecret(value, byKeyRule: false, compatibility: compatibility)
        case .pairName:
            return heldNameNamesSecret(value, field: nil, compatibility: compatibility)
        case .element:
            return FreeTextScanner.mentionsSecret(value, compatibility: compatibility)
        case .quoted(let key):
            if let key, holdsNameInText(key), heldNameNamesSecret(value, field: key, compatibility: compatibility) { return true }
            return !value.isEmpty && nameNamesSecret(value, byKeyRule: false, compatibility: compatibility)
        }
    }

    /// Whether a name written as a value names a secret: the one decision of every place that
    /// reads a name. With `byKeyRule`, for a field that holds a name or the name of a pair, a name
    /// that is not plain ASCII names one (see ``FieldName/hidesValue(_:)``), and so does a name
    /// with a control character (Cc) in it, whatever it says. Elsewhere a name names a secret when
    /// its words do, as free text reads them (see ``FreeTextScanner/nameNamesSecret(_:compatibility:)``);
    /// a name with a control character in it is read twice, with its control characters left out
    /// and with each read as a space, as one reader trims or drops them and another splits there
    /// (`DbPassword\n`, `\r\npin`, `Db\nPassword`, `pa\nssword`), and either reading counts. So a
    /// name with a line break or a tab that names nothing either way (`Hello\nWorld`, `ok\n`,
    /// `a\tb`) keeps what is beside it.
    static func nameNamesSecret(_ value: [Unicode.Scalar], byKeyRule: Bool, compatibility: CompatibilityText) -> Bool {
        if byKeyRule, FieldName.hidesValue(value) { return true }
        guard value.contains(where: isControl) else { return FreeTextScanner.nameNamesSecret(value, compatibility: compatibility) }
        if byKeyRule { return true }
        let dropped = value.filter { !isControl($0) }
        let split = value.map { isControl($0) ? " " : $0 }
        return FreeTextScanner.nameNamesSecret(dropped, compatibility: compatibility)
            || FreeTextScanner.nameNamesSecret(split, compatibility: compatibility)
    }

    /// The control characters, U+0000 to U+001F and U+007F to U+009F: the general category Cc.
    private static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || (0x7F...0x9F).contains(scalar.value)
    }

    /// Whether a string of at most ``PlainName/maximumKeyLength`` scalars holds a control
    /// character and nothing but control characters and white space (`\n`, `\t`, `\u{0}`, ` \n `).
    static func isBlankWithControl(_ value: [Unicode.Scalar]) -> Bool {
        guard value.count <= PlainName.maximumKeyLength, value.contains(where: isControl) else { return false }
        return value.allSatisfy { isControl($0) || $0.properties.isWhitespace }
    }

    // MARK: Fields that hold names

    /// The fields whose value is a name: the names of name and value pairs, as HTTP archives,
    /// JSON Patch, SCIM, forms and configurations write them.
    static let nameFields: Set<String> = ["name", "key", "field", "label", "type", "header", "param", "path", "id", "k", "n"]

    /// The fields that stay beside a name that names a secret, when they hold a string: the names
    /// of pairs, which are names and not values.
    static let stayingFields: Set<String> = ["name", "key", "field", "header", "param", "path", "k", "n"]

    /// The JSON Patch and SCIM operations, whose `op` stays beside a name.
    private static let operations: Set<String> = ["add", "remove", "replace", "move", "copy", "test"]

    private static let longestField = nameFields.union(["op"]).map(\.count).max() ?? 0

    /// Whether a field holds a name: one of ``nameFields`` in any case, or a field whose own name
    /// is not plain ASCII, which may be one of them disguised (`lab\u{200B}el`, `ⓛⓐⓑⓔⓛ`).
    static func holdsName(_ field: [Unicode.Scalar]) -> Bool {
        if isField(field, oneOf: nameFields) { return true }
        // A field of ASCII letters and digits is plain; only the others need to be read.
        let isAlphanumeric = field.allSatisfy { $0.isASCII && ASCII.isAlphanumeric(UInt8($0.value)) }
        if !field.isEmpty, field.count <= PlainName.maximumKeyLength, isAlphanumeric { return false }
        return PlainName(field) == nil
    }

    /// Whether a key of free text holds a name: as ``holdsName(_:)``, but for `path`, which in a
    /// log line is the route of a request (`path=/v1/users`) and is allowed by default.
    static func holdsNameInText(_ key: [Unicode.Scalar]) -> Bool {
        holdsName(key) && !isField(key, oneOf: ["path"])
    }

    /// Whether the field `field` with the string `value` stays beside a name that names a secret:
    /// the name of a pair, or the `op` of a JSON Patch or SCIM operation.
    static func staysBesideName(_ field: [Unicode.Scalar], value: [Unicode.Scalar]) -> Bool {
        if isField(field, oneOf: stayingFields) { return true }
        guard isField(field, oneOf: ["op"]), value.count <= 7 else { return false }
        return operations.contains(String(String.UnicodeScalarView(value)).lowercased())
    }

    static func isField(_ field: [Unicode.Scalar], oneOf names: Set<String>) -> Bool {
        field.count <= longestField && names.contains(String(String.UnicodeScalarView(field)).lowercased())
    }

    /// A name held by a field, read by the key rule: anything but a plain-ASCII name that names no
    /// secret names one. Of a `path`, every part between `/` is such a name (see
    /// ``pathNamesSecret(_:)``). The words of a plain name are read as free text reads them too.
    private static func heldNameNamesSecret(_ value: [Unicode.Scalar], field: [Unicode.Scalar]?, compatibility: CompatibilityText) -> Bool {
        if let field, isField(field, oneOf: ["path"]) { return pathNamesSecret(value) }
        return nameNamesSecret(value, byKeyRule: true, compatibility: compatibility)
    }

    /// Whether a JSON Pointer or SCIM path leads to a value that is hidden: one of its parts
    /// between `/` hides a value by the key rule. The last part names the field (`/user/password`,
    /// SCIM `password`), and a part before it holds the field (`/apiKeys/0`, `/password/hint`), so
    /// the value is inside a secret either way. Array indexes (`0`, and `-` for the end) name
    /// nothing. An empty path, which stands for the whole document, hides the value.
    static func pathNamesSecret(_ path: [Unicode.Scalar]) -> Bool {
        var parts = path.split(separator: "/", omittingEmptySubsequences: false)
        if path.first == "/" { parts.removeFirst() }
        return parts.contains { part in !(part.count == 1 && part.first == "-") && FieldName.hidesValue(part) }
    }

    // MARK: Names in other fields

    /// Whether a string is a name rather than a sentence or a document: at most
    /// ``PlainName/maximumKeyLength`` scalars with a letter or digit, and once the punctuation,
    /// spaces and line breaks around it are left out, without `:`, `=`, `,`, `;`, quotes or
    /// brackets, which pair a key with a value or hold one (`Error: token expired`,
    /// `{"password":…}`). A symbol whose compatibility form is a letter or digit (`ⓟ`, `🄿`, `①`)
    /// counts as one, so a name written only in such symbols is a name. The `;` that ends a
    /// character reference (`p&#97;ssword`, `&#x63;ard`, `&amp;#xauth`) pairs nothing: it is part
    /// of the escape, which the name is read through (see ``FreeTextScanner/nameNamesSecret(_:compatibility:)``).
    /// A line break does not keep a string from being a name: a name with one in it
    /// (`DbPassword\n`, `Db\nPassword`) names a secret by the one decision of
    /// ``nameNamesSecret(_:byKeyRule:compatibility:)``.
    static func isName(_ scalars: [Unicode.Scalar], compatibility: CompatibilityText) -> Bool {
        guard scalars.count <= PlainName.maximumKeyLength else { return false }
        let isLetterOrDigit = { (scalar: Unicode.Scalar) in Self.isLetterOrDigit(scalar, compatibility: compatibility) }
        guard let first = scalars.firstIndex(where: isLetterOrDigit), let last = scalars.lastIndex(where: isLetterOrDigit) else { return false }
        return !(first...last).contains { i in
            notInNames.contains(scalars[i]) && !(scalars[i] == ";" && endsReference(scalars, at: i))
        }
    }

    /// Whether the `;` at `i` ends a character reference: `&`, then ASCII letters, digits, `#` and
    /// the `;` of references before it (`&amp;`, `&#97;`, `&#x61;`, `&amp;#x63;`). Reading more as
    /// a name only ever hides more: the name still has to name a secret.
    private static func endsReference(_ scalars: [Unicode.Scalar], at i: Int) -> Bool {
        var j = i - 1
        while j >= 0, scalars[j].isASCII, ASCII.isAlphanumeric(UInt8(scalars[j].value)) || scalars[j] == "#" || scalars[j] == ";" { j -= 1 }
        return j >= 0 && j < i - 1 && scalars[j] == "&"
    }

    private static let notInNames = Set(":=,;\"'()[]{}<>".unicodeScalars)

    /// A letter, mark or number of any script, or a symbol whose compatibility form is ASCII
    /// letters and digits.
    private static func isLetterOrDigit(_ scalar: Unicode.Scalar, compatibility: CompatibilityText) -> Bool {
        if scalar.isASCII { return ASCII.isAlphanumeric(UInt8(scalar.value)) }
        if ScalarClass.isLetterOrNumber(scalar) { return true }
        let reading = compatibility.ascii(scalar)
        return !reading.isEmpty && reading.allSatisfy(ASCII.isAlphanumeric)
    }
}

/// The fields of an object, a form, a URL query or a multipart body that name a secret in their
/// value. The value of every other field is hidden whole, whatever the field is called, unless it
/// stays beside the name (see ``WrittenName/staysBesideName(_:value:)``): the fields have no
/// order, so what belongs to the name cannot be told.
///
/// Only the positions of the fields that name a secret are kept, not the fields: a form of a
/// quarter of a megabyte has 60,000 of them.
struct NamingFields {
    enum Value {
        case string([Unicode.Scalar])
        /// An object or an array, which a field that holds a name cannot hold as a name.
        case structure
        /// A number, `true`, `false`, `null`, or no value at all.
        case other
    }

    typealias Field = (name: [Unicode.Scalar], value: Value)

    private var naming: [Int] = []
    private var count = 0

    /// No fields yet; ``read(_:compatibility:)`` reads them in order.
    init() {}

    /// Reads the fields in order, one at a time.
    init(_ fields: some Sequence<Field>, compatibility: CompatibilityText) {
        for field in fields { read(field, compatibility: compatibility) }
    }

    /// Whether a field read so far names a secret.
    var hasNamingField: Bool { !naming.isEmpty }

    /// Reads the next field.
    mutating func read(_ field: Field, compatibility: CompatibilityText) {
        if Self.namesSecret(field, compatibility: compatibility) { naming.append(count) }
        count += 1
    }

    private static func namesSecret(_ field: Field, compatibility: CompatibilityText) -> Bool {
        switch field.value {
        case .string(let text): WrittenName.namesSecret(text, in: .field(field.name), compatibility: compatibility)
        case .structure: WrittenName.holdsName(field.name)
        case .other: false
        }
    }

    /// Whether the value of field `index`, which is `field`, is hidden because another field
    /// names a secret. The field is made only when one does.
    func hidesValue(at index: Int, of field: @autoclosure () -> Field) -> Bool {
        guard naming.count > 1 || naming.first.map({ $0 != index }) == true else { return false }
        let field = field()
        guard case .string(let text) = field.value else { return true }
        return !WrittenName.staysBesideName(field.name, value: text)
    }
}
