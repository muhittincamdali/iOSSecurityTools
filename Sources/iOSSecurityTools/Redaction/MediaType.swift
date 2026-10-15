/// A `Content-Type` value, read strictly as RFC 9110 writes it: `type/subtype` and
/// `; name=value` parameters whose value is a token or a quoted string.
struct MediaType {
    /// `type/subtype` in lowercase, such as `application/json`.
    let essence: String
    /// The parameters in order, with lowercase names; quoted values without their quotes.
    let parameters: [(name: String, value: String)]

    init?(_ text: String) {
        var reader = HeaderValueReader(Array(text.unicodeScalars))
        reader.skipWhitespace()
        guard let type = reader.token(), reader.consume("/"), let subtype = reader.token() else { return nil }
        guard let parameters = reader.parameters() else { return nil }
        self.essence = (type + "/" + subtype).lowercased()
        self.parameters = parameters
    }

    var isJSON: Bool { essence == "application/json" || essence == "text/json" || essence.hasSuffix("+json") }
    var isForm: Bool { essence == "application/x-www-form-urlencoded" }
    var isMultipartFormData: Bool { essence == "multipart/form-data" }
    var isPlainText: Bool { essence == "text/plain" }

    /// The values of every parameter with this name.
    func values(of name: String) -> [String] {
        parameters.filter { $0.name == name }.map(\.value)
    }

    /// Whether the text is UTF-8: no `charset`, or `utf-8` or `us-ascii`.
    var isUTF8: Bool {
        let charsets = values(of: "charset").map { $0.lowercased() }
        return charsets.isEmpty || (charsets.count == 1 && ["utf-8", "utf8", "us-ascii"].contains(charsets[0]))
    }
}

/// Reads the `token`, `quoted-string` and parameter syntax shared by `Content-Type` and
/// `Content-Disposition`.
struct HeaderValueReader {
    private let scalars: [Unicode.Scalar]
    private var position = 0

    init(_ scalars: [Unicode.Scalar]) { self.scalars = scalars }

    /// `*( OWS ";" OWS name "=" value ) OWS` up to the end; nil when anything else is there.
    mutating func parameters() -> [(name: String, value: String)]? {
        var parameters: [(name: String, value: String)] = []
        while true {
            skipWhitespace()
            if position == scalars.count { return parameters }
            guard consume(";") else { return nil }
            skipWhitespace()
            guard let name = token(), consume("=") else { return nil }
            guard let value = scalars.indices.contains(position) && scalars[position] == "\"" ? quotedString() : token() else { return nil }
            parameters.append((name.lowercased(), value))
        }
    }

    mutating func token() -> String? {
        let start = position
        while position < scalars.count, Self.isTokenCharacter(scalars[position]) { position += 1 }
        return position > start ? String(String.UnicodeScalarView(scalars[start..<position])) : nil
    }

    /// A quoted string; its content may hold UTF-8 text, as browsers send file and field names.
    /// A `\` escape is kept as written: servers differ in whether they decode it, and a name with
    /// a `\` is not plain, so its value is hidden either way.
    private mutating func quotedString() -> String? {
        position += 1
        var value = String.UnicodeScalarView()
        while position < scalars.count {
            let scalar = scalars[position]
            position += 1
            switch scalar {
            case "\"": return String(value)
            case "\\":
                guard position < scalars.count, scalars[position] != "\r", scalars[position] != "\n" else { return nil }
                value.append(scalar)
                value.append(scalars[position])
                position += 1
            case "\r", "\n", "\0": return nil
            default: value.append(scalar)
            }
        }
        return nil
    }

    mutating func consume(_ scalar: Unicode.Scalar) -> Bool {
        guard position < scalars.count, scalars[position] == scalar else { return false }
        position += 1
        return true
    }

    mutating func skipWhitespace() {
        while position < scalars.count, scalars[position] == " " || scalars[position] == "\t" { position += 1 }
    }

    static func isTokenCharacter(_ scalar: Unicode.Scalar) -> Bool {
        guard scalar.isASCII else { return false }
        return ASCII.isAlphanumeric(UInt8(scalar.value)) || "!#$%&'*+-.^_`|~".unicodeScalars.contains(scalar)
    }
}
