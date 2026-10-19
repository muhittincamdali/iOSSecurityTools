import Foundation

/// A JSON text, read with the grammar of RFC 8259 and nothing more, together with where each
/// value is in the text.
///
/// The reader keeps every member of an object in order, repeated names included, and knows the
/// range of every value, which `JSONSerialization` does not report. So that redaction decisions
/// are made on what a JSON parser reads, a document is accepted only when `JSONSerialization`
/// also parses the text and finds the same structure, the same names and the same strings.
/// Anything else, such as a trailing comma, a comment, a lone surrogate escape or nesting deeper
/// than ``maximumDepth``, is not a document.
struct JSONDocument {
    struct Node {
        /// The whole value in the text, quotes and brackets included.
        let range: Range<Int>
        let value: Value
    }

    indirect enum Value {
        case object([Member])
        case array([Node])
        case string(StringToken)
        case number
        case boolean
        case null
    }

    struct Member {
        let name: StringToken
        let value: Node
    }

    struct StringToken {
        /// The characters between the quotes, as written.
        let content: Range<Int>
        /// The string after its escapes are decoded; nil when it has no escapes.
        let decoded: [Unicode.Scalar]?
    }

    static let maximumDepth = 256

    let scalars: [Unicode.Scalar]
    let root: Node

    /// Reads a JSON text; nil when it is not one or `JSONSerialization` reads it differently.
    /// - Parameter allowsFragments: Whether the text may be a single string, number or literal
    ///   instead of an object or array.
    init?(_ scalars: [Unicode.Scalar], allowsFragments: Bool) {
        var reader = Reader(scalars: scalars)
        guard let root = reader.document(), allowsFragments || root.isContainer else { return nil }
        let data = Data(String(String.UnicodeScalarView(scalars)).utf8)
        guard let parsed = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed),
              Self.agrees(root, with: parsed, in: scalars)
        else { return nil }
        self.scalars = scalars
        self.root = root
    }

    /// Reads the JSON object or array that starts at `start` in a longer text, such as a log line;
    /// nil when there is none or `JSONSerialization` reads it differently. Ranges are offsets in
    /// the whole text.
    init?(_ scalars: [Unicode.Scalar], at start: Int) {
        var reader = Reader(scalars: scalars, position: start)
        guard let root = reader.value(), root.isContainer else { return nil }
        let data = Data(String(String.UnicodeScalarView(scalars[root.range])).utf8)
        guard let parsed = try? JSONSerialization.jsonObject(with: data), Self.agrees(root, with: parsed, in: scalars) else { return nil }
        self.scalars = scalars
        self.root = root
    }

    /// The text of a string, with its escapes decoded.
    func text(of token: StringToken) -> [Unicode.Scalar] {
        token.decoded ?? Array(scalars[token.content])
    }

    // MARK: Agreement with JSONSerialization

    private static func agrees(_ node: Node, with parsed: Any, in scalars: [Unicode.Scalar]) -> Bool {
        switch node.value {
        case .object(let members):
            guard let dictionary = parsed as? NSDictionary else { return false }
            return agrees(members, with: dictionary, in: scalars)
        case .array(let elements):
            guard let array = parsed as? NSArray, array.count == elements.count else { return false }
            return zip(elements, array).allSatisfy { agrees($0, with: $1, in: scalars) }
        case .string(let token):
            guard let string = parsed as? NSString else { return false }
            return Array((string as String).utf16) == utf16(token, in: scalars)
        case .number, .boolean:
            return parsed is NSNumber
        case .null:
            return parsed is NSNull
        }
    }

    /// Names are compared as UTF-16, as `NSString` compares them: Swift's `String` equality would
    /// treat canonically equivalent names (`é` and `e` with a combining accent) as one.
    private static func agrees(_ members: [Member], with dictionary: NSDictionary, in scalars: [Unicode.Scalar]) -> Bool {
        var counts: [[UInt16]: Int] = [:]
        for member in members { counts[utf16(member.name, in: scalars), default: 0] += 1 }
        guard counts.count == dictionary.count else { return false }
        for key in dictionary.allKeys {
            guard let key = key as? NSString, counts[Array((key as String).utf16)] != nil else { return false }
        }
        // Which of several values under one name JSONSerialization keeps is not specified, so only
        // the values of names that appear once are compared. Redaction treats every one of them.
        for member in members {
            let name = utf16(member.name, in: scalars)
            guard counts[name] == 1 else { continue }
            let key = String(decoding: name, as: UTF16.self) as NSString
            guard let value = dictionary.object(forKey: key), agrees(member.value, with: value, in: scalars) else { return false }
        }
        return true
    }

    private static func utf16(_ token: StringToken, in scalars: [Unicode.Scalar]) -> [UInt16] {
        let text = token.decoded ?? Array(scalars[token.content])
        return Array(String(String.UnicodeScalarView(text)).utf16)
    }
}

extension JSONDocument.Node {
    var isContainer: Bool {
        switch value {
        case .object, .array: true
        default: false
        }
    }
}

// MARK: - Reader

extension JSONDocument {
    /// A recursive descent reader for RFC 8259.
    private struct Reader {
        let scalars: [Unicode.Scalar]
        var position = 0

        init(scalars: [Unicode.Scalar], position: Int = 0) {
            self.scalars = scalars
            self.position = position
        }

        mutating func document() -> Node? {
            skipWhitespace()
            guard let root = value(depth: 0) else { return nil }
            skipWhitespace()
            return position == scalars.count ? root : nil
        }

        /// One value at the current position, with nothing read after it.
        mutating func value() -> Node? {
            value(depth: 0)
        }

        private mutating func value(depth: Int) -> Node? {
            guard depth < JSONDocument.maximumDepth, position < scalars.count else { return nil }
            let start = position
            let value: Value?
            switch scalars[position] {
            case "{": value = object(depth: depth)
            case "[": value = array(depth: depth)
            case "\"": value = string().map(Value.string)
            case "t": value = literal("true") ? .boolean : nil
            case "f": value = literal("false") ? .boolean : nil
            case "n": value = literal("null") ? .null : nil
            default: value = number() ? .number : nil
            }
            return value.map { Node(range: start..<position, value: $0) }
        }

        private mutating func object(depth: Int) -> Value? {
            position += 1
            skipWhitespace()
            var members: [Member] = []
            if consume("}") { return .object(members) }
            repeat {
                skipWhitespace()
                guard position < scalars.count, scalars[position] == "\"", let name = string() else { return nil }
                skipWhitespace()
                guard consume(":") else { return nil }
                skipWhitespace()
                guard let value = value(depth: depth + 1) else { return nil }
                members.append(Member(name: name, value: value))
                skipWhitespace()
            } while consume(",")
            return consume("}") ? .object(members) : nil
        }

        private mutating func array(depth: Int) -> Value? {
            position += 1
            skipWhitespace()
            var elements: [Node] = []
            if consume("]") { return .array(elements) }
            repeat {
                skipWhitespace()
                guard let element = value(depth: depth + 1) else { return nil }
                elements.append(element)
                skipWhitespace()
            } while consume(",")
            return consume("]") ? .array(elements) : nil
        }

        /// A string at a `"`; nil for a control character, an unknown escape or a lone surrogate.
        private mutating func string() -> StringToken? {
            position += 1
            let start = position
            var decoded: [Unicode.Scalar] = []
            var hasEscapes = false
            while position < scalars.count {
                let scalar = scalars[position]
                if scalar == "\"" {
                    position += 1
                    return StringToken(content: start..<(position - 1), decoded: hasEscapes ? decoded : nil)
                }
                guard scalar.value >= 0x20 else { return nil }
                if scalar == "\\" {
                    hasEscapes = true
                    guard let escaped = escape() else { return nil }
                    decoded.append(escaped)
                } else {
                    decoded.append(scalar)
                    position += 1
                }
            }
            return nil
        }

        /// The character a `\` escape stands for; a surrogate pair is one character.
        private mutating func escape() -> Unicode.Scalar? {
            guard position + 1 < scalars.count else { return nil }
            let kind = scalars[position + 1]
            position += 2
            switch kind {
            case "\"", "\\", "/": return kind
            case "b": return "\u{08}"
            case "f": return "\u{0C}"
            case "n": return "\n"
            case "r": return "\r"
            case "t": return "\t"
            case "u": break
            default: return nil
            }
            guard let unit = hexadecimalUnit() else { return nil }
            if (0xDC00...0xDFFF).contains(unit) { return nil }
            guard (0xD800...0xDBFF).contains(unit) else { return Unicode.Scalar(unit) }
            guard position + 1 < scalars.count, scalars[position] == "\\", scalars[position + 1] == "u" else { return nil }
            position += 2
            guard let low = hexadecimalUnit(), (0xDC00...0xDFFF).contains(low) else { return nil }
            return Unicode.Scalar(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
        }

        private mutating func hexadecimalUnit() -> UInt32? {
            guard position + 4 <= scalars.count else { return nil }
            var value: UInt32 = 0
            for scalar in scalars[position..<position + 4] {
                guard let digit = Character(scalar).hexDigitValue, scalar.isASCII else { return nil }
                value = value * 16 + UInt32(digit)
            }
            position += 4
            return value
        }

        /// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`
        private mutating func number() -> Bool {
            _ = consume("-")
            if consume("0") {
                // A leading zero is followed by a fraction, an exponent or nothing.
            } else {
                guard digits() > 0 else { return false }
            }
            if consume(".") { guard digits() > 0 else { return false } }
            if consume("e") || consume("E") {
                _ = consume("+") || consume("-")
                guard digits() > 0 else { return false }
            }
            return true
        }

        private mutating func digits() -> Int {
            let start = position
            while position < scalars.count, ("0"..."9").contains(scalars[position]) { position += 1 }
            return position - start
        }

        private mutating func literal(_ word: String) -> Bool {
            let letters = Array(word.unicodeScalars)
            guard position + letters.count <= scalars.count, Array(scalars[position..<position + letters.count]) == letters else { return false }
            position += letters.count
            return true
        }

        private mutating func consume(_ scalar: Unicode.Scalar) -> Bool {
            guard position < scalars.count, scalars[position] == scalar else { return false }
            position += 1
            return true
        }

        private mutating func skipWhitespace() {
            while position < scalars.count, [" ", "\t", "\n", "\r"].contains(scalars[position]) { position += 1 }
        }
    }
}
