/// Secret names written in text that the hiding pass hid without reading it: a second pass over
/// each line, so that a name written as a value names what follows it wherever it is written, also
/// inside the value of another key (`Content-Disposition: form-data; name="pin"`).
extension FreeTextScanner {
    /// How the text is read.
    enum Pass {
        /// Values are hidden, and what each line leaves open is carried to the next.
        case hiding
        /// Text that the hiding pass hid without reading it (the rest of a line after a key, a
        /// line below a value) is read for the secret names written in it: only what such a name
        /// hides on its line and leaves open below it is kept. Values are not hidden again, and
        /// JSON and URLs are passed over, as their parsers read them.
        case triggers
        /// As ``triggers``, up to the first secret name: whether the text of a value holds one.
        case detection
    }

    /// The secret names on one line that the trigger pass follows one by one. Each is read to the
    /// end of the line, so a line of many names would take time quadratic in its length; after
    /// these, only the last name on the line is followed, and the next line with text is hidden.
    static let maximumNamesFollowed = 16

    /// The trigger pass over the line that ends at byte `lineEnd`, from the first byte the hiding
    /// pass hid without reading (see ``unreadFrom``). The secret names found there hide the rest
    /// of the line after them, and what they leave open is joined with what the hiding pass left
    /// open, before the next line is read.
    mutating func readHiddenText(lineEnd: Int) {
        guard let start = unreadFrom else { return }
        unreadFrom = nil
        guard start < lineEnd else { return }
        var reader = reader(for: .triggers, at: start)
        reader.scan(to: lineEnd)
        if let last = reader.lastNameNotFollowed {
            let markup = reader.markupReader(before: last.nameStart)
            reader.followName(at: last.nameStart, from: last.start, valueStart: last.valueStart, lineEnd: lineEnd, markup: markup)
            reader.setCarry(.valueOnNextLine(indent: lineIndent))
        }
        absorb(reader)
    }

    /// Whether the text of a value, bytes `range` of the line, writes a secret name that names
    /// what follows it, as the trigger pass reads names: `name=\"pin\"`, `label=Şifre`,
    /// `<key>token</key>`.
    func holdsSecretName(in range: Range<Int>) -> Bool {
        guard !range.isEmpty else { return false }
        var reader = reader(for: .detection, at: range.lowerBound)
        reader.scan(to: range.upperBound)
        return reader.foundName
    }

    /// The markup of the line up to byte `nameStart`, read on from where the last name on the
    /// line was, so the names of one line read it once.
    mutating func markupReader(before nameStart: Int) -> MarkupReader {
        guard let read = lineMarkup, read.end <= nameStart else {
            let reader = MarkupReader(text, line: lineStartOfText..<nameStart, nameStart: nameStart)
            lineMarkup = (reader, nameStart)
            return reader
        }
        var reader = read.reader
        _ = reader.read(text, read.end..<nameStart)
        lineMarkup = (reader, nameStart)
        return reader
    }

    // MARK: JSON

    /// JSON after a key, read by the trigger pass. After a key that holds a name it cannot be
    /// read as a name, so it names what follows it: the rest of the line where its brackets close,
    /// and the lines up to there (see ``Carry/brackets(depth:indent:)``). What it holds is not
    /// read: its parser reads JSON.
    mutating func readJSONValue(from start: Int, key: [Unicode.Scalar]?, lineEnd: Int) {
        let (close, depth) = bracketsEnd(from: start, to: lineEnd)
        position = close ?? lineEnd
        guard let key, WrittenName.holdsNameInText(key) else { return }
        if let close {
            hideAfterName(at: start, from: close, valueStart: close, lineEnd: lineEnd)
        } else {
            hideAfterName(at: start, from: lineEnd, valueStart: lineEnd, lineEnd: lineEnd)
            if pass == .triggers { setCarry(.brackets(depth: depth, indent: lineIndent)) }
        }
        position = max(position, close ?? lineEnd)
    }

    /// The byte after the bracket that closes the brackets open at `start`, `depth` of them
    /// opened before it, counting brackets outside double-quoted strings up to byte `limit`; or
    /// nil and the depth at `limit`. A string ends at its closing quote or at `limit`.
    func bracketsEnd(from start: Int, to limit: Int, depth: Int = 0) -> (close: Int?, depth: Int) {
        var depth = depth
        var inString = false
        var k = start
        while k < limit {
            let byte = text.bytes[k]
            if inString {
                if byte == UInt8(ascii: "\""), !isEscaped(k) { inString = false }
            } else if byte == UInt8(ascii: "\"") {
                inString = true
            } else if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") {
                depth += 1
            } else if byte == UInt8(ascii: "}") || byte == UInt8(ascii: "]") {
                depth -= 1
                if depth <= 0 { return (k + 1, 0) }
            }
            k += 1
        }
        return (nil, depth)
    }

    /// A line of JSON that a name held (see ``Carry/brackets(depth:indent:)``): hidden whole;
    /// where the brackets close, what follows them on the line is read like the value after a
    /// name, and may go on below. Returns whether the rest of the line is scanned.
    mutating func continueBrackets(depth: Int, indent: Int, lineStart: Int, lineEnd: Int) -> Bool {
        hide(fromByte: lineStart, toLineEnd: lineEnd)
        let (close, left) = bracketsEnd(from: lineStart, to: lineEnd, depth: depth)
        guard let close else {
            carry = .brackets(depth: left, indent: indent)
            return false
        }
        carry = carryAfterHiding(from: close, valueStart: close, lineEnd: lineEnd, indent: indent)
        return false
    }
}

extension FreeTextScanner.Carry {
    /// What two carries leave open together, as one carry. Markup is followed with the other as
    /// its fallback. An open quote and JSON over lines hide every line until they end, and so the
    /// next line with text, which goes before the lines indented more; when both carries are such,
    /// the first goes on as it is, so a name found in the trigger pass never ends what the hiding
    /// pass carries.
    func joined(with other: Self) -> Self {
        switch (self, other) {
        case (.none, _): return other
        case (_, .none): return self
        case let (.markup(element, indent, fallback), _):
            return .markup(element, indent: indent, fallback: fallback.joined(with: other))
        case let (_, .markup(element, indent, fallback)):
            return .markup(element, indent: indent, fallback: joined(with: fallback))
        case let (.continuation(a, x), .continuation(b, y)):
            return .continuation(indent: min(a, b), backslash: x || y)
        case let (.valueOnNextLine(a), .valueOnNextLine(b)), let (.valueOnNextLine(a), .continuation(b, _)),
             let (.continuation(a, _), .valueOnNextLine(b)):
            return .valueOnNextLine(indent: min(a, b))
        case (.continuation, _), (.valueOnNextLine, _):
            return other
        default:
            return self
        }
    }
}
