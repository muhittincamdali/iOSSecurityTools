extension FreeTextFields {
    // MARK: HTML character references

    /// Where the character reference that starts at the `&` at `start` ends, after its `;`:
    /// `&#97;`, `&#x61;` or `&amp;`.
    func entityEnd(startingAt start: Int) -> Int? {
        var j = start + 1
        guard j < upper else { return nil }
        if scalars[j] == "#" {
            j += 1
            let isHexadecimal = j < upper && (scalars[j] == "x" || scalars[j] == "X")
            if isHexadecimal { j += 1 }
            let digitsStart = j
            while j < upper, j - digitsStart < 7, Self.isDigit(scalars[j], hexadecimal: isHexadecimal) { j += 1 }
            guard j > digitsStart else { return nil }
        } else {
            let nameStart = j
            while j < upper, j - nameStart < 32, scalars[j].isASCII, ASCII.isAlphanumeric(UInt8(scalars[j].value)) { j += 1 }
            guard j > nameStart, ASCII.isLetter(UInt8(scalars[nameStart].value)) else { return nil }
        }
        return j < upper && scalars[j] == ";" ? j + 1 : nil
    }

    /// Where the character reference that ends with the `;` at `end` starts.
    func entityStart(endingAt end: Int) -> Int? {
        var j = end - 1
        while j >= bounds.lowerBound, end - j <= 34, scalars[j] != "&" {
            guard scalars[j].isASCII, ASCII.isAlphanumeric(UInt8(scalars[j].value)) || scalars[j] == "#" else { return nil }
            j -= 1
        }
        guard j >= bounds.lowerBound, scalars[j] == "&", entityEnd(startingAt: j) == end + 1 else { return nil }
        return j
    }

    private static func isDigit(_ scalar: Unicode.Scalar, hexadecimal: Bool) -> Bool {
        guard scalar.isASCII else { return false }
        let byte = UInt8(scalar.value)
        return ASCII.isDigit(byte) || (hexadecimal && (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte | 0x20))
    }

    // MARK: XML elements

    /// The content of elements whose name hides a value, `<password>…</password>`, also with
    /// attributes or a namespace prefix (`<wsse:Password Type="…">`): up to the next `<`, or to
    /// the end of the line when no `<` follows.
    func elementSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = bounds.lowerBound
        while i < upper {
            guard scalars[i] == "<" else {
                i += 1
                continue
            }
            var nameEnd = i + 1
            while nameEnd < upper, isElementNameCharacter(scalars[nameEnd]) { nameEnd += 1 }
            let name = (i + 1)..<nameEnd
            guard !name.isEmpty, scalars[i + 1] != "!", scalars[i + 1] != "?", elementHidesContent(name),
                  let contentStart = indexAfterStartTag(from: nameEnd),
                  let content = elementContent(from: contentStart)
            else {
                i = max(nameEnd, i + 1)
                continue
            }
            spans.append(SensitiveDataRedactor.Span(
                start: content.lowerBound, end: content.upperBound, kind: .secretFields, replacement: SensitiveDataRedactor.replacement
            ))
            i = content.upperBound
        }
        return spans
    }

    private func isElementNameCharacter(_ scalar: Unicode.Scalar) -> Bool {
        !scalar.properties.isWhitespace && !"<>/=\"'".unicodeScalars.contains(scalar)
    }

    /// A name with a namespace prefix is judged by its local part; the prefix has to be plain.
    /// Text such as `<NSHTTPURLResponse: 0x600>`, where a part is empty or there are several
    /// `:`, is not an element.
    private func elementHidesContent(_ name: Range<Int>) -> Bool {
        let parts = scalars[name].split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count <= 2, parts.allSatisfy({ !$0.isEmpty }) else { return false }
        if parts.count == 2, PlainName(parts[0]) == nil { return true }
        return FieldName.hidesValue(parts[parts.count - 1])
    }

    /// Where the content starts after the rest of a start tag at `i`: a `>` right away, or
    /// whitespace, attributes and then `>`. Nil for an empty tag (`<password/>`) and for a tag
    /// that a `<` or the end of the text cuts short; a `>` inside a quoted attribute value does
    /// not end the tag.
    private func indexAfterStartTag(from i: Int) -> Int? {
        guard i < upper else { return nil }
        if scalars[i] == ">" { return i + 1 }
        guard scalars[i].properties.isWhitespace else { return nil }
        var quote: Unicode.Scalar?
        for j in i..<upper {
            let scalar = scalars[j]
            if scalar == "<" { return nil }
            if let open = quote {
                if scalar == open { quote = nil }
            } else if Self.isQuote(scalar) {
                quote = scalar
            } else if scalar == ">" {
                return scalars[j - 1] == "/" ? nil : j + 1
            }
        }
        return nil
    }

    private func elementContent(from start: Int) -> Range<Int>? {
        var end = start
        var lineEnd: Int?
        while end < upper, scalars[end] != "<" {
            if lineEnd == nil, Self.isLineBreak(scalars[end]) { lineEnd = end }
            end += 1
        }
        if end == upper, let lineEnd { end = lineEnd }
        return end > start ? start..<end : nil
    }
}
