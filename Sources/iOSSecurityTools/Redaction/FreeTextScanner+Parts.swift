/// Multipart bodies written into text, as a log writes a request: a part whose header writes a
/// secret name (`Content-Disposition: form-data; name="pin"`) holds the secret in its value, which
/// comes after the part's other headers and a blank line, and may take more than one line.
extension FreeTextScanner {
    /// Where a multipart part whose header wrote a secret name is read.
    enum PartState {
        /// Its header lines, up to a blank line.
        case headers
        /// The first line of its value, after the blank line.
        case valueStart
        /// The rest of its value.
        case value
    }

    /// The longest delimiter line: `--`, a boundary of up to 70 characters (RFC 2046) and `--`.
    static let maximumDelimiterLength = 74

    private static let dash = UInt8(ascii: "-")
    private static let contentDisposition = Array("content-disposition".utf8)
    private static let formData = Array("form-data".utf8)

    /// Notes the line from byte `lineStart` to `lineEnd` as the multipart delimiter when it may be
    /// one: `--` and more, without white space, at most ``maximumDelimiterLength`` long.
    mutating func noteDelimiter(from lineStart: Int, to lineEnd: Int) {
        let start = firstNonSpace(from: lineStart, to: lineEnd)
        guard start + 2 < lineEnd, text.bytes[start] == Self.dash, text.bytes[start + 1] == Self.dash else { return }
        let end = trimmedEnd(from: start, lineEnd: lineEnd)
        guard end - start <= Self.maximumDelimiterLength, !(start..<end).contains(where: { text.isSpace($0) }) else { return }
        multipartDelimiter = Array(text.bytes[start..<end])
    }

    /// Whether a secret name at byte `nameStart` is written in a header of a multipart part: after
    /// `Content-Disposition` or `form-data` on its line, in any case.
    func isPartHeader(nameStart: Int) -> Bool {
        holds(Self.contentDisposition, from: lineStartOfText, to: nameStart) || holds(Self.formData, from: lineStartOfText, to: nameStart)
    }

    /// Whether bytes `start..<end` hold `word`, in any case.
    private func holds(_ word: [UInt8], from start: Int, to end: Int) -> Bool {
        guard end - start >= word.count else { return false }
        return (start...(end - word.count)).contains { k in
            word.indices.allSatisfy { ASCII.lowercased(text.bytes[k + $0]) == word[$0] }
        }
    }

    /// A line of a multipart part whose header wrote a secret name (see
    /// ``Carry/part(delimiter:state:)``). The part's header lines are hidden up to the blank line
    /// after them, and then its value, up to the line of the delimiter written before the header,
    /// which is read again; a line that is not a header (`Name: value`) starts the value. When no
    /// delimiter was written before the header, the value ends at a blank line or at a line that
    /// starts with `--` (`--boundary--`), after its first line, which is hidden whatever it is
    /// (`-----BEGIN PRIVATE KEY-----`). Returns whether the rest of the line is scanned.
    mutating func continuePart(delimiter: [UInt8]?, state: PartState, lineStart: Int, lineEnd: Int) -> Bool {
        let textStart = firstNonSpace(from: lineStart, to: lineEnd)
        guard textStart < lineEnd else {
            if state == .headers {
                carry = .part(delimiter: delimiter, state: .valueStart)
            } else if state == .value, delimiter == nil {
                carry = .none
            }
            return false
        }
        let line = textStart..<trimmedEnd(from: textStart, lineEnd: lineEnd)
        let endsPart = delimiter.map { isDelimiter(line, $0) } ?? (state != .valueStart && startsWithDashes(line))
        if endsPart {
            carry = .none
            return true
        }
        hide(fromByte: textStart, toLineEnd: lineEnd)
        if state != .headers || !isHeaderLine(line) { carry = .part(delimiter: delimiter, state: .value) }
        return false
    }

    /// The byte after the last character of the line that is not white space.
    private func trimmedEnd(from start: Int, lineEnd: Int) -> Int {
        var end = lineEnd
        while end > start, text.isSpace(end - 1) { end -= 1 }
        return end
    }

    /// Whether the line is the delimiter, or the delimiter that closes the body (`--boundary--`).
    private func isDelimiter(_ line: Range<Int>, _ delimiter: [UInt8]) -> Bool {
        let bytes = text.bytes[line]
        if bytes.elementsEqual(delimiter) { return true }
        let (longer, shorter) = bytes.count > delimiter.count ? (Array(bytes), delimiter) : (delimiter, Array(bytes))
        return longer.count == shorter.count + 2 && longer.starts(with: shorter) && longer.suffix(2).allSatisfy { $0 == Self.dash }
    }

    private func startsWithDashes(_ line: Range<Int>) -> Bool {
        line.count >= 2 && text.bytes[line.lowerBound] == Self.dash && text.bytes[line.lowerBound + 1] == Self.dash
    }

    /// Whether the line is a header, `Name: value`, with a name of letters, digits and `-`.
    private func isHeaderLine(_ line: Range<Int>) -> Bool {
        var k = line.lowerBound
        while k < line.upperBound, ASCII.isAlphanumeric(text.bytes[k]) || text.bytes[k] == Self.dash { k += 1 }
        guard k > line.lowerBound else { return false }
        k = firstNonSpace(from: k, to: line.upperBound)
        return k < line.upperBound && text.bytes[k] == UInt8(ascii: ":")
    }
}
