import Foundation

/// A `multipart/form-data` body, read as RFC 7578 and RFC 2046 describe it.
///
/// The reader accepts only what servers agree on. Every `--boundary` in the body, compared without
/// case, has to be a delimiter line of its own after a CRLF: PHP and Werkzeug also split a part at
/// one after a bare LF, Werkzeug at one after a bare CR, and a reader that missed such a split
/// would take the next part's name and value for text. The reader also rejects text before the
/// first boundary or after the closing one, a boundary line that goes on (`--boundaryX`,
/// `--boundary ` before the CRLF), part headers that are not UTF-8, end their lines with a bare LF
/// or CR or continue on a folded line, a header name that is not a token, more than one
/// `Content-Disposition` or `Content-Type` in a part, a disposition other than `form-data`, a
/// missing or repeated `name`, `name*` and `filename*` parameters, and more than
/// ``maximumPartCount`` parts.
struct MultipartBody {
    struct Part {
        /// The header fields in order, names as sent.
        let headers: [(name: String, value: String)]
        let name: String
        let filename: String?
        let contentType: MediaType?
        let content: ArraySlice<UInt8>
    }

    static let maximumPartCount = 1_000

    let parts: [Part]

    init?(_ bytes: [UInt8], boundary: String) {
        let delimiter = Array("--\(boundary)".utf8)
        let lineBreak: [UInt8] = [13, 10]
        // Every match is a delimiter or the body is rejected, so no server finds a part this
        // reader did not.
        let starts = Self.occurrences(of: delimiter, in: bytes)
        guard let last = starts.last, starts[0] == 0, starts.count - 1 <= Self.maximumPartCount else { return nil }
        var parts: [Part] = []
        for (start, next) in zip(starts, starts.dropFirst()) {
            let partStart = start + delimiter.count + 2
            guard bytes[(start + delimiter.count)...].starts(with: lineBreak), next - 2 >= partStart,
                  bytes[(next - 2)..<next].elementsEqual(lineBreak),
                  let part = Self.part(bytes, partStart..<(next - 2))
            else { return nil }
            parts.append(part)
        }
        let closing = bytes[(last + delimiter.count)...]
        guard closing.starts(with: [45, 45]), closing.dropFirst(2).isEmpty || closing.dropFirst(2).elementsEqual(lineBreak),
              starts.allSatisfy({ bytes[$0..<($0 + delimiter.count)].elementsEqual(delimiter) })
        else { return nil }
        self.parts = parts
    }

    /// Whether a boundary is 1 to 70 of the characters RFC 2046 allows, not ending in a space.
    static func isValidBoundary(_ boundary: String) -> Bool {
        let allowed = "'()+_,-./:=? ".unicodeScalars
        let scalars = boundary.unicodeScalars
        return (1...70).contains(scalars.count) && scalars.last != " "
            && scalars.allSatisfy { $0.isASCII && (ASCII.isAlphanumeric(UInt8($0.value)) || allowed.contains($0)) }
    }

    private static func part(_ bytes: [UInt8], _ range: Range<Int>) -> Part? {
        let lineBreak: [UInt8] = [13, 10]
        let headerEnd: Int
        let contentStart: Int
        if bytes[range].starts(with: lineBreak) {
            headerEnd = range.lowerBound
            contentStart = range.lowerBound + 2
        } else {
            guard let end = firstIndex(of: lineBreak + lineBreak, in: bytes, range: range) else { return nil }
            headerEnd = end
            contentStart = end + 4
        }
        guard let headers = String(bytes: bytes[range.lowerBound..<headerEnd], encoding: .utf8) else { return nil }
        var disposition: String?
        var contentType: String?
        var fields: [(name: String, value: String)] = []
        for line in headers.isEmpty ? [] : headers.components(separatedBy: "\r\n") {
            guard let field = headerField(line) else { return nil }
            fields.append(field)
            switch field.name.lowercased() {
            case "content-disposition":
                guard disposition == nil else { return nil }
                disposition = field.value
            case "content-type":
                guard contentType == nil else { return nil }
                contentType = field.value
            default:
                break
            }
        }
        guard let disposition, let (name, filename) = formDataNames(disposition) else { return nil }
        let mediaType = contentType.map(MediaType.init)
        if case .some(.none) = mediaType { return nil }
        return Part(headers: fields, name: name, filename: filename, contentType: mediaType ?? nil, content: bytes[contentStart..<range.upperBound])
    }

    /// `name: value` on one line; nil for a folded line, a bare CR or LF or a name that is not a token.
    /// The colon is found among the scalars, since `:` followed by a mark is one `Character`.
    private static func headerField(_ line: String) -> (name: String, value: String)? {
        let scalars = line.unicodeScalars
        guard let first = scalars.first, first != " ", first != "\t",
              !scalars.contains(where: { $0 == "\r" || $0 == "\n" }),
              let colon = scalars.firstIndex(of: ":")
        else { return nil }
        let name = scalars[..<colon]
        guard name.allSatisfy(HeaderValueReader.isTokenCharacter) else { return nil }
        return (String(Substring(name)), String(Substring(scalars[scalars.index(after: colon)...])))
    }

    /// The `name` and `filename` of a `form-data` disposition.
    private static func formDataNames(_ disposition: String) -> (name: String, filename: String?)? {
        var reader = HeaderValueReader(Array(disposition.unicodeScalars))
        reader.skipWhitespace()
        guard reader.token()?.lowercased() == "form-data", let parameters = reader.parameters() else { return nil }
        let names = parameters.filter { $0.name == "name" }.map(\.value)
        let filenames = parameters.filter { $0.name == "filename" }.map(\.value)
        guard names.count == 1, filenames.count <= 1,
              !parameters.contains(where: { $0.name == "name*" || $0.name == "filename*" })
        else { return nil }
        return (names[0], filenames.first)
    }

    private static func firstIndex(of needle: [UInt8], in bytes: [UInt8], range: Range<Int>) -> Int? {
        var i = range.lowerBound
        while i + needle.count <= range.upperBound {
            if bytes[i] == needle[0], bytes[i..<(i + needle.count)].elementsEqual(needle) { return i }
            i += 1
        }
        return nil
    }

    /// Where the needle starts in the bytes, overlapping matches included, with ASCII letters
    /// compared without case; in time linear in the length of both (Knuth–Morris–Pratt).
    static func occurrences(of needle: [UInt8], in bytes: [UInt8]) -> [Int] {
        let pattern = needle.map(ASCII.lowercased)
        guard !pattern.isEmpty else { return [] }
        var border = [0]
        var length = 0
        for byte in pattern.dropFirst() {
            while length > 0, byte != pattern[length] { length = border[length - 1] }
            if byte == pattern[length] { length += 1 }
            border.append(length)
        }
        var starts: [Int] = []
        length = 0
        for (i, byte) in bytes.enumerated() {
            let lowered = ASCII.lowercased(byte)
            while length > 0, lowered != pattern[length] { length = border[length - 1] }
            if lowered == pattern[length] { length += 1 }
            if length == pattern.count {
                starts.append(i + 1 - length)
                length = border[length - 1]
            }
        }
        return starts
    }
}
