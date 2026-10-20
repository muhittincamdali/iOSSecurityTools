/// How far redaction has gone into documents written inside documents: JSON in a string of JSON,
/// a URL in a query value, JSON in a form field or a multipart part.
///
/// Every reader that can find another document in what it reads takes the nesting of that text
/// and passes a deeper one on, so a single budget bounds the whole descent, whatever mix of
/// documents makes it up. Each JSON reader used to have a limit of its own, 256 levels, and a few
/// kilobytes of JSON quoted inside JSON six times overflowed a 512 KiB thread stack.
///
/// A text that reaches a limit while it is inside a document is hidden whole: what it holds
/// cannot be read within the budget.
struct Nesting {
    /// The most JSON objects and arrays open at once, counted across every document a text is in.
    static let maximumDepth = 64

    /// The most documents one inside another: a JSON body is one, JSON in one of its strings two.
    static let maximumLevel = 4

    /// Free text that is not inside any document, as ``SensitiveDataRedactor/redact(_:)`` reads it.
    static let text = Nesting(depth: 0, level: 0)

    /// A document passed in on its own: a body or a URL.
    static let document = Nesting(depth: 0, level: 1)

    /// The JSON objects and arrays open around the text being read.
    let depth: Int

    /// The documents the text being read is in.
    let level: Int

    /// Whether the text being read is inside a document, so that it is hidden whole when a
    /// document in it goes past a limit.
    var isEmbedded: Bool { level > 0 }

    /// How many objects and arrays a document that starts here may open one inside another.
    var depthLeft: Int { Self.maximumDepth - depth }

    /// The nesting inside a document that starts in the text being read; nil when that document
    /// would be one level too many.
    func enteringDocument() -> Nesting? {
        guard level < Self.maximumLevel else { return nil }
        return Nesting(depth: depth, level: level + 1)
    }

    /// The nesting inside one more JSON object or array of the same document.
    func enteringContainer() -> Nesting {
        Nesting(depth: depth + 1, level: level)
    }
}
