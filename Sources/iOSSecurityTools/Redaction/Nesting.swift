/// How far redaction has gone into documents written inside documents: JSON in a string of JSON,
/// a URL in a query value, JSON in a form field or a multipart part.
///
/// Every reader that can find another document in what it reads takes the nesting of that text
/// and passes a deeper one on, so a single budget bounds the whole descent, whatever mix of
/// documents makes it up. Each JSON reader used to have a limit of its own, 256 levels, and a few
/// kilobytes of JSON quoted inside JSON six times overflowed a 512 KiB thread stack.
///
/// The documents found inside the input also share one ``ReadingBudget``: each level reads what
/// the level around it holds once more, so without it a megabyte of JSON quoted in JSON three
/// times took a release build more than a second.
///
/// A text that reaches a limit while it is inside a document is hidden whole: what it holds
/// cannot be read within the budget.
struct Nesting {
    /// The most JSON objects and arrays open at once, counted across every document a text is in.
    static let maximumDepth = 64

    /// The most documents one inside another: a JSON body is one, JSON in one of its strings two.
    static let maximumLevel = 4

    /// Free text that is not inside any document, as ``SensitiveDataRedactor/redact(_:)`` reads
    /// it, `length` scalars long.
    static func text(length: Int) -> Nesting {
        Nesting(depth: 0, level: 0, inputLevel: 0, budget: ReadingBudget(inputLength: length))
    }

    /// A document passed in on its own, a body or a URL, of `length` scalars.
    static func document(length: Int) -> Nesting {
        Nesting(depth: 0, level: 1, inputLevel: 1, budget: ReadingBudget(inputLength: length))
    }

    /// The JSON objects and arrays open around the text being read.
    let depth: Int

    /// The documents the text being read is in.
    let level: Int

    /// The level of the input itself: what is read at a deeper level is in a document found in it.
    private let inputLevel: Int

    /// What the documents found in the input may still read.
    private let budget: ReadingBudget

    /// Whether the text being read is inside a document, so that it is hidden whole when a
    /// document in it goes past a limit.
    var isEmbedded: Bool { level > 0 }

    /// How many objects and arrays a document that starts here may open one inside another.
    var depthLeft: Int { Self.maximumDepth - depth }

    /// The nesting inside a document that starts in the text being read; nil when that document
    /// would be one level too many.
    func enteringDocument() -> Nesting? {
        guard level < Self.maximumLevel else { return nil }
        return Nesting(depth: depth, level: level + 1, inputLevel: inputLevel, budget: budget)
    }

    /// The nesting inside one more JSON object or array of the same document.
    func enteringContainer() -> Nesting {
        Nesting(depth: depth + 1, level: level, inputLevel: inputLevel, budget: budget)
    }

    /// The most scalars that a text at this nesting may still read; unlimited in the input itself.
    var lengthLeft: Int { level > inputLevel ? budget.left : Int.max }

    /// Takes the reading of `length` scalars at this nesting from the budget, when it is in a
    /// document found in the input. Returns false, taking nothing, when the budget does not
    /// cover it: the text is then hidden whole.
    func reads(_ length: Int) -> Bool {
        level <= inputLevel || budget.spend(length)
    }
}

/// The reading that the documents found inside one input may do together: four times the
/// input's length, in Unicode scalars.
///
/// Each document found in the input (JSON in a line or in a string, a URL in text, a multipart
/// part) takes its length when it is read, and so does every text read inside it as free text:
/// a JSON string, a query value, a part's text. Text that the budget does not cover is hidden
/// whole, so the work of one redaction stays a fixed multiple of its input, however the input
/// nests documents.
final class ReadingBudget {
    /// How many times its own length the documents inside an input may read.
    static let inputMultiple = 4

    private(set) var left: Int

    init(inputLength: Int) {
        let (budget, overflow) = inputLength.multipliedReportingOverflow(by: Self.inputMultiple)
        left = overflow ? Int.max : budget
    }

    /// Takes `length` from what is left, or nothing when less is left.
    func spend(_ length: Int) -> Bool {
        guard length <= left else { return false }
        left -= length
        return true
    }
}
