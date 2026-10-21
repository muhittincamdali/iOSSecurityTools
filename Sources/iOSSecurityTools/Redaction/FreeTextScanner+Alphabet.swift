/// The characters free text may hold before it is cut, and the escapes and words that cut it.
///
/// Free text is read only as far as it is written in a safe alphabet: letters, marks and digits of
/// any script (the general categories L*, M* and N*), the ASCII space, tab, line feed and carriage
/// return, and the printable ASCII punctuation. The first character outside it cuts the text:
/// punctuation, a symbol or a space outside ASCII (`꞉`, `≔`, `→`, `·`, `＝`, an emoji, U+00A0), a
/// control character, a format character and any default-ignorable code point. No list of
/// look-alike separators is kept; a character is judged by its Unicode category alone. A modifier
/// letter (`ː`, `ー`) belongs to the safe alphabet only after a letter or digit outside ASCII, as in
/// Japanese or Thai: after ASCII it can stand for a colon.
///
/// An escape is never decoded in free text: it cuts the text at the start of the word it is in, as
/// what the escape stands for cannot be read, nor what the value detectors would find through it
/// (`alice%40example.com`). A backslash is an escape whatever follows it, unless an ASCII space,
/// tab or line break or the end of the text does, so no list of the forms of backslash escapes is
/// kept. A word longer than ``FreeTextScanner/longestWord`` cuts the text too: it cannot be read
/// as a name, and so no word is copied for reading at more than that length.
extension FreeTextScanner {
    /// The longest word of free text that is read, in scalars: a longer one cuts the text at its
    /// start.
    static let longestWord = 256

    /// The offset of the first scalar of the text outside the safe alphabet, or nil. The scanning
    /// copy finds the same offset while it is made (``NormalizedText/firstUnsafeOffset``), which
    /// the scan uses.
    static func firstUnsafeOffset(in scalars: [Unicode.Scalar]) -> Int? {
        var alphabet = SafeAlphabetReader()
        for (offset, scalar) in scalars.enumerated() {
            if scalar.isASCII {
                alphabet.read(ascii: UInt8(scalar.value), at: offset)
            } else {
                alphabet.read(SafeAlphabet.class(of: scalar), at: offset)
            }
            if let unsafe = alphabet.firstUnsafe { return unsafe }
        }
        return nil
    }

    /// Whether an escape starts at byte `i`: an escape that can stand for any character, which free
    /// text never decodes.
    ///
    /// - `%` and two hex digits, or `%u` and four (`%3D`, `%u003D`);
    /// - `&#` and a digit, `&#x` and a hex digit (`&#61;`, `&#x3d`), and `&` with a name made of
    ///   letters and digits, as HTML5 names its references, with or without the `;` (`&colon;`,
    ///   `&equals;`, `&amp;`) — but not the name of a field before `=` (`&count=3`);
    /// - `\` before anything but an ASCII space, tab or line break or the end of the text (see
    ///   ``backslashEscapes(at:)``).
    func isEscape(at i: Int) -> Bool {
        switch text.bytes[i] {
        case UInt8(ascii: "%"):
            if isHex(i + 1), isHex(i + 2) { return true }
            return byte(i + 1) | 0x20 == UInt8(ascii: "u") && (2...5).allSatisfy { isHex(i + $0) }
        case UInt8(ascii: "&"):
            if byte(i + 1) == UInt8(ascii: "#") {
                return ASCII.isDigit(byte(i + 2)) || (byte(i + 2) | 0x20 == UInt8(ascii: "x") && isHex(i + 3))
            }
            guard ASCII.isLetter(byte(i + 1)) else { return false }
            var k = i + 1
            while k < text.count, ASCII.isNameCharacter(text.bytes[k]), text.bytes[k] != UInt8(ascii: " ") { k += 1 }
            return byte(k) != UInt8(ascii: "=")
        case UInt8(ascii: "\\"):
            return backslashEscapes(at: i)
        default:
            return false
        }
    }

    /// Whether the backslash at byte `i` starts an escape: it does unless an ASCII space, tab or
    /// line break comes right after it in the original text, or the text ends there. What follows
    /// it is not read as any form of escape, so every form counts, known or not: `\075`, `\x3D`,
    /// `\x{73}`, `\o{163}`, `\N{…}`, `\u{73}`, `\q`, `\\`, `\"`. A mark or an invisible character
    /// right after it, which the scanning copy leaves out, counts as what it escapes.
    func backslashEscapes(at i: Int) -> Bool {
        if i + 1 < text.count, !Self.blanksAfterBackslash.contains(text.bytes[i + 1]) { return true }
        // The scanning copy left out what came right after the backslash, or read it as a space
        // (U+3000): the original scalar decides.
        let next = text.offset(at: i) + 1
        return next < source.count && !(source[next].isASCII && Self.blanksAfterBackslash.contains(UInt8(source[next].value)))
    }

    /// What a backslash can come before without starting an escape: an ASCII space, tab or line
    /// break.
    private static let blanksAfterBackslash = ByteSet(" \t\n\r")

    /// The byte at `i`, or 0 past the end of the text.
    private func byte(_ i: Int) -> UInt8 {
        i < text.count ? text.bytes[i] : 0
    }

    private func isHex(_ i: Int) -> Bool {
        let value = byte(i)
        return ASCII.isDigit(value) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(value | 0x20)
    }

    /// Whether the word in the bytes `range` is longer than ``longestWord`` scalars.
    func isOpaque(_ range: Range<Int>) -> Bool {
        text.offset(at: range.upperBound) - text.offset(at: range.lowerBound) > Self.longestWord
    }
}

/// The safe alphabet of free text, scalar by scalar.
enum SafeAlphabet {
    /// What the safe alphabet makes of a scalar outside ASCII.
    enum Class {
        /// A letter or digit, which a modifier letter may follow.
        case letter
        /// A mark, which belongs to the scalar before it.
        case mark
        /// A modifier letter: in the alphabet only after a letter or digit outside ASCII.
        case modifierLetter
        /// Outside the alphabet.
        case unsafe
    }

    static func `class`(of scalar: Unicode.Scalar) -> Class {
        let properties = scalar.properties
        guard !properties.isDefaultIgnorableCodePoint else { return .unsafe }
        switch properties.generalCategory {
        case .nonspacingMark, .spacingMark, .enclosingMark: return .mark
        case .modifierLetter: return .modifierLetter
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .otherLetter, .decimalNumber, .letterNumber, .otherNumber: return .letter
        default: return .unsafe
        }
    }
}

/// Reads scalars in order and keeps the offset of the first one outside the safe alphabet.
struct SafeAlphabetReader {
    private(set) var firstUnsafe: Int?
    /// Whether the last scalar that is not a mark is a letter or digit outside ASCII.
    private var followsNonASCIILetter = false

    /// Printable ASCII, tab, line feed and carriage return are in the alphabet.
    mutating func read(ascii byte: UInt8, at offset: Int) {
        guard firstUnsafe == nil else { return }
        followsNonASCIILetter = false
        if !(0x20...0x7E).contains(byte), byte != 0x09, byte != 0x0A, byte != 0x0D { firstUnsafe = offset }
    }

    mutating func read(_ class: SafeAlphabet.Class, at offset: Int) {
        guard firstUnsafe == nil else { return }
        switch `class` {
        case .letter: followsNonASCIILetter = true
        case .mark: break
        case .modifierLetter: if !followsNonASCIILetter { firstUnsafe = offset }
        case .unsafe: firstUnsafe = offset
        }
    }
}
