import Foundation

/// Masks for showing part of a sensitive value, such as "•••• 4242" for a card.
///
/// Every mask has a fixed length, so the output does not tell how long the value is, and a value
/// too short to hide most of it is masked completely: the last four characters of a five-digit
/// PIN would give away almost all of it.
///
/// ```swift
/// Mask.cardNumber("4242 4242 4242 4242")   // "•••• 4242"
/// Mask.email("alice@example.com")          // "a•••@example.com"
/// Mask.trailing("DE89370400440532013000")  // "•••• 3000"
/// Mask.trailing("1234")                    // "••••"
/// ```
public enum Mask {
    /// The text that stands for the hidden part.
    public static let hidden = "••••"

    /// Masks a card number, keeping the last four digits.
    ///
    /// Digits from any script are recognized and shown as ASCII digits; spaces, hyphens and other
    /// characters are dropped. Fewer than 12 digits are masked completely.
    public static func cardNumber(_ text: String) -> String {
        let digits = text.unicodeScalars.compactMap(ScalarClass.decimalDigit)
        guard digits.count >= 12 else { return hidden }
        return hidden + " " + String(digits.suffix(4).map { Character(Unicode.Scalar(UInt8(ascii: "0") + $0)) })
    }

    /// Masks the part of an email address before the `@`, keeping the domain.
    ///
    /// The first character of the name is kept when the name has at least three characters.
    /// Text that is not a single address — no `@`, no dot in the domain, whitespace or control
    /// characters — is masked completely.
    public static func email(_ text: String) -> String {
        guard let at = text.lastIndex(of: "@") else { return hidden }
        let name = text[..<at]
        let domain = text[text.index(after: at)...]
        let isAddress = !name.isEmpty
            && domain.contains(".")
            && !domain.hasPrefix(".") && !domain.hasSuffix(".")
            && !text.unicodeScalars.contains { $0 == " " || ScalarClass.isUnsafeToShow($0) }
            && !name.contains("@")
        guard isAddress else { return hidden }
        let visible = name.count >= 3 ? String(name.prefix(1)) : ""
        return visible + "•••@" + domain
    }

    /// Masks all but the last characters of a value, such as an account or phone number.
    ///
    /// - Parameters:
    ///   - text: The value.
    ///   - visibleCount: How many trailing characters to keep, clamped to 0...4. They are kept
    ///     only when the value is at least three times as long, so at least two thirds stay hidden.
    /// - Returns: ``hidden``, followed by a space and the kept characters if any.
    public static func trailing(_ text: String, visibleCount: Int = 4) -> String {
        let visible = min(max(visibleCount, 0), 4)
        guard visible > 0, text.count >= visible * 3 else { return hidden }
        let suffix = text.suffix(visible)
        guard !suffix.unicodeScalars.contains(where: ScalarClass.isUnsafeToShow) else { return hidden }
        return hidden + " " + suffix
    }
}

/// Character classes shared by ``Mask`` and ``SensitiveDataRedactor``.
enum ScalarClass {
    /// The value of a decimal digit in any script (ASCII, full-width, Arabic-Indic, ...).
    static func decimalDigit(_ scalar: Unicode.Scalar) -> UInt8? {
        guard scalar.properties.numericType == .decimal,
              let value = scalar.properties.numericValue,
              value >= 0, value <= 9
        else { return nil }
        return UInt8(value)
    }

    /// Control and format characters (zero-width, direction overrides) and whitespace other than
    /// the plain space: characters that can hide text or start a new log line.
    static func isUnsafeToShow(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator: true
        default: scalar != " " && scalar.properties.isWhitespace
        }
    }

    /// Scalars that can be put into a value without changing how it looks, and that the scanning
    /// copy leaves out: format characters, marks, variation selectors, every default-ignorable
    /// code point (fillers such as U+115F and U+3164, unassigned ones such as U+FFF0 and
    /// U+E0080), and control characters other than tab and the line terminators.
    static func isInvisible(_ scalar: Unicode.Scalar) -> Bool {
        let properties = scalar.properties
        switch properties.generalCategory {
        case .format, .nonspacingMark, .enclosingMark, .spacingMark: return true
        case .control: return !isKeptControl(scalar)
        default: return properties.isVariationSelector || properties.isDefaultIgnorableCodePoint
        }
    }

    /// The invisible scalars that only hide text: all of them but marks and variation selectors,
    /// which belong to letters and emoji. A word of free text that holds one cannot be read with
    /// certainty.
    static func isHiding(_ scalar: Unicode.Scalar) -> Bool {
        let properties = scalar.properties
        switch properties.generalCategory {
        case .format: return true
        case .control: return !isKeptControl(scalar)
        case .nonspacingMark, .enclosingMark, .spacingMark: return false
        default: return properties.isDefaultIgnorableCodePoint && !properties.isVariationSelector
        }
    }

    /// Tab, line feed, carriage return, vertical tab, form feed and U+0085: the control characters
    /// that are white space or end a line.
    private static func isKeptControl(_ scalar: Unicode.Scalar) -> Bool {
        (0x09...0x0D).contains(scalar.value) || scalar.value == 0x85
    }
}
