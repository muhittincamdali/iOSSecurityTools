import Foundation

/// Comparison whose running time does not depend on where two values differ.
///
/// `==` on `Data` or `String` returns at the first byte that differs, so the time it takes tells
/// an attacker how many leading bytes of a guess were right. Compare secrets (one-time codes,
/// MACs, password hashes) with ``isEqual(_:_:)`` instead.
public enum ConstantTime {
    /// Returns whether two byte sequences are equal, looking at every byte.
    ///
    /// The time depends only on the lengths: sequences of different length return `false` right
    /// away, because the length of a MAC or a code is not a secret.
    public static func isEqual(_ lhs: some DataProtocol, _ rhs: some DataProtocol) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }

    /// Returns whether two strings have the same UTF-8 bytes, looking at every byte.
    ///
    /// The strings are compared byte for byte, without Unicode normalization: `"é"` written as one
    /// code point and as `e` plus a combining accent are different.
    public static func isEqual(_ lhs: String, _ rhs: String) -> Bool {
        isEqual(Array(lhs.utf8), Array(rhs.utf8))
    }
}
