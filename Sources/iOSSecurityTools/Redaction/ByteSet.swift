/// A set of ASCII bytes, looked up without hashing. The scanners test such a set for most bytes
/// they read, and a `Set<UInt8>` hashed every one of them.
struct ByteSet: Sendable {
    private let low: UInt64
    private let high: UInt64

    /// The set of the ASCII characters of `characters`.
    init(_ characters: String) {
        var low: UInt64 = 0
        var high: UInt64 = 0
        for byte in characters.utf8 {
            precondition(byte < 128, "a ByteSet holds ASCII bytes")
            if byte < 64 { low |= 1 << UInt64(byte) } else { high |= 1 << UInt64(byte - 64) }
        }
        self.low = low
        self.high = high
    }

    func contains(_ byte: UInt8) -> Bool {
        if byte < 64 { return low & (1 << UInt64(byte)) != 0 }
        return byte < 128 && high & (1 << UInt64(byte - 64)) != 0
    }
}
