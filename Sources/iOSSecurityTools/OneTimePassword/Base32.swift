import Foundation

/// Base32 with the RFC 4648 alphabet, as used for one-time password secrets.
enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    /// Encodes without `=` padding, as authenticator apps expect in `otpauth://` URIs.
    static func encode(_ data: Data) -> String {
        var output = [UInt8]()
        output.reserveCapacity((data.count * 8 + 4) / 5)
        var buffer = 0
        var bitCount = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bitCount += 8
            while bitCount >= 5 {
                output.append(alphabet[(buffer >> (bitCount - 5)) & 0x1F])
                bitCount -= 5
            }
            buffer &= (1 << bitCount) - 1
        }
        if bitCount > 0 {
            output.append(alphabet[(buffer << (5 - bitCount)) & 0x1F])
        }
        return String(decoding: output, as: UTF8.self)
    }

    /// Decodes Base32 text, ignoring case, spaces, hyphens and trailing `=` padding.
    ///
    /// Returns `nil` for any other character, for padding in the middle, and for a length that
    /// no byte sequence encodes to.
    static func decode(_ text: String) -> Data? {
        var symbols = [UInt8]()
        symbols.reserveCapacity(text.utf8.count)
        var sawPadding = false
        for byte in text.utf8 {
            switch byte {
            case UInt8(ascii: " "), UInt8(ascii: "-"):
                continue
            case UInt8(ascii: "="):
                sawPadding = true
            case UInt8(ascii: "A")...UInt8(ascii: "Z"):
                guard !sawPadding else { return nil }
                symbols.append(byte - UInt8(ascii: "A"))
            case UInt8(ascii: "a")...UInt8(ascii: "z"):
                guard !sawPadding else { return nil }
                symbols.append(byte - UInt8(ascii: "a"))
            case UInt8(ascii: "2")...UInt8(ascii: "7"):
                guard !sawPadding else { return nil }
                symbols.append(byte - UInt8(ascii: "2") + 26)
            default:
                return nil
            }
        }
        // 1, 3 and 6 trailing symbols cannot come from whole bytes.
        guard ![1, 3, 6].contains(symbols.count % 8) else { return nil }

        var output = Data()
        output.reserveCapacity(symbols.count * 5 / 8)
        var buffer = 0
        var bitCount = 0
        for symbol in symbols {
            buffer = (buffer << 5) | Int(symbol)
            bitCount += 5
            if bitCount >= 8 {
                output.append(UInt8((buffer >> (bitCount - 8)) & 0xFF))
                bitCount -= 8
            }
            buffer &= (1 << bitCount) - 1
        }
        return output
    }
}
