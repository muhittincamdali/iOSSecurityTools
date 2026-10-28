import Foundation

/// The three parts of a compact JWS, decoded with no leniency.
struct JWTParts {
    let header: Data
    let claims: Data
    let signature: Data
    /// `header.claims` as written: the bytes the signature covers.
    let signingInput: Data

    init(_ token: String) throws(JWTError) {
        // Measure before copying, so an oversized token is rejected without allocating its size.
        guard token.utf8.count <= JWTVerifier.maximumTokenLength else {
            throw .malformed("The token is longer than \(JWTVerifier.maximumTokenLength) bytes.")
        }
        let bytes = Array(token.utf8)
        let parts = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw .malformed("A compact token has three parts separated by dots, not \(parts.count).")
        }
        guard let header = Base64URL.strictDecode(parts[0]), !header.isEmpty,
              let claims = Base64URL.strictDecode(parts[1]), !claims.isEmpty,
              let signature = Base64URL.strictDecode(parts[2]) else {
            throw .malformed("A part is not unpadded Base64URL.")
        }
        self.header = header
        self.claims = claims
        self.signature = signature
        signingInput = Data(bytes[..<parts[2].startIndex].dropLast())
    }

    /// Reads a part as a JSON object whose member names are all different. `JSONSerialization`
    /// keeps one of two members with the same name, and another parser may keep the other, so
    /// such a header or claim set is refused rather than read one way.
    static func object(_ data: Data, part: String) throws(JWTError) -> [String: Any] {
        // `String(data:encoding:)` drops a byte order mark, which RFC 8259 §8.1 forbids here.
        guard !data.starts(with: [0xEF, 0xBB, 0xBF]), let text = String(data: data, encoding: .utf8) else {
            throw .malformed("The \(part) is not UTF-8 without a byte order mark.")
        }
        let scalars = Array(text.unicodeScalars)
        guard let document = try? JSONDocument(scalars, utf8: data, allowsFragments: false, nesting: .document(length: scalars.count)),
              case .object(let members) = document.root.value else {
            throw .malformed("The \(part) is not a JSON object.")
        }
        var names = Set<[Unicode.Scalar]>()
        for member in members where !names.insert(document.text(of: member.name)).inserted {
            throw .malformed("The \(part) repeats a member name.")
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw .malformed("The \(part) is not a JSON object.")
        }
        return object
    }
}

extension Base64URL {
    /// Decodes canonical unpadded Base64URL; nil for padding, any other character, an
    /// impossible length or unused bits that are not zero.
    static func strictDecode(_ bytes: ArraySlice<UInt8>) -> Data? {
        guard bytes.count % 4 != 1 else { return nil }
        var standard = [UInt8]()
        standard.reserveCapacity(bytes.count + 3)
        for byte in bytes {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"):
                standard.append(byte)
            case UInt8(ascii: "-"): standard.append(UInt8(ascii: "+"))
            case UInt8(ascii: "_"): standard.append(UInt8(ascii: "/"))
            default: return nil
            }
        }
        while !standard.count.isMultiple(of: 4) {
            standard.append(UInt8(ascii: "="))
        }
        guard let data = Data(base64Encoded: Data(standard)) else { return nil }
        // One token, one encoding: refuse text whose unused bits are set.
        guard encode(data).utf8.elementsEqual(bytes) else { return nil }
        return data
    }
}
