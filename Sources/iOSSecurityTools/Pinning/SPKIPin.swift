import CryptoKit
import Foundation
import Security

/// The SHA-256 hash of a certificate's public key (its SubjectPublicKeyInfo), the value that
/// certificate pinning compares.
///
/// Pinning the key instead of the whole certificate keeps the pin valid when the server renews
/// its certificate with the same key. The base64 text is the same as the `pin-sha256` values of
/// HPKP and the pins of TrustKit, and as this OpenSSL pipeline prints:
///
/// ```sh
/// openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
///   | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
///   | openssl dgst -sha256 -binary | base64
/// ```
public struct SPKIPin: Sendable, Hashable, CustomStringConvertible {
    /// The 32-byte SHA-256 hash.
    public let sha256: Data

    /// Reads a pin from base64 text, optionally prefixed with `sha256/`.
    ///
    /// - Throws: ``PinningError/invalidPin(_:)`` unless the text is base64 of exactly 32 bytes.
    public init(base64 text: String) throws(PinningError) {
        let trimmed = text.hasPrefix("sha256/") ? String(text.dropFirst(7)) : text
        guard trimmed.utf8.count == 44, let data = Data(base64Encoded: trimmed), data.count == 32 else {
            throw .invalidPin(text)
        }
        self.sha256 = data
    }

    /// Computes the pin of a certificate's public key.
    ///
    /// - Throws: ``PinningError/unsupportedKey(_:)`` for keys other than RSA and EC P-256, P-384
    ///   and P-521.
    public init(certificate: SecCertificate) throws(PinningError) {
        guard let key = SecCertificateCopyKey(certificate) else {
            throw .unsupportedKey("The certificate's public key cannot be read.")
        }
        try self.init(publicKey: key)
    }

    /// Computes the pin of a public key.
    public init(publicKey: SecKey) throws(PinningError) {
        self.sha256 = Data(SHA256.hash(data: try Self.subjectPublicKeyInfo(of: publicKey)))
    }

    /// The pin as base64 text, without a prefix.
    public var base64: String { sha256.base64EncodedString() }

    /// The pin as `sha256/<base64>`.
    public var description: String { "sha256/\(base64)" }
}

extension SPKIPin: Codable {
    /// Decodes a pin from its base64 text, with or without the `sha256/` prefix.
    public init(from decoder: any Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        do {
            try self.init(base64: text)
        } catch {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: error.localizedDescription))
        }
    }

    /// Encodes the pin as base64 text without a prefix.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64)
    }

}

extension SPKIPin {
    /// The DER-encoded SubjectPublicKeyInfo of a key.
    ///
    /// `SecKeyCopyExternalRepresentation` returns only the key itself (PKCS #1 for RSA, the X9.63
    /// point for EC); the algorithm identifier that the certificate stores around it is added here.
    static func subjectPublicKeyInfo(of key: SecKey) throws(PinningError) -> Data {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let type = attributes[kSecAttrKeyType as String] as? String,
              let bits = (attributes[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue
        else {
            throw .unsupportedKey("The key's attributes cannot be read.")
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            error?.release()
            throw .unsupportedKey("The key cannot be exported.")
        }
        let algorithm: [UInt8]
        if type == kSecAttrKeyTypeRSA as String {
            // SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
            algorithm = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
        } else if type == kSecAttrKeyTypeECSECPrimeRandom as String {
            // SEQUENCE { OID 1.2.840.10045.2.1 (ecPublicKey), OID of the curve }
            let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
            let curve: [UInt8] = switch bits {
            case 256: [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
            case 384: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]
            case 521: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]
            default: throw .unsupportedKey("EC keys of \(bits) bits are not supported.")
            }
            algorithm = DER.sequence(ecPublicKey + curve)
        } else {
            throw .unsupportedKey("Key type \(type) is not RSA or EC.")
        }
        let bitString = [0x03] + DER.length(raw.count + 1) + [0x00] + [UInt8](raw)
        return Data(DER.sequence(algorithm + bitString))
    }
}

/// The few DER encoding rules SubjectPublicKeyInfo needs.
enum DER {
    static func length(_ count: Int) -> [UInt8] {
        guard count >= 0x80 else { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + length(content.count) + content
    }
}
