import CommonCrypto
import CryptoKit
import Foundation

/// Derives keys from other keys with HKDF-SHA256 (RFC 5869).
///
/// Use it to turn one master key into independent keys for different purposes — one for local
/// files, one for a cache — so that a key leaked from one use does not expose the others.
///
/// ```swift
/// let master = try Keychain(service: "com.example.app").symmetricKey(forKey: "master")
/// let filesKey = try KeyDerivation.derive(from: master, info: Data("files v1".utf8))
/// ```
public enum KeyDerivation {
    /// The largest output HKDF-SHA256 can produce: 255 blocks of 32 bytes.
    public static let maximumOutputByteCount = 255 * 32

    /// Derives a key.
    ///
    /// - Parameters:
    ///   - inputKey: The source key material.
    ///   - salt: Optional random salt; it can be stored in the clear.
    ///   - info: A label for the purpose of the key. Different labels give unrelated keys.
    ///   - outputByteCount: The size of the derived key, from 16 to
    ///     ``maximumOutputByteCount`` bytes. The default, 32, suits ``DataCipher``.
    /// - Throws: ``CipherError/invalidParameter(_:)`` for an output size outside that range.
    public static func derive(
        from inputKey: SymmetricKey,
        salt: some DataProtocol = Data(),
        info: some DataProtocol,
        outputByteCount: Int = 32
    ) throws(CipherError) -> SymmetricKey {
        guard (16...maximumOutputByteCount).contains(outputByteCount) else {
            throw .invalidParameter("The output size must be 16 to \(maximumOutputByteCount) bytes, not \(outputByteCount).")
        }
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: inputKey, salt: salt, info: info, outputByteCount: outputByteCount)
    }
}

/// Derives a key from a password with PBKDF2-HMAC-SHA256.
///
/// A password has far less entropy than a random key, so it is stretched: each guess costs an
/// attacker the same number of iterations. ``recommendedIterations`` follows the OWASP Password
/// Storage Cheat Sheet value for PBKDF2-HMAC-SHA256.
///
/// ```swift
/// let salt = try SecureRandom.bytes(count: 16)       // store it next to the encrypted data
/// let key = try PasswordKeyDerivation.deriveKey(from: "correct horse battery staple", salt: salt)
/// let cipher = try DataCipher(key: key)
/// ```
///
/// Every parameter has a limit, so values read from a file or a server (for example, the
/// iteration count of an encoded ``PasswordHash``) cannot make the call run for hours or allocate
/// without bound.
public enum PasswordKeyDerivation {
    /// 600,000 iterations, the OWASP recommendation for PBKDF2-HMAC-SHA256.
    public static let recommendedIterations = 600_000
    /// Accepted iteration counts.
    public static let iterationRange = 1_000...10_000_000
    /// Accepted salt sizes in bytes. 16 random bytes are enough.
    public static let saltLengthRange = 16...1024
    /// Accepted password sizes in UTF-8 bytes, after normalization.
    public static let passwordLengthRange = 1...4096
    /// Accepted output sizes in bytes.
    public static let outputByteCountRange = 16...64

    /// Derives a key from a password.
    ///
    /// The password is normalized to Unicode NFC first, so the same password typed on keyboards
    /// that produce composed or decomposed accents gives the same key.
    ///
    /// - Parameters:
    ///   - password: The password, 1 to 4096 UTF-8 bytes.
    ///   - salt: Random bytes, 16 to 1024, unique per password. Store them with the result.
    ///   - iterations: The work factor, within ``iterationRange``.
    ///   - outputByteCount: The key size, 16 to 64 bytes; 32 for ``DataCipher``.
    /// - Throws: ``CipherError/invalidParameter(_:)`` when a value is outside its range.
    public static func deriveKey(
        from password: String,
        salt: Data,
        iterations: Int = recommendedIterations,
        outputByteCount: Int = 32
    ) throws(CipherError) -> SymmetricKey {
        let passwordBytes = Array(password.precomposedStringWithCanonicalMapping.utf8)
        guard passwordLengthRange.contains(passwordBytes.count) else {
            throw .invalidParameter("The password must be 1 to 4096 bytes long.")
        }
        guard saltLengthRange.contains(salt.count) else {
            throw .invalidParameter("The salt must be 16 to 1024 bytes long, not \(salt.count).")
        }
        guard iterationRange.contains(iterations) else {
            throw .invalidParameter("The iteration count must be \(iterationRange.lowerBound) to \(iterationRange.upperBound), not \(iterations).")
        }
        guard outputByteCountRange.contains(outputByteCount) else {
            throw .invalidParameter("The output size must be 16 to 64 bytes, not \(outputByteCount).")
        }
        return SymmetricKey(data: try pbkdf2SHA256(password: passwordBytes, salt: [UInt8](salt), iterations: iterations, outputByteCount: outputByteCount))
    }

    /// PBKDF2-HMAC-SHA256 without range checks; callers validate.
    static func pbkdf2SHA256(password: [UInt8], salt: [UInt8], iterations: Int, outputByteCount: Int) throws(CipherError) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: outputByteCount)
        let status = password.withUnsafeBufferPointer { passwordBuffer in
            passwordBuffer.withMemoryRebound(to: CChar.self) { passwordChars in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordChars.baseAddress, passwordChars.count,
                    salt, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &output, output.count
                )
            }
        }
        guard status == kCCSuccess else {
            throw .invalidParameter("PBKDF2 failed with status \(status).")
        }
        return output
    }
}
