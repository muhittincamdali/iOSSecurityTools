import Foundation

/// Hashes a password or PIN for later verification on the device, in the PHC string format.
///
/// Use it for an app lock: store the hash (in the ``Keychain``) when the user picks a PIN, and
/// check later entries against it. The hash contains the algorithm, the iteration count and the
/// salt, so it can be verified without other settings:
///
/// ```text
/// $pbkdf2-sha256$i=600000$<salt>$<hash>
/// ```
///
/// ```swift
/// let stored = try PasswordHash.make(for: "4921")
/// try PasswordHash.verify("4921", against: stored)    // true
/// try PasswordHash.verify("4920", against: stored)    // false
/// ```
///
/// Passwords for a server account are hashed on the server, not in the app.
public enum PasswordHash {
    /// The longest encoded hash ``verify(_:against:)`` reads.
    public static let maximumEncodedLength = 512
    private static let identifier = "pbkdf2-sha256"
    private static let saltByteCount = 16
    private static let hashByteCount = 32

    /// Hashes a password with a new random salt.
    ///
    /// - Parameters:
    ///   - password: The password or PIN, 1 to 4096 UTF-8 bytes.
    ///   - iterations: The work factor; see ``PasswordKeyDerivation/recommendedIterations``.
    /// - Returns: The encoded hash, about 100 ASCII characters.
    public static func make(for password: String, iterations: Int = PasswordKeyDerivation.recommendedIterations) throws(CipherError) -> String {
        let salt: Data
        do {
            salt = try SecureRandom.bytes(count: saltByteCount)
        } catch {
            throw .invalidParameter(error.localizedDescription)
        }
        let key = try PasswordKeyDerivation.deriveKey(from: password, salt: salt, iterations: iterations, outputByteCount: hashByteCount)
        let hash = key.withUnsafeBytes { Data($0) }
        return "$\(identifier)$i=\(iterations)$\(encode(salt))$\(encode(hash))"
    }

    /// Returns whether a password matches an encoded hash.
    ///
    /// The comparison takes the same time wherever the hashes differ.
    ///
    /// - Throws: ``CipherError/malformedHash(_:)`` when `encoded` is not a hash made by
    ///   ``make(for:iterations:)`` — including one whose iteration count is outside
    ///   ``PasswordKeyDerivation/iterationRange``, so a tampered hash cannot make the check run
    ///   for hours — and ``CipherError/invalidParameter(_:)`` for an empty or overlong password.
    public static func verify(_ password: String, against encoded: String) throws(CipherError) -> Bool {
        let parts = try parse(encoded)
        let key = try PasswordKeyDerivation.deriveKey(from: password, salt: parts.salt, iterations: parts.iterations, outputByteCount: parts.hash.count)
        return key.withUnsafeBytes { ConstantTime.isEqual(Data($0), parts.hash) }
    }

    /// Returns whether a hash was made with fewer iterations than `iterations`, so the app can
    /// hash the password again after the user enters it correctly.
    public static func needsRehash(_ encoded: String, iterations: Int = PasswordKeyDerivation.recommendedIterations) throws(CipherError) -> Bool {
        try parse(encoded).iterations < iterations
    }

    private static func parse(_ encoded: String) throws(CipherError) -> (iterations: Int, salt: Data, hash: Data) {
        guard encoded.utf8.count <= maximumEncodedLength else {
            throw .malformedHash("It is longer than \(maximumEncodedLength) characters.")
        }
        let fields = encoded.split(separator: "$", omittingEmptySubsequences: false)
        guard fields.count == 5, fields[0].isEmpty, fields[1] == identifier else {
            throw .malformedHash("Expected $\(identifier)$i=<iterations>$<salt>$<hash>.")
        }
        let iterationField = fields[2]
        guard iterationField.hasPrefix("i="),
              let iterations = Int(iterationField.dropFirst(2)),
              String(iterations) == iterationField.dropFirst(2)
        else {
            throw .malformedHash("The iteration count is not a number.")
        }
        guard PasswordKeyDerivation.iterationRange.contains(iterations) else {
            throw .malformedHash("The iteration count \(iterations) is outside \(PasswordKeyDerivation.iterationRange).")
        }
        guard let salt = decode(fields[3]), PasswordKeyDerivation.saltLengthRange.contains(salt.count) else {
            throw .malformedHash("The salt is not valid base64 of 16 to 1024 bytes.")
        }
        guard let hash = decode(fields[4]), PasswordKeyDerivation.outputByteCountRange.contains(hash.count) else {
            throw .malformedHash("The hash is not valid base64 of 16 to 64 bytes.")
        }
        return (iterations, salt, hash)
    }

    /// Standard base64 without padding, as the PHC string format specifies.
    private static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    private static func decode(_ text: Substring) -> Data? {
        guard !text.contains("=") else { return nil }
        let remainder = text.utf8.count % 4
        guard remainder != 1 else { return nil }
        let padded = String(text) + String(repeating: "=", count: (4 - remainder) % 4)
        return Data(base64Encoded: padded)
    }
}
