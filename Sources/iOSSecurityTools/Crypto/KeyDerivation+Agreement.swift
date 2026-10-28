import CryptoKit
import Foundation

extension KeyDerivation {
    /// Derives a key that two parties share, from one party's private key and the other's public
    /// key: X25519 (RFC 7748) followed by HKDF-SHA256.
    ///
    /// Each side calls it with its own private key and the other side's public key and gets the
    /// same key, without the key ever being sent. Use it for a long-lived channel between two
    /// devices that already know each other's public keys; to encrypt a single message to a
    /// public key, ``PublicKeyCipher`` is simpler.
    ///
    /// ```swift
    /// let phone = Curve25519.KeyAgreement.PrivateKey()
    /// let watch = Curve25519.KeyAgreement.PrivateKey()
    /// let info = Data("sync v1".utf8)
    /// let phoneKey = try KeyDerivation.sharedKey(privateKey: phone, peerPublicKey: watch.publicKey, info: info)
    /// let watchKey = try KeyDerivation.sharedKey(privateKey: watch, peerPublicKey: phone.publicKey, info: info)
    /// // phoneKey == watchKey; use it with DataCipher.
    /// ```
    ///
    /// The raw X25519 output is never returned: it is not uniformly random and must go through a
    /// key derivation function first. Neither side is authenticated by this call alone: check
    /// the peer's public key out of band, or sign it with a ``SigningKey``.
    ///
    /// - Parameters:
    ///   - privateKey: This side's private key.
    ///   - peerPublicKey: The other side's public key.
    ///   - salt: Optional salt, such as a random value both sides know.
    ///   - info: A label for the purpose of the key, ideally with both public keys in it, so that
    ///     keys for different purposes or pairs are unrelated.
    ///   - outputByteCount: The size of the derived key, 16 to ``maximumOutputByteCount`` bytes.
    /// - Throws: ``CipherError/invalidParameter(_:)`` for an output size outside that range, and
    ///   ``CipherError/invalidParameter(_:)`` when the peer key is a low-order point, which would give a
    ///   shared secret of zeros that an attacker knows.
    public static func sharedKey(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        peerPublicKey: Curve25519.KeyAgreement.PublicKey,
        salt: some DataProtocol = Data(),
        info: some DataProtocol,
        outputByteCount: Int = 32
    ) throws(CipherError) -> SymmetricKey {
        try checkOutputByteCount(outputByteCount)
        let secret: SharedSecret
        do {
            secret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        } catch {
            throw .invalidParameter("The peer public key gives no shared secret: \(error)")
        }
        try rejectZeroSecret(secret)
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
    }

    /// Derives a key that two parties share with ECDH over P-256 followed by HKDF-SHA256.
    ///
    /// Use it when the other side requires P-256; otherwise prefer the X25519 version. The
    /// parameters and errors are those of
    /// ``sharedKey(privateKey:peerPublicKey:salt:info:outputByteCount:)-(Curve25519.KeyAgreement.PrivateKey,_,_,_,_)``.
    public static func sharedKey(
        privateKey: P256.KeyAgreement.PrivateKey,
        peerPublicKey: P256.KeyAgreement.PublicKey,
        salt: some DataProtocol = Data(),
        info: some DataProtocol,
        outputByteCount: Int = 32
    ) throws(CipherError) -> SymmetricKey {
        try checkOutputByteCount(outputByteCount)
        let secret: SharedSecret
        do {
            secret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        } catch {
            throw .invalidParameter("The peer public key gives no shared secret: \(error)")
        }
        try rejectZeroSecret(secret)
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
    }

    private static func checkOutputByteCount(_ count: Int) throws(CipherError) {
        guard (16...maximumOutputByteCount).contains(count) else {
            throw .invalidParameter("The output size must be 16 to \(maximumOutputByteCount) bytes, not \(count).")
        }
    }

    /// RFC 7748 §6.1: a peer key of low order gives an all-zero secret, which must be rejected.
    /// CryptoKit may or may not do this itself, so it is checked here as well, in constant time.
    private static func rejectZeroSecret(_ secret: SharedSecret) throws(CipherError) {
        let combined = secret.withUnsafeBytes { bytes in bytes.reduce(UInt8(0)) { $0 | $1 } }
        guard combined != 0 else {
            throw .invalidParameter("The peer public key is a low-order point; the shared secret would be zero.")
        }
    }
}
