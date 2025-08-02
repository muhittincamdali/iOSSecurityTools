import Foundation
import CryptoKit

// MARK: - AES Encryption
public class AESEncryption {
    
    // MARK: - Singleton
    public static let shared = AESEncryption()
    
    // MARK: - Private Properties
    private let keySize = 256 // AES-256
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate AES key
    public func generateKey() throws -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }
    
    /// Generate AES key from password using PBKDF2
    public func generateKey(from password: String, salt: Data? = nil) throws -> SymmetricKey {
        let saltData = salt ?? generateSalt()
        let keyData = try deriveKey(from: password, salt: saltData)
        return SymmetricKey(data: keyData)
    }
    
    /// Encrypt data with AES
    public func encrypt(_ data: Data, with key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined ?? Data()
    }
    
    /// Encrypt string with AES
    public func encrypt(_ string: String, with key: SymmetricKey) throws -> Data {
        guard let data = string.data(using: .utf8) else {
            throw EncryptionError.invalidData
        }
        return try encrypt(data, with: key)
    }
    
    /// Decrypt data with AES
    public func decrypt(_ encryptedData: Data, with key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    /// Decrypt data to string with AES
    public func decryptToString(_ encryptedData: Data, with key: SymmetricKey) throws -> String {
        let decryptedData = try decrypt(encryptedData, with: key)
        guard let string = String(data: decryptedData, encoding: .utf8) else {
            throw EncryptionError.invalidData
        }
        return string
    }
    
    /// Encrypt file with AES
    public func encryptFile(at fileURL: URL, with key: SymmetricKey) throws -> URL {
        let data = try Data(contentsOf: fileURL)
        let encryptedData = try encrypt(data, with: key)
        
        let encryptedFileURL = fileURL.appendingPathExtension("encrypted")
        try encryptedData.write(to: encryptedFileURL)
        
        return encryptedFileURL
    }
    
    /// Decrypt file with AES
    public func decryptFile(at fileURL: URL, with key: SymmetricKey) throws -> URL {
        let encryptedData = try Data(contentsOf: fileURL)
        let decryptedData = try decrypt(encryptedData, with: key)
        
        let decryptedFileURL = fileURL.deletingPathExtension()
        try decryptedData.write(to: decryptedFileURL)
        
        return decryptedFileURL
    }
    
    /// Generate random salt
    public func generateSalt() -> Data {
        return Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }
    
    // MARK: - Private Methods
    
    private func deriveKey(from password: String, salt: Data) throws -> Data {
        let passwordData = password.data(using: .utf8)!
        let rounds = 100_000
        
        var derivedKeyData = Data(repeating: 0, count: 32)
        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress,
                        passwordData.count,
                        saltBytes.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(rounds),
                        derivedKeyBytes.baseAddress,
                        derivedKeyData.count
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw EncryptionError.keyDerivationFailed
        }
        
        return derivedKeyData
    }
}

// MARK: - RSA Encryption
public class RSAEncryption {
    
    // MARK: - Singleton
    public static let shared = RSAEncryption()
    
    // MARK: - Private Properties
    private let keySize = 2048
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate RSA key pair
    public func generateKeyPair() throws -> RSAKeyPair {
        let privateKey = try P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        return RSAKeyPair(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
    
    /// Encrypt data with RSA public key
    public func encrypt(_ data: Data, with publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeralPrivateKey = try P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey
        
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "RSA-Encryption".data(using: .utf8)!,
            sharedInfo: ephemeralPublicKey.rawRepresentation,
            outputByteCount: 32
        )
        
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        let encryptedData = sealedBox.combined ?? Data()
        
        // Combine ephemeral public key with encrypted data
        var combinedData = Data()
        combinedData.append(ephemeralPublicKey.rawRepresentation)
        combinedData.append(encryptedData)
        
        return combinedData
    }
    
    /// Decrypt data with RSA private key
    public func decrypt(_ encryptedData: Data, with privateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        guard encryptedData.count > 65 else { // Minimum size for ephemeral key + some encrypted data
            throw EncryptionError.invalidData
        }
        
        // Extract ephemeral public key (first 65 bytes)
        let ephemeralPublicKeyData = encryptedData.prefix(65)
        let encryptedPayload = encryptedData.dropFirst(65)
        
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "RSA-Encryption".data(using: .utf8)!,
            sharedInfo: ephemeralPublicKey.rawRepresentation,
            outputByteCount: 32
        )
        
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedPayload)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
    
    /// Encrypt string with RSA public key
    public func encrypt(_ string: String, with publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        guard let data = string.data(using: .utf8) else {
            throw EncryptionError.invalidData
        }
        return try encrypt(data, with: publicKey)
    }
    
    /// Decrypt data to string with RSA private key
    public func decryptToString(_ encryptedData: Data, with privateKey: P256.KeyAgreement.PrivateKey) throws -> String {
        let decryptedData = try decrypt(encryptedData, with: privateKey)
        guard let string = String(data: decryptedData, encoding: .utf8) else {
            throw EncryptionError.invalidData
        }
        return string
    }
}

// MARK: - Hash Generator
public class HashGenerator {
    
    // MARK: - Singleton
    public static let shared = HashGenerator()
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate SHA-256 hash
    public func sha256(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }
    
    /// Generate SHA-256 hash from string
    public func sha256(_ string: String) -> String {
        guard let data = string.data(using: .utf8) else {
            return ""
        }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate SHA-512 hash
    public func sha512(_ data: Data) -> Data {
        return Data(SHA512.hash(data: data))
    }
    
    /// Generate SHA-512 hash from string
    public func sha512(_ string: String) -> String {
        guard let data = string.data(using: .utf8) else {
            return ""
        }
        let hash = SHA512.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate MD5 hash (for legacy compatibility)
    public func md5(_ data: Data) -> Data {
        return Data(Insecure.MD5.hash(data: data))
    }
    
    /// Generate MD5 hash from string
    public func md5(_ string: String) -> String {
        guard let data = string.data(using: .utf8) else {
            return ""
        }
        let hash = Insecure.MD5.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Verify hash
    public func verify(_ data: Data, hash: Data) -> Bool {
        let computedHash = sha256(data)
        return computedHash == hash
    }
    
    /// Verify hash from string
    public func verify(_ string: String, hash: String) -> Bool {
        let computedHash = sha256(string)
        return computedHash == hash
    }
    
    /// Generate HMAC
    public func hmac(_ data: Data, key: Data) -> Data {
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
    
    /// Generate HMAC from string
    public func hmac(_ string: String, key: String) -> String {
        guard let data = string.data(using: .utf8),
              let keyData = key.data(using: .utf8) else {
            return ""
        }
        let hmacData = hmac(data, key: keyData)
        return hmacData.compactMap { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Key Derivation
public class KeyDerivation {
    
    // MARK: - Singleton
    public static let shared = KeyDerivation()
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Derive key using PBKDF2
    public func deriveKey(from password: String, salt: Data, rounds: Int = 100_000, keyLength: Int = 32) throws -> Data {
        let passwordData = password.data(using: .utf8)!
        
        var derivedKeyData = Data(repeating: 0, count: keyLength)
        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress,
                        passwordData.count,
                        saltBytes.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(rounds),
                        derivedKeyBytes.baseAddress,
                        derivedKeyData.count
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw EncryptionError.keyDerivationFailed
        }
        
        return derivedKeyData
    }
    
    /// Generate random salt
    public func generateSalt(length: Int = 32) -> Data {
        return Data((0..<length).map { _ in UInt8.random(in: 0...255) })
    }
}

// MARK: - Supporting Types

/// RSA Key Pair
public struct RSAKeyPair {
    public let privateKey: P256.KeyAgreement.PrivateKey
    public let publicKey: P256.KeyAgreement.PublicKey
    
    public init(privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

/// Encryption Error
public enum EncryptionError: LocalizedError {
    case invalidData
    case keyDerivationFailed
    case encryptionFailed
    case decryptionFailed
    case invalidKey
    case unsupportedAlgorithm
    
    public var errorDescription: String? {
        switch self {
        case .invalidData:
            return "Invalid data provided"
        case .keyDerivationFailed:
            return "Key derivation failed"
        case .encryptionFailed:
            return "Encryption failed"
        case .decryptionFailed:
            return "Decryption failed"
        case .invalidKey:
            return "Invalid key provided"
        case .unsupportedAlgorithm:
            return "Unsupported algorithm"
        }
    }
} 