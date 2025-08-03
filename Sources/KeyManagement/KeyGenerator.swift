import Foundation
import CryptoKit
import Security

/// Cryptographic key generator for various algorithms
public class KeyGenerator {
    
    // MARK: - Singleton
    public static let shared = KeyGenerator()
    
    // MARK: - Private Properties
    private let defaultKeySize = 256
    private let defaultRSASize = 2048
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate AES key
    public func generateAESKey(size: Int = 256) throws -> SymmetricKey {
        switch size {
        case 128:
            return SymmetricKey(size: .bits128)
        case 192:
            return SymmetricKey(size: .bits192)
        case 256:
            return SymmetricKey(size: .bits256)
        default:
            throw KeyGeneratorError.invalidKeySize
        }
    }
    
    /// Generate AES key from password
    public func generateAESKey(from password: String, salt: Data? = nil) throws -> SymmetricKey {
        let saltData = salt ?? generateSalt()
        let keyData = try deriveKey(from: password, salt: saltData)
        return SymmetricKey(data: keyData)
    }
    
    /// Generate RSA key pair
    public func generateRSAKeyPair(size: Int = 2048) throws -> RSAKeyPair {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: size,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeyGeneratorError.keyGenerationFailed(error?.takeRetainedValue())
        }
        
        return RSAKeyPair(privateKey: privateKey, publicKey: publicKey)
    }
    
    /// Generate EC key pair
    public func generateECKeyPair(curve: String = "P-256") throws -> ECKeyPair {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: getECKeySize(for: curve),
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeyGeneratorError.keyGenerationFailed(error?.takeRetainedValue())
        }
        
        return ECKeyPair(privateKey: privateKey, publicKey: publicKey)
    }
    
    /// Generate random bytes
    public func generateRandomBytes(length: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        
        guard status == errSecSuccess else {
            throw KeyGeneratorError.randomGenerationFailed
        }
        
        return Data(bytes)
    }
    
    /// Generate random string
    public func generateRandomString(length: Int, charset: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") throws -> String {
        let randomBytes = try generateRandomBytes(length: length)
        var result = ""
        
        for byte in randomBytes {
            let index = Int(byte) % charset.count
            let charIndex = charset.index(charset.startIndex, offsetBy: index)
            result.append(charset[charIndex])
        }
        
        return result
    }
    
    /// Generate UUID
    public func generateUUID() -> String {
        return UUID().uuidString
    }
    
    /// Generate salt
    public func generateSalt(length: Int = 32) -> Data {
        return try! generateRandomBytes(length: length)
    }
    
    /// Generate key from password using PBKDF2
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
            throw KeyGeneratorError.keyDerivationFailed
        }
        
        return derivedKeyData
    }
    
    /// Generate HMAC key
    public func generateHMACKey(size: Int = 256) throws -> SymmetricKey {
        return try generateAESKey(size: size)
    }
    
    /// Generate key for specific algorithm
    public func generateKey(for algorithm: String, size: Int? = nil) throws -> Any {
        switch algorithm.uppercased() {
        case "AES":
            return try generateAESKey(size: size ?? defaultKeySize)
        case "RSA":
            return try generateRSAKeyPair(size: size ?? defaultRSASize)
        case "EC", "ECDSA", "ECDH":
            return try generateECKeyPair()
        case "HMAC":
            return try generateHMACKey(size: size ?? defaultKeySize)
        default:
            throw KeyGeneratorError.unsupportedAlgorithm
        }
    }
    
    /// Validate key strength
    public func validateKeyStrength(_ key: Data, algorithm: String) -> KeyStrength {
        let keySize = key.count * 8
        
        switch algorithm.uppercased() {
        case "AES":
            switch keySize {
            case 128:
                return .weak
            case 192:
                return .medium
            case 256:
                return .strong
            default:
                return .weak
            }
        case "RSA":
            switch keySize {
            case 0..<1024:
                return .weak
            case 1024..<2048:
                return .medium
            case 2048...:
                return .strong
            default:
                return .weak
            }
        case "EC":
            switch keySize {
            case 0..<256:
                return .weak
            case 256..<384:
                return .medium
            case 384...:
                return .strong
            default:
                return .weak
            }
        default:
            return .unknown
        }
    }
    
    // MARK: - Private Methods
    
    private func getECKeySize(for curve: String) -> Int {
        switch curve.uppercased() {
        case "P-256":
            return 256
        case "P-384":
            return 384
        case "P-521":
            return 521
        default:
            return 256
        }
    }
}

// MARK: - Supporting Types

/// RSA key pair
public struct RSAKeyPair {
    public let privateKey: SecKey
    public let publicKey: SecKey
    
    public init(privateKey: SecKey, publicKey: SecKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

/// EC key pair
public struct ECKeyPair {
    public let privateKey: SecKey
    public let publicKey: SecKey
    
    public init(privateKey: SecKey, publicKey: SecKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

/// Key strength levels
public enum KeyStrength {
    case weak
    case medium
    case strong
    case unknown
}

/// Key generator errors
public enum KeyGeneratorError: LocalizedError {
    case invalidKeySize
    case keyGenerationFailed(CFError?)
    case randomGenerationFailed
    case keyDerivationFailed
    case unsupportedAlgorithm
    case invalidParameters
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeySize:
            return "Invalid key size specified"
        case .keyGenerationFailed(let error):
            return "Failed to generate key: \(error?.localizedDescription ?? "Unknown error")"
        case .randomGenerationFailed:
            return "Failed to generate random bytes"
        case .keyDerivationFailed:
            return "Failed to derive key from password"
        case .unsupportedAlgorithm:
            return "Unsupported cryptographic algorithm"
        case .invalidParameters:
            return "Invalid parameters for key generation"
        }
    }
} 