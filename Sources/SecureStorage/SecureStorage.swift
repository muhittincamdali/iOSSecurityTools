import Foundation
import CryptoKit
import Security

/// Secure storage manager for encrypted data persistence
public class SecureStorage {
    
    // MARK: - Singleton
    public static let shared = SecureStorage()
    
    // MARK: - Private Properties
    private let keychainManager = KeychainManager.shared
    private let encryption = AESEncryption.shared
    private let keyGenerator = KeyGenerator.shared
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Store encrypted data
    public func store(_ data: Data, forKey key: String) throws {
        let encryptionKey = try keyGenerator.generateAESKey()
        let encryptedData = try encryption.encrypt(data, with: encryptionKey)
        
        // Store encryption key in Keychain
        try keychainManager.storeKey(encryptionKey.withUnsafeBytes { Data($0) }, forKey: "\(key)_key")
        
        // Store encrypted data in UserDefaults
        UserDefaults.standard.set(encryptedData, forKey: key)
    }
    
    /// Store encrypted string
    public func store(_ string: String, forKey key: String) throws {
        guard let data = string.data(using: .utf8) else {
            throw SecureStorageError.invalidData
        }
        try store(data, forKey: key)
    }
    
    /// Store encrypted object
    public func store<T: Codable>(_ object: T, forKey key: String) throws {
        let data = try JSONEncoder().encode(object)
        try store(data, forKey: key)
    }
    
    /// Retrieve encrypted data
    public func retrieve(forKey key: String) throws -> Data {
        guard let encryptedData = UserDefaults.standard.data(forKey: key) else {
            throw SecureStorageError.dataNotFound
        }
        
        // Retrieve encryption key from Keychain
        let keyData = try keychainManager.retrieveKey(forKey: "\(key)_key")
        let encryptionKey = SymmetricKey(data: keyData)
        
        return try encryption.decrypt(encryptedData, with: encryptionKey)
    }
    
    /// Retrieve encrypted string
    public func retrieveString(forKey key: String) throws -> String {
        let data = try retrieve(forKey: key)
        guard let string = String(data: data, encoding: .utf8) else {
            throw SecureStorageError.invalidData
        }
        return string
    }
    
    /// Retrieve encrypted object
    public func retrieve<T: Codable>(forKey key: String, as type: T.Type) throws -> T {
        let data = try retrieve(forKey: key)
        return try JSONDecoder().decode(type, from: data)
    }
    
    /// Delete encrypted data
    public func delete(forKey key: String) throws {
        UserDefaults.standard.removeObject(forKey: key)
        try keychainManager.deleteKey(forKey: "\(key)_key")
    }
    
    /// Check if data exists
    public func exists(forKey key: String) -> Bool {
        return UserDefaults.standard.object(forKey: key) != nil
    }
    
    /// Store sensitive data with custom encryption
    public func storeSensitive(_ data: Data, forKey key: String, encryptionKey: SymmetricKey) throws {
        let encryptedData = try encryption.encrypt(data, with: encryptionKey)
        UserDefaults.standard.set(encryptedData, forKey: key)
    }
    
    /// Retrieve sensitive data with custom encryption
    public func retrieveSensitive(forKey key: String, encryptionKey: SymmetricKey) throws -> Data {
        guard let encryptedData = UserDefaults.standard.data(forKey: key) else {
            throw SecureStorageError.dataNotFound
        }
        
        return try encryption.decrypt(encryptedData, with: encryptionKey)
    }
    
    /// Store data with biometric protection
    public func storeWithBiometric(_ data: Data, forKey key: String) throws {
        let biometricAuth = BiometricAuth.shared
        
        guard biometricAuth.isBiometricAvailable() else {
            throw SecureStorageError.biometricNotAvailable
        }
        
        let encryptionKey = try keyGenerator.generateAESKey()
        let encryptedData = try encryption.encrypt(data, with: encryptionKey)
        
        // Store encryption key with biometric protection
        try keychainManager.storeKey(encryptionKey.withUnsafeBytes { Data($0) }, forKey: "\(key)_biometric_key")
        
        UserDefaults.standard.set(encryptedData, forKey: key)
    }
    
    /// Retrieve data with biometric protection
    public func retrieveWithBiometric(forKey key: String) throws -> Data {
        let biometricAuth = BiometricAuth.shared
        
        guard biometricAuth.isBiometricAvailable() else {
            throw SecureStorageError.biometricNotAvailable
        }
        
        // Authenticate with biometrics
        try await biometricAuth.authenticate(reason: "Access secure data")
        
        guard let encryptedData = UserDefaults.standard.data(forKey: key) else {
            throw SecureStorageError.dataNotFound
        }
        
        let keyData = try keychainManager.retrieveKey(forKey: "\(key)_biometric_key")
        let encryptionKey = SymmetricKey(data: keyData)
        
        return try encryption.decrypt(encryptedData, with: encryptionKey)
    }
    
    /// Store data with expiration
    public func store(_ data: Data, forKey key: String, expiresAt date: Date) throws {
        let expirationData = try JSONEncoder().encode(date)
        let combinedData = data + expirationData
        
        try store(combinedData, forKey: key)
    }
    
    /// Retrieve data with expiration check
    public func retrieve(forKey key: String, checkExpiration: Bool = true) throws -> Data {
        let data = try retrieve(forKey: key)
        
        if checkExpiration {
            // Check if data has expiration
            let expirationSize = MemoryLayout<Date>.size
            guard data.count > expirationSize else {
                return data
            }
            
            let expirationData = data.suffix(expirationSize)
            let expirationDate = try JSONDecoder().decode(Date.self, from: expirationData)
            
            guard Date() < expirationDate else {
                try delete(forKey: key)
                throw SecureStorageError.dataExpired
            }
            
            return data.dropLast(expirationSize)
        }
        
        return data
    }
    
    /// Clear all stored data
    public func clearAll() throws {
        let keys = UserDefaults.standard.dictionaryRepresentation().keys.filter { key in
            key.hasPrefix("secure_") || key.hasSuffix("_key")
        }
        
        for key in keys {
            UserDefaults.standard.removeObject(forKey: key)
        }
        
        try keychainManager.clearAll()
    }
    
    /// Get all stored keys
    public func getAllKeys() -> [String] {
        return UserDefaults.standard.dictionaryRepresentation().keys.filter { key in
            key.hasPrefix("secure_") && !key.hasSuffix("_key")
        }.map { $0 }
    }
    
    /// Get storage statistics
    public func getStorageStats() -> StorageStats {
        let keys = getAllKeys()
        var totalSize: Int = 0
        
        for key in keys {
            if let data = UserDefaults.standard.data(forKey: key) {
                totalSize += data.count
            }
        }
        
        return StorageStats(
            totalKeys: keys.count,
            totalSize: totalSize,
            averageSize: keys.isEmpty ? 0 : totalSize / keys.count
        )
    }
    
    /// Migrate data to new encryption
    public func migrateData(forKey key: String, newEncryptionKey: SymmetricKey) throws {
        let oldData = try retrieve(forKey: key)
        try storeSensitive(oldData, forKey: key, encryptionKey: newEncryptionKey)
    }
    
    /// Backup encrypted data
    public func backup(forKey key: String) throws -> Data {
        guard let encryptedData = UserDefaults.standard.data(forKey: key) else {
            throw SecureStorageError.dataNotFound
        }
        
        let keyData = try keychainManager.retrieveKey(forKey: "\(key)_key")
        
        var backupData = Data()
        backupData.append(keyData)
        backupData.append(encryptedData)
        
        return backupData
    }
    
    /// Restore encrypted data from backup
    public func restore(_ backupData: Data, forKey key: String) throws {
        let keySize = 32 // AES-256 key size
        guard backupData.count > keySize else {
            throw SecureStorageError.invalidBackupData
        }
        
        let keyData = backupData.prefix(keySize)
        let encryptedData = backupData.dropFirst(keySize)
        
        try keychainManager.storeKey(keyData, forKey: "\(key)_key")
        UserDefaults.standard.set(encryptedData, forKey: key)
    }
}

// MARK: - Supporting Types

/// Storage statistics
public struct StorageStats {
    public let totalKeys: Int
    public let totalSize: Int
    public let averageSize: Int
}

/// Secure storage errors
public enum SecureStorageError: LocalizedError {
    case dataNotFound
    case invalidData
    case encryptionFailed
    case decryptionFailed
    case biometricNotAvailable
    case dataExpired
    case invalidBackupData
    case migrationFailed
    case keyNotFound
    
    public var errorDescription: String? {
        switch self {
        case .dataNotFound:
            return "Encrypted data not found"
        case .invalidData:
            return "Invalid data format"
        case .encryptionFailed:
            return "Failed to encrypt data"
        case .decryptionFailed:
            return "Failed to decrypt data"
        case .biometricNotAvailable:
            return "Biometric authentication not available"
        case .dataExpired:
            return "Stored data has expired"
        case .invalidBackupData:
            return "Invalid backup data format"
        case .migrationFailed:
            return "Failed to migrate data"
        case .keyNotFound:
            return "Encryption key not found"
        }
    }
} 