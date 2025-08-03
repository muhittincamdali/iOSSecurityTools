import Foundation
import CryptoKit

/// Automatic key rotation utilities
public class KeyRotation {
    
    // MARK: - Singleton
    public static let shared = KeyRotation()
    
    // MARK: - Private Properties
    private let keychainManager = KeychainManager.shared
    private let keyGenerator = KeyGenerator.shared
    private let secureStorage = SecureStorage.shared
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Rotate encryption key
    public func rotateEncryptionKey(forKey keyName: String) throws -> SymmetricKey {
        // Generate new key
        let newKey = try keyGenerator.generateAESKey()
        
        // Store new key in Keychain
        try keychainManager.storeKey(newKey.withUnsafeBytes { Data($0) }, forKey: "\(keyName)_rotated")
        
        // Update key metadata
        let metadata = KeyMetadata(
            keyName: keyName,
            rotationDate: Date(),
            keySize: newKey.bitCount,
            algorithm: "AES-256-GCM"
        )
        
        try secureStorage.store(metadata, forKey: "\(keyName)_metadata")
        
        return newKey
    }
    
    /// Rotate RSA key pair
    public func rotateRSAKeyPair(forKey keyName: String) throws -> RSAKeyPair {
        // Generate new key pair
        let newKeyPair = try keyGenerator.generateRSAKeyPair()
        
        // Store new keys in Keychain
        try keychainManager.storeKey(newKeyPair.privateKey.rawRepresentation, forKey: "\(keyName)_private_rotated")
        try keychainManager.storeKey(newKeyPair.publicKey.rawRepresentation, forKey: "\(keyName)_public_rotated")
        
        // Update key metadata
        let metadata = KeyMetadata(
            keyName: keyName,
            rotationDate: Date(),
            keySize: 2048,
            algorithm: "RSA-2048"
        )
        
        try secureStorage.store(metadata, forKey: "\(keyName)_metadata")
        
        return newKeyPair
    }
    
    /// Rotate EC key pair
    public func rotateECKeyPair(forKey keyName: String) throws -> ECKeyPair {
        // Generate new key pair
        let newKeyPair = try keyGenerator.generateECKeyPair()
        
        // Store new keys in Keychain
        try keychainManager.storeKey(newKeyPair.privateKey.rawRepresentation, forKey: "\(keyName)_private_rotated")
        try keychainManager.storeKey(newKeyPair.publicKey.rawRepresentation, forKey: "\(keyName)_public_rotated")
        
        // Update key metadata
        let metadata = KeyMetadata(
            keyName: keyName,
            rotationDate: Date(),
            keySize: 256,
            algorithm: "EC-P-256"
        )
        
        try secureStorage.store(metadata, forKey: "\(keyName)_metadata")
        
        return newKeyPair
    }
    
    /// Migrate data to new key
    public func migrateDataToNewKey(dataKey: String, newKey: SymmetricKey) throws {
        // Retrieve old data
        let oldData = try secureStorage.retrieve(forKey: dataKey)
        
        // Re-encrypt with new key
        try secureStorage.storeSensitive(oldData, forKey: dataKey, encryptionKey: newKey)
        
        // Update migration metadata
        let migrationMetadata = MigrationMetadata(
            dataKey: dataKey,
            migrationDate: Date(),
            oldKeySize: 256,
            newKeySize: newKey.bitCount
        )
        
        try secureStorage.store(migrationMetadata, forKey: "\(dataKey)_migration")
    }
    
    /// Schedule key rotation
    public func scheduleKeyRotation(forKey keyName: String, rotationInterval: TimeInterval) throws {
        let schedule = RotationSchedule(
            keyName: keyName,
            rotationInterval: rotationInterval,
            nextRotationDate: Date().addingTimeInterval(rotationInterval),
            isActive: true
        )
        
        try secureStorage.store(schedule, forKey: "\(keyName)_schedule")
    }
    
    /// Check if key rotation is due
    public func isKeyRotationDue(forKey keyName: String) -> Bool {
        guard let schedule: RotationSchedule = try? secureStorage.retrieve(forKey: "\(keyName)_schedule", as: RotationSchedule.self) else {
            return false
        }
        
        return Date() >= schedule.nextRotationDate
    }
    
    /// Get next rotation date
    public func getNextRotationDate(forKey keyName: String) -> Date? {
        guard let schedule: RotationSchedule = try? secureStorage.retrieve(forKey: "\(keyName)_schedule", as: RotationSchedule.self) else {
            return nil
        }
        
        return schedule.nextRotationDate
    }
    
    /// Update rotation schedule
    public func updateRotationSchedule(forKey keyName: String, rotationInterval: TimeInterval) throws {
        guard let schedule: RotationSchedule = try? secureStorage.retrieve(forKey: "\(keyName)_schedule", as: RotationSchedule.self) else {
            try scheduleKeyRotation(forKey: keyName, rotationInterval: rotationInterval)
            return
        }
        
        let updatedSchedule = RotationSchedule(
            keyName: keyName,
            rotationInterval: rotationInterval,
            nextRotationDate: Date().addingTimeInterval(rotationInterval),
            isActive: schedule.isActive
        )
        
        try secureStorage.store(updatedSchedule, forKey: "\(keyName)_schedule")
    }
    
    /// Disable key rotation
    public func disableKeyRotation(forKey keyName: String) throws {
        guard let schedule: RotationSchedule = try? secureStorage.retrieve(forKey: "\(keyName)_schedule", as: RotationSchedule.self) else {
            return
        }
        
        let disabledSchedule = RotationSchedule(
            keyName: keyName,
            rotationInterval: schedule.rotationInterval,
            nextRotationDate: schedule.nextRotationDate,
            isActive: false
        )
        
        try secureStorage.store(disabledSchedule, forKey: "\(keyName)_schedule")
    }
    
    /// Enable key rotation
    public func enableKeyRotation(forKey keyName: String) throws {
        guard let schedule: RotationSchedule = try? secureStorage.retrieve(forKey: "\(keyName)_schedule", as: RotationSchedule.self) else {
            return
        }
        
        let enabledSchedule = RotationSchedule(
            keyName: keyName,
            rotationInterval: schedule.rotationInterval,
            nextRotationDate: Date().addingTimeInterval(schedule.rotationInterval),
            isActive: true
        )
        
        try secureStorage.store(enabledSchedule, forKey: "\(keyName)_schedule")
    }
    
    /// Get key metadata
    public func getKeyMetadata(forKey keyName: String) -> KeyMetadata? {
        return try? secureStorage.retrieve(forKey: "\(keyName)_metadata", as: KeyMetadata.self)
    }
    
    /// Get migration metadata
    public func getMigrationMetadata(forDataKey dataKey: String) -> MigrationMetadata? {
        return try? secureStorage.retrieve(forKey: "\(dataKey)_migration", as: MigrationMetadata.self)
    }
    
    /// Get rotation schedule
    public func getRotationSchedule(forKey keyName: String) -> RotationSchedule? {
        return try? secureStorage.retrieve(forKey: "\(keyName)_schedule", as: RotationSchedule.self)
    }
    
    /// Get all rotation schedules
    public func getAllRotationSchedules() -> [RotationSchedule] {
        let keys = secureStorage.getAllKeys()
        var schedules: [RotationSchedule] = []
        
        for key in keys where key.hasSuffix("_schedule") {
            if let schedule: RotationSchedule = try? secureStorage.retrieve(forKey: key, as: RotationSchedule.self) {
                schedules.append(schedule)
            }
        }
        
        return schedules
    }
    
    /// Get due rotations
    public func getDueRotations() -> [String] {
        let schedules = getAllRotationSchedules()
        var dueKeys: [String] = []
        
        for schedule in schedules {
            if schedule.isActive && Date() >= schedule.nextRotationDate {
                dueKeys.append(schedule.keyName)
            }
        }
        
        return dueKeys
    }
    
    /// Perform automatic rotation
    public func performAutomaticRotation() throws {
        let dueKeys = getDueRotations()
        
        for keyName in dueKeys {
            try rotateEncryptionKey(forKey: keyName)
            
            // Update schedule
            if let schedule = getRotationSchedule(forKey: keyName) {
                let updatedSchedule = RotationSchedule(
                    keyName: keyName,
                    rotationInterval: schedule.rotationInterval,
                    nextRotationDate: Date().addingTimeInterval(schedule.rotationInterval),
                    isActive: schedule.isActive
                )
                
                try secureStorage.store(updatedSchedule, forKey: "\(keyName)_schedule")
            }
        }
    }
    
    /// Backup old keys
    public func backupOldKeys(forKey keyName: String) throws -> Data {
        var backupData = Data()
        
        // Backup old encryption key
        if let oldKeyData = try? keychainManager.retrieveKey(forKey: keyName) {
            backupData.append(oldKeyData)
        }
        
        // Backup old RSA keys
        if let oldPrivateKeyData = try? keychainManager.retrieveKey(forKey: "\(keyName)_private") {
            backupData.append(oldPrivateKeyData)
        }
        
        if let oldPublicKeyData = try? keychainManager.retrieveKey(forKey: "\(keyName)_public") {
            backupData.append(oldPublicKeyData)
        }
        
        return backupData
    }
    
    /// Restore old keys from backup
    public func restoreOldKeys(from backupData: Data, forKey keyName: String) throws {
        // This is a simplified implementation
        // In production, you'd need proper parsing of backup data
        
        let keySize = 32 // AES-256 key size
        guard backupData.count >= keySize else {
            throw KeyRotationError.invalidBackupData
        }
        
        let keyData = backupData.prefix(keySize)
        try keychainManager.storeKey(keyData, forKey: keyName)
    }
    
    /// Clean up old keys
    public func cleanupOldKeys(forKey keyName: String) throws {
        // Remove old keys from Keychain
        try? keychainManager.deleteKey(forKey: keyName)
        try? keychainManager.deleteKey(forKey: "\(keyName)_private")
        try? keychainManager.deleteKey(forKey: "\(keyName)_public")
        
        // Remove old metadata
        try? secureStorage.delete(forKey: "\(keyName)_metadata")
    }
}

// MARK: - Supporting Types

/// Key metadata
public struct KeyMetadata: Codable {
    public let keyName: String
    public let rotationDate: Date
    public let keySize: Int
    public let algorithm: String
}

/// Migration metadata
public struct MigrationMetadata: Codable {
    public let dataKey: String
    public let migrationDate: Date
    public let oldKeySize: Int
    public let newKeySize: Int
}

/// Rotation schedule
public struct RotationSchedule: Codable {
    public let keyName: String
    public let rotationInterval: TimeInterval
    public let nextRotationDate: Date
    public let isActive: Bool
}

/// Key rotation errors
public enum KeyRotationError: LocalizedError {
    case keyNotFound
    case invalidBackupData
    case rotationFailed
    case migrationFailed
    case scheduleNotFound
    
    public var errorDescription: String? {
        switch self {
        case .keyNotFound:
            return "Key not found for rotation"
        case .invalidBackupData:
            return "Invalid backup data format"
        case .rotationFailed:
            return "Key rotation failed"
        case .migrationFailed:
            return "Data migration failed"
        case .scheduleNotFound:
            return "Rotation schedule not found"
        }
    }
} 