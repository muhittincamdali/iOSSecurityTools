import Foundation
import iOSSecurityTools

// MARK: - Data Encryption Example
// Comprehensive example demonstrating data encryption features

class DataEncryptionExample {
    
    // MARK: - Properties
    private let encryptionManager = DataEncryptionManager()
    private let keyManager = KeyManagementManager()
    private let keychainManager = KeychainManager()
    
    // MARK: - Initialization
    init() {
        setupDataEncryption()
    }
    
    // MARK: - Setup
    private func setupDataEncryption() {
        // Configure encryption
        let encryptionConfig = EncryptionConfiguration()
        encryptionConfig.algorithm = .aes256
        encryptionConfig.mode = .gcm
        encryptionConfig.keySize = 256
        encryptionConfig.enableKeyRotation = true
        encryptionConfig.enableAuthenticatedEncryption = true
        
        encryptionManager.configure(encryptionConfig)
        
        // Configure key management
        let keyConfig = KeyManagementConfiguration()
        keyConfig.enableKeyRotation = true
        keyConfig.enableKeyBackup = true
        keyConfig.enableKeyRecovery = true
        keyConfig.keyRotationInterval = 30 // days
        
        keyManager.configure(keyConfig)
        
        // Configure keychain
        let keychainConfig = KeychainConfiguration()
        keychainConfig.enableEncryption = true
        keychainConfig.enableAccessControl = true
        keychainConfig.enableBiometricProtection = true
        
        keychainManager.configure(keychainConfig)
    }
    
    // MARK: - Basic Data Encryption
    func encryptSensitiveData() {
        print("🔐 Starting data encryption...")
        
        let sensitiveData = "Highly sensitive information that needs protection"
        
        encryptionManager.encrypt(data: sensitiveData) { result in
            switch result {
            case .success(let encryptedData):
                print("✅ Data encryption successful")
                print("Original data: \(sensitiveData)")
                print("Encrypted data: \(encryptedData.encrypted)")
                print("IV: \(encryptedData.iv)")
                print("Tag: \(encryptedData.tag)")
                print("Algorithm: \(encryptedData.algorithm)")
                print("Key ID: \(encryptedData.keyId)")
                
                // Store encrypted data securely
                self.storeEncryptedData(encryptedData)
                
            case .failure(let error):
                print("❌ Data encryption failed: \(error)")
            }
        }
    }
    
    // MARK: - Data Decryption
    func decryptData(_ encryptedData: EncryptedData) {
        print("🔓 Decrypting data...")
        
        encryptionManager.decrypt(encryptedData: encryptedData) { result in
            switch result {
            case .success(let decryptedData):
                print("✅ Data decryption successful")
                print("Decrypted data: \(decryptedData)")
                
            case .failure(let error):
                print("❌ Data decryption failed: \(error)")
            }
        }
    }
    
    // MARK: - Advanced Encryption Features
    func performAdvancedEncryption() {
        print("🔐 Performing advanced encryption...")
        
        // Generate encryption key
        keyManager.generateKey(algorithm: .aes256) { [weak self] result in
            switch result {
            case .success(let key):
                print("✅ Encryption key generated")
                print("Key ID: \(key.keyId)")
                print("Algorithm: \(key.algorithm)")
                print("Key size: \(key.keySize)")
                
                self?.encryptWithCustomKey(key)
                
            case .failure(let error):
                print("❌ Key generation failed: \(error)")
            }
        }
    }
    
    private func encryptWithCustomKey(_ key: EncryptionKey) {
        let sensitiveData = "Data encrypted with custom key"
        
        encryptionManager.encrypt(data: sensitiveData, using: key) { result in
            switch result {
            case .success(let encryptedData):
                print("✅ Custom key encryption successful")
                print("Key ID: \(encryptedData.keyId)")
                print("Encrypted data: \(encryptedData.encrypted)")
                
                // Store key securely
                self.storeEncryptionKey(key)
                
            case .failure(let error):
                print("❌ Custom key encryption failed: \(error)")
            }
        }
    }
    
    // MARK: - Key Management
    func rotateEncryptionKeys() {
        print("🔄 Rotating encryption keys...")
        
        keyManager.rotateKeys(algorithm: .aes256) { result in
            switch result {
            case .success(let rotation):
                print("✅ Key rotation successful")
                print("Old key ID: \(rotation.oldKeyId)")
                print("New key ID: \(rotation.newKeyId)")
                print("Rotation time: \(rotation.rotationTime)")
                
                // Re-encrypt data with new key
                self.reEncryptDataWithNewKey(rotation.newKeyId)
                
            case .failure(let error):
                print("❌ Key rotation failed: \(error)")
            }
        }
    }
    
    private func reEncryptDataWithNewKey(_ newKeyId: String) {
        print("🔐 Re-encrypting data with new key...")
        
        // Retrieve old encrypted data
        retrieveEncryptedData { oldEncryptedData in
            // Decrypt with old key
            self.decryptData(oldEncryptedData) { decryptedData in
                // Encrypt with new key
                self.encryptDataWithNewKey(decryptedData, newKeyId: newKeyId)
            }
        }
    }
    
    // MARK: - Secure Storage
    func storeEncryptedData(_ encryptedData: EncryptedData) {
        print("🗝️ Storing encrypted data securely...")
        
        let secureItem = KeychainItem(
            service: "com.example.app.encryption",
            account: "encrypted_data",
            data: encryptedData.encrypted,
            accessControl: .userPresence
        )
        
        keychainManager.store(secureItem) { result in
            switch result {
            case .success:
                print("✅ Encrypted data stored securely")
                
            case .failure(let error):
                print("❌ Secure storage failed: \(error)")
            }
        }
    }
    
    func storeEncryptionKey(_ key: EncryptionKey) {
        print("🗝️ Storing encryption key securely...")
        
        let keyData = try? JSONEncoder().encode(key)
        
        let secureItem = KeychainItem(
            service: "com.example.app.encryption",
            account: "encryption_key_\(key.keyId)",
            data: keyData ?? Data(),
            accessControl: .userPresence
        )
        
        keychainManager.store(secureItem) { result in
            switch result {
            case .success:
                print("✅ Encryption key stored securely")
                
            case .failure(let error):
                print("❌ Key storage failed: \(error)")
            }
        }
    }
    
    // MARK: - Backup and Recovery
    func backupEncryptionKeys() {
        print("💾 Backing up encryption keys...")
        
        keyManager.backupKeys { result in
            switch result {
            case .success(let backup):
                print("✅ Keys backed up successfully")
                print("Backup ID: \(backup.backupId)")
                print("Key count: \(backup.keyCount)")
                print("Backup size: \(backup.size) bytes")
                
            case .failure(let error):
                print("❌ Key backup failed: \(error)")
            }
        }
    }
    
    func recoverEncryptionKeys(backupId: String) {
        print("🔄 Recovering encryption keys...")
        
        keyManager.recoverKeys(backupId: backupId) { result in
            switch result {
            case .success:
                print("✅ Keys recovered successfully")
                
            case .failure(let error):
                print("❌ Key recovery failed: \(error)")
            }
        }
    }
    
    // MARK: - Performance Testing
    func testEncryptionPerformance() {
        print("⚡ Testing encryption performance...")
        
        let testData = "Performance test data" * 1000 // Large data
        let iterations = 10
        
        var totalTime: TimeInterval = 0
        
        for i in 1...iterations {
            let startTime = CFAbsoluteTimeGetCurrent()
            
            encryptionManager.encrypt(data: testData) { result in
                let endTime = CFAbsoluteTimeGetCurrent()
                let duration = endTime - startTime
                totalTime += duration
                
                switch result {
                case .success:
                    print("✅ Iteration \(i): \(String(format: "%.3f", duration))s")
                    
                    if i == iterations {
                        let averageTime = totalTime / Double(iterations)
                        print("📊 Average encryption time: \(String(format: "%.3f", averageTime))s")
                        print("📊 Total time: \(String(format: "%.3f", totalTime))s")
                    }
                    
                case .failure(let error):
                    print("❌ Iteration \(i) failed: \(error)")
                }
            }
        }
    }
    
    // MARK: - Security Validation
    func validateEncryptionSecurity() {
        print("🔍 Validating encryption security...")
        
        // Test with different data types
        let testCases = [
            "Simple text",
            "Text with special characters: !@#$%^&*()",
            "Unicode text: 🚀🔐💻",
            "Large data: " + String(repeating: "A", count: 10000)
        ]
        
        for (index, testData) in testCases.enumerated() {
            encryptionManager.encrypt(data: testData) { [weak self] result in
                switch result {
                case .success(let encryptedData):
                    print("✅ Test case \(index + 1): Encryption successful")
                    print("   Original size: \(testData.count) characters")
                    print("   Encrypted size: \(encryptedData.encrypted.count) bytes")
                    
                    // Test decryption
                    self?.encryptionManager.decrypt(encryptedData: encryptedData) { result in
                        switch result {
                        case .success(let decryptedData):
                            XCTAssertEqual(decryptedData, testData)
                            print("✅ Test case \(index + 1): Decryption successful")
                            
                        case .failure(let error):
                            print("❌ Test case \(index + 1): Decryption failed: \(error)")
                        }
                    }
                    
                case .failure(let error):
                    print("❌ Test case \(index + 1): Encryption failed: \(error)")
                }
            }
        }
    }
    
    // MARK: - Helper Methods
    private func retrieveEncryptedData(completion: @escaping (EncryptedData) -> Void) {
        // Simulate retrieving encrypted data
        let encryptedData = EncryptedData(
            encrypted: Data(),
            iv: Data(),
            tag: Data(),
            algorithm: .aes256,
            keyId: "test_key"
        )
        completion(encryptedData)
    }
    
    private func decryptData(_ encryptedData: EncryptedData, completion: @escaping (String) -> Void) {
        // Simulate decryption
        let decryptedData = "Decrypted sensitive data"
        completion(decryptedData)
    }
    
    private func encryptDataWithNewKey(_ data: String, newKeyId: String) {
        print("✅ Data re-encrypted with new key: \(newKeyId)")
    }
    
    // MARK: - Example Usage
    func runDataEncryptionExample() {
        print("🔐 Data Encryption Example")
        print("==========================")
        
        // Perform basic encryption
        encryptSensitiveData()
        
        // Perform advanced encryption
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            self.performAdvancedEncryption()
        }
        
        // Test performance
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
            self.testEncryptionPerformance()
        }
        
        // Validate security
        DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) {
            self.validateEncryptionSecurity()
        }
        
        // Rotate keys
        DispatchQueue.main.asyncAfter(deadline: .now() + 8.0) {
            self.rotateEncryptionKeys()
        }
        
        // Backup keys
        DispatchQueue.main.asyncAfter(deadline: .now() + 10.0) {
            self.backupEncryptionKeys()
        }
    }
}

// MARK: - Usage Example
extension DataEncryptionExample {
    
    static func runExample() {
        let example = DataEncryptionExample()
        example.runDataEncryptionExample()
    }
}

// MARK: - Example Usage
// Uncomment to run the example
// DataEncryptionExample.runExample() 