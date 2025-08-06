import Foundation
import iOSSecurityTools

// MARK: - Secure Storage Example
// Comprehensive example demonstrating secure storage using keychain

class SecureStorageExample {
    
    // MARK: - Properties
    private let keychainManager = KeychainManager()
    private let accessControlManager = KeychainAccessControlManager()
    private let backupManager = KeychainBackupManager()
    
    // MARK: - Initialization
    init() {
        setupSecureStorage()
    }
    
    // MARK: - Setup
    private func setupSecureStorage() {
        // Configure keychain
        let keychainConfig = KeychainConfiguration()
        keychainConfig.enableEncryption = true
        keychainConfig.enableAccessControl = true
        keychainConfig.enableBiometricProtection = true
        keychainConfig.enableCloudSync = true
        keychainConfig.enableBackupProtection = true
        
        keychainManager.configure(keychainConfig)
        
        // Configure access control
        let accessConfig = AccessControlConfiguration()
        accessConfig.enableBiometricProtection = true
        accessConfig.enableDevicePasscode = true
        accessConfig.enableUserPresence = true
        accessConfig.enableApplicationPassword = true
        
        accessControlManager.configure(accessConfig)
        
        // Configure backup
        let backupConfig = BackupConfiguration()
        backupConfig.enableEncryptedBackup = true
        backupConfig.enableBackupVerification = true
        backupConfig.enableBackupRecovery = true
        
        backupManager.configure(backupConfig)
    }
    
    // MARK: - Basic Secure Storage
    func storeSecureCredentials() {
        print("🗝️ Storing secure credentials...")
        
        let credentials = [
            ("user@example.com", "secure_password_123"),
            ("admin@example.com", "admin_secure_password"),
            ("api_key", "sk-1234567890abcdef"),
            ("access_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        ]
        
        for (account, password) in credentials {
            let secureItem = KeychainItem(
                service: "com.example.app.credentials",
                account: account,
                data: password,
                accessControl: .userPresence
            )
            
            keychainManager.store(secureItem) { result in
                switch result {
                case .success:
                    print("✅ Credential stored: \(account)")
                    
                case .failure(let error):
                    print("❌ Credential storage failed for \(account): \(error)")
                }
            }
        }
    }
    
    func retrieveSecureCredentials() {
        print("🗝️ Retrieving secure credentials...")
        
        let accounts = ["user@example.com", "admin@example.com", "api_key", "access_token"]
        
        for account in accounts {
            keychainManager.retrieve(
                service: "com.example.app.credentials",
                account: account
            ) { result in
                switch result {
                case .success(let item):
                    print("✅ Credential retrieved: \(account)")
                    print("   Data: \(String(repeating: "*", count: item.data.count))")
                    print("   Access control: \(item.accessControl)")
                    
                case .failure(let error):
                    print("❌ Credential retrieval failed for \(account): \(error)")
                }
            }
        }
    }
    
    // MARK: - Advanced Access Control
    func storeWithAdvancedAccessControl() {
        print("🔐 Storing with advanced access control...")
        
        // Create access control with biometric protection
        let biometricAccessControl = KeychainAccessControl(
            protection: .userPresence,
            accessibility: .whenUnlocked,
            sharing: .private
        )
        
        let sensitiveData = "Highly sensitive data requiring biometric authentication"
        
        let secureItem = KeychainItem(
            service: "com.example.app.sensitive",
            account: "sensitive_data",
            data: sensitiveData,
            accessControl: .userPresence
        )
        
        keychainManager.storeWithAccessControl(
            item: secureItem,
            accessControl: biometricAccessControl
        ) { result in
            switch result {
            case .success:
                print("✅ Sensitive data stored with biometric protection")
                
            case .failure(let error):
                print("❌ Sensitive data storage failed: \(error)")
            }
        }
    }
    
    // MARK: - Cryptographic Key Storage
    func storeCryptographicKeys() {
        print("🔑 Storing cryptographic keys...")
        
        let keys = [
            ("encryption_key", "aes256_key_data"),
            ("signing_key", "rsa2048_key_data"),
            ("hmac_key", "sha256_key_data"),
            ("derived_key", "pbkdf2_key_data")
        ]
        
        for (keyName, keyData) in keys {
            let keyItem = KeychainKeyItem(
                service: "com.example.app.keys",
                account: keyName,
                key: keyData,
                accessControl: .userPresence
            )
            
            keychainManager.storeKey(keyItem) { result in
                switch result {
                case .success:
                    print("✅ Cryptographic key stored: \(keyName)")
                    
                case .failure(let error):
                    print("❌ Key storage failed for \(keyName): \(error)")
                }
            }
        }
    }
    
    func retrieveCryptographicKeys() {
        print("🔑 Retrieving cryptographic keys...")
        
        let keyNames = ["encryption_key", "signing_key", "hmac_key", "derived_key"]
        
        for keyName in keyNames {
            keychainManager.retrieveKey(
                service: "com.example.app.keys",
                account: keyName
            ) { result in
                switch result {
                case .success(let key):
                    print("✅ Cryptographic key retrieved: \(keyName)")
                    print("   Key size: \(key.keySize) bits")
                    print("   Algorithm: \(key.algorithm)")
                    
                case .failure(let error):
                    print("❌ Key retrieval failed for \(keyName): \(error)")
                }
            }
        }
    }
    
    // MARK: - Certificate Storage
    func storeCertificates() {
        print("📜 Storing certificates...")
        
        let certificates = [
            ("client_cert", "client_certificate_data"),
            ("ca_cert", "ca_certificate_data"),
            ("intermediate_cert", "intermediate_certificate_data")
        ]
        
        for (certName, certData) in certificates {
            let certItem = KeychainCertificateItem(
                service: "com.example.app.certificates",
                account: certName,
                certificate: certData,
                accessControl: .userPresence
            )
            
            keychainManager.storeCertificate(certItem) { result in
                switch result {
                case .success:
                    print("✅ Certificate stored: \(certName)")
                    
                case .failure(let error):
                    print("❌ Certificate storage failed for \(certName): \(error)")
                }
            }
        }
    }
    
    // MARK: - Backup and Recovery
    func backupKeychainData() {
        print("💾 Backing up keychain data...")
        
        backupManager.createBackup { result in
            switch result {
            case .success(let backup):
                print("✅ Keychain backup created")
                print("   Backup ID: \(backup.backupId)")
                print("   Backup size: \(backup.size) bytes")
                print("   Item count: \(backup.itemCount)")
                print("   Created: \(backup.createdDate)")
                
            case .failure(let error):
                print("❌ Keychain backup failed: \(error)")
            }
        }
    }
    
    func restoreKeychainData(backupId: String) {
        print("🔄 Restoring keychain data...")
        
        backupManager.restoreFromBackup(backupId: backupId) { result in
            switch result {
            case .success:
                print("✅ Keychain data restored successfully")
                
            case .failure(let error):
                print("❌ Keychain restore failed: \(error)")
            }
        }
    }
    
    // MARK: - Cloud Sync
    func syncKeychainToCloud() {
        print("☁️ Syncing keychain to cloud...")
        
        let cloudSync = KeychainCloudSync()
        
        let syncConfig = CloudSyncConfiguration()
        syncConfig.enableiCloudSync = true
        syncConfig.enableMultiDeviceSync = true
        syncConfig.enableConflictResolution = true
        syncConfig.enableEncryptedSync = true
        
        cloudSync.configure(syncConfig)
        
        cloudSync.syncKeychain { result in
            switch result {
            case .success:
                print("✅ Keychain synced to cloud successfully")
                
            case .failure(let error):
                print("❌ Cloud sync failed: \(error)")
            }
        }
    }
    
    // MARK: - Data Management
    func updateSecureData() {
        print("🔄 Updating secure data...")
        
        let updatedItem = KeychainItem(
            service: "com.example.app.credentials",
            account: "user@example.com",
            data: "updated_secure_password_456",
            accessControl: .userPresence
        )
        
        keychainManager.update(updatedItem) { result in
            switch result {
            case .success:
                print("✅ Secure data updated successfully")
                
            case .failure(let error):
                print("❌ Data update failed: \(error)")
            }
        }
    }
    
    func deleteSecureData() {
        print("🗑️ Deleting secure data...")
        
        let itemsToDelete = [
            ("com.example.app.credentials", "user@example.com"),
            ("com.example.app.keys", "encryption_key"),
            ("com.example.app.certificates", "client_cert")
        ]
        
        for (service, account) in itemsToDelete {
            keychainManager.delete(
                service: service,
                account: account
            ) { result in
                switch result {
                case .success:
                    print("✅ Secure data deleted: \(account)")
                    
                case .failure(let error):
                    print("❌ Data deletion failed for \(account): \(error)")
                }
            }
        }
    }
    
    // MARK: - Security Validation
    func validateKeychainSecurity() {
        print("🔍 Validating keychain security...")
        
        // Test different access control levels
        let accessLevels = [
            (.userPresence, "User Presence"),
            (.biometric, "Biometric"),
            (.devicePasscode, "Device Passcode"),
            (.applicationPassword, "Application Password")
        ]
        
        for (level, description) in accessLevels {
            let testItem = KeychainItem(
                service: "com.example.app.test",
                account: "test_\(description.lowercased().replacingOccurrences(of: " ", with: "_"))",
                data: "test_data",
                accessControl: level
            )
            
            keychainManager.store(testItem) { result in
                switch result {
                case .success:
                    print("✅ \(description) access control: Success")
                    
                case .failure(let error):
                    print("❌ \(description) access control: \(error)")
                }
            }
        }
    }
    
    // MARK: - Performance Testing
    func testKeychainPerformance() {
        print("⚡ Testing keychain performance...")
        
        let iterations = 100
        var totalStoreTime: TimeInterval = 0
        var totalRetrieveTime: TimeInterval = 0
        
        for i in 1...iterations {
            let testData = "Performance test data \(i)"
            
            // Test storage performance
            let storeStartTime = CFAbsoluteTimeGetCurrent()
            
            let testItem = KeychainItem(
                service: "com.example.app.performance",
                account: "test_\(i)",
                data: testData,
                accessControl: .userPresence
            )
            
            keychainManager.store(testItem) { result in
                let storeEndTime = CFAbsoluteTimeGetCurrent()
                let storeDuration = storeEndTime - storeStartTime
                totalStoreTime += storeDuration
                
                switch result {
                case .success:
                    // Test retrieval performance
                    let retrieveStartTime = CFAbsoluteTimeGetCurrent()
                    
                    self.keychainManager.retrieve(
                        service: "com.example.app.performance",
                        account: "test_\(i)"
                    ) { result in
                        let retrieveEndTime = CFAbsoluteTimeGetCurrent()
                        let retrieveDuration = retrieveEndTime - retrieveStartTime
                        totalRetrieveTime += retrieveDuration
                        
                        switch result {
                        case .success:
                            if i == iterations {
                                let avgStoreTime = totalStoreTime / Double(iterations)
                                let avgRetrieveTime = totalRetrieveTime / Double(iterations)
                                
                                print("📊 Performance Results:")
                                print("   Average store time: \(String(format: "%.3f", avgStoreTime))s")
                                print("   Average retrieve time: \(String(format: "%.3f", avgRetrieveTime))s")
                                print("   Total operations: \(iterations * 2)")
                            }
                            
                        case .failure(let error):
                            print("❌ Retrieval failed: \(error)")
                        }
                    }
                    
                case .failure(let error):
                    print("❌ Storage failed: \(error)")
                }
            }
        }
    }
    
    // MARK: - Example Usage
    func runSecureStorageExample() {
        print("🗝️ Secure Storage Example")
        print("=========================")
        
        // Store secure credentials
        storeSecureCredentials()
        
        // Store with advanced access control
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            self.storeWithAdvancedAccessControl()
        }
        
        // Store cryptographic keys
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
            self.storeCryptographicKeys()
        }
        
        // Store certificates
        DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) {
            self.storeCertificates()
        }
        
        // Retrieve stored data
        DispatchQueue.main.asyncAfter(deadline: .now() + 8.0) {
            self.retrieveSecureCredentials()
            self.retrieveCryptographicKeys()
        }
        
        // Backup keychain data
        DispatchQueue.main.asyncAfter(deadline: .now() + 10.0) {
            self.backupKeychainData()
        }
        
        // Sync to cloud
        DispatchQueue.main.asyncAfter(deadline: .now() + 12.0) {
            self.syncKeychainToCloud()
        }
        
        // Test performance
        DispatchQueue.main.asyncAfter(deadline: .now() + 14.0) {
            self.testKeychainPerformance()
        }
        
        // Validate security
        DispatchQueue.main.asyncAfter(deadline: .now() + 16.0) {
            self.validateKeychainSecurity()
        }
    }
}

// MARK: - Usage Example
extension SecureStorageExample {
    
    static func runExample() {
        let example = SecureStorageExample()
        example.runSecureStorageExample()
    }
}

// MARK: - Example Usage
// Uncomment to run the example
// SecureStorageExample.runExample() 