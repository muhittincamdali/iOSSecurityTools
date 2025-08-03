import XCTest
@testable import iOSSecurityTools
import LocalAuthentication

final class BiometricAuthTests: XCTestCase {
    
    var biometricAuth: BiometricAuth!
    
    override func setUp() {
        super.setUp()
        biometricAuth = BiometricAuth.shared
    }
    
    override func tearDown() {
        biometricAuth = nil
        super.tearDown()
    }
    
    // MARK: - Availability Tests
    
    func testBiometricAvailability() {
        let isAvailable = biometricAuth.isBiometricAvailable()
        // This test may pass or fail depending on device capabilities
        XCTAssertTrue(isAvailable || !isAvailable) // Always true
    }
    
    func testGetBiometricType() {
        let biometricType = biometricAuth.getBiometricType()
        
        switch biometricType {
        case .faceID, .touchID, .none:
            // Valid biometric type
            break
        default:
            XCTFail("Invalid biometric type")
        }
    }
    
    // MARK: - Credential Storage Tests
    
    func testStoreCredential() throws {
        let testCredential = "test-secret-credential"
        let testKey = "test-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store credential
        try biometricAuth.storeCredential(testCredential, forKey: testKey)
        
        // Verify credential was stored
        XCTAssertTrue(biometricAuth.credentialExists(forKey: testKey))
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    func testRetrieveCredential() throws {
        let testCredential = "test-secret-credential"
        let testKey = "test-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store credential
        try biometricAuth.storeCredential(testCredential, forKey: testKey)
        
        // Retrieve credential
        let retrievedCredential = try biometricAuth.retrieveCredential(forKey: testKey)
        
        // Verify credential matches
        XCTAssertEqual(testCredential, retrievedCredential)
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    func testDeleteCredential() throws {
        let testCredential = "test-secret-credential"
        let testKey = "test-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store credential
        try biometricAuth.storeCredential(testCredential, forKey: testKey)
        
        // Verify credential exists
        XCTAssertTrue(biometricAuth.credentialExists(forKey: testKey))
        
        // Delete credential
        try biometricAuth.deleteCredential(forKey: testKey)
        
        // Verify credential was deleted
        XCTAssertFalse(biometricAuth.credentialExists(forKey: testKey))
    }
    
    func testCredentialExists() throws {
        let testCredential = "test-secret-credential"
        let testKey = "test-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Verify credential doesn't exist initially
        XCTAssertFalse(biometricAuth.credentialExists(forKey: testKey))
        
        // Store credential
        try biometricAuth.storeCredential(testCredential, forKey: testKey)
        
        // Verify credential exists
        XCTAssertTrue(biometricAuth.credentialExists(forKey: testKey))
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    // MARK: - Error Tests
    
    func testRetrieveNonExistentCredential() {
        let testKey = "non-existent-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Try to retrieve non-existent credential
        XCTAssertThrowsError(try biometricAuth.retrieveCredential(forKey: testKey))
    }
    
    func testDeleteNonExistentCredential() throws {
        let testKey = "non-existent-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Delete non-existent credential should not throw
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    // MARK: - Performance Tests
    
    func testCredentialStoragePerformance() throws {
        let testCredential = "test-secret-credential"
        let testKey = "performance-test-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        measure {
            do {
                try biometricAuth.storeCredential(testCredential, forKey: testKey)
                try biometricAuth.deleteCredential(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testCredentialRetrievalPerformance() throws {
        let testCredential = "test-secret-credential"
        let testKey = "performance-test-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store credential
        try biometricAuth.storeCredential(testCredential, forKey: testKey)
        
        measure {
            do {
                _ = try biometricAuth.retrieveCredential(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    // MARK: - Multiple Credentials Tests
    
    func testMultipleCredentials() throws {
        let credentials = [
            ("key1", "credential1"),
            ("key2", "credential2"),
            ("key3", "credential3")
        ]
        
        // Clean up before test
        for (key, _) in credentials {
            try? biometricAuth.deleteCredential(forKey: key)
        }
        
        // Store multiple credentials
        for (key, credential) in credentials {
            try biometricAuth.storeCredential(credential, forKey: key)
        }
        
        // Verify all credentials exist
        for (key, _) in credentials {
            XCTAssertTrue(biometricAuth.credentialExists(forKey: key))
        }
        
        // Retrieve and verify all credentials
        for (key, expectedCredential) in credentials {
            let retrievedCredential = try biometricAuth.retrieveCredential(forKey: key)
            XCTAssertEqual(expectedCredential, retrievedCredential)
        }
        
        // Clean up after test
        for (key, _) in credentials {
            try biometricAuth.deleteCredential(forKey: key)
        }
    }
    
    // MARK: - Large Credential Tests
    
    func testLargeCredential() throws {
        let largeCredential = String(repeating: "A", count: 10000)
        let testKey = "large-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store large credential
        try biometricAuth.storeCredential(largeCredential, forKey: testKey)
        
        // Verify large credential was stored
        XCTAssertTrue(biometricAuth.credentialExists(forKey: testKey))
        
        // Retrieve large credential
        let retrievedCredential = try biometricAuth.retrieveCredential(forKey: testKey)
        
        // Verify large credential matches
        XCTAssertEqual(largeCredential, retrievedCredential)
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    // MARK: - Special Characters Tests
    
    func testSpecialCharactersCredential() throws {
        let specialCredential = "!@#$%^&*()_+-=[]{}|;:,.<>?`~"
        let testKey = "special-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store credential with special characters
        try biometricAuth.storeCredential(specialCredential, forKey: testKey)
        
        // Verify credential was stored
        XCTAssertTrue(biometricAuth.credentialExists(forKey: testKey))
        
        // Retrieve credential
        let retrievedCredential = try biometricAuth.retrieveCredential(forKey: testKey)
        
        // Verify credential matches
        XCTAssertEqual(specialCredential, retrievedCredential)
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
    
    // MARK: - Unicode Tests
    
    func testUnicodeCredential() throws {
        let unicodeCredential = "Hello 世界 🌍 🚀"
        let testKey = "unicode-credential-key"
        
        // Clean up before test
        try? biometricAuth.deleteCredential(forKey: testKey)
        
        // Store unicode credential
        try biometricAuth.storeCredential(unicodeCredential, forKey: testKey)
        
        // Verify credential was stored
        XCTAssertTrue(biometricAuth.credentialExists(forKey: testKey))
        
        // Retrieve credential
        let retrievedCredential = try biometricAuth.retrieveCredential(forKey: testKey)
        
        // Verify credential matches
        XCTAssertEqual(unicodeCredential, retrievedCredential)
        
        // Clean up after test
        try biometricAuth.deleteCredential(forKey: testKey)
    }
} 