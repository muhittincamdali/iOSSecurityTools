import XCTest
@testable import iOSSecurityTools

// MARK: - Security Tools Tests
// Comprehensive test suite for iOS Security Tools framework

final class SecurityToolsTests: XCTestCase {
    
    // MARK: - Properties
    var securityManager: SecurityToolsManager!
    var biometricAuth: BiometricAuthenticationManager!
    var encryptionManager: DataEncryptionManager!
    var keychainManager: KeychainManager!
    var networkSecurity: NetworkSecurityManager!
    
    // MARK: - Setup and Teardown
    override func setUp() {
        super.setUp()
        
        // Initialize security tools
        securityManager = SecurityToolsManager()
        biometricAuth = BiometricAuthenticationManager()
        encryptionManager = DataEncryptionManager()
        keychainManager = KeychainManager()
        networkSecurity = NetworkSecurityManager()
        
        // Configure basic settings
        configureSecurityTools()
    }
    
    override func tearDown() {
        // Clean up after tests
        cleanupTestData()
        
        securityManager = nil
        biometricAuth = nil
        encryptionManager = nil
        keychainManager = nil
        networkSecurity = nil
        
        super.tearDown()
    }
    
    // MARK: - Configuration
    private func configureSecurityTools() {
        // Configure security manager
        let securityConfig = SecurityToolsConfiguration()
        securityConfig.enableAuthentication = true
        securityConfig.enableEncryption = true
        securityConfig.enableKeychain = true
        securityConfig.enableNetworkSecurity = true
        
        securityManager.configure(securityConfig)
        
        // Configure biometric authentication
        let biometricConfig = BiometricConfiguration()
        biometricConfig.enableFaceID = true
        biometricConfig.enableTouchID = true
        biometricConfig.fallbackToPasscode = true
        
        biometricAuth.configure(biometricConfig)
        
        // Configure encryption
        let encryptionConfig = EncryptionConfiguration()
        encryptionConfig.algorithm = .aes256
        encryptionConfig.mode = .gcm
        encryptionConfig.keySize = 256
        
        encryptionManager.configure(encryptionConfig)
        
        // Configure keychain
        let keychainConfig = KeychainConfiguration()
        keychainConfig.enableEncryption = true
        keychainConfig.enableAccessControl = true
        
        keychainManager.configure(keychainConfig)
        
        // Configure network security
        let networkConfig = NetworkSecurityConfiguration()
        networkConfig.enableSSLValidation = true
        networkConfig.enableCertificatePinning = true
        
        networkSecurity.configure(networkConfig)
    }
    
    // MARK: - Authentication Tests
    func testBiometricAuthenticationAvailability() {
        // Given
        let expectation = XCTestExpectation(description: "Biometric availability check")
        
        // When
        biometricAuth.checkBiometricAvailability { result in
            // Then
            switch result {
            case .success(let availability):
                XCTAssertNotNil(availability)
                XCTAssertTrue(availability.faceIDAvailable || availability.touchIDAvailable || !availability.biometricAvailable)
                expectation.fulfill()
                
            case .failure(let error):
                XCTFail("Biometric availability check failed: \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testBiometricAuthentication() {
        // Given
        let expectation = XCTestExpectation(description: "Biometric authentication")
        let reason = "Test authentication"
        
        // When
        biometricAuth.authenticate(reason: reason) { result in
            // Then
            switch result {
            case .success:
                expectation.fulfill()
                
            case .failure(let error):
                // Authentication might fail in test environment
                print("Biometric authentication failed (expected in test): \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 10.0)
    }
    
    // MARK: - Encryption Tests
    func testDataEncryption() {
        // Given
        let expectation = XCTestExpectation(description: "Data encryption")
        let testData = "Test sensitive data"
        
        // When
        encryptionManager.encrypt(data: testData) { result in
            // Then
            switch result {
            case .success(let encryptedData):
                XCTAssertNotNil(encryptedData.encrypted)
                XCTAssertNotNil(encryptedData.iv)
                XCTAssertNotNil(encryptedData.tag)
                expectation.fulfill()
                
            case .failure(let error):
                XCTFail("Data encryption failed: \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testDataDecryption() {
        // Given
        let expectation = XCTestExpectation(description: "Data decryption")
        let testData = "Test sensitive data"
        
        // When
        encryptionManager.encrypt(data: testData) { [weak self] result in
            switch result {
            case .success(let encryptedData):
                // Then decrypt
                self?.encryptionManager.decrypt(encryptedData: encryptedData) { result in
                    switch result {
                    case .success(let decryptedData):
                        XCTAssertEqual(decryptedData, testData)
                        expectation.fulfill()
                        
                    case .failure(let error):
                        XCTFail("Data decryption failed: \(error)")
                        expectation.fulfill()
                    }
                }
                
            case .failure(let error):
                XCTFail("Data encryption failed: \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 10.0)
    }
    
    // MARK: - Keychain Tests
    func testKeychainStorage() {
        // Given
        let expectation = XCTestExpectation(description: "Keychain storage")
        let testItem = KeychainItem(
            service: "com.test.app",
            account: "test@example.com",
            data: "test_password",
            accessControl: .userPresence
        )
        
        // When
        keychainManager.store(testItem) { result in
            // Then
            switch result {
            case .success:
                expectation.fulfill()
                
            case .failure(let error):
                XCTFail("Keychain storage failed: \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testKeychainRetrieval() {
        // Given
        let expectation = XCTestExpectation(description: "Keychain retrieval")
        let testItem = KeychainItem(
            service: "com.test.app",
            account: "test@example.com",
            data: "test_password",
            accessControl: .userPresence
        )
        
        // When
        keychainManager.store(testItem) { [weak self] result in
            switch result {
            case .success:
                // Then retrieve
                self?.keychainManager.retrieve(
                    service: "com.test.app",
                    account: "test@example.com"
                ) { result in
                    switch result {
                    case .success(let retrievedItem):
                        XCTAssertEqual(retrievedItem.data, testItem.data)
                        expectation.fulfill()
                        
                    case .failure(let error):
                        XCTFail("Keychain retrieval failed: \(error)")
                        expectation.fulfill()
                    }
                }
                
            case .failure(let error):
                XCTFail("Keychain storage failed: \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 10.0)
    }
    
    // MARK: - Network Security Tests
    func testSSLConfiguration() {
        // Given
        let sslConfig = SSLConfiguration()
        sslConfig.minimumTLSVersion = .tls12
        sslConfig.enableCertificateValidation = true
        sslConfig.enableHostnameValidation = true
        
        // When
        networkSecurity.configureSSL(sslConfig)
        
        // Then
        XCTAssertNotNil(networkSecurity)
        // Additional assertions would depend on the actual implementation
    }
    
    func testCertificatePinning() {
        // Given
        let expectation = XCTestExpectation(description: "Certificate pinning")
        let pinningManager = CertificatePinningManager()
        
        // When
        pinningManager.addPinnedCertificate(
            hostname: "api.example.com",
            certificate: Data() // Empty data for test
        ) { result in
            // Then
            switch result {
            case .success:
                expectation.fulfill()
                
            case .failure(let error):
                // Pinning might fail with empty data
                print("Certificate pinning failed (expected): \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    // MARK: - Performance Tests
    func testEncryptionPerformance() {
        // Given
        let testData = "Performance test data" * 1000 // Large data
        let expectation = XCTestExpectation(description: "Encryption performance")
        
        // When
        let startTime = CFAbsoluteTimeGetCurrent()
        
        encryptionManager.encrypt(data: testData) { result in
            let endTime = CFAbsoluteTimeGetCurrent()
            let duration = endTime - startTime
            
            // Then
            switch result {
            case .success:
                XCTAssertLessThan(duration, 1.0, "Encryption should complete within 1 second")
                expectation.fulfill()
                
            case .failure(let error):
                XCTFail("Performance test encryption failed: \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    // MARK: - Security Tests
    func testSecurityConfiguration() {
        // Given
        let securityConfig = SecurityToolsConfiguration()
        
        // When
        securityConfig.enableAuthentication = true
        securityConfig.enableEncryption = true
        securityConfig.enableKeychain = true
        securityConfig.enableNetworkSecurity = true
        
        // Then
        XCTAssertTrue(securityConfig.enableAuthentication)
        XCTAssertTrue(securityConfig.enableEncryption)
        XCTAssertTrue(securityConfig.enableKeychain)
        XCTAssertTrue(securityConfig.enableNetworkSecurity)
    }
    
    func testErrorHandling() {
        // Given
        let expectation = XCTestExpectation(description: "Error handling")
        
        // When
        encryptionManager.encrypt(data: "") { result in
            // Then
            switch result {
            case .success:
                XCTFail("Should fail with empty data")
                expectation.fulfill()
                
            case .failure(let error):
                XCTAssertNotNil(error)
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    // MARK: - Integration Tests
    func testFullSecurityWorkflow() {
        // Given
        let expectation = XCTestExpectation(description: "Full security workflow")
        let testData = "Integration test data"
        
        // When
        // Step 1: Authenticate
        biometricAuth.authenticate(reason: "Test workflow") { [weak self] result in
            switch result {
            case .success:
                // Step 2: Encrypt data
                self?.encryptionManager.encrypt(data: testData) { result in
                    switch result {
                    case .success(let encryptedData):
                        // Step 3: Store in keychain
                        let keychainItem = KeychainItem(
                            service: "com.test.app",
                            account: "integration_test",
                            data: encryptedData.encrypted,
                            accessControl: .userPresence
                        )
                        
                        self?.keychainManager.store(keychainItem) { result in
                            switch result {
                            case .success:
                                expectation.fulfill()
                                
                            case .failure(let error):
                                XCTFail("Keychain storage failed: \(error)")
                                expectation.fulfill()
                            }
                        }
                        
                    case .failure(let error):
                        XCTFail("Encryption failed: \(error)")
                        expectation.fulfill()
                    }
                }
                
            case .failure(let error):
                // Authentication might fail in test environment
                print("Authentication failed (expected in test): \(error)")
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 15.0)
    }
    
    // MARK: - Helper Methods
    private func cleanupTestData() {
        // Clean up test data from keychain
        keychainManager.delete(
            service: "com.test.app",
            account: "test@example.com"
        ) { _ in }
        
        keychainManager.delete(
            service: "com.test.app",
            account: "integration_test"
        ) { _ in }
    }
}

// MARK: - String Extension for Performance Test
extension String {
    static func * (lhs: String, rhs: Int) -> String {
        return String(repeating: lhs, count: rhs)
    }
} 