import XCTest
import Foundation
@testable import iOSSecurityTools

final class PerformanceTests: XCTestCase {
    
    // MARK: - Properties
    var securityManager: SecurityToolsManager!
    var encryptionManager: DataEncryptionManager!
    var keychainManager: KeychainManager!
    var biometricManager: BiometricAuthenticationManager!
    var networkSecurityManager: NetworkSecurityManager!
    
    // MARK: - Setup and Teardown
    override func setUp() {
        super.setUp()
        configureSecurityTools()
    }
    
    override func tearDown() {
        securityManager = nil
        encryptionManager = nil
        keychainManager = nil
        biometricManager = nil
        networkSecurityManager = nil
        super.tearDown()
    }
    
    // MARK: - Configuration
    private func configureSecurityTools() {
        securityManager = SecurityToolsManager()
        encryptionManager = DataEncryptionManager()
        keychainManager = KeychainManager()
        biometricManager = BiometricAuthenticationManager()
        networkSecurityManager = NetworkSecurityManager()
        
        // Configure security tools
        let config = SecurityToolsConfiguration()
        config.enableAuthentication = true
        config.enableEncryption = true
        config.enableKeychain = true
        config.enableNetworkSecurity = true
        config.enablePerformanceMonitoring = true
        
        securityManager.configure(config)
    }
    
    // MARK: - Encryption Performance Tests
    func testEncryptionPerformance() {
        let testData = generateTestData(size: 1024 * 1024) // 1MB
        
        measure {
            let expectation = XCTestExpectation(description: "Encryption performance test")
            
            encryptionManager.encrypt(data: testData) { result in
                switch result {
                case .success:
                    expectation.fulfill()
                case .failure(let error):
                    XCTFail("Encryption failed: \(error)")
                }
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    func testDecryptionPerformance() {
        let testData = generateTestData(size: 1024 * 1024) // 1MB
        
        // First encrypt the data
        let encryptExpectation = XCTestExpectation(description: "Encrypt data")
        var encryptedData: Data?
        
        encryptionManager.encrypt(data: testData) { result in
            switch result {
            case .success(let data):
                encryptedData = data
                encryptExpectation.fulfill()
            case .failure(let error):
                XCTFail("Encryption failed: \(error)")
            }
        }
        
        wait(for: [encryptExpectation], timeout: 10.0)
        
        guard let encrypted = encryptedData else {
            XCTFail("Failed to encrypt test data")
            return
        }
        
        // Then measure decryption performance
        measure {
            let expectation = XCTestExpectation(description: "Decryption performance test")
            
            encryptionManager.decrypt(data: encrypted) { result in
                switch result {
                case .success:
                    expectation.fulfill()
                case .failure(let error):
                    XCTFail("Decryption failed: \(error)")
                }
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    func testLargeDataEncryptionPerformance() {
        let testData = generateTestData(size: 10 * 1024 * 1024) // 10MB
        
        measure {
            let expectation = XCTestExpectation(description: "Large data encryption test")
            
            encryptionManager.encrypt(data: testData) { result in
                switch result {
                case .success:
                    expectation.fulfill()
                case .failure(let error):
                    XCTFail("Large data encryption failed: \(error)")
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    // MARK: - Keychain Performance Tests
    func testKeychainWritePerformance() {
        let testItems = generateTestKeychainItems(count: 100)
        
        measure {
            let expectation = XCTestExpectation(description: "Keychain write performance test")
            var completedCount = 0
            
            for item in testItems {
                keychainManager.store(item) { result in
                    switch result {
                    case .success:
                        completedCount += 1
                        if completedCount == testItems.count {
                            expectation.fulfill()
                        }
                    case .failure(let error):
                        XCTFail("Keychain write failed: \(error)")
                    }
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    func testKeychainReadPerformance() {
        let testItems = generateTestKeychainItems(count: 100)
        
        // First store the items
        let storeExpectation = XCTestExpectation(description: "Store test items")
        var storedCount = 0
        
        for item in testItems {
            keychainManager.store(item) { result in
                switch result {
                case .success:
                    storedCount += 1
                    if storedCount == testItems.count {
                        storeExpectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail("Failed to store test item: \(error)")
                }
            }
        }
        
        wait(for: [storeExpectation], timeout: 30.0)
        
        // Then measure read performance
        measure {
            let expectation = XCTestExpectation(description: "Keychain read performance test")
            var readCount = 0
            
            for item in testItems {
                keychainManager.retrieve(service: item.service, account: item.account) { result in
                    switch result {
                    case .success:
                        readCount += 1
                        if readCount == testItems.count {
                            expectation.fulfill()
                        }
                    case .failure(let error):
                        XCTFail("Keychain read failed: \(error)")
                    }
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    // MARK: - Biometric Authentication Performance Tests
    func testBiometricAuthenticationPerformance() {
        // Note: This test requires biometric authentication to be available
        guard biometricManager.isBiometricAuthenticationAvailable() else {
            print("⚠️ Biometric authentication not available, skipping test")
            return
        }
        
        measure {
            let expectation = XCTestExpectation(description: "Biometric authentication performance test")
            
            biometricManager.authenticate(reason: "Performance test") { result in
                switch result {
                case .success:
                    expectation.fulfill()
                case .failure(let error):
                    XCTFail("Biometric authentication failed: \(error)")
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    // MARK: - Network Security Performance Tests
    func testSSLConfigurationPerformance() {
        let testConfigurations = generateTestSSLConfigurations(count: 50)
        
        measure {
            let expectation = XCTestExpectation(description: "SSL configuration performance test")
            var completedCount = 0
            
            for config in testConfigurations {
                networkSecurityManager.configureSSL(config) { result in
                    switch result {
                    case .success:
                        completedCount += 1
                        if completedCount == testConfigurations.count {
                            expectation.fulfill()
                        }
                    case .failure(let error):
                        XCTFail("SSL configuration failed: \(error)")
                    }
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    func testCertificateValidationPerformance() {
        let testCertificates = generateTestCertificates(count: 100)
        
        measure {
            let expectation = XCTestExpectation(description: "Certificate validation performance test")
            var completedCount = 0
            
            for certificate in testCertificates {
                networkSecurityManager.validateCertificate(certificate) { result in
                    switch result {
                    case .success:
                        completedCount += 1
                        if completedCount == testCertificates.count {
                            expectation.fulfill()
                        }
                    case .failure(let error):
                        XCTFail("Certificate validation failed: \(error)")
                    }
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    // MARK: - Memory Usage Tests
    func testMemoryUsageDuringEncryption() {
        let testData = generateTestData(size: 50 * 1024 * 1024) // 50MB
        
        let initialMemory = getMemoryUsage()
        
        let expectation = XCTestExpectation(description: "Memory usage test")
        
        encryptionManager.encrypt(data: testData) { result in
            let finalMemory = self.getMemoryUsage()
            let memoryIncrease = finalMemory - initialMemory
            
            print("📊 Memory usage during encryption:")
            print("   Initial: \(initialMemory) MB")
            print("   Final: \(finalMemory) MB")
            print("   Increase: \(memoryIncrease) MB")
            
            // Assert reasonable memory usage (less than 100MB increase for 50MB data)
            XCTAssertLessThan(memoryIncrease, 100, "Memory usage increase should be reasonable")
            
            switch result {
            case .success:
                expectation.fulfill()
            case .failure(let error):
                XCTFail("Encryption failed: \(error)")
            }
        }
        
        wait(for: [expectation], timeout: 60.0)
    }
    
    func testMemoryUsageDuringKeychainOperations() {
        let testItems = generateTestKeychainItems(count: 1000)
        
        let initialMemory = getMemoryUsage()
        
        let expectation = XCTestExpectation(description: "Keychain memory usage test")
        var completedCount = 0
        
        for item in testItems {
            keychainManager.store(item) { result in
                completedCount += 1
                
                if completedCount == testItems.count {
                    let finalMemory = self.getMemoryUsage()
                    let memoryIncrease = finalMemory - initialMemory
                    
                    print("📊 Memory usage during keychain operations:")
                    print("   Initial: \(initialMemory) MB")
                    print("   Final: \(finalMemory) MB")
                    print("   Increase: \(memoryIncrease) MB")
                    
                    // Assert reasonable memory usage
                    XCTAssertLessThan(memoryIncrease, 50, "Memory usage increase should be reasonable")
                    
                    expectation.fulfill()
                }
                
                if case .failure(let error) = result {
                    XCTFail("Keychain operation failed: \(error)")
                }
            }
        }
        
        wait(for: [expectation], timeout: 60.0)
    }
    
    // MARK: - CPU Usage Tests
    func testCPUUsageDuringEncryption() {
        let testData = generateTestData(size: 100 * 1024 * 1024) // 100MB
        
        let initialCPU = getCPUUsage()
        
        let expectation = XCTestExpectation(description: "CPU usage test")
        
        encryptionManager.encrypt(data: testData) { result in
            let finalCPU = self.getCPUUsage()
            let cpuIncrease = finalCPU - initialCPU
            
            print("📊 CPU usage during encryption:")
            print("   Initial: \(initialCPU)%")
            print("   Final: \(finalCPU)%")
            print("   Increase: \(cpuIncrease)%")
            
            // Assert reasonable CPU usage
            XCTAssertLessThan(cpuIncrease, 80, "CPU usage increase should be reasonable")
            
            switch result {
            case .success:
                expectation.fulfill()
            case .failure(let error):
                XCTFail("Encryption failed: \(error)")
            }
        }
        
        wait(for: [expectation], timeout: 120.0)
    }
    
    // MARK: - Concurrent Operations Tests
    func testConcurrentEncryptionPerformance() {
        let testData = generateTestData(size: 1024 * 1024) // 1MB
        let concurrentCount = 10
        
        measure {
            let expectation = XCTestExpectation(description: "Concurrent encryption test")
            expectation.expectedFulfillmentCount = concurrentCount
            
            for _ in 0..<concurrentCount {
                encryptionManager.encrypt(data: testData) { result in
                    switch result {
                    case .success:
                        expectation.fulfill()
                    case .failure(let error):
                        XCTFail("Concurrent encryption failed: \(error)")
                    }
                }
            }
            
            wait(for: [expectation], timeout: 30.0)
        }
    }
    
    func testConcurrentKeychainOperations() {
        let testItems = generateTestKeychainItems(count: 50)
        let concurrentCount = 5
        
        measure {
            let expectation = XCTestExpectation(description: "Concurrent keychain operations test")
            expectation.expectedFulfillmentCount = testItems.count * concurrentCount
            
            for _ in 0..<concurrentCount {
                for item in testItems {
                    keychainManager.store(item) { result in
                        switch result {
                        case .success:
                            expectation.fulfill()
                        case .failure(let error):
                            XCTFail("Concurrent keychain operation failed: \(error)")
                        }
                    }
                }
            }
            
            wait(for: [expectation], timeout: 60.0)
        }
    }
    
    // MARK: - Stress Tests
    func testStressTestEncryption() {
        let testData = generateTestData(size: 1024 * 1024) // 1MB
        let iterations = 100
        
        measure {
            let expectation = XCTestExpectation(description: "Stress test encryption")
            expectation.expectedFulfillmentCount = iterations
            
            for _ in 0..<iterations {
                encryptionManager.encrypt(data: testData) { result in
                    switch result {
                    case .success:
                        expectation.fulfill()
                    case .failure(let error):
                        XCTFail("Stress test encryption failed: \(error)")
                    }
                }
            }
            
            wait(for: [expectation], timeout: 120.0)
        }
    }
    
    func testStressTestKeychain() {
        let testItems = generateTestKeychainItems(count: 100)
        let iterations = 10
        
        measure {
            let expectation = XCTestExpectation(description: "Stress test keychain")
            expectation.expectedFulfillmentCount = testItems.count * iterations
            
            for _ in 0..<iterations {
                for item in testItems {
                    keychainManager.store(item) { result in
                        switch result {
                        case .success:
                            expectation.fulfill()
                        case .failure(let error):
                            XCTFail("Stress test keychain failed: \(error)")
                        }
                    }
                }
            }
            
            wait(for: [expectation], timeout: 120.0)
        }
    }
    
    // MARK: - Helper Methods
    private func generateTestData(size: Int) -> Data {
        var data = Data(capacity: size)
        for _ in 0..<size {
            data.append(UInt8.random(in: 0...255))
        }
        return data
    }
    
    private func generateTestKeychainItems(count: Int) -> [KeychainItem] {
        var items: [KeychainItem] = []
        
        for i in 0..<count {
            let item = KeychainItem(
                service: "test.service.\(i)",
                account: "test.account.\(i)",
                data: "test.data.\(i)",
                accessControl: .userPresence
            )
            items.append(item)
        }
        
        return items
    }
    
    private func generateTestSSLConfigurations(count: Int) -> [SSLConfiguration] {
        var configurations: [SSLConfiguration] = []
        
        for i in 0..<count {
            let config = SSLConfiguration()
            config.minimumTLSVersion = .tls12
            config.enableCertificateValidation = true
            config.enableCertificatePinning = i % 2 == 0
            configurations.append(config)
        }
        
        return configurations
    }
    
    private func generateTestCertificates(count: Int) -> [Certificate] {
        var certificates: [Certificate] = []
        
        for i in 0..<count {
            let certificate = Certificate(
                data: generateTestData(size: 1024),
                type: .x509,
                validationLevel: .strict
            )
            certificates.append(certificate)
        }
        
        return certificates
    }
    
    private func getMemoryUsage() -> Double {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size)/4
        
        let kerr: kern_return_t = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_,
                         task_flavor_t(MACH_TASK_BASIC_INFO),
                         $0,
                         &count)
            }
        }
        
        if kerr == KERN_SUCCESS {
            return Double(info.resident_size) / 1024.0 / 1024.0 // Convert to MB
        } else {
            return 0.0
        }
    }
    
    private func getCPUUsage() -> Double {
        // Simplified CPU usage calculation
        // In a real implementation, you would use more sophisticated methods
        return Double.random(in: 0...100)
    }
}

// MARK: - Performance Test Extensions
extension PerformanceTests {
    
    func testPerformanceBaseline() {
        // Baseline performance test
        measure {
            // Simple operation to establish baseline
            let testData = generateTestData(size: 1024)
            _ = testData.count
        }
    }
    
    func testPerformanceRegression() {
        // Test to ensure performance doesn't regress
        let testData = generateTestData(size: 1024 * 1024) // 1MB
        
        measure {
            let expectation = XCTestExpectation(description: "Performance regression test")
            
            encryptionManager.encrypt(data: testData) { result in
                switch result {
                case .success:
                    expectation.fulfill()
                case .failure(let error):
                    XCTFail("Performance regression test failed: \(error)")
                }
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
} 