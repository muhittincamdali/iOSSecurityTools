import XCTest
@testable import iOSSecurityTools

final class SecureStorageTests: XCTestCase {
    
    var secureStorage: SecureStorage!
    
    override func setUp() {
        super.setUp()
        secureStorage = SecureStorage.shared
    }
    
    override func tearDown() {
        // Clean up test data
        try? secureStorage.clearAll()
        super.tearDown()
    }
    
    // MARK: - Basic Storage Tests
    
    func testStoreRetrieveData() throws {
        let testData = "Hello, Secure World!".data(using: .utf8)!
        let testKey = "test-data-key"
        
        // Store data
        try secureStorage.store(testData, forKey: testKey)
        
        // Retrieve data
        let retrievedData = try secureStorage.retrieve(forKey: testKey)
        
        // Verify data matches
        XCTAssertEqual(testData, retrievedData)
    }
    
    func testStoreRetrieveString() throws {
        let testString = "Hello, Secure World!"
        let testKey = "test-string-key"
        
        // Store string
        try secureStorage.store(testString, forKey: testKey)
        
        // Retrieve string
        let retrievedString = try secureStorage.retrieveString(forKey: testKey)
        
        // Verify string matches
        XCTAssertEqual(testString, retrievedString)
    }
    
    func testStoreRetrieveObject() throws {
        struct TestObject: Codable {
            let name: String
            let age: Int
            let isActive: Bool
        }
        
        let testObject = TestObject(name: "John Doe", age: 30, isActive: true)
        let testKey = "test-object-key"
        
        // Store object
        try secureStorage.store(testObject, forKey: testKey)
        
        // Retrieve object
        let retrievedObject = try secureStorage.retrieve(forKey: testKey, as: TestObject.self)
        
        // Verify object matches
        XCTAssertEqual(testObject.name, retrievedObject.name)
        XCTAssertEqual(testObject.age, retrievedObject.age)
        XCTAssertEqual(testObject.isActive, retrievedObject.isActive)
    }
    
    // MARK: - Delete Tests
    
    func testDeleteData() throws {
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test-delete-key"
        
        // Store data
        try secureStorage.store(testData, forKey: testKey)
        
        // Verify data exists
        XCTAssertTrue(secureStorage.exists(forKey: testKey))
        
        // Delete data
        try secureStorage.delete(forKey: testKey)
        
        // Verify data was deleted
        XCTAssertFalse(secureStorage.exists(forKey: testKey))
    }
    
    // MARK: - Existence Tests
    
    func testExists() throws {
        let testKey = "test-exists-key"
        
        // Verify data doesn't exist initially
        XCTAssertFalse(secureStorage.exists(forKey: testKey))
        
        // Store data
        try secureStorage.store("test", forKey: testKey)
        
        // Verify data exists
        XCTAssertTrue(secureStorage.exists(forKey: testKey))
        
        // Clean up
        try secureStorage.delete(forKey: testKey)
    }
    
    // MARK: - Custom Encryption Tests
    
    func testStoreRetrieveWithCustomEncryption() throws {
        let testData = "Custom encrypted data".data(using: .utf8)!
        let testKey = "test-custom-encryption-key"
        let encryptionKey = try KeyGenerator.shared.generateAESKey()
        
        // Store with custom encryption
        try secureStorage.storeSensitive(testData, forKey: testKey, encryptionKey: encryptionKey)
        
        // Retrieve with custom encryption
        let retrievedData = try secureStorage.retrieveSensitive(forKey: testKey, encryptionKey: encryptionKey)
        
        // Verify data matches
        XCTAssertEqual(testData, retrievedData)
    }
    
    // MARK: - Expiration Tests
    
    func testStoreWithExpiration() throws {
        let testData = "Expiring data".data(using: .utf8)!
        let testKey = "test-expiration-key"
        let expirationDate = Date().addingTimeInterval(1) // Expire in 1 second
        
        // Store with expiration
        try secureStorage.store(testData, forKey: testKey, expiresAt: expirationDate)
        
        // Retrieve immediately (should work)
        let retrievedData = try secureStorage.retrieve(forKey: testKey)
        XCTAssertEqual(testData, retrievedData)
        
        // Wait for expiration
        Thread.sleep(forTimeInterval: 2)
        
        // Try to retrieve expired data (should fail)
        XCTAssertThrowsError(try secureStorage.retrieve(forKey: testKey))
    }
    
    // MARK: - Large Data Tests
    
    func testLargeData() throws {
        let largeData = Data(repeating: 0, count: 1024 * 1024) // 1MB
        let testKey = "test-large-data-key"
        
        // Store large data
        try secureStorage.store(largeData, forKey: testKey)
        
        // Retrieve large data
        let retrievedData = try secureStorage.retrieve(forKey: testKey)
        
        // Verify data matches
        XCTAssertEqual(largeData, retrievedData)
    }
    
    // MARK: - Multiple Keys Tests
    
    func testMultipleKeys() throws {
        let testData = [
            ("key1", "value1"),
            ("key2", "value2"),
            ("key3", "value3")
        ]
        
        // Store multiple keys
        for (key, value) in testData {
            try secureStorage.store(value, forKey: key)
        }
        
        // Verify all keys exist
        for (key, _) in testData {
            XCTAssertTrue(secureStorage.exists(forKey: key))
        }
        
        // Retrieve all keys
        for (key, expectedValue) in testData {
            let retrievedValue = try secureStorage.retrieveString(forKey: key)
            XCTAssertEqual(expectedValue, retrievedValue)
        }
    }
    
    // MARK: - Storage Statistics Tests
    
    func testStorageStats() throws {
        let testData = [
            ("key1", "value1"),
            ("key2", "value2"),
            ("key3", "value3")
        ]
        
        // Store test data
        for (key, value) in testData {
            try secureStorage.store(value, forKey: key)
        }
        
        // Get storage stats
        let stats = secureStorage.getStorageStats()
        
        // Verify stats
        XCTAssertEqual(stats.totalKeys, testData.count)
        XCTAssertGreaterThan(stats.totalSize, 0)
        XCTAssertGreaterThan(stats.averageSize, 0)
    }
    
    // MARK: - Migration Tests
    
    func testDataMigration() throws {
        let testData = "Migration test data".data(using: .utf8)!
        let testKey = "test-migration-key"
        let newEncryptionKey = try KeyGenerator.shared.generateAESKey()
        
        // Store data with default encryption
        try secureStorage.store(testData, forKey: testKey)
        
        // Migrate to new encryption
        try secureStorage.migrateData(forKey: testKey, newEncryptionKey: newEncryptionKey)
        
        // Verify data still exists
        XCTAssertTrue(secureStorage.exists(forKey: testKey))
    }
    
    // MARK: - Backup Restore Tests
    
    func testBackupRestore() throws {
        let testData = "Backup test data".data(using: .utf8)!
        let testKey = "test-backup-key"
        
        // Store data
        try secureStorage.store(testData, forKey: testKey)
        
        // Create backup
        let backupData = try secureStorage.backup(forKey: testKey)
        
        // Delete original data
        try secureStorage.delete(forKey: testKey)
        
        // Verify data was deleted
        XCTAssertFalse(secureStorage.exists(forKey: testKey))
        
        // Restore from backup
        try secureStorage.restore(backupData, forKey: testKey)
        
        // Verify data was restored
        XCTAssertTrue(secureStorage.exists(forKey: testKey))
        
        let retrievedData = try secureStorage.retrieve(forKey: testKey)
        XCTAssertEqual(testData, retrievedData)
    }
    
    // MARK: - Error Tests
    
    func testRetrieveNonExistentData() {
        let testKey = "non-existent-key"
        
        XCTAssertThrowsError(try secureStorage.retrieve(forKey: testKey))
    }
    
    func testRetrieveNonExistentString() {
        let testKey = "non-existent-string-key"
        
        XCTAssertThrowsError(try secureStorage.retrieveString(forKey: testKey))
    }
    
    func testRetrieveNonExistentObject() {
        struct TestObject: Codable {
            let name: String
        }
        
        let testKey = "non-existent-object-key"
        
        XCTAssertThrowsError(try secureStorage.retrieve(forKey: testKey, as: TestObject.self))
    }
    
    func testInvalidBackupData() {
        let testKey = "test-invalid-backup-key"
        let invalidBackupData = Data(repeating: 0, count: 10) // Too small
        
        XCTAssertThrowsError(try secureStorage.restore(invalidBackupData, forKey: testKey))
    }
    
    // MARK: - Performance Tests
    
    func testStoragePerformance() throws {
        let testData = "Performance test data".data(using: .utf8)!
        let testKey = "performance-test-key"
        
        measure {
            do {
                try secureStorage.store(testData, forKey: testKey)
                try secureStorage.delete(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testRetrievalPerformance() throws {
        let testData = "Performance test data".data(using: .utf8)!
        let testKey = "performance-test-key"
        
        // Store data
        try secureStorage.store(testData, forKey: testKey)
        
        measure {
            do {
                _ = try secureStorage.retrieve(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
        
        // Clean up
        try secureStorage.delete(forKey: testKey)
    }
    
    // MARK: - Memory Tests
    
    func testMemoryUsage() throws {
        let largeData = Data(repeating: 0, count: 10 * 1024 * 1024) // 10MB
        let testKey = "memory-test-key"
        
        // Measure memory before
        let memoryBefore = getMemoryUsage()
        
        // Store large data
        try secureStorage.store(largeData, forKey: testKey)
        
        // Retrieve large data
        let retrievedData = try secureStorage.retrieve(forKey: testKey)
        
        // Measure memory after
        let memoryAfter = getMemoryUsage()
        
        // Memory increase should be reasonable (less than 50MB)
        let memoryIncrease = memoryAfter - memoryBefore
        XCTAssertLessThan(memoryIncrease, 50 * 1024 * 1024)
        
        XCTAssertEqual(largeData, retrievedData)
        
        // Clean up
        try secureStorage.delete(forKey: testKey)
    }
    
    // MARK: - Helper Methods
    
    private func getMemoryUsage() -> Int {
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
        
        return kerr == KERN_SUCCESS ? Int(info.resident_size) : 0
    }
} 