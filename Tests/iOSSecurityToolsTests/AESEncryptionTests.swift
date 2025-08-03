import XCTest
@testable import iOSSecurityTools

final class AESEncryptionTests: XCTestCase {
    
    var encryption: AESEncryption!
    
    override func setUp() {
        super.setUp()
        encryption = AESEncryption.shared
    }
    
    override func tearDown() {
        encryption = nil
        super.tearDown()
    }
    
    // MARK: - Key Generation Tests
    
    func testGenerateKey() throws {
        let key = try encryption.generateKey()
        XCTAssertEqual(key.bitCount, 256)
    }
    
    func testGenerateKeyFromPassword() throws {
        let password = "testPassword123"
        let salt = encryption.generateSalt()
        let key = try encryption.generateKey(from: password, salt: salt)
        XCTAssertEqual(key.bitCount, 256)
    }
    
    func testGenerateKeyFromPasswordWithoutSalt() throws {
        let password = "testPassword123"
        let key = try encryption.generateKey(from: password)
        XCTAssertEqual(key.bitCount, 256)
    }
    
    // MARK: - Encryption Tests
    
    func testEncryptDecryptData() throws {
        let key = try encryption.generateKey()
        let originalData = "Hello, World!".data(using: .utf8)!
        
        let encryptedData = try encryption.encrypt(originalData, with: key)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        
        XCTAssertEqual(originalData, decryptedData)
    }
    
    func testEncryptDecryptString() throws {
        let key = try encryption.generateKey()
        let originalString = "Hello, World!"
        
        let encryptedData = try encryption.encrypt(originalString, with: key)
        let decryptedString = try encryption.decryptToString(encryptedData, with: key)
        
        XCTAssertEqual(originalString, decryptedString)
    }
    
    func testEncryptDecryptLargeData() throws {
        let key = try encryption.generateKey()
        let originalData = Data(repeating: 0, count: 1024 * 1024) // 1MB
        
        let encryptedData = try encryption.encrypt(originalData, with: key)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        
        XCTAssertEqual(originalData, decryptedData)
    }
    
    func testEncryptDecryptEmptyData() throws {
        let key = try encryption.generateKey()
        let originalData = Data()
        
        let encryptedData = try encryption.encrypt(originalData, with: key)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        
        XCTAssertEqual(originalData, decryptedData)
    }
    
    // MARK: - File Encryption Tests
    
    func testEncryptDecryptFile() throws {
        let key = try encryption.generateKey()
        let originalContent = "This is a test file content"
        let originalData = originalContent.data(using: .utf8)!
        
        // Create temporary file
        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("test.txt")
        try originalData.write(to: tempURL)
        
        defer {
            try? FileManager.default.removeItem(at: tempURL)
        }
        
        // Encrypt file
        let encryptedFileURL = try encryption.encryptFile(at: tempURL, with: key)
        
        defer {
            try? FileManager.default.removeItem(at: encryptedFileURL)
        }
        
        // Decrypt file
        let decryptedFileURL = try encryption.decryptFile(at: encryptedFileURL, with: key)
        
        defer {
            try? FileManager.default.removeItem(at: decryptedFileURL)
        }
        
        // Verify content
        let decryptedData = try Data(contentsOf: decryptedFileURL)
        let decryptedContent = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(originalContent, decryptedContent)
    }
    
    // MARK: - Salt Generation Tests
    
    func testGenerateSalt() {
        let salt1 = encryption.generateSalt()
        let salt2 = encryption.generateSalt()
        
        XCTAssertEqual(salt1.count, 32)
        XCTAssertEqual(salt2.count, 32)
        XCTAssertNotEqual(salt1, salt2) // Salts should be different
    }
    
    // MARK: - Error Tests
    
    func testEncryptWithInvalidKey() {
        let invalidKey = SymmetricKey(size: .bits128)
        let data = "Test".data(using: .utf8)!
        
        XCTAssertThrowsError(try encryption.encrypt(data, with: invalidKey))
    }
    
    func testDecryptWithWrongKey() throws {
        let key1 = try encryption.generateKey()
        let key2 = try encryption.generateKey()
        let data = "Test".data(using: .utf8)!
        
        let encryptedData = try encryption.encrypt(data, with: key1)
        
        XCTAssertThrowsError(try encryption.decrypt(encryptedData, with: key2))
    }
    
    func testDecryptInvalidData() throws {
        let key = try encryption.generateKey()
        let invalidData = Data(repeating: 0, count: 16)
        
        XCTAssertThrowsError(try encryption.decrypt(invalidData, with: key))
    }
    
    // MARK: - Performance Tests
    
    func testEncryptionPerformance() throws {
        let key = try encryption.generateKey()
        let data = Data(repeating: 0, count: 1024 * 1024) // 1MB
        
        measure {
            for _ in 0..<10 {
                _ = try! encryption.encrypt(data, with: key)
            }
        }
    }
    
    func testDecryptionPerformance() throws {
        let key = try encryption.generateKey()
        let data = Data(repeating: 0, count: 1024 * 1024) // 1MB
        let encryptedData = try encryption.encrypt(data, with: key)
        
        measure {
            for _ in 0..<10 {
                _ = try! encryption.decrypt(encryptedData, with: key)
            }
        }
    }
    
    // MARK: - Memory Tests
    
    func testMemoryUsage() throws {
        let key = try encryption.generateKey()
        let largeData = Data(repeating: 0, count: 10 * 1024 * 1024) // 10MB
        
        // Measure memory before
        let memoryBefore = getMemoryUsage()
        
        let encryptedData = try encryption.encrypt(largeData, with: key)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        
        // Measure memory after
        let memoryAfter = getMemoryUsage()
        
        // Memory increase should be reasonable (less than 50MB)
        let memoryIncrease = memoryAfter - memoryBefore
        XCTAssertLessThan(memoryIncrease, 50 * 1024 * 1024)
        
        XCTAssertEqual(largeData, decryptedData)
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