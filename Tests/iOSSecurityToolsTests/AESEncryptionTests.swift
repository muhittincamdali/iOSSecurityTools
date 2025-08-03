import XCTest
import CryptoKit
@testable import iOSSecurityTools

final class AESEncryptionTests: XCTestCase {
    
    var aesEncryption: AESEncryption!
    
    override func setUp() {
        super.setUp()
        aesEncryption = AESEncryption()
    }
    
    override func tearDown() {
        aesEncryption = nil
        super.tearDown()
    }
    
    // MARK: - Key Generation Tests
    
    func testGenerateKey() throws {
        let key = try aesEncryption.generateKey()
        XCTAssertNotNil(key)
        XCTAssertEqual(key.count, 32) // AES-256 key size
    }
    
    func testGenerateKeyWithCustomSize() throws {
        let key = try aesEncryption.generateKey(size: .bits128)
        XCTAssertNotNil(key)
        XCTAssertEqual(key.count, 16) // AES-128 key size
    }
    
    func testGenerateKeyWithInvalidSize() {
        XCTAssertThrowsError(try aesEncryption.generateKey(size: .bits64)) { error in
            XCTAssertEqual(error as? AESEncryptionError, .invalidKeySize)
        }
    }
    
    // MARK: - Encryption Tests
    
    func testEncryptString() throws {
        let key = try aesEncryption.generateKey()
        let plaintext = "Hello, World!"
        
        let encryptedData = try aesEncryption.encrypt(plaintext, with: key)
        XCTAssertNotNil(encryptedData)
        XCTAssertNotEqual(encryptedData, plaintext.data(using: .utf8))
    }
    
    func testEncryptData() throws {
        let key = try aesEncryption.generateKey()
        let plaintextData = "Secret message".data(using: .utf8)!
        
        let encryptedData = try aesEncryption.encrypt(plaintextData, with: key)
        XCTAssertNotNil(encryptedData)
        XCTAssertNotEqual(encryptedData, plaintextData)
    }
    
    func testEncryptEmptyString() throws {
        let key = try aesEncryption.generateKey()
        let plaintext = ""
        
        let encryptedData = try aesEncryption.encrypt(plaintext, with: key)
        XCTAssertNotNil(encryptedData)
    }
    
    func testEncryptLargeData() throws {
        let key = try aesEncryption.generateKey()
        let largeData = String(repeating: "A", count: 10000).data(using: .utf8)!
        
        let encryptedData = try aesEncryption.encrypt(largeData, with: key)
        XCTAssertNotNil(encryptedData)
        XCTAssertNotEqual(encryptedData, largeData)
    }
    
    // MARK: - Decryption Tests
    
    func testDecryptString() throws {
        let key = try aesEncryption.generateKey()
        let plaintext = "Hello, World!"
        
        let encryptedData = try aesEncryption.encrypt(plaintext, with: key)
        let decryptedString = try aesEncryption.decrypt(encryptedData, with: key)
        
        XCTAssertEqual(decryptedString, plaintext)
    }
    
    func testDecryptData() throws {
        let key = try aesEncryption.generateKey()
        let plaintextData = "Secret message".data(using: .utf8)!
        
        let encryptedData = try aesEncryption.encrypt(plaintextData, with: key)
        let decryptedData = try aesEncryption.decrypt(encryptedData, with: key)
        
        XCTAssertEqual(decryptedData, plaintextData)
    }
    
    func testDecryptWithWrongKey() throws {
        let key1 = try aesEncryption.generateKey()
        let key2 = try aesEncryption.generateKey()
        let plaintext = "Hello, World!"
        
        let encryptedData = try aesEncryption.encrypt(plaintext, with: key1)
        
        XCTAssertThrowsError(try aesEncryption.decrypt(encryptedData, with: key2)) { error in
            XCTAssertEqual(error as? AESEncryptionError, .decryptionFailed)
        }
    }
    
    func testDecryptCorruptedData() throws {
        let key = try aesEncryption.generateKey()
        let corruptedData = "Corrupted data".data(using: .utf8)!
        
        XCTAssertThrowsError(try aesEncryption.decrypt(corruptedData, with: key)) { error in
            XCTAssertEqual(error as? AESEncryptionError, .decryptionFailed)
        }
    }
    
    // MARK: - Performance Tests
    
    func testEncryptionPerformance() throws {
        let key = try aesEncryption.generateKey()
        let testData = String(repeating: "A", count: 1000).data(using: .utf8)!
        
        measure {
            do {
                _ = try aesEncryption.encrypt(testData, with: key)
            } catch {
                XCTFail("Encryption failed: \(error)")
            }
        }
    }
    
    func testDecryptionPerformance() throws {
        let key = try aesEncryption.generateKey()
        let testData = String(repeating: "A", count: 1000).data(using: .utf8)!
        let encryptedData = try aesEncryption.encrypt(testData, with: key)
        
        measure {
            do {
                _ = try aesEncryption.decrypt(encryptedData, with: key)
            } catch {
                XCTFail("Decryption failed: \(error)")
            }
        }
    }
    
    // MARK: - Memory Tests
    
    func testMemoryUsage() throws {
        let key = try aesEncryption.generateKey()
        let largeData = String(repeating: "A", count: 100000).data(using: .utf8)!
        
        // Measure memory before
        let memoryBefore = getMemoryUsage()
        
        let encryptedData = try aesEncryption.encrypt(largeData, with: key)
        let decryptedData = try aesEncryption.decrypt(encryptedData, with: key)
        
        // Measure memory after
        let memoryAfter = getMemoryUsage()
        
        XCTAssertEqual(decryptedData, largeData)
        XCTAssertLessThan(memoryAfter - memoryBefore, 50 * 1024 * 1024) // 50MB limit
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

// MARK: - AESEncryptionError Extension

extension AESEncryptionError: Equatable {
    public static func == (lhs: AESEncryptionError, rhs: AESEncryptionError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidKeySize, .invalidKeySize),
             (.encryptionFailed, .encryptionFailed),
             (.decryptionFailed, .decryptionFailed):
            return true
        default:
            return false
        }
    }
} 