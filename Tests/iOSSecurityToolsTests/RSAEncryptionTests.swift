import XCTest
import CryptoKit
@testable import iOSSecurityTools

final class RSAEncryptionTests: XCTestCase {
    
    var rsaEncryption: RSAEncryption!
    
    override func setUp() {
        super.setUp()
        rsaEncryption = RSAEncryption()
    }
    
    override func tearDown() {
        rsaEncryption = nil
        super.tearDown()
    }
    
    // MARK: - Key Pair Generation Tests
    
    func testGenerateKeyPair() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertNotEqual(keyPair.publicKey, keyPair.privateKey)
    }
    
    func testGenerateKeyPairWithCustomSize() throws {
        let keyPair = try rsaEncryption.generateKeyPair(size: .bits2048)
        
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertNotNil(keyPair.privateKey)
    }
    
    func testGenerateKeyPairWithInvalidSize() {
        XCTAssertThrowsError(try rsaEncryption.generateKeyPair(size: .bits512)) { error in
            XCTAssertEqual(error as? RSAEncryptionError, .invalidKeySize)
        }
    }
    
    // MARK: - Encryption Tests
    
    func testEncryptString() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let plaintext = "Hello, World!"
        
        let encryptedData = try rsaEncryption.encrypt(plaintext, with: keyPair.publicKey)
        XCTAssertNotNil(encryptedData)
        XCTAssertNotEqual(encryptedData, plaintext.data(using: .utf8))
    }
    
    func testEncryptData() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let plaintextData = "Secret message".data(using: .utf8)!
        
        let encryptedData = try rsaEncryption.encrypt(plaintextData, with: keyPair.publicKey)
        XCTAssertNotNil(encryptedData)
        XCTAssertNotEqual(encryptedData, plaintextData)
    }
    
    func testEncryptLargeData() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let largeData = String(repeating: "A", count: 100).data(using: .utf8)!
        
        let encryptedData = try rsaEncryption.encrypt(largeData, with: keyPair.publicKey)
        XCTAssertNotNil(encryptedData)
        XCTAssertNotEqual(encryptedData, largeData)
    }
    
    func testEncryptWithWrongKey() throws {
        let keyPair1 = try rsaEncryption.generateKeyPair()
        let keyPair2 = try rsaEncryption.generateKeyPair()
        let plaintext = "Hello, World!"
        
        let encryptedData = try rsaEncryption.encrypt(plaintext, with: keyPair1.publicKey)
        
        XCTAssertThrowsError(try rsaEncryption.decrypt(encryptedData, with: keyPair2.privateKey)) { error in
            XCTAssertEqual(error as? RSAEncryptionError, .decryptionFailed)
        }
    }
    
    // MARK: - Decryption Tests
    
    func testDecryptString() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let plaintext = "Hello, World!"
        
        let encryptedData = try rsaEncryption.encrypt(plaintext, with: keyPair.publicKey)
        let decryptedString = try rsaEncryption.decrypt(encryptedData, with: keyPair.privateKey)
        
        XCTAssertEqual(decryptedString, plaintext)
    }
    
    func testDecryptData() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let plaintextData = "Secret message".data(using: .utf8)!
        
        let encryptedData = try rsaEncryption.encrypt(plaintextData, with: keyPair.publicKey)
        let decryptedData = try rsaEncryption.decrypt(encryptedData, with: keyPair.privateKey)
        
        XCTAssertEqual(decryptedData, plaintextData)
    }
    
    func testDecryptCorruptedData() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let corruptedData = "Corrupted data".data(using: .utf8)!
        
        XCTAssertThrowsError(try rsaEncryption.decrypt(corruptedData, with: keyPair.privateKey)) { error in
            XCTAssertEqual(error as? RSAEncryptionError, .decryptionFailed)
        }
    }
    
    // MARK: - Digital Signature Tests
    
    func testSignData() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let data = "Message to sign".data(using: .utf8)!
        
        let signature = try rsaEncryption.sign(data, with: keyPair.privateKey)
        XCTAssertNotNil(signature)
    }
    
    func testVerifySignature() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let data = "Message to sign".data(using: .utf8)!
        
        let signature = try rsaEncryption.sign(data, with: keyPair.privateKey)
        let isValid = try rsaEncryption.verify(data, signature: signature, with: keyPair.publicKey)
        
        XCTAssertTrue(isValid)
    }
    
    func testVerifySignatureWithWrongKey() throws {
        let keyPair1 = try rsaEncryption.generateKeyPair()
        let keyPair2 = try rsaEncryption.generateKeyPair()
        let data = "Message to sign".data(using: .utf8)!
        
        let signature = try rsaEncryption.sign(data, with: keyPair1.privateKey)
        let isValid = try rsaEncryption.verify(data, signature: signature, with: keyPair2.publicKey)
        
        XCTAssertFalse(isValid)
    }
    
    func testVerifySignatureWithModifiedData() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let originalData = "Message to sign".data(using: .utf8)!
        let modifiedData = "Modified message".data(using: .utf8)!
        
        let signature = try rsaEncryption.sign(originalData, with: keyPair.privateKey)
        let isValid = try rsaEncryption.verify(modifiedData, signature: signature, with: keyPair.publicKey)
        
        XCTAssertFalse(isValid)
    }
    
    // MARK: - Performance Tests
    
    func testEncryptionPerformance() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let testData = "Test message".data(using: .utf8)!
        
        measure {
            do {
                _ = try rsaEncryption.encrypt(testData, with: keyPair.publicKey)
            } catch {
                XCTFail("Encryption failed: \(error)")
            }
        }
    }
    
    func testDecryptionPerformance() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let testData = "Test message".data(using: .utf8)!
        let encryptedData = try rsaEncryption.encrypt(testData, with: keyPair.publicKey)
        
        measure {
            do {
                _ = try rsaEncryption.decrypt(encryptedData, with: keyPair.privateKey)
            } catch {
                XCTFail("Decryption failed: \(error)")
            }
        }
    }
    
    func testSignaturePerformance() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let testData = "Test message".data(using: .utf8)!
        
        measure {
            do {
                _ = try rsaEncryption.sign(testData, with: keyPair.privateKey)
            } catch {
                XCTFail("Signing failed: \(error)")
            }
        }
    }
    
    // MARK: - Memory Tests
    
    func testMemoryUsage() throws {
        let keyPair = try rsaEncryption.generateKeyPair()
        let testData = String(repeating: "A", count: 1000).data(using: .utf8)!
        
        // Measure memory before
        let memoryBefore = getMemoryUsage()
        
        let encryptedData = try rsaEncryption.encrypt(testData, with: keyPair.publicKey)
        let decryptedData = try rsaEncryption.decrypt(encryptedData, with: keyPair.privateKey)
        
        // Measure memory after
        let memoryAfter = getMemoryUsage()
        
        XCTAssertEqual(decryptedData, testData)
        XCTAssertLessThan(memoryAfter - memoryBefore, 10 * 1024 * 1024) // 10MB limit
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

// MARK: - RSAEncryptionError Extension

extension RSAEncryptionError: Equatable {
    public static func == (lhs: RSAEncryptionError, rhs: RSAEncryptionError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidKeySize, .invalidKeySize),
             (.encryptionFailed, .encryptionFailed),
             (.decryptionFailed, .decryptionFailed),
             (.signingFailed, .signingFailed),
             (.verificationFailed, .verificationFailed):
            return true
        default:
            return false
        }
    }
} 