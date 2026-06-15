import Foundation
import CryptoKit

/// iOSSecurityTools: Secure Memory Encryption.
/// 
/// Prevents sensitive data (Keys, Tokens) from remaining in plain-text 
/// within the heap, where it can be inspected via memory dumps.
public struct SecureRAM: Sendable {
    
    /// A wrapper that keeps data encrypted in RAM.
    public struct EncryptedValue: Sendable {
        private let encryptedData: Data
        private let key: SymmetricKey
        
        public init(_ plainText: String) throws {
            let data = Data(plainText.utf8)
            self.key = SymmetricKey(size: .bits256)
            let sealedBox = try AES.GCM.seal(data, using: key)
            self.encryptedData = sealedBox.combined!
        }
        
        /// Decrypts the value temporarily for usage. 
        /// Recommendation: Clear the result immediately after use.
        public func decrypt() throws -> String {
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            return String(data: decryptedData, encoding: .utf8) ?? ""
        }
    }
}
