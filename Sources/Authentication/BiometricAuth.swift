import Foundation
import LocalAuthentication
import Security

/// Biometric authentication manager for Face ID and Touch ID
public class BiometricAuth {
    
    // MARK: - Singleton
    public static let shared = BiometricAuth()
    
    // MARK: - Private Properties
    private let context = LAContext()
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Check if biometric authentication is available
    public func isBiometricAvailable() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Get biometric type
    public func getBiometricType() -> BiometricType {
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .none:
            return .none
        @unknown default:
            return .none
        }
    }
    
    /// Authenticate with biometrics
    public func authenticate(reason: String) async throws {
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: BiometricAuthError.authenticationFailed(error))
                }
            }
        }
    }
    
    /// Store biometric credential
    public func storeCredential(_ credential: String, forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: credential.data(using: .utf8)!,
            kSecAttrAccessControl as String: try createAccessControl()
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BiometricAuthError.storageFailed(status)
        }
    }
    
    /// Retrieve biometric credential
    public func retrieveCredential(forKey key: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseOperationPrompt as String: "Authenticate to access credential"
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let credential = String(data: data, encoding: .utf8) else {
            throw BiometricAuthError.retrievalFailed(status)
        }
        
        return credential
    }
    
    /// Delete biometric credential
    public func deleteCredential(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BiometricAuthError.deletionFailed(status)
        }
    }
    
    /// Check if credential exists
    public func credentialExists(forKey key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // MARK: - Private Methods
    
    private func createAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryAny,
            &error
        )
        
        guard let accessControl = accessControl else {
            throw BiometricAuthError.accessControlCreationFailed(error?.takeRetainedValue())
        }
        
        return accessControl
    }
}

// MARK: - Supporting Types

/// Biometric authentication types
public enum BiometricType {
    case faceID
    case touchID
    case none
}

/// Biometric authentication errors
public enum BiometricAuthError: LocalizedError {
    case authenticationFailed(Error?)
    case storageFailed(OSStatus)
    case retrievalFailed(OSStatus)
    case deletionFailed(OSStatus)
    case accessControlCreationFailed(CFError?)
    case biometricNotAvailable
    case biometricNotEnrolled
    case biometricLockout
    
    public var errorDescription: String? {
        switch self {
        case .authenticationFailed(let error):
            return "Biometric authentication failed: \(error?.localizedDescription ?? "Unknown error")"
        case .storageFailed(let status):
            return "Failed to store credential: \(status)"
        case .retrievalFailed(let status):
            return "Failed to retrieve credential: \(status)"
        case .deletionFailed(let status):
            return "Failed to delete credential: \(status)"
        case .accessControlCreationFailed(let error):
            return "Failed to create access control: \(error?.localizedDescription ?? "Unknown error")"
        case .biometricNotAvailable:
            return "Biometric authentication is not available"
        case .biometricNotEnrolled:
            return "No biometric authentication is enrolled"
        case .biometricLockout:
            return "Biometric authentication is locked out"
        }
    }
} 