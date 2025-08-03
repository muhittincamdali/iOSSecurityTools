import Foundation
import CryptoKit
import Security

/// General security utilities for iOS applications
public class SecurityUtilities {
    
    // MARK: - Singleton
    public static let shared = SecurityUtilities()
    
    // MARK: - Private Properties
    private let keyGenerator = KeyGenerator.shared
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate secure random string
    public func generateSecureRandomString(length: Int = 32) -> String {
        let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        let randomString = String((0..<length).map { _ in
            characters.randomElement()!
        })
        return randomString
    }
    
    /// Generate secure random bytes
    public func generateSecureRandomBytes(length: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        
        guard status == errSecSuccess else {
            fatalError("Failed to generate secure random bytes")
        }
        
        return Data(bytes)
    }
    
    /// Generate UUID
    public func generateUUID() -> String {
        return UUID().uuidString
    }
    
    /// Hash data with SHA-256
    public func hashData(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }
    
    /// Hash string with SHA-256
    public func hashString(_ string: String) -> String {
        guard let data = string.data(using: .utf8) else {
            return ""
        }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate HMAC
    public func generateHMAC(data: Data, key: Data) -> Data {
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
    
    /// Generate HMAC for string
    public func generateHMAC(string: String, key: String) -> String {
        guard let data = string.data(using: .utf8),
              let keyData = key.data(using: .utf8) else {
            return ""
        }
        
        let hmacData = generateHMAC(data: data, key: keyData)
        return hmacData.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Verify HMAC
    public func verifyHMAC(data: Data, key: Data, hmac: Data) -> Bool {
        let computedHMAC = generateHMAC(data: data, key: key)
        return computedHMAC == hmac
    }
    
    /// Generate salt
    public func generateSalt(length: Int = 32) -> Data {
        return generateSecureRandomBytes(length: length)
    }
    
    /// Derive key from password using PBKDF2
    public func deriveKey(from password: String, salt: Data, rounds: Int = 100_000, keyLength: Int = 32) -> Data {
        let passwordData = password.data(using: .utf8)!
        
        var derivedKeyData = Data(repeating: 0, count: keyLength)
        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress,
                        passwordData.count,
                        saltBytes.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(rounds),
                        derivedKeyBytes.baseAddress,
                        derivedKeyData.count
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            fatalError("Failed to derive key from password")
        }
        
        return derivedKeyData
    }
    
    /// Generate secure password
    public func generateSecurePassword(length: Int = 16) -> String {
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let lowercase = "abcdefghijklmnopqrstuvwxyz"
        let numbers = "0123456789"
        let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        let allCharacters = uppercase + lowercase + numbers + symbols
        var password = ""
        
        // Ensure at least one character from each category
        password += uppercase.randomElement()!
        password += lowercase.randomElement()!
        password += numbers.randomElement()!
        password += symbols.randomElement()!
        
        // Fill the rest with random characters
        for _ in 4..<length {
            password += allCharacters.randomElement()!
        }
        
        // Shuffle the password
        return String(password.shuffled())
    }
    
    /// Check if device is jailbroken
    public func isDeviceJailbroken() -> Bool {
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    /// Check if app is running in debug mode
    public func isRunningInDebugMode() -> Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }
    
    /// Get app bundle identifier
    public func getAppBundleIdentifier() -> String {
        return Bundle.main.bundleIdentifier ?? "unknown"
    }
    
    /// Get app version
    public func getAppVersion() -> String {
        return Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
    }
    
    /// Get build number
    public func getBuildNumber() -> String {
        return Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
    }
    
    /// Get device model
    public func getDeviceModel() -> String {
        return UIDevice.current.model
    }
    
    /// Get system version
    public func getSystemVersion() -> String {
        return UIDevice.current.systemVersion
    }
    
    /// Get device identifier
    public func getDeviceIdentifier() -> String {
        return UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
    }
    
    /// Check if device supports biometric authentication
    public func supportsBiometricAuthentication() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Get biometric type
    public func getBiometricType() -> String {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "none"
        }
        
        switch context.biometryType {
        case .faceID:
            return "faceID"
        case .touchID:
            return "touchID"
        case .none:
            return "none"
        @unknown default:
            return "unknown"
        }
    }
    
    /// Check if device has secure enclave
    public func hasSecureEnclave() -> Bool {
        // This is a simplified check. In production, you'd need more sophisticated detection
        return supportsBiometricAuthentication()
    }
    
    /// Get available disk space
    public func getAvailableDiskSpace() -> Int64 {
        do {
            let attributes = try FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory())
            return attributes[.systemFreeSize] as? Int64 ?? 0
        } catch {
            return 0
        }
    }
    
    /// Check if device has enough disk space
    public func hasEnoughDiskSpace(requiredSpace: Int64) -> Bool {
        return getAvailableDiskSpace() >= requiredSpace
    }
    
    /// Get memory usage
    public func getMemoryUsage() -> Int {
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
    
    /// Check if memory usage is acceptable
    public func isMemoryUsageAcceptable(maxUsage: Int = 100 * 1024 * 1024) -> Bool {
        return getMemoryUsage() < maxUsage
    }
    
    /// Generate certificate fingerprint
    public func generateCertificateFingerprint(certificate: SecCertificate) -> String {
        let data = SecCertificateCopyData(certificate) as Data
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Validate certificate
    public func validateCertificate(_ certificate: SecCertificate) -> Bool {
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        
        guard status == errSecSuccess, let trust = trust else {
            return false
        }
        
        var result: SecTrustResultType = .invalid
        let trustStatus = SecTrustEvaluate(trust, &result)
        
        return trustStatus == errSecSuccess && (result == .unspecified || result == .proceed)
    }
    
    /// Get certificate expiration date
    public func getCertificateExpirationDate(_ certificate: SecCertificate) -> Date? {
        let data = SecCertificateCopyData(certificate) as Data
        
        guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
            return nil
        }
        
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(cert, policy, &trust)
        
        guard status == errSecSuccess, let trust = trust else {
            return nil
        }
        
        var result: SecTrustResultType = .invalid
        let trustStatus = SecTrustEvaluate(trust, &result)
        
        guard trustStatus == errSecSuccess else {
            return nil
        }
        
        return SecCertificateCopyValues(cert, nil, nil) as? Date
    }
    
    /// Check if certificate is expired
    public func isCertificateExpired(_ certificate: SecCertificate) -> Bool {
        guard let expirationDate = getCertificateExpirationDate(certificate) else {
            return true
        }
        
        return Date() > expirationDate
    }
    
    /// Generate secure token
    public func generateSecureToken(length: Int = 32) -> String {
        let data = generateSecureRandomBytes(length: length)
        return data.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
    
    /// Generate secure nonce
    public func generateSecureNonce() -> String {
        return generateSecureToken(length: 16)
    }
    
    /// Generate secure challenge
    public func generateSecureChallenge() -> String {
        return generateSecureToken(length: 64)
    }
} 