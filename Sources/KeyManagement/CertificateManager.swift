import Foundation
import Security

/// SSL certificate manager for handling certificates
public class CertificateManager {
    
    // MARK: - Singleton
    public static let shared = CertificateManager()
    
    // MARK: - Private Properties
    private let keychainManager = KeychainManager.shared
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Load certificate from data
    public func loadCertificate(from data: Data) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            throw CertificateError.invalidCertificateData
        }
        return certificate
    }
    
    /// Load certificate from file
    public func loadCertificate(from fileURL: URL) throws -> SecCertificate {
        let data = try Data(contentsOf: fileURL)
        return try loadCertificate(from: data)
    }
    
    /// Load certificate from PEM string
    public func loadCertificate(fromPEM pemString: String) throws -> SecCertificate {
        // Remove PEM headers and footers
        let cleanPEM = pemString
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
        
        guard let data = Data(base64Encoded: cleanPEM) else {
            throw CertificateError.invalidPEMFormat
        }
        
        return try loadCertificate(from: data)
    }
    
    /// Get certificate data
    public func getCertificateData(_ certificate: SecCertificate) -> Data {
        return SecCertificateCopyData(certificate) as Data
    }
    
    /// Get certificate subject
    public func getCertificateSubject(_ certificate: SecCertificate) -> String? {
        let data = getCertificateData(certificate)
        
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
        
        return SecCertificateCopySubjectSummary(cert) as String?
    }
    
    /// Get certificate issuer
    public func getCertificateIssuer(_ certificate: SecCertificate) -> String? {
        let data = getCertificateData(certificate)
        
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
        
        return SecCertificateCopyIssuerSummary(cert) as String?
    }
    
    /// Get certificate expiration date
    public func getCertificateExpirationDate(_ certificate: SecCertificate) -> Date? {
        let data = getCertificateData(certificate)
        
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
    
    /// Validate certificate
    public func validateCertificate(_ certificate: SecCertificate) -> CertificateValidationResult {
        let data = getCertificateData(certificate)
        
        guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
            return CertificateValidationResult(isValid: false, error: .invalidCertificateData)
        }
        
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(cert, policy, &trust)
        
        guard status == errSecSuccess, let trust = trust else {
            return CertificateValidationResult(isValid: false, error: .trustCreationFailed)
        }
        
        var result: SecTrustResultType = .invalid
        let trustStatus = SecTrustEvaluate(trust, &result)
        
        guard trustStatus == errSecSuccess else {
            return CertificateValidationResult(isValid: false, error: .trustEvaluationFailed)
        }
        
        let isValid = result == .unspecified || result == .proceed
        let error: CertificateError? = isValid ? nil : .invalidCertificate
        
        return CertificateValidationResult(isValid: isValid, error: error)
    }
    
    /// Store certificate in Keychain
    public func storeCertificate(_ certificate: SecCertificate, forKey key: String) throws {
        try keychainManager.storeCertificate(certificate, forKey: key)
    }
    
    /// Retrieve certificate from Keychain
    public func retrieveCertificate(forKey key: String) throws -> SecCertificate {
        return try keychainManager.retrieveCertificate(forKey: key)
    }
    
    /// Delete certificate from Keychain
    public func deleteCertificate(forKey key: String) throws {
        try keychainManager.delete(forKey: key)
    }
    
    /// Check if certificate exists in Keychain
    public func certificateExists(forKey key: String) -> Bool {
        return keychainManager.exists(forKey: key)
    }
    
    /// Get certificate fingerprint
    public func getCertificateFingerprint(_ certificate: SecCertificate, algorithm: String = "SHA-256") -> String {
        let data = getCertificateData(certificate)
        
        switch algorithm.uppercased() {
        case "SHA-256":
            let hash = SHA256.hash(data: data)
            return hash.compactMap { String(format: "%02x", $0) }.joined()
        case "SHA-1":
            let hash = Insecure.SHA1.hash(data: data)
            return hash.compactMap { String(format: "%02x", $0) }.joined()
        default:
            let hash = SHA256.hash(data: data)
            return hash.compactMap { String(format: "%02x", $0) }.joined()
        }
    }
    
    /// Get certificate serial number
    public func getCertificateSerialNumber(_ certificate: SecCertificate) -> String? {
        let data = getCertificateData(certificate)
        
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
        
        return SecCertificateCopySerialNumber(cert)?.base64EncodedString()
    }
    
    /// Get certificate public key
    public func getCertificatePublicKey(_ certificate: SecCertificate) -> SecKey? {
        let data = getCertificateData(certificate)
        
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
        
        return SecTrustCopyPublicKey(trust)
    }
    
    /// Get certificate key size
    public func getCertificateKeySize(_ certificate: SecCertificate) -> Int? {
        guard let publicKey = getCertificatePublicKey(certificate) else {
            return nil
        }
        
        let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any]
        return attributes?[kSecAttrKeySizeInBits as String] as? Int
    }
    
    /// Get certificate signature algorithm
    public func getCertificateSignatureAlgorithm(_ certificate: SecCertificate) -> String? {
        let data = getCertificateData(certificate)
        
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
        
        return SecCertificateCopySignatureAlgorithm(cert) as String?
    }
    
    /// Export certificate to PEM format
    public func exportCertificateToPEM(_ certificate: SecCertificate) -> String {
        let data = getCertificateData(certificate)
        let base64String = data.base64EncodedString()
        
        let pemString = """
        -----BEGIN CERTIFICATE-----
        \(base64String)
        -----END CERTIFICATE-----
        """
        
        return pemString
    }
    
    /// Export certificate to DER format
    public func exportCertificateToDER(_ certificate: SecCertificate) -> Data {
        return getCertificateData(certificate)
    }
    
    /// Create certificate chain
    public func createCertificateChain(_ certificates: [SecCertificate]) -> SecTrust? {
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return trust
    }
    
    /// Validate certificate chain
    public func validateCertificateChain(_ certificates: [SecCertificate]) -> CertificateValidationResult {
        guard let trust = createCertificateChain(certificates) else {
            return CertificateValidationResult(isValid: false, error: .trustCreationFailed)
        }
        
        var result: SecTrustResultType = .invalid
        let trustStatus = SecTrustEvaluate(trust, &result)
        
        guard trustStatus == errSecSuccess else {
            return CertificateValidationResult(isValid: false, error: .trustEvaluationFailed)
        }
        
        let isValid = result == .unspecified || result == .proceed
        let error: CertificateError? = isValid ? nil : .invalidCertificate
        
        return CertificateValidationResult(isValid: isValid, error: error)
    }
}

// MARK: - Supporting Types

/// Certificate validation result
public struct CertificateValidationResult {
    public let isValid: Bool
    public let error: CertificateError?
}

/// Certificate-related errors
public enum CertificateError: LocalizedError {
    case invalidCertificateData
    case invalidPEMFormat
    case invalidCertificate
    case trustCreationFailed
    case trustEvaluationFailed
    case certificateNotFound
    case certificateExpired
    case certificateRevoked
    
    public var errorDescription: String? {
        switch self {
        case .invalidCertificateData:
            return "Invalid certificate data"
        case .invalidPEMFormat:
            return "Invalid PEM format"
        case .invalidCertificate:
            return "Invalid certificate"
        case .trustCreationFailed:
            return "Failed to create trust"
        case .trustEvaluationFailed:
            return "Failed to evaluate trust"
        case .certificateNotFound:
            return "Certificate not found"
        case .certificateExpired:
            return "Certificate has expired"
        case .certificateRevoked:
            return "Certificate has been revoked"
        }
    }
} 