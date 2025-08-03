import Foundation

/// Main iOS Security Tools module
public class iOSSecurityTools {
    
    // MARK: - Singleton
    public static let shared = iOSSecurityTools()
    
    // MARK: - Private Properties
    private let encryption = AESEncryption.shared
    private let keychainManager = KeychainManager.shared
    private let biometricAuth = BiometricAuth.shared
    private let secureStorage = SecureStorage.shared
    private let jwtManager = JWTManager.shared
    private let otpGenerator = OTPGenerator.shared
    private let oauthManager = OAuthManager.shared
    private let keyGenerator = KeyGenerator.shared
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Initialize security tools
    public func initialize() {
        // Initialize security components
        setupSecurityDefaults()
        validateSecurityConfiguration()
    }
    
    /// Get security status
    public func getSecurityStatus() -> SecurityStatus {
        return SecurityStatus(
            encryptionAvailable: true,
            keychainAvailable: keychainManager.exists(forKey: "test_key"),
            biometricAvailable: biometricAuth.isBiometricAvailable(),
            secureStorageAvailable: true,
            jwtAvailable: true,
            otpAvailable: true,
            oauthAvailable: true
        )
    }
    
    /// Perform security audit
    public func performSecurityAudit() async throws -> SecurityAudit {
        let vulnerabilities = try await SecurityScanner.shared.scanForVulnerabilities()
        
        return SecurityAudit(
            timestamp: Date(),
            vulnerabilities: vulnerabilities,
            recommendations: generateRecommendations(from: vulnerabilities),
            riskLevel: calculateRiskLevel(from: vulnerabilities)
        )
    }
    
    /// Encrypt sensitive data
    public func encryptSensitiveData(_ data: Data) throws -> EncryptedData {
        let key = try keyGenerator.generateAESKey()
        let encryptedData = try encryption.encrypt(data, with: key)
        
        return EncryptedData(
            data: encryptedData,
            key: key,
            timestamp: Date()
        )
    }
    
    /// Decrypt sensitive data
    public func decryptSensitiveData(_ encryptedData: EncryptedData) throws -> Data {
        return try encryption.decrypt(encryptedData.data, with: encryptedData.key)
    }
    
    /// Store sensitive data securely
    public func storeSensitiveData(_ data: Data, forKey key: String) throws {
        try secureStorage.store(data, forKey: key)
    }
    
    /// Retrieve sensitive data securely
    public func retrieveSensitiveData(forKey key: String) throws -> Data {
        return try secureStorage.retrieve(forKey: key)
    }
    
    /// Authenticate with biometrics
    public func authenticateWithBiometrics(reason: String) async throws {
        try await biometricAuth.authenticate(reason: reason)
    }
    
    /// Generate secure token
    public func generateSecureToken(payload: [String: Any], expiresIn: TimeInterval = 3600) throws -> String {
        return try jwtManager.createJWT(payload: payload, secret: getSecureSecret(), expiresIn: expiresIn)
    }
    
    /// Verify secure token
    public func verifySecureToken(_ token: String) throws -> Bool {
        return try jwtManager.verifyJWT(token, secret: getSecureSecret())
    }
    
    /// Generate OTP
    public func generateOTP(secret: String, digits: Int = 6) throws -> String {
        return try otpGenerator.generateTOTP(secret: secret, digits: digits)
    }
    
    /// Verify OTP
    public func verifyOTP(_ otp: String, secret: String) -> Bool {
        return otpGenerator.verifyTOTP(otp, secret: secret)
    }
    
    /// Generate OAuth URL
    public func generateOAuthURL(clientID: String, redirectURI: String, scope: String) throws -> URL {
        return try oauthManager.generateAuthorizationURL(
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope
        )
    }
    
    /// Exchange OAuth code for token
    public func exchangeOAuthCode(_ code: String, clientID: String, clientSecret: String, redirectURI: String) async throws -> OAuthToken {
        return try await oauthManager.exchangeCodeForToken(
            code: code,
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI
        )
    }
    
    /// Generate secure random string
    public func generateSecureRandomString(length: Int) throws -> String {
        return try keyGenerator.generateRandomString(length: length)
    }
    
    /// Generate secure random bytes
    public func generateSecureRandomBytes(length: Int) throws -> Data {
        return try keyGenerator.generateRandomBytes(length: length)
    }
    
    /// Hash data securely
    public func hashData(_ data: Data) -> Data {
        return HashGenerator.shared.sha256(data)
    }
    
    /// Hash string securely
    public func hashString(_ string: String) -> String {
        return HashGenerator.shared.sha256(string)
    }
    
    /// Validate input securely
    public func validateInput(_ input: String, type: InputType) -> ValidationResult {
        let validationTools = ValidationTools()
        
        switch type {
        case .email:
            return ValidationResult(
                isValid: validationTools.isValidEmail(input),
                message: validationTools.isValidEmail(input) ? "Valid email" : "Invalid email format"
            )
        case .password:
            let strength = validationTools.checkPasswordStrength(input)
            return ValidationResult(
                isValid: strength.score >= 3,
                message: "Password strength: \(strength.score)/5"
            )
        case .url:
            return ValidationResult(
                isValid: URL(string: input) != nil,
                message: URL(string: input) != nil ? "Valid URL" : "Invalid URL format"
            )
        case .phone:
            return ValidationResult(
                isValid: validationTools.isValidPhone(input),
                message: validationTools.isValidPhone(input) ? "Valid phone" : "Invalid phone format"
            )
        }
    }
    
    /// Sanitize input
    public func sanitizeInput(_ input: String, type: SanitizationType) -> String {
        let validationTools = ValidationTools()
        
        switch type {
        case .html:
            return validationTools.sanitizeHTML(input)
        case .sql:
            return validationTools.sanitizeSQLInput(input)
        case .javascript:
            return validationTools.sanitizeJavaScript(input)
        case .url:
            return validationTools.sanitizeURL(input)
        }
    }
    
    /// Get security configuration
    public func getSecurityConfiguration() -> SecurityConfiguration {
        return SecurityConfiguration(
            encryptionAlgorithm: "AES-256-GCM",
            hashAlgorithm: "SHA-256",
            keySize: 256,
            tokenExpiration: 3600,
            otpDigits: 6,
            otpPeriod: 30,
            maxLoginAttempts: 5,
            sessionTimeout: 1800,
            requireBiometric: false,
            enableAuditLogging: true,
            enableThreatDetection: true
        )
    }
    
    /// Update security configuration
    public func updateSecurityConfiguration(_ config: SecurityConfiguration) {
        // Update security configuration
        UserDefaults.standard.set(config.tokenExpiration, forKey: "security_token_expiration")
        UserDefaults.standard.set(config.otpDigits, forKey: "security_otp_digits")
        UserDefaults.standard.set(config.maxLoginAttempts, forKey: "security_max_login_attempts")
        UserDefaults.standard.set(config.sessionTimeout, forKey: "security_session_timeout")
        UserDefaults.standard.set(config.requireBiometric, forKey: "security_require_biometric")
        UserDefaults.standard.set(config.enableAuditLogging, forKey: "security_enable_audit_logging")
        UserDefaults.standard.set(config.enableThreatDetection, forKey: "security_enable_threat_detection")
    }
    
    // MARK: - Private Methods
    
    private func setupSecurityDefaults() {
        // Set default security configuration
        let defaultConfig = SecurityConfiguration()
        updateSecurityConfiguration(defaultConfig)
    }
    
    private func validateSecurityConfiguration() {
        // Validate security configuration
        let config = getSecurityConfiguration()
        
        guard config.keySize >= 256 else {
            fatalError("Security configuration invalid: key size must be at least 256 bits")
        }
        
        guard config.tokenExpiration > 0 else {
            fatalError("Security configuration invalid: token expiration must be positive")
        }
    }
    
    private func getSecureSecret() -> String {
        // In production, this should be stored securely
        return "your-secure-secret-key"
    }
    
    private func generateRecommendations(from vulnerabilities: [SecurityVulnerability]) -> [String] {
        return vulnerabilities.map { $0.recommendation }
    }
    
    private func calculateRiskLevel(from vulnerabilities: [SecurityVulnerability]) -> RiskLevel {
        let highCount = vulnerabilities.filter { $0.severity == .high }.count
        let mediumCount = vulnerabilities.filter { $0.severity == .medium }.count
        let lowCount = vulnerabilities.filter { $0.severity == .low }.count
        
        if highCount > 0 {
            return .high
        } else if mediumCount > 2 {
            return .medium
        } else if lowCount > 5 {
            return .low
        } else {
            return .minimal
        }
    }
}

// MARK: - Supporting Types

/// Security status
public struct SecurityStatus {
    public let encryptionAvailable: Bool
    public let keychainAvailable: Bool
    public let biometricAvailable: Bool
    public let secureStorageAvailable: Bool
    public let jwtAvailable: Bool
    public let otpAvailable: Bool
    public let oauthAvailable: Bool
}

/// Security audit
public struct SecurityAudit {
    public let timestamp: Date
    public let vulnerabilities: [SecurityVulnerability]
    public let recommendations: [String]
    public let riskLevel: RiskLevel
}

/// Encrypted data
public struct EncryptedData {
    public let data: Data
    public let key: SymmetricKey
    public let timestamp: Date
}

/// Input types for validation
public enum InputType {
    case email
    case password
    case url
    case phone
}

/// Sanitization types
public enum SanitizationType {
    case html
    case sql
    case javascript
    case url
}

/// Validation result
public struct ValidationResult {
    public let isValid: Bool
    public let message: String
}

/// Security configuration
public struct SecurityConfiguration {
    public let encryptionAlgorithm: String
    public let hashAlgorithm: String
    public let keySize: Int
    public let tokenExpiration: TimeInterval
    public let otpDigits: Int
    public let otpPeriod: Int
    public let maxLoginAttempts: Int
    public let sessionTimeout: TimeInterval
    public let requireBiometric: Bool
    public let enableAuditLogging: Bool
    public let enableThreatDetection: Bool
    
    public init(
        encryptionAlgorithm: String = "AES-256-GCM",
        hashAlgorithm: String = "SHA-256",
        keySize: Int = 256,
        tokenExpiration: TimeInterval = 3600,
        otpDigits: Int = 6,
        otpPeriod: Int = 30,
        maxLoginAttempts: Int = 5,
        sessionTimeout: TimeInterval = 1800,
        requireBiometric: Bool = false,
        enableAuditLogging: Bool = true,
        enableThreatDetection: Bool = true
    ) {
        self.encryptionAlgorithm = encryptionAlgorithm
        self.hashAlgorithm = hashAlgorithm
        self.keySize = keySize
        self.tokenExpiration = tokenExpiration
        self.otpDigits = otpDigits
        self.otpPeriod = otpPeriod
        self.maxLoginAttempts = maxLoginAttempts
        self.sessionTimeout = sessionTimeout
        self.requireBiometric = requireBiometric
        self.enableAuditLogging = enableAuditLogging
        self.enableThreatDetection = enableThreatDetection
    }
}

/// Risk levels
public enum RiskLevel {
    case minimal
    case low
    case medium
    case high
    case critical
} 