import UIKit
import iOSSecurityTools

class AdvancedSecurityExampleViewController: UIViewController {
    
    // MARK: - UI Components
    private let scrollView = UIScrollView()
    private let contentView = UIView()
    
    private let titleLabel = UILabel()
    private let descriptionLabel = UILabel()
    
    private let hybridEncryptionSection = UIView()
    private let multiFactorSection = UIView()
    private let threatDetectionSection = UIView()
    private let complianceSection = UIView()
    
    // MARK: - Security Tools
    private let hybridEncryption = HybridEncryption()
    private let multiFactorAuth = MultiFactorAuth()
    private let threatDetector = AdvancedThreatDetector()
    private let complianceManager = ComplianceManager()
    
    // MARK: - Lifecycle
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        setupAdvancedSecurityFeatures()
        demonstrateAdvancedFeatures()
    }
    
    // MARK: - UI Setup
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        setupScrollView()
        setupTitleSection()
        setupHybridEncryptionSection()
        setupMultiFactorSection()
        setupThreatDetectionSection()
        setupComplianceSection()
    }
    
    private func setupScrollView() {
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)
        
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        contentView.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            
            contentView.topAnchor.constraint(equalTo: scrollView.topAnchor),
            contentView.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor),
            contentView.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor),
            contentView.widthAnchor.constraint(equalTo: scrollView.widthAnchor)
        ])
    }
    
    private func setupTitleSection() {
        titleLabel.text = "iOS Security Tools - Advanced Example"
        titleLabel.font = .systemFont(ofSize: 24, weight: .bold)
        titleLabel.textAlignment = .center
        titleLabel.numberOfLines = 0
        
        descriptionLabel.text = "This example demonstrates advanced security features including hybrid encryption, multi-factor authentication, threat detection, and compliance management."
        descriptionLabel.font = .systemFont(ofSize: 16)
        descriptionLabel.textAlignment = .center
        descriptionLabel.numberOfLines = 0
        descriptionLabel.textColor = .secondaryLabel
        
        contentView.addSubview(titleLabel)
        contentView.addSubview(descriptionLabel)
        
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        descriptionLabel.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 20),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            
            descriptionLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 10),
            descriptionLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            descriptionLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20)
        ])
    }
    
    private func setupHybridEncryptionSection() {
        let sectionTitle = createSectionTitle("🔐 Hybrid Encryption")
        let sectionDescription = createSectionDescription("Demonstrates AES + RSA hybrid encryption")
        
        let encryptButton = createButton("Encrypt with Hybrid", action: #selector(hybridEncrypt))
        let decryptButton = createButton("Decrypt with Hybrid", action: #selector(hybridDecrypt))
        
        hybridEncryptionSection.addSubview(sectionTitle)
        hybridEncryptionSection.addSubview(sectionDescription)
        hybridEncryptionSection.addSubview(encryptButton)
        hybridEncryptionSection.addSubview(decryptButton)
        
        contentView.addSubview(hybridEncryptionSection)
        
        setupSectionConstraints(hybridEncryptionSection, after: descriptionLabel)
        setupButtonConstraints([encryptButton, decryptButton], in: hybridEncryptionSection)
    }
    
    private func setupMultiFactorSection() {
        let sectionTitle = createSectionTitle("🛡️ Multi-Factor Authentication")
        let sectionDescription = createSectionDescription("Demonstrates MFA with biometrics and OTP")
        
        let mfaButton = createButton("Authenticate with MFA", action: #selector(authenticateWithMFA))
        let setupMFAButton = createButton("Setup MFA", action: #selector(setupMFA))
        
        multiFactorSection.addSubview(sectionTitle)
        multiFactorSection.addSubview(sectionDescription)
        multiFactorSection.addSubview(mfaButton)
        multiFactorSection.addSubview(setupMFAButton)
        
        contentView.addSubview(multiFactorSection)
        
        setupSectionConstraints(multiFactorSection, after: hybridEncryptionSection)
        setupButtonConstraints([mfaButton, setupMFAButton], in: multiFactorSection)
    }
    
    private func setupThreatDetectionSection() {
        let sectionTitle = createSectionTitle("🚨 Threat Detection")
        let sectionDescription = createSectionDescription("Demonstrates real-time threat detection")
        
        let startMonitoringButton = createButton("Start Monitoring", action: #selector(startThreatMonitoring))
        let analyzeThreatsButton = createButton("Analyze Threats", action: #selector(analyzeThreats))
        
        threatDetectionSection.addSubview(sectionTitle)
        threatDetectionSection.addSubview(sectionDescription)
        threatDetectionSection.addSubview(startMonitoringButton)
        threatDetectionSection.addSubview(analyzeThreatsButton)
        
        contentView.addSubview(threatDetectionSection)
        
        setupSectionConstraints(threatDetectionSection, after: multiFactorSection)
        setupButtonConstraints([startMonitoringButton, analyzeThreatsButton], in: threatDetectionSection)
    }
    
    private func setupComplianceSection() {
        let sectionTitle = createSectionTitle("✅ Compliance Management")
        let sectionDescription = createSectionDescription("Demonstrates GDPR and CCPA compliance")
        
        let gdprButton = createButton("Check GDPR", action: #selector(checkGDPR))
        let ccpaButton = createButton("Check CCPA", action: #selector(checkCCPA))
        
        complianceSection.addSubview(sectionTitle)
        complianceSection.addSubview(sectionDescription)
        complianceSection.addSubview(gdprButton)
        complianceSection.addSubview(ccpaButton)
        
        contentView.addSubview(complianceSection)
        
        setupSectionConstraints(complianceSection, after: threatDetectionSection)
        setupButtonConstraints([gdprButton, ccpaButton], in: complianceSection)
        
        // Set bottom constraint for scroll view
        complianceSection.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -20).isActive = true
    }
    
    // MARK: - Helper Methods
    
    private func createSectionTitle(_ text: String) -> UILabel {
        let label = UILabel()
        label.text = text
        label.font = .systemFont(ofSize: 20, weight: .semibold)
        label.textColor = .label
        return label
    }
    
    private func createSectionDescription(_ text: String) -> UILabel {
        let label = UILabel()
        label.text = text
        label.font = .systemFont(ofSize: 14)
        label.textColor = .secondaryLabel
        label.numberOfLines = 0
        return label
    }
    
    private func createButton(_ title: String, action: Selector) -> UIButton {
        let button = UIButton(type: .system)
        button.setTitle(title, for: .normal)
        button.titleLabel?.font = .systemFont(ofSize: 16, weight: .medium)
        button.backgroundColor = .systemBlue
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 8
        button.addTarget(self, action: action, for: .touchUpInside)
        return button
    }
    
    private func setupSectionConstraints(_ section: UIView, after previousView: UIView) {
        section.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            section.topAnchor.constraint(equalTo: previousView.bottomAnchor, constant: 30),
            section.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            section.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20)
        ])
    }
    
    private func setupButtonConstraints(_ buttons: [UIButton], in section: UIView) {
        for (index, button) in buttons.enumerated() {
            button.translatesAutoresizingMaskIntoConstraints = false
            
            NSLayoutConstraint.activate([
                button.topAnchor.constraint(equalTo: section.subviews[index * 2 + 1].bottomAnchor, constant: 10),
                button.leadingAnchor.constraint(equalTo: section.leadingAnchor),
                button.trailingAnchor.constraint(equalTo: section.trailingAnchor),
                button.heightAnchor.constraint(equalToConstant: 44)
            ])
        }
    }
    
    // MARK: - Advanced Security Setup
    
    private func setupAdvancedSecurityFeatures() {
        // Initialize advanced security features
        SecurityTools.initialize()
    }
    
    // MARK: - Advanced Demonstrations
    
    private func demonstrateAdvancedFeatures() {
        // This method can be used to demonstrate advanced security features
        print("Advanced security features initialized successfully")
    }
    
    // MARK: - Button Actions
    
    @objc private func hybridEncrypt() {
        do {
            let keyPair = try RSAEncryption().generateKeyPair()
            let data = "Advanced hybrid encryption test".data(using: .utf8)!
            
            let encryptedData = try hybridEncryption.encrypt(data, with: keyPair)
            
            showAlert(title: "Hybrid Encryption Success", message: "Data encrypted with hybrid method")
            print("Hybrid encrypted data size: \(encryptedData.encryptedData.count) bytes")
        } catch {
            showAlert(title: "Hybrid Encryption Error", message: "Failed to encrypt: \(error)")
        }
    }
    
    @objc private func hybridDecrypt() {
        do {
            let keyPair = try RSAEncryption().generateKeyPair()
            let data = "Advanced hybrid encryption test".data(using: .utf8)!
            
            let encryptedData = try hybridEncryption.encrypt(data, with: keyPair)
            let decryptedData = try hybridEncryption.decrypt(encryptedData, with: keyPair)
            
            let decryptedString = String(data: decryptedData, encoding: .utf8) ?? "Failed to decode"
            showAlert(title: "Hybrid Decryption Success", message: "Decrypted: \(decryptedString)")
        } catch {
            showAlert(title: "Hybrid Decryption Error", message: "Failed to decrypt: \(error)")
        }
    }
    
    @objc private func authenticateWithMFA() {
        Task {
            do {
                let result = try await multiFactorAuth.authenticateWithMFA(
                    userId: "user123",
                    password: "securePassword123!"
                )
                
                await MainActor.run {
                    showAlert(title: "MFA Success", message: "Authentication successful with token: \(result.token.prefix(20))...")
                }
            } catch {
                await MainActor.run {
                    showAlert(title: "MFA Failed", message: "Authentication failed: \(error)")
                }
            }
        }
    }
    
    @objc private func setupMFA() {
        showAlert(title: "MFA Setup", message: "Multi-factor authentication setup initiated")
    }
    
    @objc private func startThreatMonitoring() {
        Task {
            do {
                let threats = try await threatDetector.monitorForThreats()
                
                await MainActor.run {
                    showAlert(title: "Threat Monitoring", message: "Monitoring started. Found \(threats.count) threats.")
                }
            } catch {
                await MainActor.run {
                    showAlert(title: "Monitoring Error", message: "Failed to start monitoring: \(error)")
                }
            }
        }
    }
    
    @objc private func analyzeThreats() {
        Task {
            do {
                let analysis = try await threatDetector.analyzeSecurityEvents()
                
                await MainActor.run {
                    showAlert(title: "Threat Analysis", message: "Analysis completed. Risk level: \(analysis.riskLevel)")
                }
            } catch {
                await MainActor.run {
                    showAlert(title: "Analysis Error", message: "Failed to analyze threats: \(error)")
                }
            }
        }
    }
    
    @objc private func checkGDPR() {
        Task {
            do {
                let report = try await complianceManager.checkGDPRCompliance()
                
                await MainActor.run {
                    showAlert(title: "GDPR Compliance", message: "GDPR compliance: \(report.isCompliant ? "Compliant" : "Non-compliant")")
                }
            } catch {
                await MainActor.run {
                    showAlert(title: "GDPR Check Error", message: "Failed to check GDPR: \(error)")
                }
            }
        }
    }
    
    @objc private func checkCCPA() {
        Task {
            do {
                let report = try await complianceManager.checkCCPACompliance()
                
                await MainActor.run {
                    showAlert(title: "CCPA Compliance", message: "CCPA compliance: \(report.isCompliant ? "Compliant" : "Non-compliant")")
                }
            } catch {
                await MainActor.run {
                    showAlert(title: "CCPA Check Error", message: "Failed to check CCPA: \(error)")
                }
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func showAlert(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}

// MARK: - Supporting Classes

class HybridEncryption {
    private let aesEncryption = AESEncryption()
    private let rsaEncryption = RSAEncryption()
    
    func encrypt(_ data: Data, with rsaKeyPair: RSAKeyPair) throws -> HybridEncryptedData {
        let aesKey = try aesEncryption.generateKey()
        let encryptedData = try aesEncryption.encrypt(data, with: aesKey)
        let encryptedAESKey = try rsaEncryption.encrypt(aesKey, with: rsaKeyPair.publicKey)
        
        return HybridEncryptedData(
            encryptedData: encryptedData,
            encryptedKey: encryptedAESKey
        )
    }
    
    func decrypt(_ hybridData: HybridEncryptedData, with rsaKeyPair: RSAKeyPair) throws -> Data {
        let aesKey = try rsaEncryption.decrypt(hybridData.encryptedKey, with: rsaKeyPair.privateKey)
        return try aesEncryption.decrypt(hybridData.encryptedData, with: aesKey)
    }
}

struct HybridEncryptedData {
    let encryptedData: Data
    let encryptedKey: Data
}

class MultiFactorAuth {
    private let biometricAuth = BiometricAuth()
    private let otpGenerator = OTPGenerator()
    private let jwtManager = JWTManager()
    
    func authenticateWithMFA(userId: String, password: String) async throws -> AuthResult {
        guard validatePassword(password) else {
            throw AuthError.invalidPassword
        }
        
        try await biometricAuth.authenticate(reason: "Multi-factor authentication")
        
        let otp = otpGenerator.generateOTP()
        let payload = [
            "user_id": userId,
            "otp": otp,
            "auth_method": "mfa"
        ]
        
        let jwt = try jwtManager.createJWT(
            payload: payload,
            secret: "your-secret-key",
            expiresIn: 3600
        )
        
        return AuthResult(
            token: jwt,
            otp: otp,
            expiresAt: Date().addingTimeInterval(3600)
        )
    }
    
    private func validatePassword(_ password: String) -> Bool {
        return password.count >= 8
    }
}

struct AuthResult {
    let token: String
    let otp: String
    let expiresAt: Date
}

enum AuthError: Error {
    case invalidPassword
    case biometricFailed
    case otpGenerationFailed
}

class AdvancedThreatDetector {
    private let threatDetector = ThreatDetector()
    private let auditLogger = AuditLogger()
    
    func monitorForThreats() async throws -> [Threat] {
        let config = ThreatDetectionConfiguration(
            enableRealTimeMonitoring: true,
            threatLevel: .high,
            monitoringInterval: 30
        )
        
        return try await threatDetector.detectThreats(configuration: config)
    }
    
    func analyzeSecurityEvents() async throws -> SecurityAnalysis {
        let events = try await auditLogger.getSecurityEvents()
        return try await threatDetector.analyzeEvents(events)
    }
}

struct Threat {
    let type: ThreatType
    let severity: ThreatSeverity
    let timestamp: Date
}

enum ThreatType: String {
    case unauthorizedAccess = "unauthorized_access"
    case dataBreach = "data_breach"
    case malware = "malware"
}

enum ThreatSeverity: String {
    case low = "low"
    case medium = "medium"
    case high = "high"
    case critical = "critical"
}

struct SecurityAnalysis {
    let riskLevel: String
    let threats: [Threat]
    let recommendations: [String]
}

class ComplianceManager {
    private let complianceChecker = ComplianceChecker()
    
    func checkGDPRCompliance() async throws -> ComplianceReport {
        let config = GDPRComplianceConfiguration(
            dataRetentionPeriod: 30,
            userConsentRequired: true,
            dataPortabilityEnabled: true
        )
        
        return try await complianceChecker.checkGDPRCompliance(configuration: config)
    }
    
    func checkCCPACompliance() async throws -> ComplianceReport {
        let config = CCPAComplianceConfiguration(
            privacyNoticeRequired: true,
            optOutMechanismEnabled: true
        )
        
        return try await complianceChecker.checkCCPACompliance(configuration: config)
    }
}

struct ComplianceReport {
    let isCompliant: Bool
    let violations: [String]
    let recommendations: [String]
} 