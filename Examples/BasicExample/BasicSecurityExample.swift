import UIKit
import iOSSecurityTools

class BasicSecurityExampleViewController: UIViewController {
    
    // MARK: - UI Components
    private let scrollView = UIScrollView()
    private let contentView = UIView()
    
    private let titleLabel = UILabel()
    private let descriptionLabel = UILabel()
    
    private let encryptionSection = UIView()
    private let keychainSection = UIView()
    private let biometricSection = UIView()
    private let validationSection = UIView()
    
    // MARK: - Security Tools
    private let aesEncryption = AESEncryption()
    private let keychainManager = KeychainManager()
    private let biometricAuth = BiometricAuth()
    private let validationTools = ValidationTools()
    
    // MARK: - Lifecycle
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        setupSecurityTools()
        demonstrateSecurityFeatures()
    }
    
    // MARK: - UI Setup
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        setupScrollView()
        setupTitleSection()
        setupEncryptionSection()
        setupKeychainSection()
        setupBiometricSection()
        setupValidationSection()
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
        titleLabel.text = "iOS Security Tools - Basic Example"
        titleLabel.font = .systemFont(ofSize: 24, weight: .bold)
        titleLabel.textAlignment = .center
        titleLabel.numberOfLines = 0
        
        descriptionLabel.text = "This example demonstrates basic security features including encryption, keychain storage, biometric authentication, and input validation."
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
    
    private func setupEncryptionSection() {
        let sectionTitle = createSectionTitle("🔐 Encryption")
        let sectionDescription = createSectionDescription("Demonstrates AES encryption and decryption")
        
        let encryptButton = createButton("Encrypt Data", action: #selector(encryptData))
        let decryptButton = createButton("Decrypt Data", action: #selector(decryptData))
        
        encryptionSection.addSubview(sectionTitle)
        encryptionSection.addSubview(sectionDescription)
        encryptionSection.addSubview(encryptButton)
        encryptionSection.addSubview(decryptButton)
        
        contentView.addSubview(encryptionSection)
        
        setupSectionConstraints(encryptionSection, after: descriptionLabel)
        setupButtonConstraints([encryptButton, decryptButton], in: encryptionSection)
    }
    
    private func setupKeychainSection() {
        let sectionTitle = createSectionTitle("🔑 Keychain Storage")
        let sectionDescription = createSectionDescription("Demonstrates secure key storage in Keychain")
        
        let storeButton = createButton("Store Key", action: #selector(storeKey))
        let retrieveButton = createButton("Retrieve Key", action: #selector(retrieveKey))
        
        keychainSection.addSubview(sectionTitle)
        keychainSection.addSubview(sectionDescription)
        keychainSection.addSubview(storeButton)
        keychainSection.addSubview(retrieveButton)
        
        contentView.addSubview(keychainSection)
        
        setupSectionConstraints(keychainSection, after: encryptionSection)
        setupButtonConstraints([storeButton, retrieveButton], in: keychainSection)
    }
    
    private func setupBiometricSection() {
        let sectionTitle = createSectionTitle("🛡️ Biometric Authentication")
        let sectionDescription = createSectionDescription("Demonstrates Face ID and Touch ID integration")
        
        let checkButton = createButton("Check Biometric", action: #selector(checkBiometric))
        let authenticateButton = createButton("Authenticate", action: #selector(authenticate))
        
        biometricSection.addSubview(sectionTitle)
        biometricSection.addSubview(sectionDescription)
        biometricSection.addSubview(checkButton)
        biometricSection.addSubview(authenticateButton)
        
        contentView.addSubview(biometricSection)
        
        setupSectionConstraints(biometricSection, after: keychainSection)
        setupButtonConstraints([checkButton, authenticateButton], in: biometricSection)
    }
    
    private func setupValidationSection() {
        let sectionTitle = createSectionTitle("✅ Input Validation")
        let sectionDescription = createSectionDescription("Demonstrates input validation and sanitization")
        
        let emailButton = createButton("Validate Email", action: #selector(validateEmail))
        let passwordButton = createButton("Check Password", action: #selector(checkPassword))
        
        validationSection.addSubview(sectionTitle)
        validationSection.addSubview(sectionDescription)
        validationSection.addSubview(emailButton)
        validationSection.addSubview(passwordButton)
        
        contentView.addSubview(validationSection)
        
        setupSectionConstraints(validationSection, after: biometricSection)
        setupButtonConstraints([emailButton, passwordButton], in: validationSection)
        
        // Set bottom constraint for scroll view
        validationSection.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -20).isActive = true
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
    
    // MARK: - Security Setup
    
    private func setupSecurityTools() {
        // Initialize security tools
        try? SecurityTools.initialize()
    }
    
    // MARK: - Security Demonstrations
    
    private func demonstrateSecurityFeatures() {
        // This method can be used to demonstrate security features
        print("Security tools initialized successfully")
    }
    
    // MARK: - Button Actions
    
    @objc private func encryptData() {
        do {
            let key = try aesEncryption.generateKey()
            let plaintext = "Hello, Security World!"
            let encryptedData = try aesEncryption.encrypt(plaintext, with: key)
            
            showAlert(title: "Encryption Success", message: "Data encrypted successfully")
            print("Encrypted data: \(encryptedData)")
        } catch {
            showAlert(title: "Encryption Error", message: "Failed to encrypt data: \(error)")
        }
    }
    
    @objc private func decryptData() {
        do {
            let key = try aesEncryption.generateKey()
            let plaintext = "Hello, Security World!"
            let encryptedData = try aesEncryption.encrypt(plaintext, with: key)
            let decryptedString = try aesEncryption.decrypt(encryptedData, with: key)
            
            showAlert(title: "Decryption Success", message: "Decrypted: \(decryptedString)")
        } catch {
            showAlert(title: "Decryption Error", message: "Failed to decrypt data: \(error)")
        }
    }
    
    @objc private func storeKey() {
        do {
            try keychainManager.store(key: "my-secret-key", forKey: "example-key")
            showAlert(title: "Key Stored", message: "Key stored successfully in Keychain")
        } catch {
            showAlert(title: "Storage Error", message: "Failed to store key: \(error)")
        }
    }
    
    @objc private func retrieveKey() {
        do {
            let retrievedKey = try keychainManager.retrieve(forKey: "example-key")
            showAlert(title: "Key Retrieved", message: "Retrieved key: \(retrievedKey)")
        } catch {
            showAlert(title: "Retrieval Error", message: "Failed to retrieve key: \(error)")
        }
    }
    
    @objc private func checkBiometric() {
        let biometricType = biometricAuth.getBiometricType()
        let message: String
        
        switch biometricType {
        case .faceID:
            message = "Face ID is available"
        case .touchID:
            message = "Touch ID is available"
        case .none:
            message = "No biometric authentication available"
        }
        
        showAlert(title: "Biometric Status", message: message)
    }
    
    @objc private func authenticate() {
        Task {
            do {
                try await biometricAuth.authenticate(reason: "Authenticate to access secure features")
                await MainActor.run {
                    showAlert(title: "Authentication Success", message: "Biometric authentication successful")
                }
            } catch {
                await MainActor.run {
                    showAlert(title: "Authentication Failed", message: "Biometric authentication failed: \(error)")
                }
            }
        }
    }
    
    @objc private func validateEmail() {
        let testEmails = ["user@example.com", "invalid-email", "test@domain.co.uk"]
        
        for email in testEmails {
            let isValid = validationTools.isValidEmail(email)
            print("Email '\(email)' is valid: \(isValid)")
        }
        
        showAlert(title: "Email Validation", message: "Check console for validation results")
    }
    
    @objc private func checkPassword() {
        let testPasswords = ["weak", "MySecurePassword123!", "password123"]
        
        for password in testPasswords {
            let strength = validationTools.checkPasswordStrength(password)
            print("Password '\(password)' strength: \(strength)")
        }
        
        showAlert(title: "Password Check", message: "Check console for password strength results")
    }
    
    // MARK: - Helper Methods
    
    private func showAlert(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
} 