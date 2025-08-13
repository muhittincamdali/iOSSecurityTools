import UIKit
import iOSSecurityTools

@main
class BasicExampleApp: UIResponder, UIApplicationDelegate {
    
    var window: UIWindow?
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        // Initialize security tools
        try? iOSSecurityTools.shared.initialize()
        
        // Setup window
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = BasicExampleViewController()
        window?.makeKeyAndVisible()
        
        return true
    }
}

class BasicExampleViewController: UIViewController {
    
    private let stackView = UIStackView()
    private let encryptButton = UIButton()
    private let decryptButton = UIButton()
    private let biometricButton = UIButton()
    private let storageButton = UIButton()
    private let resultLabel = UILabel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Setup stack view
        stackView.axis = .vertical
        stackView.spacing = 20
        stackView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stackView)
        
        // Setup buttons
        encryptButton.setTitle("Encrypt Data", for: .normal)
        encryptButton.backgroundColor = .systemBlue
        encryptButton.layer.cornerRadius = 8
        encryptButton.addTarget(self, action: #selector(encryptData), for: .touchUpInside)
        
        decryptButton.setTitle("Decrypt Data", for: .normal)
        decryptButton.backgroundColor = .systemGreen
        decryptButton.layer.cornerRadius = 8
        decryptButton.addTarget(self, action: #selector(decryptData), for: .touchUpInside)
        
        biometricButton.setTitle("Biometric Auth", for: .normal)
        biometricButton.backgroundColor = .systemOrange
        biometricButton.layer.cornerRadius = 8
        biometricButton.addTarget(self, action: #selector(biometricAuth), for: .touchUpInside)
        
        storageButton.setTitle("Secure Storage", for: .normal)
        storageButton.backgroundColor = .systemPurple
        storageButton.layer.cornerRadius = 8
        storageButton.addTarget(self, action: #selector(secureStorage), for: .touchUpInside)
        
        // Setup result label
        resultLabel.numberOfLines = 0
        resultLabel.textAlignment = .center
        resultLabel.text = "Tap a button to test security features"
        
        // Add subviews
        stackView.addArrangedSubview(encryptButton)
        stackView.addArrangedSubview(decryptButton)
        stackView.addArrangedSubview(biometricButton)
        stackView.addArrangedSubview(storageButton)
        stackView.addArrangedSubview(resultLabel)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            stackView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stackView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            stackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20)
        ])
    }
    
    @objc private func encryptData() {
        do {
            let encryption = AESEncryption.shared
            let key = try encryption.generateKey()
            let originalText = "Hello, Security World!"
            
            let encryptedData = try encryption.encrypt(originalText, with: key)
            let encryptedString = encryptedData.base64EncodedString()
            
            resultLabel.text = "Encrypted: \(encryptedString.prefix(50))..."
            
            // Store key for decryption
            UserDefaults.standard.set(key.withUnsafeBytes { Data($0) }, forKey: "demo_key")
            
        } catch {
            resultLabel.text = "Encryption failed: \(error.localizedDescription)"
        }
    }
    
    @objc private func decryptData() {
        do {
            let encryption = AESEncryption.shared
            
            // Get stored key
            guard let keyData = UserDefaults.standard.data(forKey: "demo_key"),
                  let encryptedData = UserDefaults.standard.data(forKey: "demo_encrypted") else {
                resultLabel.text = "No encrypted data found. Encrypt first."
                return
            }
            
            let key = SymmetricKey(data: keyData)
            let decryptedString = try encryption.decryptToString(encryptedData, with: key)
            
            resultLabel.text = "Decrypted: \(decryptedString)"
            
        } catch {
            resultLabel.text = "Decryption failed: \(error.localizedDescription)"
        }
    }
    
    @objc private func biometricAuth() {
        let biometricAuth = BiometricAuth.shared
        
        guard biometricAuth.isBiometricAvailable() else {
            resultLabel.text = "Biometric authentication not available"
            return
        }
        
        Task {
            do {
                try await biometricAuth.authenticate(reason: "Authenticate to access secure features")
                DispatchQueue.main.async {
                    self.resultLabel.text = "Biometric authentication successful!"
                }
            } catch {
                DispatchQueue.main.async {
                    self.resultLabel.text = "Biometric authentication failed: \(error.localizedDescription)"
                }
            }
        }
    }
    
    @objc private func secureStorage() {
        do {
            let secureStorage = SecureStorage.shared
            let testData = "This is securely stored data"
            
            try secureStorage.store(testData, forKey: "demo_storage")
            
            let retrievedData = try secureStorage.retrieveString(forKey: "demo_storage")
            
            resultLabel.text = "Stored and retrieved: \(retrievedData)"
            
        } catch {
            resultLabel.text = "Secure storage failed: \(error.localizedDescription)"
        }
    }
} 