import Foundation
import iOSSecurityTools

// MARK: - Basic Authentication Example
// This example demonstrates basic authentication features using iOS Security Tools

class BasicAuthenticationExample {
    
    // MARK: - Properties
    private let biometricAuth = BiometricAuthenticationManager()
    private let keychainManager = KeychainManager()
    private let sessionManager = SessionManager()
    
    // MARK: - Initialization
    init() {
        setupAuthentication()
    }
    
    // MARK: - Setup
    private func setupAuthentication() {
        // Configure biometric authentication
        let biometricConfig = BiometricConfiguration()
        biometricConfig.enableFaceID = true
        biometricConfig.enableTouchID = true
        biometricConfig.fallbackToPasscode = true
        
        biometricAuth.configure(biometricConfig)
        
        // Configure keychain
        let keychainConfig = KeychainConfiguration()
        keychainConfig.enableEncryption = true
        keychainConfig.enableAccessControl = true
        keychainConfig.enableBiometricProtection = true
        
        keychainManager.configure(keychainConfig)
        
        // Configure session management
        let sessionConfig = SessionConfiguration()
        sessionConfig.maxSessionDuration = 3600 // 1 hour
        sessionConfig.enableAutoLogout = true
        sessionConfig.enableSessionEncryption = true
        
        sessionManager.configure(sessionConfig)
    }
    
    // MARK: - Biometric Authentication
    func authenticateWithBiometric() {
        print("🔐 Starting biometric authentication...")
        
        biometricAuth.checkBiometricAvailability { [weak self] result in
            switch result {
            case .success(let availability):
                print("✅ Biometric authentication available")
                print("Face ID: \(availability.faceIDAvailable)")
                print("Touch ID: \(availability.touchIDAvailable)")
                
                self?.performBiometricAuthentication()
                
            case .failure(let error):
                print("❌ Biometric authentication not available: \(error)")
                self?.handleAuthenticationFailure(error)
            }
        }
    }
    
    private func performBiometricAuthentication() {
        biometricAuth.authenticate(reason: "Access secure data") { [weak self] result in
            switch result {
            case .success:
                print("✅ Biometric authentication successful")
                self?.onAuthenticationSuccess()
                
            case .failure(let error):
                print("❌ Biometric authentication failed: \(error)")
                self?.handleAuthenticationFailure(error)
            }
        }
    }
    
    // MARK: - Keychain Operations
    func storeSecureData() {
        print("🗝️ Storing secure data in keychain...")
        
        let secureItem = KeychainItem(
            service: "com.example.app",
            account: "user@example.com",
            data: "secure_password_data",
            accessControl: .userPresence
        )
        
        keychainManager.store(secureItem) { result in
            switch result {
            case .success:
                print("✅ Secure data stored successfully")
                
            case .failure(let error):
                print("❌ Keychain storage failed: \(error)")
            }
        }
    }
    
    func retrieveSecureData() {
        print("🗝️ Retrieving secure data from keychain...")
        
        keychainManager.retrieve(
            service: "com.example.app",
            account: "user@example.com"
        ) { result in
            switch result {
            case .success(let item):
                print("✅ Secure data retrieved successfully")
                print("Data: \(item.data)")
                print("Access control: \(item.accessControl)")
                
            case .failure(let error):
                print("❌ Keychain retrieval failed: \(error)")
            }
        }
    }
    
    // MARK: - Session Management
    func createSecureSession() {
        print("🔄 Creating secure session...")
        
        sessionManager.createSession(userId: "user123") { result in
            switch result {
            case .success(let session):
                print("✅ Session created successfully")
                print("Session ID: \(session.sessionId)")
                print("Expires: \(session.expiryDate)")
                
            case .failure(let error):
                print("❌ Session creation failed: \(error)")
            }
        }
    }
    
    func validateSession(sessionId: String) {
        print("🔄 Validating session...")
        
        sessionManager.validateSession(sessionId: sessionId) { result in
            switch result {
            case .success(let valid):
                if valid {
                    print("✅ Session is valid")
                } else {
                    print("❌ Session has expired")
                }
                
            case .failure(let error):
                print("❌ Session validation failed: \(error)")
            }
        }
    }
    
    // MARK: - Authentication Flow
    func startAuthenticationFlow() {
        print("🚀 Starting authentication flow...")
        
        // Step 1: Check biometric availability
        biometricAuth.checkBiometricAvailability { [weak self] result in
            switch result {
            case .success(let availability):
                if availability.faceIDAvailable || availability.touchIDAvailable {
                    // Step 2: Perform biometric authentication
                    self?.performBiometricAuthentication()
                } else {
                    // Step 3: Fallback to passcode
                    self?.performPasscodeAuthentication()
                }
                
            case .failure(let error):
                print("❌ Biometric check failed: \(error)")
                self?.performPasscodeAuthentication()
            }
        }
    }
    
    private func performPasscodeAuthentication() {
        print("🔢 Performing passcode authentication...")
        
        // Simulate passcode authentication
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            print("✅ Passcode authentication successful")
            self?.onAuthenticationSuccess()
        }
    }
    
    // MARK: - Success/Failure Handlers
    private func onAuthenticationSuccess() {
        print("🎉 Authentication successful!")
        
        // Store user credentials securely
        storeSecureData()
        
        // Create secure session
        createSecureSession()
        
        // Proceed with app functionality
        proceedWithAppFunctionality()
    }
    
    private func handleAuthenticationFailure(_ error: Error) {
        print("❌ Authentication failed: \(error)")
        
        // Show user-friendly error message
        showAuthenticationError(error)
        
        // Optionally retry authentication
        retryAuthentication()
    }
    
    // MARK: - App Functionality
    private func proceedWithAppFunctionality() {
        print("📱 Proceeding with app functionality...")
        
        // Example: Access secure data
        retrieveSecureData()
        
        // Example: Perform secure operations
        performSecureOperations()
    }
    
    private func performSecureOperations() {
        print("🔒 Performing secure operations...")
        
        // Example secure operations
        print("✅ Secure operations completed")
    }
    
    private func showAuthenticationError(_ error: Error) {
        print("⚠️ Authentication error: \(error.localizedDescription)")
        
        // In a real app, show an alert to the user
        // UIAlertController would be used here
    }
    
    private func retryAuthentication() {
        print("🔄 Retrying authentication...")
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.startAuthenticationFlow()
        }
    }
}

// MARK: - Usage Example
extension BasicAuthenticationExample {
    
    static func runExample() {
        print("🔐 Basic Authentication Example")
        print("================================")
        
        let example = BasicAuthenticationExample()
        
        // Start the authentication flow
        example.startAuthenticationFlow()
    }
}

// MARK: - Example Usage
// Uncomment to run the example
// BasicAuthenticationExample.runExample() 