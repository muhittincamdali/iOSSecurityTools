import Foundation
import iOSSecurityTools

// MARK: - Biometric Authentication Example
// Comprehensive example demonstrating biometric authentication features

class BiometricAuthenticationExample {
    
    // MARK: - Properties
    private let biometricAuth = BiometricAuthenticationManager()
    private let sessionManager = SessionManager()
    private let keychainManager = KeychainManager()
    
    // MARK: - Initialization
    init() {
        setupBiometricAuthentication()
    }
    
    // MARK: - Setup
    private func setupBiometricAuthentication() {
        // Configure biometric authentication
        let biometricConfig = BiometricConfiguration()
        biometricConfig.enableFaceID = true
        biometricConfig.enableTouchID = true
        biometricConfig.enableCustomBiometric = true
        biometricConfig.fallbackToPasscode = true
        biometricConfig.enableLivenessDetection = true
        biometricConfig.enableSpoofingDetection = true
        
        biometricAuth.configure(biometricConfig)
        
        // Configure session management
        let sessionConfig = SessionConfiguration()
        sessionConfig.maxSessionDuration = 3600 // 1 hour
        sessionConfig.enableAutoLogout = true
        sessionConfig.enableSessionEncryption = true
        sessionConfig.enableSessionAudit = true
        
        sessionManager.configure(sessionConfig)
        
        // Configure keychain
        let keychainConfig = KeychainConfiguration()
        keychainConfig.enableEncryption = true
        keychainConfig.enableAccessControl = true
        keychainConfig.enableBiometricProtection = true
        keychainConfig.enableCloudSync = true
        
        keychainManager.configure(keychainConfig)
    }
    
    // MARK: - Biometric Availability Check
    func checkBiometricAvailability() {
        print("🔍 Checking biometric availability...")
        
        biometricAuth.checkBiometricAvailability { result in
            switch result {
            case .success(let availability):
                print("✅ Biometric authentication available")
                print("Face ID: \(availability.faceIDAvailable)")
                print("Touch ID: \(availability.touchIDAvailable)")
                print("Biometric type: \(availability.biometricType)")
                print("Liveness detection: \(availability.livenessDetectionAvailable)")
                print("Spoofing detection: \(availability.spoofingDetectionAvailable)")
                
                if availability.biometricAvailable {
                    self.performBiometricAuthentication()
                } else {
                    self.handleBiometricUnavailable()
                }
                
            case .failure(let error):
                print("❌ Biometric authentication not available: \(error)")
                self.handleBiometricUnavailable()
            }
        }
    }
    
    // MARK: - Biometric Authentication
    func performBiometricAuthentication() {
        print("🔐 Performing biometric authentication...")
        
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
    
    // MARK: - Advanced Biometric Features
    func performAdvancedBiometricAuthentication() {
        print("🔐 Performing advanced biometric authentication...")
        
        // Configure advanced biometric features
        let advancedConfig = AdvancedBiometricConfiguration()
        advancedConfig.enableLivenessDetection = true
        advancedConfig.enableSpoofingDetection = true
        advancedConfig.enableBehavioralAnalysis = true
        advancedConfig.enableContinuousAuthentication = true
        advancedConfig.enableMultiModalBiometrics = true
        
        biometricAuth.configureAdvanced(advancedConfig)
        
        // Perform advanced authentication
        biometricAuth.authenticateWithAdvancedFeatures(reason: "Secure access") { [weak self] result in
            switch result {
            case .success(let authResult):
                print("✅ Advanced biometric authentication successful")
                print("Liveness score: \(authResult.livenessScore)")
                print("Spoofing score: \(authResult.spoofingScore)")
                print("Behavioral score: \(authResult.behavioralScore)")
                print("Confidence level: \(authResult.confidenceLevel)")
                
                self?.onAdvancedAuthenticationSuccess(authResult)
                
            case .failure(let error):
                print("❌ Advanced biometric authentication failed: \(error)")
                self?.handleAuthenticationFailure(error)
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
                print("User ID: \(session.userId)")
                print("Created: \(session.createdDate)")
                print("Expires: \(session.expiryDate)")
                
                // Store session securely
                self.storeSessionSecurely(session)
                
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
                    self.refreshSession(sessionId: sessionId)
                } else {
                    print("❌ Session has expired")
                    self.handleSessionExpired()
                }
                
            case .failure(let error):
                print("❌ Session validation failed: \(error)")
                self.handleSessionError(error)
            }
        }
    }
    
    func refreshSession(sessionId: String) {
        print("🔄 Refreshing session...")
        
        sessionManager.refreshSession(sessionId: sessionId) { result in
            switch result {
            case .success(let session):
                print("✅ Session refreshed successfully")
                print("New expiry: \(session.expiryDate)")
                
            case .failure(let error):
                print("❌ Session refresh failed: \(error)")
                self.handleSessionError(error)
            }
        }
    }
    
    // MARK: - Secure Storage
    func storeSessionSecurely(_ session: Session) {
        print("🗝️ Storing session securely...")
        
        let sessionData = try? JSONEncoder().encode(session)
        
        let secureItem = KeychainItem(
            service: "com.example.app.session",
            account: session.userId,
            data: sessionData ?? Data(),
            accessControl: .userPresence
        )
        
        keychainManager.store(secureItem) { result in
            switch result {
            case .success:
                print("✅ Session stored securely")
                
            case .failure(let error):
                print("❌ Session storage failed: \(error)")
            }
        }
    }
    
    func retrieveSessionSecurely(userId: String) {
        print("🗝️ Retrieving session securely...")
        
        keychainManager.retrieve(
            service: "com.example.app.session",
            account: userId
        ) { result in
            switch result {
            case .success(let item):
                print("✅ Session retrieved successfully")
                
                if let session = try? JSONDecoder().decode(Session.self, from: item.data) {
                    print("Session ID: \(session.sessionId)")
                    print("Expires: \(session.expiryDate)")
                    
                    // Validate the retrieved session
                    self.validateSession(sessionId: session.sessionId)
                }
                
            case .failure(let error):
                print("❌ Session retrieval failed: \(error)")
            }
        }
    }
    
    // MARK: - Authentication Flow
    func startAuthenticationFlow() {
        print("🚀 Starting authentication flow...")
        
        // Step 1: Check biometric availability
        checkBiometricAvailability()
    }
    
    // MARK: - Success Handlers
    private func onAuthenticationSuccess() {
        print("🎉 Authentication successful!")
        
        // Create secure session
        createSecureSession()
        
        // Proceed with app functionality
        proceedWithAppFunctionality()
    }
    
    private func onAdvancedAuthenticationSuccess(_ authResult: AdvancedBiometricResult) {
        print("🎉 Advanced authentication successful!")
        
        // Log authentication metrics
        logAuthenticationMetrics(authResult)
        
        // Create secure session
        createSecureSession()
        
        // Proceed with app functionality
        proceedWithAppFunctionality()
    }
    
    // MARK: - Failure Handlers
    private func handleAuthenticationFailure(_ error: Error) {
        print("❌ Authentication failed: \(error)")
        
        // Show user-friendly error message
        showAuthenticationError(error)
        
        // Optionally retry authentication
        retryAuthentication()
    }
    
    private func handleBiometricUnavailable() {
        print("⚠️ Biometric authentication unavailable")
        
        // Fallback to passcode authentication
        performPasscodeAuthentication()
    }
    
    private func handleSessionExpired() {
        print("⚠️ Session expired")
        
        // Re-authenticate user
        startAuthenticationFlow()
    }
    
    private func handleSessionError(_ error: Error) {
        print("❌ Session error: \(error)")
        
        // Handle session error
        handleSessionFailure(error)
    }
    
    // MARK: - Fallback Authentication
    func performPasscodeAuthentication() {
        print("🔢 Performing passcode authentication...")
        
        // Simulate passcode authentication
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            print("✅ Passcode authentication successful")
            self?.onAuthenticationSuccess()
        }
    }
    
    // MARK: - App Functionality
    private func proceedWithAppFunctionality() {
        print("📱 Proceeding with app functionality...")
        
        // Example: Access secure data
        accessSecureData()
        
        // Example: Perform secure operations
        performSecureOperations()
    }
    
    private func accessSecureData() {
        print("🔒 Accessing secure data...")
        
        // Retrieve session securely
        retrieveSessionSecurely(userId: "user123")
    }
    
    private func performSecureOperations() {
        print("🔒 Performing secure operations...")
        
        // Example secure operations
        print("✅ Secure operations completed")
    }
    
    // MARK: - Logging and Metrics
    private func logAuthenticationMetrics(_ authResult: AdvancedBiometricResult) {
        print("📊 Authentication metrics:")
        print("- Liveness score: \(authResult.livenessScore)")
        print("- Spoofing score: \(authResult.spoofingScore)")
        print("- Behavioral score: \(authResult.behavioralScore)")
        print("- Confidence level: \(authResult.confidenceLevel)")
        print("- Authentication time: \(authResult.authenticationTime)")
    }
    
    // MARK: - User Interface
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
    
    private func handleSessionFailure(_ error: Error) {
        print("❌ Session failure: \(error)")
        
        // Handle session failure
        // In a real app, this might involve logging out the user
    }
    
    // MARK: - Example Usage
    func runBiometricAuthenticationExample() {
        print("🔐 Biometric Authentication Example")
        print("===================================")
        
        // Start the authentication flow
        startAuthenticationFlow()
    }
}

// MARK: - Usage Example
extension BiometricAuthenticationExample {
    
    static func runExample() {
        let example = BiometricAuthenticationExample()
        example.runBiometricAuthenticationExample()
    }
}

// MARK: - Example Usage
// Uncomment to run the example
// BiometricAuthenticationExample.runExample() 