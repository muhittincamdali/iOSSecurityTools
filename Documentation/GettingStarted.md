# Getting Started with iOS Security Tools

<!-- TOC START -->
## Table of Contents
- [Getting Started with iOS Security Tools](#getting-started-with-ios-security-tools)
- [📋 Table of Contents](#-table-of-contents)
- [🚀 Installation](#-installation)
  - [Swift Package Manager](#swift-package-manager)
  - [Manual Installation](#manual-installation)
- [🔧 Basic Setup](#-basic-setup)
  - [1. Import the Framework](#1-import-the-framework)
  - [2. Initialize Security Tools](#2-initialize-security-tools)
  - [3. Check Security Status](#3-check-security-status)
- [⚡ Quick Examples](#-quick-examples)
  - [Encryption](#encryption)
  - [Secure Storage](#secure-storage)
  - [Biometric Authentication](#biometric-authentication)
  - [JWT Tokens](#jwt-tokens)
  - [OTP Generation](#otp-generation)
- [⚙️ Configuration](#-configuration)
  - [Security Configuration](#security-configuration)
  - [Keychain Configuration](#keychain-configuration)
  - [Secure Storage Configuration](#secure-storage-configuration)
- [🛡️ Best Practices](#-best-practices)
  - [1. Key Management](#1-key-management)
  - [2. Data Encryption](#2-data-encryption)
  - [3. Authentication](#3-authentication)
  - [4. Input Validation](#4-input-validation)
  - [5. Error Handling](#5-error-handling)
- [🔍 Troubleshooting](#-troubleshooting)
  - [Common Issues](#common-issues)
    - [1. Keychain Access Denied](#1-keychain-access-denied)
    - [2. Biometric Authentication Fails](#2-biometric-authentication-fails)
    - [3. Encryption Errors](#3-encryption-errors)
    - [4. Performance Issues](#4-performance-issues)
  - [Debug Mode](#debug-mode)
  - [Performance Monitoring](#performance-monitoring)
- [📚 Next Steps](#-next-steps)
- [🆘 Support](#-support)
<!-- TOC END -->


This guide will help you get started with iOS Security Tools, a comprehensive security framework for iOS applications.

## 📋 Table of Contents

- [Installation](#installation)
- [Basic Setup](#basic-setup)
- [Quick Examples](#quick-examples)
- [Configuration](#configuration)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## 🚀 Installation

### Swift Package Manager

1. Open your Xcode project
2. Go to File → Add Package Dependencies
3. Enter the repository URL: `https://github.com/muhittincamdali/iOSSecurityTools.git`
4. Select version: `1.0.0`
5. Click Add Package

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/muhittincamdali/iOSSecurityTools.git
```

2. Add the package to your project:
```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "1.0.0")
]
```

## 🔧 Basic Setup

### 1. Import the Framework

```swift
import iOSSecurityTools
```

### 2. Initialize Security Tools

```swift
// In your AppDelegate or early in app lifecycle
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    
    // Initialize security tools
    iOSSecurityTools.shared.initialize()
    
    return true
}
```

### 3. Check Security Status

```swift
let securityStatus = iOSSecurityTools.shared.getSecurityStatus()
print("Biometric available: \(securityStatus.biometricAvailable)")
print("Keychain available: \(securityStatus.keychainAvailable)")
```

## ⚡ Quick Examples

### Encryption

```swift
// Basic encryption
let encryption = AESEncryption.shared
let key = try encryption.generateKey()
let encryptedData = try encryption.encrypt("Hello, World!", with: key)
let decryptedString = try encryption.decryptToString(encryptedData, with: key)
```

### Secure Storage

```swift
// Store sensitive data
let secureStorage = SecureStorage.shared
try secureStorage.store("sensitive data", forKey: "user-data")

// Retrieve sensitive data
let data = try secureStorage.retrieveString(forKey: "user-data")
```

### Biometric Authentication

```swift
// Check if biometric is available
let biometricAuth = BiometricAuth.shared
if biometricAuth.isBiometricAvailable() {
    // Authenticate user
    try await biometricAuth.authenticate(reason: "Access secure data")
    print("Authentication successful")
}
```

### JWT Tokens

```swift
// Create JWT token
let jwtManager = JWTManager.shared
let payload = ["user_id": "123", "role": "user"]
let token = try jwtManager.createJWT(payload: payload, secret: "your-secret", expiresIn: 3600)

// Verify JWT token
let isValid = try jwtManager.verifyJWT(token, secret: "your-secret")
```

### OTP Generation

```swift
// Generate OTP
let otpGenerator = OTPGenerator.shared
let secret = otpGenerator.generateSecret()
let otp = try otpGenerator.generateTOTP(secret: secret)

// Verify OTP
let isValid = otpGenerator.verifyTOTP(otp, secret: secret)
```

## ⚙️ Configuration

### Security Configuration

```swift
// Get current configuration
let config = iOSSecurityTools.shared.getSecurityConfiguration()

// Update configuration
var newConfig = config
newConfig.tokenExpiration = 7200 // 2 hours
newConfig.requireBiometric = true
newConfig.enableAuditLogging = true

iOSSecurityTools.shared.updateSecurityConfiguration(newConfig)
```

### Keychain Configuration

```swift
// Store data in Keychain
let keychainManager = KeychainManager.shared
try keychainManager.store(string: "secret-value", forKey: "my-key")

// Retrieve from Keychain
let value = try keychainManager.retrieveString(forKey: "my-key")
```

### Secure Storage Configuration

```swift
// Store with custom encryption
let secureStorage = SecureStorage.shared
let customKey = try KeyGenerator.shared.generateAESKey()
try secureStorage.storeSensitive(data, forKey: "custom-data", encryptionKey: customKey)

// Store with biometric protection
try secureStorage.storeWithBiometric(data, forKey: "biometric-data")
```

## 🛡️ Best Practices

### 1. Key Management

- Always use strong keys (256-bit minimum)
- Store keys securely in Keychain
- Rotate keys regularly
- Never hardcode keys in source code

```swift
// Good practice
let key = try KeyGenerator.shared.generateAESKey()
try KeychainManager.shared.storeKey(key.withUnsafeBytes { Data($0) }, forKey: "encryption-key")

// Bad practice
let weakKey = "my-secret-key" // Never do this
```

### 2. Data Encryption

- Encrypt all sensitive data
- Use strong encryption algorithms
- Validate input before encryption
- Handle encryption errors properly

```swift
// Good practice
do {
    let encryptedData = try encryption.encrypt(sensitiveData, with: key)
    try secureStorage.store(encryptedData, forKey: "encrypted-data")
} catch {
    print("Encryption failed: \(error)")
}
```

### 3. Authentication

- Use biometric authentication when available
- Implement proper session management
- Validate tokens regularly
- Log authentication events

```swift
// Good practice
if biometricAuth.isBiometricAvailable() {
    try await biometricAuth.authenticate(reason: "Access secure data")
    // Proceed with secure operations
} else {
    // Fallback to other authentication
}
```

### 4. Input Validation

- Always validate user input
- Sanitize data before processing
- Use parameterized queries
- Prevent injection attacks

```swift
// Good practice
let validationResult = iOSSecurityTools.shared.validateInput(userInput, type: .email)
if validationResult.isValid {
    // Process valid input
} else {
    // Handle invalid input
}
```

### 5. Error Handling

- Never expose sensitive information in errors
- Log security events properly
- Handle errors gracefully
- Implement proper fallbacks

```swift
// Good practice
do {
    let data = try secureStorage.retrieve(forKey: "sensitive-data")
    // Process data
} catch SecureStorageError.dataNotFound {
    // Handle missing data
} catch SecureStorageError.biometricNotAvailable {
    // Handle biometric unavailable
} catch {
    // Handle other errors
    print("Security error: \(error.localizedDescription)")
}
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Keychain Access Denied

**Problem**: Cannot access Keychain
**Solution**: Check app entitlements and Keychain sharing

```swift
// Add to your app's entitlements
// Keychain Sharing: YES
// Keychain Groups: com.yourcompany.yourapp
```

#### 2. Biometric Authentication Fails

**Problem**: Biometric authentication not working
**Solution**: Check device capabilities and permissions

```swift
// Check biometric availability
let biometricType = biometricAuth.getBiometricType()
switch biometricType {
case .faceID:
    print("Face ID available")
case .touchID:
    print("Touch ID available")
case .none:
    print("No biometric available")
}
```

#### 3. Encryption Errors

**Problem**: Encryption/decryption fails
**Solution**: Check key validity and data format

```swift
// Validate key before use
let key = try KeyGenerator.shared.generateAESKey()
let keyStrength = KeyGenerator.shared.validateKeyStrength(key.withUnsafeBytes { Data($0) }, algorithm: "AES")
if keyStrength == .strong {
    // Use key for encryption
}
```

#### 4. Performance Issues

**Problem**: Security operations are slow
**Solution**: Optimize for performance

```swift
// Use background queue for heavy operations
DispatchQueue.global(qos: .userInitiated).async {
    let encryptedData = try encryption.encrypt(largeData, with: key)
    DispatchQueue.main.async {
        // Update UI with result
    }
}
```

### Debug Mode

Enable debug logging for troubleshooting:

```swift
// Enable debug mode (development only)
#if DEBUG
print("Security tools initialized")
print("Keychain available: \(keychainManager.exists(forKey: "test"))")
print("Biometric available: \(biometricAuth.isBiometricAvailable())")
#endif
```

### Performance Monitoring

Monitor security operation performance:

```swift
// Measure encryption performance
let startTime = CFAbsoluteTimeGetCurrent()
let encryptedData = try encryption.encrypt(data, with: key)
let endTime = CFAbsoluteTimeGetCurrent()
let duration = endTime - startTime

print("Encryption took \(duration) seconds")
```

## 📚 Next Steps

1. **Read the Documentation**: Explore the complete [API Reference](API.md)
2. **Check Examples**: See [Examples](../Examples/) for more use cases
3. **Security Audit**: Run [Security Monitoring](SecurityMonitoringGuide.md) tools
4. **Best Practices**: Follow [Security Guide](SecurityGuide.md) recommendations
5. **Contributing**: Read [Contributing Guide](../CONTRIBUTING.md) to help improve the project

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/muhittincamdali/iOSSecurityTools/issues)
- **Discussions**: [GitHub Discussions](https://github.com/muhittincamdali/iOSSecurityTools/discussions)
- **Documentation**: [Documentation](../Documentation/)
- **Examples**: [Examples](../Examples/)

---

**Happy coding with iOS Security Tools! 🔐** 