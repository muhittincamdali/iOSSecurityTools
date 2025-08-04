# iOS Security Tools

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2015.0+-blue.svg)](https://developer.apple.com/ios/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red.svg)](CHANGELOG.md)

A comprehensive collection of security tools and utilities for iOS development, providing encryption, authentication, secure storage, and security best practices implementation.

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### 🔐 Encryption Tools
- **AESEncryption**: Advanced Encryption Standard implementation
- **RSAEncryption**: RSA public/private key encryption
- **HashGenerator**: SHA-256, SHA-512, and MD5 hashing
- **KeyDerivation**: PBKDF2 key derivation functions

### 🔑 Key Management
- **KeychainManager**: Secure key storage in Keychain
- **KeyGenerator**: Cryptographic key generation
- **CertificateManager**: SSL certificate handling
- **KeyRotation**: Automatic key rotation utilities

### 🛡️ Authentication Tools
- **BiometricAuth**: Face ID and Touch ID integration
- **OTPGenerator**: One-time password generation
- **JWTManager**: JSON Web Token handling
- **OAuthManager**: OAuth 2.0 implementation

### 🔒 Secure Storage
- **SecureStorage**: Encrypted data storage
- **FileEncryption**: File-level encryption
- **DatabaseEncryption**: Database encryption utilities
- **MemoryProtection**: Memory protection mechanisms

### 🚨 Security Monitoring
- **SecurityScanner**: Security vulnerability scanning
- **ThreatDetector**: Threat detection and analysis
- **AuditLogger**: Security audit logging
- **ComplianceChecker**: Security compliance validation

### 🔧 Security Utilities
- **SecurityUtilities**: General security utilities
- **CryptoHelpers**: Cryptographic helper functions
- **ValidationTools**: Input validation and sanitization
- **SecurityConfig**: Security configuration management

## 📱 Requirements

- iOS 15.0+
- Swift 5.9+
- Xcode 15.0+
- Security framework
- CryptoKit framework

## 🚀 Installation

### Swift Package Manager

Add the following dependency to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "1.0.0")
]
```

Or add it directly in Xcode:
1. File → Add Package Dependencies
2. Enter: `https://github.com/muhittincamdali/iOSSecurityTools.git`
3. Select version: `1.0.0`

### CocoaPods

Add to your `Podfile`:

```ruby
pod 'iOSSecurityTools', '~> 1.0.0'
```

### Carthage

Add to your `Cartfile`:

```
github "muhittincamdali/iOSSecurityTools" ~> 1.0.0
```

## ⚡ Quick Start

### 1. Setup Security Tools

```swift
import iOSSecurityTools

// Initialize security tools
SecurityTools.initialize()
```

### 2. Encryption

```swift
import iOSSecurityTools

// AES encryption
let aesEncryption = AESEncryption()
let key = try aesEncryption.generateKey()
let encryptedData = try aesEncryption.encrypt("Hello, World!", with: key)
let decryptedData = try aesEncryption.decrypt(encryptedData, with: key)

// RSA encryption
let rsaEncryption = RSAEncryption()
let keyPair = try rsaEncryption.generateKeyPair()
let encryptedData = try rsaEncryption.encrypt("Secret message", with: keyPair.publicKey)
let decryptedData = try rsaEncryption.decrypt(encryptedData, with: keyPair.privateKey)

// Hashing
let hashGenerator = HashGenerator()
let hash = hashGenerator.sha256("password123")
let isMatch = hashGenerator.verify("password123", hash: hash)
```

### 3. Key Management

```swift
import iOSSecurityTools

// Store key in Keychain
let keychainManager = KeychainManager()
try keychainManager.store(key: "my-secret-key", forKey: "encryption-key")

// Retrieve key from Keychain
let retrievedKey = try keychainManager.retrieve(forKey: "encryption-key")

// Generate cryptographic key
let keyGenerator = KeyGenerator()
let aesKey = try keyGenerator.generateAESKey()
let rsaKeyPair = try keyGenerator.generateRSAKeyPair()
```

### 4. Biometric Authentication

```swift
import iOSSecurityTools

// Check biometric availability
let biometricAuth = BiometricAuth()
if biometricAuth.isBiometricAvailable() {
    // Authenticate with biometrics
    try await biometricAuth.authenticate(reason: "Authenticate to access secure data")
    print("Biometric authentication successful")
}

// Get biometric type
let biometricType = biometricAuth.getBiometricType()
switch biometricType {
case .faceID:
    print("Face ID available")
case .touchID:
    print("Touch ID available")
case .none:
    print("No biometric authentication available")
}
```

### 5. Secure Storage

```swift
import iOSSecurityTools

// Store encrypted data
let secureStorage = SecureStorage()
try secureStorage.store("sensitive data", forKey: "user-data")

// Retrieve encrypted data
let data = try secureStorage.retrieve(forKey: "user-data")

// Encrypt file
let fileEncryption = FileEncryption()
let encryptedFileURL = try fileEncryption.encryptFile(
    at: originalFileURL,
    with: encryptionKey
)

// Decrypt file
let decryptedFileURL = try fileEncryption.decryptFile(
    at: encryptedFileURL,
    with: encryptionKey
)
```

### 6. JWT Management

```swift
import iOSSecurityTools

// Create JWT
let jwtManager = JWTManager()
let payload = ["user_id": "123", "role": "admin"]
let jwt = try jwtManager.createJWT(
    payload: payload,
    secret: "your-secret-key",
    expiresIn: 3600
)

// Verify JWT
let isValid = try jwtManager.verifyJWT(jwt, secret: "your-secret-key")
if isValid {
    let payload = try jwtManager.decodeJWT(jwt)
    print("JWT is valid, payload: \(payload)")
}
```

### 7. Security Monitoring

```swift
import iOSSecurityTools

// Security scanning
let securityScanner = SecurityScanner()
let vulnerabilities = try await securityScanner.scanForVulnerabilities()

// Threat detection
let threatDetector = ThreatDetector()
let threats = try await threatDetector.detectThreats()

// Audit logging
let auditLogger = AuditLogger()
auditLogger.logSecurityEvent(
    event: "user_login",
    details: ["user_id": "123", "ip_address": "192.168.1.1"]
)
```

### 8. Input Validation

```swift
import iOSSecurityTools

// Validate input
let validationTools = ValidationTools()

// Email validation
let isValidEmail = validationTools.isValidEmail("user@example.com")

// Password strength
let passwordStrength = validationTools.checkPasswordStrength("MySecurePassword123!")

// SQL injection prevention
let sanitizedInput = validationTools.sanitizeSQLInput("user input")

// XSS prevention
let sanitizedHTML = validationTools.sanitizeHTML("<script>alert('xss')</script>")
```

## 📚 Documentation

### [Getting Started Guide](Documentation/GettingStarted.md)
Complete setup and configuration guide.

### [Encryption Guide](Documentation/EncryptionGuide.md)
Comprehensive encryption implementation.

### [Key Management Guide](Documentation/KeyManagementGuide.md)
Secure key storage and management.

### [Authentication Guide](Documentation/AuthenticationGuide.md)
Biometric and token-based authentication.

### [Secure Storage Guide](Documentation/SecureStorageGuide.md)
Encrypted data and file storage.

### [Security Monitoring Guide](Documentation/SecurityMonitoringGuide.md)
Security scanning and threat detection.

### [API Reference](Documentation/API.md)
Complete API documentation.

## 🎯 Examples

### [Basic Example](Examples/BasicExample/)
Simple security implementation example.

### [Advanced Example](Examples/AdvancedExample/)
Complex security features implementation.

### [Custom Example](Examples/CustomExample/)
Custom security implementation.

## 🛠️ Architecture

```
iOSSecurityTools/
├── Sources/
│   ├── Encryption/
│   │   ├── AESEncryption.swift
│   │   ├── RSAEncryption.swift
│   │   ├── HashGenerator.swift
│   │   └── KeyDerivation.swift
│   ├── KeyManagement/
│   │   ├── KeychainManager.swift
│   │   ├── KeyGenerator.swift
│   │   ├── CertificateManager.swift
│   │   └── KeyRotation.swift
│   ├── Authentication/
│   │   ├── BiometricAuth.swift
│   │   ├── OTPGenerator.swift
│   │   ├── JWTManager.swift
│   │   └── OAuthManager.swift
│   ├── SecureStorage/
│   │   ├── SecureStorage.swift
│   │   ├── FileEncryption.swift
│   │   ├── DatabaseEncryption.swift
│   │   └── MemoryProtection.swift
│   ├── SecurityMonitoring/
│   │   ├── SecurityScanner.swift
│   │   ├── ThreatDetector.swift
│   │   ├── AuditLogger.swift
│   │   └── ComplianceChecker.swift
│   ├── SecurityUtilities/
│   │   ├── SecurityUtilities.swift
│   │   ├── CryptoHelpers.swift
│   │   ├── ValidationTools.swift
│   │   └── SecurityConfig.swift
│   └── iOSSecurityTools/
│       └── iOSSecurityTools.swift
├── Documentation/
├── Examples/
├── Tests/
└── Resources/
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style

- Follow Swift API Design Guidelines
- Use meaningful names
- Add documentation comments
- Write comprehensive tests
- Follow security best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**⭐ Star this repository if it helped you!**

## 📊 Project Statistics

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/muhittincamdali/iOSSecurityTools?style=social)](https://github.com/muhittincamdali/iOSSecurityTools/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/muhittincamdali/iOSSecurityTools?style=social)](https://github.com/muhittincamdali/iOSSecurityTools/network)
[![GitHub issues](https://img.shields.io/github/issues/muhittincamdali/iOSSecurityTools)](https://github.com/muhittincamdali/iOSSecurityTools/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/muhittincamdali/iOSSecurityTools)](https://github.com/muhittincamdali/iOSSecurityTools/pulls)

</div>

## 🌟 Stargazers

[![Stargazers repo roster for @muhittincamdali/iOSSecurityTools](https://reporoster.com/stars/muhittincamdali/iOSSecurityTools)](https://github.com/muhittincamdali/iOSSecurityTools/stargazers)

## 🙏 Acknowledgments

- [CryptoKit](https://developer.apple.com/documentation/cryptokit) for cryptographic operations
- [Security](https://developer.apple.com/documentation/security) for security framework
- The iOS security community for inspiration and feedback

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/muhittincamdali/iOSSecurityTools/issues)
- **Discussions**: [GitHub Discussions](https://github.com/muhittincamdali/iOSSecurityTools/discussions)
- **Documentation**: [Documentation](Documentation/)
- **Examples**: [Examples](Examples/)

---

**Made with ❤️ for the iOS security community** 