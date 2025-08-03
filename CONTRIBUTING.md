# Contributing to iOS Security Tools

Thank you for your interest in contributing to iOS Security Tools! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

We welcome contributions from the community! Whether you're fixing bugs, adding features, improving documentation, or suggesting ideas, your contributions are valuable.

### Types of Contributions

- **🐛 Bug Reports**: Report bugs and issues
- **✨ Feature Requests**: Suggest new features
- **📝 Documentation**: Improve documentation
- **🧪 Tests**: Add or improve tests
- **🔧 Code**: Submit code improvements
- **🎨 UI/UX**: Improve user experience
- **🔒 Security**: Enhance security features
- **⚡ Performance**: Optimize performance
- **🌐 Localization**: Add translations

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Security Guidelines](#security-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)
- [Code of Conduct](#code-of-conduct)

## 🚀 Getting Started

### Prerequisites

- Xcode 15.0+
- Swift 5.9+
- iOS 15.0+ SDK
- macOS 12.0+ (for development)
- Git

### Required Tools

- [SwiftLint](https://github.com/realm/SwiftLint) for code style
- [SwiftFormat](https://github.com/nicklockwood/SwiftFormat) for code formatting
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) for project generation

## 🛠️ Development Setup

### 1. Fork the Repository

1. Go to [iOSSecurityTools](https://github.com/muhittincamdali/iOSSecurityTools)
2. Click the "Fork" button
3. Clone your fork locally:

```bash
git clone https://github.com/your-username/iOSSecurityTools.git
cd iOSSecurityTools
```

### 2. Setup Development Environment

```bash
# Install SwiftLint
brew install swiftlint

# Install SwiftFormat
brew install swiftformat

# Install XcodeGen
brew install xcodegen

# Setup pre-commit hooks
cp .github/hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

### 3. Build the Project

```bash
# Generate Xcode project
xcodegen generate

# Open in Xcode
open iOSSecurityTools.xcodeproj

# Or build from command line
swift build
```

### 4. Run Tests

```bash
# Run all tests
swift test

# Run specific test
swift test --filter TestEncryption

# Run with coverage
swift test --enable-code-coverage
```

## 📝 Code Style

### Swift Style Guide

We follow the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/) and use SwiftLint for enforcement.

#### Naming Conventions

```swift
// ✅ Good
class AESEncryption {
    func encrypt(_ data: Data, with key: SymmetricKey) throws -> Data
}

// ❌ Bad
class aesEncryption {
    func encryptData(_ data: Data, key: SymmetricKey) throws -> Data
}
```

#### Documentation

```swift
/// Encrypts data using AES-256 encryption
/// - Parameters:
///   - data: The data to encrypt
///   - key: The symmetric key for encryption
/// - Returns: Encrypted data
/// - Throws: `EncryptionError` if encryption fails
public func encrypt(_ data: Data, with key: SymmetricKey) throws -> Data {
    // Implementation
}
```

#### Error Handling

```swift
// ✅ Good
public enum EncryptionError: LocalizedError {
    case invalidData
    case keyDerivationFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidData:
            return "Invalid data provided"
        case .keyDerivationFailed:
            return "Key derivation failed"
        }
    }
}

// ❌ Bad
public enum EncryptionError: Error {
    case invalidData
    case keyDerivationFailed
}
```

### File Organization

```
Sources/
├── Encryption/
│   ├── AESEncryption.swift
│   ├── RSAEncryption.swift
│   ├── HashGenerator.swift
│   └── KeyDerivation.swift
├── Authentication/
│   ├── BiometricAuth.swift
│   ├── OTPGenerator.swift
│   ├── JWTManager.swift
│   └── OAuthManager.swift
└── ...
```

### Import Order

```swift
// System imports first
import Foundation
import CryptoKit
import Security

// Third-party imports
import SomeThirdPartyLibrary

// Local imports last
import iOSSecurityTools
```

## 🔒 Security Guidelines

### Security Best Practices

1. **Never commit secrets**: Use environment variables or secure storage
2. **Validate all inputs**: Sanitize user input
3. **Use secure random numbers**: Use `SecRandomCopyBytes` or `CryptoKit`
4. **Implement proper error handling**: Don't expose sensitive information
5. **Follow OWASP guidelines**: Implement security best practices

### Security Review Process

All security-related changes require:

1. **Security review** by maintainers
2. **Penetration testing** for new features
3. **Vulnerability assessment** for changes
4. **Compliance verification** for standards

### Security Checklist

- [ ] Input validation implemented
- [ ] Output sanitization applied
- [ ] Secure random generation used
- [ ] Error messages don't leak information
- [ ] Authentication properly implemented
- [ ] Authorization checks in place
- [ ] Encryption algorithms are current
- [ ] Key management is secure
- [ ] No hardcoded secrets
- [ ] Security tests written

## 🧪 Testing

### Test Structure

```
Tests/
├── EncryptionTests/
│   ├── AESEncryptionTests.swift
│   ├── RSAEncryptionTests.swift
│   └── HashGeneratorTests.swift
├── AuthenticationTests/
│   ├── BiometricAuthTests.swift
│   └── JWTManagerTests.swift
└── IntegrationTests/
    └── SecurityIntegrationTests.swift
```

### Test Guidelines

1. **100% test coverage** for security-critical code
2. **Unit tests** for all public APIs
3. **Integration tests** for complex workflows
4. **Performance tests** for critical paths
5. **Security tests** for vulnerability detection

### Writing Tests

```swift
import XCTest
@testable import iOSSecurityTools

final class AESEncryptionTests: XCTestCase {
    
    func testEncryptionDecryption() throws {
        // Given
        let encryption = AESEncryption()
        let key = try encryption.generateKey()
        let originalData = "Hello, World!".data(using: .utf8)!
        
        // When
        let encryptedData = try encryption.encrypt(originalData, with: key)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        
        // Then
        XCTAssertEqual(originalData, decryptedData)
    }
    
    func testInvalidKeyThrowsError() {
        // Given
        let encryption = AESEncryption()
        let invalidKey = SymmetricKey(size: .bits128)
        let data = "Test".data(using: .utf8)!
        
        // When & Then
        XCTAssertThrowsError(try encryption.encrypt(data, with: invalidKey))
    }
}
```

### Performance Testing

```swift
func testEncryptionPerformance() throws {
    let encryption = AESEncryption()
    let key = try encryption.generateKey()
    let data = Data(repeating: 0, count: 1024 * 1024) // 1MB
    
    measure {
        for _ in 0..<10 {
            _ = try! encryption.encrypt(data, with: key)
        }
    }
}
```

## 📚 Documentation

### Documentation Standards

1. **API Documentation**: All public APIs must be documented
2. **Usage Examples**: Provide practical examples
3. **Security Notes**: Document security considerations
4. **Performance Notes**: Document performance characteristics
5. **Migration Guides**: Provide upgrade paths

### Documentation Structure

```
Documentation/
├── GettingStarted.md
├── EncryptionGuide.md
├── AuthenticationGuide.md
├── SecurityGuide.md
├── PerformanceGuide.md
├── MigrationGuide.md
└── API.md
```

### Writing Documentation

```markdown
# Encryption Guide

## Overview

The encryption module provides secure cryptographic operations for iOS applications.

## Usage

### Basic Encryption

```swift
import iOSSecurityTools

let encryption = AESEncryption()
let key = try encryption.generateKey()
let encryptedData = try encryption.encrypt("Hello, World!", with: key)
```

### Security Considerations

- Always use strong keys
- Store keys securely
- Validate all inputs
- Handle errors appropriately
```

## 🔄 Pull Request Process

### Before Submitting

1. **Check existing issues**: Don't duplicate work
2. **Create feature branch**: Use descriptive names
3. **Write tests**: Ensure 100% coverage
4. **Update documentation**: Keep docs current
5. **Run linting**: Fix all style issues
6. **Test thoroughly**: Verify functionality

### Pull Request Template

```markdown
## Description

Brief description of changes

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security enhancement

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Performance tests added/updated
- [ ] Security tests added/updated

## Documentation

- [ ] API documentation updated
- [ ] README updated
- [ ] Examples updated
- [ ] Migration guide updated

## Security

- [ ] Security review completed
- [ ] Vulnerability assessment done
- [ ] Compliance verified
- [ ] Penetration testing passed

## Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation is complete
- [ ] Security considerations addressed
- [ ] Performance impact assessed
- [ ] Breaking changes documented
```

### Review Process

1. **Automated checks** must pass
2. **Code review** by maintainers
3. **Security review** for sensitive changes
4. **Performance review** for critical paths
5. **Documentation review** for completeness

## 🚀 Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Version bumped
- [ ] Security audit completed
- [ ] Performance benchmarks run
- [ ] Release notes written
- [ ] GitHub release created

### Release Steps

1. **Prepare release branch**
2. **Update version numbers**
3. **Update CHANGELOG**
4. **Create release notes**
5. **Tag release**
6. **Publish to GitHub**
7. **Announce release**

## 📋 Issue Templates

### Bug Report

```markdown
## Bug Description

Clear description of the bug

## Steps to Reproduce

1. Step 1
2. Step 2
3. Step 3

## Expected Behavior

What should happen

## Actual Behavior

What actually happens

## Environment

- iOS Version: 15.0+
- Xcode Version: 15.0+
- iOSSecurityTools Version: 1.0.0

## Additional Information

Screenshots, logs, etc.
```

### Feature Request

```markdown
## Feature Description

Clear description of the feature

## Use Case

Why this feature is needed

## Proposed Solution

How to implement the feature

## Alternatives Considered

Other approaches considered

## Additional Information

Mockups, examples, etc.
```

## 🤝 Code of Conduct

### Our Standards

- **Respectful**: Treat everyone with respect
- **Inclusive**: Welcome diverse perspectives
- **Professional**: Maintain professional conduct
- **Constructive**: Provide constructive feedback
- **Collaborative**: Work together effectively

### Unacceptable Behavior

- Harassment or discrimination
- Inappropriate or offensive content
- Spam or commercial solicitation
- Violation of privacy or security
- Disruptive or unprofessional behavior

### Reporting Issues

Report violations to: security@muhittincamdali.com

## 🙏 Acknowledgments

Thank you to all contributors who have helped make iOS Security Tools better:

- **Core Contributors**: Active development team
- **Security Reviewers**: Security experts and auditors
- **Community Members**: Bug reports and feedback
- **Documentation Writers**: Documentation improvements
- **Test Writers**: Comprehensive test coverage

## 📞 Support

### Getting Help

- **Documentation**: [Documentation](Documentation/)
- **Issues**: [GitHub Issues](https://github.com/muhittincamdali/iOSSecurityTools/issues)
- **Discussions**: [GitHub Discussions](https://github.com/muhittincamdali/iOSSecurityTools/discussions)
- **Security**: security@muhittincamdali.com

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Email**: Security-related concerns
- **Contributor Chat**: Real-time collaboration

---

**Thank you for contributing to iOS Security Tools! 🚀** 