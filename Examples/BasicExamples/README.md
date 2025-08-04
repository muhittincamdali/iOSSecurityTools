# Basic Examples

This directory contains basic examples for iOS Security Tools.

## Examples

- **SimpleAuthentication.swift** - Basic authentication example
- **SimpleEncryption.swift** - Basic encryption example
- **SimpleKeychain.swift** - Basic keychain example

## Usage

```swift
import iOSSecurityTools

// Basic authentication example
let authManager = AuthenticationManager()
authManager.authenticateWithBiometrics { result in
    // Handle result
}
```

## Getting Started

1. Import the framework
2. Create security manager instances
3. Configure security parameters
4. Implement security features
5. Handle results
