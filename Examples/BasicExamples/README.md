# Basic Examples

This directory contains basic examples demonstrating fundamental iOS Security Tools functionality.

## Examples

- **SimpleAuthentication.swift** - Basic biometric authentication
- **SimpleEncryption.swift** - Basic data encryption
- **SimpleKeychain.swift** - Basic keychain operations
- **SimpleNetworkSecurity.swift** - Basic network security

## Getting Started

1. Open the example file you want to explore
2. Follow the step-by-step comments
3. Run the example in Xcode
4. Observe the security features in action

## Requirements

- iOS 15.0+
- Xcode 15.0+
- Swift 5.9+

## Usage

```swift
import iOSSecurityTools

// Basic authentication example
let auth = SimpleAuthentication()
auth.authenticate { result in
    // Handle authentication result
}
```
