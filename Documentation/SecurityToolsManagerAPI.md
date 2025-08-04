# Security Tools Manager API

## Overview

The SecurityToolsManager is the core component of iOS Security Tools that orchestrates all security activities.

## Core Features

- **Authentication Management**: Manage all authentication types
- **Encryption Services**: Provide encryption and decryption services
- **Keychain Management**: Secure keychain operations
- **Network Security**: Network security and threat detection
- **Security Auditing**: Comprehensive security auditing

## Usage

```swift
import iOSSecurityTools

let securityManager = SecurityToolsManager()
securityManager.start(with: configuration)
```

## Configuration

```swift
let config = SecurityConfiguration()
config.enableBiometricAuth = true
config.enableEncryption = true
config.enableKeychain = true
config.enableNetworkSecurity = true
```
