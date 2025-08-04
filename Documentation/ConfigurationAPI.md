# Configuration API

## Overview

The Configuration API provides comprehensive configuration options for iOS Security Tools.

## Core Features

- **Security Configuration**: Configure security settings
- **Authentication Settings**: Configure authentication options
- **Encryption Settings**: Configure encryption parameters
- **Network Security**: Configure network security settings
- **Threat Detection**: Configure threat detection parameters

## Usage

```swift
import iOSSecurityTools

let securityConfig = SecurityConfiguration()

// Enable security features
securityConfig.enableBiometricAuth = true
securityConfig.enableEncryption = true
securityConfig.enableKeychain = true
securityConfig.enableNetworkSecurity = true
securityConfig.enableThreatDetection = true

// Configure authentication
securityConfig.biometricAuthEnabled = true
securityConfig.passwordAuthEnabled = true
securityConfig.multiFactorAuthEnabled = true

// Configure encryption
securityConfig.encryptionAlgorithm = .aes256
securityConfig.keySize = 256

// Apply configuration
securityManager.configure(securityConfig)
```

## Configuration Options

- **Authentication**: Configure biometric, password, and multi-factor auth
- **Encryption**: Configure encryption algorithms and key sizes
- **Keychain**: Configure keychain access and synchronization
- **Network Security**: Configure SSL/TLS and certificate pinning
- **Threat Detection**: Configure threat detection parameters
