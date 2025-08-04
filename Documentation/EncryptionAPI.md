# Encryption API

## Overview

The Encryption API provides comprehensive encryption and decryption capabilities for iOS applications.

## Core Features

- **AES Encryption**: Advanced Encryption Standard
- **RSA Encryption**: Asymmetric encryption
- **Hash Functions**: SHA-256, SHA-512, MD5
- **Digital Signatures**: RSA and ECDSA signatures
- **Key Management**: Secure key generation and storage

## Usage

```swift
import iOSSecurityTools

let encryptionManager = EncryptionManager()

// Encrypt data
let encryptedData = try encryptionManager.encrypt(
    data: originalData,
    algorithm: .aes256
)

// Decrypt data
let decryptedData = try encryptionManager.decrypt(
    data: encryptedData,
    algorithm: .aes256
)
```

## Algorithms

- **AES**: Advanced Encryption Standard (128, 192, 256-bit)
- **RSA**: Asymmetric encryption
- **SHA**: Secure Hash Algorithm
- **HMAC**: Hash-based Message Authentication Code
