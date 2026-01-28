# iOS Security Tools

<p align="center">
  <a href="https://swift.org"><img src="https://img.shields.io/badge/Swift-5.9+-F05138?style=flat&logo=swift&logoColor=white" alt="Swift"></a>
  <a href="https://developer.apple.com/ios/"><img src="https://img.shields.io/badge/iOS-15.0+-000000?style=flat&logo=apple&logoColor=white" alt="iOS"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
</p>

<p align="center">
  <b>Security utilities for iOS: encryption, keychain, biometrics, and secure storage.</b>
</p>

---

## Features

- **Encryption** — AES-256, RSA, and hashing (SHA-256, MD5)
- **Keychain** — Secure credential storage
- **Biometrics** — Face ID and Touch ID authentication
- **Secure Storage** — Encrypted file storage
- **Jailbreak Detection** — Device integrity checks
- **SSL Pinning** — Certificate pinning for network security

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "1.0.0")
]
```

## Quick Start

### AES Encryption

```swift
import iOSSecurityTools

let crypto = AESCrypto()

// Generate key
let key = crypto.generateKey()

// Encrypt
let plaintext = "Sensitive data"
let encrypted = try crypto.encrypt(plaintext, key: key)

// Decrypt
let decrypted = try crypto.decrypt(encrypted, key: key)
print(decrypted) // "Sensitive data"
```

### Hashing

```swift
let hasher = Hasher()

// SHA-256
let hash = hasher.sha256("password")
print(hash) // "5e884898da28047d..."

// SHA-512
let hash512 = hasher.sha512("password")

// MD5 (not recommended for security)
let md5 = hasher.md5("data")

// Password hashing with salt
let salt = hasher.generateSalt()
let passwordHash = hasher.hashPassword("myPassword", salt: salt)
```

### Keychain

```swift
let keychain = SecureKeychain()

// Save credentials
try keychain.save(
    "user_token_123",
    forKey: "authToken",
    accessibility: .whenUnlocked
)

// Read credentials
let token: String? = try keychain.read(forKey: "authToken")

// Delete
try keychain.delete(forKey: "authToken")

// Save with biometric protection
try keychain.save(
    "sensitive_data",
    forKey: "protectedData",
    accessibility: .whenPasscodeSetThisDeviceOnly,
    requireBiometrics: true
)
```

### Biometric Authentication

```swift
let biometrics = BiometricAuth()

// Check availability
switch biometrics.availableType {
case .faceID:
    print("Face ID available")
case .touchID:
    print("Touch ID available")
case .none:
    print("No biometrics available")
}

// Authenticate
biometrics.authenticate(reason: "Access your account") { result in
    switch result {
    case .success:
        print("Authenticated!")
    case .failure(let error):
        switch error {
        case .userCancel:
            print("User cancelled")
        case .biometryNotAvailable:
            print("Biometrics not available")
        case .biometryLockout:
            print("Too many failed attempts")
        default:
            print("Authentication failed")
        }
    }
}

// Async version
let authenticated = try await biometrics.authenticate(reason: "Verify identity")
```

### Secure File Storage

```swift
let secureStorage = SecureFileStorage()

// Save encrypted file
let data = "Secret document".data(using: .utf8)!
try secureStorage.save(data, filename: "secret.txt")

// Read encrypted file
let decryptedData = try secureStorage.read(filename: "secret.txt")

// Delete
try secureStorage.delete(filename: "secret.txt")

// List all secure files
let files = secureStorage.listFiles()
```

### Jailbreak Detection

```swift
let security = DeviceSecurity()

if security.isJailbroken {
    // Handle jailbroken device
    print("Device is compromised")
    // Optionally restrict functionality
}

// Check specific indicators
let checks = security.runSecurityChecks()
print("Cydia installed: \(checks.cydiaInstalled)")
print("Suspicious files: \(checks.suspiciousFilesFound)")
print("Sandbox intact: \(checks.sandboxIntact)")
```

### SSL Certificate Pinning

```swift
let pinnedCertificates = [
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
]

let session = URLSession(
    configuration: .default,
    delegate: SSLPinningDelegate(pins: pinnedCertificates),
    delegateQueue: nil
)

// Use session for secure requests
let (data, _) = try await session.data(from: url)
```

### Secure Random Generation

```swift
let random = SecureRandom()

// Random bytes
let bytes = random.generateBytes(count: 32)

// Random string
let token = random.generateString(length: 64) // Hex string

// Random number
let number = random.generateNumber(in: 1000...9999)

// UUID
let uuid = random.generateUUID()
```

### Data Protection

```swift
// Save with data protection
let url = documentsDirectory.appendingPathComponent("sensitive.dat")
try data.write(to: url, options: .completeFileProtection)

// Check protection level
let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
let protection = attributes[.protectionKey] as? FileProtectionType
```

## Project Structure

```
iOSSecurityTools/
├── Sources/
│   ├── Encryption/
│   │   ├── AESCrypto.swift
│   │   ├── RSACrypto.swift
│   │   └── Hasher.swift
│   ├── Keychain/
│   │   └── SecureKeychain.swift
│   ├── Biometrics/
│   │   └── BiometricAuth.swift
│   ├── Storage/
│   │   └── SecureFileStorage.swift
│   ├── Detection/
│   │   └── JailbreakDetection.swift
│   └── Network/
│       └── SSLPinning.swift
├── Examples/
└── Tests/
```

## Security Best Practices

1. **Never hardcode secrets** — Use Keychain or environment variables
2. **Use strong encryption** — AES-256 for symmetric, RSA-2048+ for asymmetric
3. **Salt passwords** — Always use unique salts for password hashing
4. **Enable data protection** — Use `.completeFileProtection` for sensitive files
5. **Validate certificates** — Implement SSL pinning for API calls
6. **Check device integrity** — Detect jailbroken devices

## Requirements

- iOS 15.0+
- Xcode 15.0+
- Swift 5.9+

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Muhittin Camdali** — [@muhittincamdali](https://github.com/muhittincamdali)

---

<p align="center">
  <sub>Secure your iOS apps ❤️</sub>
</p>
