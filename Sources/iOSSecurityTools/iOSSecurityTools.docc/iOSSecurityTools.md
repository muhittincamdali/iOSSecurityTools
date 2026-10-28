# ``iOSSecurityTools``

Keychain storage, encryption, signatures, signed tokens, certificate pinning, one-time passwords,
integrity checks and log redaction for apps on iOS, macOS, tvOS, watchOS and visionOS.

## Overview

iOSSecurityTools wraps Apple's Security, CryptoKit, CommonCrypto and LocalAuthentication
frameworks in small value types with safe defaults. Each type validates its input and throws a
typed error instead of crashing, so values that come from a QR code, a server or a file cannot
trap the app or make it loop.

```swift
import iOSSecurityTools

let keychain = Keychain(service: "com.example.notes")
let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "notes-key"))
try keychain.set(cipher.encrypt("Meet at 7 pm"), forKey: "note")
```

The package has no dependencies and builds in the Swift 6 language mode.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:StoringSecrets>

### Keychain

- ``Keychain``
- ``KeychainAccessibility``
- ``KeychainProtection``
- ``KeychainError``

### Encryption and hashing

- ``DataCipher``
- ``KeyDerivation``
- ``PasswordKeyDerivation``
- ``PasswordHash``
- ``CipherError``
- ``SecureRandom``
- ``TokenEncoding``
- ``SecureRandomError``
- ``ConstantTime``

### End-to-end encryption and signatures

- <doc:EncryptingEndToEnd>
- ``PublicKeyCipher``
- ``SigningKey``
- ``VerifyingKey``
- ``SignatureAlgorithm``
- ``SignatureError``
- ``MessageAuthenticator``

### Signed tokens

- <doc:VerifyingSignedTokens>
- ``JWTVerifier``
- ``JWTSigner``
- ``JWTClaims``
- ``JWTAlgorithm``
- ``JWTError``

### Secure Enclave and biometrics

- ``SecureEnclaveKey``
- ``SecureEnclaveError``
- ``BiometricAuthenticator``
- ``BiometricError``

### Certificate pinning

- <doc:PinningCertificates>
- ``PinningPolicy``
- ``PinnedDomain``
- ``SPKIPin``
- ``PinningURLSessionDelegate``
- ``PinningDecision``
- ``PinningFailure``
- ``PinningError``

### One-time passwords

- ``TOTP``
- ``HOTP``
- ``OTPAuthURI``
- ``OTPAlgorithm``
- ``OTPError``

### Device integrity

- <doc:DetectingCompromisedDevices>
- ``IntegrityInspector``
- ``IntegrityChecks``
- ``IntegrityReport``
- ``IntegrityFinding``

### Logs and screens

- <doc:KeepingSecretsOutOfLogs>
- ``Redacted``
- ``Mask``
- ``SensitiveDataRedactor``
- ``PrivacyShieldConditions``
