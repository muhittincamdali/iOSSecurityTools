# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-15

A new library. In June 2026 the 1.0.0 sources were replaced with placeholder code; this release
rebuilds iOSSecurityTools from scratch as a dependency-free package of security building blocks.
No 1.0.0 API remains.

### Added

- Keychain: `Keychain` (data, strings, `Codable` values, keys, access groups, iCloud sync),
  `KeychainAccessibility`, `KeychainProtection` (user presence, any or current biometry,
  passcode) and `Keychain.symmetricKey(forKey:)`.
- Encryption: `DataCipher` (AES-256-GCM or ChaCha20-Poly1305 in a versioned, authenticated
  envelope with associated data), `KeyDerivation` (HKDF-SHA256), `PasswordKeyDerivation`
  (PBKDF2-HMAC-SHA256), `PasswordHash` (PHC string format), `SecureRandom` and `ConstantTime`.
- Secure Enclave: `SecureEnclaveKey` (P-256 signing keys for device binding) and
  `Keychain.secureEnclaveKey(forKey:protection:)`.
- Biometrics: `BiometricAuthenticator` with availability, async authentication and
  `BiometricError` (iOS, macOS, visionOS).
- Certificate pinning: `SPKIPin`, `PinnedDomain` (backup pin required, subdomains, expiration,
  report-only mode), `PinningPolicy`, `PinningURLSessionDelegate` and `URLSession.pinned(policy:)`;
  pins and failures are `Codable` for reports.
- One-time passwords: `HOTP`, `TOTP` and `OTPAuthURI` (`otpauth://` parsing and writing).
- Integrity: `IntegrityInspector` with jailbreak, debugger, simulator, injected-library and
  proxy checks, and a `Codable` `IntegrityReport`.
- Logs and screens: `Redacted`, `Mask`, `SensitiveDataRedactor`, `View.privacyShield(when:)`
  and `View.onScreenshot(perform:)`.
- DocC catalog with five articles, the SecurityLab example app for iOS and macOS, README
  screenshots captured from the app, and CI through the shared workflows of
  muhittincamdali/.github.

### Changed

- Minimum platforms: iOS 17, macOS 14, tvOS 17, watchOS 10, visionOS 1; swift-tools-version 6.2
  and the Swift 6 language mode.

### Removed

- All 1.0.0 and June 2026 types (`SecurityToolsManager`, `AESEncryption`, `RSAEncryption`,
  `JWTManager`, `OAuthManager`, `SecureVault`, `AntiDebugHook`, `RuntimeDefender`, `SecureRAM`
  and the rest), the CocoaPods spec and the `Documentation/` folder.

### Security

- Every input that can come from outside the app is validated and bounded: `otpauth://` URIs
  (length, duplicated parameters, issuer mismatch, ranges), encoded password hashes (iteration
  counts are capped, so a tampered hash cannot make verification run for hours), envelopes,
  pins and host names. Dates built from NaN or infinite intervals throw instead of trapping in
  the TOTP counter.
- `SensitiveDataRedactor` normalizes zero-width characters, combining marks, full-width forms and
  non-ASCII digits before matching, finds secret words inside longer field names (`SECRET_KEY`,
  `passwordConfirm`) and in escaped JSON, and runs in linear time.
- Calls into the macOS login keychain are serialized: concurrent calls could deadlock inside the
  Security framework.

## [1.0.0] - 2026-02-02

First tagged release: encryption, keychain, authentication and monitoring managers. Replaced by
2.0.0.

[Unreleased]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/muhittincamdali/iOSSecurityTools/releases/tag/v1.0.0
