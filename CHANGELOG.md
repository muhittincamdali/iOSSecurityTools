# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SensitiveDataRedactor.redact(body:contentType:)` redacts request and response bodies with a
  parser chosen by the content type: JSON, `application/x-www-form-urlencoded` forms (also read
  as split at `;`) and multipart form data, each part by its own type. A body that is not UTF-8,
  has another type or does not parse completely is omitted as
  `[body omitted: N bytes, <type>]`; uploaded files are omitted the same way.

### Changed

- `SensitiveDataRedactor` compares only plain-ASCII field names (`A`–`Z`, `a`–`z`, `0`–`9`, `_`
  and `-`, with `_` and `-` folded away) with its secret names, and hides the value of every
  other name by default: names with letters outside ASCII, mixed scripts, combining marks,
  format characters, spaces, dots, brackets, escapes or other punctuation. A value is hidden
  whole: a string, and an array or object with everything in it. Values of names such as
  `статус`, `café`, `user.id` and `user[name]` are now hidden too.
- A text that is a JSON object or array is read with a JSON parser checked against
  `JSONSerialization` instead of being scanned: names are compared after their escapes are
  decoded, at every depth, inside arrays and for every repetition of a name, and hidden values
  keep the document valid JSON (`"password":"[redacted]"` for an array or object as well).
- Other text is read with a documented free-text rule. Words before a name that only whitespace
  separates are read with it (`pass word=`); a separator with no name before it, an unclosed
  quote and punctuation outside ASCII after a secret name hide the rest of the line; a value on
  the line after its separator is hidden; an angle-bracketed value is hidden with its brackets.
- `dbpassword`, `apitoken`, `dbpwd` and other names with a compound secret word anywhere, or with
  `token`, `secret` or `pwd` at the end, now hide their value.

### Removed

- The table of look-alike letters from other scripts. It could never be complete; names that
  are not plain ASCII are hidden instead of being read as Latin.

### Fixed

- Every one of the 51 inputs that got a secret past the 2.0.1 branch is hidden, among them
  Cyrillic and Greek look-alike letters (`pаssword=`), styled letters (`𝐩𝐚𝐬𝐬𝐰𝐨𝐫𝐝=`, `ⓟassword=`),
  separators and escapes inside a name (`pass.word=`, `pass%77ord=`, `p&#97;ssword=`,
  `"pass\u0077ord":`), arrays and objects under a secret name, a value after a line break,
  vertical tab or form feed, and `︓` as a separator. They are kept as tests, together with
  tests that disguise secret names at random and check that no value shows, and tests that
  plain names that are not secret keep their value.

## [2.0.1] - 2026-10-15

### Fixed

- `SensitiveDataRedactor` no longer shows part of a card number that a secret value, bearer token
  or JSON Web Token runs into: `token=abc_4111 1111 1111 1111` became
  `token=[redacted] 1111 1111 1111`. Findings that partly overlap are now replaced together, and
  such a joined `Match` reports every kind it covers.
- `SensitiveDataRedactor.redact(_:)` took time quadratic in the number of findings (22 s for
  1.6 million characters of `pwd=x `); it now builds the output once and runs in linear time, as
  2.0.0 stated. A scaling test replaces the old timing test, which could not fail.
- `SensitiveDataRedactor` turned `PASSWORD := hunter2` into `PASSWORD :[redacted] hunter2`,
  hiding the `=` and showing the password, and did the same with `password == hunter2`,
  `password === hunter2`, `password ::= hunter2` and `password = = hunter2`; it now reads `:=`,
  `?=`, `+=`, `==`, `!=` and any further run of `=` and `:` as one separator, also when written
  as one character such as `≔`.
- `SensitiveDataRedactor` printed a secret as is when an en space or another Unicode space
  outside U+00A0, U+2007, U+2009, U+202F and U+3000 stood around the `=`, inside a card number
  or after `Bearer`; every Unicode space now counts as a space.
- `SensitiveDataRedactor` now finds secret values in form fields (`password[]=`,
  `user[password]=`, also with percent-encoded brackets as in `user%5Bpassword%5D=`), XML elements
  (`<password>…</password>`, also with attributes or a namespace prefix such as
  `<wsse:Password Type="…">`), after a percent-encoded `=` or `:` (`password%3D…`, also with
  `%20` or `+` around it) and inside angle brackets (`password: <…>`), and treats
  `pass`, `session_id`, `session_key`, `PHPSESSID`, `JSESSIONID` and a field named exactly
  `session` as secret names.
- `PasswordHash.verify(_:against:)` returns `false` for an empty or overlong password instead of
  throwing `CipherError.invalidParameter`; a malformed hash still throws.

### Changed

- CI uses the shared workflows of muhittincamdali/.github v1.1.0.

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

[Unreleased]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/muhittincamdali/iOSSecurityTools/releases/tag/v1.0.0
