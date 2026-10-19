# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SensitiveDataRedactor.redact(body:contentType:)` redacts request and response bodies with a
  parser chosen by the content type: JSON, `application/x-www-form-urlencoded` forms, multipart
  form data (each part by its own type) and plain text. A body that is not UTF-8, has another
  type, is larger than 1 MiB or does not parse completely is omitted as
  `[body omitted: N bytes, <type>]`; uploaded files are omitted the same way.
- `SensitiveDataRedactor.redact(url:)` writes a URL read with `URLComponents` without its user
  name, password and fragment. A query value is kept only for the names on
  `allowedQueryParameters`, which is empty by default; a path segment that looks like an
  identifier or a secret, and the segment after one that names a secret (`/pin/4831`), become
  `:id`. With `URLDetail.hostOnly` only the scheme, host and port are written.
- `allowedTextKeys` and `defaultAllowedTextKeys`: the keys whose values free text keeps.

### Changed

- Keys of structured input (JSON names, form and multipart field names, query names) are compared
  with the secret names only when they are plain ASCII (`A`–`Z`, `a`–`z`, `0`–`9`, `_`, `-`, `.`
  and spaces, with the separators folded away). Every other key has its value hidden by default:
  letters outside ASCII, mixed scripts, marks, format characters, brackets, escapes or other
  punctuation. A hidden value is hidden whole: a string, a number, and an array or object with
  everything in it. A plain key that holds a secret word as a word hides its value even when it
  only describes the secret (`passwordHint`, `token_type`, `pin_length`), and `pw` is a secret
  word.
- A text that is a JSON object or array is read with a JSON parser checked against
  `JSONSerialization`: keys are compared after their escapes are decoded, at every depth, inside
  arrays and for every repetition of a key, and the output stays valid JSON. The `value`, `val`
  or `v` of an object whose `name`, `key`, `field`, `header`, `param`, `k` or `n` names a secret is
  hidden too.
- Free text keeps a value only after an allowed key: in `key=value`, `key: value` and
  `"key":"value"` every other value is hidden, so `user=bob` becomes `user=[redacted]`. A quoted
  value is hidden up to its closing quote, also on a later line; an unquoted one to the end of its
  line, with the lines below that it may go on to. A word that holds a secret name hides the rest
  of its line, also when it is escaped, split by punctuation or a space, or spelled with a letter
  that has no ASCII form; a word that mixes scripts or holds an invisible character hides itself
  and the rest of its line.
- Default-ignorable code points (such as U+115F and U+3164) and control characters are left out
  of the scanning copy, like format characters, so they no longer split a secret name, a card
  number, an IBAN, a token or an email address.

### Removed

- The table of look-alike letters from other scripts. It could never be complete; keys that
  are not plain ASCII are hidden instead of being read as Latin.

### Fixed

- The inputs that got a secret past the earlier designs of this release are hidden, apart from
  the limitations the logging guide names: the 51 inputs of the second review, the 386 probes of
  the adversarial set (one of them a limitation) and the 453 probes of the review of the redesign
  (30 of them limitations). Among them are look-alike letters, styled letters, escapes,
  separators inside a name, arrays and objects under a secret name, values that run over lines in
  single quotes and backticks, fillers and control characters inside labels and card numbers, and
  URL path segments after a secret label. They are kept as tests, together with property tests
  that generate disguised secret names and random keys that are not allowed and check that no
  value shows, and tests that allowed keys and plain names keep their value.

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
