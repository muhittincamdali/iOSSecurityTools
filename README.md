<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-light.svg" alt="iOSSecurityTools: Keychain, encryption, pinning, one-time codes and integrity checks for Apple apps."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Latest version: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Supported platforms: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Language version: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="License: MIT"></picture></a>
</p>

<p align="center">
<a href="#quick-start"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-en-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-en-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-en-light.svg" alt="Get started"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-en-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-en-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-en-light.svg" alt="Documentation"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-en-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-en-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-en-light.svg" alt="Examples"></picture></a>
</p>

<!-- brand:end -->

A Swift package of security building blocks for apps on iOS, macOS, tvOS, watchOS and
visionOS: keychain storage, authenticated encryption, PIN hashes, Secure Enclave keys,
certificate pinning, one-time passwords, device integrity checks and log redaction. It is for
app developers who need these pieces done correctly without studying the Security framework's
C APIs. Each type validates what it is given and throws a typed error instead of crashing, so
values from a QR code, a server or a file cannot trap the app. The package has no dependencies.

## Highlights

- **Keychain without the dictionaries** — `Keychain` stores data, strings and `Codable` values,
  creates encryption keys on first use, and can require Face ID, Touch ID or the passcode,
  enforced by the keychain itself rather than by an `if` around `LAContext`.
- **Encryption that detects tampering** — `DataCipher` writes AES-256-GCM or ChaCha20-Poly1305
  envelopes that carry their own version, algorithm and nonce; any changed byte, wrong key or
  wrong associated data fails decryption. HKDF, PBKDF2 and PHC-format PIN hashes come with it.
- **Pinning that does not lock users out** — `PinningPolicy` requires a backup pin, supports
  subdomains, expiration dates and a report-only mode, and still requires the system's own trust
  evaluation to pass.
- **Signals, not promises** — `IntegrityInspector` reports jailbreak files, a debugger, the
  simulator, hooking libraries and a system proxy as a `Codable` report, and the documentation
  says what an attacker can hide from it.
- **Secrets stay out of logs and screenshots** — `@Redacted` prints `<redacted>` everywhere,
  `SensitiveDataRedactor` scrubs card numbers, emails, tokens and secret fields, and
  `.privacyShield()` covers views in the app switcher and during screen recording. The redactor
  compares plain-ASCII keys with its secret names and redacts any other key by default; JSON,
  form and multipart bodies are parsed, and unparsed bodies are omitted, as are bodies that a
  server could split into fields differently.
- **Tested against hostile input** — RFC 4226, 6238 and 5869 vectors, envelopes and hashes made by
  an independent implementation, certificate chains from a test PKI, NaN and infinite dates,
  `Int.min` and `Int.max`, oversized and duplicated URI parameters: 311 Swift Testing tests on
  macOS and an iPhone simulator, plus the keychain suites inside the example app.

### What's included

| Area                   | Types                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| Keychain               | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError`               |
| Encryption and hashing | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave         | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)`                      |
| Biometrics             | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS)                         |
| Certificate pinning    | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| One-time passwords     | `TOTP`, `HOTP`, `OTPAuthURI`                                                              |
| Device integrity       | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding`                               |
| Logs and screens       | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Quick start

**1. Add the package**

In Xcode, choose **File › Add Package Dependencies…** and enter the repository URL:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Paste it into the search field at the top right of the window. Leave **Dependency Rule** at
**Up to Next Major Version** from `2.1.0`, then click **Add Package**. In the next window,
choose your app target next to **iOSSecurityTools** and click **Add Package** again.

**2. Import the module**

```swift
import iOSSecurityTools
```

Put this line at the top of the Swift file where you use the package, below `import SwiftUI`.

**3. Use it**

In a new Xcode app (**File › New › Project… › App**), replace everything in `ContentView.swift`
with:

```swift
import SwiftUI
import iOSSecurityTools

struct ContentView: View {
    @State private var status = "Nothing stored yet"

    var body: some View {
        VStack(spacing: 16) {
            Text(status)
            Button("Encrypt and store a note") {
                do {
                    let keychain = Keychain(service: "QuickStart")
                    let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "notes-key"))
                    try keychain.set(cipher.encrypt("Meet at 7 pm"), forKey: "note")

                    let stored = try keychain.data(forKey: "note") ?? Data()
                    status = "Decrypted: \(try cipher.decryptString(stored))"
                } catch {
                    status = error.localizedDescription
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .privacyShield()
    }
}
```

Choose an iPhone simulator and press **Run** (⌘R). Tap the button: the app creates a key in the
keychain, encrypts the note with it, stores the encrypted bytes, reads them back and shows
"Decrypted: Meet at 7 pm". `.privacyShield()` covers the screen with a lock while the app is in
the background, so the app switcher does not show the note.

## Installation

### Swift Package Manager

In Xcode, choose **File › Add Package Dependencies…** and enter the repository URL:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Or add it to the `dependencies` in your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.1.0")
],
targets: [
    .target(name: "YourApp", dependencies: [
        .product(name: "iOSSecurityTools", package: "iOSSecurityTools")
    ])
]
```

Version 2.0.0 (October 2026) is the first release of the current package. The earlier release,
1.0.0 (February 2026), is a different code base: in June 2026 its sources were replaced with
placeholder code, and in October 2026 the package was rebuilt from scratch with tests.
[CHANGELOG.md](CHANGELOG.md) lists the changes.

A macOS app needs a development team under **Signing & Capabilities** to use the keychain;
iOS apps and the simulator need nothing extra. For Face ID, add `NSFaceIDUsageDescription` to the
app's Info.plist.

## Usage

The samples below are copied from
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift).
The example app and the test suite both compile that file, and the tests run the samples that
need no prompt or network.

### Store a token in the keychain

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Require Face ID for a value

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Encrypt a record

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Check an app lock PIN

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Show one-time codes from a QR code

```swift
func oneTimePasswordSample() throws -> Bool {
    let scanned = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    let uri = try OTPAuthURI(parsing: scanned)
    guard case .totp(let totp) = uri.kind else { return false }

    let code = try totp.code()                    // six digits, new every 30 seconds
    let secondsLeft = try totp.secondsRemaining()
    print("\(uri.issuer ?? ""): \(code), \(secondsLeft) s left")
    return try totp.verify(code)                   // also accepts the previous and next code
}
```

### Pin a server's keys

```swift
func pinnedSessionSample() throws -> URLSession {
    let policy = try PinningPolicy([
        PinnedDomain("letsencrypt.org", pins: [
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",   // ISRG Root X1
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",   // ISRG Root X2
        ], includesSubdomains: true),
    ])
    return URLSession.pinned(policy: policy) { failure in
        print("Blocked: \(failure.localizedDescription)")
    }
}
```

The [pinning guide](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
shows how to get the pins of your own server and roll them out without locking users out.

### Check the device

```swift
func integritySample() -> IntegrityReport {
    let report = IntegrityInspector().inspect()
    if report.hasFindings(in: [.jailbreak, .injectedLibraries]) {
        // Add friction: ask for the passcode again, lower limits, flag the session on the server.
    }
    for finding in report.findings {
        print(finding)   // for example "Running in the simulator"
    }
    return report
}
```

### Keep secrets out of logs

```swift
struct LoginRequest: Codable {
    var username: String
    @Redacted var password: String
}

func redactionSample() -> (request: String, log: String) {
    let request = LoginRequest(username: "alice", password: "hunter2")
    let printed = "\(request)"   // LoginRequest(username: "alice", _password: <redacted>)

    let redactor = SensitiveDataRedactor()
    let log = redactor.redact("charged 4242 4242 4242 4242 to alice@example.com, token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln")
    // "charged •••• 4242 to a•••@example.com, token=[redacted]"
    return (printed, log)
}
```

`SensitiveDataRedactor` compares only plain-ASCII keys (`A`–`Z`, `a`–`z`, `0`–`9`, `_`, `-`,
`.` and spaces) with its secret names; any other key is redacted by default, because look-alike
letters, invisible characters and escapes can disguise a secret name. JSON, form and multipart
bodies are read with a parser, and a body it cannot parse completely is omitted as
`[body omitted: N bytes, <type>]`, and so is a body that a common server parser could split into
fields differently, such as a multipart boundary after a bare line feed or a form with a `;`.
A body over 1 MiB is omitted too, and JSON is read at most 64 objects and arrays deep and four
documents one inside another, JSON in strings included, which bounds the stack that hostile input
can use; a string that holds more is redacted whole.
Free text keeps a value only after an allowed key (`status`,
`method`, `path`, `duration_ms`, `count` and the keys you pass), so `user=bob` becomes
`user=[redacted]`. Redaction is a safety net, not a guarantee. The
[logging guide](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
describes the rule for free text, what it costs and what it does not find.

### Bind an account to the device

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Demo

Screens of the SecurityLab example app on an iPhone simulator, captured from the running app by
[`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh):

| Integrity | Vault | One-time codes |
| --- | --- | --- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Integrity report in the simulator: jailbreak check not applicable, simulator found, debugger, injected libraries and proxy clear" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="A note encrypted into the keychain as 46 bytes and read back, and a PIN checked against its stored hash" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="A six-digit TOTP code from an otpauth URI with a ring counting down the seconds left" width="260"></picture> |

| Redaction | Privacy shield |
| --- | --- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="A log text with an email, a password, a bearer token and a card number, and the redacted version below it" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="A card details view covered by the privacy shield with a lock symbol" width="260"></picture> |

To run the app, open `SecurityLab.xcodeproj` in [`Examples/SecurityLab`](Examples/SecurityLab)
with Xcode, choose an iPhone simulator or **My Mac**, and press **Run**. It also has the quick
start and a certificate pinning screen that connects to a server and lists the pins of its
chain; [Examples/README.md](Examples/README.md) has the details.

## Documentation

Reference documentation and articles:

- [API reference](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, published to GitHub Pages from `master`)
- Build it locally in Xcode with **Product › Build Documentation**, or from the command line:

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Guides

- [Getting Started](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — add the package, encrypt a note into the keychain and cover the screen
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Storing Secrets](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — accessibility, biometric protection, encryption keys, PIN hashes and Secure Enclave keys
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Pinning Certificates](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — getting pins, choosing a backup, report-only rollout and expiration
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Detecting Compromised Devices](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — what each integrity check sees, what it cannot, and when to use App Attest
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Keeping Secrets Out of Logs](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, masks, the redactor and the privacy shield
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Requirements

| Platform  | Minimum version       |
| --------- | --------------------- |
| iOS       | 17                    |
| macOS     | 14                    |
| tvOS      | 17                    |
| watchOS   | 10                    |
| visionOS  | 1                     |
| Toolchain | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` is not available on tvOS and watchOS, which have no biometry. CI builds
with the default Xcode of GitHub's `macos-26` runner image. The package is developed with
Xcode 27.

## Architecture

- `Sources/iOSSecurityTools/<Area>/` holds one folder per area: `Keychain`, `Crypto`, `Random`,
  `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`, `Redaction` and
  `Privacy`. Everything is a `Sendable` value type except `PinningURLSessionDelegate`, which
  `URLSession` requires to be a class.
- The package calls Apple's frameworks directly — Security for the keychain and trust
  evaluation, CryptoKit for AES-GCM, ChaCha20-Poly1305, HKDF, HMAC and the Secure Enclave,
  CommonCrypto for PBKDF2, LocalAuthentication for biometry — and implements only what they lack:
  the envelope format, SubjectPublicKeyInfo encoding for pins, HOTP/TOTP truncation, Base32,
  the PHC hash format and the redaction scanner.
- Errors are typed (`throws(KeychainError)`, `throws(CipherError)`, ...) and every enum case
  has a description. Values that come from outside the app have limits checked before any work
  is done.
- Code that reads the system (integrity checks, `LAContext`) goes through small internal
  protocols, so the tests drive every branch with fakes and also check the live implementation.
- What the package does not do is part of the design: no `ptrace` deny-attach, no method
  swizzling, no reading of private dyld structures. Those break between OS releases and are easy
  to bypass; the [integrity guide](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  points to App Attest instead.
- CI runs `swift test` on macOS, `xcodebuild test` on an iPhone simulator, builds for all five
  platforms, builds the example app for iOS and macOS, runs its tests inside the app, and
  publishes the DocC documentation.

Run the tests locally:

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

A test bundle without a host app has no keychain entitlement on the simulator, so the package's
keychain suites run there inside the example app:

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Roadmap

- An App Attest wrapper (`DCAppAttestService`) with a server-side verification example.
- Add the package to the Swift Package Index; `.spi.yml` is already in the repository.

## Contributing

Contributions are welcome. Read the [contributing guide](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) and the [code of conduct](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md) before opening a pull request. Report security issues privately as described in the [security policy](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md).

## License

Released under the MIT license. See [LICENSE](LICENSE).
