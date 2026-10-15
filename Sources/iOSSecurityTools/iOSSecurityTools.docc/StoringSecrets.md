# Storing Secrets

Choose where a secret lives on the device and who can read it.

## Overview

Tokens, keys and PINs belong in the keychain, not in `UserDefaults` or a file: the keychain
encrypts them with a key the system protects, and can require the user to authenticate before it
releases them. This article goes from a plain token to a key that never leaves the Secure
Enclave.

### Store a token

```swift
let keychain = Keychain(service: "com.example.app.credentials")
try keychain.set("r-7f3a9c", forKey: "refreshToken")
let token = try keychain.string(forKey: "refreshToken")
```

A missing key reads as `nil`; setting a key again replaces the value.
``Keychain/setValue(_:forKey:protection:)`` and ``Keychain/value(_:forKey:prompt:)`` store
`Codable` values as JSON.

### Choose when values can be read

``KeychainAccessibility`` decides when the system decrypts a value. The default,
``KeychainAccessibility/afterFirstUnlockThisDeviceOnly``, works for background refreshes and keeps
the value out of backups restored to other devices. Use
``KeychainAccessibility/whenUnlockedThisDeviceOnly`` for values that are only needed on screen, and
an accessibility without `ThisDeviceOnly` together with `synchronizable: true` for values that
should reach the user's other devices through iCloud Keychain.

To share values with an app extension, list a keychain access group in both targets'
entitlements and pass it as `accessGroup`.

### Require Face ID, Touch ID or the passcode

Pass a ``KeychainProtection`` when you store the value:

```swift
let keychain = Keychain(service: "com.example.app.cards")
try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
let pin = try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
```

Reading the value shows the system prompt; the keychain itself refuses to decrypt it until the
user passes. This is stronger than asking ``BiometricAuthenticator`` first and reading an
unprotected value afterwards: a patched `LAContext` on a jailbroken device can make the prompt
"succeed", but it cannot make the keychain release a protected value.

``KeychainProtection/biometryCurrentSet`` makes the value unreadable after a fingerprint or face
is added, so someone who learns the passcode cannot enrol their own face to read it. Read
protected values off the main thread: the call waits for the user.

### Encrypt larger data

The keychain is meant for small values. Encrypt files and records with a ``DataCipher`` and keep
only its key in the keychain:

```swift
let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "records-key"))
let envelope = try cipher.encrypt(record, authenticating: Data(recordID.utf8))
```

The associated data (`recordID`) is not encrypted, but it must match when you decrypt, so an
envelope copied into another record fails with ``CipherError/authenticationFailed``. Use
``KeyDerivation/derive(from:salt:info:outputByteCount:)`` to derive separate keys for separate
purposes from one master key.

### Check a PIN without storing it

For an app lock, store a hash of the PIN instead of the PIN:

```swift
let stored = try PasswordHash.make(for: "4921")
try keychain.set(stored, forKey: "pin-hash")

let matches = try PasswordHash.verify(enteredPIN, against: stored)
```

``PasswordHash`` uses PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt, and compares
in constant time. A four-digit PIN has only 10,000 values, so the hash alone does not stop a
determined attacker who copies the keychain item; combine it with an attempt counter, and with
``KeychainProtection`` for the data the PIN unlocks.

### Bind an account to the device

A ``SecureEnclaveKey`` is a signing key whose private part never leaves the Secure Enclave:

```swift
let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
upload(key.publicKeyDER)                       // once, when the user signs in
let signature = try key.signature(for: challenge)
```

Your server stores the public key and later verifies signatures of random challenges it sends.
A copied keychain backup or another device cannot produce them. Check
``SecureEnclaveKey/isAvailable`` first; Macs without Apple silicon or a T2 chip have no Secure
Enclave.
