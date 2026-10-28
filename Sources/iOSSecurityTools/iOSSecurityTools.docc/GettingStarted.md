# Getting Started

Add the package, store an encrypted value in the keychain, and cover the screen in the app
switcher.

## Overview

This article builds a screen that encrypts a note, stores it in the keychain, reads it back and
hides itself in the app switcher. It takes about five minutes in a new Xcode project.

### Add the package

In Xcode, choose **File › Add Package Dependencies…**, paste the repository URL into the search
field and click **Add Package**:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

In the next window, choose your app target next to **iOSSecurityTools** and click **Add Package**
again. In a `Package.swift`, add

```swift
.package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.2.0")
```

and `.product(name: "iOSSecurityTools", package: "iOSSecurityTools")` to the target's
dependencies.

### Encrypt and store a value

Create a ``Keychain`` for your app's data, ask it for an encryption key, and use the key with a
``DataCipher``:

```swift
import iOSSecurityTools

let keychain = Keychain(service: "QuickStart")
let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "notes-key"))
try keychain.set(cipher.encrypt("Meet at 7 pm"), forKey: "note")

let stored = try keychain.data(forKey: "note") ?? Data()
let note = try cipher.decryptString(stored)   // "Meet at 7 pm"
```

``Keychain/symmetricKey(forKey:)`` creates a random 256-bit key the first time and returns the same
key afterwards. The system keeps it encrypted in the keychain; ``DataCipher`` uses it for
AES-256-GCM, which detects any change to the stored bytes.

Run the app on an iPhone simulator or a device. A macOS app needs a development team under
**Signing & Capabilities** for the keychain; without one, calls throw
``KeychainError/missingEntitlement``.

### Hide the screen in the app switcher

Add ``SwiftUICore/View/privacyShield(when:)`` to a view that shows sensitive data:

```swift
NoteView(note: note)
    .privacyShield()
```

When the user opens the app switcher, the system takes a snapshot of the app; the shield covers
the view before that happens. It also covers the view while the screen is recorded or mirrored.

### Next steps

- <doc:StoringSecrets> covers keychain options, biometric protection, PIN hashes and Secure
  Enclave keys.
- <doc:PinningCertificates> explains how to pin your server's keys without locking out installed
  apps.
- <doc:DetectingCompromisedDevices> describes what the integrity checks can and cannot tell.
- <doc:KeepingSecretsOutOfLogs> shows how to keep passwords and card numbers out of logs.
