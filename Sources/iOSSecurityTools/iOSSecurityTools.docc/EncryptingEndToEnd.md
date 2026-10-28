# Encrypting End to End

Send data that only one device can read, sign what you send, and authenticate messages with a
shared key.

## Overview

``DataCipher`` encrypts with a key both sides already hold. When they do not — a server that
must send a device a secret, two devices of one user, a message to another user —
``PublicKeyCipher`` encrypts to a public key instead. ``SigningKey`` and ``VerifyingKey``
prove who wrote the data, and ``MessageAuthenticator`` checks data against a shared key, as a
webhook signature does. All of them run on CryptoKit; the package adds key formats, limits and
typed errors, not new cryptography.

### Give each device a key pair

Create the private key once, keep it in the keychain, and upload its 32-byte public key:

```swift
let keychain = Keychain(service: "com.example.chat")
let deviceKey = try keychain.keyAgreementKey(forKey: "device")
try await api.register(publicKey: deviceKey.publicKey.rawRepresentation)
```

``Keychain/keyAgreementKey(forKey:)`` creates the key on the first call and returns the same key
afterwards, also when two threads ask at once. The key stays readable after the first unlock and
never leaves the device through a backup (``KeychainAccessibility/afterFirstUnlockThisDeviceOnly``
by default).

### Seal and open a message

Any sender seals with the public key; no secret is shared beforehand:

```swift
let recipient = try PublicKeyCipher.publicKey(rawRepresentation: uploadedKey)
let envelope = try PublicKeyCipher.seal("Door code 4831", to: recipient,
                                        authenticating: Data("conversation-9 #41".utf8))
```

The device opens it with its private key and the same associated data:

```swift
let text = try PublicKeyCipher.openString(envelope, using: deviceKey,
                                          authenticating: Data("conversation-9 #41".utf8))
```

``PublicKeyCipher`` runs HPKE (RFC 9180) with X25519, HKDF-SHA256 and ChaCha20-Poly1305. Every
envelope has a fresh ephemeral key, so sealing the same text twice gives unrelated bytes, and
any changed byte, wrong key or wrong associated data throws ``CipherError/authenticationFailed``.

Put a message number in the associated data and check that it grows: an attacker who records an
envelope can send it again, and the cipher alone cannot tell.

### Know who sent it

A plain envelope says nothing about its sender. To bind the sender, seal with the sender's
private key as well:

```swift
let envelope = try PublicKeyCipher.seal("Door code 4831", to: recipient, from: senderKey)
let text = try PublicKeyCipher.openString(envelope, using: deviceKey, from: senderPublicKey)
```

This is HPKE's auth mode. It convinces the recipient, but not a third party: the recipient's own
private key could have made the same envelope. When others must be able to check who wrote
something — a support team reading a report, a server checking a receipt — sign it.

### Sign data

```swift
let signingKey = try keychain.signingKey(forKey: "author")      // Ed25519
let signature = try signingKey.signature(for: report)

// Anywhere else, with only the public key:
let author = try VerifyingKey(pemRepresentation: authorPEM)
guard author.isValidSignature(signature, for: report) else { throw ReportError.forged }
```

``SignatureAlgorithm/ed25519`` is the default. Choose ``SignatureAlgorithm/p256`` when the other
side requires ECDSA P-256, or use a ``SecureEnclaveKey`` when the private key must never leave
the hardware; ``VerifyingKey`` checks both the 64-byte signatures of ``SigningKey`` and the DER
signatures of the Secure Enclave. Public keys are read from raw bytes, DER or PEM, and every
P-256 point is checked to be on the curve.

### Agree on a key for a long conversation

Two devices that exchange many messages can derive one ``DataCipher`` key from their key pairs
instead of sealing each message to a public key:

```swift
let key = try KeyDerivation.sharedKey(privateKey: phoneKey, peerPublicKey: watchPublicKey,
                                      info: Data("sync v1".utf8))
let cipher = try DataCipher(key: key)
```

Both sides get the same key. A peer key of low order, which would give a shared secret of zeros,
throws ``CipherError/invalidParameter(_:)``.

### Check a webhook or a stored file

With a key both sides already hold, an HMAC is enough:

```swift
let authenticator = try MessageAuthenticator(key: SymmetricKey(data: webhookSecret))
guard authenticator.isValid(hexCode: signatureHeader, for: body) else { throw WebhookError.forged }
```

The comparison runs in constant time, codes of the wrong length or with stray characters are
refused, and keys shorter than 128 bits throw.

### What this does not cover

- Forward secrecy for the recipient: a stolen device private key opens every envelope ever
  sealed to it. Rotate device keys, and use a messaging protocol such as MLS or Signal when you
  need per-message keys.
- Trust in a public key: the package checks that bytes are a valid key, not whose key it is.
  Compare keys out of band, sign them with a key you already trust, or pin them.
- Replay: see the associated data advice above.
