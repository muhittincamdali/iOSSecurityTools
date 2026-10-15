# Pinning Certificates

Accept only the server keys you expect, without locking out installed apps when the keys change.

## Overview

Without pinning, a connection is trusted when any certificate authority in the system's store
vouches for the server. Pinning adds a second condition: one of the certificates in the chain
must carry a public key you listed. A certificate issued by another authority — after a
compromise, or by a proxy whose root the user installed — is then rejected.

Pinning cannot be undone remotely: a pin that no longer matches the server breaks every
installed copy of the app that has it. The rules below keep that from happening.

### Get the pins

A pin is the base64 SHA-256 hash of a certificate's SubjectPublicKeyInfo. Print the pin of the
certificate a server presents with OpenSSL:

```sh
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

For a certificate file, start the pipeline at `openssl x509 -in certificate.pem -pubkey -noout`.
In Swift, ``SPKIPin/init(certificate:)`` computes the same value. The SecurityLab example app lists
the pins of every certificate in a server's chain.

### Pin a key you control and a backup

``PinnedDomain`` requires two different pins. Pick them so that one survives any planned change:

- **Your own key and a backup key.** Generate the backup key pair now, keep it offline, and pin
  its hash. When you rotate, issue the new certificate for the backup key.
- **Your certificate authority's root or intermediate and a second authority's.** Pinning the
  roots of Let's Encrypt, for example, keeps working through certificate renewals. Pin a second
  authority you could move to.

```swift
let policy = try PinningPolicy([
    PinnedDomain("letsencrypt.org", pins: [
        "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",   // ISRG Root X1
        "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",   // ISRG Root X2
    ], includesSubdomains: true),
])
let session = URLSession.pinned(policy: policy) { failure in
    print("Blocked: \(failure.localizedDescription)")
}
```

A connection is accepted when any certificate of the verified chain matches, so leaf,
intermediate and root pins can be mixed.

### Roll out safely

1. Ship the pins with `isEnforced: false`. Mismatches are reported to the failure handler —
   ``PinningFailure`` is `Codable`, so you can send it to your server — and the request continues.
2. When the reports show no unexpected chains, ship with `isEnforced: true`.
3. Set an `expirationDate` about a year ahead. After it, the pins are ignored and only the
   system's checks apply, so a copy of the app that is never updated does not lose its connection
   when the keys change. Move the date forward with each release.

### What pinning does not replace

``PinningPolicy/evaluate(_:host:at:)`` first runs the system's trust evaluation for the host name,
and rejects the chain if it fails, even when a pin matches. Pinning therefore never accepts an
expired certificate, a certificate for another host name or an unknown authority. It also cannot
stop an attacker who controls the device: with a jailbreak, the check itself can be patched out.
Use App Attest when the server must know that it talks to your genuine app.
