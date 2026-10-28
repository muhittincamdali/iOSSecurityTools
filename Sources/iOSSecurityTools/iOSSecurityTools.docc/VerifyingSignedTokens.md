# Verifying Signed Tokens

Check a JSON Web Token before the app trusts anything in it, and sign tokens the app issues.

## Overview

A JSON Web Token (JWT) carries claims — who the user is, what they may do, until when — and a
signature over them. Decoding the claims is easy; trusting them is safe only after the
signature, the algorithm and the time and audience claims are checked. ``JWTVerifier`` does all
of that in one call and returns ``JWTClaims`` only when every check passes.

Typical uses are a license or entitlement token the app keeps offline, a token in a deep link,
or an ID token you want to read on the device. A server that issues tokens to the app should
still check every request on the server: verifying on the device protects the app, not the API.

### Verify a token

Create one verifier for each key and reuse it:

```swift
let verifier = try JWTVerifier(
    publicKey: VerifyingKey(pemRepresentation: issuerKeyPEM),
    issuer: "https://auth.example.com",
    audience: "ios-app"
)

do {
    let claims = try verifier.verify(token)
    showAccount(claims.subject)
} catch JWTError.expired {
    try await refresh()
}
```

The key decides the algorithm: a P-256 ``VerifyingKey`` accepts only `ES256`, an Ed25519 key
only `EdDSA`, and ``JWTVerifier/init(key:issuer:audience:leeway:requiresExpiration:)`` with a
shared key of at least 256 bits only `HS256`. A token that names another algorithm, `none`
included, throws ``JWTError/algorithmMismatch(expected:found:)`` before its signature or claims
are read. That closes the classic attack of an `HS256` token keyed with the public key.

### What is checked

In this order, each failure with its own ``JWTError``:

1. The token is at most ``JWTVerifier/maximumTokenLength`` bytes: three parts of canonical,
   unpadded Base64URL.
2. The header is a JSON object without repeated names, its `alg` is the key's, and it has no
   `crit`. Header fields that point to other keys (`jku`, `jwk`, `x5u`, `x5c`) are ignored: the
   verifier never fetches a key.
3. The signature matches. `ES256` and `EdDSA` signatures must be the 64 raw bytes JWS uses.
4. The claims are a JSON object without repeated names. `exp`, `nbf` and `iat` are finite
   numbers; `iss`, `sub` and `jti` are strings; `aud` is a string or a list of strings.
5. `exp` is present (unless `requiresExpiration` is false) and `now` is before
   `exp` + leeway; `now` + leeway is not before `nbf`. The leeway defaults to 60 seconds and may
   be 0 to 600.
6. With an issuer set, `iss` equals it. A token with `aud` must list the verifier's audience;
   one without `aud` is accepted.

A clock that returns NaN or infinity fails the time checks instead of passing them.

### Read your own claims

Decode the claim set into a type of your own after verification:

```swift
struct License: Decodable {
    let sub: String
    let plan: String
    let seats: Int
}

let license = try verifier.verify(token, as: License.self)
```

Dates in your type are read as seconds since 1970.

### Sign a token

``JWTSigner`` writes compact tokens with the same three algorithms, for example a short-lived
proof that a request comes from this device:

```swift
let deviceKey = try Keychain(service: "com.example.app").signingKey(forKey: "device")
let token = try JWTSigner(signingKey: deviceKey).sign(
    JWTClaims(subject: "device-42", audience: ["api"],
              expiration: Date().addingTimeInterval(120), issuedAt: Date()),
    keyID: "device-42"
)
```

Dates are written as whole seconds when they have no fraction; a NaN or infinite date throws
instead of producing a token.

### Not supported

RSA (`RS256`, `PS256`), JSON Web Key sets and encrypted tokens (JWE) are not part of the
package. For RSA keys published as a JWK set, fetch and pin the set on your server and issue the
app an `ES256` or `EdDSA` token instead.
