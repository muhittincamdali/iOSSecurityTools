# Keeping Secrets Out of Logs

Stop passwords, tokens and card numbers from reaching logs, crash reports and screenshots.

## Overview

Most leaks are accidents: a model printed while debugging, a request body in an error message, a
screen in the app switcher. iOSSecurityTools has one tool for each.

### Mark values that must never be printed

Wrap sensitive properties in ``Redacted``:

```swift
struct LoginRequest: Codable {
    var username: String
    @Redacted var password: String
}

print(LoginRequest(username: "alice", password: "hunter2"))
// LoginRequest(username: "alice", _password: <redacted>)
```

String interpolation, `print`, `dump`, `Mirror`, the debugger summary and `NSLog("%@")` all show
`<redacted>`. Reading `request.password` still returns the value, and `Codable` encodes it as
usual, because sending a request body is deliberate.

### Show only part of a value

``Mask`` keeps the part a user needs to recognize a value:

```swift
Mask.cardNumber("4242 4242 4242 4242")   // "•••• 4242"
Mask.email("alice@example.com")          // "a•••@example.com"
Mask.trailing("DE89370400440532013000")  // "•••• 3000"
```

The hidden part is always written as four dots, whatever its length, and a value too short to hide
most of it is hidden completely.

### Scrub text you do not control

Error messages and server responses can contain data you never meant to log. Pass them through a
``SensitiveDataRedactor`` before they reach a log or an analytics event:

```swift
let redactor = SensitiveDataRedactor()
logger.error("\(redactor.redact(error.localizedDescription), privacy: .public)")
```

It finds card numbers (with the Luhn check), email addresses, JSON Web Tokens, bearer tokens and
the values of fields named like secrets (`password`, `token`, `api_key`, `authorization`, ...). It
removes invisible characters and maps full-width letters and digits from other scripts before
matching, so `password=` with a zero-width space inside the name, or a card number in full-width
digits, is still found. It works in one pass without regular expressions, so a long or crafted
input cannot slow it down.

With `os.Logger`, interpolated values are already private in release logs unless you mark them
`.public`; use the redactor for the values you do mark public, and for logs sent to your own
servers.

### Cover the screen

Add ``SwiftUICore/View/privacyShield(when:)`` to views with sensitive content. It covers the view
while the app is in the app switcher and, on iOS, tvOS and visionOS, while the screen is recorded,
mirrored or shared. iOS reports screenshots only after they are taken;
``SwiftUICore/View/onScreenshot(perform:)`` lets you react to them.
