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
the values of fields named like secrets (`password`, `pass`, `token`, `api_key`, `authorization`,
`session_id`, a field named exactly `session`, `PHPSESSID` or `JSESSIONID`, ...), also when the
secret word is one part of a longer name (`SECRET_KEY`, `DB_PASS`, `aws_secret_access_key`,
`passwordConfirm`). Besides JSON, query strings, headers and `key: value` text, it reads JSON
escaped inside another string, form fields (`password[]=`, `user[password]=`, and
`user%5Bpassword%5D=` as form bodies send them), `:=`, `?=` and `+=` assignments, XML elements
(`<password>…</password>`, also with attributes or a namespace prefix such as
`<wsse:Password Type="…">`) and a percent-encoded separator (`password%3D…`). Names that only
describe a secret, such as
`passwordHint`, `token_type` or `session_start`, are left alone. When a token runs into a card
number, the whole stretch is replaced, so no part of either shows.

It removes invisible characters and maps full-width letters and digits from other scripts before
matching, so `password=` with a zero-width space inside the name, or a card number in full-width
digits, is still found. Scanning and replacing take time linear in the length of the text, without
regular expressions, so a long or crafted input cannot slow it down.

It cannot find a secret that has no label or a label it does not know (`pin`, `credentials`), or
text encoded as a whole, such as base64 or percent-encoded JSON. It does not read XML `CDATA`
sections, text percent-encoded twice (`password%253D…`), spaces inside form brackets
(`user[ password ]=`) or a secret given as an attribute value (`<input name="password" value="…">`).
Keep secrets out of log calls in the first place, and treat the redactor as the net under that
rule.

With `os.Logger`, interpolated values are already private in release logs unless you mark them
`.public`; use the redactor for the values you do mark public, and for logs sent to your own
servers.

### Cover the screen

Add ``SwiftUICore/View/privacyShield(when:)`` to views with sensitive content. It covers the view
while the app is in the app switcher and, on iOS, tvOS and visionOS, while the screen is recorded,
mirrored or shared. iOS reports screenshots only after they are taken;
``SwiftUICore/View/onScreenshot(perform:)`` lets you react to them.
