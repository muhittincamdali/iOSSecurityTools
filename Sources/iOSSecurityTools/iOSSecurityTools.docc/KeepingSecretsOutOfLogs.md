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
`passwordConfirm`, `dbpassword`, `apitoken`). Names that only describe a secret, such as
`passwordHint`, `token_type` or `session_start`, are left alone.

### Plain-ASCII names are compared; any other name is redacted

A secret name can be disguised with look-alike letters from other scripts, styled or full-width
letters, combining marks, invisible format characters, escapes or punctuation, and no list of
look-alikes is ever complete. So the redactor compares only plain-ASCII names — `A`–`Z`, `a`–`z`,
`0`–`9`, `_` and `-`, with `_` and `-` folded away, so `PASS-WORD` reads as `password` — and
redacts the value of every other name by default:

```swift
let redactor = SensitiveDataRedactor()
redactor.redact("p\u{0430}ssword=hunter2 pass.word=hunter2 user[name]=bob user=bob")
// "pаssword=[redacted] pass.word=[redacted] user[name]=[redacted] user=bob"
```

The cost is that a name written in another script, or with a dot or brackets, hides its value
even when it holds nothing secret (`статус=ok`, `user.id=42`). A hidden value is hidden whole:
a string, and an array or object with everything in it.

### Structured input is parsed; what does not parse is omitted

A text that is a JSON object or array is read with a JSON parser and checked against
`JSONSerialization`, so names are compared after their escapes are decoded (`"pass\u0077ord"`),
at every depth, inside arrays and for every repetition of a name. Request and response bodies go
through ``SensitiveDataRedactor/redact(body:contentType:)``, which reads JSON, form
(`application/x-www-form-urlencoded`) and multipart form bodies with a parser chosen by the
content type. A body it cannot parse completely — cut off, malformed, of another type such as XML,
or a multipart body that servers could split differently — is omitted:

```swift
redactor.redact(body: Data(#"{"user":"bob","password":"hunter2"}"#.utf8), contentType: "application/json")
// {"user":"bob","password":"[redacted]"}
redactor.redact(body: Data("<password>hunter2</password>".utf8), contentType: "application/xml")
// [body omitted: 28 bytes, application/xml]
```

### Free text follows a documented rule

Other text, such as a log line or an error message, is read as `name=value` and `name: value`
fields with the same name rule. Separators include runs such as `:=` and `==`, characters whose
Unicode compatibility form is `=` or `:` (`＝`, `︓`) and escaped forms (`%3D`, `&#61;`). The name
is the quoted text or the word before the separator; words before it that only whitespace
separates are read with it, so `pass word=` and `API key:` count. The value is a quoted string,
a bracketed value up to its closing bracket, or the next word. Where the rule cannot tell where a
name or a value ends, it hides more: the rest of the line after a separator with no name, after an
unclosed quote, or after punctuation outside ASCII that follows a secret name (`password꞉…`).
``SensitiveDataRedactor`` lists the details.

Card numbers, email addresses and tokens are found after Unicode compatibility normalization, so
full-width digits, zero-width characters and Unicode spaces do not hide them. Scanning and
replacing take time linear in the length of the text, without regular expressions, so a long or
crafted input cannot slow it down.

It cannot find a secret that has no label or a plain-ASCII label it does not know (`pin`,
`credentials`), or text encoded as a whole, such as base64. In free text it does not read a value
separated from its name only by whitespace (`password hunter2`), more than the first word of an
unquoted value, XML `CDATA` sections or attribute values (`<input name="password" value="…">`).
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
