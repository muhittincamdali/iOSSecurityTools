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

It finds card numbers (with the Luhn check), IBANs (with the mod-97 check), email addresses, JSON
Web Tokens, bearer tokens, runs of 32 or more hex or base64 characters, the password in
`user:password@host`, and the values of fields named like secrets. Its rule is that what it does
not fully understand is hidden, never shown.

### A safety net, not a guarantee

Redaction catches mistakes; it does not make it safe to log secrets. Keep passwords, tokens and
personal data out of log calls in the first place, and treat the redactor as the net under that
rule.

What it writes: the text around the findings, the names of fields, the values of plain names that
are not secret in JSON, form and multipart bodies, the values of the keys on
``SensitiveDataRedactor/allowedTextKeys`` in free text, masks that keep the last four digits of a
card number or an IBAN and the domain and first letter of an email address, and for a body it
cannot parse a note with its size and content type. What it never writes: the value of a field it
reads as secret or cannot read, a value in free text after a key that is not allowed, the rest of
a line it cannot read, a body it cannot parse completely, the other digits of a card number or an
IBAN, and the rest of the name in an email address.

### Plain-ASCII keys are compared; any other key is redacted

A secret name can be disguised with look-alike letters from other scripts, styled or full-width
letters, combining marks, invisible format characters, escapes or punctuation, and no list of
look-alikes is ever complete. So the redactor compares only plain-ASCII keys — at most 256 of
`A`–`Z`, `a`–`z`, `0`–`9`, `_`, `-`, `.` and spaces, with the separators folded away, so
`PASS-WORD` and `pass.word` read as `password` — and redacts the value of every other key by
default:

```swift
let form = "p%D0%B0ssword=a&pass.word=b&user%5Bname%5D=c&user.name=bob"
redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded")
// "p%D0%B0ssword=[redacted]&pass.word=[redacted]&user%5Bname%5D=[redacted]&user.name=bob"
```

The secret names are the list the redaction spec shares between packages — `password`, `passwd`,
`pwd`, `secret`, `token`, `access_token`, `refresh_token`, `id_token`, `api_key`, `apikey`,
`key`, `auth`, `authorization`, `cookie`, `set-cookie`, `session`, `sid`, `otp`, `pin`, `cvv`,
`card`, `iban`, `ssn`, `private_key`, `client_secret`, `signature` — and `passphrase`,
`passcode`, `credential`, `cvc`, `sessid`, `pw` and compounds such as `pin_code` or
`verification_code`, also in the plural (`tokens`, `api_keys`). Long words count anywhere in a
key (`dbpassword`), short ones as a word of it or at its end (`user_pin`, `X-Auth-Key`,
`apitoken`), `pass`, `sid` and `pw` only as a word (`DB_PASS`, not `bypass`), and `session` as
the last word (`laravel_session`, not `session_start`).

The cost is that a key that only describes a secret hides its value too — `passwordHint`,
`token_type`, `key_path`, `pin_length` — and so does a key written in another script or with
brackets or other punctuation (`статус`, `user[id]`), even when it holds nothing secret. A hidden
value is hidden whole: a string, a number, and an array or object with everything in it.

### Structured input is parsed; unparsed bodies are omitted

A text that is a JSON object or array is read with a JSON parser and checked against
`JSONSerialization`, so keys are compared after their escapes are decoded (`"pass\u0077ord"`),
at every depth, inside arrays and for every repetition of a key. Strings are read as free text,
so `{"note":"password=hunter2"}` and an escaped JSON document inside a string are redacted too,
and so are the `value` of `{"name":"X-Api-Key","value":…}` (also with `key`, `field`, `k` and
`val`, `v`) and the elements after `"password"` in `["password","…"]`.

Request and response bodies go through ``SensitiveDataRedactor/redact(body:contentType:)``, which
reads JSON, form (`application/x-www-form-urlencoded`), multipart form and plain-text bodies with
a parser chosen by the content type. A body it cannot parse completely — cut off, malformed, of
another type such as XML, or larger than 1 MiB — is omitted:

```swift
redactor.redact(body: Data(#"{"user":"bob","password":"hunter2"}"#.utf8), contentType: "application/json")
// {"user":"bob","password":"[redacted]"}
redactor.redact(body: Data("<password>hunter2</password>".utf8), contentType: "application/xml")
// [body omitted: 28 bytes, application/xml]
```

A body is also omitted when a common server parser — PHP, Werkzeug (Flask), Rack, Go or busboy —
could split it into fields differently from the redactor, because a field the redactor did not see
could show its value. Each parser reads only what all of them agree on:

- **Multipart:** the content type has one unquoted `boundary` of at most 70 characters, and every
  `--boundary` in the body, in any case, is a delimiter line of its own after a CRLF. PHP and
  Werkzeug also split a part at `--boundary` after a bare LF, Werkzeug after a bare CR, so a part
  holding `hi\n--boundary` and a second set of headers is omitted with the body. So are part
  headers that end their lines with a bare LF, a boundary line with trailing spaces, and text
  before the first boundary or after the closing one.
- **Forms:** every character is printable ASCII other than `;`, every `%` starts an escape of two
  hex digits, and no name is spelled two ways. Rack, Python before 3.9.2 and Go before 1.17 also
  split at `;`, Rack drops spaces after a separator, servers keep, drop or reject a bare `%`, and
  PHP reads `a.b`, `a b` and `a_b` as one name, as decoding makes `pass%77ord` into `password`.
  A URL query that breaks these rules is written as `?[redacted]`.
- **JSON:** the text is RFC 8259 and nothing more, and `JSONSerialization` reads the same tree;
  a trailing comma, a comment, `NaN`, a lone surrogate escape or a second document after the
  first is not. Every repetition of a name is compared, names are compared without case, and a
  name that is not plain ASCII hides its value, so a name that Go binds without case or with
  Unicode folding (`PASSWORD`, `paſſword`) hides its value too.
- **Content type:** one `type/subtype` with `; name=value` parameters; a second type after a
  comma, a space around `=` or two `charset` parameters make the body omitted.

```swift
let body = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\n--B0und\r\n"
    + "Content-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--B0und--"
redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B0und")
// [body omitted: 137 bytes, multipart/form-data]
```

URLs go through ``SensitiveDataRedactor/redact(url:)``, which reads them with `URLComponents`.
The user name, password and fragment are never written, whatever kinds the redactor looks for;
without ``SensitiveDataRedactor/Kinds/secretFields`` only the value detectors run on the path and
the query. With it, a query parameter keeps its value only when its name is plain ASCII and on
``SensitiveDataRedactor/allowedQueryParameters``, which is empty by default. A path segment
that looks like an identifier or a secret becomes `:id`, and so does the segment after one that
names a secret:

```swift
redactor.redact(url: URL(string: "https://bob:pw@example.com/users/12345678/reset?code=x#y")!)
// https://example.com/users/:id/reset?code=[redacted]
redactor.redact(url: URL(string: "https://example.com/v1/cards/4242/pin/4831")!)
// https://example.com/v1/cards/:id/pin/:id
```

### Limits keep hostile input from exhausting the stack

Strings are read as free text, and free text may hold JSON or a URL again, so a reader can find a
document inside a document many times over. A single budget bounds that descent, and with it the
stack that a log line or body from an attacker can use:

- A body larger than ``SensitiveDataRedactor/maximumBodySize`` (1 MiB) is omitted unread.
- JSON objects and arrays may be open 64 levels deep in all, counting the levels of every
  document a JSON string is in: JSON in a string inside one object may open 63 more.
- At most four documents are read one inside another. A JSON text, a URL, a body and a multipart
  part each count: in a JSON body, JSON in a string is the second.

JSON past a limit is not read. A body is omitted, and a string or other text inside a document
that holds such JSON, or a URL one level too many, is hidden whole:

```swift
let deep = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
redactor.redact(body: Data(deep.utf8), contentType: "application/json")
// [body omitted: 130 bytes, application/json]
let note = #"{"note":""# + String(repeating: "[", count: 64) + String(repeating: "]", count: 64) + #" ok"}"#
redactor.redact(body: Data(note.utf8), contentType: "application/json")
// {"note":"[redacted]"}
```

In a log line, JSON nested deeper than 64 levels hides the line from its first bracket, like JSON
that does not parse. The package's tests run every limit on a thread with 512 KiB of stack, the
default of a secondary thread, a GCD queue and a Swift concurrency task, and with
`swift test -c release` they check that a megabyte of text, nested input or a body takes less than
a second.

### Free text keeps a value only after an allowed key

A log line has no grammar, so name matching in it can always be bypassed. Free text is therefore
read the other way round, like a query string: in `key=value`, `key: value` and `"key":"value"`
the value is kept only when the key is plain ASCII and on
``SensitiveDataRedactor/allowedTextKeys``. The default list holds harmless keys that logs use for
numbers and routes (`status`, `status_code`, `method`, `path`, `duration`, `duration_ms`, `count`,
`size`, `bytes`, `page`, `limit`, `offset`, `attempt`, `level`); pass your own to the
initializer. A key that names a secret or is not plain ASCII is never allowed.

```swift
redactor.redact("login user=bob status=401 password=hunter2")
// "login user=[redacted]"
SensitiveDataRedactor(allowedTextKeys: ["user"]).redact("login user=bob status=401 password=hunter2")
// "login user=bob status=401 password=[redacted]"
```

The rule in detail:

- **Separators** are `=` and `:`, runs such as `:=`, `==` and `=>`, characters whose Unicode
  compatibility form is `=` or `:` (`＝`, `︓`, `≠`) and escaped forms (`%3D`, `&#61;`, `%u003D`).
  Punctuation and math symbols outside ASCII (`≔`, `꞉`, `→`, `·`) separate too where they follow
  other text. A `:` between two digits, as in `12:30`, is part of a time.
- **A value after a key that is not allowed** is hidden: a quoted value (`"`, `'` or a backtick)
  up to its closing quote, a JSON object or array whole, and anything else to the end of its
  line, because where an unquoted value ends cannot be told.
- **Values go on below their line.** A quote that does not close on its line hides the lines up
  to the one where it closes, and that line whole. After a value hidden to the end of its line,
  the lines indented more (YAML blocks, folded headers) and the line after a trailing `\` are
  hidden, and so is the next line with text when nothing but punctuation followed the key, the
  line ends open (`(`, `:`, `<key>`, `"""`) or it ends at a line break other than LF and CRLF.
- **A secret name without a separator** hides the rest of its line: `password hunter2`,
  `PIN 1234`. Words are read after their escapes are decoded (`p&#97;ssword`, `pass%77ord`), with
  punctuation inside them and a space, `|`, `,`, `;`, `&` or `?` between two of them read as a
  separator (`pass~word`, `pass word`, `p|wd`), and a letter that has no ASCII form (`ɑ`, `ı`)
  read as any one letter.
- **When a word cannot be read, the rest of the line is hidden.** That is a word that mixes
  scripts (`pаssword` with a Cyrillic `а`) or holds an invisible character other than a mark: a
  format character such as a zero-width space or a soft hyphen, a filler such as U+3164 or
  U+115F, an unassigned default-ignorable code point, or a control character such as `DEL`.
  Such a character right before a word or a key belongs to it: `\u{202E}drowssap` cannot be
  read, and `\u{200D}status=200` is not the allowed key `status`.
- **JSON in a line** is parsed and redacted by the key rule for structured input; JSON that does
  not parse hides the rest of the line and the lines below until its brackets close. **URLs**
  with a scheme and `//` are written as ``SensitiveDataRedactor/redact(url:)`` writes them.

```swift
redactor.redact("password hunter2")                     // "password [redacted]"
redactor.redact("p\u{0430}ssword=hunter2")              // "pаssword=[redacted]"
redactor.redact("login pa\u{115F}ssword hunter2")       // "login [redacted]"
redactor.redact("password: 'abc\n  hunter2'")           // "password: '[redacted]\n[redacted]"
redactor.redact("| password | hunter2 |")               // "| password [redacted]"
redactor.redact("git clone https://bob:hunter2@github.com/x/y.git")
// "git clone https://github.com/x/y.git"
```

Card numbers, IBANs, email addresses and tokens are found after Unicode compatibility
decomposition without marks, format characters, default-ignorable code points and control
characters, so full-width digits, zero-width characters, fillers and Unicode spaces do not hide
them. Scanning and replacing take time linear in the length of the text, without regular
expressions, and a key is compared in time linear in its length.

### What it does not find

It cannot find a secret that has no label or a label it does not know, such as a word in another
language, or a value encoded as a whole that is shorter than 32 characters. In free text, where no
`=` or `:` follows a name, it does not read a name written wholly in another script that only
looks Latin (Greek `ΡΙΝ`), one written in letters that have no ASCII form throughout (small
capitals, enclosed letters), one spelled with digits and symbols (`p@ssword`, `passw0rd`), a name
escaped as octal (`\163`), a value written before its name or glued to a flag (`-pSECRET`), and a
name and value in two different JSON objects. It does not find card numbers grouped with dots or
underscores, glued to letters or written as a JSON floating-point number. An XML element in free
text is not read as a pair; only a secret name or a word that cannot be read in it hides what
follows. The value of an allowed key is shown, also when it is repeated (`status==…`).

Where it cannot tell, it hides more than it has to: everything after a key that is not allowed
(`Error: connection refused` hides `connection refused`), the lines after a value that ends open,
and a whole word with an invisible character in it.

With `os.Logger`, interpolated values are already private in release logs unless you mark them
`.public`; use the redactor for the values you do mark public, and for logs sent to your own
servers.

### Cover the screen

Add ``SwiftUICore/View/privacyShield(when:)`` to views with sensitive content. It covers the view
while the app is in the app switcher and, on iOS, tvOS and visionOS, while the screen is recorded,
mirrored or shared. iOS reports screenshots only after they are taken;
``SwiftUICore/View/onScreenshot(perform:)`` lets you react to them.
