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
are not secret in JSON, form and multipart bodies, free text up to its first trigger, the values of
the keys on ``SensitiveDataRedactor/allowedTextKeys`` before it, masks that keep the last four
digits of a card number or an IBAN and the domain and first letter of an email address, and for a
body it cannot parse a note with its size and content type. What it never writes: the value of a
field it reads as secret or cannot read, anything in free text after its first trigger — a key
that is not allowed, a secret name, a word it cannot read, a quote left open — a body it cannot
parse completely, the other digits of a card number or an IBAN, and the rest of the name in an
email address.

### What it is for: the threat model

The redactor is built for one threat: a developer who logs a secret by accident, such as a
request, a response, a header or user text written to a log, a trace, an analytics event or a
file. It is not built to stop someone who writes a log line on purpose to get a secret past it.

- **Structured input is default-safe.** JSON, form and multipart bodies with their part
  headers, and URLs, are read with a parser. What the redactor does not fully understand there is
  hidden: a key that is not plain ASCII, a name that cannot be read, a body that does not parse.
- **Free text is cut at its first trigger.** A log line has no grammar, so everything after the
  first trigger is hidden, to the end of the text: a key that is not on the allowlist, a secret
  name with or without a separator, a name written as a value (`name="password"`), a word that
  cannot be read, a quote or bracket left open. A value written with a separator is always
  hidden, and so is XML or a property list written into text. The one limit applies only when no
  trigger comes before a secret: a name written without a separator and disguised on purpose with
  two or more look-alike letters (`pɑsswoʀd hunter2`) is not guaranteed to be found;
  <doc:KeepingSecretsOutOfLogs#What-it-does-not-find> lists such limits. No table of look-alikes
  is kept to chase them, since none is ever complete. Write logs with separators, or as
  structured data, and keep secrets out of them.

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
so `{"note":"password=hunter2"}` is redacted too, and an escaped JSON document inside a string is
cut at its first member that is not allowed in text.

Some objects carry a field's name in one member and its value in another, and names are
classified by default too: non-ASCII names count as secret even when they are written as values.
The value of a member that holds a name — `name`, `key`, `field`, `label`, `type`, `header`,
`param`, `path`, `id`, `k` or `n`, or a member whose own name is not plain ASCII and may be one of
them disguised — is read by the key rule, as a key is. It names a secret unless it is a plain-ASCII
name without a secret word: `Şifre`, `Пароль`, a name in symbols, emoji, circled or squared letters
(`ⓟⓘⓝ`, `🄿🄸🄽`, `🔑`) or mathematical letters, a name with other punctuation (`Password:`), an
empty name and an array or object there all count as secret. Of a `path`, every part between `/`
is such a name, as JSON Patch (RFC 6902) and SCIM PatchOp (RFC 7644) write it: `/user/password`
and `/apiKeys/0` hide the value, `/status` and `/tags/-` keep it. A member whose value is a name
that names a secret or cannot be read counts wherever it is, as `{"type":"password","input":…}` and
CloudFormation's `{"ParameterKey":"DbPassword","ParameterValue":…}` write a field; a name there is
a string without `:`, `=`, `,`, `;`, quotes or brackets inside it, in which a symbol whose
compatibility form is a letter (`ⓟ`, `🄿`) counts as one, so a sentence (`"Error: token expired"`)
or JSON in a string is read as free text instead. In an object with such a name, the values of the
other members are hidden whole, whatever they are called: an object has no order, so what belongs
to the name cannot be told. The names of pairs (`name`, `key`, `field`, `header`, `param`, `path`,
`k`, `n` with a string) and an `op` that names a JSON Patch or SCIM operation stay. The second
element of a two-element array whose first is such a held name is hidden whole
(`[["Authorization","…"]]`, as fetch headers and `URLSearchParams` entries are written), and so
are the elements after `"password"` in `["password","…"]`. The fields of a form, the parameters of
a URL query and the parts of a multipart body are read the same way: `label=Password&value=…`
hides `value`. A multipart part that holds a name and cannot be read as plain UTF-8 text (in
base64 or another transfer encoding, sent as JSON, in another charset or as a file) counts as
naming a secret, as an array or object does in JSON.

The cost is that a name in another script hides what is beside it, whatever it holds:
`{"label":"Şifre","value":…}` hides the value on purpose, `{"name":"Ayşe","role":"admin"}` hides
`role`, and `{"type":"image/png","data":…}` hides `data`. Names that are plain and not secret keep
their values:

```swift
let patch = #"[{"op":"replace","path":"/user/password","value":"hunter2"},{"op":"replace","path":"/status","value":"active"}]"#
redactor.redact(body: Data(patch.utf8), contentType: "application/json-patch+json")
// [{"op":"replace","path":"/user/password","value":"[redacted]"},{"op":"replace","path":"/status","value":"active"}]
let fields = #"[{"label":"Şifre","value":"hunter2"},{"label":"ⓟⓘⓝ","value":"1234"},{"label":"status","value":"ok"}]"#
redactor.redact(body: Data(fields.utf8), contentType: "application/json")
// [{"label":"Şifre","value":"[redacted]"},{"label":"ⓟⓘⓝ","value":"[redacted]"},{"label":"status","value":"ok"}]
```

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
names a secret. A URL whose path has more than ``SensitiveDataRedactor/maximumPathSegments`` (64)
segments, or whose query or path has more than ``SensitiveDataRedactor/maximumQueryParameters``
(128) parameters, is recorded with its scheme, host and port only:

```swift
redactor.redact(url: URL(string: "https://bob:pw@example.com/users/12345678/reset?code=x#y")!)
// https://example.com/users/:id/reset?code=[redacted]
redactor.redact(url: URL(string: "https://example.com/v1/cards/4242/pin/4831")!)
// https://example.com/v1/cards/:id/pin/:id
redactor.redact(url: URL(string: "https://example.com" + String(repeating: "/a", count: 65))!)
// https://example.com
```

### Limits keep hostile input from exhausting the stack and the time

Strings are read as free text, and free text may hold JSON or a URL again, so a reader can find a
document inside a document many times over. A single budget bounds that descent, and with it the
stack and the time that a log line or body from an attacker can use:

- A body larger than ``SensitiveDataRedactor/maximumBodySize`` (1 MiB) is omitted unread.
- JSON objects and arrays may be open 64 levels deep in all, counting the levels of every
  document a JSON string is in: JSON in a string inside one object may open 63 more.
- At most four documents are read one inside another. A JSON text, a URL, a body and a multipart
  part each count: in a JSON body, JSON in a string is the second.
- The documents found inside one input read at most four times its length, all together. The
  input itself (the line, the body, the URL passed in) is read freely; each document found in it
  (JSON in a line or a string, a URL in text, a multipart part) counts its length, and so does
  each text read inside such a document. Each level of a document quoted in a document holds the
  levels inside it, so a long text quoted in JSON three times in a body, or twice in a log line,
  is read up to the budget and its innermost string is hidden; small documents nested four levels
  deep fit, since escaping makes each level shorter than the one around it.

JSON past a limit is not read. A body is omitted, and a string or other text inside a document
that holds such JSON, or a URL one level too many, is hidden whole, and so is a text inside a
found document that the reading budget no longer covers; a multipart part past it is omitted:

```swift
let deep = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
redactor.redact(body: Data(deep.utf8), contentType: "application/json")
// [body omitted: 130 bytes, application/json]
let note = #"{"note":""# + String(repeating: "[", count: 64) + String(repeating: "]", count: 64) + #" ok"}"#
redactor.redact(body: Data(note.utf8), contentType: "application/json")
// {"note":"[redacted]"}
```

In a log line, JSON nested deeper than 64 levels or longer than 64 Ki scalars cuts the line at its
first bracket, like JSON that does not parse. The package's tests run every limit on a thread with
512 KiB of stack, the default of a secondary thread, a GCD queue and a Swift concurrency task, and
with `swift test -c release` they check that a megabyte of text, nested input or a body takes less
than a second, also for ordinary shapes such as a JSON array of short strings, a multipart body of
1,000 parts, URLs of many segments and a megabyte of Turkish sentences or of `ı` quoted in JSON up
to four times, timed by the CPU time of such a thread. The default redactor and its folded keys are
made once and shared, never per array element or path segment, each path segment is read in a single
pass, and each word is compared with each secret word in a single pass. Free text is read once and
keeps a fixed number of positions, so the tests also check that a megabyte of text takes less than
16 MB more memory, among them a start tag of a megabyte of attributes followed by 17 secret names,
which an earlier design of 2.1.0 read into 583 MB.

### Free text is cut at its first trigger

A log line has no grammar, so reading it name by name can always be bypassed, and rules that carry
what a value is from one line to the next only multiply the cases. Free text is therefore read by
one rule: **in free text, the first secret name hides everything after it in that text; this
over-hides on purpose.** Not only a secret name is such a trigger: everything that the redactor
cannot read with certainty is one too, and the text is cut there, to its end — every line after
it, not only the rest of its line. A text without a trigger is written as it is, apart from the
card numbers, IBANs, email addresses and tokens in it.

Free text is a log message, a text/plain body, a string in JSON, a form value, an allowed query
value and a multipart text part, each one on its own: a trigger in one string of a JSON body hides
the rest of that string, and the next string is read again from its start.

```swift
redactor.redact("GET /api/items status=200 method=GET duration_ms=12")
// "GET /api/items status=200 method=GET duration_ms=12"
redactor.redact("login user=bob status=401 password=hunter2")
// "login user=[redacted]"
SensitiveDataRedactor(allowedTextKeys: ["user"]).redact("login user=bob status=401 password=hunter2")
// "login user=bob status=401 password=[redacted]"
redactor.redact("Error: connection refused\nretrying in 5 s")
// "Error: [redacted]"
```

The triggers:

- **A key that is not allowed.** In `key=value`, `key: value`, `key = value` and `"key":"value"`
  the text is read on only after a key that is plain ASCII and on
  ``SensitiveDataRedactor/allowedTextKeys``. The default list holds keys that logs use for a
  response status, a request method and route, a duration and a count (`status`, `method`, `path`,
  `duration_ms`, `count`); pass your own to the initializer. A key that names a secret or is not
  plain ASCII is never allowed. Any other key cuts the text at its value — `x=hunter2` as well as
  `Error: …` — and so does a separator with no key before it, or a key on the line before its
  separator.
- **A separator written another way.** The separators are `=` and `:` and runs of them (`:=`,
  `==`, `=>`). One written as a character whose compatibility form is `=` or `:` (`＝`, `︓`, `≠`),
  escaped (`%3D`, `&#61;`, `%u003D`), or as punctuation or a math symbol outside ASCII where it
  follows other text (`≔`, `꞉`, `→`, `·`, a connector glued inside a word as in `user‿bob`) cuts the
  text there. Every dash is read as `-`, which joins words. A `:` between two digits, as in
  `12:30`, is part of a time.
- **A secret name without a separator** cuts the text after the name: `password hunter2`,
  `PIN 1234`. Words are read after their escapes are decoded (`p&#97;ssword`, `pass%77ord`), with
  punctuation inside them and a space, `|`, `,`, `;`, `&` or `?` between two of them read as a
  separator (`pass~word`, `pass word`, `p|wd`), and one letter that has no ASCII form (`ɑ`, `ı`) in
  a secret word read as any one letter or, between two letters, as none (`passꞏword`). A name with
  two or more such letters is not read this way (see "What it does not find").
- **A name written as a value.** `name=`, `key=`, `label=` and the other keys that hold a name are
  not allowed by default, so they cut the text at once: `name="password"`,
  `<string name="api_key">`, `<entry key="db.password">` and `Content-Disposition: form-data;
name="pin"`, also when the name is not secret. When the app allows such a key (`id`, `type`, …
  but not `path`, the route of a request), a secret name after it, or one that is not plain ASCII,
  cuts the text after the name, as in JSON (`type="Пароль"`), and so does JSON there. The text of an
  element whose tag holds a name is read the same way (`<key>Şifre</key>`), and `<key>` is itself
  the secret word `key`. In XML and HTML a trigger inside a start tag cuts the text at the tag's
  first attribute value (`<input path="…" name="password">`).
- **A word that cannot be read** cuts the text where it starts: a word that mixes scripts
  (`pаssword` with a Cyrillic `а`) or holds an invisible character other than a mark — a format
  character such as a zero-width space or a soft hyphen, a filler such as U+3164 or U+115F, an
  unassigned default-ignorable code point, or a control character such as `DEL`. Such a character
  right before a word or a key belongs to it: `\u{202E}drowssap` cannot be read, and
  `\u{200D}status=200` is not the allowed key `status`.
- **A quote or bracket that does not close** by the end of the text cuts it after the quote or
  bracket: where its value ends cannot be told.
- **JSON in the text** is parsed and redacted by the key rule for structured input, and its
  members follow the rule for keys: the text is cut at the value of the first member that is not
  allowed, or at the first value the key rule hides, whichever comes first. JSON that does not
  parse, or is longer than 64 Ki scalars, cuts the text at its first bracket. **URLs** with a scheme
  and `//` are written as ``SensitiveDataRedactor/redact(url:)`` writes them, and the text is read
  on after them.

```swift
redactor.redact("password hunter2")                     // "password [redacted]"
redactor.redact("p\u{0430}ssword=hunter2")              // "pаssword=[redacted]"
redactor.redact("login pa\u{115F}ssword hunter2")       // "login [redacted]"
redactor.redact("password: 'abc\n  hunter2'")           // "password: [redacted]"
redactor.redact("| password | hunter2 |")               // "| password [redacted]"
redactor.redact("field name=\"password\" hunter2")      // "field name=[redacted]"
redactor.redact(#"<string name="api_key">k-1</string>"#) // "<string name=[redacted]"
redactor.redact("<key>password</key>\n<string>k-1</string>")
// "<key>[redacted]"
redactor.redact("upload ok status=200\n--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\n4831\r\n--B--")
// "upload ok status=200\n--B\r\nContent-Disposition: [redacted]"
redactor.redact(#"{"status":200,"user":"bob"} done"#)   // "{\"status\":200,\"user\":[redacted]"
redactor.redact("git clone https://bob:hunter2@github.com/x/y.git")
// "git clone https://github.com/x/y.git"
```

The scan reads the text once, left to right, and stops at the first trigger. It keeps a fixed
number of positions — the cut, the key before the next separator, the quote and the outermost
bracket that are open, the start tag it is in — however many keys or names the text holds, so
nothing is carried from line to line and no line is read twice. The line breaks of the input are
written as they are.

The name of an email address may be written in any script: it runs over letters, marks and
digits (`ayşe.yılmaz@gmail.com`, `bjørn.dæhlie@example.no`, `张伟@example.cn`), and the domain may
be an internationalized one (`王小明@例子.中国`). Only the first letter of the name is written, never
the rest: `a•••@gmail.com`, `•••@example.cn` for a name of two letters.

Card numbers, IBANs, email addresses and tokens are found after Unicode compatibility
decomposition without marks, format characters, default-ignorable code points and control
characters, so full-width digits, zero-width characters, fillers and Unicode spaces do not hide
them. They are found the same way on every path — free text, a body, a JSON string or name, a
form, a multipart part, a URL — and at least wherever 2.0.0 found them: only a letter or digit
written in ASCII glues digits or a token to a word (`id4242…`, `xeyJ…`), while a letter written
another way (`é`, `𝐚`, `№`) does not. An address after `:` shows no letter of its name, which may
be the password of `user:password@host` (`user:•••@example.com`), a token whose last dot was cut
off (`eyJ….eyJ…`) is still a token, and a finding that runs over the end of a URL in a line, as a
card number after a query or a token whose dot ends the sentence, is hidden whole. Scanning and replacing take time linear in the length of the text, without regular
expressions, and a key is compared in time linear in its length.

### What it does not find

It cannot find a secret that has no label or a label it does not know, such as a word in another
language, or a value encoded as a whole that is shorter than 32 characters. In free text, when no
trigger comes before it and no `=` or `:` follows a name, it does not read a name written wholly in
another script that only looks Latin (Greek `ΡΙΝ`), one disguised with two or more letters that have
no ASCII form (`pɑsswoʀd hunter2` shows `hunter2`, and a URL path `/pɑsswoʀd/…` the segment after
it) or written in them throughout (small capitals, enclosed letters), one spelled with digits and
symbols (`p@ssword`, `passw0rd`), a name escaped as octal (`\163`), a value written before its name
or glued to a flag (`-pSECRET`), a value after a dash that looks like `=` (`user゠bob`) or an arrow
drawn as a symbol (`user⭢bob`), a name in another script as an element of an array of more than two
(`["Şifre","…","…"]`), and a name and value in two different JSON objects or arrays. It does not
find card numbers grouped with dots or underscores, glued to ASCII letters or written as a JSON
floating-point number. XML in free text is not parsed: its attributes are keys like any other, and
the text of an element whose tag holds no name is read as words. The value of an allowed key is
shown, also when it is repeated (`status==…`).

Where it cannot tell, it hides more than it has to, on purpose: everything after the first key that
is not allowed (`Error: connection refused` hides `connection refused` and every line after it),
after the first secret name, word it cannot read or quote left open, a whole JSON string after a
trigger in JSON written into it, and a multipart body or a property list written into text from
its first header or key.

With `os.Logger`, interpolated values are already private in release logs unless you mark them
`.public`; use the redactor for the values you do mark public, and for logs sent to your own
servers.

### Cover the screen

Add ``SwiftUICore/View/privacyShield(when:)`` to views with sensitive content. It covers the view
while the app is in the app switcher and, on iOS, tvOS and visionOS, while the screen is recorded,
mirrored or shared. iOS reports screenshots only after they are taken;
``SwiftUICore/View/onScreenshot(perform:)`` lets you react to them.
