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
reads as secret or cannot read, a value in free text after a key that is not allowed, what follows
a secret name written as a value, the rest of a line it cannot read, a body it cannot parse
completely, the other digits of a card number or an IBAN, and the rest of the name in an email
address.

### What it is for: the threat model

The redactor is built for one threat: a developer who logs a secret by accident, such as a
request, a response, a header or user text written to a log, a trace, an analytics event or a
file. It is not built to stop someone who writes a log line on purpose to get a secret past it.

- **Structured input is default-safe.** JSON, form and multipart bodies with their part
  headers, and URLs, are read with a parser, and XML and property lists in text by their tags. What the redactor does
  not fully understand there is hidden: a key that is not plain ASCII, a name that cannot be
  read, a body that does not parse.
- **Free text is a best effort.** A log line has no grammar. A value written with a separator is
  always hidden: `key=value`, `key: value`, a quoted name such as `name="password"`, also inside
  the value of another key, and JSON.
  A secret name written without a separator and disguised on purpose with two or more look-alike
  letters (`pɑsswoʀd hunter2`) is not guaranteed to be found; <doc:KeepingSecretsOutOfLogs#What-it-does-not-find>
  lists such limits. No table of look-alikes is kept to chase them, since none is ever complete.
  Write logs with separators, or as structured data, and keep secrets out of them.

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
so `{"note":"password=hunter2"}` and an escaped JSON document inside a string are redacted too.

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

In a log line, JSON nested deeper than 64 levels hides the line from its first bracket, like JSON
that does not parse. The package's tests run every limit on a thread with 512 KiB of stack, the
default of a secondary thread, a GCD queue and a Swift concurrency task, and with
`swift test -c release` they check that a megabyte of text, nested input or a body takes less than
a second, also for ordinary shapes such as a JSON array of short strings, a multipart body of
1,000 parts, URLs of many segments and a megabyte of Turkish sentences or of `ı` quoted in JSON up
to four times, timed by the CPU time of such a thread. The default redactor and its folded keys
are made once and shared, never per array element or path segment, each path segment is read in
a single pass, and each word is compared with each secret word in a single pass. The second
reading of a line follows at most 16 names written as values in it into markup and the lines
below; after them it follows only the last one, and hides the next line with text.

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
  other text, and so does a connector glued inside a word (`user‿bob`). Every dash is read as
  `-`, which joins words. A `:` between two digits, as in `12:30`, is part of a time.
- **A value after a key that is not allowed** is hidden: a quoted value (`"`, `'` or a backtick)
  up to its closing quote, a JSON object or array whole, and anything else to the end of its
  line, because where an unquoted value ends cannot be told.
- **Values go on below their line.** A quote that does not close on its line hides the lines up
  to the one where it closes, and that line whole. After a value hidden to the end of its line,
  the lines indented more (YAML blocks, folded headers) and the line after a trailing `\` are
  hidden, and so is the next line with text when nothing but punctuation followed the key, the
  line ends open (`(`, `:`, `<key>`, `"""`) or it ends at a line break other than LF and CRLF.
- **A secret name written as a value** names what follows it. A quoted value that holds a secret
  name or a word that cannot be read — `name="password"`, `key='token'`, `id: "pin"`,
  `header="Authorization"`, `label="API Key"` — hides the rest of its line after the closing
  quote, and the next line with text when nothing follows it; so does a name without quotes after
  a key that holds one (`name=password`). After a key that holds a name
  (`name`, `key`, `field`, `label`, `type`, `header`, `param`, `id`, `k`, `n`) a name that is not
  plain ASCII counts as secret too, as in JSON (`label="Пароль"`, `name='ⓟⓘⓝ'`), and so does JSON
  there (`name=["pin"]`), also when the key is allowed; `path=` is the route of a request in a
  log line and is not read this way. In XML and HTML the values of the
  other attributes of its start tag go too (`<input path="…" name="password">`), and so do the
  lines below up to the element's end tag while they hold markup or are indented more, or all of
  them when an end tag of the element comes later in the text
  (`<string name="api_key">…</string>`, `<entry key="db.password">`), and the rest of the line
  where the element ends. An element that closes itself or holds nothing holds no value, so after
  `<string name="password" />` or `<string name="password"></string>` the next line with text is
  hidden unless it starts with markup. A secret name in the text of an element names the element
  after it, as a property list writes a key and its value, on one line
  (`<key>password</key><string>…</string>`) or on lines of their own, indented or not: after
  `<key>password</key>` and then `<string/>` on a line of its own, the text after it or the next
  line with text is hidden too. JSON after a key that holds a name hides what follows it to the
  end of the line where it closes, also when it spans lines (`name=[`, `"pin"`, `] …`). A name
  that is not secret (`name="status"`) keeps what follows it, and an end tag (`</key>`) names
  nothing.
- **A name inside a hidden value** names what follows it all the same. Each line is read twice:
  the first reading hides values and stops at a value it hides to the end of the line, and the
  second reads what the first hid without reading it, and the quoted values, for the names written
  as values in them — quoted or not, held by a key, in markup — so a name hides the rest of its line
  and the lines it leaves open wherever it is on the line. In
  `Content-Disposition: form-data; name="pin"` the key `Content-Disposition` hides its value, and
  the name in that value still hides what follows it. A secret name in a header of a multipart part
  written to a log (after `Content-Disposition` or `form-data` on its line) hides the part's other
  header lines up to the blank line after them, and then the part's value: up to the delimiter line
  written before the header (`--boundary` or `--boundary--`), or, when none was, up to a blank line
  or a line that starts with `--` after the value's first line, which is hidden whatever it is
  (`-----BEGIN PRIVATE KEY-----`). The next part, under a name that is not secret, keeps its value.
- **A secret name without a separator** hides the rest of its line: `password hunter2`,
  `PIN 1234`. Words are read after their escapes are decoded (`p&#97;ssword`, `pass%77ord`), with
  punctuation inside them and a space, `|`, `,`, `;`, `&` or `?` between two of them read as a
  separator (`pass~word`, `pass word`, `p|wd`), and one letter that has no ASCII form (`ɑ`, `ı`)
  in a secret word read as any one letter or, between two letters, as none (`passꞏword`). A name
  with two or more such letters is not read this way (see "What it does not find").
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
redactor.redact("field name=\"password\" hunter2")      // "field name=\"[redacted]\"[redacted]"
redactor.redact(#"<string name="api_key">k-1</string>"#) // "<string name=\"[redacted]\"[redacted]"
redactor.redact("<key>password</key>\n<string>k-1</string>")
// "<key>[redacted]\n[redacted]</string>"
redactor.redact("Content-Disposition: form-data; name=\"pin\"\r\n\r\n4831")
// "Content-Disposition: [redacted]\r\n\r\n[redacted]"
redactor.redact("git clone https://bob:hunter2@github.com/x/y.git")
// "git clone https://github.com/x/y.git"
```

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
language, or a value encoded as a whole that is shorter than 32 characters. In free text, where no
`=` or `:` follows a name, it does not read a name written wholly in another script that only
looks Latin (Greek `ΡΙΝ`), one disguised with two or more letters that have no ASCII form
(`pɑsswoʀd hunter2` shows `hunter2`, and a URL path `/pɑsswoʀd/…` the segment after it) or
written in them throughout (small capitals, enclosed letters), one spelled with digits and symbols
(`p@ssword`, `passw0rd`), a name escaped as octal (`\163`), a value written before its name or
glued to a flag (`-pSECRET`), a value after a dash that looks like `=` (`user゠bob`) or an arrow
drawn as a symbol (`user⭢bob`), a name in another script as an element of an array of more than
two (`["Şifre","…","…"]`), and a name and value in two different JSON objects or arrays. It does
not find card numbers grouped with dots or
underscores, glued to ASCII letters or written as a JSON floating-point number. XML in free text
is not parsed: only a secret name or a word that cannot be read in it hides what follows, an
attribute before the name on an earlier line of its start tag is not read, and the lines of an
element that never ends are hidden only while they hold markup or are indented more. The value
of an allowed key is shown, also when it is repeated (`status==…`), unless a secret name before
it leaves its line open (`name=password`, then `value=…` on the next line).

Where it cannot tell, it hides more than it has to: everything after a key that is not allowed
(`Error: connection refused` hides `connection refused`), the lines after a value that ends open,
a whole word with an invisible character in it, and the headers and value of a multipart part
written into text whose header names a secret, up to its delimiter.

With `os.Logger`, interpolated values are already private in release logs unless you mark them
`.public`; use the redactor for the values you do mark public, and for logs sent to your own
servers.

### Cover the screen

Add ``SwiftUICore/View/privacyShield(when:)`` to views with sensitive content. It covers the view
while the app is in the app switcher and, on iOS, tvOS and visionOS, while the screen is recorded,
mirrored or shared. iOS reports screenshots only after they are taken;
``SwiftUICore/View/onScreenshot(perform:)`` lets you react to them.
