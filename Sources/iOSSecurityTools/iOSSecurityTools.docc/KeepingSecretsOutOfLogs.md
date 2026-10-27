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
the keys on ``SensitiveDataRedactor/allowedTextKeys`` before it, clean URLs before it with
identifiers as `:id`, URL hosts that are names of ASCII labels or addresses, the part headers a multipart part carries, masks that keep the last four
digits of a card number or an IBAN and the domain and first letter of an email address, and for a
body it cannot parse or that is too large a note with its size and content type. What it never
writes: the value of a field it reads as secret or cannot read, anything in free text after its
first trigger — a key that is not allowed, a character outside the safe alphabet, an escape, a
word longer than 256 characters, a secret name, a word it cannot read, a markup tag, a quote that
does not close on its line, a URL that is not clean — a body it cannot parse completely, a URL host that is not an address, the name of a part header it does
not know, the other digits of a card number or an IBAN, and the rest of the name in an email
address.

### What it is for: the threat model

The redactor is built for one threat: a developer who logs a secret by accident, such as a
request, a response, a header or user text written to a log, a trace, an analytics event or a
file. It is not built to stop someone who writes a log line on purpose to get a secret past it.

- **Structured input is default-safe.** JSON, form and multipart bodies with their part
  headers, and URLs with their hosts, are read with a parser. What the redactor does not fully
  understand there is hidden: a key that is not plain ASCII, a name that cannot be read, a part
  header it does not know, a host that is not an address, a body that does not parse or is
  larger than the limit. Structured key names are shown: the names of JSON members and of form
  and multipart fields are written as they are and only the values under them are hidden, so a
  secret written into a name (`{"password hunter2":…}` in a body) shows.
- **Free text is cut at its first trigger.** A log line has no grammar, so everything after the
  first trigger is hidden, to the end of the text. Six rules set the triggers, and none of them
  keeps a list of variants: the first character outside a safe alphabet, any escape (every
  backslash before anything but white space among them), a word longer than 256 characters, a
  key that is not on the allowlist in any of its shapes, a markup tag, and a secret name with or
  without a separator. A URL is shown only when it is clean; any other URL
  cuts the text where it starts. Over-hiding is by design. A value written with a
  separator, ASCII or not, is always hidden. One wildcard rule reads a name written without a
  separator: a letter, mark or number outside ASCII that has no ASCII form, inside an ASCII word,
  counts as nothing or as any one letter, so one such character put in or put in place of a letter
  is found (`pɑssword`, `tøken`, `tͦken` with a small `o` written above the `t`, `passw〇rd`,
  `piꞏn`, and `t၀ken` with a Myanmar zero: a decimal digit of another script is such a number).
  The limit applies only when no trigger comes before a secret and the name is written without a
  separator, and it is deliberate disguise: a name in letters of the safe alphabet with
  two or more of its letters replaced on purpose by look-alike letters (`pɑsswoʀd hunter2`) is not
  guaranteed to be found. <doc:KeepingSecretsOutOfLogs#What-it-does-not-find> lists such limits.
  No table of look-alikes is kept to chase them, since none is ever complete. Write logs with
  separators, or as structured data, and keep secrets out of them.

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
`verification_code`, also in the plural (`tokens`, `api_keys`). The long names and the compounds
(`password`, `passwd`, `passphrase`, `passcode`, `apikey`, `credential`, `signature`, `cookie`,
`authorization`, `access_token`, `pin_code`, …) count anywhere in a key (`dbpassword`); `token`,
`secret` and the short words as a word of it or at its end (`user_pin`, `X-Auth-Key`, `apitoken`,
`mysecret`, not `tokenvalue` or `secretvalue`); `pass`, `sid` and `pw` only as a word (`DB_PASS`,
`user_pw`, not `bypass` or `dbpw`); and `session` only as the last word (`laravel_session`, not
`session_start`).

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
or JSON in a string is read as free text instead. One function makes the decision for every place
that reads a name. A name with a control character in it — a line feed or carriage return
before, inside or after it, a tab or any other — names a secret whatever it says in a member that
holds a name and as the name of a pair. Elsewhere it is read twice, with its control characters
left out and with each read as a space, as one reader of the name trims it and another splits it,
and either reading that names a secret counts: `{"ParameterKey":"DbPassword\n",…}`,
`{"OptionName":"\nDBPassword",…}`, `{"OptionName":"Db\nPassword",…}` and
`{"OptionName":"pa\nssword",…}` hide the value beside them. A short string of control characters
and white space alone (`"\n"`, `"\t"`, `"\u0000"`, `" \n "`) names a secret beside any member, as
what it stands for cannot be told. A name with a percent escape or a character
reference is read as written, with the `x` of `&#x` and the `u` of `%u` read as punctuation, and
with its escapes decoded, and any of these readings that names a secret counts: `%card` and
`&#xcvv` name `card` and `cvv` although decoding takes their first letters for hex digits,
`&#xpass` names `pass`, and `p&#97;ssword` names `password`, the `;` that ends a character
reference being part of the escape. In an object with such a name, the values of the
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
`role`, and `{"type":"image/png","data":…}` hides `data`. So does a short string of control
characters and white space alone: `{"title":"\n","data":…}` hides `data`. A short string with a
line break or a tab in it that names no secret either way is not such a name, so
`{"message":"Hello\nWorld","id":"7"}` and `{"stdout":"ok\n","exit_code":0,"duration_ms":12}` keep
every member. Names that are plain and not secret keep their values:

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
another type such as XML, or larger than ``SensitiveDataRedactor/maximumBodySize`` — is omitted.
The limit is 256 KiB by default, so that reading a body takes less than 16 MB, whatever its
shape; an app may raise it with `SensitiveDataRedactor(maximumBodySize:)`, at a cost of up to
about 40 bytes of memory for each byte of the body in the worst shapes, such as JSON arrays nested
63 levels deep. A part header name is a key of the part: the redactor writes it only when it is
one of the headers a part carries (`Content-Length`, `Content-Transfer-Encoding`, `Content-ID`,
`Content-Description`, `Content-Language`, `Content-Location`, `Content-Encoding`), and
`[redacted]` otherwise, so a card number or a token in a header name never shows. Only the values
of `Content-Length` and `Content-Transfer-Encoding` are written, by their shape, and they are not
read as free text, where a value that no rule finds would show: a length of one to twelve ASCII
digits as it is, and `7bit`, `8bit`, `binary`, `base64` or `quoted-printable` in lowercase. Any
other value is `[redacted]`, such as `Content-Length: 12 hunter2`, a card number written as a
length or `Content-Transfer-Encoding: hunter2`:

```swift
redactor.redact(body: Data(#"{"user":"bob","password":"hunter2"}"#.utf8), contentType: "application/json")
// {"user":"bob","password":"[redacted]"}
redactor.redact(body: Data("<password>hunter2</password>".utf8), contentType: "application/xml")
// [body omitted: 28 bytes, application/xml]
let part = "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\nX-4111111111111111: 1\r\n"
    + "Content-Length: 1\r\n\r\nx\r\n--B0und--"
redactor.redact(body: Data(part.utf8), contentType: "multipart/form-data; boundary=B0und")
// "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\n[redacted]: [redacted]\r\nContent-Length: 1\r\n\r\nx\r\n--B0und--"
let length = "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Length: 12 hunter2\r\n\r\nx\r\n--B0und--"
redactor.redact(body: Data(length.utf8), contentType: "multipart/form-data; boundary=B0und")
// "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Length: [redacted]\r\n\r\nx\r\n--B0und--"
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
The host is a key of the URL: it is written only when it is a name of ASCII letters, digits and
`-` in labels separated by `.`, an IPv4 address or an IPv6 address in brackets, and the value
detectors find nothing in it. Any other host — `password=hunter2` in `myapp://password=hunter2`,
`h.example;password=hunter2`, a card number or a run of 32 hex digits as a label, a host in
letters outside ASCII — is written as `[redacted]` after the scheme, with nothing after it. In
free text such a URL is not clean, so it cuts the text where it starts (see below). With
``SensitiveDataRedactor/Kinds/secretFields`` so is a host that names a secret, by the key rule or
as a word, since its value may be written in the host itself (`myapp://password.hunter2`,
`https://pin-4831.example.com`), in the port (`myapp://pin:4831`) or in the path after it: with a
scheme of the app's own `URLComponents` reads the first part after `//` as the host, so
`myapp://pin/4831` has the host `pin` and the path `/4831`, and is written as `myapp://[redacted]`.
A host such as `auth.example.com` names `auth` too and is hidden whole, which over-hides on
purpose; with ``SensitiveDataRedactor/URLDetail/hostOnly`` the host follows the same rule.
The user name, password and fragment are never written, whatever kinds the redactor looks for;
without ``SensitiveDataRedactor/Kinds/secretFields`` only the value detectors run on the path and
the query. With it, a query parameter keeps its value only when its name is plain ASCII and on
``SensitiveDataRedactor/allowedQueryParameters``, which is empty by default. A path segment
that looks like an identifier or a secret becomes `:id`, and so does the segment after one that
names a secret or is not a plain-ASCII name — ASCII letters and digits, `_`, `-`, `.` and spaces,
read by the same rule as a name held by a field — so `/şifre/…`, `/p%0Ain/…`, `/p%20in/…`,
`/@me/…` and `/a,b/…` hide the segment after them, and `:id` is not such a name. A URL whose path has more than ``SensitiveDataRedactor/maximumPathSegments`` (64)
segments, or whose query has more than ``SensitiveDataRedactor/maximumQueryParameters`` (128)
parameters, is recorded with its scheme, host and port only, and so is a URL whose path servers
resolve to other segments than it is written with: one with a dot segment (`/pin/./4831`,
`/token/x/../…`), a `;` anywhere in it (`/a;pin/4831`, `/cart;jsessionid=…`), or a `.`, `/`,
`\`, `;` or `%` written as an escape (`%2E`, `%2F`, `%5C`, `%3B`, `%25`, in either case), since
which segment follows a secret name would depend on the server. A Java servlet reads what follows
a `;` in a segment as parameters, while Express, Go, Rails, Django and ASP.NET Core keep it in the
segment, so the parameters after a `;` are not read at all:

```swift
redactor.redact(url: URL(string: "https://bob:pw@example.com/users/12345678/reset?code=x#y")!)
// https://example.com/users/:id/reset?code=[redacted]
redactor.redact(url: URL(string: "https://example.com/v1/cards/4242/pin/4831")!)
// https://example.com/v1/cards/:id/pin/:id
redactor.redact(url: URL(string: "https://example.com" + String(repeating: "/a", count: 65))!)
// https://example.com
redactor.redact(url: URL(string: "https://example.com/pin/./4831")!)
// https://example.com
redactor.redact(url: URL(string: "https://example.com/a;pin/4831")!)
// https://example.com
redactor.redact(url: URL(string: "https://h.example;password=hunter2/db")!)
// https://[redacted]
redactor.redact(url: URL(string: "myapp://pin/4831")!)
// myapp://[redacted]
redactor.redact(url: URL(string: "https://pin-4831.example.com/a")!)
// https://[redacted]
```

### Limits keep hostile input from exhausting the stack and the time

Strings are read as free text, and free text may hold JSON or a URL again, so a reader can find a
document inside a document many times over. A single budget bounds that descent, and with it the
stack and the time that a log line or body from an attacker can use:

- A body larger than ``SensitiveDataRedactor/maximumBodySize`` (256 KiB by default) is omitted
  unread.
- A text longer than 2^28 − 1 scalars (256 Mi) is hidden whole, unread: a log line passed to
  ``SensitiveDataRedactor/redact(_:)`` becomes `[redacted]` alone and is one match of
  ``SensitiveDataRedactor/matches(in:)``, a URL query value `[redacted]` and a path segment
  `:id`, with the segment after it. No offset of such a text is kept, so none can be cut short.
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
1,000 parts, URLs of many segments, a megabyte of Turkish sentences or of `ı` quoted in JSON up
to four times, quotes of every style, a quote before a megabyte of escaped ones, comparisons
written with `<`, and a megabyte of `eyJ ` or of line separators between digits and tokens, with
every kind and with the value detectors alone (an earlier reading of tokens across line
separators took 46.6 s for a megabyte of `eyJ `), timed by the CPU time of such a thread. The
default redactor and its folded keys are made once and shared, never per array element or path segment, each path segment is read in a single
pass, and each word is compared with each secret word in a single pass. Free text is read once and
keeps a fixed number of positions, the tree of each JSON in it is released before the next one is
read, no word longer than 256 characters is copied for reading and a quoted key is compared where
it is, never copied, so the tests also check that a
megabyte of text takes less than 16 MB more memory, and a body of 256 KiB less than 16 MB, in every
shape the reviews measured: a start tag of a megabyte of attributes followed by 17 secret names,
which an earlier design of 2.1.0 read into 583 MB, a megabyte word of backslashes or escapes, which
took 36 MB, a form of a megabyte, which took 67 MB, and a megabyte of log lines of short JSON
(`{"count":1}`), whose trees `JSONSerialization` kept until the redaction ended, 19 MB, and a
quoted key of a megabyte inside another, which an earlier reading of quoted keys copied into
26 MB, and a megabyte dense with findings, up to 18.55 MiB: log lines of short email addresses with
one `ﬁ` each, ``SensitiveDataRedactor/matches(in:)`` on them, and addresses after a zero-width
space that hid them all. The scanning copy now keeps the offset of each byte's scalar as runs,
one where a scalar is read as several bytes or left out, not one for each byte; the value
detectors look for findings only before the cut and count them before they keep them, in an
array of exactly that size; a finding takes 24 bytes; findings are put in order in place; and
`matches(in:)` finds the index of each start and end in one walk, without an index for each
scalar. The densest findings the detectors have — a user info password every four bytes
(`1:2@`) — take less than 13 MiB for a megabyte. A body of 256 KiB of arrays 63 deep, a JSON value
for nearly every two bytes, took 15.65 MiB; the JSON reader now keeps each value in 16 bytes,
without a box of its own, and a JSON body goes to `JSONSerialization` as it came, not encoded
again, so it takes less than 10 MiB, and the tests hold it to 12 MiB. A megabyte in which nearly
every character is a different one outside ASCII — every scalar from U+30000 on, each with a space
after it, or every scalar from U+0080 on — took up to 17.39 MiB, and 4 MB took 68.15 MiB: the
reading of each character was cached, one for every character, each with an array of its own,
and the scanning copy read the whole text, also past a control character that cut it at its
start. The readings are now cached in a table whose size is fixed when it is made, about one
slot for each scalar of the text, body or URL it serves, from 16 to 8,192 slots of 24 bytes, and
the scanning copy ends after the line of the first character outside the safe alphabet and the
next line that is not blank, as far as the scan and the value detectors read; such a megabyte
takes about 2 MiB, and the tests hold 4 MB to four times the limit of one. The table never grows:
one that doubled whenever two characters met in a slot let seven characters that meet in every
size (`丆幛丆幛丆幛丆`, `ÂۿÂۿÂۿÂ`) take each new table to 4,096 slots, so a megabyte of short log
lines of them took 1.77 s and a form of such fields 0.94 s. The slots are in sets of two, a
character's set is chosen with Swift's `Hasher`, seeded at random in every process, so no text
can choose characters that meet, ideographs and Hangul syllables are read without Foundation, and
one table serves a whole body or URL with every field, part and segment in it; the tests time
these shapes too. Memory is measured until the
thread that redacts has ended, so what it releases only then counts too.

### Free text is cut at its first trigger

A log line has no grammar, so reading it name by name can always be bypassed, and rules that carry
what a value is from one line to the next only multiply the cases. Free text is therefore read by
one rule: **in free text, the first secret name hides everything after it in that text; this
over-hides on purpose.** Over-hiding is by design. Not only a secret name is such a trigger:
everything that the redactor cannot read with certainty is one too, and the text is cut there, to
its end — every line after it, not only the rest of its line. A text without a trigger is written
as it is, apart from the card numbers, IBANs, email addresses and tokens in it.

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

Six rules set the triggers. None of them keeps a list of variants, which earlier designs of 2.1.0
kept and reviews got past one variant at a time:

- **A safe alphabet.** The text is read only as far as it is written in letters, marks and digits
  of any script (the Unicode categories L, M and N), the ASCII space, tab, line feed and carriage
  return, and printable ASCII. The first character outside it cuts the text there: punctuation, a
  symbol or a space outside ASCII — a look-alike separator (`꞉`, `≔`, `→`, `·`, `∶`, `＝`), a dash
  (`—`), a currency sign (`€`), East Asian punctuation (`、`), an emoji, a non-breaking space,
  U+2028 — a control character (`DEL`, a vertical tab, U+0085), a format character such as a
  zero-width space, and every default-ignorable code point (U+3164). A character is judged by its
  Unicode category and by its compatibility form, which is what the text is read as: a letter or
  number whose compatibility form holds punctuation, a space, a symbol or a modifier letter (`🄁`
  is `0,`, `⒈` is `1.`, `⑴` is `(1)`, `½` is `1⁄2`, `ŉ` is `ʼn`) cuts the text too, so nothing
  next to it is read as a key that the text does not hold (`🄁status=…`). A modifier letter
  (`ː`, `ー`) is in the alphabet only after a letter or digit outside ASCII, as in Japanese or Thai
  text; after ASCII it can stand for a colon.
- **Escapes.** No escape is decoded in free text. One that can stand for any character cuts the
  text at the start of the word it is in: `%3D` and `%u003D`, `&#61;` and `&#x3D;`, a named
  reference such as `&colon;`, `&equals;` or `&amp;`, and `&` before a letter unless it starts the
  name of a field before `=` (`&count=3`). In free text every backslash escape cuts the text: a
  backslash cuts it at the start of its word whatever follows it, unless an ASCII space, tab or
  line break or the end of the text does, so no list of the forms of backslash escapes is kept —
  `\075`, `\3d`, `\x3D`, `\x{73}`, `\o{163}`, `\u{3D}`, `\N{…}`, `\q` and `\"` all cut it
  (`login pa\x{73}sword hunter2` keeps `login `). An earlier design of 2.1.0 listed the forms, and
  a review got past the list with the braced escapes of C++23, Perl and PCRE (`\x{73}`,
  `\o{163}`). A Windows path or a regular expression in free text is hidden from the word of its
  first backslash on (`copied to \\nas\backup` keeps `copied to `); over-hiding is by design. The
  value detectors cannot read through an escape either, so the word goes whole
  (`alice%40example.com`).
- **Opaque words.** A word longer than 256 characters cannot be read as a name: it cuts the text
  where it starts. No word is copied for reading at more than that length.
- **The key rule, in every shape.** In `key=value`, `key: value`, `key = value` and
  `"key":"value"` the text is read on only after a key that is plain ASCII, without a space, and
  on ``SensitiveDataRedactor/allowedTextKeys``. The default list holds keys that logs use for a
  response status, a request method and route, a duration and a count (`status`, `method`, `path`,
  `duration_ms`, `count`); pass your own to the initializer. A key that names a secret or is not
  plain ASCII is never allowed. Any other key cuts the text at its value — `x=hunter2` as well as
  `Error: …` — and so does a separator with no key before it, or a key on the line before its
  separator. The separators are `=` and `:` and runs of them (`:=`, `==`, `=>`); a `:` between two
  digits is part of a number only when both sides have the whole shape of one — a time, a date and
  time, an address and its port or a line and column (`12:30:45`, `2026-10-19T12:30:45.123+03:00`,
  `10.0.0.1:8080`, `42:10`): one to four digits after it (five after an address), then more groups
  after `:`, a fraction after `.`, `Z` or an offset, and then the end of the word. A letter after
  the digits (`7:9hunter2`, `12:3hunter2`), five or more digits right after the `:` (`1:482913`)
  and a key that ends in digits (`user1:2345`) make it a separator, which cuts the text at the
  value. A key in quotes of any kind (`"…":`, `'…'=`, or
  in backticks) that is not allowed cuts the text at its opening quote, so nothing written in the
  quotes shows: `cache miss for "session Qz9Wk7rX": refetching` keeps `cache miss for `,
  `"password hint": 1` keeps nothing, and `{'status': 200, 'last status': 'x'}` keeps
  `{'status': 200, `. A `'` opens a quote only at the start of a word, so `don't` holds none.
  A quote glued to the word before it starts no quoted key: that word is part of the key, which
  is then not plain, so the text is cut where the word starts (`x"status": 200` and
  `🄁"status": 200` keep nothing).
  JSON in the text is parsed and its members follow the same rule, a member name that is not
  allowed cutting the text at its opening quote (`{"password hunter2": 1}` keeps `{`), as does the
  first string of a two-element array, as fetch headers and `URLSearchParams` entries write a pair
  (`[["X-User","bob"]]` cuts at `"X-User"`). JSON that does not parse, or is longer than 64 Ki
  scalars, cuts the text at its first bracket.
- **Markup.** In free text the first markup tag cuts the text. Markup is never parsed, and the
  rule names what a comparison is, not what a tag starts with: a `<` is a comparison only before
  an ASCII space, tab or line break, an ASCII digit, `=` or the end of the text (`a < b`, `1<2`,
  `<3`). Before anything else it cuts the text there, whatever the tag and whatever comes between
  it and the text — a letter of any script, `_`, `:`, `/`, `!`, `?`, other punctuation or a digit
  outside ASCII: `<user>`, `<_id>`, `</a>`, `<br/>`, `<!-- … -->`, `<![CDATA[…]]>`, `<?xml …?>`,
  `<०>`, `x << 1` — so `login <user>bob</user>` keeps `login `, and no tag is allowed, whatever
  keys the app allows. An earlier design of 2.1.0 read a tag as a key and cut at the text of its
  element; reviews got the text past it behind a quote opened before the tag and behind other
  markup between the tag and the text, and then past a list of the characters that start a tag,
  which left out `_` and digits outside ASCII (`<_id>…</_id>`).
- **Secret names.** A word that holds a secret name cuts the text after the name, with or without
  a separator: `password hunter2`, `PIN 1234`. Punctuation inside a word and a space, `|`, `,`,
  `;`, `&` or `?` between two words are read as a separator (`pass~word`, `pass word`, `p|wd`). A
  word is compared by its ASCII skeleton, the one reading every path uses: once the text is read
  in compatibility form (`ｐａｓｓ`, `pässword`), every letter still without an ASCII form (`ꞏ`,
  `ı`, `ɑ`, `ø`) is left out, and what remains is compared with the secret names, a plural `s`
  included. That is the one wildcard rule: a letter, mark or number outside ASCII that has no
  ASCII form — `ꞏ`, `ı`, `ɑ`, `ø`, a combining mark such as `ͦ` (U+0366), `〇`, a decimal digit
  of another script such as the Myanmar `၀` or the Devanagari `०` — counts as nothing or as any
  one letter. Such a digit is still its digit in a number and to the value detectors
  (`४२४२ ४२४२ ४२४२ ४२४२` is a card number); only a word reads it as the wildcard. A digit that
  has an ASCII form (`０`, `𝟎`, `⁰`) is that digit, so `passw０rd` reads as `passw0rd`. As
  nothing, however many such characters are put in, the name is found: `piꞏn`, `tokeın`,
  `tokenꞏs` and `keyıs` read as `pin`, `token`, `tokens` and `keys`. As a letter, a name counts with one of its letters missing where such a character stands, so one put
  in place of a letter of the name is found too (`pɑssword`, `user_pın`, `tͦken`, `ͦtp`,
  `passw〇rd`, `t၀ken`, `passw०rd`). A word of another language that reads as a name this way
  hides what follows it — Turkish `yapın` reads as `pin` — which over-hides on purpose. A name
  with two or more of its letters replaced is not read this way (see "What it does not find"). A name
  written as a value is read too: `name=`, `key=`, `label=` and
  the other keys that hold a name are not allowed by default, so they cut the text at once
  (`name="password"`, `Content-Disposition: form-data; name="pin"`).
  When the app allows such a key (`id`, `type`, … but not `path`, the route of a request), a
  secret name after it, or one that is not plain ASCII, cuts the text after the name, as in JSON
  (`type="Пароль"`), and so does JSON there.

A word that mixes scripts (`pаssword` with a Cyrillic `а`) cuts the text where it starts. A quote —
`"`, a backtick, or `'` at the start of a word, so not the apostrophe of `don't` — that does not
close on its line, or before the first character outside the safe alphabet, cuts the text at the
quote: what it holds cannot be told, and a quoted key with a line break in it shows nothing
(`"note\nQx31": 1` keeps nothing). A quote closes only at the next quote of its kind written the
same way, escaped (`\"`) or not. A bracket that does not close before the text ends cuts it after
the bracket: where its value ends cannot be told. Quotes and brackets are read in a pass of their
own, by position alone: no quote or tag is open while the text is read.

**URLs.** A URL in free text is shown only when it is clean — `scheme://host` and an optional
path of ASCII letters, digits, `.`, `_`, `-` and `/` (no `?`, `#`, `;`, `%`, `=`, `:`, `@` or
`\`), whose host and segments name no secret, followed by white space, a line break, the end of
the text or one `.`, `,`, `!` or `)` before one of those — and any other URL cuts the text where it
starts; ``SensitiveDataRedactor/allowedQueryParameters`` applies only to
``SensitiveDataRedactor/redact(url:)``. A quote, a backtick, `>`, `]`, `}`, a second mark (`).`)
or a `?`, `#`, `;` or `:` after a URL leaves open where it ends, as a URL parser reads
`https://x.example/a'#token` on past the `'`, so such a URL is not clean:
`see https://x.example/a'#token` keeps `see `, as `redact(url:)` hides the fragment of the same
URL. A clean URL is written as `redact(url:)` writes it, so an identifier in its path becomes
`:id`, its last segment is read with the next word (`https://x.example/to ken hunter2` keeps
`https://x.example/to ken `), and one longer than 256 characters cuts the text like any long
word. Without a scheme, `?`, `;` and `&` are separators between words and the key rule reads
the names after them.

```swift
redactor.redact("user꞉ hunter2")                         // "user[redacted]"
redactor.redact("status=200 note→ hunter2")              // "status=200 note[redacted]"
redactor.redact("user&colon;hunter2")                    // "[redacted]"
redactor.redact("contact alice%40example.com")           // "contact [redacted]"
redactor.redact(#"log [["X-User","bob"]]"#)              // "log [[[redacted]"
redactor.redact(#"cache miss for "session Qz9Wk7rX": refetching"#)
// "cache miss for [redacted]"
redactor.redact("<user>bob</user>")                      // "[redacted]"
redactor.redact("note \"a\nhunter2\": 1")                 // "note [redacted]"
redactor.redact("if a < b then")                         // "if a < b then"
redactor.redact("password hunter2")                      // "password [redacted]"
redactor.redact("p\u{0430}ssword=hunter2")               // "pаssword=[redacted]"
redactor.redact("login pa\u{115F}ssword hunter2")        // "login [redacted]"
redactor.redact("password: 'abc\n  hunter2'")            // "password: [redacted]"
redactor.redact("| password | hunter2 |")                // "| password [redacted]"
redactor.redact("field name=\"password\" hunter2")       // "field name=[redacted]"
redactor.redact(#"<string name="api_key">k-1</string>"#) // "[redacted]"
redactor.redact("<key>password</key>\n<string>k-1</string>")
// "[redacted]"
redactor.redact("upload ok status=200\n--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\n4831\r\n--B--")
// "upload ok status=200\n--B\r\nContent-Disposition: [redacted]"
redactor.redact(#"{"status":200,"user":"bob"} done"#)   // "{\"status\":200,[redacted]"
redactor.redact("git clone https://bob:hunter2@github.com/x/y.git") // "git clone [redacted]"
redactor.redact("connect myapp://password=hunter2 ok")   // "connect [redacted]"
redactor.redact("see https://x.example/a?token= hunter2") // "see [redacted]"
redactor.redact("GET https://api.example.com/items 200") // "GET https://api.example.com/items 200"
redactor.redact("GET https://api.example.com/users/12345678 200")
// "GET https://api.example.com/users/:id 200"
redactor.redact("user1:2345678 at 12:30")                 // "user1:[redacted]"
redactor.redact("at 12:30 id 7:9hunter2")                 // "at 12:30 id 7:[redacted]"
redactor.redact("login t\u{0366}ken hunter2")            // "login tͦken [redacted]"
redactor.redact("paid with 4111 1111 1111\u{2028}1111")  // "paid with [redacted]"
```

The scan reads the text once, left to right, and stops at the first trigger. It keeps two
positions — the cut and the key before the next separator — however many keys or names the text
holds, and the pass that reads quotes and brackets keeps two more, so nothing is carried from line
to line. The line breaks of the input are
written as they are.

The name of an email address may be written in any script: it runs over letters, marks and
digits (`ayşe.yılmaz@gmail.com`, `bjørn.dæhlie@example.no`, `张伟@example.cn`), and the domain may
be an internationalized one (`王小明@例子.中国`). Only the first letter of the name is written, never
the rest: `a•••@gmail.com`, `•••@example.cn` for a name of two letters.

Card numbers, IBANs, email addresses and tokens are found after Unicode compatibility
decomposition without marks, format characters, default-ignorable code points and control
characters, so full-width digits, zero-width characters, fillers and Unicode spaces do not hide
them. They are found the same way on every path — free text, a body, a JSON string or name, a
form, a multipart part, a URL and its host — and at least wherever 2.0.0 found them: only a letter
or digit written in ASCII glues digits or a token to a word (`id4242…`, `xeyJ…`), while a letter
written another way (`é`, `𝐚`) does not. A finding that runs over the point where free text is
cut, such as a card number grouped with non-breaking spaces, is hidden whole with the rest of the
text. So is one written across a vertical tab, a form feed, U+0085, U+2028 or U+2029: each of them
cuts free text, and the detectors read across them — as the white space between the groups of a
card number or an IBAN and after `Bearer`, and as nothing inside an address, its domain, a token
and the token after `Bearer` — so the text is hidden from the start of the finding (`paid with
4111 1111 1111` and a vertical tab before `1111` keeps `paid with `), as it is across a control
character that the scanning copy leaves out. The two readings are each written once, and no
detector tests for a line separator itself: read as nothing, the groups of two card numbers on
either side of one would run together and neither would be found; read as white space, one would
end an address, whose name the cut would then show. The detectors alone, without
``SensitiveDataRedactor/Kinds/secretFields``, read across them the same way. A line feed
or carriage return written as such is a line break of the log and ends a finding. An address
after `:` shows no letter of its name, which may be the password of
`user:password@host` (`user:•••@example.com`), a token whose last dot was cut off (`eyJ….eyJ…`) is
still a token, and a finding that runs over the end of a clean URL in a line, as a card number
that starts in its path or a token whose dot ends the sentence, is hidden whole. Scanning and replacing take time
linear in the length of the text, without regular expressions, and a key is compared in time
linear in its length.

### What it does not find

It cannot find a secret that has no label or a label it does not know, such as a word in another
language, or a value encoded as a whole that is shorter than 32 characters. In free text, when no
trigger comes before it and no `=` or `:` follows a name, it does not read a name written wholly in
another script that only looks Latin (Greek `ΡΙΝ`), one with two or more of its letters replaced
by letters of the safe alphabet that have no ASCII form (`pɑsswoʀd hunter2` shows `hunter2`) or
written in them throughout (small capitals), one written with a space between its letters
(`p a s s w o r d`), one spelled with digits and symbols
(`p@ssword`, `passw0rd`), a value written before its name or glued to a flag (`-pSECRET`), a value
after a flag or a name that is not on the list without a separator (`--user SECRET`), a name in
another script as an element of an array of more than two (`["Şifre","…","…"]`), and a name and
value in two different JSON objects or arrays. In structured input it shows a secret written into
a key name, since structured key names are shown (`{"password hunter2":…}` in a JSON body hides
the value and shows the name). It does not find card numbers grouped with dots,
underscores or `+`, split by a line break of the log (a line feed or carriage return), glued to
ASCII letters or written as a JSON floating-point number, an IBAN
written in lowercase, or a token split by `/` or `-` into pieces shorter than 32 characters. The value of
an allowed key is shown, also when it is repeated (`status==…`). A URL host that names no secret
is shown, so a secret written as a label of such a host (`https://hunter2.example.com/a`) shows,
and so does a short value in a path that looks ordinary (`/reset/abc123`).

Where it cannot tell, it hides more than it has to, on purpose: over-hiding is by design. It hides
everything after the first key that is not allowed (`Error: connection refused` hides
`connection refused` and every line after it), after the first secret name, word it cannot read or
quote that does not close on its line, after the first character outside the safe alphabet — an
emoji, a dash, a currency sign or East Asian punctuation in a sentence (`Merhaba dünya 👋 bye`
keeps only `Merhaba dünya `) — a whole word with an escape in it, a backslash before anything
but white space among them (`pattern ^\d+$ matched` keeps `pattern `), a word longer than 256
characters, everything from the first markup tag on, whatever the tag (`Optional<String>(x)` keeps
`Optional`, and an email address written as `<bob@example.com>` goes whole), everything from a
`<` that no ASCII space, tab, line break, digit or `=` follows (`x << 1` keeps `x `), a whole JSON string
after a trigger in JSON written into it, everything from a URL that is not clean on — one with a
query, a port, user info or a host in letters outside ASCII (`see https://x.example/a?q=1 ok`
keeps `see `), or one that a quote, a second mark or a `?` follows (`see "https://x.example/a" ok`
keeps `see "`) — a multipart body written into text from its first header and a property list or
any other markup from its first tag.

With `os.Logger`, interpolated values are already private in release logs unless you mark them
`.public`; use the redactor for the values you do mark public, and for logs sent to your own
servers.

### Known limitations

These are known and not changed yet:

- A name with a control character in it hides the members beside it whatever it says when a
  member that holds a name or the first element of a pair holds it
  (`{"name":"Hello\nWorld","value":"x"}` hides `value`), and elsewhere when it names a secret
  once its control characters are left out or read as spaces (`{"note":"pass\nword","id":"7"}`
  hides `id`).
- A key counts `token` and `secret` only as a word or at its end and `pw` only as a word, so
  `{"tokenvalue":…}`, `{"TOKENID":…}`, `{"secretvalue":…}`, `{"secrethash":…}`, `{"userpw":…}`
  and `{"dbpw":…}` show their values; mark such properties with ``Redacted``.
- A short string of control characters and white space alone hides every member beside it, also
  where it means nothing (`{"title":"\n","data":"x"}` hides `data`), while one of more than 256
  scalars is read as text and hides nothing beside it.

### Cover the screen

Add ``SwiftUICore/View/privacyShield(when:)`` to views with sensitive content. It covers the view
while the app is in the app switcher and, on iOS, tvOS and visionOS, while the screen is recorded,
mirrored or shared. iOS reports screenshots only after they are taken;
``SwiftUICore/View/onScreenshot(perform:)`` lets you react to them.
