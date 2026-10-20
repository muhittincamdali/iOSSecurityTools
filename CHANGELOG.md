# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - Unreleased

### Added

- `SensitiveDataRedactor.redact(body:contentType:)` redacts request and response bodies with a
  parser chosen by the content type: JSON, `application/x-www-form-urlencoded` forms, multipart
  form data (each part by its own type) and plain text. A body that is not UTF-8, has another
  type, is larger than `maximumBodySize`, does not parse completely or could be split into
  fields differently by a common server parser is omitted as `[body omitted: N bytes, <type>]`;
  uploaded files are omitted the same way. The limit is 256 KiB (`defaultMaximumBodySize`)
  unless the app passes another to `SensitiveDataRedactor(maximumBodySize:)`; a body of 256 KiB
  takes less than 16 MB of memory in every shape tested, and the worst shapes take up to about
  60 bytes for each byte, so a limit of 1 MiB can take 64 MB. A multipart part header name is
  written only when it is one of the headers a part carries (`Content-Length`,
  `Content-Transfer-Encoding`, `Content-ID`, `Content-Description`, `Content-Language`,
  `Content-Location`, `Content-Encoding`); any other is `[redacted]` with its value.
- `SensitiveDataRedactor.redact(url:)` writes a URL read with `URLComponents` without its user
  name, password and fragment, whatever `kinds` holds. The host is written only when it is a name
  of ASCII letters, digits and `-` in labels, an IPv4 address or an IPv6 address in brackets, and
  the value detectors find nothing in it; any other host (`myapp://password=hunter2`,
  `https://h.example;password=hunter2/db`, a card number or 32 hex digits as a label) is written
  as `scheme://[redacted]`, in a URL, in a line and in a JSON string alike. With `.secretFields` a query value is
  kept only for the names on `allowedQueryParameters`, which is empty by default, and a path
  segment that looks like an identifier or a secret, and the segment after one that names a
  secret (`/pin/4831`), become `:id` (`identifierPlaceholder`); without it only the value
  detectors run on the path and the query. A query that servers could split into fields
  differently is written as `?[redacted]`, and a URL that `URLComponents` cannot parse as
  `unparsedURL`. With `URLDetail.hostOnly` (the `urlDetail` argument of the initializer) only the
  scheme, host and port are written.
- `SensitiveDataRedactor.maximumPathSegments` (64) and `.maximumQueryParameters` (128): a URL
  with more path segments, or more query or path parameters, is recorded with its scheme, host
  and port only, which bounds the work one URL can ask for.
- `allowedTextKeys` and `defaultAllowedTextKeys` (`status`, `method`, `path`, `duration_ms`,
  `count`): the keys after which free text is read on.
- `SensitiveDataRedactor.Kinds.ibans` and `.longTokens`, both in `.all`: IBANs that pass the
  mod-97 check, shown as `•••• 3000`, and runs of 32 or more hexadecimal digits or base64 letters
  and digits, shown as `[redacted]`.

### Changed

- Keys of structured input (JSON names, form and multipart field names, query names) are compared
  with the secret names only when they are plain ASCII (`A`–`Z`, `a`–`z`, `0`–`9`, `_`, `-`, `.`
  and spaces, with the separators folded away). Every other key has its value hidden by default:
  letters outside ASCII, mixed scripts, marks, format characters, brackets, escapes or other
  punctuation. A hidden value is hidden whole: a string, a number, and an array or object with
  everything in it. A plain key that holds a secret word as a word hides its value even when it
  only describes the secret (`passwordHint`, `token_type`, `pin_length`), and `pw` is a secret
  word.
- A text that is a JSON object or array is read with a JSON parser checked against
  `JSONSerialization`: keys are compared after their escapes are decoded, at every depth, inside
  arrays and for every repetition of a key, and the output stays valid JSON.
- Name and value pairs follow the key rule in every shape, and names are classified by default too:
  non-ASCII names count as secret even when they are written as values. The value of a field that
  holds a name (`name`, `key`, `field`, `label`, `type`, `header`, `param`, `path`, `id`, `k`, `n`,
  or a field whose own name is not plain ASCII), the first element of a two-element array and a
  quoted value after `name=`, `key=`, `label=` and the like in free text are read by the key rule:
  anything but a plain-ASCII name without a secret word — `Şifre`, `ⓟⓘⓝ`, `🄿🄸🄽`, `🔑`, `Password:`,
  an empty name, an array or object — names a secret. In an object with such a name, the values of
  the other members are hidden whole, apart from the names of pairs and a JSON Patch or SCIM `op`;
  `{"label":"Şifre","value":…}` hides the value on purpose. Of a `path` every part between `/`
  counts, as JSON Patch (RFC 6902) and SCIM PatchOp (RFC 7644) write it: `/user/password` and
  `/apiKeys/0` hide the value, `/status` and `/tags/-` keep it. The second element of a two-element
  array whose first is such a name is hidden whole (`[["Authorization","…"]]`, fetch headers,
  `URLSearchParams` entries). One function makes this decision for JSON in a body, in a line, in a
  JSON string, in a form value, in a URL query and in a multipart part, for two-element arrays, for
  form fields, URL query parameters and multipart parts (`label=Password&value=…`), and for quoted
  values and markup in free text. A multipart part that holds a name and cannot be read as plain
  UTF-8 text (base64 or another transfer encoding, JSON, another charset, a file) names a secret.
- Email addresses are found with a name in any script, over letters, marks and digits
  (`ayşe.yılmaz@…`, `bjørn.dæhlie@…`, `张伟@…`), and with an internationalized domain
  (`王小明@例子.中国`); only the first letter of the name is written.
- Redaction reads input within fixed limits, which bound the stack that hostile input can use:
  JSON objects and arrays may be open 64 levels deep in all, counting the levels of every
  document a JSON string is in, and at most four documents (a JSON text, a URL, a body, a
  multipart part) are read one inside another. A JSON body deeper than that is omitted, and a
  string or other text inside a document that holds such JSON, or a URL one level too many, is
  hidden whole; a body larger than the body limit is still omitted unread. Tests redact JSON quoted inside
  JSON strings, URLs in query values and runs of brackets on a thread with 512 KiB of stack in
  debug and release builds, and check with `swift test -c release` that a megabyte of text,
  nested input or a body takes less than a second, also for ordinary shapes timed by the CPU time
  of such a thread: JSON arrays of short or empty strings, a multipart body of 1,000 parts, URLs
  of many segments, and a megabyte of Turkish sentences or of `ı` quoted in JSON up to four
  times. The default redactor and its folded keys are made once and shared, a short plain word
  is not scanned, a URL path segment is read in a single pass, and a word is compared with each
  secret word in a single pass. JSON in free text is parsed up to 64 Ki scalars, and longer JSON
  cuts the text at its first bracket; a test run in a process of its own checks that a megabyte of
  free text takes less than 16 MB more memory, and a body of 256 KiB less than 16 MB, in every
  shape the reviews measured.
- A reading budget bounds the time one redaction takes: the documents found inside an input
  (JSON in a line or a string, a URL in text, a multipart part) and the texts read inside them
  read at most four times the input's length in all. The input itself is read freely; a text past
  the budget is hidden whole and a multipart part is omitted. A long text quoted in JSON three
  times in a body, or twice in a log line, has its innermost string hidden, and a chain of URLs
  each in the query of the one before is read two levels deep.
- Free text is cut once: in free text, the first secret name hides everything after it in that
  text; this over-hides on purpose. Over-hiding is by design. Five rules set the triggers, and
  none keeps a list of variants:
  - **A safe alphabet.** Free text is read only as far as it is written in letters, marks and
    digits of any script (L, M, N), the ASCII space, tab, line feed and carriage return, and
    printable ASCII. The first character outside it cuts the text: punctuation, a symbol or a
    space outside ASCII (`꞉`, `≔`, `→`, `·`, `＝`, `—`, `€`, `、`, an emoji, U+00A0, U+2028), a
    control or format character and every default-ignorable code point. A modifier letter
    (`ː`, `ー`) counts as a letter only after a letter or digit outside ASCII.
  - **Escapes.** No escape is decoded in free text: `%XX`, `%uXXXX`, `&#…;`, a named HTML
    reference (`&colon;`, `&equals;`, `&amp;`, and `&` before a letter unless it starts the name
    of a field before `=`), octal and CSS escapes (`\075`, `\3d`), `\xNN`, `\uNNNN`, `\u{…}`,
    `\U…` and `\N{…}` cut the text at the start of the word they are in.
  - **Opaque words.** A word longer than 256 characters cuts the text where it starts, so no
    word is copied for reading at more than that length.
  - **The key rule in every shape.** A key that is not on `allowedTextKeys` cuts the text at its
    value: in `key=value` and `key: value` (also `x=hunter2` and `Error: …`, a separator without
    a key and a key on the line before its separator), as a member of JSON in the text, as the
    first string of a two-element array (`["user","…"]`, `[["X-User","…"]]`) and as the tag of an
    element, whose text is cut (`<user>…</user>`).
  - **Secret names**, with or without a separator, split by punctuation or a space or spelled with
    one letter that has no ASCII form, and names written as values (`name="password"`,
    `<string name="api_key">`, `Content-Disposition: form-data; name="pin"`).
  A word that mixes scripts, a quote or bracket left open and JSON that does not parse cut the text
  too. Everything after the first trigger is hidden, to the end of the text and not only of its
  line; a log message, a text/plain body, a JSON string, a form value, an allowed query value and
  a multipart text part each count as one text. A text without a trigger is written as it is,
  apart from the value detectors. Nothing is carried from line to line and no line is read twice:
  the scan keeps a fixed number of positions and stops at the trigger. Free text is a best
  effort, as the threat model in the README and the logging guide now says: a name written
  without a separator in letters of the safe alphabet and disguised with two or more letters that
  have no ASCII form (`pɑsswoʀd hunter2`) is not guaranteed to be found when nothing before it
  cuts the text, and no table of look-alikes is kept to chase it.
- A secret name written as a value names what follows it. In free text it is a trigger; in a JSON
  object, a member whose value is such a name hides the values of the other members, apart from
  the members that hold names and a JSON Patch or SCIM `op`. A name that is not secret
  (`{"label":"Status",…}`) keeps what follows it.
- The JSON Web Token detector also finds a header and payload whose last dot was cut off
  (`eyJ….eyJ…`), as a URL at the end of a sentence loses it to the full stop.
- Default-ignorable code points (such as U+115F and U+3164) and control characters are left out
  of the scanning copy, like format characters, so they no longer split a secret name, a card
  number, an IBAN, a token or an email address.
- Bodies and URL queries are read only when the common server parsers (PHP, Werkzeug, Rack, Go,
  busboy) split them into the same fields. A multipart body needs a content type with one
  unquoted `boundary` of at most 70 characters, and every `--boundary` in it, in any case, has
  to be a delimiter line of its own after a CRLF. A form has to be printable ASCII without `;`,
  with every `%` the start of an escape and no name spelled two ways (`a.b` and `a_b`,
  `pass%77ord` and `password`, `Note` and `note`). Any other body is omitted, and such a query
  is written as `?[redacted]`.
- An invisible character right before a key or a word of free text belongs to it:
  `\u{200D}status=…` is no longer read as the allowed key `status`, and `\u{202E}drowssap`, which
  cannot be read, cuts the text there.
- CI uses the shared workflows of muhittincamdali/.github v1.1.0.

### Removed

- The table of look-alike letters from other scripts. It could never be complete; keys that
  are not plain ASCII are hidden instead of being read as Latin.

### Fixed

- The inputs that got a secret past the earlier designs of this release are hidden, apart from
  the limitations the logging guide names: the 51 inputs of the second review, the 386 probes of
  the adversarial set (one of them a limitation) and the 453 probes of the review of the redesign
  (30 of them limitations). Among them are look-alike letters, styled letters, escapes,
  separators inside a name, arrays and objects under a secret name, values that run over lines in
  single quotes and backticks, fillers and control characters inside labels and card numbers, and
  URL path segments after a secret label. They are kept as tests, together with property tests
  that generate disguised secret names and random keys that are not allowed and check that no
  value shows, and tests that allowed keys and plain names keep their value.
- Text after a secret name written as a value was shown: `<string name="api_key">…</string>`
  became `<string name="[redacted]">…</string>` with the key still in it, and so did
  `<entry key="db.password">…`, `<field id="pin">…`, `<param name="token" value="x">…`,
  `<string name="password" />…`, `field name="password" …`, `name='token' …`, `id: "pin" …`,
  `header="Authorization" …`, `label="password", …` and `note="password"` with the secret on the
  next line, also in text/plain bodies and inside JSON strings. These inputs of the ninth review
  are kept as tests, with Android `strings.xml`, Java Properties XML, property lists, HTML forms
  and Spring and .NET configuration, and a property test writes generated disguised names as
  values in free text, XML, property lists and JSON objects.
- A JSON object that names a field in one member and holds its value in another, under names
  outside the pair list, showed the value: `{"label":"Password","value":…}`,
  `{"type":"password","input":…}`, `{"variable":"API_KEY","value":…}`,
  `{"ParameterKey":"DbPassword","ParameterValue":…}` and `{"key":"pin","text":…}`.
- A name written only in circled or squared letters (`ⓟⓘⓝ`, `🄿🄸🄽`, `ⒶⓅⒾ ⓀⒺⓎ`) as the value of a
  JSON member did not hide the other members, on any path a JSON object takes: a JSON body, a
  text/plain body, a log line, a JSON string, a form value, an allowed URL query and a multipart
  part. Such a string had no letter or digit by its Unicode category, so it was not read as a
  name; a symbol whose compatibility form is a letter or digit counts as one now. The 353 probes
  of the tenth review are kept as tests (7 of them documented limitations), with a property test
  that writes generated names in symbols, emoji, styled letters and other scripts beside a value
  on every path, and one that plain names keep their values. The review's other findings are
  fixed with them: `{"label":"Пароль","value":…}`, `label="パスワード" …`, `name=["pin"] …`,
  `{"label":{"en":"Password"},…}`, `label=Password&value=…` in a form, the next line after
  `<string name="password" />` and after an empty element that follows `<key>password</key>`, and
  `passꞏword …`, a letter without an ASCII form put between two letters of a name.
- The value detectors found less than 2.0.0 in two cases: a card number, JSON Web Token, bearer
  token or IBAN right after a letter written outside ASCII (`é4242…`, `𝐚eyJ…`), which the scanning
  copy reads as an ASCII letter that glues the value to a word, and an email address after `:`
  (`mailto:alice@example.com`) when the kinds did not include `.secretFields`. Only letters and
  digits written in ASCII glue now, and an address after `:` is masked without any letter of its
  name, which may be the password of `user:password@host` (`user:•••@example.com`). A test runs
  2.0.0's detector tests unchanged with 2.0.0's kinds, and every 2.0.0 sample between 38 texts
  before it and 24 after it that do not glue it to a word, with its own kind and with every kind.
- A finding that ran over the end of a URL in a line was shown in part: the URL ends before the
  dot that ends a sentence, so `?q=eyJ….eyJ….` lost the last dot of an unsigned token, and a card
  number that starts in a query and goes on after the URL kept its last groups. A finding of the
  value detectors that crosses the edge of a URL or JSON in a line is now hidden whole. A
  differential test runs every detector on fourteen paths: free text, an allowed key, a
  text/plain body, a JSON string, name and array element, JSON in a line, a form value and name,
  a multipart part, a query value, a path segment and a URL in a line, also before a full stop.
- An email address whose name holds a letter without an ASCII form kept the name up to that
  letter: `{"email":"ayşe.yılmaz@gmail.com"}` gave `ayşe.yıl•••@gmail.com`,
  `ılgın.öztürk@firma.com.tr` kept `ılgın`, also in form bodies and free text, and `张伟@example.cn`
  was not found. The whole name is now masked.
- A JSON Patch or SCIM PatchOp operation kept its value:
  `[{"op":"replace","path":"/password","value":"…"}]` and
  `{"Operations":[{"op":"replace","path":"password","value":"…"}]}` showed it in JSON,
  `application/json-patch+json` and `application/scim+json` bodies and in log lines.
- Redaction during this release made a redactor for every JSON array element and URL path
  segment and read each segment three times, so a megabyte of a JSON array of one-letter
  strings took 1.1-1.2 s in a release build and a URL of `/a/a/…` 4 s. The same input now
  takes 0.2 s and under 0.05 s.
- A multipart body in which Werkzeug 3.1.3 and PHP find another part after a `--boundary` that
  follows a bare LF or CR showed that part's value: in
  `…name="note"\r\n\r\nhi\n--B0und\r\nContent-Disposition: form-data; name="password"\r\n\r\n…`
  the redactor read one `note` part whose text kept the password. Such a body is now omitted.
- `SensitiveDataRedactor` no longer shows part of a card number that a secret value, bearer token
  or JSON Web Token runs into: `token=abc_4111 1111 1111 1111` became
  `token=[redacted] 1111 1111 1111`. Findings that partly overlap are now replaced together, and
  such a joined `Match` reports every kind it covers.
- `SensitiveDataRedactor.redact(_:)` took time quadratic in the number of findings (22 s for
  1.6 million characters of `pwd=x `); it now builds the output once and runs in linear time, as
  2.0.0 stated. A scaling test replaces the old timing test, which could not fail.
- `SensitiveDataRedactor` turned `PASSWORD := hunter2` into `PASSWORD :[redacted] hunter2`,
  hiding the `=` and showing the password, and did the same with `password == hunter2`,
  `password === hunter2`, `password ::= hunter2` and `password = = hunter2`; it now reads `:=`,
  `?=`, `+=`, `==`, `!=` and any further run of `=` and `:` as one separator; one written as a
  character outside ASCII such as `≔` cuts the text there.
- `SensitiveDataRedactor` printed a secret as is when an en space or another Unicode space
  outside U+00A0, U+2007, U+2009, U+202F and U+3000 stood around the `=`, inside a card number
  or after `Bearer`; the value detectors now read every Unicode space as a space, and free text
  is cut at one.
- `SensitiveDataRedactor` now finds secret values in form fields (`password[]=`,
  `user[password]=`, also with percent-encoded brackets as in `user%5Bpassword%5D=`), XML elements
  (`<password>…</password>`, also with attributes or a namespace prefix such as
  `<wsse:Password Type="…">`), after a percent-encoded `=` or `:` (`password%3D…`, also with
  `%20` or `+` around it) and inside angle brackets (`password: <…>`), and treats
  `pass`, `session_id`, `session_key`, `PHPSESSID`, `JSESSIONID` and a field named exactly
  `session` as secret names.
- The eleventh review timed a megabyte of text quoted in JSON at 1.1 to 2.6 seconds a megabyte in
  a release build, past the one-second limit, and found values that showed: a property list's
  value on the lines below its key (`<key>password</key>`, then `<string/>` and the value below
  it), the text after an element that holds nothing, JSON over several lines after `name=`, and a
  multipart label part in base64, as JSON or in another charset. The reading budget and a single
  pass per secret word bound the time; the others are hidden on every path. A connector glued
  inside a word (`user‿bob`) cuts the text. The review's 475 probes are kept as tests, 47 of them
  documented limitations, with property tests for the budget, for layouts over lines and for the
  one-pass match.
- The twelfth review found that a secret name inside the value of another key, which that key
  hides, named nothing: `Content-Disposition: form-data; name="pin"` followed by a blank line and
  the part's value showed the value, in a log line, in a text/plain body
  (`upload failed body=--B…`) and in a JSON string, and so did `name=password` without quotes and
  `note: a name="pin"` with the value on the next line. The key before the name is now the first
  trigger, which hides it and everything after it.
- A second reading of each line, which an earlier design of this release used for the names inside
  hidden values, kept the attribute values of a start tag once for every name in it: a start tag
  of a megabyte of attributes followed by 17 secret names took 583 MB, and 4 MB of it 2.3 GB. It
  also let a quote, a multipart part or a JSON value that it carried end the one the first reading
  carried, so `x: <string name="pin"> msg='start` with the secret two lines below showed it, and
  so did an open quote in a part header, a name in markup that closes on its line, an end tag
  without `>` (`</pin 1234`) and an escaped separator inside a hidden value
  (`msg: name%3Dpassword`). The one cut replaces both readings and every carry. The probes of every
  review of the redesign, 2,906 of them, and 66 repros of the twelfth review are kept as one test
  resource, 33 of them documented limitations, with a property test that no value after any
  trigger shows on any path that reads free text, a test that lines of allowed keys stay, and the
  memory test. Storing no offsets for text in which each scalar is one byte, masking the scanning
  copy without copying its offsets and joining the findings in one array bring a megabyte of
  addresses or URLs under 16 MB too.
- The thirteenth review got values past free text one variant at a time, which the five rules
  close as classes: a look-alike separator glued to a key and followed by a space or a line break
  (`user꞉ hunter2`, `user≔\nhunter2`, `[INFO] user꞉ v done`, 67 inputs on every path that reads
  free text, also `status꞉ v` after an allowed key), separators escaped as named references and
  octal escapes (`user&colon;…`, `user&coloneq;…`, `user&amp;equals;…`, `user\075…`), the second
  element of a two-element array in a line (`log [["user","…"]]`, `log ["user","…"]`), the text of
  an element (`<user>…</user>`, which the guide said was hidden), the host of a URL
  (`connect https://password=hunter2 ok`, `x://user=…`, `https://4111111111111111.example/`,
  `myapp://token=eyJ…`, also in a JSON string) and the name of a multipart part header
  (`4111111111111111: 1`, `X-<JSON Web Token>: 1`). It also measured a megabyte word of free text
  at up to 36 MB, as the reading of a word copied it eight bytes for each byte, a megabyte of
  `4242 ` card digit groups at 18.8 MB, and bodies of a megabyte at up to 67 MB (a form of one
  field repeated). Words are read only up to 256 characters, card digit groups through a window
  of the groups a card number can span, a form field by field without keeping its fields, and
  bodies up to 256 KiB by default: every free-text shape of the review now takes at most 12 MB
  for a megabyte and every body shape at most 10 MB at the limit. The review's 579 probes and 245
  inputs of its second lens are kept as tests, checked claim by claim (14 of them limitations or
  values shown by design), with property tests that no value after a character outside the safe
  alphabet, an escape, a long word, an unallowed key of a pair or a tag, an unknown part header
  name or a host that is not an address shows, and that text in the safe alphabet without a
  trigger and allowed pairs, tags, part headers and hosts stay.
- The fourteenth review got values past free text right after a URL whose end named them, 168
  inputs in every scheme (`http`, `HTTPS`, `ftp`, `wss`, `postgres`, `mongodb+srv`, `[::1]`, IPv4,
  ports, user info, `myapp`) and on every path that reads free text, also after an allowed key and
  in JSON strings, form values, multipart text parts and text/plain bodies: an empty or quoted query
  value (`?api_key='…' 200`, `?token= …`, `[docs](…?token=) …`), path parameters (`;token= …`), a
  fragment (`#access_token= …`, written without the fragment), a path that ends in `=` or `:`, and
  a last segment, query name or host that is a secret name (`/password …`, `?secret …`,
  `https://password …`). The scan wrote the URL and read on after it with nothing pending. A URL in
  free text is no longer a place to read on from: its path parameters, query or fragment cut the
  text right after their mark unless every parameter is on `allowedQueryParameters`, has a value
  in the URL and names no secret as a value, and a URL that ends in `=` or `:`, or whose last
  segment, or host when it has no path, names a secret, cannot be read or is not plain ASCII, cuts
  the text after it. A URL that `URLComponents` cannot read cuts the text where it starts, one
  whose host is not written after its scheme, unless the host holds only names with values
  (`myapp://password=hunter2`), and one past the limits of segments or parameters after its host.
  The same review found that every `:` between two digits was read as part of a time, so the value
  of a key that ends in digits showed (`user1:2345678`, `acct2:44556677`, `user_id2:998877`, also
  in a JSON string or a form value): such a `:` is part of a number now only after a number
  (`12:30:45`, `2026-10-19T12:30:45Z`, `10.0.0.1:8080`). It also measured a megabyte of log lines
  of short JSON (`{"count":1}`) at 19 MB, as `JSONSerialization` autoreleased each parsed tree and
  the thread kept them until the redaction ended; each tree is released before the next JSON is
  read now (9 MB), and the memory test measures until the thread that redacts has ended, which the
  earlier test, ending when the redaction returned, did not see. The review's 758 and 402 probes
  and 60 hand-run inputs are kept as tests, checked claim by claim (12 of them limitations or
  values shown by design), with generated tests of every scheme, ending and character between a
  URL and its value on every path, and tests that allowed URLs, times and addresses with ports
  stay.
- `PasswordHash.verify(_:against:)` returns `false` for an empty or overlong password instead of
  throwing `CipherError.invalidParameter`; a malformed hash still throws.

## [2.0.0] - 2026-10-15

A new library. In June 2026 the 1.0.0 sources were replaced with placeholder code; this release
rebuilds iOSSecurityTools from scratch as a dependency-free package of security building blocks.
No 1.0.0 API remains.

### Added

- Keychain: `Keychain` (data, strings, `Codable` values, keys, access groups, iCloud sync),
  `KeychainAccessibility`, `KeychainProtection` (user presence, any or current biometry,
  passcode) and `Keychain.symmetricKey(forKey:)`.
- Encryption: `DataCipher` (AES-256-GCM or ChaCha20-Poly1305 in a versioned, authenticated
  envelope with associated data), `KeyDerivation` (HKDF-SHA256), `PasswordKeyDerivation`
  (PBKDF2-HMAC-SHA256), `PasswordHash` (PHC string format), `SecureRandom` and `ConstantTime`.
- Secure Enclave: `SecureEnclaveKey` (P-256 signing keys for device binding) and
  `Keychain.secureEnclaveKey(forKey:protection:)`.
- Biometrics: `BiometricAuthenticator` with availability, async authentication and
  `BiometricError` (iOS, macOS, visionOS).
- Certificate pinning: `SPKIPin`, `PinnedDomain` (backup pin required, subdomains, expiration,
  report-only mode), `PinningPolicy`, `PinningURLSessionDelegate` and `URLSession.pinned(policy:)`;
  pins and failures are `Codable` for reports.
- One-time passwords: `HOTP`, `TOTP` and `OTPAuthURI` (`otpauth://` parsing and writing).
- Integrity: `IntegrityInspector` with jailbreak, debugger, simulator, injected-library and
  proxy checks, and a `Codable` `IntegrityReport`.
- Logs and screens: `Redacted`, `Mask`, `SensitiveDataRedactor`, `View.privacyShield(when:)`
  and `View.onScreenshot(perform:)`.
- DocC catalog with five articles, the SecurityLab example app for iOS and macOS, README
  screenshots captured from the app, and CI through the shared workflows of
  muhittincamdali/.github.

### Changed

- Minimum platforms: iOS 17, macOS 14, tvOS 17, watchOS 10, visionOS 1; swift-tools-version 6.2
  and the Swift 6 language mode.

### Removed

- All 1.0.0 and June 2026 types (`SecurityToolsManager`, `AESEncryption`, `RSAEncryption`,
  `JWTManager`, `OAuthManager`, `SecureVault`, `AntiDebugHook`, `RuntimeDefender`, `SecureRAM`
  and the rest), the CocoaPods spec and the `Documentation/` folder.

### Security

- Every input that can come from outside the app is validated and bounded: `otpauth://` URIs
  (length, duplicated parameters, issuer mismatch, ranges), encoded password hashes (iteration
  counts are capped, so a tampered hash cannot make verification run for hours), envelopes,
  pins and host names. Dates built from NaN or infinite intervals throw instead of trapping in
  the TOTP counter.
- `SensitiveDataRedactor` normalizes zero-width characters, combining marks, full-width forms and
  non-ASCII digits before matching, finds secret words inside longer field names (`SECRET_KEY`,
  `passwordConfirm`) and in escaped JSON, and runs in linear time.
- Calls into the macOS login keychain are serialized: concurrent calls could deadlock inside the
  Security framework.

## [1.0.0] - 2026-02-02

First tagged release: encryption, keychain, authentication and monitoring managers. Replaced by
2.0.0.

[2.1.0]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/muhittincamdali/iOSSecurityTools/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/muhittincamdali/iOSSecurityTools/releases/tag/v1.0.0
