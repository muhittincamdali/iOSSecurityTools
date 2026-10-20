# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - Unreleased

### Added

- `SensitiveDataRedactor.redact(body:contentType:)` redacts request and response bodies with a
  parser chosen by the content type: JSON, `application/x-www-form-urlencoded` forms, multipart
  form data (each part by its own type) and plain text. A body that is not UTF-8, has another
  type, is larger than 1 MiB (`maximumBodySize`), does not parse completely or could be split
  into fields differently by a common server parser is omitted as
  `[body omitted: N bytes, <type>]`; uploaded files are omitted the same way.
- `SensitiveDataRedactor.redact(url:)` writes a URL read with `URLComponents` without its user
  name, password and fragment, whatever `kinds` holds. With `.secretFields` a query value is
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
- `allowedTextKeys` and `defaultAllowedTextKeys`: the keys whose values free text keeps.
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
- Name and value pairs follow the key rule in every shape. In an object whose `name`, `key`,
  `field`, `header`, `param`, `path`, `k` or `n` is a secret name or not plain ASCII, every
  `value`, `val`, `values`, `content`, `data`, `secret` and `v` is hidden whole; a name that is an
  array or object hides them too. Of a `path` every part between `/` counts, as JSON Patch
  (RFC 6902) and SCIM PatchOp (RFC 7644) write it: `/user/password` and `/apiKeys/0` hide the
  value, `/status` and `/tags/-` keep it. The second element of a two-element array whose first
  is such a name is hidden whole (`[["Authorization","…"]]`, fetch headers, `URLSearchParams`
  entries).
- Email addresses are found with a name in any script, over letters, marks and digits
  (`ayşe.yılmaz@…`, `bjørn.dæhlie@…`, `张伟@…`), and with an internationalized domain
  (`王小明@例子.中国`); only the first letter of the name is written.
- Redaction reads input within fixed limits, which bound the stack that hostile input can use:
  JSON objects and arrays may be open 64 levels deep in all, counting the levels of every
  document a JSON string is in, and at most four documents (a JSON text, a URL, a body, a
  multipart part) are read one inside another. A JSON body deeper than that is omitted, and a
  string or other text inside a document that holds such JSON, or a URL one level too many, is
  hidden whole; a body larger than 1 MiB is still omitted unread. Tests redact JSON quoted inside
  JSON strings, URLs in query values and runs of brackets on a thread with 512 KiB of stack in
  debug and release builds, and check with `swift test -c release` that a megabyte of text,
  nested input or a body takes less than a second, also for ordinary shapes timed by the CPU time
  of such a thread: JSON arrays of short or empty strings, a multipart body of 1,000 parts and
  URLs of many segments. The default redactor and its folded keys are made once and shared, a
  short plain word is not scanned, and a URL path segment is read in a single pass.
- Free text keeps a value only after an allowed key: in `key=value`, `key: value` and
  `"key":"value"` every other value is hidden, so `user=bob` becomes `user=[redacted]`. A quoted
  value is hidden up to its closing quote, also on a later line; an unquoted one to the end of its
  line, with the lines below that it may go on to. A word that holds a secret name hides the rest
  of its line, also when it is escaped, split by punctuation or a space, or spelled with a letter
  that has no ASCII form; a word that mixes scripts or holds an invisible character hides itself
  and the rest of its line.
- A secret name written as a value names what follows it. In free text, a text/plain body and
  text inside a JSON string, a quoted value that holds a secret name or a word that cannot be read
  (`name="password"`, `key='token'`, `id: "pin"`, `label="API Key"`) hides the rest of its line
  after the closing quote. In XML and HTML the other attribute values of its start tag are hidden
  too, and the lines below up to the element's end tag; a secret name in an element's text
  (`<key>password</key>`) names the element after it, as a property list writes a key and its
  value. In a JSON object, a member whose value is such a name hides the values of the other
  members, apart from the members that hold names and a JSON Patch or SCIM `op`. A name that is
  not secret (`name="status"`, `{"label":"Status",…}`) keeps what follows it.
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
  cannot be read, hides the rest of its line.
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
  `?=`, `+=`, `==`, `!=` and any further run of `=` and `:` as one separator, also when written
  as one character such as `≔`.
- `SensitiveDataRedactor` printed a secret as is when an en space or another Unicode space
  outside U+00A0, U+2007, U+2009, U+202F and U+3000 stood around the `=`, inside a card number
  or after `Bearer`; every Unicode space now counts as a space.
- `SensitiveDataRedactor` now finds secret values in form fields (`password[]=`,
  `user[password]=`, also with percent-encoded brackets as in `user%5Bpassword%5D=`), XML elements
  (`<password>…</password>`, also with attributes or a namespace prefix such as
  `<wsse:Password Type="…">`), after a percent-encoded `=` or `:` (`password%3D…`, also with
  `%20` or `+` around it) and inside angle brackets (`password: <…>`), and treats
  `pass`, `session_id`, `session_key`, `PHPSESSID`, `JSESSIONID` and a field named exactly
  `session` as secret names.
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
