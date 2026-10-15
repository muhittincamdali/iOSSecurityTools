# Security policy

## Supported versions

Security fixes are made for the latest release. Version 1.0.0 is a different, unmaintained code
base and does not receive fixes.

## What counts as a vulnerability

iOSSecurityTools protects secrets inside apps and reads data the app does not control: scanned
`otpauth://` URIs, server certificates, stored password hashes and envelopes, log text. Please
report privately anything that makes it:

- reveal a secret: a key, a keychain value, a TOTP secret or a `Redacted` value in a description,
  a log line, an error message or a file,
- accept what it should reject: a tampered envelope, a wrong one-time code, a certificate chain
  that is not trusted or not pinned, a malformed URI or hash,
- miss data that `SensitiveDataRedactor` or `Mask` documents that it hides, for example through
  Unicode tricks,
- crash (a trap, an out-of-range index, an integer overflow) instead of throwing,
- run for a very long time or allocate memory out of proportion to its input.

The integrity checks are documented as signals that an attacker who controls the device can hide
from; a way to hide from them is not a vulnerability, but a false positive on a stock device is a
bug worth an issue.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue, pull request or discussion.

1. **Preferred:** open the repository's **Security** tab and choose
   **Report a vulnerability** ([how private reporting works](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)).
2. **Or** email [muhittincamdali@gmail.com](mailto:muhittincamdali@gmail.com) with
   "Security" in the subject.

Include the iOSSecurityTools version (tag or commit), the platform and OS version, the input that
triggers the problem and what happens.

## What happens next

- You get a reply within 7 days confirming that the report arrived.
- The issue is confirmed, fixed with a regression test, and released together with a GitHub
  security advisory on a disclosure date agreed with you.
- You are credited in the advisory unless you prefer not to be.
