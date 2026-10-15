# Detecting Compromised Devices

Read the integrity report as a set of signals and decide what each one should change.

## Overview

``IntegrityInspector`` looks for traces of a jailbreak, an attached debugger, the simulator,
injected hooking libraries and a system proxy:

```swift
let report = IntegrityInspector().inspect()
if report.hasFindings(in: [.jailbreak, .injectedLibraries]) {
    // Add friction: ask for the passcode again, lower limits, flag the session on the server.
}
```

Every check runs inside your app's process. Someone who controls the device controls that
process too, and can hide files, clear the debugger flag or patch the inspector. A clean report
therefore proves nothing; a report with findings is worth acting on, because hiding takes effort
that ordinary users do not make.

### What each check looks for

| Check | Looks for | Expect it in development |
| --- | --- | --- |
| ``IntegrityChecks/jailbreak`` | Files of jailbreaks and package managers (Cydia, Sileo, Substrate, `/var/jb`, ...), and whether the app can create a file outside its sandbox | No: it runs only on iOS and iPadOS devices |
| ``IntegrityChecks/debugger`` | The `P_TRACED` flag of the process | Yes, when Xcode runs the app |
| ``IntegrityChecks/simulator`` | A simulator build | Yes |
| ``IntegrityChecks/injectedLibraries`` | `DYLD_INSERT_LIBRARIES`, and loaded libraries of Frida, Substrate, libhooker, ElleKit and similar tools | Yes: Xcode injects the Main Thread Checker this way |
| ``IntegrityChecks/proxy`` | An HTTP, HTTPS or automatic proxy in the system settings | When you debug traffic through a proxy |

The jailbreak check is skipped in the simulator, on macOS and for iPad apps running on a Mac,
where `/bin/bash` and similar files are normal; ``IntegrityReport/checksRun`` tells which checks
ran.

### Respond in proportion

Blocking the app on any finding locks out developers, testers and people behind a corporate
proxy, and attackers bypass the block anyway. Prefer responses that cost an attacker more than a
user:

- Require the passcode or Face ID again before sensitive actions.
- Lower transaction limits for the session.
- Send the report with the request (``IntegrityReport`` is `Codable`) and let the server decide,
  together with what it knows about the account.

### When you need proof

For a decision the server must be able to trust — a payment, a reward, an account recovery —
use App Attest (`DCAppAttestService` in DeviceCheck). The Secure Enclave signs an attestation that
Apple's servers vouch for, so your server can verify that a request comes from your genuine app on
a genuine device, which no in-process check can show.
