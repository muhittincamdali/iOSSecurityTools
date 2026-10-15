# Examples

## SecurityLab

A small iOS and macOS app with one screen per feature: the README quick start, the integrity
report, an encrypted note and a PIN hash in the keychain, live TOTP codes from an `otpauth://`
URI, log redaction, the privacy shield and a certificate pinning check against a real server.
It uses the package from this checkout (a local package reference to `../..`), so it always
shows the current code.

Run it:

1. Open `Examples/SecurityLab/SecurityLab.xcodeproj` in Xcode 26 or later.
2. Choose the **SecurityLab** scheme and an iPhone simulator or **My Mac** as the run
   destination.
3. Press **Run** (⌘R).

On the Mac the app is signed to run locally, without a team, so the keychain screens report
the missing keychain entitlement; choose your team under **Signing & Capabilities** to use them
there. The simulator needs no signing.

From the command line:

```sh
cd Examples/SecurityLab
xcodebuild build -scheme SecurityLab -destination 'generic/platform=iOS Simulator'
xcodebuild build -scheme SecurityLab -destination 'platform=macOS'
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

The test target runs inside the app on the simulator. It holds the package's keychain and
Secure Enclave suites, which need the keychain entitlement that only an app has, and checks the
quick start and the README keychain sample end to end.

The README samples live in
[`SecurityLab/ReadmeSamples.swift`](SecurityLab/SecurityLab/ReadmeSamples.swift). The README
copies its code from that file, and the package's test target compiles it through the symlink
`Tests/iOSSecurityToolsTests/ReadmeExamples.swift` and runs the samples that need no prompt or
network.

The README screenshots come from this app: `scripts/capture-example-screens.sh` opens each screen
on a simulator with `-screen <name> -demo YES` and saves light and dark captures in `docs/images`.

The project file is made with [XcodeGen](https://github.com/yonaskolb/XcodeGen) from
[`project.yml`](SecurityLab/project.yml) and committed, so you only need XcodeGen after editing
`project.yml`.
