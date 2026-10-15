# Contributing

Thanks for taking the time to improve iOSSecurityTools.

## Reporting bugs

Open an issue with:

- the type and method you used, and the arguments,
- what you expected and what happened, including the error,
- platform, OS version and Xcode version, and whether it was a device or the simulator.

Do not put real secrets, tokens or certificates of private servers in an issue. Security problems
go through the [security policy](SECURITY.md), not an issue.

## Pull requests

1. Fork the repository and branch from `master`.
2. Keep each pull request focused on one change.
3. Run the tests on macOS, on an iOS simulator, and in the example app (which runs the keychain
   suites inside a signed app):

    ```sh
    swift test
    xcodebuild test -scheme iOSSecurityTools -destination 'platform=iOS Simulator,name=iPhone 17'
    cd Examples/SecurityLab
    xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
    ```

4. Add a test for every change in behaviour in `Tests/iOSSecurityToolsTests`. Cover invalid and
   hostile input, not only the happy path: empty and oversized values, `NaN`, infinite and
   negative numbers, `Int.min` and `Int.max`, duplicated or conflicting parameters, Unicode
   tricks (zero-width characters, combining marks, full-width forms). For a standard algorithm,
   test against the published vectors (RFC 4226, RFC 6238, RFC 5869) or against an independent
   implementation, and say in a comment where the values come from.
5. Public functions validate their input and throw a typed error; they do not crash. Every loop
   and allocation whose size depends on input is bounded. Comparisons of secrets use
   `ConstantTime`. Types that hold a secret leave it out of `description` and `customMirror`.
6. If you change a README code sample, change the copy in
   `Examples/SecurityLab/SecurityLab/ReadmeSamples.swift` as well. That file is what gets
   compiled: by the example app, and by `swift test` through the symlink
   `Tests/iOSSecurityToolsTests/ReadmeExamples.swift`.
7. If a change affects a screen of the example app shown in the README, regenerate the
   screenshots with `scripts/capture-example-screens.sh`.
8. If you change the certificate fixtures, regenerate them with
   `scripts/make-test-certificates.sh` instead of editing `CertificateFixtures.swift`.

## Code style

- Follow the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/).
- The package builds in the Swift 6 language mode; new code should not add warnings, and
  `xcodebuild docbuild` should stay free of documentation warnings.
- Document public API with DocC comments (`///`), including every parameter and what it throws,
  and say plainly what a feature does not protect against.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`).
