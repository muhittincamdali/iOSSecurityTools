<!-- i18n-source: README.md@a4823044eb48b1a3327b2bdea9fd2180411db856 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-de-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-de-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-de-light.svg" alt="iOSSecurityTools: Schlüsselbund, Verschlüsselung, Pinning, Einmalcodes und Integritätsprüfungen für Apple-Apps."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="CI-Status"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Aktuelle Version: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Unterstützte Plattformen: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Sprachversion: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="Lizenz: MIT"></picture></a>
</p>

<p align="center">
<a href="#schnellstart"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-de-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-de-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-de-light.svg" alt="Loslegen"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-de-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-de-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-de-light.svg" alt="Dokumentation"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-de-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-de-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-de-light.svg" alt="Beispiele"></picture></a>
</p>

> Dies ist eine Übersetzung der englischen README. Bei Abweichungen gilt die englische Fassung.

<!-- brand:end -->

Ein Swift-Paket mit Sicherheitsbausteinen für Apps auf iOS, macOS, tvOS, watchOS und visionOS:
Schlüsselbund-Speicherung, authentifizierte Verschlüsselung, PIN-Hashes, Secure-Enclave-Schlüssel,
Certificate Pinning, Einmalpasswörter, Integritätsprüfungen des Geräts und das Schwärzen von
Logs. Es richtet sich an App-Entwickler, die diese Teile korrekt umsetzen wollen, ohne die
C-APIs des Security-Frameworks zu studieren. Jeder Typ prüft, was er bekommt, und wirft einen
typisierten Fehler, statt abzustürzen. So können Werte aus einem QR-Code, von einem Server oder
aus einer Datei die App nicht zum Absturz bringen. Das Paket hat keine Abhängigkeiten.

## Highlights

- **Schlüsselbund ohne Dictionaries** — `Keychain` speichert Daten, Strings und `Codable`-Werte,
  legt Verschlüsselungsschlüssel bei der ersten Verwendung an und kann Face ID, Touch ID oder den
  Gerätecode verlangen. Das erzwingt der Schlüsselbund selbst und nicht ein `if` um `LAContext`.
- **Verschlüsselung, die Manipulation erkennt** — `DataCipher` schreibt AES-256-GCM- oder
  ChaCha20-Poly1305-Umschläge, die ihre Version, ihren Algorithmus und ihre Nonce selbst
  mitführen. Jedes geänderte Byte, ein falscher Schlüssel oder falsche zugehörige Daten lassen die
  Entschlüsselung fehlschlagen. HKDF, PBKDF2 und PIN-Hashes im PHC-Format sind dabei.
- **Pinning, das Nutzer nicht aussperrt** — `PinningPolicy` verlangt einen Backup-Pin, unterstützt
  Subdomains, Ablaufdaten und einen reinen Meldemodus und setzt trotzdem voraus, dass die
  systemeigene Vertrauensprüfung besteht.
- **Signale statt Versprechen** — `IntegrityInspector` meldet Jailbreak-Dateien, einen Debugger,
  den Simulator, Hooking-Bibliotheken und einen System-Proxy als `Codable`-Bericht. Die
  Dokumentation sagt außerdem, was ein Angreifer davor verbergen kann.
- **Geheimnisse bleiben aus Logs und Screenshots heraus** — `@Redacted` gibt überall
  `<redacted>` aus, `SensitiveDataRedactor` entfernt Kartennummern, E-Mail-Adressen, Tokens und
  geheime Felder, und `.privacyShield()` verdeckt Ansichten im App-Umschalter und während der
  Bildschirmaufnahme. Der Redactor vergleicht nur reine ASCII-Schlüssel mit seinen geheimen
  Namen und schwärzt jeden anderen Schlüssel standardmäßig; JSON-, Formular- und
  Multipart-Bodys werden geparst, nicht parsbare Bodys werden ausgelassen.
- **Gegen feindliche Eingaben getestet** — Testvektoren aus RFC 4226, 6238 und 5869, Umschläge
  und Hashes aus einer unabhängigen Implementierung, Zertifikatsketten aus einer Test-PKI, NaN
  und unendliche Datumswerte, `Int.min` und `Int.max`, übergroße und doppelte URI-Parameter:
  282 Swift-Testing-Tests auf macOS und in einem iPhone-Simulator, dazu die
  Schlüsselbund-Testsuites in der Beispiel-App.

### Was enthalten ist

| Bereich | Typen |
| --- | --- |
| Schlüsselbund | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| Verschlüsselung und Hashing | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| Biometrie | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| Certificate Pinning | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| Einmalpasswörter | `TOTP`, `HOTP`, `OTPAuthURI` |
| Geräteintegrität | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| Logs und Bildschirme | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Schnellstart

**1. Paket hinzufügen**

Wähle in Xcode **File › Add Package Dependencies…** und gib die Repository-URL ein:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Füge sie oben rechts im Fenster in das Suchfeld ein. Lass **Dependency Rule** auf **Up to Next
Major Version** ab `2.1.0` stehen und klicke auf **Add Package**. Wähle im nächsten Fenster neben
**iOSSecurityTools** das Target deiner App aus und klicke noch einmal auf **Add Package**.

**2. Modul importieren**

```swift
import iOSSecurityTools
```

Setze diese Zeile an den Anfang der Swift-Datei, in der du das Paket verwendest, unter
`import SwiftUI`.

**3. Verwenden**

Ersetze in einer neuen Xcode-App (**File › New › Project… › App**) den gesamten Inhalt von
`ContentView.swift` durch:

```swift
import SwiftUI
import iOSSecurityTools

struct ContentView: View {
    @State private var status = "Nothing stored yet"

    var body: some View {
        VStack(spacing: 16) {
            Text(status)
            Button("Encrypt and store a note") {
                do {
                    let keychain = Keychain(service: "QuickStart")
                    let cipher = try DataCipher(key: keychain.symmetricKey(forKey: "notes-key"))
                    try keychain.set(cipher.encrypt("Meet at 7 pm"), forKey: "note")

                    let stored = try keychain.data(forKey: "note") ?? Data()
                    status = "Decrypted: \(try cipher.decryptString(stored))"
                } catch {
                    status = error.localizedDescription
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .privacyShield()
    }
}
```

Wähle einen iPhone-Simulator und drücke **Run** (⌘R). Tippe auf den Button: Die App legt im
Schlüsselbund einen Schlüssel an, verschlüsselt damit die Notiz, speichert die verschlüsselten
Bytes, liest sie zurück und zeigt "Decrypted: Meet at 7 pm". `.privacyShield()` verdeckt den
Bildschirm mit einem Schloss, während die App im Hintergrund ist, sodass der App-Umschalter die
Notiz nicht anzeigt.

## Installation

### Swift Package Manager

Wähle in Xcode **File › Add Package Dependencies…** und gib die Repository-URL ein:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Oder füge es zu den `dependencies` in deiner `Package.swift` hinzu:

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.1.0")
],
targets: [
    .target(name: "YourApp", dependencies: [
        .product(name: "iOSSecurityTools", package: "iOSSecurityTools")
    ])
]
```

Version 2.0.0 (Oktober 2026) ist das erste Release des aktuellen Pakets. Das frühere Release
1.0.0 (Februar 2026) ist eine andere Codebasis: Im Juni 2026 wurde ihr Quellcode durch
Platzhaltercode ersetzt, und im Oktober 2026 wurde das Paket mit Tests von Grund auf neu
aufgebaut. Die Änderungen stehen in [CHANGELOG.md](CHANGELOG.md).

Eine macOS-App braucht für den Schlüsselbund ein Entwicklungsteam unter **Signing & Capabilities**;
iOS-Apps und der Simulator benötigen nichts Zusätzliches. Für Face ID füge `NSFaceIDUsageDescription`
zur Info.plist der App hinzu.

## Verwendung

Die folgenden Beispiele sind kopiert aus
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift).
Die Beispiel-App und die Testsuite kompilieren diese Datei, und die Tests führen die Beispiele
aus, die keine Abfrage und kein Netzwerk brauchen.

### Ein Token im Schlüsselbund speichern

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Face ID für einen Wert verlangen

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Einen Datensatz verschlüsseln

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Die PIN der App-Sperre prüfen

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Einmalcodes aus einem QR-Code anzeigen

```swift
func oneTimePasswordSample() throws -> Bool {
    let scanned = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    let uri = try OTPAuthURI(parsing: scanned)
    guard case .totp(let totp) = uri.kind else { return false }

    let code = try totp.code()                    // six digits, new every 30 seconds
    let secondsLeft = try totp.secondsRemaining()
    print("\(uri.issuer ?? ""): \(code), \(secondsLeft) s left")
    return try totp.verify(code)                   // also accepts the previous and next code
}
```

### Die Schlüssel eines Servers pinnen

```swift
func pinnedSessionSample() throws -> URLSession {
    let policy = try PinningPolicy([
        PinnedDomain("letsencrypt.org", pins: [
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",   // ISRG Root X1
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",   // ISRG Root X2
        ], includesSubdomains: true),
    ])
    return URLSession.pinned(policy: policy) { failure in
        print("Blocked: \(failure.localizedDescription)")
    }
}
```

Die [Pinning-Anleitung](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) zeigt, wie du die Pins deines eigenen Servers
bekommst und sie einführst, ohne Nutzer auszusperren.

### Das Gerät prüfen

```swift
func integritySample() -> IntegrityReport {
    let report = IntegrityInspector().inspect()
    if report.hasFindings(in: [.jailbreak, .injectedLibraries]) {
        // Add friction: ask for the passcode again, lower limits, flag the session on the server.
    }
    for finding in report.findings {
        print(finding)   // for example "Running in the simulator"
    }
    return report
}
```

### Geheimnisse aus Logs heraushalten

```swift
struct LoginRequest: Codable {
    var username: String
    @Redacted var password: String
}

func redactionSample() -> (request: String, log: String) {
    let request = LoginRequest(username: "alice", password: "hunter2")
    let printed = "\(request)"   // LoginRequest(username: "alice", _password: <redacted>)

    let redactor = SensitiveDataRedactor()
    let log = redactor.redact("charged 4242 4242 4242 4242 to alice@example.com, token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln")
    // "charged •••• 4242 to a•••@example.com, token=[redacted]"
    return (printed, log)
}
```

`SensitiveDataRedactor` vergleicht nur reine ASCII-Schlüssel (`A`–`Z`, `a`–`z`, `0`–`9`, `_`, `-`,
`.` und Leerzeichen) mit seinen geheimen Namen; der Wert jedes anderen Schlüssels wird
standardmäßig geschwärzt, denn ähnlich aussehende Buchstaben, unsichtbare Zeichen und
Escape-Sequenzen können einen geheimen Namen tarnen. JSON-, Formular- und Multipart-Bodys werden
mit einem Parser gelesen; einen Body, den es nicht vollständig parsen kann, lässt es als
`[body omitted: N bytes, <type>]` aus. Freier Text behält einen Wert nur nach einem erlaubten
Schlüssel (`status`, `method`, `path`, `duration_ms`, `count` und die Schlüssel, die Sie
übergeben), sodass aus `user=bob` `user=[redacted]` wird. Schwärzen ist ein Sicherheitsnetz,
keine Garantie. Der
[Logging-Leitfaden](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
beschreibt die Regel für freien Text, ihren Preis und was sie nicht findet.

### Ein Konto an das Gerät binden

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Demo

Bildschirme der Beispiel-App SecurityLab in einem iPhone-Simulator, aufgenommen aus der laufenden
App mit [`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh):

| Integrität                                                                                                                                                            | Tresor                                                                                                                                                     | Einmalcodes                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Integritätsbericht im Simulator: Jailbreak-Prüfung nicht anwendbar, Simulator erkannt, Debugger, eingeschleuste Bibliotheken und Proxy unauffällig" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="Eine als 46 Bytes im Schlüsselbund verschlüsselte und wieder gelesene Notiz sowie eine PIN, die gegen ihren gespeicherten Hash geprüft wird" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="Ein sechsstelliger TOTP-Code aus einem otpauth-URI mit einem Ring, der die verbleibenden Sekunden herunterzählt" width="260"></picture> |

| Schwärzung                                                                                                                      | Sichtschutz                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="Ein Logtext mit E-Mail-Adresse, Passwort, Bearer-Token und Kartennummer und darunter die geschwärzte Fassung" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="Eine Ansicht mit Kartendetails, verdeckt vom Sichtschutz mit einem Schloss-Symbol" width="260"></picture> |

Um die App auszuführen, öffne `SecurityLab.xcodeproj` in [`Examples/SecurityLab`](Examples/SecurityLab)
mit Xcode, wähle einen iPhone-Simulator oder **My Mac** und drücke **Run**. Sie enthält auch den
Schnellstart und einen Certificate-Pinning-Bildschirm, der sich mit einem Server verbindet und die
Pins seiner Kette auflistet; Einzelheiten stehen in [Examples/README.md](Examples/README.md).

## Dokumentation

API-Referenz und Artikel:

- [API-Referenz](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, von `master` auf GitHub Pages veröffentlicht)
- Baue sie lokal in Xcode mit **Product › Build Documentation** oder in der Kommandozeile:

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Anleitungen

- [Erste Schritte](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — das Paket hinzufügen, eine Notiz im Schlüsselbund verschlüsseln und den Bildschirm verdecken
  ([Quelle](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Geheimnisse speichern](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — Zugriffsbedingungen, biometrischer Schutz, Verschlüsselungsschlüssel, PIN-Hashes und
  Secure-Enclave-Schlüssel ([Quelle](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Zertifikate pinnen](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — Pins beschaffen, ein Backup wählen, im Meldemodus einführen und Ablaufdaten
  ([Quelle](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Kompromittierte Geräte erkennen](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — was jede Integritätsprüfung sieht, was nicht und wann App Attest sinnvoll ist
  ([Quelle](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Geheimnisse aus Logs heraushalten](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, Masken, der Redactor und der Sichtschutz
  ([Quelle](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Voraussetzungen

| Plattform | Mindestversion |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| Toolchain | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` ist auf tvOS und watchOS nicht verfügbar, da sie keine Biometrie haben.
Die CI baut mit dem Standard-Xcode des Runner-Images `macos-26` von GitHub. Das Paket wird mit
Xcode 27 entwickelt.

## Architektur

- `Sources/iOSSecurityTools/<Area>/` enthält pro Bereich einen Ordner: `Keychain`, `Crypto`,
  `Random`, `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`,
  `Redaction` und `Privacy`. Alles ist ein `Sendable`-Werttyp, außer
  `PinningURLSessionDelegate`, das laut `URLSession` eine Klasse sein muss.
- Das Paket ruft die Frameworks von Apple direkt auf — Security für Schlüsselbund und
  Vertrauensprüfung, CryptoKit für AES-GCM, ChaCha20-Poly1305, HKDF, HMAC und die Secure Enclave,
  CommonCrypto für PBKDF2, LocalAuthentication für die Biometrie — und implementiert nur, was
  ihnen fehlt: das Umschlagformat, die SubjectPublicKeyInfo-Kodierung für Pins, die
  HOTP/TOTP-Kürzung, Base32, das PHC-Hashformat und den Scanner zum Schwärzen.
- Fehler sind typisiert (`throws(KeychainError)`, `throws(CipherError)`, ...), und jeder
  Enum-Fall hat eine Beschreibung. Bei Werten, die von außerhalb der App kommen, werden die
  Grenzen geprüft, bevor irgendeine Arbeit beginnt.
- Code, der das System ausliest (Integritätsprüfungen, `LAContext`), läuft über kleine interne
  Protokolle. So durchlaufen die Tests jeden Zweig mit Fakes und prüfen zusätzlich die echte
  Implementierung.
- Was das Paket nicht tut, gehört zum Entwurf: kein `ptrace` deny-attach, kein Method
  Swizzling, kein Auslesen privater dyld-Strukturen. Das bricht zwischen OS-Versionen und lässt
  sich leicht umgehen; die [Integritätsanleitung](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  verweist stattdessen auf App Attest.
- Die CI führt `swift test` auf macOS und `xcodebuild test` in einem iPhone-Simulator aus, baut
  für alle fünf Plattformen, baut die Beispiel-App für iOS und macOS, führt ihre Tests in der
  App aus und veröffentlicht die DocC-Dokumentation.

Die Tests lokal ausführen:

```sh
swift test                                    # macOS
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

Ein Testbundle ohne Host-App hat im Simulator keine Keychain-Berechtigung, deshalb laufen die
Schlüsselbund-Testsuites des Pakets dort in der Beispiel-App:

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Roadmap

- Ein App-Attest-Wrapper (`DCAppAttestService`) mit einem Beispiel für die serverseitige Prüfung.
- Das Paket in den Swift Package Index aufnehmen; `.spi.yml` liegt bereits im Repository.

## Mitwirken

Beiträge sind willkommen. Lies vor einem Pull Request den [Leitfaden für Beiträge](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) und den [Verhaltenskodex](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md). Sicherheitsprobleme meldest du vertraulich, wie in der [Sicherheitsrichtlinie](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md) beschrieben.

## Lizenz

Veröffentlicht unter der MIT-Lizenz. Siehe [LICENSE](LICENSE).
