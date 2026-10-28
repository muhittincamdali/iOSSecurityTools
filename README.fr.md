<!-- i18n-source: README.md@f40d0d8d2a5dc0db52e83c57aa98a2cd44b5fec0 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-fr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-fr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-fr-light.svg" alt="iOSSecurityTools: Trousseau, chiffrement, pinning, codes à usage unique et contrôles d’intégrité pour les apps Apple."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="État de la CI"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Dernière version: v2.2.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Plateformes prises en charge: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Version du langage: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="Licence: MIT"></picture></a>
</p>

<p align="center">
<a href="#démarrage-rapide"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-fr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-fr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-fr-light.svg" alt="Commencer"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-fr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-fr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-fr-light.svg" alt="Documentation"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-fr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-fr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-fr-light.svg" alt="Exemples"></picture></a>
</p>

> Ceci est une traduction du README anglais. En cas de différence, la version anglaise fait foi.

<!-- brand:end -->

Un paquet Swift de briques de sécurité pour les apps iOS, macOS, tvOS, watchOS et visionOS :
stockage dans le trousseau, chiffrement authentifié, chiffrement à clé publique, signatures, tokens signés (JWT), hachages de PIN, clés Secure Enclave,
certificate pinning, mots de passe à usage unique, contrôles d’intégrité de l’appareil et
masquage des données dans les journaux. Il s’adresse aux développeurs d’apps qui veulent mettre en
place ces éléments correctement sans étudier les API en C du framework Security. Chaque type valide
ce qu’il reçoit et lève une erreur typée au lieu de planter ; les valeurs issues d’un code QR,
d’un serveur ou d’un fichier ne peuvent donc pas faire planter l’app. Le paquet n’a aucune
dépendance.

## Points forts

- **Un trousseau sans dictionnaires** — `Keychain` stocke des données, des chaînes et des valeurs
  `Codable`, crée les clés de chiffrement à la première utilisation et peut exiger Face ID,
  Touch ID ou le code de l’appareil ; c’est le trousseau lui-même qui l’impose, et non un `if`
  autour de `LAContext`.
- **Un chiffrement qui détecte les altérations** — `DataCipher` écrit des enveloppes AES-256-GCM
  ou ChaCha20-Poly1305 qui portent leur propre version, leur algorithme et leur nonce ; un octet
  modifié, une mauvaise clé ou de mauvaises données associées font échouer le déchiffrement. HKDF,
  PBKDF2 et les hachages de PIN au format PHC sont fournis avec.
- **Un chiffrement de bout en bout sans secret partagé** — `PublicKeyCipher` scelle des données pour la clé publique d’un appareil avec HPKE (RFC 9180), si bien qu’un serveur ou un autre utilisateur peut envoyer ce que seul cet appareil ouvre ; `SigningKey` et `VerifyingKey` signent et vérifient des données avec des clés Ed25519 ou P-256 lues depuis des octets bruts, du DER ou du PEM.
- **Des tokens vérifiés avant qu’on leur fasse confiance** — `JWTVerifier` prend l’algorithme à partir de sa clé : les tokens `none` et les tokens `HS256` avec une clé publique échouent donc avant que quoi que ce soit soit lu, puis il vérifie la signature, `exp`, `nbf`, `iss` et `aud` ; `JWTSigner` émet des tokens avec les mêmes clés.
- **Un pinning qui n’enferme pas les utilisateurs dehors** — `PinningPolicy` exige un pin de
  secours, prend en charge les sous-domaines, les dates d’expiration et un mode de simple
  signalement, et exige toujours que l’évaluation de confiance du système réussisse.
- **Des signaux, pas des promesses** — `IntegrityInspector` signale les fichiers de jailbreak, un
  débogueur, le simulateur, les bibliothèques de hooking et un proxy système sous la forme d’un
  rapport `Codable`, et la documentation précise ce qu’un attaquant peut lui cacher.
- **Les secrets restent hors des journaux et des captures d’écran** — `@Redacted` affiche
  `<redacted>` partout, `SensitiveDataRedactor` masque les numéros de carte, les e-mails, les
  tokens et les champs secrets, et `.privacyShield()` recouvre les vues dans le sélecteur d’apps
  et pendant l’enregistrement de l’écran. Le masqueur ne compare à ses noms secrets que les clés
  en ASCII simple et masque par défaut toute autre clé ; les corps JSON, de formulaire et
  multipart sont analysés, et les corps non analysables sont omis, comme ceux qu’un serveur
  pourrait découper autrement en champs. Le texte libre est coupé à son premier déclencheur : un
  caractère hors d’un alphabet sûr, une séquence d’échappement, un mot long, une clé non
  autorisée ou un nom secret.
- **Testé face à des entrées hostiles** — vecteurs des RFC 4226, 6238, 5869, 7748, 8032 et 4231, enveloppes, hachages, signatures et tokens créés par une implémentation indépendante, chaînes de certificats d’une PKI de test, dates NaN et infinies, `Int.min` et `Int.max`, paramètres d’URI démesurés ou en double, en-têtes de token falsifiés : 676 tests Swift Testing sur macOS et dans un simulateur d’iPhone, plus les suites du trousseau dans l’app d’exemple.

### Ce qui est inclus

| Domaine | Types |
| --- | --- |
| Trousseau | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| Chiffrement et hachage | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `MessageAuthenticator`, `SecureRandom`, `ConstantTime` |
| Chiffrement de bout en bout | `PublicKeyCipher`, `KeyDerivation.sharedKey(privateKey:peerPublicKey:salt:info:outputByteCount:)`, `Keychain.keyAgreementKey(forKey:)` |
| Signatures | `SigningKey`, `VerifyingKey`, `SignatureAlgorithm`, `Keychain.signingKey(forKey:algorithm:)` |
| Tokens signés | `JWTVerifier`, `JWTSigner`, `JWTClaims`, `JWTAlgorithm` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| Biométrie | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| Certificate pinning | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| Mots de passe à usage unique | `TOTP`, `HOTP`, `OTPAuthURI` |
| Intégrité de l’appareil | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| Journaux et écrans | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Démarrage rapide

**1. Ajouter le paquet**

Dans Xcode, choisissez **File › Add Package Dependencies…** et saisissez l’URL du dépôt :

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Collez-la dans le champ de recherche en haut à droite de la fenêtre. Laissez **Dependency Rule** sur
**Up to Next Major Version** à partir de `2.2.0`, puis cliquez sur **Add Package**. Dans la fenêtre
suivante, choisissez la cible de votre app à côté de **iOSSecurityTools** et cliquez de nouveau sur
**Add Package**.

**2. Importer le module**

```swift
import iOSSecurityTools
```

Placez cette ligne en haut du fichier Swift où vous utilisez le paquet, sous `import SwiftUI`.

**3. L’utiliser**

Dans une nouvelle app Xcode (**File › New › Project… › App**), remplacez tout le contenu de
`ContentView.swift` par :

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

Choisissez un simulateur d’iPhone et appuyez sur **Run** (⌘R). Touchez le bouton : l’app crée une
clé dans le trousseau, chiffre la note avec elle, stocke les octets chiffrés, les relit et affiche
"Decrypted: Meet at 7 pm". `.privacyShield()` recouvre l’écran d’un cadenas pendant que l’app est en
arrière-plan, de sorte que le sélecteur d’apps n’affiche pas la note.

## Installation

### Swift Package Manager

Dans Xcode, choisissez **File › Add Package Dependencies…** et saisissez l’URL du dépôt :

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Ou ajoutez-le aux `dependencies` de votre `Package.swift` :

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.2.0")
],
targets: [
    .target(name: "YourApp", dependencies: [
        .product(name: "iOSSecurityTools", package: "iOSSecurityTools")
    ])
]
```

La version 2.2.0 reprend le code de chiffrement à clé publique, de signature, de HMAC et de tokens de SwiftCrypto-Pro, qui est archivé ; le [CHANGELOG](CHANGELOG.md) fait correspondre ses types à ceux de ce paquet.

La version 2.0.0 (octobre 2026) est la première version du paquet actuel. La version précédente,
1.0.0 (février 2026), est une autre base de code : en juin 2026, ses sources ont été remplacées par
du code factice, et en octobre 2026 le paquet a été reconstruit de zéro, avec des tests.
[CHANGELOG.md](CHANGELOG.md) liste les changements.

Une app macOS a besoin d’une équipe de développement sous **Signing & Capabilities** pour utiliser
le trousseau ; les apps iOS et le simulateur n’ont besoin de rien de plus. Pour Face ID, ajoutez
`NSFaceIDUsageDescription` à l’Info.plist de l’app.

## Utilisation

Les exemples ci-dessous sont copiés depuis
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift).
L’app d’exemple et la suite de tests compilent ce fichier, et les tests exécutent les exemples qui
n’ont besoin ni d’invite ni de réseau.

### Stocker un token dans le trousseau

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Exiger Face ID pour une valeur

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Chiffrer un enregistrement

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Envoyer un message que seul un appareil peut lire

```swift
func endToEndSample() throws -> String {
    // On the receiving device: create a key pair once and publish the 32-byte public key.
    let deviceKey = PublicKeyCipher.PrivateKey()   // or Keychain.keyAgreementKey(forKey:)
    let published = deviceKey.publicKey.rawRepresentation

    // On any sender, your server included: no shared secret needed.
    let recipient = try PublicKeyCipher.publicKey(rawRepresentation: published)
    let envelope = try PublicKeyCipher.seal("See you at 7", to: recipient)

    // Back on the device: only its private key opens the envelope.
    return try PublicKeyCipher.openString(envelope, using: deviceKey)   // "See you at 7"
}
```

L’enveloppe n’indique pas qui l’a envoyée et peut être renvoyée par quiconque l’a enregistrée : le [guide du chiffrement de bout en bout](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/encryptingendtoend) présente l’authentification de l’expéditeur, les numéros de message et l’accord de clés pour les longues conversations.

### Signer et vérifier des données

```swift
func signatureSample() throws -> Bool {
    let signingKey = SigningKey()                     // Ed25519; SigningKey(algorithm: .p256) for P-256
    let export = Data("orders.csv contents".utf8)
    let signature = try signingKey.signature(for: export)

    // Anyone with the public key (raw, DER or PEM) can check the file.
    let publicKey = try VerifyingKey(pemRepresentation: signingKey.publicKey.pemRepresentation)
    return publicKey.isValidSignature(signature, for: export)   // true
}
```

### Vérifier un token signé

```swift
func tokenSample() throws -> String? {
    // Your server signs the token; here a key made in place stands in for it.
    let serverKey = SigningKey()
    let token = try JWTSigner(signingKey: serverKey).sign(JWTClaims(
        issuer: "https://auth.example.com", subject: "user-42", audience: ["ios-app"],
        expiration: Date().addingTimeInterval(600)
    ))

    // The app checks the signature, the algorithm, exp, nbf, iss and aud before trusting it.
    let verifier = try JWTVerifier(publicKey: serverKey.publicKey,
                                   issuer: "https://auth.example.com", audience: "ios-app")
    return try verifier.verify(token).subject   // "user-42"
}
```

Le [guide des tokens](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/verifyingsignedtokens) énumère chaque contrôle dans l’ordre et ce qui n’est pas pris en charge (RSA, jeux JWK, tokens chiffrés).

### Vérifier le PIN de verrouillage de l’app

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Afficher des codes à usage unique à partir d’un code QR

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

### Épingler les clés d’un serveur

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

Le [guide du pinning](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) explique comment obtenir les pins de votre propre
serveur et les déployer sans enfermer les utilisateurs dehors.

### Vérifier l’appareil

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

### Garder les secrets hors des journaux

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

`SensitiveDataRedactor` ne compare à ses noms secrets que les clés en ASCII simple (`A`–`Z`,
`a`–`z`, `0`–`9`, `_`, `-`, `.` et espaces) ; la valeur de toute autre clé est masquée par
défaut, car des lettres semblables, des caractères invisibles et des séquences d’échappement
peuvent déguiser un nom secret. Les corps JSON, de formulaire et multipart sont lus par un
analyseur ; un corps qu’il ne peut pas analyser entièrement est omis sous la forme
`[body omitted: N bytes, <type>]`, de même qu’un corps qu’un analyseur de serveur courant
pourrait découper autrement en champs, comme une limite multipart après un saut de ligne seul
ou un formulaire contenant `;`.
Un corps de plus de 256 Kio est omis lui aussi (`maximumBodySize` ; une app peut relever la limite,
au prix de jusqu’à environ 40 octets de mémoire pour chaque octet du corps), et le JSON est lu sur
64 niveaux d’objets et de tableaux au plus et sur quatre documents imbriqués au plus, JSON dans les
chaînes compris, ce qui borne la pile qu’une entrée hostile peut occuper ; une chaîne qui en
contient davantage est masquée en entier. Les documents trouvés dans une entrée lisent en tout au
plus quatre fois sa longueur, ce qui borne le temps ; le texte au-delà de ce budget est masqué en
entier, tout comme, sans être lu, un texte de 2^28 scalaires (256 Mi) ou plus.
Un champ dont le nom est à un endroit et la valeur à un autre, comme dans
`{"name":"X-Api-Key","value":…}`, dans une opération JSON Patch ou SCIM sur `/password` ou dans
`[["Authorization","…"]]`, a sa valeur masquée en entier quand le nom est secret ou n’est pas en
ASCII simple. Un hôte d’URL qui n’est ni un nom fait de libellés ASCII ni une adresse, qui porte
un numéro de carte ou un jeton, ou qui nomme un secret, la valeur pouvant se trouver dans l’hôte
lui-même (`myapp://pin/4831`, dont l’hôte est `pin`, ou `https://pin-4831.example.com`) est écrit `scheme://[redacted]`,
sans port, chemin ni query, et le nom d’un en-tête de partie multipart n’est écrit que s’il fait
partie de ceux qu’une partie porte. Des valeurs des en-têtes de partie, seules celles de
`Content-Length` (un à douze chiffres ASCII) et de `Content-Transfer-Encoding` (`7bit`, `8bit`,
`binary`, `base64` ou `quoted-printable`) sont écrites, sous cette forme et sans jamais être lues
comme texte libre ; toute autre valeur devient `[redacted]`. Une URL de plus de 64 segments de chemin ou de 128 paramètres,
ou dont le chemin est résolu différemment selon les
serveurs (un segment point comme dans `/pin/./4831`, un `;` comme dans `/a;pin/4831`, un `.`, `/`,
`\`, `;` ou `%` échappé), n’est enregistrée qu’avec son schéma et son hôte, et une
adresse e-mail ne montre que la première lettre de son nom, dans n’importe quelle écriture
(`ayşe.yılmaz@gmail.com` devient `a•••@gmail.com`).
Les noms qui ne sont pas en ASCII simple comptent comme secrets même quand ils sont écrits comme
valeurs : la valeur à côté d’un champ qui porte un nom (`name`, `label`, `type`, `id`, …) comme
`Şifre`, `ⓟⓘⓝ` ou `🔑` est masquée.
Un nom qui contient un saut de ligne ou un autre caractère de contrôle compte comme secret, quoi
qu’il dise, dans un champ qui contient un nom, et ailleurs quand il nomme un secret une fois ses
caractères de contrôle retirés ou lus comme des espaces
(`{"ParameterKey":"DbPassword\n","ParameterValue":…}`) ; une courte chaîne faite seulement de
caractères de contrôle (`"\n"`) compte aussi, tandis que `{"message":"Hello\nWorld","id":"7"}` garde
`id`, et dans `redact(url:)` le segment qui
suit un segment de chemin qui n’est pas un nom en ASCII simple devient `:id` (`/şifre/…`,
`/a,b/…`).
Dans le texte libre, le premier nom secret masque tout ce qui le suit dans ce texte ; cela masque
trop, volontairement. Masquer trop est un choix de conception. Six règles fixent où le texte est
coupé, et aucune ne tient de liste de variantes : le premier caractère hors d’un alphabet sûr
(lettres, marques et chiffres de toute écriture, l’espace ASCII, la tabulation et les sauts de
ligne, et l’ASCII imprimable), si bien qu’un séparateur ressemblant comme `꞉` ou `→`, un emoji ou
un caractère de contrôle le coupe, de même qu’une lettre ou un chiffre dont la forme de
compatibilité n’est pas dans cet alphabet (`🄁` donne `0,`) ; toute séquence d’échappement
(`%3D`, `&colon;`, `\075`), qui n’est jamais décodée — en texte libre, toute séquence
d’échappement par barre oblique inverse coupe le texte, c’est-à-dire toute barre oblique inverse
que ne suit pas une espace, une tabulation ou un saut de ligne ASCII (`login pa\x{73}sword
hunter2` garde `login `, et un chemin Windows comme `\\nas\backup` est masqué dès sa première
barre oblique inverse) ;
un mot de plus de 256 caractères ; une clé qui n’est pas autorisée (toute
clé sauf `status`, `method`, `path`, `duration_ms`, `count` et les clés que vous fournissez), aussi
entre guillemets de toute sorte (`"`, `'`, accent grave), où elle coupe le texte au guillemet
ouvrant
(`cache miss for "session Qz9Wk7rX": refetching` devient `cache miss for [redacted]`), ou comme
première chaîne d’un tableau de deux éléments ; une balise, car dans le texte libre la première
balise coupe le texte, quelle qu’elle soit (`<user>`, `<_id>`, `</a>`, `<!--`) : tout `<` qui
n’est suivi ni d’une espace, d’une tabulation, d’un saut de ligne ou d’un chiffre ASCII, ni de `=`,
ni de la fin du texte le coupe ; et un nom secret,
avec ou sans séparateur, aussi écrit comme valeur comme `name="password"`. Un mot est comparé par
son squelette ASCII avec une seule règle de joker : une lettre, un signe ou un nombre hors ASCII
sans forme ASCII compte pour rien ou pour une lettre quelconque, si bien que `piꞏn`, `tokeın` et
`tokenꞏs` se lisent `pin`, `token` et `tokens`, et qu’un tel caractère mis à la place d’une lettre
est trouvé (`pɑssword`, `tͦken`, `passw〇rd`
et `t၀ken` : un chiffre décimal d’une autre écriture est un tel nombre).
Un guillemet qui ne se ferme pas sur sa ligne coupe le
texte à ce guillemet, si bien que rien n’apparaît d’une clé entre guillemets contenant un saut de
ligne. Le texte est
coupé jusqu’à sa fin et pas seulement jusqu’à la fin de la ligne : `login user=bob status=401`
devient `login user=[redacted]`, et un corps multipart écrit dans un journal
est masqué à partir de son premier en-tête, une property list à partir de sa première balise.
Une URL dans du texte libre n’est affichée que si elle est propre — `scheme://host` et un chemin
facultatif de lettres ASCII, de chiffres, de `.`, `_`, `-` et `/`, dont l’hôte et les segments ne
nomment aucun secret, suivie d’une espace, d’un saut de ligne, de la fin du texte ou d’un seul `.`,
`,`, `!` ou `)` avant l’un d’eux — et toute autre URL coupe le texte là où elle commence, aussi celle
que suit un guillemet, `>`, un accent grave ou un `?`, `#` ou `;` (`see https://x.example/a?page=2 ok`
et `see https://x.example/a'#token` deviennent `see [redacted]` ; `allowedQueryParameters` ne s’applique qu’à `redact(url:)`). Un `:`
entre des chiffres ne fait partie d’un nombre que si ses deux côtés sont des nombres d’une même
forme (`12:30:45`, `10.0.0.1:8080`, `42:10`) ; après une clé qui se termine par des chiffres
(`user1:2345`), avant une lettre (`id 7:9hunter2`) ou avant cinq chiffres ou plus (`1:482913`),
c’est un séparateur. Un numéro de carte, un IBAN, une adresse e-mail ou un jeton écrit à travers
une tabulation verticale, un saut de page ou un séparateur de ligne Unicode est trouvé en entier,
et le texte est masqué à partir de son début.
Le masquage est un filet de
sécurité, pas une garantie : il est conçu pour les secrets journalisés par accident. L’entrée
structurée (JSON, formulaires, corps multipart et en-têtes de leurs parties, URL et leurs hôtes)
est sûre par défaut, et ce qu’il n’y comprend pas est masqué ; les noms des clés structurées sont
affichés et seules les valeurs qu’elles portent sont masquées. Dans le texte libre, un nom écrit
sans séparateur dont deux lettres ou plus sont remplacées par des lettres ressemblantes
(`pɑsswoʀd hunter2`) n’est pas forcément trouvé quand rien avant lui ne coupe le texte : c’est un
déguisement délibéré, alors qu’une lettre, un signe ou un nombre mis à la place d’une lettre est
trouvé (`tͦken hunter2`). Le
[guide des journaux](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
décrit les règles pour le texte libre, ce qu’elles coûtent et ce qu’elles ne trouvent pas.

### Lier un compte à l’appareil

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Limites connues

Ces limites sont connues et pas encore corrigées :

- Un nom qui contient un caractère de contrôle masque les membres à côté de lui, quoi qu’il dise,
  quand un champ qui contient un nom ou le premier élément d’une paire le contient
  (`{"name":"Hello\nWorld","value":"x"}` masque `value`), et ailleurs quand il nomme un secret une
  fois ses caractères de contrôle retirés ou lus comme des espaces (`{"note":"pass\nword","id":"7"}`
  masque `id`).
- Une clé compte `token` et `secret` seulement comme mot ou à sa fin et `pw` seulement comme mot,
  donc `tokenvalue`, `TOKENID`, `secretvalue`, `secrethash`, `userpw` et `dbpw` montrent leur valeur
  ; marquez ces propriétés avec `@Redacted`.
- Une courte chaîne faite seulement de caractères de contrôle et d’espaces masque tous les membres à
  côté d’elle, même là où elle ne signifie rien (`{"title":"\n","data":"x"}` masque `data`), tandis
  qu’une chaîne de plus de 256 scalaires est lue comme du texte.

## Démo

Écrans de l’app d’exemple SecurityLab sur un simulateur d’iPhone, capturés depuis l’app en cours
d’exécution par [`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh) :

| Intégrité                                                                                                                                                                       | Coffre                                                                                                                          | Codes à usage unique                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Rapport d’intégrité dans le simulateur : contrôle du jailbreak non applicable, simulateur détecté, débogueur, bibliothèques injectées et proxy sans anomalie" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="Une note chiffrée dans le trousseau sur 46 octets puis relue, et un PIN vérifié par rapport à son hachage stocké" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="Un code TOTP à six chiffres issu d’un URI otpauth, avec un anneau qui décompte les secondes restantes" width="260"></picture> |

| Masquage                                                                                                                                               | Écran de confidentialité                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="Un texte de journal contenant un e-mail, un mot de passe, un token bearer et un numéro de carte, avec en dessous la version masquée" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="Une vue des détails d’une carte recouverte par l’écran de confidentialité, avec un symbole de cadenas" width="260"></picture> |

Pour lancer l’app, ouvrez `SecurityLab.xcodeproj`, dans [`Examples/SecurityLab`](Examples/SecurityLab), avec Xcode, choisissez un simulateur d’iPhone ou **My Mac**, puis appuyez sur **Run**. Elle contient aussi le démarrage rapide, un écran Messages qui scelle un message pour la clé de l’appareil, le signe et vérifie un token signé, ainsi qu’un écran de certificate pinning qui se connecte à un serveur et liste les pins de sa chaîne ; [Examples/README.md](Examples/README.md) donne les détails.

## Documentation

Référence de l’API et articles :

- [Référence de l’API](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, publiée sur GitHub Pages depuis `master`)
- Générez-la en local dans Xcode avec **Product › Build Documentation**, ou en ligne de commande :

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Guides

- [Premiers pas](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — ajouter le paquet, chiffrer une note dans le trousseau et recouvrir l’écran
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Stocker des secrets](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — accessibilité, protection biométrique, clés de chiffrement, hachages de PIN et clés
  Secure Enclave ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Épingler des certificats](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — obtenir les pins, choisir un pin de secours, déployer en mode simple signalement et gérer
  l’expiration ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Détecter les appareils compromis](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — ce que voit chaque contrôle d’intégrité, ce qu’il ne peut pas voir, et quand recourir à
  App Attest ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Le chiffrement de bout en bout](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/encryptingendtoend)
  — paires de clés de l’appareil, scellement pour une clé publique, authentification de l’expéditeur, signatures et HMAC
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/EncryptingEndToEnd.md)).
- [Vérifier les tokens signés](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/verifyingsignedtokens)
  — ce que contrôle `JWTVerifier`, comment lire vos propres claims et comment signer des tokens
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/VerifyingSignedTokens.md)).
- [Garder les secrets hors des journaux](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, les masques, le redactor et l’écran de confidentialité
  ([source](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Prérequis

| Plateforme | Version minimale |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| Chaîne d’outils | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` n’est pas disponible sur tvOS et watchOS, qui n’ont pas de biométrie. La CI
compile avec le Xcode par défaut de l’image de runner `macos-26` de GitHub. Le paquet est développé
avec Xcode 27.

## Architecture

- `Sources/iOSSecurityTools/<Area>/` contient un dossier par domaine : `Keychain`, `Crypto`, `Signing`, `Tokens`, `Random`, `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`, `Redaction` et `Privacy`. Tout est un type valeur `Sendable`, sauf `PinningURLSessionDelegate`, que `URLSession` impose d’écrire sous forme de classe.
- Le paquet appelle directement les frameworks d’Apple — Security pour le trousseau et l’évaluation de confiance, CryptoKit pour AES-GCM, ChaCha20-Poly1305, HPKE, X25519, Ed25519, ECDSA P-256, HKDF, HMAC et la Secure Enclave, CommonCrypto pour PBKDF2, LocalAuthentication pour la biométrie — et n’implémente que ce qui leur manque : les formats d’enveloppe, l’encodage SubjectPublicKeyInfo et PEM des pins et des clés, le format compact des JWT, la troncature HOTP/TOTP, Base32, le format de hachage PHC et l’analyseur de masquage. Il n’y a aucune arithmétique de chiffrement, de hachage ou de courbe qui lui soit propre.
- Les erreurs sont typées (`throws(KeychainError)`, `throws(CipherError)`, ...) et chaque cas
  d’enum a une description. Les limites des valeurs qui viennent de l’extérieur de l’app sont
  vérifiées avant tout traitement.
- Le code qui lit l’état du système (contrôles d’intégrité, `LAContext`) passe par de petits
  protocoles internes ; les tests exercent ainsi chaque branche avec des doublures et vérifient
  aussi l’implémentation réelle.
- Ce que le paquet ne fait pas fait partie de la conception : pas de `ptrace` deny-attach, pas de
  method swizzling, pas de lecture des structures privées de dyld. Cela casse d’une version de
  l’OS à l’autre et se contourne facilement ; le [guide de l’intégrité](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  renvoie plutôt vers App Attest.
- La CI exécute `swift test` sur macOS et `xcodebuild test` sur un simulateur d’iPhone, compile pour
  les cinq plateformes, compile l’app d’exemple pour iOS et macOS, exécute ses tests dans l’app et
  publie la documentation DocC.

Pour lancer les tests en local :

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

Un bundle de tests sans app hôte n’a pas l’entitlement du trousseau sur le simulateur ; les suites
de tests du trousseau du paquet s’y exécutent donc dans l’app d’exemple :

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Feuille de route

- Un wrapper App Attest (`DCAppAttestService`) avec un exemple de vérification côté serveur.
- Ajouter le paquet au Swift Package Index ; `.spi.yml` est déjà dans le dépôt.

## Contribuer

Les contributions sont les bienvenues. Lisez le [guide de contribution](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) et le [code de conduite](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md) avant d’ouvrir une pull request. Signalez les problèmes de sécurité en privé, comme indiqué dans la [politique de sécurité](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md).

## Licence

Publié sous licence MIT. Voir [LICENSE](LICENSE).
