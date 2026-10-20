<!-- i18n-source: README.md@7f2232f6110eda04e383d2a0b2cadbfafead4407 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-tr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-tr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-tr-light.svg" alt="iOSSecurityTools: Apple uygulamaları için keychain, şifreleme, pinning, tek kullanımlık kodlar ve bütünlük denetimi."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="CI durumu"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Son sürüm: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Desteklenen platformlar: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Dil sürümü: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="Lisans: MIT"></picture></a>
</p>

<p align="center">
<a href="#hızlı-başlangıç"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-tr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-tr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-tr-light.svg" alt="Başlayın"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-tr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-tr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-tr-light.svg" alt="Dokümantasyon"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-tr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-tr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-tr-light.svg" alt="Örnekler"></picture></a>
</p>

> Bu belge İngilizce README'nin çevirisidir. İkisi arasında fark varsa güncel olan İngilizce sürümdür.

<!-- brand:end -->

iOS, macOS, tvOS, watchOS ve visionOS uygulamaları için güvenlik yapı taşlarından oluşan bir
Swift paketi: keychain ile saklama, doğrulanmış şifreleme, PIN özetleri, Secure Enclave anahtarları,
sertifika pinning'i, tek kullanımlık parolalar, cihaz bütünlüğü denetimleri ve günlüklerde veri
maskeleme. Bu parçaların Security framework'ünün C API'lerini incelemeden doğru biçimde
yazılmasını isteyen uygulama geliştiricileri için hazırlandı. Her tür, aldığı değeri doğrular ve
çökmek yerine tipli bir hata fırlatır; böylece bir QR kodundan, sunucudan veya dosyadan gelen
değerler uygulamayı çökertemez. Paketin hiçbir bağımlılığı yoktur.

## Öne çıkanlar

- **Sözlük kullanmadan Keychain** — `Keychain` veri, metin ve `Codable` değerleri saklar,
  şifreleme anahtarlarını ilk kullanımda oluşturur ve Face ID, Touch ID ya da cihaz parolasını
  zorunlu kılabilir; bu zorunluluğu `LAContext` etrafındaki bir `if` değil, keychain'in kendisi
  uygular.
- **Kurcalamayı fark eden şifreleme** — `DataCipher`, sürümünü, algoritmasını ve nonce'unu kendi
  içinde taşıyan AES-256-GCM veya ChaCha20-Poly1305 zarfları yazar; değişen tek bir bayt, yanlış
  anahtar ya da yanlış ilişkili veri şifre çözmeyi başarısız kılar. HKDF, PBKDF2 ve PHC
  biçiminde PIN özetleri de pakete dahildir.
- **Kullanıcıyı dışarıda bırakmayan pinning** — `PinningPolicy` yedek bir pin ister; alt alan
  adlarını, son kullanma tarihlerini ve yalnızca raporlama kipini destekler ve yine de sistemin
  kendi güven değerlendirmesinin başarılı olmasını şart koşar.
- **Söz değil, sinyal** — `IntegrityInspector`; jailbreak dosyalarını, hata ayıklayıcıyı,
  simülatörü, hooking kütüphanelerini ve sistem proxy'sini `Codable` bir rapor olarak bildirir;
  dokümantasyon da bir saldırganın bunlardan nelerini gizleyebileceğini açıkça söyler.
- **Gizli veriler günlüklerde ve ekran görüntülerinde görünmez** — `@Redacted` her yerde
  `<redacted>` yazdırır, `SensitiveDataRedactor` kart numaralarını, e-posta adreslerini,
  token'ları ve gizli alanları siler, `.privacyShield()` ise uygulama değiştiricide ve ekran
  kaydı sırasında görünümleri örter. Maskeleyici yalnız düz ASCII anahtarları gizli adlarla
  karşılaştırır, diğer her anahtarı varsayılan olarak maskeler; JSON, form ve multipart
  gövdeleri ayrıştırılır; ayrıştırılamayan gövdeler ve bir sunucunun alanlara farklı
  bölebileceği gövdeler atlanır.
- **Düşmanca girdiyle sınandı** — RFC 4226, 6238 ve 5869 test vektörleri, bağımsız bir
  gerçekleştirmenin ürettiği zarflar ve özetler, test PKI'sından sertifika zincirleri, NaN ve
  sonsuz tarihler, `Int.min` ve `Int.max`, aşırı büyük ve tekrarlanan URI parametreleri: macOS'ta
  ve bir iPhone simülatöründe 351 Swift Testing testi, ayrıca örnek uygulamanın içinde çalışan
  keychain test setleri.

### Pakette neler var

| Alan | Türler |
| --- | --- |
| Keychain | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| Şifreleme ve özetleme | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| Biyometri | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| Sertifika pinning'i | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| Tek kullanımlık parolalar | `TOTP`, `HOTP`, `OTPAuthURI` |
| Cihaz bütünlüğü | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| Günlükler ve ekranlar | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Hızlı başlangıç

**1. Paketi ekleyin**

Xcode'da **File › Add Package Dependencies…** menüsünü seçin ve depo adresini girin:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Adresi pencerenin sağ üstündeki arama alanına yapıştırın. **Dependency Rule** ayarını
`2.1.0` sürümünden itibaren **Up to Next Major Version** olarak bırakın, ardından **Add Package**
düğmesine tıklayın. Açılan pencerede **iOSSecurityTools** satırının yanından uygulama hedefinizi
seçin ve yeniden **Add Package**'a tıklayın.

**2. Modülü içe aktarın**

```swift
import iOSSecurityTools
```

Bu satırı, paketi kullandığınız Swift dosyasının en üstüne, `import SwiftUI` satırının altına
ekleyin.

**3. Kullanın**

Yeni bir Xcode uygulamasında (**File › New › Project… › App**) `ContentView.swift` dosyasının
tüm içeriğini şununla değiştirin:

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

Bir iPhone simülatörü seçin ve **Run**'a (⌘R) basın. Düğmeye dokunun: uygulama keychain'de bir
anahtar oluşturur, notu bu anahtarla şifreler, şifrelenmiş baytları saklar, geri okur ve
"Decrypted: Meet at 7 pm" yazısını gösterir. `.privacyShield()`, uygulama arka plandayken ekranı
bir kilitle örter; böylece uygulama değiştirici notu göstermez.

## Kurulum

### Swift Package Manager

Xcode'da **File › Add Package Dependencies…** menüsünü seçin ve depo adresini girin:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Ya da `Package.swift` dosyanızdaki `dependencies` listesine ekleyin:

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

2.0.0 sürümü (Ekim 2026), paketin güncel halinin ilk sürümüdür. Daha önceki 1.0.0 sürümü
(Şubat 2026) farklı bir kod tabanıdır: Haziran 2026'da kaynak kodu yer tutucu kodla
değiştirildi, Ekim 2026'da paket testlerle birlikte sıfırdan yeniden yazıldı.
Değişikliklerin listesi [CHANGELOG.md](CHANGELOG.md) dosyasındadır.

Bir macOS uygulamasının keychain'i kullanabilmesi için **Signing & Capabilities** altında bir
geliştirme ekibi seçilmiş olmalıdır; iOS uygulamaları ve simülatör için ek bir şey gerekmez. Face
ID için uygulamanın Info.plist dosyasına `NSFaceIDUsageDescription` ekleyin.

## Kullanım

Aşağıdaki örnekler
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift)
dosyasından kopyalanmıştır. Örnek uygulama ve test seti bu dosyayı birlikte derler; testler,
onay penceresi veya ağ gerektirmeyen örnekleri çalıştırır.

### Keychain'de bir token saklama

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Bir değer için Face ID zorunlu kılma

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Bir kaydı şifreleme

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Uygulama kilidi PIN'ini doğrulama

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Bir QR kodundan tek kullanımlık kodlar gösterme

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

### Bir sunucunun anahtarlarını sabitleme

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

Kendi sunucunuzun pin'lerini nasıl alacağınızı ve kullanıcıları dışarıda bırakmadan nasıl
devreye alacağınızı [pinning rehberi](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) anlatır.

### Cihazı denetleme

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

### Gizli verileri günlüklerden uzak tutma

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

`SensitiveDataRedactor` gizli adlarla yalnız düz ASCII anahtarları (`A`–`Z`, `a`–`z`, `0`–`9`,
`_`, `-`, `.` ve boşluk) karşılaştırır; benzer harfler, görünmez karakterler ve kaçış dizileri bir
gizli adı gizleyebildiği için diğer her anahtarın değeri varsayılan olarak maskelenir. JSON, form
ve multipart gövdeleri bir ayrıştırıcıyla okunur; tamamen ayrıştıramadığı bir gövdeyi
`[body omitted: N bytes, <type>]` olarak atlar. Yaygın bir sunucu ayrıştırıcısının alanlara
farklı bölebileceği bir gövde de atlanır; örneğin tek başına bir satır sonundan sonra gelen
multipart sınırı ya da `;` içeren bir form.
1 MiB'tan büyük bir gövde de atlanır; JSON, dizelerin içindeki JSON da sayılarak en fazla 64 nesne
ve dizi derinliğinde ve iç içe en fazla dört belge olarak okunur, böylece kötü niyetli bir girdinin
kullanabileceği yığın sınırlı kalır; daha fazlasını içeren bir dize bütünüyle maskelenir.
Adı bir yerde, değeri başka bir yerde duran bir alanın — `{"name":"X-Api-Key","value":…}`,
`/password` üzerinde bir JSON Patch ya da SCIM işlemi veya `[["Authorization","…"]]` — adı gizliyse
ya da düz ASCII değilse değeri bütünüyle maskelenir. 64'ten fazla yol bölümü ya da 128'den fazla
parametresi olan bir URL yalnız şeması ve host'u ile kaydedilir; bir e-posta adresinde, hangi yazı
sisteminde olursa olsun, adın yalnız ilk harfi görünür (`ayşe.yılmaz@gmail.com`, `a•••@gmail.com`
olur).
Değer olarak yazılmış gizli bir ad — `name="password"`, `<string name="api_key">…</string>` ya da
`<key>password</key>` gibi — kendisinden sonra geleni gizler: satırın geri kalanını, XML ya da
HTML'de ayrıca öğenin diğer öznitelik değerlerini ve kapanış etiketine kadarki satırlarını, bir
JSON nesnesinde de diğer üyelerin değerlerini.
Serbest metin bir değeri yalnız izin verilen bir
anahtardan sonra korur (`status`, `method`, `path`, `duration_ms`, `count` ve sizin verdiğiniz
anahtarlar); bu yüzden `user=bob`, `user=[redacted]` olur. Maskeleme bir güvenlik ağıdır, garanti
değildir. Serbest metin kuralını, bedelini ve neleri bulmadığını
[günlük kılavuzu](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
anlatır.

### Bir hesabı cihaza bağlama

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Demo

SecurityLab örnek uygulamasının bir iPhone simülatöründeki ekranları;
[`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh) betiğiyle çalışan
uygulamadan alındı:

| Bütünlük        | Kasa                                                                                                                                             | Tek kullanımlık kodlar |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Simülatörde bütünlük raporu: jailbreak denetimi geçerli değil, simülatör bulundu; hata ayıklayıcı, enjekte edilmiş kütüphaneler ve proxy temiz" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="Keychain'e 46 bayt olarak şifrelenip geri okunan bir not ve saklanan özetiyle karşılaştırılan bir PIN" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="Bir otpauth URI'sinden üretilmiş altı haneli TOTP kodu ve kalan saniyeleri geri sayan bir halka" width="260"></picture> |

| Maskeleme       | Gizlilik kalkanı                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------ |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="İçinde e-posta, parola, bearer token ve kart numarası bulunan bir günlük metni ve altında maskelenmiş hali" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="Gizlilik kalkanının kilit simgesiyle örttüğü bir kart bilgileri ekranı" width="260"></picture> |

Uygulamayı çalıştırmak için [`Examples/SecurityLab`](Examples/SecurityLab) klasöründeki
`SecurityLab.xcodeproj` dosyasını Xcode ile açın, bir iPhone simülatörü ya da **My Mac** seçin ve
**Run**'a basın. Uygulamada ayrıca hızlı başlangıç örneği ve bir sunucuya bağlanıp sertifika
zincirinin pin'lerini listeleyen bir sertifika pinning ekranı da var; ayrıntılar
[Examples/README.md](Examples/README.md) dosyasında.

## Dokümantasyon

API başvuru belgeleri ve makaleler:

- [API başvurusu](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, `master` dalından GitHub Pages'e yayımlanır)
- Yerelde Xcode'da **Product › Build Documentation** ile ya da komut satırından derleyin:

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Rehberler

- [Başlangıç](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — paketi ekleyin, bir notu keychain'e şifreleyerek kaydedin ve ekranı örtün
  ([kaynak](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Gizli verileri saklama](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — erişilebilirlik, biyometrik koruma, şifreleme anahtarları, PIN özetleri ve Secure Enclave
  anahtarları ([kaynak](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Sertifika pinning'i](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — pin'leri alma, yedek seçme, yalnızca raporlama kipiyle devreye alma ve son kullanma
  ([kaynak](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Ele geçirilmiş cihazları algılama](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — her bütünlük denetiminin ne gördüğü, neyi göremediği ve App Attest'in ne zaman kullanılacağı
  ([kaynak](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Gizli verileri günlüklerden uzak tutma](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, maskeler, redactor ve gizlilik kalkanı
  ([kaynak](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Gereksinimler

| Platform | En düşük sürüm |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| Araç zinciri | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator`, biyometrisi olmayan tvOS ve watchOS'ta kullanılamaz. CI, GitHub'ın
`macos-26` runner imajındaki varsayılan Xcode ile derler. Paket Xcode 27 ile geliştirilmektedir.

## Mimari

- `Sources/iOSSecurityTools/<Area>/` her alan için bir klasör içerir: `Keychain`, `Crypto`,
  `Random`, `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`,
  `Redaction` ve `Privacy`. `URLSession`'ın sınıf olmasını şart koştuğu
  `PinningURLSessionDelegate` dışında her şey `Sendable` bir değer türüdür.
- Paket Apple'ın framework'lerini doğrudan çağırır — keychain ve güven değerlendirmesi için
  Security, AES-GCM, ChaCha20-Poly1305, HKDF, HMAC ve Secure Enclave için CryptoKit, PBKDF2 için
  CommonCrypto, biyometri için LocalAuthentication — ve yalnızca bunların sunmadığı parçaları
  kendisi gerçekleştirir: zarf biçimi, pin'ler için SubjectPublicKeyInfo kodlaması, HOTP/TOTP
  kırpma işlemi, Base32, PHC özet biçimi ve maskeleme tarayıcısı.
- Hatalar tiplidir (`throws(KeychainError)`, `throws(CipherError)`, ...) ve her enum durumunun
  bir açıklaması vardır. Uygulamanın dışından gelen değerlerin sınırları, herhangi bir işlem
  yapılmadan önce denetlenir.
- Sistemi okuyan kod (bütünlük denetimleri, `LAContext`) küçük dahili protokollerden geçer;
  böylece testler her dalı sahte nesnelerle çalıştırır ve gerçek gerçekleştirimi de denetler.
- Paketin yapmadıkları da tasarımın parçasıdır: `ptrace` deny-attach yok, method swizzling yok,
  özel dyld yapılarını okuma yok. Bunlar işletim sistemi sürümleri arasında bozulur ve
  aşılması kolaydır; [bütünlük rehberi](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  bunun yerine App Attest'i önerir.
- CI, macOS'ta `swift test` çalıştırır, bir iPhone simülatöründe `xcodebuild test` çalıştırır,
  beş platformun hepsi için derler, örnek uygulamayı iOS ve macOS için derler, testlerini
  uygulamanın içinde çalıştırır ve DocC dokümantasyonunu yayımlar.

Testleri yerelde çalıştırmak için:

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

Ana uygulaması olmayan bir test paketinin simülatörde keychain yetkisi yoktur; bu yüzden
paketin keychain test setleri orada örnek uygulamanın içinde çalışır:

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Yol haritası

- Sunucu tarafı doğrulama örneğiyle birlikte bir App Attest sarmalayıcısı (`DCAppAttestService`).
- Paketi Swift Package Index'e eklemek; `.spi.yml` zaten depoda.

## Katkıda bulunma

Katkılarınızı bekliyoruz. Pull request açmadan önce [katkı rehberini](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) ve [davranış kurallarını](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md) okuyun. Güvenlik açıklarını [güvenlik politikasında](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md) anlatıldığı gibi gizli olarak bildirin.

## Lisans

MIT lisansıyla yayımlanmıştır. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
