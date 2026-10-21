<!-- i18n-source: README.md@72c6a3c0d9670618c43accdb704574b6810e25b5 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ru-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ru-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ru-light.svg" alt="iOSSecurityTools: Связка ключей, шифрование, пиннинг, одноразовые коды и проверки целостности для приложений Apple."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="Статус CI"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Последняя версия: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Поддерживаемые платформы: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Версия языка: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="Лицензия: MIT"></picture></a>
</p>

<p align="center">
<a href="#быстрый-старт"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ru-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ru-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ru-light.svg" alt="Начать"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ru-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ru-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ru-light.svg" alt="Документация"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ru-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ru-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ru-light.svg" alt="Примеры"></picture></a>
</p>

> Это перевод README на английском языке. Если они расходятся, актуальна английская версия.

<!-- brand:end -->

Swift-пакет с набором компонентов безопасности для приложений на iOS, macOS, tvOS, watchOS и
visionOS: хранение в связке ключей, шифрование с проверкой подлинности, хеши PIN-кодов, ключи
Secure Enclave, пиннинг сертификатов, одноразовые пароли, проверки целостности устройства и
маскирование данных в логах. Он предназначен для разработчиков приложений, которым нужно
правильно реализовать всё это, не изучая C API фреймворка Security. Каждый тип проверяет то, что
получает, и вместо падения выбрасывает типизированную ошибку, поэтому значения из QR-кода, от
сервера или из файла не могут привести приложение к аварийному завершению. У пакета нет
зависимостей.

## Основные возможности

- **Связка ключей без словарей** — `Keychain` хранит данные, строки и значения `Codable`, создаёт
  ключи шифрования при первом использовании и может требовать Face ID, Touch ID или код-пароль;
  это обеспечивает сама связка ключей, а не `if` вокруг `LAContext`.
- **Шифрование, которое обнаруживает подмену** — `DataCipher` записывает конверты AES-256-GCM или
  ChaCha20-Poly1305, в которых хранятся их версия, алгоритм и nonce; любой изменённый байт,
  неверный ключ или неверные связанные данные приводят к ошибке расшифровки. В комплекте HKDF,
  PBKDF2 и хеши PIN-кодов в формате PHC.
- **Пиннинг, который не блокирует пользователей** — `PinningPolicy` требует резервный пин,
  поддерживает поддомены, сроки действия и режим «только отчёты» и при этом по-прежнему требует,
  чтобы проходила собственная проверка доверия системы.
- **Сигналы, а не обещания** — `IntegrityInspector` сообщает о файлах джейлбрейка, отладчике,
  симуляторе, библиотеках для хукинга и системном прокси в виде отчёта `Codable`, а в документации
  сказано, что от него может скрыть злоумышленник.
- **Секреты не попадают в логи и скриншоты** — `@Redacted` везде выводит `<redacted>`,
  `SensitiveDataRedactor` затирает номера карт, адреса электронной почты, токены и секретные
  поля, а `.privacyShield()` закрывает экраны в переключателе приложений и во время записи
  экрана. Редактор сравнивает с секретными именами только ключи из простого ASCII, а значения
  любых других ключей по умолчанию скрывает; тела JSON, форм и multipart разбираются парсером,
  а тела, которые не удалось разобрать или которые сервер мог бы разделить на поля иначе,
  пропускаются. Свободный текст обрезается на первом триггере: символе вне безопасного алфавита,
  escape-последовательности, длинном слове, неразрешённом ключе или секретном имени.
- **Проверено на враждебных входных данных** — тестовые векторы RFC 4226, 6238 и 5869, конверты и
  хеши, созданные независимой реализацией, цепочки сертификатов из тестовой PKI, даты NaN и
  бесконечности, `Int.min` и `Int.max`, слишком большие и повторяющиеся параметры URI: 493 тестов
  Swift Testing на macOS и в симуляторе iPhone, а также наборы тестов связки ключей внутри
  примера приложения.

### Что входит в пакет

| Область | Типы |
| --- | --- |
| Связка ключей | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| Шифрование и хеширование | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| Биометрия | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| Пиннинг сертификатов | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| Одноразовые пароли | `TOTP`, `HOTP`, `OTPAuthURI` |
| Целостность устройства | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| Логи и экраны | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Быстрый старт

**1. Добавьте пакет**

В Xcode выберите **File › Add Package Dependencies…** и введите адрес репозитория:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Вставьте его в поле поиска в правом верхнем углу окна. Оставьте **Dependency Rule** в значении
**Up to Next Major Version** начиная с `2.1.0` и нажмите **Add Package**. В следующем окне выберите
таргет вашего приложения рядом с **iOSSecurityTools** и ещё раз нажмите **Add Package**.

**2. Импортируйте модуль**

```swift
import iOSSecurityTools
```

Поместите эту строку в начало Swift-файла, где вы используете пакет, под `import SwiftUI`.

**3. Используйте**

В новом приложении Xcode (**File › New › Project… › App**) замените всё содержимое
`ContentView.swift` на:

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

Выберите симулятор iPhone и нажмите **Run** (⌘R). Нажмите кнопку: приложение создаст ключ в связке
ключей, зашифрует им заметку, сохранит зашифрованные байты, прочитает их обратно и покажет
"Decrypted: Meet at 7 pm". `.privacyShield()` закрывает экран замком, пока приложение находится в
фоне, поэтому переключатель приложений не показывает заметку.

## Установка

### Swift Package Manager

В Xcode выберите **File › Add Package Dependencies…** и введите адрес репозитория:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Или добавьте его в `dependencies` вашего `Package.swift`:

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

Версия 2.0.0 (октябрь 2026 года) — первый релиз текущего пакета. Предыдущий релиз, 1.0.0
(февраль 2026 года), — это другая кодовая база: в июне 2026 года её исходный код заменили кодом-заглушкой, а в октябре 2026 года пакет был с нуля переписан вместе с тестами. Список изменений —
в [CHANGELOG.md](CHANGELOG.md).

Чтобы использовать связку ключей в приложении для macOS, в **Signing & Capabilities** должна быть
указана команда разработки; приложениям для iOS и симулятору ничего дополнительного не нужно. Для
Face ID добавьте `NSFaceIDUsageDescription` в Info.plist приложения.

## Использование

Примеры ниже скопированы из
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift).
Пример приложения и набор тестов компилируют этот файл, а тесты запускают примеры, которым не нужны
ни запросы к пользователю, ни сеть.

### Сохранить токен в связке ключей

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Требовать Face ID для значения

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Зашифровать запись

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Проверить PIN-код блокировки приложения

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Показать одноразовые коды из QR-кода

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

### Закрепить ключи сервера

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

[Руководство по пиннингу](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) показывает, как получить пины вашего сервера и
внедрить их, не блокируя пользователей.

### Проверить устройство

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

### Не пускать секреты в логи

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

`SensitiveDataRedactor` сравнивает с секретными именами только ключи из простого ASCII (`A`–`Z`,
`a`–`z`, `0`–`9`, `_`, `-`, `.` и пробелы); значение любого другого ключа по умолчанию
скрывается: похожие буквы, невидимые символы и escape-последовательности могут замаскировать
секретное имя. Тела JSON, форм и multipart читаются парсером; тело, которое не удаётся разобрать
полностью, пропускается как `[body omitted: N bytes, <type>]`. Так же пропускается тело,
которое распространённый серверный парсер мог бы разделить на поля иначе, например граница
multipart после одиночного перевода строки или форма с `;`.
Тело больше 256 КиБ тоже пропускается (`maximumBodySize`; приложение может поднять этот предел,
ценой до примерно 60 байт памяти на каждый байт тела), а JSON читается не глубже 64 уровней
объектов и массивов и не больше четырёх вложенных друг в друга документов, считая JSON внутри
строк, что ограничивает стек, который может занять враждебный ввод; строка, в которой их больше,
скрывается целиком.
Документы, найденные внутри одного ввода, вместе читают не больше четырёх его длин, что
ограничивает время; текст сверх этого бюджета скрывается целиком.
Поле, у которого имя записано в одном месте, а значение в другом, как в
`{"name":"X-Api-Key","value":…}`, в операции JSON Patch или SCIM над `/password` или в
`[["Authorization","…"]]`, скрывается со всем значением, если имя секретное или не состоит из
простого ASCII. Хост URL, который не является ни именем из меток ASCII, ни адресом, или содержит
номер карты или токен, записывается как `scheme://[redacted]`, а имя заголовка части multipart
записывается, только если это один из заголовков, которые несёт часть. URL, в котором больше 64
сегментов пути или 128 параметров, записывается только как схема и хост, а у адреса электронной
почты видна только первая буква имени, в любой письменности (`ayşe.yılmaz@gmail.com` превращается в
`a•••@gmail.com`).
Имена не из простого ASCII считаются секретными, даже когда они записаны как значения: значение
рядом с полем, которое хранит имя (`name`, `label`, `type`, `id`, …), например `Şifre`, `ⓟⓘⓝ` или
`🔑`, скрывается.
В свободном тексте первое секретное имя скрывает всё, что идёт после него в этом тексте; это
намеренно скрывает больше, чем нужно. Скрывать лишнее — решение, принятое намеренно. Где
обрезается текст, задают шесть правил, и ни одно не хранит список вариантов: первый символ вне
безопасного алфавита (буквы, знаки и цифры любой письменности, пробел ASCII, табуляция и переводы
строки, а также печатаемый ASCII), так что похожий разделитель вроде `꞉` или `→`, эмодзи или
управляющий символ обрезают текст; любая escape-последовательность (`%3D`, `&colon;`, `\075`),
которая никогда не декодируется; слово длиннее 256 символов; ключ, который не разрешён (любой,
кроме `status`, `method`, `path`, `duration_ms`, `count` и ключей, которые вы передадите), в том
числе в кавычках, где он обрезает текст по открывающей кавычке
(`cache miss for "session Qz9Wk7rX": refetching` превращается в `cache miss for [redacted]`), или как
первая строка массива из двух элементов; тег разметки, ведь в свободном тексте первый тег разметки
обрезает текст, каким бы ни был тег (`<user>`, `</a>`, `<!--`); и секретное имя, с разделителем или
без, в том числе записанное как значение, например `name="password"`. Слово сравнивается по его
ASCII-скелету: буквы без формы в ASCII отбрасываются, так что `piꞏn`, `tokeın` и `tokenꞏs`
читаются как `pin`, `token` и `tokens`, а имя засчитывается и без одной буквы там, где буква была
отброшена (`pɑssword`). Кавычка, которая не закрывается в своей строке, обрезает текст по этой
кавычке, так что от ключа в кавычках с переводом строки внутри ничего не видно. Текст
обрезается до его конца, а не только до конца строки: `login user=bob status=401` превращается в
`login user=[redacted]`, а тело multipart, записанное в лог, скрывается начиная
с первого заголовка, а property list — начиная с первого тега.
URL в свободном тексте показывается, только если он чистый — `scheme://host` и необязательный путь
из букв ASCII, цифр, `.`, `_`, `-` и `/`, хост и сегменты которого не называют секрет, а после него
идёт пробел, перевод строки или знак препинания в конце предложения, — а любой другой URL обрезает
текст там, где начинается (`see https://x.example/a?page=2 ok` превращается в `see [redacted]`;
`allowedQueryParameters` действует только для `redact(url:)`). `:` между цифрами является частью
числа только после числа (`12:30`, `10.0.0.1:8080`); после ключа, который заканчивается цифрами
(`user1:2345`), это
разделитель.
Скрытие — это страховка, а не гарантия: оно рассчитано на секреты,
попавшие в логи случайно. Структурированный ввод (JSON, формы, тела multipart и заголовки их
частей, URL и их хосты) безопасен по умолчанию: то, что в нём непонятно, скрывается; имена ключей
структурированного ввода показываются, а скрываются только значения под ними. В свободном тексте
имя без разделителя, в котором две или более буквы заменены похожими (`pɑsswoʀd hunter2`),
не обязательно будет найдено, если до него ничто не обрезало текст.
[Руководство по логам](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
описывает правила для свободного текста, их цену и то, чего они не находят.

### Привязать учётную запись к устройству

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Демо

Экраны примера приложения SecurityLab в симуляторе iPhone, снятые с работающего приложения
скриптом [`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh):

| Целостность                                                                                                                                                       | Хранилище                                                                                                                            | Одноразовые коды                                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Отчёт о целостности в симуляторе: проверка на джейлбрейк неприменима, симулятор обнаружен, отладчик, внедрённые библиотеки и прокси не найдены" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="Заметка, зашифрованная в связке ключей в виде 46 байт и прочитанная обратно, и PIN-код, сверенный с сохранённым хешем" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="Шестизначный код TOTP из URI otpauth и кольцо, отсчитывающее оставшиеся секунды" width="260"></picture> |

| Маскирование                                                                                                                         | Экран конфиденциальности                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="Текст лога с адресом электронной почты, паролем, bearer-токеном и номером карты и ниже его замаскированная версия" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="Экран с данными карты, закрытый экраном конфиденциальности со значком замка" width="260"></picture> |

Чтобы запустить приложение, откройте `SecurityLab.xcodeproj` из папки
[`Examples/SecurityLab`](Examples/SecurityLab) в Xcode, выберите симулятор iPhone или **My Mac** и
нажмите **Run**. В нём также есть быстрый старт и экран пиннинга сертификатов, который
подключается к серверу и выводит список пинов его цепочки; подробности — в
[Examples/README.md](Examples/README.md).

## Документация

Справочник API и статьи:

- [Справочник API](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, публикуется на GitHub Pages из ветки `master`)
- Соберите его локально в Xcode командой **Product › Build Documentation** или из командной строки:

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Руководства

- [Начало работы](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — добавьте пакет, зашифруйте заметку в связке ключей и закройте экран
  ([исходник](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Хранение секретов](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — доступность, биометрическая защита, ключи шифрования, хеши PIN-кодов и ключи Secure Enclave
  ([исходник](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Пиннинг сертификатов](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — как получить пины, выбрать резервный, внедрять в режиме «только отчёты» и учитывать срок
  действия ([исходник](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Обнаружение скомпрометированных устройств](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — что видит каждая проверка целостности, чего не видит и когда использовать App Attest
  ([исходник](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Как не пускать секреты в логи](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, маски, редактор и экран конфиденциальности
  ([исходник](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Требования

| Платформа | Минимальная версия |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| Инструменты | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` недоступен на tvOS и watchOS, где нет биометрии. CI собирает проект с
Xcode по умолчанию из образа раннера `macos-26` на GitHub. Пакет разрабатывается в Xcode 27.

## Архитектура

- В `Sources/iOSSecurityTools/<Area>/` по одной папке на область: `Keychain`, `Crypto`, `Random`,
  `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`, `Redaction` и
  `Privacy`. Всё — значимые типы `Sendable`, кроме `PinningURLSessionDelegate`: `URLSession`
  требует, чтобы он был классом.
- Пакет напрямую вызывает фреймворки Apple — Security для связки ключей и проверки доверия,
  CryptoKit для AES-GCM, ChaCha20-Poly1305, HKDF, HMAC и Secure Enclave, CommonCrypto для PBKDF2,
  LocalAuthentication для биометрии — и сам реализует только то, чего в них нет: формат конверта,
  кодирование SubjectPublicKeyInfo для пинов, усечение HOTP/TOTP, Base32, формат хешей PHC и
  сканер для маскирования.
- Ошибки типизированы (`throws(KeychainError)`, `throws(CipherError)`, ...), и у каждого случая
  enum есть описание. Для значений, приходящих извне приложения, ограничения проверяются до начала
  любой работы.
- Код, который читает состояние системы (проверки целостности, `LAContext`), работает через
  небольшие внутренние протоколы, поэтому тесты проходят все ветви на заглушках и дополнительно
  проверяют настоящую реализацию.
- То, чего пакет не делает, — тоже часть замысла: никакого `ptrace` deny-attach, никакого method
  swizzling, никакого чтения приватных структур dyld. Такие приёмы ломаются между версиями ОС и
  легко обходятся; [руководство по целостности](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  вместо них советует App Attest.
- CI запускает `swift test` на macOS и `xcodebuild test` в симуляторе iPhone, собирает проект для
  всех пяти платформ, собирает пример приложения для iOS и macOS, запускает его тесты внутри
  приложения и публикует документацию DocC.

Запустить тесты локально:

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

У тестового бандла без хост-приложения в симуляторе нет entitlement для связки ключей, поэтому
наборы тестов связки ключей из пакета запускаются там внутри примера приложения:

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## План развития

- Обёртка над App Attest (`DCAppAttestService`) с примером проверки на стороне сервера.
- Добавить пакет в Swift Package Index; `.spi.yml` уже есть в репозитории.

## Участие в разработке

Мы рады вашему участию. Перед открытием pull request прочитайте [руководство для участников](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) и [кодекс поведения](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md). О проблемах безопасности сообщайте конфиденциально, как описано в [политике безопасности](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md).

## Лицензия

Распространяется по лицензии MIT. Подробнее — в файле [LICENSE](LICENSE).
