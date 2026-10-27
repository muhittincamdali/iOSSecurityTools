<!-- i18n-source: README.md@b30f471d7d7c5223cfb9cd62afebedbf800271e2 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ko-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ko-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ko-light.svg" alt="iOSSecurityTools: Apple 앱을 위한 키체인, 암호화, 인증서 피닝, 일회용 코드, 무결성 검사."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="CI 상태"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="최신 버전: v2.1.1"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="지원 플랫폼: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="언어 버전: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="라이선스: MIT"></picture></a>
</p>

<p align="center">
<a href="#빠른-시작"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ko-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ko-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ko-light.svg" alt="시작하기"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ko-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ko-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ko-light.svg" alt="문서"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ko-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ko-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ko-light.svg" alt="예제"></picture></a>
</p>

> 이 문서는 영어 README의 번역본입니다. 내용이 다를 경우 영어 버전이 최신입니다.

<!-- brand:end -->

iOS, macOS, tvOS, watchOS, visionOS 앱을 위한 보안 구성 요소 모음인 Swift 패키지입니다. 키체인 저장, 인증된 암호화, PIN 해시, Secure Enclave 키, 인증서 피닝, 일회용 비밀번호, 기기 무결성 검사, 로그 마스킹을 제공합니다. Security framework의 C API를 따로 공부하지 않고도 이런 기능을 올바르게 구현하려는 앱 개발자를 위한 패키지입니다. 각 타입은 전달받은 값을 검증하고, 크래시하는 대신 타입이 지정된 에러를 던집니다. 그래서 QR 코드, 서버, 파일에서 온 값 때문에 앱이 중단되지 않습니다. 이 패키지는 의존성이 없습니다.

## 주요 기능

- **딕셔너리 없이 쓰는 키체인** — `Keychain`은 데이터, 문자열, `Codable` 값을 저장하고, 처음 사용할 때 암호화 키를 만들며, Face ID, Touch ID 또는 암호를 요구할 수 있습니다. 이 요구 사항은 `LAContext` 주변의 `if`가 아니라 키체인 자체가 강제합니다.
- **변조를 감지하는 암호화** — `DataCipher`는 버전, 알고리즘, nonce를 스스로 담고 있는 AES-256-GCM 또는 ChaCha20-Poly1305 엔벨로프를 만듭니다. 한 바이트라도 바뀌거나 키 또는 연관 데이터가 틀리면 복호화에 실패합니다. HKDF, PBKDF2, PHC 형식의 PIN 해시도 함께 제공합니다.
- **사용자를 막아 버리지 않는 피닝** — `PinningPolicy`는 백업 핀을 필수로 요구하고, 서브도메인, 만료일, 보고 전용 모드를 지원하며, 시스템 자체의 신뢰 평가도 여전히 통과해야 합니다.
- **약속이 아닌 신호** — `IntegrityInspector`는 탈옥 관련 파일, 디버거, 시뮬레이터, 후킹 라이브러리, 시스템 프록시를 `Codable` 리포트로 알려 줍니다. 공격자가 무엇을 숨길 수 있는지도 문서에 적혀 있습니다.
- **비밀 정보를 로그와 스크린샷에서 지킵니다** — `@Redacted`는 어디에서 출력하든 `<redacted>`로 표시합니다. `SensitiveDataRedactor`는 카드 번호, 이메일, 토큰, 비밀 필드를 가립니다. `.privacyShield()`는 앱 전환기와 화면 녹화 중에 뷰를 가려 줍니다. 리댁터는 순수 ASCII 키만 비밀 이름과 비교하고, 그 밖의 키는 모두 기본으로 가립니다. JSON, 폼, multipart 본문은 파서로 읽고, 파싱할 수 없는 본문과 서버가 필드를 다르게 나눌 수 있는 본문은 생략합니다. 자유 형식 텍스트는 첫 번째 트리거(안전한 알파벳 밖의 문자, 이스케이프, 긴 단어, 허용되지 않은 키, 비밀 이름)에서 잘립니다.
- **악의적인 입력에 맞서 테스트했습니다** — RFC 4226, 6238, 5869 테스트 벡터, 독립된 구현이 만든 엔벨로프와 해시, 테스트용 PKI의 인증서 체인, NaN과 무한대 날짜, `Int.min`과 `Int.max`, 지나치게 크거나 중복된 URI 매개변수까지 다룹니다. macOS와 iPhone 시뮬레이터에서 Swift Testing 테스트 622개를 실행하고, 예제 앱 안에서 키체인 테스트 스위트도 실행합니다.

### 포함된 구성 요소

| 영역 | 타입 |
| --- | --- |
| 키체인 | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| 암호화와 해싱 | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| 생체 인증 | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| 인증서 피닝 | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| 일회용 비밀번호 | `TOTP`, `HOTP`, `OTPAuthURI` |
| 기기 무결성 | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| 로그와 화면 | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## 빠른 시작

**1. 패키지 추가**

Xcode에서 **File › Add Package Dependencies…**를 선택하고 저장소 URL을 입력하세요.

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

창 오른쪽 위의 검색 필드에 붙여 넣으세요. **Dependency Rule**은 `2.1.1`부터 **Up to Next Major Version**으로 두고 **Add Package**를 클릭하세요. 다음 창에서 **iOSSecurityTools** 옆에서 앱 타깃을 선택한 다음 **Add Package**를 다시 클릭하세요.

**2. 모듈 가져오기**

```swift
import iOSSecurityTools
```

이 줄은 패키지를 사용하는 Swift 파일의 맨 위, `import SwiftUI` 아래에 넣으세요.

**3. 사용하기**

새 Xcode 앱(**File › New › Project… › App**)에서 `ContentView.swift`의 내용을 모두 다음 코드로 바꾸세요.

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

iPhone 시뮬레이터를 선택하고 **Run**(⌘R)을 누르세요. 버튼을 탭하면 앱이 키체인에 키를 만들고, 그 키로 메모를 암호화해 암호화된 바이트를 저장한 뒤, 다시 읽어서 "Decrypted: Meet at 7 pm"을 표시합니다. `.privacyShield()`는 앱이 백그라운드에 있는 동안 화면을 잠금 표시로 덮기 때문에 앱 전환기에 메모가 나타나지 않습니다.

## 설치

### Swift Package Manager

Xcode에서 **File › Add Package Dependencies…**를 선택하고 저장소 URL을 입력하세요.

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

또는 `Package.swift`의 `dependencies`에 추가하세요.

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.1.1")
],
targets: [
    .target(name: "YourApp", dependencies: [
        .product(name: "iOSSecurityTools", package: "iOSSecurityTools")
    ])
]
```

2.0.0 버전(2026년 10월)은 현재 패키지의 첫 번째 릴리스입니다. 이전 릴리스인 1.0.0(2026년 2월)은 다른 코드베이스입니다. 2026년 6월에 소스가 자리 표시자 코드로 교체되었고, 2026년 10월에 패키지를 테스트와 함께 처음부터 다시 만들었습니다. 변경 사항은 [CHANGELOG.md](CHANGELOG.md)에서 확인할 수 있습니다.

macOS 앱에서 키체인을 사용하려면 **Signing & Capabilities**에서 개발 팀을 지정해야 합니다. iOS 앱과 시뮬레이터에서는 추가 설정이 필요 없습니다. Face ID를 사용하려면 앱의 Info.plist에 `NSFaceIDUsageDescription`을 추가하세요.

## 사용법

아래 예제는 [`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift)에서 가져왔습니다. 예제 앱과 테스트 스위트가 모두 이 파일을 컴파일하며, 테스트는 프롬프트나 네트워크가 필요 없는 예제를 실행합니다.

### 키체인에 토큰 저장하기

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### 값에 Face ID 요구하기

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### 레코드 암호화하기

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### 앱 잠금 PIN 확인하기

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### QR 코드로 일회용 코드 표시하기

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

### 서버의 키 고정하기

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

[피닝 가이드](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)에서 내 서버의 핀을 얻는 방법과, 사용자를 막아 버리지 않고 단계적으로 적용하는 방법을 설명합니다.

### 기기 확인하기

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

### 비밀 정보를 로그에 남기지 않기

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

`SensitiveDataRedactor`는 순수 ASCII 키(`A`–`Z`, `a`–`z`, `0`–`9`, `_`, `-`, `.`, 공백)만 비밀 이름과 비교합니다. 모양이 비슷한 글자, 보이지 않는 문자, 이스케이프로 비밀 이름을 위장할 수 있으므로 그 밖의 키 값은 기본으로 가려집니다. JSON, 폼, multipart 본문은 파서로 읽고, 완전히 파싱할 수 없는 본문은 `[body omitted: N bytes, <type>]`으로 생략됩니다. 널리 쓰이는 서버 파서가 필드를 다르게 나눌 수 있는 본문(단독 줄바꿈 뒤의 multipart 경계, `;`가 들어간 폼 등)도 같은 방식으로 생략됩니다. 256 KiB를 넘는 본문도 생략됩니다(`maximumBodySize`. 앱이 한도를 올릴 수 있지만, 그 대가로 본문 1바이트마다 최대 약 40바이트의 메모리를 씁니다). JSON은 문자열 안의 JSON까지 합쳐 객체와 배열 64단계, 문서 중첩 4단계까지만 읽으므로 악의적인 입력이 쓸 수 있는 스택에 한도가 있습니다. 그보다 많이 담은 문자열은 통째로 가려집니다. 하나의 입력 안에서 찾은 문서들은 모두 합쳐 입력 길이의 4배까지만 읽으므로 처리 시간에도 한도가 있습니다. 이 예산을 넘는 텍스트는 통째로 가려집니다. 2^28 스칼라(256 Mi) 이상인 텍스트도 읽지 않고 통째로 가려집니다. 이름과 값이 서로 다른 곳에 있는 필드(`{"name":"X-Api-Key","value":…}`, `/password`에 대한 JSON Patch나 SCIM 작업, `[["Authorization","…"]]` 등)는 이름이 비밀 이름이거나 순수 ASCII가 아니면 값 전체가 가려집니다. ASCII 레이블로 된 이름도 주소도 아닌 URL 호스트, 카드 번호나 토큰이 든 호스트, 비밀 이름을 가리키는 호스트(`myapp://pin/4831`의 호스트는 `pin`입니다. 값이 호스트 자체에 있을 수도 있습니다: `https://pin-4831.example.com`)는 포트, 경로, 쿼리 없이 `scheme://[redacted]`로 쓰이고, multipart 파트의 헤더 이름은 파트가 담는 헤더 중 하나일 때만 쓰입니다. 파트 헤더의 값은 `Content-Length`(1~12자리 ASCII 숫자)와 `Content-Transfer-Encoding`(`7bit`, `8bit`, `binary`, `base64`, `quoted-printable`)만 그 형태로 쓰이고, 자유 형식 텍스트로 읽히지 않습니다. 그 밖의 값은 `[redacted]`가 됩니다. 경로 세그먼트가 64개 또는 매개변수가 128개를 넘는 URL, 서버마다 다르게 해석할 수 있는 경로(`/pin/./4831` 같은 점 세그먼트, `/a;pin/4831` 같은 `;`, 이스케이프된 `.`, `/`, `\`, `;`, `%`)를 가진 URL은 스킴과 호스트만 기록됩니다. 이메일 주소는 어떤 문자 체계든 이름의 첫 글자만 보입니다(`ayşe.yılmaz@gmail.com`은 `a•••@gmail.com`이 됩니다). ASCII가 아닌 이름은 값으로 쓰여도 비밀 이름으로 취급됩니다. 이름을 담는 필드(`name`, `label`, `type`, `id` 등)의 이름이 `Şifre`, `ⓟⓘⓝ`, `🔑` 같으면 그 옆의 값이 가려집니다. 줄바꿈이나 다른 제어 문자가 든 이름은 이름을 담는 필드에서는 내용과 관계없이 비밀 이름으로 취급되고, 그 밖의 곳에서는 제어 문자를 빼거나 공백으로 읽었을 때 비밀 이름이 되면 취급됩니다(`{"ParameterKey":"DbPassword\n","ParameterValue":…}`). 제어 문자만으로 된 짧은 문자열(`"\n"`)도 비밀 이름으로 취급되지만, `{"message":"Hello\nWorld","id":"7"}`에서는 `id`가 남습니다. `redact(url:)`에서는 순수 ASCII 이름이 아닌 경로 세그먼트 다음의 세그먼트가 `:id`가 됩니다(`/şifre/…`, `/a,b/…`). 자유 형식 텍스트에서는 첫 번째 비밀 이름이 그 텍스트에서 자신 뒤에 오는 모든 것을 가립니다. 이는 일부러 더 많이 가리는 것입니다. 더 많이 가리는 것은 설계상의 선택입니다. 텍스트를 어디서 자를지는 여섯 가지 규칙이 정하며, 어느 규칙도 변형 목록을 두지 않습니다. 안전한 알파벳(모든 문자 체계의 글자, 결합 기호, 숫자, ASCII 공백·탭·줄바꿈, 출력 가능한 ASCII) 밖의 첫 문자, 곧 `꞉`나 `→` 같은 비슷한 구분 기호, 이모지, 제어 문자가 텍스트를 자릅니다. 호환 분해 형태가 이 알파벳 밖에 있는 글자나 숫자(`🄁`은 `0,`)도 마찬가지입니다. 절대 디코딩하지 않는 모든 이스케이프(`%3D`, `&colon;`, `\075`. 자유 텍스트에서는 백슬래시 이스케이프가 모두 텍스트를 자르며, ASCII 공백·탭·줄바꿈이 뒤따르지 않는 백슬래시는 모두 여기에 해당하므로 `login pa\x{73}sword hunter2`는 `login `만 남고 `\\nas\backup` 같은 Windows 경로도 첫 백슬래시부터 가려짐), 256자를 넘는 단어, 허용되지 않은 키(`status`, `method`, `path`, `duration_ms`, `count`와 직접 넘긴 키를 제외한 모든 키, 어떤 종류든 따옴표(`"`, `'`, 백틱)로 감싼 키와 두 요소 배열의 첫 문자열로 나타난 것도 포함하며, 따옴표로 감싼 키는 여는 따옴표에서 텍스트를 자르므로 `cache miss for "session Qz9Wk7rX": refetching`은 `cache miss for [redacted]`가 됨), 마크업 태그(자유 형식 텍스트에서는 태그가 무엇이든 첫 번째 마크업 태그가 텍스트를 자릅니다: `<user>`, `<_id>`, `</a>`, `<!--`. 뒤에 ASCII 공백·탭·줄바꿈·숫자, `=`, 텍스트 끝 중 어느 것도 오지 않는 `<`는 모두 텍스트를 자릅니다), 그리고 구분 기호가 있든 없든, `name="password"`처럼 값으로 쓰인 것도 포함한 비밀 이름도 텍스트를 자릅니다. 단어는 ASCII 골격으로, 와일드카드 규칙 하나에 따라 비교합니다. ASCII 형태가 없는 ASCII 밖의 글자, 부호, 숫자는 없는 것으로도, 아무 글자 하나로도 칩니다. 그래서 `piꞏn`, `tokeın`, `tokenꞏs`는 `pin`, `token`, `tokens`로 읽히고, 이름의 한 글자 대신 놓인 그런 문자 하나는 찾아냅니다(`pɑssword`, `tͦken`, `passw〇rd`, `t၀ken`. 다른 문자 체계의 십진 숫자도 그런 숫자입니다). 같은 줄에서 닫히지 않는 따옴표는 그 따옴표에서 텍스트를 자르므로, 줄바꿈이 든 따옴표 키는 아무것도 보이지 않습니다. 줄 끝까지가 아니라 텍스트 끝까지입니다. `login user=bob status=401`은 `login user=[redacted]`가 되고, 로그에 쓰인 multipart 본문은 첫 헤더부터, 프로퍼티 리스트는 첫 태그부터 가려집니다. 자유 형식 텍스트 안의 URL은 깨끗할 때만 표시됩니다. 깨끗한 URL은 `scheme://host`와, ASCII 영문자, 숫자, `.`, `_`, `-`, `/`로만 이루어진 선택적인 경로로 되어 있고, 호스트와 세그먼트가 비밀 이름이 아니며, 뒤에 공백, 줄바꿈, 텍스트 끝, 또는 그 앞에 하나만 놓인 `.`, `,`, `!`, `)`가 오는 URL입니다. 그 밖의 URL은 따옴표, `>`, 백틱, `?`, `#`, `;`가 뒤따르는 URL을 포함해 시작하는 곳에서 텍스트를 자릅니다(`see https://x.example/a?page=2 ok`와 `see https://x.example/a'#token`은 `see [redacted]`가 됩니다. `allowedQueryParameters`는 `redact(url:)`에만 적용됩니다). 숫자 사이의 `:`는 양쪽이 같은 모양의 숫자일 때만 숫자의 일부입니다(`12:30:45`, `10.0.0.1:8080`, `42:10`). 숫자로 끝나는 키(`user1:2345`) 뒤, 글자 앞(`id 7:9hunter2`), 다섯 자리 이상의 숫자 앞(`1:482913`)에서는 구분 기호입니다. 세로 탭, 폼 피드, 유니코드 줄 구분 문자를 사이에 두고 쓴 카드 번호, IBAN, 이메일 주소, 토큰은 통째로 찾아내며, 텍스트는 그 시작부터 가려집니다. 가리기는 안전망이지 보장이 아닙니다. 실수로 로그에 기록된 비밀을 위해 만들었습니다. 구조화된 입력(JSON, 폼, multipart 본문과 그 파트의 헤더, URL과 그 호스트)은 기본적으로 안전하며, 이해하지 못하는 것은 가려집니다. 구조화된 키의 이름은 그대로 보이고 그 아래의 값만 가려집니다. 자유 형식 텍스트에서 구분 기호 없이 쓰고 글자 둘 이상을 비슷한 글자로 바꾼 이름(`pɑsswoʀd hunter2`)은 그 앞에서 텍스트를 자르는 것이 없으면 찾는다고 보장할 수 없습니다. 이는 의도적인 위장이며, 한 글자 대신 놓인 글자, 부호, 숫자 하나는 찾아냅니다(`tͦken hunter2`). 자유 형식 텍스트에 적용하는 규칙과 그 대가, 찾지 못하는 것은 [로그 가이드](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)에서 설명합니다.

### 계정을 기기에 연결하기

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## 알려진 제한

다음 제한은 알려져 있으며 아직 바뀌지 않았습니다.

- 제어 문자가 든 이름은 이름을 담는 필드나 쌍의 첫 요소에 있으면 내용과 관계없이 옆의 멤버를 가리고(`{"name":"Hello\nWorld","value":"x"}`는 `value`를 가립니다), 그 밖의 곳에서는 제어 문자를 빼거나 공백으로 읽었을 때 비밀 이름이 되면 가립니다(`{"note":"pass\nword","id":"7"}`는 `id`를 가립니다).
- 키는 `token`과 `secret`을 단어로 쓰이거나 끝에 올 때만, `pw`는 단어로 쓰일 때만 세므로 `tokenvalue`, `TOKENID`, `secretvalue`, `secrethash`, `userpw`, `dbpw`의 값은 보입니다. 이런 속성에는 `@Redacted`를 붙이세요.
- 제어 문자와 공백만으로 된 짧은 문자열은 아무 의미가 없는 곳에서도 옆의 모든 멤버를 가립니다(`{"title":"\n","data":"x"}`는 `data`를 가립니다). 256 스칼라를 넘는 문자열은 텍스트로 읽힙니다.

## 데모

iPhone 시뮬레이터에서 실행한 SecurityLab 예제 앱의 화면입니다. [`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh)로 실행 중인 앱에서 캡처했습니다.

| 무결성                                                                                                                               | 보관함                                                                                            | 일회용 코드                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="시뮬레이터의 무결성 리포트: 탈옥 검사는 해당 없음, 시뮬레이터 감지, 디버거, 주입된 라이브러리, 프록시는 이상 없음" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="46바이트로 키체인에 암호화해 저장했다가 다시 읽은 메모와, 저장된 해시와 대조한 PIN" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="otpauth URI로 만든 여섯 자리 TOTP 코드와 남은 시간을 초 단위로 세는 링" width="260"></picture> |

| 마스킹                                                                                                        | 개인정보 보호막                                                                |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="이메일, 비밀번호, bearer 토큰, 카드 번호가 들어 있는 로그 텍스트와 그 아래의 마스킹된 결과" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="자물쇠 기호가 있는 개인정보 보호막이 덮고 있는 카드 상세 화면" width="260"></picture> |

앱을 실행하려면 [`Examples/SecurityLab`](Examples/SecurityLab)의 `SecurityLab.xcodeproj`를 Xcode로 열고, iPhone 시뮬레이터나 **My Mac**을 선택한 다음 **Run**을 누르세요. 빠른 시작 예제와 함께, 서버에 연결해 인증서 체인의 핀을 나열하는 인증서 피닝 화면도 있습니다. 자세한 내용은 [Examples/README.md](Examples/README.md)를 참고하세요.

## 문서

API 레퍼런스와 문서:

- [API 레퍼런스](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/) (DocC, `master`에서 GitHub Pages로 게시)
- Xcode에서 **Product › Build Documentation**으로 로컬에서 빌드하거나 명령줄에서 빌드하세요.

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## 가이드

- [시작하기](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted) — 패키지를 추가하고, 메모를 암호화해 키체인에 저장하고, 화면을 가립니다([소스](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [비밀 정보 저장](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets) — 접근 가능 조건, 생체 인증 보호, 암호화 키, PIN 해시, Secure Enclave 키([소스](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [인증서 피닝](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) — 핀 얻기, 백업 핀 고르기, 보고 전용 모드로 단계적 적용하기, 만료([소스](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [손상된 기기 감지](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices) — 각 무결성 검사가 볼 수 있는 것과 볼 수 없는 것, 그리고 App Attest를 써야 하는 때([소스](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [비밀 정보를 로그에 남기지 않기](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs) — `Redacted`, 마스크, 리댁터, 개인정보 보호막([소스](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## 요구 사항

| 플랫폼 | 최소 버전 |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| 툴체인 | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator`는 생체 인증이 없는 tvOS와 watchOS에서는 사용할 수 없습니다. CI는 GitHub의 `macos-26` 러너 이미지에 포함된 기본 Xcode로 빌드합니다. 이 패키지는 Xcode 27로 개발합니다.

## 아키텍처

- `Sources/iOSSecurityTools/<Area>/`에는 영역마다 폴더가 하나씩 있습니다. `Keychain`, `Crypto`, `Random`, `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`, `Redaction`, `Privacy`입니다. `URLSession`이 클래스를 요구하는 `PinningURLSessionDelegate`를 제외하면 모두 `Sendable` 값 타입입니다.
- 패키지는 Apple의 framework를 직접 호출합니다. 키체인과 신뢰 평가에는 Security, AES-GCM, ChaCha20-Poly1305, HKDF, HMAC, Secure Enclave에는 CryptoKit, PBKDF2에는 CommonCrypto, 생체 인증에는 LocalAuthentication을 사용하고, 그것들에 없는 부분만 직접 구현합니다. 엔벨로프 형식, 핀을 위한 SubjectPublicKeyInfo 인코딩, HOTP/TOTP 절단, Base32, PHC 해시 형식, 마스킹 스캐너입니다.
- 에러는 타입이 지정되어 있고(`throws(KeychainError)`, `throws(CipherError)` 등) 모든 enum case에 설명이 있습니다. 앱 밖에서 들어오는 값은 어떤 작업을 하기 전에 한계를 먼저 검사합니다.
- 시스템을 읽는 코드(무결성 검사, `LAContext`)는 작은 내부 protocol을 거칩니다. 그래서 테스트가 모든 분기를 가짜 객체로 실행하고, 실제 구현도 함께 확인합니다.
- 패키지가 하지 않는 일도 설계의 일부입니다. `ptrace` deny-attach, 메서드 스위즐링, 비공개 dyld 구조체 읽기를 하지 않습니다. 이런 방법은 OS 릴리스마다 깨지고 우회하기도 쉽습니다. 대신 App Attest를 쓰도록 [무결성 가이드](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)에서 안내합니다.
- CI는 macOS에서 `swift test`를, iPhone 시뮬레이터에서 `xcodebuild test`를 실행하고, 다섯 플랫폼 모두를 빌드합니다. 또한 예제 앱을 iOS와 macOS용으로 빌드해 앱 안에서 테스트를 실행하고, DocC 문서를 게시합니다.

로컬에서 테스트를 실행하려면 다음과 같이 하세요.

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

호스트 앱이 없는 테스트 번들은 시뮬레이터에서 키체인 entitlement가 없습니다. 그래서 패키지의 키체인 테스트 스위트는 그곳에서 예제 앱 안에서 실행합니다.

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## 로드맵

- App Attest 래퍼(`DCAppAttestService`)와 서버 측 검증 예제.
- 패키지를 Swift Package Index에 추가하기. `.spi.yml`은 이미 저장소에 있습니다.

## 기여하기

기여를 환영합니다. pull request를 열기 전에 [기여 가이드](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md)와 [행동 강령](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md)을 읽어 주세요. 보안 문제는 [보안 정책](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md)에 따라 비공개로 제보해 주세요.

## 라이선스

MIT 라이선스로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.
