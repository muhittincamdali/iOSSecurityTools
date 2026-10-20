<!-- i18n-source: README.md@805f7f93502ff39528591b4f81b896e4bfbe25f8 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-zh-CN-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-zh-CN-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-zh-CN-light.svg" alt="iOSSecurityTools: 面向 Apple 应用的钥匙串、加密、证书固定、一次性验证码和完整性检查。"></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="CI 状态"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="最新版本: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="支持的平台: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="语言版本: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="许可证: MIT"></picture></a>
</p>

<p align="center">
<a href="#快速开始"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-zh-CN-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-zh-CN-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-zh-CN-light.svg" alt="开始使用"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-zh-CN-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-zh-CN-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-zh-CN-light.svg" alt="文档"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-zh-CN-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-zh-CN-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-zh-CN-light.svg" alt="示例"></picture></a>
</p>

> 本文是英文 README 的译文。如两者内容不一致，以英文版为准。

<!-- brand:end -->

一个面向 iOS、macOS、tvOS、watchOS 和 visionOS 应用的 Swift 安全组件包：钥匙串存储、认证加密、PIN 哈希、Secure Enclave 密钥、证书固定、一次性密码、设备完整性检查和日志脱敏。它适合希望正确实现这些功能、又不想研究 Security framework 的 C API 的应用开发者。每个类型都会校验收到的输入，并抛出带类型的错误而不是崩溃，因此来自二维码、服务器或文件的值不会让应用陷入崩溃。该软件包没有任何依赖。

## 亮点

- **无需手写字典的钥匙串** —— `Keychain` 可以存储数据、字符串和 `Codable` 值，在首次使用时创建加密密钥，并可要求 Face ID、Touch ID 或设备密码；这一限制由钥匙串本身强制执行，而不是靠 `LAContext` 外面的一个 `if`。
- **能发现篡改的加密** —— `DataCipher` 写出 AES-256-GCM 或 ChaCha20-Poly1305 信封，信封中自带版本、算法和 nonce；任何一个字节被改动、密钥错误或关联数据错误，都会导致解密失败。同时提供 HKDF、PBKDF2 和 PHC 格式的 PIN 哈希。
- **不会把用户锁在门外的证书固定** —— `PinningPolicy` 要求提供备用 pin，支持子域名、过期日期和仅报告模式，并且仍要求系统自身的信任评估通过。
- **提供信号，而非承诺** —— `IntegrityInspector` 以 `Codable` 报告的形式给出越狱文件、调试器、模拟器、hook 库和系统代理的检测结果；文档也会说明攻击者能够隐藏哪些内容。
- **机密不会出现在日志和截图中** —— `@Redacted` 在任何地方都输出 `<redacted>`；`SensitiveDataRedactor` 会清除银行卡号、电子邮件、token 和机密字段；`.privacyShield()` 会在 App 切换器和屏幕录制期间遮住视图。脱敏器只把纯 ASCII 的键与机密名称比较，其他任何键默认都会被脱敏；JSON、表单和 multipart 请求体会经过解析，无法解析的请求体以及服务器可能以不同方式拆分字段的请求体会被省略。自由文本在第一个触发点处截断：安全字母表之外的字符、转义序列、长单词、不被允许的键或机密名称。
- **经受过恶意输入的测试** —— RFC 4226、6238 和 5869 的测试向量，由独立实现生成的信封和哈希，来自测试 PKI 的证书链，NaN 和无穷大的日期，`Int.min` 和 `Int.max`，过大和重复的 URI 参数：在 macOS 和 iPhone 模拟器上共有 456 个 Swift Testing 测试，另外还有示例应用内部的钥匙串测试套件。

### 包含的内容

| 领域 | 类型 |
| --- | --- |
| 钥匙串 | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| 加密与哈希 | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| 生物识别 | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| 证书固定 | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| 一次性密码 | `TOTP`, `HOTP`, `OTPAuthURI` |
| 设备完整性 | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| 日志与屏幕 | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## 快速开始

**1. 添加软件包**

在 Xcode 中选择 **File › Add Package Dependencies…**，然后输入仓库地址：

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

将地址粘贴到窗口右上角的搜索框中。保持 **Dependency Rule** 为从 `2.1.0` 起的 **Up to Next Major Version**，然后点击 **Add Package**。在下一个窗口中，在 **iOSSecurityTools** 旁选择你的 App target，再次点击 **Add Package**。

**2. 导入模块**

```swift
import iOSSecurityTools
```

把这一行放在使用该软件包的 Swift 文件顶部，位于 `import SwiftUI` 之下。

**3. 开始使用**

在一个新的 Xcode App 项目中（**File › New › Project… › App**），用下面的代码替换 `ContentView.swift` 的全部内容：

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

选择一个 iPhone 模拟器并点击 **Run**（⌘R）。点击按钮后，应用会在钥匙串中创建一个密钥，用它加密这条笔记，存储加密后的字节，再读回并显示 "Decrypted: Meet at 7 pm"。`.privacyShield()` 会在应用进入后台时用一个锁屏覆盖画面，因此 App 切换器不会显示这条笔记。

## 安装

### Swift Package Manager

在 Xcode 中选择 **File › Add Package Dependencies…**，然后输入仓库地址：

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

或者将其添加到 `Package.swift` 的 `dependencies` 中：

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

2.0.0 版（2026 年 10 月）是当前软件包的首个发布版本。更早的 1.0.0 版（2026 年 2 月）是另一套代码：2026 年 6 月，它的源代码被替换成了占位代码，2026 年 10 月，该软件包连同测试一起被完全重写。变更列表见 [CHANGELOG.md](CHANGELOG.md)。

macOS 应用要使用钥匙串，需要在 **Signing & Capabilities** 中设置开发团队；iOS 应用和模拟器无需额外设置。若要使用 Face ID，请在应用的 Info.plist 中添加 `NSFaceIDUsageDescription`。

## 使用方法

下面的示例复制自 [`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift)。示例应用和测试套件都会编译这个文件，测试会运行其中不需要弹出提示或联网的示例。

### 在钥匙串中存储 token

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### 要求用 Face ID 访问某个值

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### 加密一条记录

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### 校验应用锁 PIN

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### 根据二维码显示一次性验证码

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

### 固定服务器的密钥

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

[证书固定指南](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)介绍了如何获取你自己服务器的 pin，以及如何在不把用户锁在门外的前提下逐步上线。

### 检查设备

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

### 让机密远离日志

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

`SensitiveDataRedactor` 只把纯 ASCII 的键（`A`–`Z`、`a`–`z`、`0`–`9`、`_`、`-`、`.` 和空格）与机密名称比较。形近字母、不可见字符和转义序列都可能伪装机密名称，因此其他任何键的值默认都会被脱敏。JSON、表单和 multipart 请求体由解析器读取；无法完整解析的请求体会以 `[body omitted: N bytes, <type>]` 的形式省略。常见服务器解析器可能以不同方式拆分字段的请求体（例如单独换行符之后的 multipart 边界，或含有 `;` 的表单）也同样会被省略。超过 256 KiB 的请求体同样会被省略（`maximumBodySize`；应用可以调高这一上限，代价是请求体每个字节最多约占 60 字节内存）；JSON 最多读取 64 层对象和数组以及 4 层相互嵌套的文档（字符串中的 JSON 也计算在内），因此恶意输入可占用的栈空间是有上限的；包含更多层的字符串会被整体脱敏。在一个输入中找到的所有文档合计最多读取输入长度的四倍，因此耗时也有上限；超出这一预算的文本会被整体脱敏。名称和值分处两处的字段（如 `{"name":"X-Api-Key","value":…}`、针对 `/password` 的 JSON Patch 或 SCIM 操作，以及 `[["Authorization","…"]]`），只要名称是机密名称或不是纯 ASCII，其值就会被整体脱敏。既不是由 ASCII 标签组成的名称、也不是地址，或者含有卡号或令牌的 URL 主机，会写成 `scheme://[redacted]`；multipart 部分的头部名称只有在属于部分所携带的头部时才会写出。路径段超过 64 个或参数超过 128 个的 URL 只记录协议和主机。电子邮件地址无论使用哪种文字，都只显示名称的第一个字母（`ayşe.yılmaz@gmail.com` 会变成 `a•••@gmail.com`）。非 ASCII 的名称即使作为值写出，也视为机密名称：承载名称的字段（`name`、`label`、`type`、`id` 等）若为 `Şifre`、`ⓟⓘⓝ` 或 `🔑` 这样的名称，其旁边的值会被脱敏。在自由文本中，第一个机密名称会隐藏该文本中它之后的所有内容；这是有意多隐藏。多隐藏是设计上的选择。文本在哪里被截断由五条规则决定，没有一条维护变体列表：安全字母表（任何文字的字母、附加符号和数字，ASCII 空格、制表符和换行，以及可打印 ASCII）之外的第一个字符，因此像 `꞉` 或 `→` 这样的形近分隔符、表情符号或控制字符都会截断文本；任何从不解码的转义序列（`%3D`、`&colon;`、`\075`）；超过 256 个字符的单词；不被允许的键（`status`、`method`、`path`、`duration_ms`、`count` 以及你传入的键之外的任何键），也包括作为二元素数组的第一个字符串或作为元素标签出现的键；以及机密名称，无论有无分隔符，也包括像 `name="password"` 这样作为值写出的名称。文本被截到末尾，而不只是截到行尾：`login user=bob status=401` 会变成 `login user=[redacted]`，写入日志的 multipart 正文或属性列表从第一个头部或键开始被隐藏。自由文本中的 URL 只有在其中没有留给后续文本的内容时，才会保留它后面的文本：它的查询、片段或 `;` 参数会在其标记之后立即截断文本，除非每个参数都在 `allowedQueryParameters` 中且带有值；以 `=` 或 `:` 结尾，或者最后一个路径段或主机是机密名称的 URL，会在它之后截断文本（`see https://x.example/a?token= hunter2` 会变成 `see https://x.example/a?[redacted]`）。数字之间的 `:` 只有在数字之后才是数字的一部分（`12:30`、`10.0.0.1:8080`）；在以数字结尾的键（`user1:2345`）之后，它是分隔符。脱敏是安全网，不是保证：它为意外写入日志的机密而设计。结构化输入（JSON、表单、multipart 正文及其各部分的头部、URL 及其主机）默认是安全的，其中无法理解的内容都会被脱敏。在自由文本中，没有分隔符、又用两个或更多形近字母伪装的名称（`pɑsswoʀd hunter2`），如果之前没有任何内容截断文本，就不保证能被找到。[日志指南](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)说明了自由文本的规则、它们的代价以及它们找不到的内容。

### 将账户绑定到设备

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## 演示

SecurityLab 示例应用在 iPhone 模拟器上的界面，由 [`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh) 从运行中的应用截取：

| 完整性                                                                                              | 保险库                                                                                   | 一次性验证码                                                                       |
| --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="模拟器中的完整性报告：越狱检查不适用，检测到模拟器，调试器、注入库和代理均为正常" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="一条笔记被加密为 46 字节存入钥匙串并读回，以及一个 PIN 与其存储的哈希比对" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="由 otpauth URI 生成的六位 TOTP 验证码，旁边的圆环倒计时显示剩余秒数" width="260"></picture> |

| 脱敏                                                                                             | 隐私屏障                                                |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="一段包含电子邮件、密码、bearer token 和银行卡号的日志文本，下方是脱敏后的版本" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="银行卡详情视图被带锁图标的隐私屏障遮住" width="260"></picture> |

要运行该应用，请用 Xcode 打开 [`Examples/SecurityLab`](Examples/SecurityLab) 中的 `SecurityLab.xcodeproj`，选择一个 iPhone 模拟器或 **My Mac**，然后点击 **Run**。应用中还包含快速开始示例，以及一个证书固定页面，它会连接服务器并列出其证书链的 pin；详情见 [Examples/README.md](Examples/README.md)。

## 文档

API 参考文档与文章：

- [API 参考](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)（DocC，从 `master` 发布到 GitHub Pages）
- 在 Xcode 中通过 **Product › Build Documentation** 在本地构建，或使用命令行：

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## 指南

- [快速入门](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted) —— 添加软件包，把一条笔记加密存入钥匙串，并遮住屏幕（[源文件](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)）。
- [存储机密](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets) —— 可访问性、生物识别保护、加密密钥、PIN 哈希和 Secure Enclave 密钥（[源文件](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)）。
- [证书固定](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) —— 获取 pin、选择备用 pin、仅报告模式的逐步上线以及过期处理（[源文件](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)）。
- [检测被入侵的设备](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices) —— 每项完整性检查能看到什么、看不到什么，以及何时应使用 App Attest（[源文件](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)）。
- [让机密远离日志](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs) —— `Redacted`、掩码、脱敏器和隐私屏障（[源文件](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)）。

## 系统要求

| 平台 | 最低版本 |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| 工具链 | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` 在没有生物识别功能的 tvOS 和 watchOS 上不可用。CI 使用 GitHub `macos-26` runner 镜像自带的默认 Xcode 构建。该软件包使用 Xcode 27 开发。

## 架构

- `Sources/iOSSecurityTools/<Area>/` 中每个功能领域对应一个文件夹：`Keychain`、`Crypto`、`Random`、`SecureEnclave`、`Biometrics`、`Pinning`、`OneTimePassword`、`Integrity`、`Redaction` 和 `Privacy`。除了 `URLSession` 要求必须是类的 `PinningURLSessionDelegate` 之外，所有类型都是 `Sendable` 的值类型。
- 软件包直接调用 Apple 的 framework —— 用 Security 处理钥匙串和信任评估，用 CryptoKit 处理 AES-GCM、ChaCha20-Poly1305、HKDF、HMAC 和 Secure Enclave，用 CommonCrypto 处理 PBKDF2，用 LocalAuthentication 处理生物识别 —— 只实现它们所缺少的部分：信封格式、用于 pin 的 SubjectPublicKeyInfo 编码、HOTP/TOTP 截断、Base32、PHC 哈希格式和脱敏扫描器。
- 错误是带类型的（`throws(KeychainError)`、`throws(CipherError)` 等），每个枚举 case 都有描述。来自应用外部的值会在执行任何处理之前先检查其限制。
- 读取系统状态的代码（完整性检查、`LAContext`）都经过小型的内部 protocol，因此测试可以用 fake 对象覆盖每个分支，同时也会检查真实的实现。
- 软件包不做什么，同样是设计的一部分：不使用 `ptrace` deny-attach，不使用 method swizzling，不读取私有的 dyld 结构。这些做法在不同系统版本之间容易失效，也很容易被绕过；[完整性指南](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)建议改用 App Attest。
- CI 会在 macOS 上运行 `swift test`，在 iPhone 模拟器上运行 `xcodebuild test`，为全部五个平台构建，为 iOS 和 macOS 构建示例应用，在应用内运行它的测试，并发布 DocC 文档。

在本地运行测试：

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

在模拟器上，没有宿主应用的测试 bundle 不具备钥匙串 entitlement，因此软件包的钥匙串测试套件在那里是在示例应用内运行的：

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## 路线图

- 提供一个 App Attest 封装（`DCAppAttestService`），并附带服务端验证示例。
- 将该软件包加入 Swift Package Index；`.spi.yml` 已在仓库中。

## 参与贡献

欢迎参与贡献。提交 pull request 之前，请先阅读[贡献指南](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md)和[行为准则](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md)。如发现安全问题，请按照[安全策略](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md)私下报告。

## 许可证

基于 MIT 许可证发布。详见 [LICENSE](LICENSE)。
