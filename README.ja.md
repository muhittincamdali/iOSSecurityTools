<!-- i18n-source: README.md@7f32b9c6808f9063527af1053a4fb1e3799889af status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ja-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ja-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-ja-light.svg" alt="iOSSecurityTools: Apple アプリ向けのキーチェーン、暗号化、証明書ピンニング、ワンタイムコード、整合性チェック。"></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="CI ステータス"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="最新バージョン: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="対応プラットフォーム: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="言語バージョン: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="ライセンス: MIT"></picture></a>
</p>

<p align="center">
<a href="#クイックスタート"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ja-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ja-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-ja-light.svg" alt="はじめる"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ja-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ja-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-ja-light.svg" alt="ドキュメント"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ja-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ja-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-ja-light.svg" alt="サンプル"></picture></a>
</p>

> このドキュメントは英語版 README の翻訳です。内容が異なる場合は英語版が最新です。

<!-- brand:end -->

iOS、macOS、tvOS、watchOS、visionOS のアプリ向けに、セキュリティの部品をまとめた Swift パッケージです。キーチェーンへの保存、認証付き暗号化、PIN のハッシュ、Secure Enclave の鍵、証明書ピンニング、ワンタイムパスワード、デバイスの整合性チェック、ログのマスキングを含みます。Security framework の C API を学ばなくても、これらを正しく実装したいアプリ開発者のためのものです。各型は受け取った値を検証し、クラッシュする代わりに型付きのエラーを throw します。そのため、QR コードやサーバー、ファイルから受け取った値でアプリが異常終了することはありません。パッケージに依存関係はありません。

## 主な特長

- **辞書を書かずに使えるキーチェーン** — `Keychain` はデータ、文字列、`Codable` の値を保存し、初回の利用時に暗号化キーを作成します。Face ID、Touch ID、パスコードの要求も可能で、その強制は `LAContext` の周りの `if` ではなく、キーチェーン自身が行います。
- **改ざんを検出する暗号化** — `DataCipher` は、バージョン、アルゴリズム、nonce を自身に持つ AES-256-GCM または ChaCha20-Poly1305 のエンベロープを書き出します。1 バイトでも変更されたり、鍵や関連データが誤っていたりすると、復号は失敗します。HKDF、PBKDF2、PHC 形式の PIN ハッシュも付属します。
- **ユーザーを締め出さないピンニング** — `PinningPolicy` はバックアップ用のピンを必須とし、サブドメイン、有効期限、レポートのみのモードに対応します。そのうえで、システム標準の信頼評価に合格することも引き続き求めます。
- **約束ではなくシグナル** — `IntegrityInspector` は、脱獄の痕跡ファイル、デバッガ、シミュレータ、フックするライブラリ、システムプロキシを `Codable` のレポートとして返します。攻撃者がどこまで隠せるかも、ドキュメントに明記しています。
- **秘密情報をログとスクリーンショットから遠ざける** — `@Redacted` はどこで出力しても `<redacted>` と表示します。`SensitiveDataRedactor` は、カード番号、メールアドレス、token、秘密のフィールドを消去します。`.privacyShield()` は、App スイッチャーや画面収録中にビューを覆います。リダクタは純粋な ASCII のキーだけを秘密の名前と比較し、それ以外のキーはすべて既定でマスクします。JSON、フォーム、multipart の本文はパーサーで読み、解析できない本文と、サーバーがフィールドを別の形に分割しうる本文は省略します。自由形式のテキストは最初のトリガー（安全なアルファベットの外にある文字、エスケープ、長い単語、許可されていないキー、秘密の名前）で切られます。
- **悪意ある入力に対するテスト済み** — RFC 4226、6238、5869 のテストベクトル、独立した実装が作成したエンベロープとハッシュ、テスト用 PKI の証明書チェーン、NaN と無限大の日付、`Int.min` と `Int.max`、過大な URI パラメータや重複した URI パラメータ。macOS と iPhone シミュレータで 478 件の Swift Testing テストを実行し、さらにサンプルアプリの中でキーチェーンのテストスイートも実行します。

### 含まれるもの

| 分野 | 型 |
| --- | --- |
| キーチェーン | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| 暗号化とハッシュ | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| 生体認証 | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| 証明書ピンニング | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| ワンタイムパスワード | `TOTP`, `HOTP`, `OTPAuthURI` |
| デバイスの整合性 | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| ログと画面 | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## クイックスタート

**1. パッケージを追加する**

Xcode で **File › Add Package Dependencies…** を選び、リポジトリの URL を入力します。

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

ウィンドウ右上の検索欄に貼り付けます。**Dependency Rule** は `2.1.0` からの **Up to Next Major Version** のままにして、**Add Package** をクリックします。次のウィンドウで、**iOSSecurityTools** の横にあるアプリのターゲットを選び、もう一度 **Add Package** をクリックします。

**2. モジュールをインポートする**

```swift
import iOSSecurityTools
```

この行は、パッケージを使う Swift ファイルの先頭、`import SwiftUI` の下に書きます。

**3. 使ってみる**

新しい Xcode のアプリ（**File › New › Project… › App**）で、`ContentView.swift` の中身をすべて次の内容に置き換えます。

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

iPhone シミュレータを選び、**Run**（⌘R）を押します。ボタンをタップすると、アプリはキーチェーンに鍵を作成し、その鍵でメモを暗号化して、暗号化したバイト列を保存します。それを読み戻して "Decrypted: Meet at 7 pm" と表示します。`.privacyShield()` は、アプリがバックグラウンドにある間、画面をロックの表示で覆います。そのため、App スイッチャーにメモは表示されません。

## インストール

### Swift Package Manager

Xcode で **File › Add Package Dependencies…** を選び、リポジトリの URL を入力します。

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

または `Package.swift` の `dependencies` に追加します。

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

バージョン 2.0.0（2026 年 10 月）は、現行のパッケージとして最初のリリースです。以前の 1.0.0（2026 年 2 月）は別のコードベースです。2026 年 6 月にソースがプレースホルダーのコードに置き換えられ、2026 年 10 月にパッケージはテストとともにゼロから作り直されました。変更内容は [CHANGELOG.md](CHANGELOG.md) にあります。

macOS アプリでキーチェーンを使うには、**Signing & Capabilities** で開発チームを設定する必要があります。iOS アプリとシミュレータでは追加の設定は不要です。Face ID を使うには、アプリの Info.plist に `NSFaceIDUsageDescription` を追加してください。

## 使い方

以下のサンプルは、[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift) からコピーしたものです。サンプルアプリとテストスイートの両方がこのファイルをコンパイルし、テストでは、プロンプトやネットワークを必要としないサンプルを実行します。

### トークンをキーチェーンに保存する

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### 値の読み出しに Face ID を要求する

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### レコードを暗号化する

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### アプリロックの PIN を確認する

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### QR コードからワンタイムコードを表示する

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

### サーバーの鍵をピン留めする

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

自分のサーバーのピンを取得する方法と、ユーザーを締め出さずに段階的に導入する方法は、[ピンニングガイド](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)で説明しています。

### デバイスを確認する

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

### 秘密情報をログに出さない

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

`SensitiveDataRedactor` が秘密の名前と比較するのは、純粋な ASCII のキー（`A`–`Z`、`a`–`z`、`0`–`9`、`_`、`-`、`.`、空白）だけです。似た形の文字、不可視文字、エスケープで秘密の名前を偽装できるため、それ以外のキーの値は既定でマスクされます。JSON、フォーム、multipart の本文はパーサーで読み込み、完全に解析できない本文は `[body omitted: N bytes, <type>]` として省略されます。一般的なサーバーのパーサーがフィールドを別の形に分割しうる本文（単独の改行の後にある multipart の境界や、`;` を含むフォームなど）も同じく省略されます。256 KiB を超える本文も省略されます（`maximumBodySize`。アプリは上限を引き上げられますが、その代わりに本文 1 バイトあたり最大で約 60 バイトのメモリを使います）。JSON は文字列の中の JSON も含めて、オブジェクトと配列の入れ子 64 段、ドキュメントの入れ子 4 段までしか読み込まないため、悪意ある入力が使えるスタックには上限があります。それを超えるものを含む文字列は丸ごとマスクされます。1 つの入力の中で見つかったドキュメントは合計で入力の長さの 4 倍までしか読み込まないため、処理時間にも上限があります。この予算を超えるテキストは丸ごとマスクされます。名前と値が別の場所にあるフィールド（`{"name":"X-Api-Key","value":…}`、`/password` に対する JSON Patch や SCIM の操作、`[["Authorization","…"]]` など）は、名前が秘密の名前であるか純粋な ASCII でない場合、値全体がマスクされます。ASCII のラベルからなる名前でもアドレスでもない URL のホスト、またはカード番号やトークンを含むホストは `scheme://[redacted]` と書かれ、multipart のパートのヘッダー名は、パートが持つヘッダーのひとつである場合にだけ書かれます。パスのセグメントが 64 個、またはパラメータが 128 個を超える URL は、スキームとホストだけが記録されます。メールアドレスは、どの文字体系でも名前の最初の 1 文字だけが表示されます（`ayşe.yılmaz@gmail.com` は `a•••@gmail.com` になります）。ASCII 以外の名前は、値として書かれていても秘密の名前として扱われます。名前を持つフィールド（`name`、`label`、`type`、`id` など）が `Şifre`、`ⓟⓘⓝ`、`🔑` のような名前を持つと、隣の値がマスクされます。自由形式のテキストでは、最初の秘密の名前がそのテキストの中でそれより後にあるものをすべてマスクします。これは意図的に多めにマスクするものです。多めにマスクするのは設計上の選択です。テキストをどこで切るかは 5 つの規則で決まり、どの規則も変種のリストを持ちません。安全なアルファベット（あらゆる文字体系の文字・記号付き文字・数字、ASCII の空白・タブ・改行、印字可能な ASCII）の外にある最初の文字。つまり `꞉` や `→` のような似た形の区切り文字、絵文字、制御文字はテキストを切ります。決してデコードされないあらゆるエスケープ（`%3D`、`&colon;`、`\075`）。256 文字を超える単語。許可されていないキー（`status`、`method`、`path`、`duration_ms`、`count` と渡したキー以外のすべてのキー）。引用符で囲まれたキーも含み、その場合は開き引用符でテキストを切ります（`cache miss for "session Qz9Wk7rX": refetching` は `cache miss for [redacted]` になります）。2 要素の配列の最初の文字列や要素のタグとして現れるものも含みます。そして区切り文字の有無を問わず、`name="password"` のように値として書かれたものも含む秘密の名前です。単語は ASCII の骨格で比較されます。ASCII の形を持たない文字は取り除かれるため、`piꞏn`、`tokeın`、`tokenꞏs` は `pin`、`token`、`tokens` と読まれ、文字が取り除かれた位置で 1 文字が欠けた名前も名前として数えます（`pɑssword`）。行の終わりまでではなく、テキストの終わりまで切られます。`login user=bob status=401` は `login user=[redacted]` になり、ログに書かれた multipart の本文やプロパティリストは最初のヘッダーまたはキーから先がマスクされます。自由形式のテキストの中の URL は、クリーンな場合にだけ表示されます。クリーンな URL とは、`scheme://host` と、ASCII の英字、数字、`.`、`_`、`-`、`/` だけからなる省略可能なパスでできていて、ホストとセグメントが秘密の名前ではなく、後ろに空白、改行、または文を終える句読点が続くものです。それ以外の URL は、その始まりでテキストを切ります（`see https://x.example/a?page=2 ok` は `see [redacted]` になります。`allowedQueryParameters` が適用されるのは `redact(url:)` だけです）。数字の間の `:` は、数の後にある場合にだけ数の一部です（`12:30`、`10.0.0.1:8080`）。数字で終わるキー（`user1:2345`）の後では区切り文字です。マスクは安全網であり、保証ではありません。誤ってログに書かれた秘密を想定して作られています。構造化された入力（JSON、フォーム、multipart 本文とそのパートのヘッダー、URL とそのホスト）は既定で安全で、理解できないものはマスクされます。構造化されたキーの名前は表示され、その下の値だけがマスクされます。自由形式のテキストでは、区切り文字なしで書かれ、2 文字以上が似た形の文字に置き換えられた名前（`pɑsswoʀd hunter2`）は、その前でテキストを切るものがなければ、見つかる保証はありません。自由形式のテキストに対する規則、その代償、見つけられないものは[ログのガイド](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)で説明しています。

### アカウントをデバイスに結び付ける

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## デモ

iPhone シミュレータ上の SecurityLab サンプルアプリの画面です。[`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh) で、実行中のアプリから取得しました。

| 整合性                                                                                                                                          | ボールト                                                                                                         | ワンタイムコード                                                                                 |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="シミュレータでの整合性レポート。脱獄チェックは対象外、シミュレータを検出、デバッガ、注入されたライブラリ、プロキシは問題なし" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="46 バイトとしてキーチェーンに暗号化して保存し、読み戻したメモと、保存済みのハッシュと照合した PIN" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="otpauth URI から生成した 6 桁の TOTP コードと、残り秒数をカウントダウンするリング" width="260"></picture> |

| マスキング                                                                                                                    | プライバシーシールド                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="メールアドレス、パスワード、bearer token、カード番号を含むログのテキストと、その下にマスキング後のテキスト" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="ロックのシンボルを表示するプライバシーシールドで覆われたカード詳細ビュー" width="260"></picture> |

アプリを実行するには、[`Examples/SecurityLab`](Examples/SecurityLab) の `SecurityLab.xcodeproj` を Xcode で開き、iPhone シミュレータまたは **My Mac** を選んで **Run** を押します。クイックスタートのサンプルに加えて、サーバーに接続して証明書チェーンのピンを一覧表示する証明書ピンニングの画面もあります。詳細は [Examples/README.md](Examples/README.md) をご覧ください。

## ドキュメント

API リファレンスと解説記事：

- [API リファレンス](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)（DocC。`master` から GitHub Pages に公開されます）
- Xcode の **Product › Build Documentation** でローカルにビルドするか、コマンドラインから実行します。

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## ガイド

- [はじめに](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted) — パッケージを追加し、メモを暗号化してキーチェーンに保存し、画面を覆います（[ソース](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)）。
- [秘密情報の保存](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets) — アクセス可能性、生体認証による保護、暗号化キー、PIN ハッシュ、Secure Enclave の鍵（[ソース](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)）。
- [証明書のピンニング](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) — ピンの取得、バックアップの選び方、レポートのみの段階的導入、有効期限（[ソース](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)）。
- [侵害されたデバイスの検出](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices) — 各整合性チェックで分かること、分からないこと、App Attest を使うべき場面（[ソース](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)）。
- [秘密情報をログに出さない](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs) — `Redacted`、マスク、リダクター、プライバシーシールド（[ソース](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)）。

## 動作要件

| プラットフォーム | 最小バージョン |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| ツールチェーン | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` は、生体認証のない tvOS と watchOS では利用できません。CI は、GitHub の `macos-26` ランナーイメージに入っている標準の Xcode でビルドします。パッケージの開発には Xcode 27 を使っています。

## アーキテクチャ

- `Sources/iOSSecurityTools/<Area>/` には、分野ごとに 1 つのフォルダがあります。`Keychain`、`Crypto`、`Random`、`SecureEnclave`、`Biometrics`、`Pinning`、`OneTimePassword`、`Integrity`、`Redaction`、`Privacy` です。`URLSession` がクラスであることを要求する `PinningURLSessionDelegate` を除き、すべて `Sendable` な値型です。
- パッケージは Apple の framework を直接呼び出します。キーチェーンと信頼評価には Security、AES-GCM、ChaCha20-Poly1305、HKDF、HMAC、Secure Enclave には CryptoKit、PBKDF2 には CommonCrypto、生体認証には LocalAuthentication を使い、それらにないものだけを自前で実装しています。エンベロープの形式、ピンのための SubjectPublicKeyInfo のエンコード、HOTP/TOTP の切り詰め、Base32、PHC ハッシュ形式、マスキングのスキャナです。
- エラーは型付きで（`throws(KeychainError)`、`throws(CipherError)` など）、すべての enum のケースに説明があります。アプリの外から来る値は、処理を行う前に上限を確認します。
- システムを読み取るコード（整合性チェック、`LAContext`）は、小さな内部 protocol を介します。そのため、テストではフェイクですべての分岐を動かし、実際の実装も確認します。
- パッケージが行わないことも設計の一部です。`ptrace` の deny-attach、メソッドスウィズリング、非公開の dyld 構造体の読み取りは行いません。これらは OS のリリースごとに壊れやすく、回避も容易です。代わりに App Attest を使うことを、[整合性ガイド](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)で案内しています。
- CI では、macOS で `swift test`、iPhone シミュレータで `xcodebuild test` を実行し、5 つすべてのプラットフォーム向けにビルドします。さらに、サンプルアプリを iOS と macOS 向けにビルドしてアプリ内でテストを実行し、DocC ドキュメントを公開します。

テストをローカルで実行するには、次のようにします。

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

ホストアプリのないテストバンドルは、シミュレータ上でキーチェーンの entitlement を持たないため、パッケージのキーチェーンのテストスイートは、そこではサンプルアプリの中で実行します。

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## ロードマップ

- App Attest のラッパー（`DCAppAttestService`）と、サーバー側での検証のサンプル。
- パッケージを Swift Package Index に追加すること。`.spi.yml` はすでにリポジトリにあります。

## コントリビューション

コントリビューションを歓迎します。pull request を作成する前に[コントリビューションガイド](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md)と[行動規範](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md)をお読みください。セキュリティ上の問題は[セキュリティポリシー](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md)に従って非公開で報告してください。

## ライセンス

MIT ライセンスで公開しています。詳細は [LICENSE](LICENSE) を参照してください。
