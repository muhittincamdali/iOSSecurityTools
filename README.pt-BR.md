<!-- i18n-source: README.md@5e8f2ed939dc0762ec5c87d3bdcc998942d52639 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-pt-BR-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-pt-BR-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-pt-BR-light.svg" alt="iOSSecurityTools: Keychain, criptografia, pinning, códigos de uso único e verificações de integridade para apps Apple."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="Status da CI"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Versão mais recente: v2.1.0"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Plataformas compatíveis: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Versão da linguagem: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="Licença: MIT"></picture></a>
</p>

<p align="center">
<a href="#início-rápido"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-pt-BR-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-pt-BR-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-pt-BR-light.svg" alt="Começar"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-pt-BR-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-pt-BR-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-pt-BR-light.svg" alt="Documentação"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-pt-BR-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-pt-BR-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-pt-BR-light.svg" alt="Exemplos"></picture></a>
</p>

> Esta é uma tradução do README em inglês. Se houver diferença, vale a versão em inglês.

<!-- brand:end -->

Um pacote Swift com blocos de segurança para apps em iOS, macOS, tvOS, watchOS e visionOS:
armazenamento no keychain, criptografia autenticada, hashes de PIN, chaves do Secure Enclave,
certificate pinning, senhas de uso único, verificações de integridade do dispositivo e
ocultação de dados nos logs. Ele é para desenvolvedores de apps que precisam implementar essas
peças corretamente sem estudar as APIs em C do framework Security. Cada tipo valida o que recebe
e lança um erro tipado em vez de travar, então valores vindos de um QR code, de um servidor ou de
um arquivo não conseguem derrubar o app. O pacote não tem dependências.

## Destaques

- **Keychain sem dicionários** — `Keychain` guarda dados, strings e valores `Codable`, cria
  chaves de criptografia no primeiro uso e pode exigir Face ID, Touch ID ou o código do
  aparelho; quem impõe isso é o próprio keychain, e não um `if` em volta do `LAContext`.
- **Criptografia que detecta adulteração** — `DataCipher` grava envelopes AES-256-GCM ou
  ChaCha20-Poly1305 que carregam a própria versão, o algoritmo e o nonce; qualquer byte
  alterado, chave errada ou dado associado errado faz a descriptografia falhar. HKDF, PBKDF2 e
  hashes de PIN no formato PHC acompanham o pacote.
- **Pinning que não deixa os usuários de fora** — `PinningPolicy` exige um pin de reserva, aceita
  subdomínios, datas de expiração e um modo somente relatório, e ainda exige que a avaliação de
  confiança do próprio sistema seja aprovada.
- **Sinais, não promessas** — `IntegrityInspector` informa arquivos de jailbreak, um depurador,
  o simulador, bibliotecas de hooking e um proxy do sistema em um relatório `Codable`, e a
  documentação diz o que um atacante consegue esconder dele.
- **Segredos fora dos logs e das capturas de tela** — `@Redacted` imprime `<redacted>` em
  qualquer lugar, `SensitiveDataRedactor` apaga números de cartão, e-mails, tokens e campos
  secretos e `.privacyShield()` cobre as telas no seletor de apps e durante a gravação de tela.
  O redator compara com os nomes secretos apenas chaves em ASCII simples e oculta por padrão
  qualquer outra chave; corpos JSON, de formulário e multipart são analisados, e corpos que não
  podem ser analisados são omitidos, assim como corpos que um servidor poderia dividir em
  campos de outro jeito. O texto livre é cortado no primeiro gatilho: um caractere fora de um
  alfabeto seguro, uma sequência de escape, uma palavra longa, uma chave não permitida ou um nome
  secreto.
- **Testado contra entradas hostis** — vetores das RFCs 4226, 6238 e 5869, envelopes e hashes
  gerados por uma implementação independente, cadeias de certificados de uma PKI de teste, datas
  NaN e infinitas, `Int.min` e `Int.max`, parâmetros de URI grandes demais ou duplicados: 529
  testes com Swift Testing no macOS e em um simulador de iPhone, além das suítes do keychain
  dentro do app de exemplo.

### O que está incluído

| Área | Tipos |
| --- | --- |
| Keychain | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| Criptografia e hash | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| Biometria | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| Certificate pinning | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| Senhas de uso único | `TOTP`, `HOTP`, `OTPAuthURI` |
| Integridade do dispositivo | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| Logs e telas | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Início rápido

**1. Adicione o pacote**

No Xcode, escolha **File › Add Package Dependencies…** e informe a URL do repositório:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Cole-o no campo de busca no canto superior direito da janela. Deixe **Dependency Rule** em
**Up to Next Major Version** a partir de `2.1.0` e clique em **Add Package**. Na janela seguinte,
escolha o target do seu app ao lado de **iOSSecurityTools** e clique em **Add Package** de novo.

**2. Importe o módulo**

```swift
import iOSSecurityTools
```

Coloque esta linha no topo do arquivo Swift em que você usa o pacote, abaixo de `import SwiftUI`.

**3. Use**

Em um app novo do Xcode (**File › New › Project… › App**), substitua todo o conteúdo de
`ContentView.swift` por:

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

Escolha um simulador de iPhone e pressione **Run** (⌘R). Toque no botão: o app cria uma chave no
keychain, criptografa a nota com ela, guarda os bytes criptografados, lê de volta e mostra
"Decrypted: Meet at 7 pm". `.privacyShield()` cobre a tela com um cadeado enquanto o app está em
segundo plano, e por isso o seletor de apps não mostra a nota.

## Instalação

### Swift Package Manager

No Xcode, escolha **File › Add Package Dependencies…** e informe a URL do repositório:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Ou adicione-o às `dependencies` do seu `Package.swift`:

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

A versão 2.0.0 (outubro de 2026) é a primeira versão do pacote atual. A versão anterior, a
1.0.0 (fevereiro de 2026), é outra base de código: em junho de 2026 seu código-fonte foi
substituído por código provisório e, em outubro de 2026, o pacote foi reconstruído do zero, com
testes. O [CHANGELOG.md](CHANGELOG.md) lista as mudanças.

Um app para macOS precisa de uma equipe de desenvolvimento em **Signing & Capabilities** para usar
o keychain; apps para iOS e o simulador não precisam de nada a mais. Para o Face ID, adicione
`NSFaceIDUsageDescription` ao Info.plist do app.

## Uso

Os exemplos abaixo foram copiados de
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift).
O app de exemplo e a suíte de testes compilam esse arquivo, e os testes executam os exemplos que
não precisam de nenhuma solicitação nem de rede.

### Guardar um token no keychain

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Exigir Face ID para um valor

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Criptografar um registro

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Verificar o PIN de bloqueio do app

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Mostrar códigos de uso único a partir de um QR code

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

### Fixar as chaves de um servidor

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

O [guia de pinning](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) mostra como obter os pins do seu próprio servidor e
colocá-los em produção sem deixar usuários de fora.

### Verificar o dispositivo

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

### Manter segredos fora dos logs

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

`SensitiveDataRedactor` compara com os nomes secretos apenas chaves em ASCII simples (`A`–`Z`,
`a`–`z`, `0`–`9`, `_`, `-`, `.` e espaços); o valor de qualquer outra chave é ocultado por padrão,
porque letras parecidas, caracteres invisíveis e sequências de escape podem disfarçar um nome
secreto. Corpos JSON, de formulário e multipart são lidos por um analisador; um corpo que não
consegue analisar por completo é omitido como `[body omitted: N bytes, <type>]`, assim como um
corpo que um analisador de servidor comum poderia dividir em campos de outro jeito, como um limite
multipart depois de uma quebra de linha solta ou um formulário com `;`.
Um corpo maior que 256 KiB também é omitido (`maximumBodySize`; um app pode aumentar o limite, ao
custo de até cerca de 40 bytes de memória para cada byte do corpo), e o JSON é lido com no máximo
64 níveis de objetos e arrays e quatro documentos um dentro do outro, contando o JSON dentro de
strings, o que limita a pilha que uma entrada hostil pode ocupar; uma string que contenha mais é
ocultada por inteiro.
Os documentos encontrados dentro de uma entrada leem no total no máximo quatro vezes o comprimento
dela, o que limita o tempo; o texto além desse orçamento é ocultado por inteiro.
Um campo cujo nome está em um lugar e o valor em outro, como em `{"name":"X-Api-Key","value":…}`,
em uma operação JSON Patch ou SCIM sobre `/password` ou em `[["Authorization","…"]]`, tem o valor
ocultado por inteiro quando o nome é secreto ou não é ASCII simples. Um host de URL que não é um
nome de rótulos ASCII nem um endereço, ou que carrega um número de cartão ou um token, é escrito
como `scheme://[redacted]`, e o nome de um cabeçalho de parte multipart só é escrito quando é um
dos que uma parte carrega. Uma URL com mais de 64 segmentos de caminho ou 128 parâmetros,
ou com um caminho que servidores resolvem de forma diferente (um segmento de ponto como em
`/pin/./4831`, um `.`, `/`, `\` ou `%`
escapado, um segmento só com parâmetros), é registrada apenas com o esquema e o host,
e um endereço de e-mail mostra só a primeira letra do
nome, em qualquer escrita (`ayşe.yılmaz@gmail.com` vira `a•••@gmail.com`).
Nomes que não são ASCII simples contam como secretos mesmo quando escritos como valores: o valor ao
lado de um campo que guarda um nome (`name`, `label`, `type`, `id`, …), como `Şifre`, `ⓟⓘⓝ` ou `🔑`,
é ocultado.
Em texto livre, o primeiro nome secreto oculta tudo o que vem depois dele nesse texto; isso oculta
demais de propósito. Ocultar demais é uma decisão de projeto. Seis regras definem onde o texto é
cortado, e nenhuma mantém uma lista de variantes: o primeiro caractere fora de um alfabeto seguro
(letras, marcas e dígitos de qualquer escrita, o espaço ASCII, a tabulação e as quebras de linha, e
o ASCII imprimível), de modo que um separador parecido como `꞉` ou `→`, um emoji ou um caractere de
controle o cortam, assim como uma letra ou um número cuja forma de compatibilidade não está nesse
alfabeto (`🄁` é `0,`); qualquer sequência de escape (`%3D`, `&colon;`, `\075`), que nunca é
decodificada — em texto livre, toda sequência de escape com barra invertida corta o texto, ou
seja, toda barra invertida que não seja seguida de espaço, tabulação ou quebra de linha ASCII
(`login pa\x{73}sword hunter2` mantém `login `, e um caminho do Windows como `\\nas\backup`
é ocultado a partir da primeira barra invertida);
uma palavra com mais de 256 caracteres; uma chave que não é permitida (qualquer chave
além de `status`, `method`, `path`, `duration_ms`, `count` e das chaves que você passar), também
entre aspas de qualquer tipo (`"`, `'`, crase), onde corta o texto na aspa de abertura
(`cache miss for "session Qz9Wk7rX": refetching` vira `cache miss for [redacted]`), ou como
primeira string de um array de dois elementos; uma tag de marcação, pois em texto livre a primeira
tag de marcação corta o texto, seja qual for a tag (`<user>`, `<_id>`, `</a>`, `<!--`): todo `<`
que não seja seguido de espaço, tabulação, quebra de linha ou dígito ASCII, de `=` ou do fim do texto
o corta; e um nome secreto, com
ou sem separador, também escrito como valor, como `name="password"`. Uma palavra é comparada pelo
seu esqueleto ASCII: as letras sem forma ASCII são omitidas, de modo que `piꞏn`, `tokeın` e
`tokenꞏs` são lidos como `pin`, `token` e `tokens`, e um nome também conta com uma letra a menos
onde uma foi omitida (`pɑssword`). Uma aspa que não fecha na sua linha corta o texto na aspa, de
modo que nada aparece de uma chave entre aspas com uma quebra de linha dentro. O texto é cortado até o
fim dele e não só até o fim da linha: `login user=bob status=401` vira `login user=[redacted]`, e um
corpo multipart escrito em um log é ocultado a partir do primeiro cabeçalho, e uma property list a
partir da primeira tag.
Uma URL em texto livre só é mostrada quando está limpa — `scheme://host` e um caminho opcional de
letras ASCII, dígitos, `.`, `_`, `-` e `/`, cujo host e segmentos não nomeiam nenhum segredo,
seguida de espaço, quebra de linha, fim do texto ou um único `.`, `,`, `!` ou `)` antes de um deles
—, e qualquer outra URL corta o texto onde começa, também uma seguida de aspas, `>`, crase ou `?`,
`#` ou `;` (`see https://x.example/a?page=2 ok` e `see https://x.example/a'#token` viram
`see [redacted]`;
`allowedQueryParameters` vale só para `redact(url:)`). Um `:` entre
dígitos só faz parte de um número depois de um número (`12:30`, `10.0.0.1:8080`); depois de uma
chave que termina em dígitos (`user1:2345`), ele é um separador.
A ocultação é uma rede de segurança, não uma garantia: ela foi feita para
segredos registrados por acidente. A entrada estruturada (JSON, formulários, corpos multipart e os
cabeçalhos das partes, URLs e os hosts delas) é segura por padrão, e o que o redator não entende ali
é ocultado; os nomes das chaves estruturadas são mostrados e só os valores sob eles são
ocultados. Em texto livre, um nome escrito sem separador com duas ou mais letras trocadas por
letras parecidas (`pɑsswoʀd hunter2`) não tem garantia de ser encontrado quando nada antes dele corta o
texto. O
[guia de logs](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
descreve as regras para texto livre, o que elas custam e o que elas não encontram.

### Vincular uma conta ao dispositivo

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Demonstração

Telas do app de exemplo SecurityLab em um simulador de iPhone, capturadas do app em execução por
[`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh):

| Integridade                                                                                                                                                                      | Cofre                                                                                                                    | Códigos de uso único                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Relatório de integridade no simulador: verificação de jailbreak não se aplica, simulador encontrado, depurador, bibliotecas injetadas e proxy sem ocorrências" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="Uma nota criptografada no keychain com 46 bytes e lida de volta, e um PIN conferido com o hash armazenado" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="Um código TOTP de seis dígitos de um URI otpauth, com um anel que faz a contagem regressiva dos segundos restantes" width="260"></picture> |

| Ocultação                                                                                                                                         | Escudo de privacidade                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="Um texto de log com um e-mail, uma senha, um token bearer e um número de cartão, e abaixo dele a versão com os dados ocultados" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="Uma tela de detalhes de cartão coberta pelo escudo de privacidade, com um símbolo de cadeado" width="260"></picture> |

Para executar o app, abra `SecurityLab.xcodeproj`, em [`Examples/SecurityLab`](Examples/SecurityLab),
no Xcode, escolha um simulador de iPhone ou **My Mac** e pressione **Run**. Ele também tem o início
rápido e uma tela de certificate pinning que se conecta a um servidor e lista os pins da cadeia
dele; o [Examples/README.md](Examples/README.md) traz os detalhes.

## Documentação

Referência da API e artigos:

- [Referência da API](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, publicada no GitHub Pages a partir de `master`)
- Gere-a localmente no Xcode com **Product › Build Documentation**, ou pela linha de comando:

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Guias

- [Primeiros passos](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — adicione o pacote, criptografe uma nota no keychain e cubra a tela
  ([código-fonte](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Guardando segredos](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — acessibilidade, proteção biométrica, chaves de criptografia, hashes de PIN e chaves do
  Secure Enclave ([código-fonte](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Fixando certificados](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — como obter os pins, escolher um pin de reserva, implantar em modo somente relatório e lidar
  com a expiração ([código-fonte](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Detectando dispositivos comprometidos](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — o que cada verificação de integridade enxerga, o que ela não enxerga e quando usar o App Attest
  ([código-fonte](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Mantendo segredos fora dos logs](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, máscaras, o redator e o escudo de privacidade
  ([código-fonte](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Requisitos

| Plataforma | Versão mínima |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| Ferramentas | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` não está disponível no tvOS e no watchOS, que não têm biometria. O CI
compila com o Xcode padrão da imagem de runner `macos-26` do GitHub. O pacote é desenvolvido com
o Xcode 27.

## Arquitetura

- `Sources/iOSSecurityTools/<Area>/` tem uma pasta por área: `Keychain`, `Crypto`, `Random`,
  `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`, `Redaction` e
  `Privacy`. Tudo é um tipo de valor `Sendable`, exceto `PinningURLSessionDelegate`, que o
  `URLSession` exige que seja uma classe.
- O pacote chama diretamente os frameworks da Apple — Security para o keychain e a avaliação de
  confiança, CryptoKit para AES-GCM, ChaCha20-Poly1305, HKDF, HMAC e o Secure Enclave,
  CommonCrypto para o PBKDF2 e LocalAuthentication para a biometria — e implementa apenas o que
  falta neles: o formato do envelope, a codificação SubjectPublicKeyInfo dos pins, o truncamento
  de HOTP/TOTP, Base32, o formato de hash PHC e o analisador de ocultação.
- Os erros são tipados (`throws(KeychainError)`, `throws(CipherError)`, ...) e todo caso de enum
  tem uma descrição. Os valores que vêm de fora do app têm seus limites verificados antes de
  qualquer processamento.
- O código que lê o estado do sistema (verificações de integridade, `LAContext`) passa por
  pequenos protocolos internos, de modo que os testes percorrem cada ramo com dublês e também
  verificam a implementação real.
- O que o pacote não faz faz parte do projeto: nada de `ptrace` deny-attach, nada de method
  swizzling, nada de ler estruturas privadas do dyld. Isso quebra entre versões do sistema e é
  fácil de contornar; o [guia de integridade](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  recomenda o App Attest no lugar.
- O CI executa `swift test` no macOS e `xcodebuild test` em um simulador de iPhone, compila para as
  cinco plataformas, compila o app de exemplo para iOS e macOS, executa os testes dele dentro do
  app e publica a documentação do DocC.

Para executar os testes localmente:

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

Um bundle de testes sem app host não tem o entitlement do keychain no simulador, por isso as
suítes do keychain do pacote são executadas lá dentro do app de exemplo:

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Roteiro

- Um wrapper do App Attest (`DCAppAttestService`) com um exemplo de verificação no servidor.
- Adicionar o pacote ao Swift Package Index; o `.spi.yml` já está no repositório.

## Como contribuir

Contribuições são bem-vindas. Leia o [guia de contribuição](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) e o [código de conduta](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md) antes de abrir um pull request. Relate problemas de segurança de forma privada, como descrito na [política de segurança](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md).

## Licença

Publicado sob a licença MIT. Veja [LICENSE](LICENSE).
