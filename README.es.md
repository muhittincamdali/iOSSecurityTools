<!-- i18n-source: README.md@cf4d89a47a7134103f2b2df8a33d41dbf9183291 status=reviewed -->
<!-- brand:start -->

<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-es-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-es-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/banner-es-light.svg" alt="iOSSecurityTools: Llavero, cifrado, pinning, códigos de un solo uso y controles de integridad para apps de Apple."></picture></p>

<!-- lang-selector:start -->
<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> · <a href="README.fr.md">Français</a> · <a href="README.pt-BR.md">Português (Brasil)</a> · <a href="README.ru.md">Русский</a></p>
<!-- lang-selector:end -->

<p align="center">
<a href="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml"><img src="https://github.com/muhittincamdali/iOSSecurityTools/actions/workflows/ci.yml/badge.svg" alt="Estado de CI"></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/releases"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-version-light.svg" alt="Última versión: v2.1.1"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-platforms-light.svg" alt="Plataformas compatibles: iOS 17+ · macOS 14+ · tvOS 17+ · watchOS 10+ · visionOS 1+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Package.swift"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-language-light.svg" alt="Versión del lenguaje: Swift 6.2+"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/blob/master/LICENSE"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/badge-license-light.svg" alt="Licencia: MIT"></picture></a>
</p>

<p align="center">
<a href="#inicio-rápido"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-es-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-es-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-start-es-light.svg" alt="Empezar"></picture></a>
<a href="https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-es-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-es-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-docs-es-light.svg" alt="Documentación"></picture></a>
<a href="https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-es-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-es-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/iOSSecurityTools/master/.github/brand/button-examples-es-light.svg" alt="Ejemplos"></picture></a>
</p>

> Esta es una traducción del README en inglés. Si hay diferencias, la versión en inglés es la vigente.

<!-- brand:end -->

Un paquete de Swift con piezas de seguridad para apps en iOS, macOS, tvOS, watchOS y visionOS:
almacenamiento en el llavero, cifrado autenticado, hashes de PIN, claves de Secure Enclave,
certificate pinning, contraseñas de un solo uso, comprobaciones de integridad del dispositivo y
redacción de datos en los registros. Está pensado para desarrolladores de apps que necesitan
resolver todo esto correctamente sin estudiar las API en C del framework Security. Cada tipo
valida lo que recibe y lanza un error tipado en lugar de fallar, de modo que los valores que
llegan desde un código QR, un servidor o un archivo no pueden hacer que la app se cierre. El
paquete no tiene dependencias.

## Lo más destacado

- **Llavero sin diccionarios** — `Keychain` guarda datos, cadenas y valores `Codable`, crea las
  claves de cifrado la primera vez que se usan y puede exigir Face ID, Touch ID o el código del
  dispositivo; lo impone el propio llavero, no un `if` alrededor de `LAContext`.
- **Cifrado que detecta manipulaciones** — `DataCipher` escribe sobres AES-256-GCM o
  ChaCha20-Poly1305 que llevan dentro su versión, su algoritmo y su nonce; cualquier byte
  modificado, una clave incorrecta o unos datos asociados distintos hacen fallar el descifrado.
  Incluye también HKDF, PBKDF2 y hashes de PIN en formato PHC.
- **Pinning que no deja a los usuarios fuera** — `PinningPolicy` exige un pin de respaldo,
  admite subdominios, fechas de caducidad y un modo de solo informe, y aun así exige que la
  evaluación de confianza del propio sistema sea correcta.
- **Señales, no promesas** — `IntegrityInspector` informa de archivos de jailbreak, un
  depurador, el simulador, bibliotecas de hooking y un proxy del sistema mediante un informe
  `Codable`, y la documentación explica qué puede ocultarle un atacante.
- **Los secretos se quedan fuera de los registros y las capturas** — `@Redacted` imprime
  `<redacted>` en cualquier sitio, `SensitiveDataRedactor` borra números de tarjeta, correos,
  tokens y campos secretos, y `.privacyShield()` cubre las vistas en el selector de apps y
  durante la grabación de pantalla. El redactor compara con sus nombres secretos solo las claves
  en ASCII simple y oculta por defecto cualquier otra clave; los cuerpos JSON, de formulario y
  multipart se analizan, y se omiten los que no se pueden analizar y los que un servidor
  podría dividir en campos de otra forma. El texto libre se corta en su primer disparador: un
  carácter fuera de un alfabeto seguro, una secuencia de escape, una palabra larga, una clave no
  permitida o un nombre secreto.
- **Probado con entradas hostiles** — vectores de las RFC 4226, 6238 y 5869, sobres y hashes
  creados por una implementación independiente, cadenas de certificados de una PKI de pruebas,
  fechas NaN e infinitas, `Int.min` e `Int.max`, y parámetros de URI desmesurados o duplicados:
  605 pruebas con Swift Testing en macOS y en un simulador de iPhone, además de las suites del
  llavero dentro de la app de ejemplo.

### Qué incluye

| Área | Tipos |
| --- | --- |
| Llavero | `Keychain`, `KeychainAccessibility`, `KeychainProtection`, `KeychainError` |
| Cifrado y hashing | `DataCipher`, `KeyDerivation`, `PasswordKeyDerivation`, `PasswordHash`, `SecureRandom`, `ConstantTime` |
| Secure Enclave | `SecureEnclaveKey`, `Keychain.secureEnclaveKey(forKey:protection:)` |
| Biometría | `BiometricAuthenticator`, `BiometricError` (iOS, macOS, visionOS) |
| Certificate pinning | `PinningPolicy`, `PinnedDomain`, `SPKIPin`, `PinningURLSessionDelegate`, `URLSession.pinned(policy:)` |
| Contraseñas de un solo uso | `TOTP`, `HOTP`, `OTPAuthURI` |
| Integridad del dispositivo | `IntegrityInspector`, `IntegrityReport`, `IntegrityFinding` |
| Registros y pantallas | `Redacted`, `Mask`, `SensitiveDataRedactor`, `.privacyShield(when:)`, `.onScreenshot(perform:)` |

## Inicio rápido

**1. Añade el paquete**

En Xcode, elige **File › Add Package Dependencies…** e introduce la URL del repositorio:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

Pégala en el campo de búsqueda de la esquina superior derecha de la ventana. Deja **Dependency
Rule** en **Up to Next Major Version** a partir de `2.1.1` y haz clic en **Add Package**. En la
ventana siguiente, elige el target de tu app junto a **iOSSecurityTools** y haz clic de nuevo en
**Add Package**.

**2. Importa el módulo**

```swift
import iOSSecurityTools
```

Pon esta línea al principio del archivo Swift donde uses el paquete, debajo de `import SwiftUI`.

**3. Úsalo**

En una app nueva de Xcode (**File › New › Project… › App**), sustituye todo el contenido de
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

Elige un simulador de iPhone y pulsa **Run** (⌘R). Toca el botón: la app crea una clave en el
llavero, cifra la nota con ella, guarda los bytes cifrados, los vuelve a leer y muestra
"Decrypted: Meet at 7 pm". `.privacyShield()` cubre la pantalla con un candado mientras la app
está en segundo plano, así que el selector de apps no muestra la nota.

## Instalación

### Swift Package Manager

En Xcode, elige **File › Add Package Dependencies…** e introduce la URL del repositorio:

```text
https://github.com/muhittincamdali/iOSSecurityTools.git
```

O añádelo a las `dependencies` de tu `Package.swift`:

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

La versión 2.0.0 (octubre de 2026) es la primera del paquete actual. La versión anterior, la
1.0.0 (febrero de 2026), es una base de código distinta: en junio de 2026 se sustituyeron sus
fuentes por código de relleno y en octubre de 2026 el paquete se reconstruyó desde cero, con
pruebas. [CHANGELOG.md](CHANGELOG.md) enumera los cambios.

Una app de macOS necesita un equipo de desarrollo en **Signing & Capabilities** para usar el
llavero; las apps de iOS y el simulador no necesitan nada más. Para Face ID, añade
`NSFaceIDUsageDescription` al Info.plist de la app.

## Uso

Los ejemplos siguientes están copiados de
[`Examples/SecurityLab/SecurityLab/ReadmeSamples.swift`](Examples/SecurityLab/SecurityLab/ReadmeSamples.swift).
La app de ejemplo y la suite de pruebas compilan ese archivo, y las pruebas ejecutan los ejemplos
que no necesitan ningún aviso ni red.

### Guardar un token en el llavero

```swift
func keychainSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.credentials")
    try keychain.set("r-7f3a9c", forKey: "refreshToken")
    let token = try keychain.string(forKey: "refreshToken")   // "r-7f3a9c"
    try keychain.removeValue(forKey: "refreshToken")
    return token
}
```

### Exigir Face ID para un valor

```swift
func protectedValueSample() throws -> String? {
    let keychain = Keychain(service: "com.example.app.cards")
    // Only the biometry enrolled now can read the value; the system enforces it.
    try keychain.set("4921", forKey: "card-pin", protection: .biometryCurrentSet)
    return try keychain.string(forKey: "card-pin", prompt: "Show your card PIN")
}
```

### Cifrar un registro

```swift
func encryptionSample() throws -> String {
    let cipher = try DataCipher(key: DataCipher.generateKey())
    let recordID = Data("note-42".utf8)

    // The record ID is authenticated, so this envelope cannot be pasted into another record.
    let envelope = try cipher.encrypt("Meet at 7 pm", authenticating: recordID)
    return try cipher.decryptString(envelope, authenticating: recordID)   // "Meet at 7 pm"
}
```

### Comprobar el PIN del bloqueo de la app

```swift
func pinSample() throws -> Bool {
    let stored = try PasswordHash.make(for: "4921")          // "$pbkdf2-sha256$i=600000$..."
    return try PasswordHash.verify("4921", against: stored)   // true
}
```

### Mostrar códigos de un solo uso a partir de un código QR

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

### Fijar las claves de un servidor

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

La [guía de pinning](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates) explica cómo obtener los pins de tu propio servidor
y desplegarlos sin dejar fuera a los usuarios.

### Comprobar el dispositivo

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

### Mantener los secretos fuera de los registros

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

`SensitiveDataRedactor` compara con sus nombres secretos solo las claves en ASCII simple (`A`–`Z`,
`a`–`z`, `0`–`9`, `_`, `-`, `.` y espacios); el valor de cualquier otra clave se oculta por
defecto, porque letras parecidas, caracteres invisibles y secuencias de escape pueden disfrazar un
nombre secreto. Los cuerpos JSON, de formulario y multipart se leen con un analizador; un cuerpo
que no puede analizar por completo se omite como `[body omitted: N bytes, <type>]`, igual que
un cuerpo que un analizador de servidor habitual podría dividir en campos de otra forma, como un
límite multipart tras un salto de línea suelto o un formulario con `;`.
También se omite un cuerpo de más de 256 KiB (`maximumBodySize`; una app puede subir el límite, con
un coste de hasta unos 40 bytes de memoria por cada byte del cuerpo), y el JSON se lee hasta 64
niveles de objetos y arrays y hasta cuatro documentos uno dentro de otro, contando el JSON dentro
de cadenas, lo que limita la pila que puede ocupar una entrada hostil; una cadena que contiene más
se oculta entera.
Los documentos encontrados dentro de una entrada leen en total como máximo cuatro veces su
longitud, lo que limita el tiempo; el texto más allá de ese presupuesto se oculta entero.
Un campo cuyo nombre está en un sitio y su valor en otro, como en `{"name":"X-Api-Key","value":…}`,
en una operación JSON Patch o SCIM sobre `/password` o en `[["Authorization","…"]]`, se oculta con
todo su valor cuando el nombre es secreto o no es ASCII simple. Un host de URL que no es un nombre
de etiquetas ASCII ni una dirección, que lleva un número de tarjeta o un token, o que nombra un
secreto (`myapp://pin/4831`, cuyo host es `pin`; el valor puede estar en el propio host, como en
`https://pin-4831.example.com`) se escribe como `scheme://[redacted]`, sin puerto, ruta ni query, y el nombre de una
cabecera de parte multipart solo se escribe cuando es una de las que lleva una parte. Una URL con
más de 64 segmentos de ruta o 128 parámetros, o con una ruta que los servidores resuelven de forma distinta (un segmento de punto como en
`/pin/./4831`, un `;` como en `/a;pin/4831`, un `.`, `/`, `\`, `;` o `%`
escapado), se registra solo con su esquema y su host,
y de una dirección de correo solo se muestra la primera letra del
nombre, en cualquier escritura (`ayşe.yılmaz@gmail.com` pasa a ser `a•••@gmail.com`).
Los nombres que no son ASCII simple cuentan como secretos aunque se escriban como valores: se
oculta el valor junto a un campo que lleva un nombre (`name`, `label`, `type`, `id`, …) como
`Şifre`, `ⓟⓘⓝ` o `🔑`.
Un nombre con un salto de línea u otro carácter de control dentro cuenta como secreto, diga lo que
diga, en un campo que contiene un nombre, y en otros lugares cuando nombra un secreto al quitar sus
caracteres de control o al leerlos como espacios
(`{"ParameterKey":"DbPassword\n","ParameterValue":…}`); una cadena corta solo de caracteres de
control (`"\n"`) también cuenta, mientras que `{"message":"Hello\nWorld","id":"7"}` conserva `id`, y en `redact(url:)` el segmento que
sigue a un segmento de ruta que no es un nombre ASCII simple pasa a ser `:id` (`/şifre/…`,
`/a,b/…`).
En texto libre, el primer nombre secreto oculta todo lo que le sigue en ese texto; esto oculta de
más a propósito. Ocultar de más es una decisión de diseño. Seis reglas fijan dónde se corta el
texto, y ninguna guarda una lista de variantes: el primer carácter fuera de un alfabeto seguro
(letras, marcas y dígitos de cualquier escritura, el espacio ASCII, el tabulador y los saltos de
línea, y el ASCII imprimible), de modo que un separador parecido como `꞉` o `→`, un emoji o un
carácter de control lo cortan, igual que una letra o un número cuya forma de compatibilidad no
está en ese alfabeto (`🄁` es `0,`); cualquier secuencia de escape (`%3D`, `&colon;`, `\075`),
que nunca se decodifica — en texto libre toda secuencia de escape con barra invertida corta el
texto, es decir, toda barra invertida a la que no siga un espacio, un tabulador o un salto de
línea ASCII (`login pa\x{73}sword hunter2` conserva `login `, y una ruta de Windows como
`\\nas\backup` se oculta desde su primera barra invertida);
una palabra de más de 256 caracteres; una clave que no está permitida (cualquiera
salvo `status`, `method`, `path`, `duration_ms`, `count` y las claves que usted pase), también
entre comillas de cualquier tipo (`"`, `'`, acento grave), donde corta el texto en la comilla de
apertura
(`cache miss for "session Qz9Wk7rX": refetching` queda como `cache miss for [redacted]`), o como
primera cadena de un array de dos elementos; una etiqueta de marcado, porque en texto libre la
primera etiqueta de marcado corta el texto, sea cual sea la etiqueta (`<user>`, `<_id>`, `</a>`,
`<!--`): todo `<` que no vaya seguido de un espacio, un tabulador, un salto de línea o un dígito
ASCII, de `=` o del final del texto lo corta; y
un nombre secreto,
con o sin separador, también escrito como valor como `name="password"`. Una palabra se compara
por su esqueleto ASCII con una única regla de comodín: una letra, marca o número fuera de ASCII
que no tiene forma ASCII cuenta como nada o como una letra cualquiera, así que `piꞏn`, `tokeın` y
`tokenꞏs` se leen como `pin`, `token` y `tokens`, y se encuentra uno de esos caracteres puesto en
lugar de una letra (`pɑssword`, `tͦken`, `passw〇rd`
y `t၀ken`: un dígito decimal de otra escritura es uno de esos números).
Una comilla que no se cierra en su línea corta el texto en
la comilla, así que de una clave entre comillas con un salto de línea dentro no se ve nada. El texto se corta hasta su
final y no solo hasta el final de la línea: `login user=bob status=401` queda como
`login user=[redacted]`, y un cuerpo multipart escrito en un log se oculta
desde su primera cabecera, y una property list desde su primera etiqueta.
Una URL en texto libre solo se muestra cuando está limpia —`scheme://host` y una ruta opcional de
letras ASCII, dígitos, `.`, `_`, `-` y `/`, cuyo host y segmentos no nombran ningún secreto, seguida
de un espacio, un salto de línea, el final del texto o un único `.`, `,`, `!` o `)` antes de uno de
ellos—, y cualquier otra URL corta el texto donde empieza, también una seguida de una comilla, `>`,
un acento grave o un `?`, `#` o `;` (`see https://x.example/a?page=2 ok` y
`see https://x.example/a'#token` se convierten en `see [redacted]`;
`allowedQueryParameters` solo se aplica a `redact(url:)`). Un
`:` entre dígitos forma parte de un número solo cuando los dos lados son números de una misma
forma (`12:30:45`, `10.0.0.1:8080`, `42:10`); después de una clave que termina en dígitos
(`user1:2345`), antes de una letra (`id 7:9hunter2`) o antes de cinco o más dígitos (`1:482913`)
es un separador. Un número de tarjeta, un IBAN, una dirección de correo o un token escrito a
través de un tabulador vertical, un salto de página o un separador de línea Unicode se encuentra
entero, y el texto se oculta desde su inicio.
La ocultación es una red de seguridad, no una garantía: está
hecha para secretos registrados por accidente. La entrada estructurada (JSON, formularios, cuerpos
multipart con las cabeceras de sus partes, URL con sus hosts) es segura por defecto, y lo que el
redactor no entiende allí se oculta; los nombres de las claves estructuradas se muestran y solo se
ocultan los valores bajo ellos. En texto libre no se garantiza encontrar un nombre escrito sin
separador con dos o más de sus letras sustituidas por letras parecidas (`pɑsswoʀd hunter2`) cuando
nada antes de él corta el texto: es un disfraz deliberado, mientras que una letra, marca o número
puesto en lugar de una letra sí se encuentra (`tͦken hunter2`). La
[guía de registros](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
describe las reglas para texto libre, lo que cuestan y lo que no encuentran.

### Vincular una cuenta al dispositivo

```swift
func deviceBindingSample(challenge: Data) throws -> (publicKey: Data, signature: Data)? {
    guard SecureEnclaveKey.isAvailable else { return nil }
    let key = try Keychain(service: "com.example.app.device").secureEnclaveKey(forKey: "device-key")
    // Send key.publicKeyDER to the server once; afterwards sign its login challenges.
    return (key.publicKeyDER, try key.signature(for: challenge))
}
```

## Limitaciones conocidas

Estas limitaciones se conocen y aún no se han cambiado:

- Un nombre con un carácter de control dentro oculta los miembros que tiene al lado, diga lo que
  diga, cuando lo contiene un campo que contiene un nombre o el primer elemento de un par
  (`{"name":"Hello\nWorld","value":"x"}` oculta `value`), y en otros lugares cuando nombra un
  secreto al quitar sus caracteres de control o al leerlos como espacios
  (`{"note":"pass\nword","id":"7"}` oculta `id`).
- Una clave cuenta `token` y `secret` solo como palabra o al final y `pw` solo como palabra, así que
  `tokenvalue`, `TOKENID`, `secretvalue`, `secrethash`, `userpw` y `dbpw` muestran sus valores;
  marca esas propiedades con `@Redacted`.
- Una cadena corta solo de caracteres de control y espacios en blanco oculta todos los miembros que
  tiene al lado, también donde no significa nada (`{"title":"\n","data":"x"}` oculta `data`),
  mientras que una de más de 256 escalares se lee como texto.

## Demo

Pantallas de la app de ejemplo SecurityLab en un simulador de iPhone, capturadas de la app en
ejecución con [`scripts/capture-example-screens.sh`](scripts/capture-example-screens.sh):

| Integridad                                                                                                                                                                     | Caja fuerte                                                                                                            | Códigos de un solo uso                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-integrity-dark.png"><img src="docs/images/example-integrity-light.png" alt="Informe de integridad en el simulador: comprobación de jailbreak no aplicable, simulador detectado, depurador, bibliotecas inyectadas y proxy sin hallazgos" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-vault-dark.png"><img src="docs/images/example-vault-light.png" alt="Una nota cifrada en el llavero como 46 bytes y leída de nuevo, y un PIN comprobado con su hash guardado" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-codes-dark.png"><img src="docs/images/example-codes-light.png" alt="Un código TOTP de seis dígitos obtenido de un URI otpauth, con un anillo que cuenta atrás los segundos restantes" width="260"></picture> |

| Redacción                                                                                                                                                   | Pantalla de privacidad                                                                                                    |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-redaction-dark.png"><img src="docs/images/example-redaction-light.png" alt="Un texto de registro con un correo, una contraseña, un token bearer y un número de tarjeta, y debajo la versión con los datos redactados" width="260"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/example-privacy-dark.png"><img src="docs/images/example-privacy-light.png" alt="Una vista con los datos de una tarjeta cubierta por la pantalla de privacidad, con un símbolo de candado" width="260"></picture> |

Para ejecutar la app, abre `SecurityLab.xcodeproj`, en [`Examples/SecurityLab`](Examples/SecurityLab),
con Xcode, elige un simulador de iPhone o **My Mac** y pulsa **Run**. También incluye el inicio
rápido y una pantalla de certificate pinning que se conecta a un servidor y muestra los pins de
su cadena; [Examples/README.md](Examples/README.md) da los detalles.

## Documentación

Referencia de la API y artículos:

- [Referencia de la API](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
  (DocC, publicada en GitHub Pages desde `master`)
- Compílala en local en Xcode con **Product › Build Documentation**, o desde la línea de comandos:

```sh
xcodebuild docbuild -scheme iOSSecurityTools -destination 'generic/platform=macOS'
```

## Guías

- [Primeros pasos](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/gettingstarted)
  — añade el paquete, cifra una nota en el llavero y cubre la pantalla
  ([fuente](Sources/iOSSecurityTools/iOSSecurityTools.docc/GettingStarted.md)).
- [Guardar secretos](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/storingsecrets)
  — accesibilidad, protección biométrica, claves de cifrado, hashes de PIN y claves de
  Secure Enclave ([fuente](Sources/iOSSecurityTools/iOSSecurityTools.docc/StoringSecrets.md)).
- [Fijar certificados](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/pinningcertificates)
  — cómo obtener los pins, elegir un respaldo, desplegar en modo de solo informe y gestionar la
  caducidad ([fuente](Sources/iOSSecurityTools/iOSSecurityTools.docc/PinningCertificates.md)).
- [Detectar dispositivos comprometidos](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  — qué ve cada comprobación de integridad, qué no puede ver y cuándo usar App Attest
  ([fuente](Sources/iOSSecurityTools/iOSSecurityTools.docc/DetectingCompromisedDevices.md)).
- [Mantener los secretos fuera de los registros](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/keepingsecretsoutoflogs)
  — `Redacted`, máscaras, el redactor y la pantalla de privacidad
  ([fuente](Sources/iOSSecurityTools/iOSSecurityTools.docc/KeepingSecretsOutOfLogs.md)).

## Requisitos

| Plataforma | Versión mínima |
| --- | --- |
| iOS | 17 |
| macOS | 14 |
| tvOS | 17 |
| watchOS | 10 |
| visionOS | 1 |
| Herramientas | Swift 6.2 · Xcode 26+ |

`BiometricAuthenticator` no está disponible en tvOS ni en watchOS, que no tienen biometría. La CI
compila con el Xcode predeterminado de la imagen de runner `macos-26` de GitHub. El paquete se
desarrolla con Xcode 27.

## Arquitectura

- `Sources/iOSSecurityTools/<Area>/` tiene una carpeta por área: `Keychain`, `Crypto`, `Random`,
  `SecureEnclave`, `Biometrics`, `Pinning`, `OneTimePassword`, `Integrity`, `Redaction` y
  `Privacy`. Todo es un tipo de valor `Sendable`, salvo `PinningURLSessionDelegate`, que
  `URLSession` exige que sea una clase.
- El paquete llama directamente a los frameworks de Apple — Security para el llavero y la
  evaluación de confianza, CryptoKit para AES-GCM, ChaCha20-Poly1305, HKDF, HMAC y Secure Enclave,
  CommonCrypto para PBKDF2 y LocalAuthentication para la biometría — e implementa solo lo que les
  falta: el formato de los sobres, la codificación SubjectPublicKeyInfo para los pins, el
  truncamiento de HOTP/TOTP, Base32, el formato de hash PHC y el analizador de redacción.
- Los errores son tipados (`throws(KeychainError)`, `throws(CipherError)`, ...) y cada caso del
  enum tiene una descripción. Los valores que vienen de fuera de la app tienen sus límites
  comprobados antes de hacer cualquier trabajo.
- El código que lee el sistema (comprobaciones de integridad, `LAContext`) pasa por pequeños
  protocolos internos, de modo que las pruebas recorren cada rama con dobles de prueba y también
  comprueban la implementación real.
- Lo que el paquete no hace forma parte del diseño: no usa `ptrace` deny-attach, ni method
  swizzling, ni lee estructuras privadas de dyld. Eso se rompe entre versiones del sistema y es
  fácil de eludir; la [guía de integridad](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/detectingcompromiseddevices)
  recomienda App Attest en su lugar.
- La CI ejecuta `swift test` en macOS y `xcodebuild test` en un simulador de iPhone, compila para
  las cinco plataformas, compila la app de ejemplo para iOS y macOS, ejecuta sus pruebas dentro de
  la app y publica la documentación de DocC.

Para ejecutar las pruebas en local:

```sh
swift test                                    # macOS
swift test -c release                         # macOS, release build
xcodebuild test -scheme iOSSecurityTools \
  -destination 'platform=iOS Simulator,name=iPhone 17'
```

Un paquete de pruebas sin app anfitriona no tiene el entitlement del llavero en el simulador, así
que las suites del llavero del paquete se ejecutan allí dentro de la app de ejemplo:

```sh
cd Examples/SecurityLab
xcodebuild test -scheme SecurityLab -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Hoja de ruta

- Un envoltorio de App Attest (`DCAppAttestService`) con un ejemplo de verificación en el servidor.
- Añadir el paquete al Swift Package Index; `.spi.yml` ya está en el repositorio.

## Contribuir

Las contribuciones son bienvenidas. Lee la [guía de contribución](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CONTRIBUTING.md) y el [código de conducta](https://github.com/muhittincamdali/.github/blob/main/CODE_OF_CONDUCT.md) antes de abrir una pull request. Informa de los problemas de seguridad de forma privada, como se describe en la [política de seguridad](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/SECURITY.md).

## Licencia

Publicado bajo la licencia MIT. Consulta [LICENSE](LICENSE).
