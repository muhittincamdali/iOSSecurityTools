/// The words that make a key secret.
///
/// The words are lowercase ASCII without separators. ``PlainName`` compares a plain-ASCII key with
/// them; any other key is hidden without being compared. Words of free text are read for them
/// loosely (see ``LooseReading``), which only ever hides more.
enum SecretNames {
    /// Where a secret word has to sit in a key for the key to hold the secret.
    enum Placement {
        /// Anywhere, also inside a longer word: `dbpassword`, `userapikey`.
        case anywhere
        /// As a word of the key (`user_pin`, `X-Auth-Key`) or at the end of the key (`apitoken`,
        /// `licensekey`).
        case wordOrEnd
        /// As a word of the key only: `DB_PASS` but not `bypass` or `passport`.
        case word
        /// As the last word of the key: `session` and `laravel_session` but not `session_start`.
        case lastWord
    }

    struct Entry {
        let letters: [UInt8]
        let placement: Placement
    }

    /// The shared list of the redaction spec (password, passwd, pwd, secret, token, access_token,
    /// refresh_token, id_token, api_key, apikey, key, auth, authorization, cookie, set-cookie,
    /// session, sid, otp, pin, cvv, card, iban, ssn, private_key, client_secret, signature), and this
    /// library's extensions.
    static let entries: [Entry] = {
        let anywhere = [
            "authorization", "clientsecret", "refreshtoken", "accesstoken", "accesskey", "authkey", "privatekey",
            "secretkey", "sessionid", "sessionkey", "sessid", "passphrase", "password", "passcode", "passwd", "idtoken",
            "apikey", "credential", "signature", "cookie", "pincode", "otpcode", "securitycode", "verificationcode",
            "authcode", "cardnumber",
        ]
        let wordOrEnd = ["token", "secret", "pwd", "key", "pin", "otp", "cvv", "cvc", "ssn", "iban", "card", "auth"]
        return anywhere.map { Entry(letters: Array($0.utf8), placement: .anywhere) }
            + wordOrEnd.map { Entry(letters: Array($0.utf8), placement: .wordOrEnd) }
            + ["pass", "sid", "pw"].map { Entry(letters: Array($0.utf8), placement: .word) }
            + [Entry(letters: Array("session".utf8), placement: .lastWord)]
    }()

    /// The entries by their first letter, `a` to `z`.
    private static let byFirstLetter = table { $0.letters[0] }

    /// The entries by their second letter, for a start where a wildcard stands for the first.
    /// Every entry has two letters or more.
    private static let bySecondLetter = table { $0.letters[1] }

    private static func table(_ letter: (Entry) -> UInt8) -> [[Entry]] {
        var table = [[Entry]](repeating: [], count: 26)
        for entry in entries { table[Int(letter(entry) - UInt8(ascii: "a"))].append(entry) }
        return table
    }

    /// The entries that can be spelled from letter `start` of a name's lowercase `letters`: those
    /// that start with that letter, or, where a ``PlainName/wildcard`` stands for the first
    /// letter, those whose second letter follows it. A word holds one wildcard at most, so after
    /// two of them in a row no entry can start.
    static func candidates(at start: Int, in letters: [UInt8]) -> [Entry] {
        let first = letters[start]
        guard first == PlainName.wildcard else { return entries(in: byFirstLetter, letter: first) }
        guard start + 1 < letters.count else { return [] }
        return entries(in: bySecondLetter, letter: letters[start + 1])
    }

    private static func entries(in table: [[Entry]], letter: UInt8) -> [Entry] {
        guard (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(letter) else { return [] }
        return table[Int(letter - UInt8(ascii: "a"))]
    }
}
