import Foundation
import Testing
@testable import iOSSecurityTools

/// The inputs that got a secret past 2.0.0 and the earlier designs of 2.1.0, kept so that none of
/// them can come back.
@Suite("SensitiveDataRedactor bypass probes")
struct RedactionProbeTests {
    let redactor = SensitiveDataRedactor()

    /// The 51 inputs of the second review, each hiding `hunter2` behind another trick, with what
    /// the redactor writes for them now.
    static let secondReview: [(String, String)] = [
        ("p\u{430}ssword=hunter2", "p\u{430}ssword=[redacted]"),
        ("\u{440}assword=hunter2", "\u{440}assword=[redacted]"),
        ("passw\u{43E}rd=hunter2", "passw\u{43E}rd=[redacted]"),
        ("{\"p\u{430}ssword\":\"hunter2\"}", "{\"p\u{430}ssword\":[redacted]"),
        ("t\u{43E}ken=hunter2", "t\u{43E}ken=[redacted]"),
        ("s\u{435}cret=hunter2", "s\u{435}cret=[redacted]"),
        ("\u{430}pi_key=hunter2", "\u{430}pi_key=[redacted]"),
        ("pass.word=hunter2", "pass.word=[redacted]"),
        ("pass word=hunter2", "pass [redacted]"),
        ("PASS-WORD=hunter2", "PASS-WORD=[redacted]"),
        ("pass_word=hunter2", "pass_word=[redacted]"),
        ("api.key=hunter2", "api.key=[redacted]"),
        ("client.secret=hunter2", "client.secret=[redacted]"),
        ("access.token: hunter2", "access.token: [redacted]"),
        ("{\"pass\\u0077ord\":\"hunter2\"}", "{\"pass\\u0077ord\":[redacted]"),
        ("pass%77ord=hunter2", "[redacted]"),
        ("p&#97;ssword=hunter2", "[redacted]"),
        ("pa\u{301}ssword=hunter2", "pa\u{301}ssword=[redacted]"),
        ("pass\u{200B}word=hunter2", "[redacted]"),
        ("pass\u{2060}word=hunter2", "[redacted]"),
        ("pass\u{AD}word=hunter2", "[redacted]"),
        ("pa\u{FE0F}ssword=hunter2", "pa[redacted]"),
        ("password\u{301}=hunter2", "password\u{301}=[redacted]"),
        ("\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=hunter2", "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=[redacted]"),
        ("\u{24DF}assword=hunter2", "[redacted]"),
        ("{\"user\":{\"password\":\"hunter2\"}}", "{\"user\":[redacted]"),
        ("[{\"password\":\"hunter2\"},{\"password\":\"hunter2\"}]", "[{\"password\":[redacted]"),
        ("password=hunter2&password=hunter2", "password=[redacted]"),
        ("{\"password\" : \"hunter2\"}", "{\"password\" : [redacted]"),
        ("password: \"hunter2", "password: [redacted]"),
        ("{\"password\":\n\"hunter2\"}", "{\"password\":\n[redacted]"),
        ("password\u{2028}=hunter2", "password[redacted]"),
        ("password\u{85}=hunter2", "password[redacted]"),
        ("password\u{B}=hunter2", "password[redacted]"),
        ("password\u{C}=hunter2", "password[redacted]"),
        ("password\u{FF1D}hunter2", "password[redacted]"),
        ("password\u{FE13}hunter2", "password[redacted]"),
        ("password\u{FF1A}hunter2", "password[redacted]"),
        ("password:hunter2", "password:[redacted]"),
        ("PASSWORD=hunter2", "PASSWORD=[redacted]"),
        ("\u{FEFF}password=hunter2", "[redacted]"),
        ("password='hunter2", "password=[redacted]"),
        ("password=\u{301}hunter2", "password=[redacted]"),
        ("{\"password\":[\"hunter2\"]}", "{\"password\":[redacted]"),
        ("{\"password\":{\"v\":\"hunter2\"}}", "{\"password\":[redacted]"),
        ("{\"password\":\"hun\\\"ter2\"}", "{\"password\":[redacted]"),
        ("Authorization: Basic aHVudGVyMg==", "Authorization: [redacted]"),
        ("password=`hunter2`", "password=[redacted]"),
        ("password=(hunter2)", "password=[redacted]"),
        ("password={hunter2}", "password=[redacted]"),
        ("password=[hunter2]", "password=[redacted]"),
    ]

    /// The inputs of the third review, with the values that must not show.
    static let thirdReview: [(String, [String])] = [
        ("password hunter2", ["hunter2"]),
        ("login secret e32", ["e32"]),
        ("login api_key e33", ["e33"]),
        ("--client-secret k128", ["k128"]),
        ("export AWS_SECRET_ACCESS_KEY k129", ["k129"]),
        ("env: API_TOKEN k127", ["k127"]),
        ("PIN 1234 entered", ["1234"]),
        ("login ok\u{2026}: password hunter2 rejected", ["hunter2"]),
        ("db_pw=ft1 pw=ft2", ["ft1", "ft2"]),
        ("refresh=ft42", ["ft42"]),
        ("see https://example.com/users/12345678/reset?code=ft14", ["ft14", "12345678"]),
        ("go https://bob:k130@example.com/a/b#frag", ["bob", "k130", "frag"]),
        ("req {\"headers\":[[\"X-Api-Key\",\"k125\"]]}", ["k125"]),
        ("headers=[[\"X-Api-Key\",\"k123\"]]", ["k123"]),
        ("login [\"password\",\"e11\"]", ["e11"]),
        ("login {\"pass\" \"word\":\"e8\"}", ["e8"]),
        ("token=abc)k131 next", ["k131"]),
        ("token=abc]k132 next", ["k132"]),
        ("token=a}k133 next", ["k133"]),
        ("token=a\"k134 next", ["k134"]),
        ("token=a'k135 next", ["k135"]),
        ("token=(abc)k136 next", ["k136"]),
        ("token=[abc]k137 next", ["k137"]),
        ("token={abc}k138 next", ["k138"]),
        ("token=\"abc\"k139 next", ["k139"]),
        ("token=<abc>k140 next", ["k140"]),
        ("password: //k141", ["k141"]),
        ("password: /*k142", ["k142"]),
        ("password: //\nk143", ["k143"]),
        ("password: /*\nk144 */", ["k144"]),
        ("password: # c\nk145", ["k145"]),
    ]

    /// The inputs of the fourth review: a disguised name that ends its line, look-alike
    /// separators after escapes, values that run over lines in quotes, invisible fillers and
    /// controls in labels and values, with the values that must not show.
    static let fourthReview: [(String, [String])] = [
        ("<key>p\u{0430}ssword</key>\n<string>S3CRETV</string>", ["S3CRETV"]),
        ("p\u{0430}ssword\nS3CRETV", ["S3CRETV"]),
        ("pass\u{2027}word\nS3CRETV", ["S3CRETV"]),
        ("- p\u{2027}in :\n  (S3CRETV)", ["S3CRETV"]),
        ("my_k$ e%79\u{2254}S3CRETV&b=2", ["S3CRETV"]),
        ("\u{200B}a\u{E0061}ut\u{AD}\\u{68}\u{2254}S3CRETV==", ["S3CRETV"]),
        ("msg=\"<key>=\n\"S3CRETV\"\"", ["S3CRETV"]),
        ("password: 'abc\n  S3CRETV'", ["S3CRETV"]),
        ("password: 'abc\nS3CRETV", ["S3CRETV"]),
        ("token=`abc\n  S3CRETV`", ["S3CRETV"]),
        ("password='a\u{2028}S3CRETV'", ["S3CRETV"]),
        ("token: 'a\r\nS3CRETV'", ["S3CRETV"]),
        ("PRIVATE_KEY='-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nS3CRETVAbC==\n-----END PRIVATE KEY-----'", ["S3CRETV", "MIIEvQ"]),
        ("login pa\u{115F}ssword S3CRETV ok", ["S3CRETV"]),
        ("login pa\u{3164}ssword S3CRETV ok", ["S3CRETV"]),
        ("login pa\u{FFF0}ssword S3CRETV ok", ["S3CRETV"]),
        ("login pa\u{E0080}ssword S3CRETV ok", ["S3CRETV"]),
        ("login pa\u{7F}ssword S3CRETV ok", ["S3CRETV"]),
        ("login pa\u{0}ssword S3CRETV ok", ["S3CRETV"]),
        ("login pa\u{9F}ssword S3CRETV ok", ["S3CRETV"]),
        ("charged 4242\u{115F}4242\u{115F}4242\u{115F}4242", ["42424242", "4242\u{115F}4242"]),
        ("charged 4242\u{7F}4242\u{7F}4242\u{7F}4242", ["42424242", "4242\u{7F}4242"]),
        ("charged 4242\u{0}4242\u{0}4242\u{0}4242", ["42424242", "4242\u{0}4242"]),
        ("got Bearer\u{3164}S3CRETV", ["S3CRETV"]),
        ("mail alice\u{115F}smithS3CRETV@example.com", ["alice", "S3CRETV"]),
        ("mail alice\u{7F}smithS3CRETV@example.com", ["alice", "S3CRETV"]),
        ("callback https://x.example/api/password-reset/S3CRETV", ["S3CRETV"]),
        ("GET https://api.x.example/token/S3CRETV/info", ["S3CRETV"]),
        ("status\\=S3CRETV", ["S3CRETV"]),
    ]

    @Test("the fourth review's probes hide their values", arguments: fourthReview)
    func fourthReviewProbes(input: String, secrets: [String]) {
        let output = redactor.redact(input)
        for secret in secrets {
            #expect(!output.contains(secret), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a path segment after one that names a secret becomes :id", arguments: [
        ("https://x.example/v1/cards/4242/pin/4831", "https://x.example/v1/cards/:id/pin/:id"),
        ("https://x.example/api/password-reset/S3CRETV", "https://x.example/api/:id/:id"),
        ("https://x.example/users/me/otp/S3CRETV", "https://x.example/users/me/otp/:id"),
        ("https://x.example/api/keys/S3CRETV", "https://x.example/api/keys/:id"),
        ("https://x.example/api/session/S3CRETV", "https://x.example/api/session/:id"),
        ("https://x.example/token/S3CRETV/info", "https://x.example/token/:id/info"),
        ("https://x.example/docs/getting-started", "https://x.example/docs/getting-started"),
    ])
    func pathLabels(url: String, expected: String) throws {
        #expect(redactor.redact(url: try #require(URL(string: url))) == expected)
    }

    @Test("there are 51 probes of the second review")
    func count() {
        #expect(Self.secondReview.count == 51)
    }

    @Test("the second review's probes hide hunter2", arguments: secondReview)
    func secondReviewProbes(input: String, expected: String) {
        let output = redactor.redact(input)
        #expect(output == expected)
        #expect(!output.contains("ter2") && !output.contains("aHVudGVyMg"))
    }

    @Test("the third review's probes hide their values", arguments: thirdReview)
    func thirdReviewProbes(input: String, secrets: [String]) {
        let output = redactor.redact(input)
        for secret in secrets {
            #expect(!output.contains(secret), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }
}
