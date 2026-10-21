import Foundation
import Testing
import iOSSecurityTools

/// The twenty-first review's URL probes: in a path, the segment after one whose `;` parameter
/// named a secret showed (`/a;pin/hunterzoo` kept `hunterzoo`), as the parameters were read like
/// query parameters while Express, Go, Rails, Django and ASP.NET Core read `a;pin` as the segment
/// and only a Java servlet reads `pin` as a parameter. A path with a `;`, raw or escaped as `%3B`,
/// now records the scheme, host and port only; no parameter after a `;` is read.
@Suite("SensitiveDataRedactor URL paths with a semicolon")
struct RedactionURLSemicolonTests {
    let redactor = SensitiveDataRedactor()

    /// The probes of the review (649, 879 to 905), the value in each starting with `hunter` or
    /// `zebraf`.
    static let probes = [
        "https://x.example/a;pin/zebrafish",
        "https://api.example.com/a;pin/hunterzoo", "https://api.example.com/a;password/hunterzoo", "https://api.example.com/a;token/hunterzoo",
        "https://api.example.com/a;session/hunterzoo", "https://api.example.com/a;apikey/hunterzoo", "https://api.example.com/a;PASSWORD/hunterzoo",
        "https://api.example.com/a;user_pin/hunterzoo", "https://api.example.com/a;cards/hunterzoo", "https://api.example.com/a;secret/hunterzoo",
        "https://api.example.com/a;sid/hunterzoo", "https://api.example.com/a;otp/hunterzoo", "https://api.example.com/a;cvv/hunterzoo",
        "https://api.example.com/login;password/hunterzoo", "https://api.example.com/v1/users;pin/hunterzoo/info",
        "https://api.example.com/a;pin=/hunterzoo", "https://api.example.com/a;b=1;token/hunterzoo", "https://api.example.com/a;pin,x/hunterzoo",
        "https://api.example.com/a;x;y;pin/hunterzoo", "https://api.example.com/a;pin%3D/hunterzoo", "https://api.example.com/a;p%69n/hunterzoo",
        "https://api.example.com/a;pin/hunterzoo;x=1", "https://api.example.com/a;pin/hunterzoo?page=2", "https://api.example.com/pin/hun;ter",
        "https://api.example.com/pin/hunterzoo;x=1", "https://api.example.com/a;pin%20/hunterzoo", "https://api.example.com/pin/hun;terzoo",
        "https://api.example.com:8443/a;pin/hunterzoo",
        // The review's paths that the redactor read differently: an escaped `;`.
        "https://api.example.com/a%3Bpin/hunterzoo", "https://api.example.com/a%3bpin/hunterzoo",
    ]

    /// The scheme, host and port of a URL.
    static func hostOnly(_ text: String) throws -> String {
        let components = try #require(URLComponents(string: text))
        let host = try #require(components.scheme) + "://" + (components.percentEncodedHost ?? "")
        return components.port.map { host + ":\($0)" } ?? host
    }

    @Test("each probe records the scheme, host and port only, with any kinds, and cuts a line at its start", arguments: probes)
    func probe(text: String) throws {
        let url = try #require(URL(string: text))
        let expected = try Self.hostOnly(text)
        #expect(redactor.redact(url: url) == expected)
        #expect(SensitiveDataRedactor(kinds: [.cardNumbers]).redact(url: url) == expected)
        #expect(SensitiveDataRedactor(allowedQueryParameters: ["page", "x"]).redact(url: url) == expected)
        #expect(redactor.redact("GET \(text) 200") == "GET [redacted]")
    }

    /// Secret names, the ways a `;` is written and where the parameter stands.
    static let names = ["pin", "password", "token", "session", "apikey", "PASSWORD", "user_pin", "sid", "otp", "cvv", "p%69n", "pin%20", "pin%3D", "pin=", "status"]
    static let semicolons = [";", "%3B", "%3b", ";b=1;", ";x;y;", ";;"]
    static let layouts = ["/a{;}{name}/{value}", "/v1/users{;}{name}/{value}/info", "/{name}/{value}{;}x=1", "/a{;}{name},x/{value}", "/{;}{name}/{value}"]

    @Test("no generated path with a semicolon shows a segment, whatever the parameter names")
    func generated() throws {
        let value = "Qz9W1hunter"
        var shown: [String] = []
        for name in Self.names {
            for semicolon in Self.semicolons {
                for layout in Self.layouts {
                    for suffix in ["", "?page=2", "#frag"] {
                        let path = layout.replacingOccurrences(of: "{;}", with: semicolon).replacingOccurrences(of: "{name}", with: name)
                            .replacingOccurrences(of: "{value}", with: value)
                        let text = "https://api.example.com:8443" + path + suffix
                        guard let url = URL(string: text) else { continue }
                        if redactor.redact(url: url) != "https://api.example.com:8443" { shown.append(text) }
                    }
                }
            }
        }
        #expect(shown.isEmpty, "\(shown.count) paths show more than the host: \(shown.prefix(10))")
    }

    @Test("a path without a semicolon is still read segment by segment")
    func plainPathsStay() throws {
        #expect(redactor.redact(url: try #require(URL(string: "https://api.example.com/v1/items/42/info"))) == "https://api.example.com/v1/items/42/info")
        #expect(redactor.redact(url: try #require(URL(string: "https://api.example.com/pin/4831/info"))) == "https://api.example.com/pin/:id/info")
        #expect(redactor.redact(url: try #require(URL(string: "https://api.example.com/a-b/c-d.json"))) == "https://api.example.com/a-b/c-d.json")
        // A segment that is not a plain-ASCII name is a label: the segment after it is a value.
        #expect(redactor.redact(url: try #require(URL(string: "https://api.example.com/a,b/c-d.json"))) == "https://api.example.com/a,b/:id")
    }
}
