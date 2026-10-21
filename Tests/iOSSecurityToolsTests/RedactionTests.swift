import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("Redacted")
struct RedactedTests {
    struct LoginRequest: Codable, Equatable {
        var username: String
        @Redacted var password: String
    }

    let request = LoginRequest(username: "alice", password: "hunter2-secret")

    @Test("no printing or reflection path shows the wrapped value")
    func everyDescriptionHidesTheValue() {
        let value = Redacted("hunter2-secret")
        var dumpedValue = ""
        dump(value, to: &dumpedValue)
        var dumpedRequest = ""
        dump(request, to: &dumpedRequest)
        let optional: Redacted<String>? = value
        let outputs = [
            "\(value)",
            String(describing: value),
            String(reflecting: value),
            "\(optional as Any)",
            "\([value])",
            "\(["key": value])",
            dumpedValue,
            "\(request)",
            String(reflecting: request),
            dumpedRequest,
            (value as AnyObject).description ?? "",
            String(describing: Mirror(reflecting: value).children.map(\.value)),
        ]
        for output in outputs {
            #expect(!output.contains("hunter2"), "Leaked in: \(output)")
        }
        #expect("\(value)" == "<redacted>")
        #expect("\(request)".contains("<redacted>"))
        #expect(Mirror(reflecting: value).children.isEmpty)
    }

    @Test("the value is available when read explicitly")
    func explicitAccess() {
        #expect(request.password == "hunter2-secret")
        #expect(Redacted(42).wrappedValue == 42)
    }

    @Test("Codable is transparent, so request bodies keep their shape")
    func codable() throws {
        let json = try JSONEncoder().encode(request)
        let object = try JSONSerialization.jsonObject(with: json) as? [String: String]
        #expect(object == ["username": "alice", "password": "hunter2-secret"])
        #expect(try JSONDecoder().decode(LoginRequest.self, from: json) == request)
    }

    @Test("equality and hashing use the wrapped value")
    func equality() {
        #expect(Redacted("a") == Redacted("a"))
        #expect(Redacted("a") != Redacted("b"))
        #expect(Set([Redacted("a"), Redacted("a")]).count == 1)
    }
}

@Suite("Mask")
struct MaskTests {
    @Test("card numbers keep the last four digits", arguments: [
        ("4242 4242 4242 4242", "•••• 4242"),
        ("4242-4242-4242-4242", "•••• 4242"),
        ("378282246310005", "•••• 0005"),
        ("４２４２４２４２４２４２４２４２", "•••• 4242"),
        ("٤٢٤٢٤٢٤٢٤٢٤٢٤٢٤٢", "•••• 4242"),
        ("12345678901", "••••"),
        ("", "••••"),
        ("not a card", "••••"),
    ])
    func cardNumbers(input: String, expected: String) {
        #expect(Mask.cardNumber(input) == expected)
    }

    @Test("emails hide the name and keep the domain", arguments: [
        ("alice@example.com", "a•••@example.com"),
        ("al@example.com", "•••@example.com"),
        ("a@example.com", "•••@example.com"),
        ("first.last+tag@mail.example.co.uk", "f•••@mail.example.co.uk"),
        ("alice", "••••"),
        ("@example.com", "••••"),
        ("alice@localhost", "••••"),
        ("alice@.com", "••••"),
        ("alice@example.com.", "••••"),
        ("al ice@example.com", "••••"),
        ("alice@example.com\nERROR forged line", "••••"),
        ("al\u{202E}ice@example.com", "••••"),
        ("a@b@example.com", "••••"),
    ])
    func emails(input: String, expected: String) {
        #expect(Mask.email(input) == expected)
    }

    @Test("trailing keeps at most a third of the value", arguments: [
        ("DE89370400440532013000", 4, "•••• 3000"),
        ("123456789012", 4, "•••• 9012"),
        ("12345678901", 4, "••••"),
        ("1234", 4, "••••"),
        ("12345", 4, "••••"),
        ("123456", 2, "•••• 56"),
        ("123456", 0, "••••"),
        ("123456", -3, "••••"),
        ("123456789012345678901234567890", 10, "•••• 7890"),
        ("123456789012345678901234567890", Int.max, "•••• 7890"),
        ("123456789012345678901234567890", Int.min, "••••"),
        ("+90 555 123 45 67", 4, "•••• 5 67"),
    ])
    func trailing(input: String, visible: Int, expected: String) {
        #expect(Mask.trailing(input, visibleCount: visible) == expected)
    }

    @Test("trailing does not show line breaks or invisible characters")
    func trailingUnsafeCharacters() {
        #expect(Mask.trailing("1234567890\n123", visibleCount: 4) == "••••")
        #expect(Mask.trailing("12345678901\u{200B}23", visibleCount: 4) == "••••")
    }

    @Test("the mask does not depend on the length of the hidden part")
    func fixedLength() {
        #expect(Mask.trailing("1234") == Mask.trailing("12345678901"))
        #expect(Mask.cardNumber("4242424242424242") == Mask.cardNumber("4242 4242 4242 4242 4242"))
    }
}

