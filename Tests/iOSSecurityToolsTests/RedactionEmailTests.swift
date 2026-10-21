import Foundation
import Testing
import iOSSecurityTools

/// Addresses whose name has letters without an ASCII form (`ı`, `ø`, `ł`, `ß`, `đ`, Han) are found
/// whole: only the first letter of the name is written, never the rest.
@Suite("SensitiveDataRedactor email addresses in any script")
struct RedactionEmailTests {
    let redactor = SensitiveDataRedactor()

    /// Addresses and their masks: Turkish, Nordic, Polish, German, Croatian, Chinese and Russian
    /// names, and domains in Cyrillic and Han.
    static let addresses: [(String, String)] = [
        ("ayşe.yılmaz@gmail.com", "a•••@gmail.com"),
        ("ılgın.öztürk@firma.com.tr", "ı•••@firma.com.tr"),
        ("ismail.ışık@example.com", "i•••@example.com"),
        ("bjørn.dæhlie@example.no", "b•••@example.no"),
        ("søren.ågård@example.dk", "s•••@example.dk"),
        ("łukasz.żółć@example.pl", "ł•••@example.pl"),
        ("michał.wróbel@example.pl", "m•••@example.pl"),
        ("groß@example.de", "g•••@example.de"),
        ("đorđe.đurić@example.hr", "đ•••@example.hr"),
        ("张伟@example.cn", "•••@example.cn"),
        ("王小明@example.cn", "王•••@example.cn"),
        ("王小明@例子.中国", "王•••@例子.中国"),
        ("иван.петров@пример.рф", "и•••@пример.рф"),
        ("first.last+tag@mail.example.co.uk", "f•••@mail.example.co.uk"),
    ]

    @Test("an address is masked whole in free text, whatever script its name is in", arguments: addresses)
    func freeText(address: String, mask: String) {
        #expect(redactor.redact("sent to \(address) today") == "sent to \(mask) today")
        #expect(redactor.redact(address) == mask)
    }

    @Test("an address is masked whole in JSON, in a form and in a multipart part", arguments: addresses)
    func bodies(address: String, mask: String) {
        let json = redactor.redact(body: Data(#"{"email":"\#(address)","to":["\#(address)"]}"#.utf8), contentType: "application/json")
        #expect(json == #"{"email":"\#(mask)","to":["\#(mask)"]}"#)
        let encoded = address.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let form = redactor.redact(body: Data("email=\(encoded)".utf8), contentType: "application/x-www-form-urlencoded")
        #expect(form.removingPercentEncoding == "email=\(mask)")
        let multipart = "--B\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\n\(address)\r\n--B--"
        #expect(redactor.redact(body: Data(multipart.utf8), contentType: "multipart/form-data; boundary=B").contains("\r\n\r\n\(mask)\r\n"))
    }

    @Test("no letter of a name but the first is written", arguments: addresses)
    func nameHidden(address: String, mask: String) {
        let name = address.unicodeScalars.prefix { $0 != "@" }
        let output = redactor.redact("1 \(address) 2") + redactor.redact(body: Data(#"["\#(address)"]"#.utf8), contentType: "application/json")
        for scalar in name.dropFirst() where scalar.properties.isAlphabetic {
            #expect(!output.unicodeScalars.contains(scalar) || mask.unicodeScalars.contains(scalar), "\(scalar) of \(address) in \(output)")
        }
    }

    @Test("the forms the review found leaking are masked whole")
    func reviewed() {
        #expect(redactor.redact(body: Data(#"{"email":"ayşe.yılmaz@gmail.com"}"#.utf8), contentType: "application/json") == #"{"email":"a•••@gmail.com"}"#)
        #expect(redactor.redact(body: Data(#"{"to":"ılgın.öztürk@firma.com.tr"}"#.utf8), contentType: "application/json") == #"{"to":"ı•••@firma.com.tr"}"#)
        let form = redactor.redact(body: Data("email=ay%C5%9Fe.y%C4%B1lmaz%40gmail.com".utf8), contentType: "application/x-www-form-urlencoded")
        #expect(form == "email=a%E2%80%A2%E2%80%A2%E2%80%A2%40gmail.com")
        #expect(redactor.redact("bjørn.dæhlie@example.no") == "b•••@example.no")
    }

    @Test("a word of letters before the address is part of its name")
    func gluedName() {
        #expect(redactor.redact("メールalice@example.com") == "メ•••@example.com")
        #expect(redactor.redact("联系张伟@example.cn") == "联•••@example.cn")
    }

    @Test("what is not an address is left as it was")
    func notAddresses() {
        for text in ["a@b.c", "x@1.2.3.4", "张伟@例子", "@example.com", "ayşe@", "name @ example.com"] {
            #expect(redactor.redact(text) == text)
        }
        #expect(redactor.redact("user:pass@host.com") == "user:[redacted]")
    }
}
