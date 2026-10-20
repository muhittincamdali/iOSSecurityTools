import Foundation
import Testing
import iOSSecurityTools

/// Objects and arrays that carry a field name in one place and its value in another: HTTP archive
/// headers, JSON Patch (RFC 6902), SCIM PatchOp (RFC 7644), fetch headers and `URLSearchParams`
/// entries. A secret or non-ASCII name hides the whole value; other names keep it.
@Suite("SensitiveDataRedactor name and value pairs")
struct RedactionPairTests {
    let redactor = SensitiveDataRedactor()
    static let secret = "hunter2"

    private func json(_ text: String, _ contentType: String = "application/json") -> String {
        redactor.redact(body: Data(text.utf8), contentType: contentType)
    }

    @Test("a JSON Patch operation on a secret path hides its value whole", arguments: [
        "/password", "/user/password", "/pin", "/credentials/apiKey", "password", "/users/0/client_secret", "/ŞİFRE", "/a~1b",
    ])
    func jsonPatch(path: String) {
        for value in [#""hunter2""#, "[\"hunter2\",1]", #"{"a":"hunter2"}"#] {
            let patch = #"[{"op":"replace","path":"\#(path)","value":\#(value)}]"#
            for contentType in ["application/json", "application/json-patch+json"] {
                let output = json(patch, contentType)
                #expect(output.hasSuffix(#","value":"[redacted]"}]"#), "\(output)")
                #expect(!output.contains(Self.secret))
            }
            #expect(!redactor.redact("status=200 \(patch) done").contains(Self.secret))
        }
    }

    @Test("a SCIM PatchOp on a secret attribute hides its value whole")
    func scimPatch() {
        let body = #"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"password","value":"hunter2"},{"op":"replace","path":"displayName","value":"Bob"}]}"#
        for contentType in ["application/json", "application/scim+json"] {
            let output = json(body, contentType)
            #expect(output.contains(#"{"op":"replace","path":"password","value":"[redacted]"}"#))
            #expect(output.contains(#"{"op":"replace","path":"displayName","value":"Bob"}"#))
        }
    }

    @Test("an operation on a path that names no secret keeps its value")
    func readablePaths() {
        let patch = #"[{"op":"replace","path":"/status","value":"active"},{"op":"add","path":"/items/3/count","value":2},{"op":"remove","path":"/password"}]"#
        #expect(json(patch) == patch)
    }

    @Test("every name field hides every value field of its object", arguments: ["name", "key", "field", "header", "param", "path", "k", "n", "Name"])
    func pairFields(nameField: String) {
        for valueField in ["value", "val", "values", "content", "data", "secret", "v", "VALUE"] {
            for name in ["Authorization", "X-Api-Key", "şifre", "pаss", "pass\u{200B}word", "a b!"] {
                let output = json(#"[{"\#(nameField)":"\#(name)","\#(valueField)":["hunter2",{"x":1}]}]"#)
                #expect(!output.contains(Self.secret), "\(nameField) \(name) \(valueField): \(output)")
            }
            // `key` and `secret` are secret names themselves, so their own values are hidden.
            let output = json(#"[{"\#(nameField)":"Accept","\#(valueField)":"text/html"}]"#)
            #expect(valueField == "secret" || output.contains(#""\#(valueField)":"text/html""#), "\(output)")
        }
    }

    @Test("a name that is an array or an object hides the value")
    func unreadableNames() {
        #expect(json(#"{"name":["password"],"value":"hunter2"}"#) == #"{"name":["password"],"value":"[redacted]"}"#)
        #expect(json(#"{"name":{"a":"b"},"value":"hunter2"}"#) == #"{"name":{"a":"b"},"value":"[redacted]"}"#)
        #expect(json(#"{"name":7,"value":42}"#) == #"{"name":7,"value":42}"#)
    }

    @Test("a two-element array whose first element hides a value hides its second whole")
    func arrayPairs() {
        let hidden = "pass\u{200B}word"
        let entries = #"[["Authorization","hunter2"],["Content-Type","application/json"],["şifre",["hunter2"]],["status","ok"],["\#(hidden)",{"a":"hunter2"}]]"#
        #expect(json(entries) == #"[["Authorization","[redacted]"],["Content-Type","application/json"],["şifre","[redacted]"],["status","ok"],["[redacted]","[redacted]"]]"#)
        #expect(!redactor.redact("headers \(entries)").contains(Self.secret))
        let har = #"{"headers":[{"name":"Cookie","value":"sid=hunter2"},{"name":"Accept","value":"*/*"}]}"#
        #expect(json(har) == #"{"headers":[{"name":"Cookie","value":"[redacted]"},{"name":"Accept","value":"*/*"}]}"#)
    }

    @Test("ordinary objects with a name and a value stay readable")
    func usefulness() {
        for kept in [
            #"{"name":"Widget","value":42,"values":[1,2],"content":"text","data":{"size":3}}"#,
            #"[["Content-Type","application/json"],["page",2]]"#,
            #"{"op":"test","path":"/status","value":"ok"}"#,
            #"{"n":7,"v":42}"#,
        ] {
            #expect(json(kept) == kept)
        }
    }

    @Test("the logging guide's examples of pairs, URL limits and addresses")
    func guideExamples() throws {
        let patch = #"[{"op":"replace","path":"/user/password","value":"hunter2"},{"op":"replace","path":"/status","value":"active"}]"#
        #expect(json(patch, "application/json-patch+json") == #"[{"op":"replace","path":"/user/password","value":"[redacted]"},{"op":"replace","path":"/status","value":"active"}]"#)
        let url = try #require(URL(string: "https://example.com" + String(repeating: "/a", count: 65)))
        #expect(redactor.redact(url: url) == "https://example.com")
        #expect(redactor.redact("ayşe.yılmaz@gmail.com 张伟@example.cn") == "a•••@gmail.com •••@example.cn")
    }
}
