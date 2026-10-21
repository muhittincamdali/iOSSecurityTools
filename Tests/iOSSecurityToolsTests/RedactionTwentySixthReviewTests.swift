import Foundation
import Testing
@testable import iOSSecurityTools

/// The twenty-sixth review (`a-26`, `c-26`) found three things:
///
/// - A name of control characters alone (`{"ParameterKey":"\n",…}`) did not hide what was beside
///   it, while the documentation said a name with a control character in it names a secret
///   wherever it is.
/// - A short string with a line break or a tab that names nothing (`ok\n`, `a\tb`) hid every
///   member beside it, in objects, forms and multipart bodies.
/// - The documentation of the type said that words of five or more letters count anywhere in a
///   key, while `token` and `secret` count only as a word or at the end, and `pw` only as a word.
@Suite("SensitiveDataRedactor twenty-sixth review")
struct RedactionTwentySixthReviewTests {
    private static let secret = "Qz26Wk5m"

    private static func json(_ text: String) -> String {
        SensitiveDataRedactor().redact(body: Data(text.utf8), contentType: "application/json")
    }

    private static func form(_ text: String) -> String {
        SensitiveDataRedactor().redact(body: Data(text.utf8), contentType: "application/x-www-form-urlencoded")
    }

    private static func multipart(name: String, beside field: String) -> String {
        let body = "--B0und\r\nContent-Disposition: form-data; name=\"\(field)\"\r\n\r\n\(name)\r\n--B0und\r\n"
            + "Content-Disposition: form-data; name=\"Value\"\r\n\r\n\(secret)\r\n--B0und--"
        return SensitiveDataRedactor().redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B0und")
    }

    @Test("a name of control characters and spaces alone hides the value beside it, on every path")
    func blankNames() {
        let s = Self.secret
        let shown = [
            Self.json(#"{"ParameterKey":"\n","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":"\t","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":"\u0000","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":" \n ","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":"\r\n\u007f","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"title":"\n","data":"\#(s)"}"#),
            Self.json(#"[{"OptionName":"\u0085","Value":"\#(s)"}]"#),
            Self.form("ParameterKey=%0A&ParameterValue=\(s)"),
            Self.form("ParameterKey=%00&ParameterValue=\(s)"),
            Self.form("ParameterKey=+%09+&ParameterValue=\(s)"),
            Self.multipart(name: "\t", beside: "OptionName"),
        ].filter { $0.contains(s) }
        #expect(shown.isEmpty, "\(shown)")
    }

    @Test("a short string with a line break or a tab that names nothing keeps the members beside it")
    func plainLinesKeepSiblings() {
        let bodies = [
            #"{"message":"Hello\nWorld","id":"7"}"#,
            #"{"stdout":"ok\n","exit_code":0,"duration_ms":12}"#,
            #"{"cols":"a\tb","row":7}"#,
            #"{"cols":"a\tb\tc","row":7}"#,
            #"{"id":1,"status":"ok","message":"line one\nline two","count":3}"#,
            #"{"text":"a\r\nb","user":"alice"}"#,
            #"[{"msg":"a\nb","user":"alice"}]"#,
        ]
        for body in bodies {
            #expect(Self.json(body) == body)
        }
        #expect(Self.form("msg=hello%0A&user=alice") == "msg=hello%0A&user=alice")
        #expect(Self.form("msg=a%09b&user=alice") == "msg=a%09b&user=alice")
        #expect(!Self.multipart(name: "line one\nline two", beside: "msg").contains("[redacted]"))
        #expect(!Self.multipart(name: "ok\n", beside: "msg").contains("[redacted]"))
    }

    @Test("a name with a control character that names a secret, left out or read as a space, hides the value")
    func controlReadings() {
        let s = Self.secret
        let names = [
            #"DbPassword\n"#, #"\nDBPassword"#, #"Db\nPassword"#, #"pa\nssword"#, #"api\nkey"#, #"\r\npin"#,
            #"pass\u0000word"#, #"to\tken"#, #"Db\u001bPassword"#, #"session\u0085id"#, #"user\tpin"#,
        ]
        var shown: [String] = []
        for name in names {
            for body in [#"{"ParameterKey":"\#(name)","ParameterValue":"\#(s)"}"#, #"[{"OptionName":"\#(name)","Value":"\#(s)"}]"#]
            where Self.json(body).contains(s) {
                shown.append(body)
            }
        }
        for name in ["pa%0Assword", "Db%0APassword", "%0D%0Apin", "to%09ken"] where Self.form("OptionName=\(name)&Value=\(s)").contains(s) {
            shown.append(name)
        }
        for name in ["pa\nssword", "Db\tPassword", "\r\npin"] where Self.multipart(name: name, beside: "OptionName").contains(s) {
            shown.append(name.debugDescription)
        }
        #expect(shown.isEmpty, "\(shown)")
    }

    @Test("a name with a control character held by a field that holds a name hides the value whatever it says")
    func heldNamesWithControls() {
        #expect(Self.json(#"{"name":"Hello\nWorld","value":"x"}"#) == #"{"name":"Hello\nWorld","value":"[redacted]"}"#)
        #expect(Self.json(#"{"label":"ok\n","value":"x"}"#) == #"{"label":"ok\n","value":"[redacted]"}"#)
        #expect(Self.json(#"[["a\tb","x"]]"#) == #"[["a\tb","[redacted]"]]"#)
        #expect(Self.form("name=region%0A&value=x") == "name=region%0A&value=[redacted]")
    }

    /// The documentation of the type and the logging guide say where a secret word counts in a key:
    /// the long names and the compounds anywhere, `token`, `secret` and the short words as a word or
    /// at the end, `pass`, `sid` and `pw` only as a word, `session` only as the last word.
    @Test("a secret word counts in a key where the documentation says", arguments: [
        ("dbpassword", true), ("dbPassword", true), ("xpassphrasey", true), ("myapikeyhash", true), ("oldcredentials", true),
        ("user_pin", true), ("X-Auth-Key", true), ("apitoken", true), ("mysecret", true), ("refresh_token", true),
        ("tokenvalue", false), ("TOKENID", false), ("secretvalue", false), ("secrethash", false), ("tokenizer", false),
        ("DB_PASS", true), ("user_pw", true), ("bypass", false), ("dbpw", false), ("userpw", false),
        ("laravel_session", true), ("session_start", false),
    ])
    func keyPlacement(key: String, hides: Bool) {
        let json = Self.json(#"{"\#(key)":"v1","status":"ok"}"#)
        #expect(json == (hides ? #"{"\#(key)":"[redacted]","status":"ok"}"# : #"{"\#(key)":"v1","status":"ok"}"#))
        let form = Self.form("\(key)=v1&status=ok")
        #expect(form == (hides ? "\(key)=[redacted]&status=ok" : "\(key)=v1&status=ok"))
    }

    /// The examples of "Known limitations" in the logging guide and the README, as written there.
    @Test("the known limitations read as the documentation says")
    func knownLimitations() {
        #expect(Self.json(#"{"name":"Hello\nWorld","value":"x"}"#) == #"{"name":"Hello\nWorld","value":"[redacted]"}"#)
        #expect(Self.json(#"{"note":"pass\nword","id":"7"}"#) == #"{"note":"pass[redacted]","id":"[redacted]"}"#)
        for key in ["tokenvalue", "TOKENID", "secretvalue", "secrethash", "userpw", "dbpw"] {
            #expect(Self.json(#"{"\#(key)":"x"}"#) == #"{"\#(key)":"x"}"#)
        }
        #expect(Self.json(#"{"title":"\n","data":"x"}"#) == #"{"title":"\n","data":"[redacted]"}"#)
        let long = String(repeating: #"\n"#, count: 257)
        #expect(Self.json(#"{"title":"\#(long)","data":"x"}"#) == #"{"title":"\#(long)","data":"x"}"#)
    }

    @Test("a name of spaces alone, or an empty one, beside a field that holds no name keeps the value")
    func spacesAlone() {
        #expect(Self.json(#"{"title":" ","data":"ok"}"#) == #"{"title":" ","data":"ok"}"#)
        #expect(Self.json(#"{"title":"","data":"ok"}"#) == #"{"title":"","data":"ok"}"#)
        #expect(Self.form("title=+&data=ok") == "title=+&data=ok")
    }
}
