/// The inputs of the seventeenth review, kept as tests (see ``RedactionSeventeenthReviewProbeTests``).
///
/// The correctness review (`c-17`) wrote free text with a value after a key that is not allowed in
/// every shape it could think of — quoted keys, separators, URLs, markup, JSON in a line and pairs
/// outside the documented shapes — and the text of an element inside quotes and inside other
/// markup. The adversarial review (`a-17`) wrote quoted keys with a line break inside them.
enum SeventeenthReviewShapes {
    static let secret = "SEKRETVAL"
    static let digits = "9182736455"
    static let tagSecret = "QZ9WK7RXV"

    /// The correctness review's free-text probes; each holds ``secret`` or ``digits`` after a key
    /// that is not allowed, or after a secret name.
    static var correctness: [String] {
        let m = secret
        return [
            // quoted keys (r17)
            "\"user\": \(m)", "\"user\" : \(m)", "\"user\"\n: \(m)", "\"user\"=\(m)", "\"user\"==\(m)", "\"user\" => \(m)", "\"user\":=\(m)",
            "\\\"user\\\": \(m)", "\\\\\"user\\\\\": \(m)", "\"us\\\"er\": \(m)", "\"status\": \"a\", \"user\": \(m)",
            "\"status\":\"a\"\"user\":\(m)", "\"(status\": \(m)", "\"status \": \(m)", "\" status\": \(m)", "\"stat us\": \(m)",
            "\"status\u{0301}\": \(m)", "\"status\": \(m) \"user\": \(m)2", "x \"user\":\"\(m)\"", "\"\": \(m)", "\"\" = \(m)",
            "\"a\" b\": \(m)", "\"status\"x: \(m)", "\"status\"\"\": \(m)", "'user': \(m)", "`user`: \(m)", "'status': 'a' 'user': '\(m)'",
            "status=\"x\" \"user\": \(m)", "status=x\"user\": \(m)", "status:\"a\":\(m)", "\"status\" \"user\": \(m)",
            "\"\\u0075ser\": \(m)", "\"st\\u0061tus\": 1 \"user\": \(m)", "{\"st\\u0061tus\":1,\"user\":\"\(m)\"}",
            "\"status\":1,\"user\":\"\(m)\"", "msg=\"\\\"user\\\": \(m)\"", "\"status\"\t:\t\"x\"\t\"user\"\t:\t\(m)",
            // keys and separators
            "user=\(m)", "user = \(m)", "user :\(m)", "user:\t\(m)", "user:\r\n\(m)", "user:\n\(m)", "user\n=\(m)", "user\r= \(m)",
            "user[name]=\(m)", "user(0)=\(m)", "{user}=\(m)", "[user]=\(m)", "<user>=\(m)", "(user)=\(m)", "user[]=\(m)",
            "status=200user=\(m)", "status=ok;user=\(m)", "status=ok,user=\(m)", "status=ok&user=\(m)", "status=ok?user=\(m)",
            "status=ok|user=\(m)", "status=a/user=\(m)", "status=a.user=\(m)", "status==user=\(m)", "status=\"a=b\" \(m)",
            "status=user:\(m)", "path=/a/b?user=\(m)", "path=/a/user=\(m)", "method=GET&user=\(m)", "count=3user=\(m)",
            "status=[user=\(m)]", "status=(user:\(m))", "status=\"ok\"user=\(m)", "12:30 user=\(m)", "12:30:user=\(m)",
            "user1:9182736455", "acct9:9182736455", "x1:9182736455", "user_1:9182736455", "user-1:9182736455", "user.1:9182736455",
            "ｕｓｅｒ=\(m)", "ｓｔａｔｕｓ=\(m)", "kullanıcı=\(m)", "user٣:\(m)", "status=200 kullanıcı: \(m)", "user\u{2474}=\(m)",
            "\u{1F101}user=\(m)", "user\u{0301}=\(m)", "us\u{0301}er=\(m)", "stat\u{200B}us=\(m)", "status\u{00A0}=\(m)",
            "user＝\(m)", "user꞉\(m)", "user\u{2028}=\(m)", "status=\u{0301}x user=\(m)", "us%65r=\(m)", "us&#101;r=\(m)",
            "X-User: \(m)", "Cookie: sid=\(m)", "Set-Cookie: sid=\(m); Path=/", "status=200 , user = '\(m)'", "Error: \(m)",
            "user == \(m)", "user := \(m)", "user ?= \(m)", "user += \(m)", "user => \(m)", "user ~= \(m)", "user <= \(m)",
            "user >= \(m)", "user =~ \(m)", "user |= \(m)", "user != \(m)",
            // URLs
            "see https://h.example/?user= \(m)", "see https://h.example/?user=\n\(m)", "https://h.example/a;user=\(m)/b",
            "https://h.example/user=\(m)/b", "https://h.example/u/user:\(m)", "https://h.example/u/user%3D\(m)", "https://h.example/x)user=\(m)",
            "https://h.example/x\\user=\(m)", "https://h.example/x>user=\(m)", "https://h.example/user\"=\(m)", "https://h.example/user' = \(m)",
            "https://h.example/status' = \(m)", "\"https://h.example/user\": \(m)", "https://h.example/user: \(m)", "https://h.example/a\" user=\(m)",
            "https://[::1]/a user=\(m)", "https://h.example/a] user=\(m)", "https://h.example/a, \"user\": \(m)", "https://h.example/a.\nuser=\(m)",
            "https://h.example/a#user=\(m)", "https://u:\(m)@h.example/a", "https://h.example:\(m)/a", "path=https://h.example/a?user=\(m)",
            // markup
            "<user>\(m)</user>", "<user><![CDATA[\(m)]]></user>", "<user><!-- c -->\(m)</user>", "<user><count/>\(m)</user>",
            "<user><status>\(m)</status></user>", "<user>< \(m)</user>", "<user><?x?>\(m)</user>", "<user><!x>\(m)</user>",
            "<user><1>\(m)</user>", "<user><_a>\(m)</user>", "<user></x>\(m)</user>", "<user><br/>\(m)</user>", "<user ><![CDATA[\(m)]]>",
            "<user>\n  <![CDATA[\(m)]]>\n</user>", "<status>ok</status><user><![CDATA[\(m)]]></user>", "<user><count>1</count>\(m)</user>",
            "<user value=\"\(m)\">", "<input name=\"user\" value=\"\(m)\">", "<user\n>\(m)</user>", "<status>ok</status> <user>\(m)</user>",
            // JSON in a line
            "{\"status\":1,\"user\":\"\(m)\"}", "{\"status\":{\"user\":\"\(m)\"}}", "[{\"status\":1},{\"user\":\"\(m)\"}]", "{\"status\":\"x\"}{\"user\":\"\(m)\"}",
            "[[\"user\",\"\(m)\"]]", "[ \"user\" , \"\(m)\" ]", "{\"status\":\"user=\(m)\"}", "{\"status\":[[\"user\",\"\(m)\"]]}",
            "{\"status\":\"ok\"} {\"user\":\"\(m)\"}", "{\"status\":\"ok\"} user=\(m)", "{\"status\":\n\"ok\"}\nuser=\(m)",
            "{\"status\":{\"name\":\"password\",\"value\":\"\(m)\"}}", "[\"status\",\"ok\"] [\"user\",\"\(m)\"]",
            // pairs outside the documented shapes (reported separately)
            "[('user', '\(m)')]", "('user','\(m)')", "{'user': '\(m)'}", "{user: \"\(m)\"}", "{:user=>\"\(m)\"}", "User(name=\(m))",
            "[\"user\",\"\(m)\",\"x\"]", "user -> \(m)", "status=200 user\t\(m)", "count=1;\(m)", "user,\(m)",
        ]
    }

    /// The correctness review's markup probes: element text after a CDATA section, a comment, a
    /// processing instruction, a child element or a closing tag, and inside quotes.
    static var markup: [String] {
        let m = tagSecret
        return [
            "<user><![CDATA[\(m)]]></user>", "<user><status>ok</status>\(m)</user>", "<user><br>\(m)</user>", "<user> <b>x</b> \(m)</user>",
            "<user></user>\(m)", "<user/>\(m)", "<phone><![CDATA[\(m)]]></phone>", "<name><!-- n -->\(m)</name>",
            "<address><line/>\(m)</address>", "<user>\n<!-- c -->\n\(m)\n</user>", "<user><?pi?>\(m)",
            "\"<user>\(m)</user>\"", "msg \"<user>\(m)</user>\" done", "'<user>\(m)</user>'", "`<user>\(m)</user>`",
            "\"x\" <user>\(m)</user>", "\"a <user>\(m)</user> b\"", "\" <user>\(m)</user>", "note: \"<user>\(m)</user>\"",
            "status=\"<user>\(m)</user>\"", "status='<phone>\(m)</phone>'", "(<user>\(m)</user>)", "[<user>\(m)</user>]",
        ]
    }

    /// The correctness review's probes that show their secret by design, with the reason.
    static var shown: [String: String] {
        let m = secret
        let pairs = "a value after a name that is not on the list without a separator (\"What it does not find\")"
        return [
            "\"status\": \(m) \"user\": \(m)2": "the value of an allowed key, before the key that cuts the text",
            "[('user', '\(m)')]": pairs, "('user','\(m)')": pairs, "[\"user\",\"\(m)\",\"x\"]": pairs, "user -> \(m)": pairs,
            "status=200 user\t\(m)": pairs, "count=1;\(m)": pairs, "user,\(m)": pairs,
        ]
    }

    /// The adversarial review's quoted keys, by how they were redacted: `t` a log line, `p` a
    /// text/plain body, `j` a JSON body. Each marker `QxNN` is written in a key or in quoted text.
    static let quotedKeys: [(mode: String, input: String)] = [
        ("t", "\"note \\\"Qx01\\\" x\": 1"),
        ("t", "\"a\\\"Qx02\": 1"),
        ("t", "\"\\\"Qx03\\\"\": 1"),
        ("t", "\"\"Qx04\"\": 1"),
        ("t", "\"note \"\"Qx05\"\" x\": 1"),
        ("t", "status=\"Qx06 note\": 1"),
        ("t", "\"status\":\"Qx07 note\":1"),
        ("t", "status = \"Qx08 note\" = 1"),
        ("t", "x\"Qx09\": 1"),
        ("t", "[\"Qx10\"]: 1"),
        ("t", "(\"Qx11\"): 1"),
        ("t", "\"Qx12\"\t: 1"),
        ("t", "\"Qx13\"\r\n: 1"),
        ("t", "\"Qx14\" := 1"),
        ("t", "\"Qx15\" => 1"),
        ("t", "\"Qx16\"==1"),
        ("t", "\"note\nQx17\": 1"),
        ("t", "[\"Qx18\",\"y\"]"),
        ("t", "[[\"status\",\"ok\"],[\"Qx19\",\"y\"]]"),
        ("t", "'Qx20 note': 1"),
        ("t", "{'user': 'Qx21'}"),
        ("t", "`Qx22`: 1"),
        ("t", "\"Qx23\":"),
        ("t", "ok \"Qx24\":\nmore"),
        ("t", "\"status\" \"Qx25\": 1"),
        ("t", "status: \"Qx26\" : 1"),
        ("t", "\"Qx27\" ,: 1"),
        ("t", "\"Qx28\"\\: 1"),
        ("t", "\"Qx29\" -> 1"),
        ("t", "\"Qx30\"\u{3000}: 1"),
        ("t", "\"note\nQx31\": 1"),
        ("t", "\"note Qx32\nx\": 1"),
        ("t", "\"Qx33\n\": 1"),
        ("t", "\"\nQx34\": 1"),
        ("t", "x \"a\nQx35 b\": 1"),
        ("t", "\"note\r\nQx36\": 1"),
        ("t", "\"note\rQx37\": 1"),
        ("t", "\"note\nQx38\""),
        ("t", "\"note\nQx39\" more"),
        ("t", "status=200 \"note\nQx40\": 1"),
        ("t", "\"note\nQx41\"=1"),
        ("t", "\"note\n\nQx42\": 1"),
        ("t", "\"a\n\" \"Qx43\": 1"),
        ("t", "\"note\n Qx44 \n\": 1"),
        ("t", "{\"note\nQx45\": 1}"),
        ("t", "\"note\tQx46\": 1"),
        ("t", "\"note\nQx47\": \"v\""),
        ("t", "log \"user\nQx48\":"),
        ("t", "\"Qx49\nnote\": x"),
        ("t", "\"session\nQx50\": 1"),
        ("t", "\"note Qx51"),
        ("t", "\"note Qx52\nmore"),
        ("t", "(note\nQx53): 1"),
        ("t", "[note\nQx54]: 1"),
        ("p", "\"note\nQx55\": 1"),
        ("j", "{\"m\":\"\\\"note\\nQx56\\\": 1\"}"),
    ]

    /// The markers of ``quotedKeys`` that show by design, with the reason: a key in quotes of any
    /// kind is cut at its opening quote (since the nineteenth review: `'Qx20 note': 1` and
    /// `` `Qx22`: 1 `` are hidden too), and the words before a key in brackets are text. Since the
    /// twenty-first review a quote glued to the word before it starts no quoted key, so
    /// `""Qx04"": 1` is cut where `Qx04` starts.
    static let shownMarkers: [String: String] = {
        var shown: [String: String] = [:]
        let byReason: [(String, [String])] = [
            ("quoted text before the quoted key that the separator follows", ["Qx05"]),
            ("JSON or brackets before a separator with no key, which cuts the text at its value", ["Qx10", "Qx11", "Qx27", "Qx28"]),
            ("a word before a key in brackets", ["Qx53", "Qx54"]),
            ("text without a trigger: `->` is no separator", ["Qx29"]),
        ]
        for (reason, markers) in byReason {
            for marker in markers { shown[marker] = reason }
        }
        return shown
    }()
}
