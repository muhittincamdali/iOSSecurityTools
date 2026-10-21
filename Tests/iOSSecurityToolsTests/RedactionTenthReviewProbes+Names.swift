import Foundation
@testable import iOSSecurityTools

// swiftlint:disable line_length
extension TenthReviewProbeSet {
    // Secret names written as values in free text, disguised with confusables,
    // invisible format characters, marks, escapes and brackets, on three paths.
    func addNames() {
        section("n9-name-value-confusable")
        p("name=\"p\u{430}ssword\" {S}")                                   // Cyrillic a
        p("name=\"\u{3C1}assword\" {S}")                                   // Greek rho
        p("name=\"\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}\" {S}") // math bold
        p("name=\"\u{24DF}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3}\" {S}")         // circled
        p("name=\"\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}\" {S}")         // full width
        p("id: \"p\u{456}n\" {S}")                                         // Cyrillic i
        p("field='\u{1D69D}\u{1D698}\u{1D694}\u{1D68E}\u{1D697}' {S}")     // math monospace token
        p("key=\"\u{FF21}\u{FF30}\u{FF29} \u{FF2B}\u{FF45}\u{FF59}\" {S}")  // full-width API Key
        p("label=\"\u{3A1}\u{1D670}\u{1D682}\u{1D682}\u{1D686}\u{1D67E}\u{1D681}\u{1D673}\" {S}")  // Greek Rho + monospace
        p("header=\"\u{24B6}uthorization\" {S}")                            // circled capital A
        p("label=\"\u{41F}\u{430}\u{440}\u{43E}\u{43B}\u{44C}\" {S}", claim: "X")              // whole-script Cyrillic word
        p("label=\"\u{30D1}\u{30B9}\u{30EF}\u{30FC}\u{30C9}\" {S}", claim: "X")                // Japanese word

        section("n9-name-value-invisible")
        p("name=\"pass\u{AD}word\" {S}")
        p("name=\"pass\u{200D}word\" {S}")
        p("name=\"pass\u{200C}word\" {S}")
        p("name=\"api\u{2060}_key\" {S}")
        p("\u{200B}name=\"token\"\u{200B} {S}")
        p("name=\u{2063}\"password\"\u{2063} {S}")
        p("name=\"\u{FEFF}secret\" {S}")
        p("name=\"pass\u{FE0F}word\" {S}")
        p("name=\"pass\u{E0020}word\" {S}")
        p("name=\"pass\u{180E}word\" {S}")
        p("name=\"pass\u{17B4}word\" {S}")
        p("name=\"pass\u{3164}word\" {S}")
        p("name=\"pass\u{1D173}word\" {S}")
        p("name=\"pass\u{7F}word\" {S}")

        section("n9-name-value-mark")
        p("name=\"pa\u{301}ssword\" {S}")
        p("name=\"to\u{308}ken\" {S}")
        p("name=\"p\u{20DD}in\" {S}")
        p("name=\"t\u{336}o\u{336}k\u{336}e\u{336}n\u{336}\" {S}")
        p("name=\"se\u{301}cret\u{327}\" {S}")
        p("name=\"pass\u{94D}word\" {S}")                                  // Devanagari virama

        section("n9-name-value-escape")
        p("name=\"pass&#119;ord\" {S}")
        p("name=\"pass&#x77;ord\" {S}")
        p("name=\"pass%77ord\" {S}")
        p("name=\"pass\\u0077ord\" {S}")
        p("name=\"pass\\x77ord\" {S}")
        p("name=\"api&#x5F;key\" {S}")
        p("name=\"&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;\" {S}")
        p("name=\"pass%2577ord\" {S}")
        p("name=&quot;password&quot; {S}")
        p("name=\\\"password\\\" {S}")

        section("n9-name-value-bracket")
        p("[password] {S}")
        p("(token): {S}")
        p("{password} {S}")
        p("\u{AB}password\u{BB} {S}")
        p("\u{3010}password\u{3011}{S}")
        p("\u{300C}token\u{300D}\u{FF1A}{S}")
        p("\"password\"{S}")
        p("'api_key'=>'{S}'")
        p("`token` `{S}`")
        p("name=(\"password\") {S}")
        p("name=[\"pin\"] {S}", claim: "X")                                   // text after a JSON value

        section("n9-name-value-shape")
        p("D/Prefs: putString(key=\"pin\", value=\"{S}\")")
        p("prefs.set(\"{S}\", forKey: \"password\")", claim: "X")         // value before the name
        p("setValue({S}, forKey: \"token\")", claim: "X")
        p("title=\"Change password\" {S}")
        p("placeholder=\"Enter PIN\" {S}")
        p("msg=\"token expired\" {S}")
        p("name=\"status\" password {S}")
        p("note=\"password\"\n\n\n{S}")
        p("note=\"password\"\n   \n\t{S}")
        p("name='token'\\\n{S}")
        p("name=\"password\" \\\n{S}")
        p("field: \"password\" (\n{S}\n)")
        p("name=\"password\",\n{S}")
        p("id = 'pin' :\n{S}")

        section("n9-name-value-paths")
        p("name=\"p\u{430}ssword\" {S}", plain)
        p("name=\"pass\u{AD}word\" {S}", plain)
        p("{\"log\":\"name=\\\"p\u{430}ssword\\\" {S}\"}", json)
        p("{\"log\":\"name=\\\"pass\\u00ADword\\\" {S}\"}", json)
        p("{\"log\":\"<string name=\\\"api_key\\\">{S}</string>\"}", json)
        p("{\"log\":\"<key>password</key>\\n<string>{S}</string>\"}", json)
        p("note=name%3D%22password%22+{S}", form)
        p("note=%3Ckey%3Epassword%3C%2Fkey%3E%3Cstring%3E{S}%3C%2Fstring%3E", form)
        p("https://x.example/a?q=name%3D%22password%22+{S}", .urlAllowing(["q"]))
        p("https://x.example/a?q=%3Ckey%3Epassword%3C%2Fkey%3E%3Cstring%3E{S}%3C%2Fstring%3E", .urlAllowing(["q"]))
    }

    // XML, HTML and property lists that write a secret name as an attribute or element text.
    func addMarkup() {
        section("n9-markup-attribute")
        p("<string name=\"\u{3C1}assword\">{S}</string>")
        p("<string name=\"\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}\">{S}</string>")
        p("<string name=\"\u{24DF}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3}\">{S}</string>")
        p("<string name=\"api\u{2060}_key\">{S}</string>")
        p("<string name=\"to\u{308}ken\">{S}</string>")
        p("<string name=\"api&#x5F;key\">{S}</string>")
        p("<string name=\"password\" translatable=\"false\">{S}</string>")
        p("<string\n    name=\"api_key\">{S}</string>")
        p("<string name=\"api_key\">\n{S}\n</string>")
        p("<string name=\"api_key\"><![CDATA[{S}]]></string>")
        p("<string name=\"api_key\">\n<![CDATA[\n{S}\n]]>\n</string>")
        p("<string name='api_key'>{S}</string>")
        p("<string name=api_key>{S}</string>")
        p("<string name=\"password\">x</string>{S}")
        p("<string name=\"status\">ok</string> <string name=\"password\">\n{S}</string>")
        p("<entry key=\"db.password\">{S}</entry>")
        p("<entry key=\"db.p\u{430}ssword\">\n  {S}\n</entry>")
        p("<add key=\"ConnectionStrings:Db\" value=\"Server=x;Password={S}\"/>")
        p("<input type=\"password\" name=\"pw\" value=\"{S}\">")
        p("<input value=\"{S}\" type=\"password\">")
        p("<input\n  value=\"{S}\"\n  type=\"password\">")
        p("<input data-x=\"{S}\" name=\"pin\" />")
        p("<param name=\"token\" value=\"x\">{S}")
        p("<string name=\"password\" />\n{S}", claim: "X")              // the element ended on its line
        p("<STRING NAME=\"PASSWORD\">{S}</STRING>")
        p("<string name=\"api_key\">\n  line one\n{S}\n</string>")
        p("<String name=\"password\">\n  x\n{S}\n</string>", claim: "X")         // end tag of another case
        p("<string name=\"api_key\">\n<!-- </string> -->\n{S}\n</string>")
        p("<string name=\"api_key\">\u{2028}{S}\u{2028}</string>")
        p("<string name=\"api_key\">\u{85}{S}</string>")
        p("<string name=\"api_key\">\r\n{S}\r\n</string>")

        section("n9-markup-element-text")
        p("<key>\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}</key><string>{S}</string>")
        p("<key>p\u{430}ssword</key>\n<string>{S}</string>")
        p("<key>pass\u{AD}word</key><string>{S}</string>")
        p("<key>pass&#x77;ord</key><string>{S}</string>")
        p("<key>password</key>\n\n\n<string>{S}</string>")
        p("<key>password</key>\n<!-- comment -->\n<string>{S}</string>")
        p("<key>Password</key><data>\n{S}\n</data>")
        p("<key>password</key>\n{S}")
        p("<key>password</key>\n    {S}")
        p("<KEY>password</KEY>\n<STRING>{S}</STRING>")
        p("<ns:key>password</ns:key><ns:string>{S}</ns:string>")
        p("<key><![CDATA[password]]></key><string>{S}</string>")
        p("<key>password</key>\u{2028}<string>{S}</string>")
        p("<key> password </key>\n<string>\n{S}\n</string>")
        p("<key>password</key><string/>\n<string>{S}</string>", claim: "X")       // empty element first
        p("<dict>\n\t<key>token</key>\n\t<string>{S}</string>\n</dict>")
        p("<dict><key>status</key><string>ok</string><key>pin</key><integer>{S}</integer></dict>")
        p("<dt>PIN</dt><dd>{S}</dd>")
        p("<tr><th>Password</th><td>{S}</td></tr>")
        p("<tr>\n<th>Password</th>\n<td>{S}</td>\n</tr>")
        p("<label>Password</label> <span>{S}</span>")
        p("<label>Password</label>\n<span>{S}</span>")
        p("<td>\u{3C1}in</td> {S}")
        p("<td>pin</td>\t{S}")
        p("<b>API key</b>: {S}")
        p("<p>Your password is</p>\n<p>{S}</p>")
        p("[DEBUG] <key>password</key><string>{S}</string> written")
        p(String(repeating: "<key>status</key><string>ok</string>\n", count: 20_000) + "<key>password</key>\n<string>{S}</string>")
        p("<key>password</key>\n<string>{S}</string>", .body("application/xml"))
        p("<key>password</key>\n<string>{S}</string>", .body("application/x-plist"))
        p("<input type=\"password\" value=\"{S}\">", .body("text/html"))
    }
}
