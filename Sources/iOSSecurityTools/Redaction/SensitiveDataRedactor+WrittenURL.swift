import Foundation

extension SensitiveDataRedactor {
    /// Where a URL written in free text cuts the text, in the scalars of the URL.
    struct WrittenURLCut: Equatable {
        /// How many scalars at the start of the URL are recorded as a URL; none when the URL cannot
        /// be read or its host is not written.
        let written: Int
        /// The scalar from which the text is hidden to its end; the length of the URL when the text
        /// is hidden from what follows the URL.
        let cut: Int
    }

    /// Where a URL in free text cuts the text, or nil when it is recorded whole and the text after
    /// it is read on. A URL is not a place to read on from when what it ends with may name a value
    /// that the text after it holds (`?token= hunter2`, `/password hunter2`), so the text is cut:
    ///
    /// - at the URL, when `URLComponents` cannot read it;
    /// - after the scheme, when the host is not written (see ``redact(url:)``), unless the host
    ///   is the whole rest of the URL and every `&`- or `;`-separated piece of it is a name and a
    ///   value (`myapp://password=hunter2`), whose value is hidden with the host;
    /// - after the host, when the URL has more segments or parameters than ``redact(url:)``
    ///   reads;
    /// - right after the `;`, `?` or `#` that starts path parameters, the query or the fragment,
    ///   unless every parameter of it is on ``allowedQueryParameters`` and has a value in the URL,
    ///   and none names a secret as a value (`?label=password`);
    /// - right after the URL, when it ends with `=` or `:`, or the last thing it names — its last
    ///   path segment, or its host when it has no path — names a secret, cannot be read or is not
    ///   plain ASCII (`https://x.example/password`, `https://password`).
    func cutInWrittenURL(_ scalars: [Unicode.Scalar]) -> WrittenURLCut? {
        let text = String(String.UnicodeScalarView(scalars))
        guard let components = URLComponents(string: text), let scheme = components.scheme, let host = components.percentEncodedHost else {
            return WrittenURLCut(written: 0, cut: 0)
        }
        let parts = WrittenURLParts(scalars, authorityStart: scheme.unicodeScalars.count + 3)
        guard showsHost(host) else {
            let isWhole = parts.authorityEnd == scalars.count && Self.isNamesAndValues(host)
            return isWhole ? nil : WrittenURLCut(written: 0, cut: parts.authorityStart)
        }
        if Self.exceedsLimits(components) { return WrittenURLCut(written: parts.authorityEnd, cut: parts.authorityEnd) }
        for section in parts.sections where !isAllowedParameters(section.scalars, separator: section.separator) {
            return WrittenURLCut(written: section.start, cut: section.start + 1)
        }
        if let last = scalars.last, last == "=" || last == ":" { return WrittenURLCut(written: scalars.count, cut: scalars.count) }
        if parts.sections.isEmpty, Self.namesSecret(parts.lastName(host: host)) {
            return WrittenURLCut(written: scalars.count, cut: scalars.count)
        }
        return nil
    }

    /// Whether every parameter of a query, fragment or path parameters is on
    /// ``allowedQueryParameters`` with a value, the text is a strict form (see
    /// ``isStrictForm(_:)``) and no parameter names a secret as a value. An empty one has none.
    private func isAllowedParameters(_ scalars: ArraySlice<Unicode.Scalar>, separator: Unicode.Scalar) -> Bool {
        guard !scalars.isEmpty else { return true }
        let form = String(String.UnicodeScalarView(scalars.map { $0 == separator ? "&" : $0 }))
        guard Self.isStrictForm(form) else { return false }
        var naming = NamingFields()
        let compatibility = CompatibilityText()
        for field in form.split(separator: "&", omittingEmptySubsequences: false) {
            let pair = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2, !pair[1].isEmpty, let name = Self.formDecoded(pair[0]), let value = Self.formDecoded(pair[1]),
                  let fold = FieldName.allowableFold(name.unicodeScalars), allowedQueryParameters.contains(fold)
            else { return false }
            naming.read(Self.namingField(name: name, value: value), compatibility: compatibility)
        }
        return !naming.hasNamingField
    }

    /// Whether a host that is not written holds only names with values, `&` or `;` between them.
    private static func isNamesAndValues(_ host: String) -> Bool {
        guard let decoded = host.removingPercentEncoding else { return false }
        return decoded.split(omittingEmptySubsequences: false) { $0 == "&" || $0 == ";" }.allSatisfy { piece in
            let pair = piece.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return pair.count == 2 && !pair[0].isEmpty && !pair[1].isEmpty
        }
    }

    /// Whether the last segment or host of a URL, percent-encoded, names a secret, cannot be read
    /// or is not plain printable ASCII once decoded.
    private static func namesSecret(_ raw: String) -> Bool {
        guard let decoded = raw.removingPercentEncoding else { return true }
        let scalars = Array(decoded.unicodeScalars)
        guard scalars.allSatisfy({ (0x21...0x7E).contains($0.value) }) else { return true }
        return FreeTextScanner.mentionsSecret(scalars, compatibility: CompatibilityText())
    }
}

/// A URL as written in text, split where its authority, path parameters, query and fragment start.
/// It is split by its characters, not by a parser: every `;` in the path, the first `?` and the
/// first `#` count, which is never fewer places than a parser finds.
struct WrittenURLParts {
    /// Path parameters (`;`), a query (`?`) or a fragment (`#`): where its mark is in the URL, the
    /// scalars after it and what separates its parameters.
    struct Section {
        let start: Int
        let scalars: ArraySlice<Unicode.Scalar>
        let separator: Unicode.Scalar
    }

    let scalars: [Unicode.Scalar]
    /// The scalar after `scheme://`, and the first scalar of the path, query or fragment.
    let authorityStart: Int
    let authorityEnd: Int
    /// Where the path ends: at the query, the fragment or the end.
    private let pathEnd: Int
    /// The sections in the order they are written.
    let sections: [Section]

    init(_ scalars: [Unicode.Scalar], authorityStart: Int) {
        self.scalars = scalars
        self.authorityStart = min(authorityStart, scalars.count)
        let authorityEnd = scalars[self.authorityStart...].firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? scalars.count
        let fragment = scalars[authorityEnd...].firstIndex(of: "#")
        let query = scalars[authorityEnd..<(fragment ?? scalars.count)].firstIndex(of: "?")
        let pathEnd = query ?? fragment ?? scalars.count
        var sections: [Section] = []
        var k = authorityEnd
        while let mark = scalars[k..<pathEnd].firstIndex(of: ";") {
            let end = scalars[(mark + 1)..<pathEnd].firstIndex(of: "/") ?? pathEnd
            sections.append(Section(start: mark, scalars: scalars[(mark + 1)..<end], separator: ";"))
            k = end
        }
        if let query { sections.append(Section(start: query, scalars: scalars[(query + 1)..<(fragment ?? scalars.count)], separator: "&")) }
        if let fragment { sections.append(Section(start: fragment, scalars: scalars[(fragment + 1)...], separator: "&")) }
        self.authorityEnd = authorityEnd
        self.pathEnd = pathEnd
        self.sections = sections
    }

    /// The last path segment that is not empty, percent-encoded, or the host when there is none.
    func lastName(host: String) -> String {
        let segments = scalars[authorityEnd..<pathEnd].split(separator: "/")
        return segments.last.map { String(String.UnicodeScalarView($0)) } ?? host
    }
}
