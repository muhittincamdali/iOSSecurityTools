import Foundation
import Security
import Testing
@testable import iOSSecurityTools

private func certificate(_ base64: String) -> SecCertificate {
    SecCertificateCreateWithData(nil, Data(base64Encoded: base64)! as CFData)!
}

/// A trust for a leaf and the test root, anchored only to that root and evaluated at a date inside
/// the certificates' validity, so the tests do not depend on the system root store or the clock.
private func makeTrust(leaf: String, anchoredTo anchor: String? = CertificateFixtures.rootDER, at date: Date = CertificateFixtures.verifyDate) -> SecTrust {
    let chain = [certificate(leaf), certificate(CertificateFixtures.rootDER)] as CFArray
    var trust: SecTrust?
    SecTrustCreateWithCertificates(chain, SecPolicyCreateBasicX509(), &trust)
    if let anchor {
        SecTrustSetAnchorCertificates(trust!, [certificate(anchor)] as CFArray)
    } else {
        SecTrustSetAnchorCertificates(trust!, [] as CFArray)
    }
    SecTrustSetAnchorCertificatesOnly(trust!, true)
    SecTrustSetVerifyDate(trust!, date as CFDate)
    SecTrustSetNetworkFetchAllowed(trust!, false)
    return trust!
}

@Suite("SPKIPin")
struct SPKIPinTests {
    @Test("matches the pins OpenSSL computes for RSA 2048 and 4096 and EC P-256 and P-384 keys", arguments: [
        (CertificateFixtures.rootDER, CertificateFixtures.rootPin),
        (CertificateFixtures.ecLeafDER, CertificateFixtures.ecLeafPin),
        (CertificateFixtures.rsaLeafDER, CertificateFixtures.rsaLeafPin),
        (CertificateFixtures.p384DER, CertificateFixtures.p384Pin),
        (CertificateFixtures.rsa4096DER, CertificateFixtures.rsa4096Pin),
    ])
    func matchesOpenSSL(der: String, expected: String) throws {
        let pin = try SPKIPin(certificate: certificate(der))
        #expect(pin.base64 == expected)
        #expect(try SPKIPin(base64: expected) == pin)
        #expect(try SPKIPin(base64: "sha256/" + expected) == pin)
        #expect(pin.description == "sha256/" + expected)
    }

    @Test("rejects text that is not base64 of 32 bytes", arguments: [
        "", "sha256/", "abc", "HFdypozKz80xLU+e0Rz1kQ3CpyvVm+JJbbpbGopluUg", "HFdypozKz80xLU+e0Rz1kQ3CpyvVm+JJbbpbGopluUgA=",
        "!FdypozKz80xLU+e0Rz1kQ3CpyvVm+JJbbpbGopluUg=", "sha1/HFdypozKz80xLU+e0Rz1kQ3CpyvVm+JJbbpbGopluUg=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ])
    func invalid(text: String) {
        #expect(throws: PinningError.invalidPin(text)) { try SPKIPin(base64: text) }
    }

    @Test("encodes DER lengths in short and long form")
    func derLength() {
        #expect(DER.length(0) == [0x00])
        #expect(DER.length(127) == [0x7F])
        #expect(DER.length(128) == [0x81, 0x80])
        #expect(DER.length(270) == [0x82, 0x01, 0x0E])
        #expect(DER.length(65_536) == [0x83, 0x01, 0x00, 0x00])
    }
}

@Suite("PinnedDomain")
struct PinnedDomainTests {
    let pins = [CertificateFixtures.ecLeafPin, CertificateFixtures.p384Pin]

    @Test("normalizes case and a trailing dot")
    func normalization() throws {
        #expect(try PinnedDomain("API.Example.COM.", pins: pins).domain == "api.example.com")
    }

    @Test("requires two different pins")
    func backupPin() {
        #expect(throws: PinningError.backupPinRequired("example.com")) {
            try PinnedDomain("example.com", pins: [CertificateFixtures.ecLeafPin])
        }
        #expect(throws: PinningError.backupPinRequired("example.com")) {
            try PinnedDomain("example.com", pins: [CertificateFixtures.ecLeafPin, "sha256/" + CertificateFixtures.ecLeafPin])
        }
    }

    @Test("rejects names that are not host names", arguments: [
        "", ".", "*.example.com", "exa mple.com", "example..com", "-example.com", "example-.com", "exämple.com",
        "https://example.com", "example.com/path", "example.com:443", String(repeating: "a", count: 64) + ".com",
        String(repeating: "a.", count: 127) + "com",
    ])
    func invalidDomains(domain: String) {
        #expect(throws: PinningError.invalidDomain(domain)) { try PinnedDomain(domain, pins: pins) }
    }

    @Test("a policy rejects a domain listed twice")
    func duplicates() throws {
        let entry = try PinnedDomain("example.com", pins: pins)
        let same = try PinnedDomain("EXAMPLE.com.", pins: pins)
        #expect(throws: PinningError.duplicateDomain("example.com")) { try PinningPolicy([entry, same]) }
    }

    @Test("lookup prefers exact matches, then the longest parent that includes subdomains")
    func lookup() throws {
        let policy = try PinningPolicy([
            PinnedDomain("example.com", pins: pins, includesSubdomains: true),
            PinnedDomain("api.example.com", pins: pins),
            PinnedDomain("eu.example.com", pins: pins, includesSubdomains: true),
            PinnedDomain("static.example.org", pins: pins),
        ])
        #expect(policy.pinnedDomain(for: "api.example.com")?.domain == "api.example.com")
        #expect(policy.pinnedDomain(for: "API.EXAMPLE.COM.")?.domain == "api.example.com")
        #expect(policy.pinnedDomain(for: "v2.api.example.com")?.domain == "example.com")
        #expect(policy.pinnedDomain(for: "cdn.eu.example.com")?.domain == "eu.example.com")
        #expect(policy.pinnedDomain(for: "example.com")?.domain == "example.com")
        #expect(policy.pinnedDomain(for: "img.static.example.org") == nil)
        #expect(policy.pinnedDomain(for: "evilexample.com") == nil)
        #expect(policy.pinnedDomain(for: "example.com.evil.net") == nil)
        #expect(policy.pinnedDomain(for: "") == nil)
    }
}

@Suite("PinningPolicy evaluation")
struct PinningEvaluationTests {
    let backupPin = CertificateFixtures.p384Pin

    func policy(_ domain: String = "pinned.test", pins: [String], includesSubdomains: Bool = false, expires: Date? = nil, enforced: Bool = true) throws -> PinningPolicy {
        try PinningPolicy([PinnedDomain(domain, pins: pins, includesSubdomains: includesSubdomains, expirationDate: expires, isEnforced: enforced)])
    }

    @Test("accepts a trusted chain whose leaf key is pinned")
    func leafPin() throws {
        let decision = try policy(pins: [CertificateFixtures.ecLeafPin, backupPin])
            .evaluate(makeTrust(leaf: CertificateFixtures.ecLeafDER), host: "pinned.test", at: CertificateFixtures.verifyDate)
        #expect(decision == .trusted(try SPKIPin(base64: CertificateFixtures.ecLeafPin)))
    }

    @Test("accepts a trusted chain whose root key is pinned")
    func rootPin() throws {
        let decision = try policy("rsa.pinned.test", pins: [CertificateFixtures.rootPin, backupPin])
            .evaluate(makeTrust(leaf: CertificateFixtures.rsaLeafDER), host: "rsa.pinned.test", at: CertificateFixtures.verifyDate)
        #expect(decision == .trusted(try SPKIPin(base64: CertificateFixtures.rootPin)))
    }

    @Test("rejects a trusted chain without a pinned key and lists the presented pins")
    func mismatch() throws {
        let decision = try policy(pins: [CertificateFixtures.rsaLeafPin, backupPin])
            .evaluate(makeTrust(leaf: CertificateFixtures.ecLeafDER), host: "pinned.test", at: CertificateFixtures.verifyDate)
        let presented = try [SPKIPin(base64: CertificateFixtures.ecLeafPin), SPKIPin(base64: CertificateFixtures.rootPin)]
        #expect(decision == .rejected(.noMatchingPin(host: "pinned.test", chainPins: presented)))
    }

    @Test("rejects an untrusted chain even when its key is pinned")
    func untrustedChain() throws {
        let pinnedPolicy = try policy(pins: [CertificateFixtures.ecLeafPin, CertificateFixtures.rootPin])
        let cases: [(SecTrust, String)] = [
            (makeTrust(leaf: CertificateFixtures.ecLeafDER, anchoredTo: nil), "pinned.test"),
            (makeTrust(leaf: CertificateFixtures.ecLeafDER, anchoredTo: CertificateFixtures.p384DER), "pinned.test"),
            (makeTrust(leaf: CertificateFixtures.ecLeafDER, at: Date(timeIntervalSince1970: 1_830_297_600)), "pinned.test"), // 2028
        ]
        for (trust, host) in cases {
            guard case .rejected(.untrustedChain) = pinnedPolicy.evaluate(trust, host: host, at: CertificateFixtures.verifyDate) else {
                Issue.record("Expected an untrusted chain")
                continue
            }
        }
    }

    @Test("checks the host name even if the trust was created for another host")
    func hostNameMismatch() throws {
        let wide = try policy("other.test", pins: [CertificateFixtures.ecLeafPin, backupPin])
        guard case .rejected(.untrustedChain(let host, _)) = wide.evaluate(makeTrust(leaf: CertificateFixtures.ecLeafDER), host: "other.test", at: CertificateFixtures.verifyDate) else {
            Issue.record("A certificate for pinned.test must not be accepted for other.test")
            return
        }
        #expect(host == "other.test")
    }

    @Test("applies subdomain pins to a certificate's other names")
    func subdomain() throws {
        let decision = try policy(pins: [CertificateFixtures.ecLeafPin, backupPin], includesSubdomains: true)
            .evaluate(makeTrust(leaf: CertificateFixtures.ecLeafDER), host: "api.pinned.test", at: CertificateFixtures.verifyDate)
        #expect(decision == .trusted(try SPKIPin(base64: CertificateFixtures.ecLeafPin)))
    }

    @Test("ignores hosts without pins and pins past their expiration date")
    func notPinnedAndExpired() throws {
        let trust = makeTrust(leaf: CertificateFixtures.ecLeafDER)
        let unrelated = try policy("example.com", pins: [CertificateFixtures.rsaLeafPin, backupPin])
        #expect(unrelated.evaluate(trust, host: "pinned.test") == .notPinned)

        let expiring = try policy(pins: [CertificateFixtures.rsaLeafPin, backupPin], expires: CertificateFixtures.verifyDate)
        #expect(expiring.evaluate(trust, host: "pinned.test", at: CertificateFixtures.verifyDate) == .pinsExpired)
        guard case .rejected = expiring.evaluate(trust, host: "pinned.test", at: CertificateFixtures.verifyDate.addingTimeInterval(-1)) else {
            Issue.record("Pins before their expiration date must be enforced")
            return
        }
    }

    @Test("report-only domains report mismatches without rejecting")
    func reportOnly() throws {
        let decision = try policy(pins: [CertificateFixtures.rsaLeafPin, backupPin], enforced: false)
            .evaluate(makeTrust(leaf: CertificateFixtures.ecLeafDER), host: "pinned.test", at: CertificateFixtures.verifyDate)
        guard case .reportOnly(.noMatchingPin) = decision else {
            Issue.record("Expected a report-only mismatch, got \(decision)")
            return
        }
    }
}

@Suite("PinningURLSessionDelegate")
struct PinningDelegateTests {
    final class ProtectionSpace: URLProtectionSpace, @unchecked Sendable {
        private let trust: SecTrust?
        init(host: String, method: String, trust: SecTrust?) {
            self.trust = trust
            super.init(host: host, port: 443, protocol: "https", realm: nil, authenticationMethod: method)
        }

        required init?(coder: NSCoder) { nil }

        override var serverTrust: SecTrust? { trust }
    }

    final class Sender: NSObject, URLAuthenticationChallengeSender {
        func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
        func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
        func cancel(_ challenge: URLAuthenticationChallenge) {}
    }

    final class FailureLog: @unchecked Sendable {
        private let lock = NSLock()
        private var failures: [PinningFailure] = []
        func append(_ failure: PinningFailure) { lock.withLock { failures.append(failure) } }
        var all: [PinningFailure] { lock.withLock { failures } }
    }

    func challenge(host: String, method: String = NSURLAuthenticationMethodServerTrust, trust: SecTrust?) -> URLAuthenticationChallenge {
        URLAuthenticationChallenge(
            protectionSpace: ProtectionSpace(host: host, method: method, trust: trust),
            proposedCredential: nil, previousFailureCount: 0, failureResponse: nil, error: nil, sender: Sender()
        )
    }

    @Test("uses the server's credential for a pinned, trusted chain")
    func trusted() throws {
        let delegate = try PinningURLSessionDelegate(policy: PinningPolicy([
            PinnedDomain("pinned.test", pins: [CertificateFixtures.ecLeafPin, CertificateFixtures.p384Pin]),
        ]))
        let (disposition, credential) = delegate.handle(challenge(host: "pinned.test", trust: makeTrust(leaf: CertificateFixtures.ecLeafDER)), at: CertificateFixtures.verifyDate)
        #expect(disposition == .useCredential)
        #expect(credential != nil)
    }

    @Test("cancels a mismatch and reports it")
    func rejected() throws {
        let log = FailureLog()
        let delegate = try PinningURLSessionDelegate(policy: PinningPolicy([
            PinnedDomain("pinned.test", pins: [CertificateFixtures.rsaLeafPin, CertificateFixtures.p384Pin]),
        ])) { log.append($0) }
        let (disposition, credential) = delegate.handle(challenge(host: "pinned.test", trust: makeTrust(leaf: CertificateFixtures.ecLeafDER)), at: CertificateFixtures.verifyDate)
        #expect(disposition == .cancelAuthenticationChallenge)
        #expect(credential == nil)
        #expect(log.all.count == 1)
    }

    @Test("leaves other hosts, report-only domains and other challenge types to the system")
    func defaultHandling() throws {
        let log = FailureLog()
        let delegate = try PinningURLSessionDelegate(policy: PinningPolicy([
            PinnedDomain("pinned.test", pins: [CertificateFixtures.rsaLeafPin, CertificateFixtures.p384Pin], isEnforced: false),
        ])) { log.append($0) }
        let trust = makeTrust(leaf: CertificateFixtures.ecLeafDER)
        #expect(delegate.handle(challenge(host: "unpinned.test", trust: trust)).0 == .performDefaultHandling)
        #expect(delegate.handle(challenge(host: "pinned.test", trust: trust), at: CertificateFixtures.verifyDate).0 == .performDefaultHandling)
        #expect(log.all.count == 1)
        #expect(delegate.handle(challenge(host: "pinned.test", method: NSURLAuthenticationMethodHTTPBasic, trust: nil)).0 == .performDefaultHandling)
        #expect(delegate.handle(challenge(host: "pinned.test", trust: nil)).0 == .performDefaultHandling)
    }
}
