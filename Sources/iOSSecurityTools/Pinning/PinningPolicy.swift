import Foundation
import Security

/// The pins of one domain.
public struct PinnedDomain: Sendable, Hashable {
    /// The domain, lowercased, without a trailing dot.
    public let domain: String
    /// The accepted public key hashes. A connection is accepted when any certificate in the
    /// verified chain — leaf, intermediate or root — has one of them.
    public let pins: Set<SPKIPin>
    /// Whether the pins also apply to every subdomain (`api.example.com` for `example.com`).
    public let includesSubdomains: Bool
    /// After this date the pins are ignored and only the system's trust evaluation applies, so an
    /// app that is never updated does not lock itself out when the keys change.
    public let expirationDate: Date?
    /// Whether a pin mismatch blocks the connection. With `false`, mismatches are only reported,
    /// which lets you check new pins against real traffic before enforcing them.
    public let isEnforced: Bool

    /// Creates the pins of a domain.
    ///
    /// - Parameters:
    ///   - domain: A host name such as `api.example.com`; case and a trailing dot are ignored.
    ///     Wildcards are not accepted; use `includesSubdomains`.
    ///   - pins: At least two different pins in base64 (``SPKIPin/init(base64:)``). The second is
    ///     a backup — the hash of a key you hold in reserve or of another CA in the chain — so a
    ///     key change does not break every installed copy of the app.
    ///   - includesSubdomains: Apply the pins to subdomains too.
    ///   - expirationDate: When to stop enforcing the pins, or `nil` for never.
    ///   - isEnforced: `false` to only report mismatches.
    /// - Throws: ``PinningError``.
    public init(
        _ domain: String,
        pins: [String],
        includesSubdomains: Bool = false,
        expirationDate: Date? = nil,
        isEnforced: Bool = true
    ) throws(PinningError) {
        var parsed: [SPKIPin] = []
        for pin in pins {
            parsed.append(try SPKIPin(base64: pin))
        }
        try self.init(domain, pins: parsed, includesSubdomains: includesSubdomains, expirationDate: expirationDate, isEnforced: isEnforced)
    }

    /// Creates the pins of a domain from ``SPKIPin`` values.
    public init(
        _ domain: String,
        pins: [SPKIPin],
        includesSubdomains: Bool = false,
        expirationDate: Date? = nil,
        isEnforced: Bool = true
    ) throws(PinningError) {
        let normalized = try Self.normalize(domain)
        let unique = Set(pins)
        guard unique.count >= 2 else { throw .backupPinRequired(normalized) }
        self.domain = normalized
        self.pins = unique
        self.includesSubdomains = includesSubdomains
        self.expirationDate = expirationDate
        self.isEnforced = isEnforced
    }

    /// Lowercases a host name, removes one trailing dot and checks it is a valid DNS name.
    static func normalize(_ domain: String) throws(PinningError) -> String {
        var name = domain.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        let isValid = !name.isEmpty && name.utf8.count <= 253 && labels.allSatisfy { label in
            (1...63).contains(label.utf8.count)
                && label.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D }
                && label.first != "-" && label.last != "-"
        }
        guard isValid else { throw .invalidDomain(domain) }
        return name
    }
}

/// Public key pins for a set of domains, and the check that applies them to a server's
/// certificate chain.
///
/// ```swift
/// let policy = try PinningPolicy([
///     PinnedDomain("api.example.com", pins: [
///         "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",   // current key
///         "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",   // backup key
///     ])
/// ])
/// let session = URLSession.pinned(policy: policy)
/// ```
///
/// Pinning adds to the system's checks; it never replaces them. A chain that the system does not
/// trust — expired, wrong host name, unknown CA — is rejected even when a pin matches.
public struct PinningPolicy: Sendable {
    /// The pinned domains.
    public let domains: [PinnedDomain]

    /// Creates a policy.
    ///
    /// - Throws: ``PinningError/duplicateDomain(_:)`` when a domain appears twice.
    public init(_ domains: [PinnedDomain]) throws(PinningError) {
        var seen = Set<String>()
        for entry in domains where !seen.insert(entry.domain).inserted {
            throw .duplicateDomain(entry.domain)
        }
        self.domains = domains
    }

    /// Returns the pins that apply to a host: an exact match, or else the longest pinned parent
    /// domain that includes subdomains.
    public func pinnedDomain(for host: String) -> PinnedDomain? {
        guard let host = try? PinnedDomain.normalize(host) else { return nil }
        if let exact = domains.first(where: { $0.domain == host }) { return exact }
        return domains
            .filter { $0.includesSubdomains && host.hasSuffix("." + $0.domain) }
            .max { $0.domain.count < $1.domain.count }
    }

    /// Checks a server's certificate chain for a host.
    ///
    /// The trust is evaluated with the SSL policy for `host` (and the system's root store and
    /// revocation settings), then every certificate of the verified chain is compared with the
    /// host's pins. Call it off the main thread: evaluation can wait for the network.
    ///
    /// - Parameters:
    ///   - trust: The server trust from the authentication challenge.
    ///   - host: The host the app connected to.
    ///   - date: The current time, for pin expiration.
    public func evaluate(_ trust: SecTrust, host: String, at date: Date = Date()) -> PinningDecision {
        guard let pinned = pinnedDomain(for: host) else { return .notPinned }
        if let expiration = pinned.expirationDate, date >= expiration { return .pinsExpired }

        let decision = Self.check(trust, host: host, against: pinned)
        if case .rejected(let failure) = decision, !pinned.isEnforced {
            return .reportOnly(failure)
        }
        return decision
    }

    private static func check(_ trust: SecTrust, host: String, against pinned: PinnedDomain) -> PinningDecision {
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            let reason = error.map { CFErrorCopyDescription($0) as String } ?? "The certificate chain is not trusted."
            return .rejected(.untrustedChain(host: host, reason: reason))
        }
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        let chainPins = chain.compactMap { try? SPKIPin(certificate: $0) }
        if let match = chainPins.first(where: pinned.pins.contains) {
            return .trusted(match)
        }
        return .rejected(.noMatchingPin(host: host, chainPins: chainPins))
    }
}

/// The result of ``PinningPolicy/evaluate(_:host:at:)``.
public enum PinningDecision: Sendable, Hashable {
    /// The host has no pins; the system's trust evaluation decides.
    case notPinned
    /// The host's pins have expired; the system's trust evaluation decides.
    case pinsExpired
    /// The chain is trusted and contains this pin.
    case trusted(SPKIPin)
    /// The connection must be refused.
    case rejected(PinningFailure)
    /// The pins do not match, but the domain is not enforced: report it and let the system decide.
    case reportOnly(PinningFailure)
}

/// Why a server's certificate chain failed pinning.
public enum PinningFailure: Error, Sendable, Hashable, LocalizedError {
    /// The system does not trust the chain for this host.
    case untrustedChain(host: String, reason: String)
    /// The chain is trusted, but no certificate in it has one of the host's pins. `chainPins`
    /// lists the pins the server presented, to compare with the configuration.
    case noMatchingPin(host: String, chainPins: [SPKIPin])

    public var errorDescription: String? {
        switch self {
        case .untrustedChain(let host, let reason):
            "The certificate of \(host) is not trusted: \(reason)"
        case .noMatchingPin(let host, let chainPins):
            "No certificate of \(host) matches its pins. The server presented \(chainPins.map(\.description).joined(separator: ", "))."
        }
    }
}

/// An error in a pinning configuration.
public enum PinningError: Error, Sendable, Hashable, LocalizedError {
    /// The text is not base64 of a 32-byte hash.
    case invalidPin(String)
    /// The text is not a DNS host name.
    case invalidDomain(String)
    /// The domain has fewer than two different pins.
    case backupPinRequired(String)
    /// The domain appears more than once in the policy.
    case duplicateDomain(String)
    /// The public key's type or size is not supported.
    case unsupportedKey(String)

    public var errorDescription: String? {
        switch self {
        case .invalidPin(let text): "\"\(text)\" is not a base64 SHA-256 pin."
        case .invalidDomain(let text): "\"\(text)\" is not a valid domain name."
        case .backupPinRequired(let domain): "\(domain) needs at least two different pins: the current key and a backup."
        case .duplicateDomain(let domain): "\(domain) is listed more than once."
        case .unsupportedKey(let reason): reason
        }
    }
}
