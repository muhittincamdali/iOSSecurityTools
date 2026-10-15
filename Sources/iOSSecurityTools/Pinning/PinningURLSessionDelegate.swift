import Foundation

/// A `URLSession` delegate that applies a ``PinningPolicy`` to every server trust challenge.
///
/// ```swift
/// let delegate = PinningURLSessionDelegate(policy: policy) { failure in
///     Logger.network.error("Pinning failed: \(failure.localizedDescription)")
/// }
/// let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
/// ```
///
/// Hosts without pins, and pins past their expiration date, get the system's default handling.
/// A rejected chain cancels the request with `URLError.cancelled`; the failure handler runs
/// first, on the session's delegate queue. It also runs for report-only domains, whose requests
/// continue.
///
/// The delegate answers both session-level and task-level challenges, so it also works as the
/// `delegate` argument of `URLSession.data(for:delegate:)`.
public final class PinningURLSessionDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    /// The policy the delegate applies.
    public let policy: PinningPolicy
    private let onFailure: (@Sendable (PinningFailure) -> Void)?

    /// Creates a delegate.
    ///
    /// - Parameters:
    ///   - policy: The pins.
    ///   - onFailure: Called with every rejected or report-only chain, for logging or a report
    ///     to your server.
    public init(policy: PinningPolicy, onFailure: (@Sendable (PinningFailure) -> Void)? = nil) {
        self.policy = policy
        self.onFailure = onFailure
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        handle(challenge)
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        handle(challenge)
    }

    /// Decides a challenge. Separate from the delegate methods so it can be tested without a
    /// network connection.
    func handle(_ challenge: URLAuthenticationChallenge, at date: Date = Date()) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = space.serverTrust else {
            return (.performDefaultHandling, nil)
        }
        switch policy.evaluate(trust, host: space.host, at: date) {
        case .notPinned, .pinsExpired:
            return (.performDefaultHandling, nil)
        case .trusted:
            return (.useCredential, URLCredential(trust: trust))
        case .reportOnly(let failure):
            onFailure?(failure)
            return (.performDefaultHandling, nil)
        case .rejected(let failure):
            onFailure?(failure)
            return (.cancelAuthenticationChallenge, nil)
        }
    }
}

extension URLSession {
    /// Returns a session that applies certificate pins to every request.
    ///
    /// - Parameters:
    ///   - policy: The pins.
    ///   - configuration: The session configuration; `.ephemeral` by default, so responses and
    ///     cookies from pinned hosts are not written to disk.
    ///   - onFailure: Called with every rejected or report-only chain.
    public static func pinned(
        policy: PinningPolicy,
        configuration: URLSessionConfiguration = .ephemeral,
        onFailure: (@Sendable (PinningFailure) -> Void)? = nil
    ) -> URLSession {
        URLSession(configuration: configuration, delegate: PinningURLSessionDelegate(policy: policy, onFailure: onFailure), delegateQueue: nil)
    }
}
