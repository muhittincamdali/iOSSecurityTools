#if canImport(LocalAuthentication) && !os(tvOS) && !os(watchOS)
import Foundation
import LocalAuthentication

/// Asks the user to confirm their identity with Face ID, Touch ID, Optic ID or the device passcode.
///
/// ```swift
/// let authenticator = BiometricAuthenticator()
/// switch authenticator.availability() {
/// case .available(let kind):
///     try await authenticator.authenticate(reason: "Show your saved cards")
///     print("Confirmed with \(kind)")
/// default:
///     break // offer another way in
/// }
/// ```
///
/// A successful call proves the user passed the prompt, not that a secret is safe: on a
/// jailbroken device the call itself can be patched to succeed. To guard data, store it in the
/// ``Keychain`` with a ``KeychainProtection``; the system then checks biometry before it releases
/// the value.
///
/// Add `NSFaceIDUsageDescription` to the app's Info.plist; without it, Face ID prompts fail.
public struct BiometricAuthenticator: Sendable {
    /// What the user may authenticate with.
    public enum Policy: Sendable, Hashable {
        /// Face ID, Touch ID or Optic ID only.
        case biometrics
        /// Biometry, with the device passcode as a fallback.
        case biometricsOrPasscode

        var laPolicy: LAPolicy {
            switch self {
            case .biometrics: .deviceOwnerAuthenticationWithBiometrics
            case .biometricsOrPasscode: .deviceOwnerAuthentication
            }
        }
    }

    /// The biometry hardware of the device.
    public enum BiometryKind: String, Sendable, Hashable, CustomStringConvertible {
        case faceID = "Face ID"
        case touchID = "Touch ID"
        case opticID = "Optic ID"
        /// No biometry, or a kind this version does not know.
        case none = "None"

        public var description: String { rawValue }
    }

    /// Whether ``authenticate(reason:policy:)`` can succeed now.
    public enum Availability: Sendable, Hashable {
        /// The user can authenticate.
        case available(BiometryKind)
        /// The device has biometry, but nothing is enrolled.
        case notEnrolled(BiometryKind)
        /// Too many failed attempts; the user must enter the passcode first.
        case lockedOut(BiometryKind)
        /// The device has no passcode, so neither biometry nor the passcode can be used.
        case passcodeNotSet
        /// The device has no biometry, or the app may not use it.
        case unavailable
    }

    private let makeContext: @Sendable () -> any AuthenticationContext

    /// Creates an authenticator. Each call uses a new `LAContext`.
    public init() {
        self.makeContext = { LAContext() }
    }

    init(makeContext: @escaping @Sendable () -> any AuthenticationContext) {
        self.makeContext = makeContext
    }

    /// Returns whether authentication with a policy can succeed now, and with which biometry.
    public func availability(for policy: Policy = .biometrics) -> Availability {
        let context = makeContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(policy.laPolicy, error: &error)
        let kind = BiometryKind(context.biometryType)
        if canEvaluate { return .available(kind) }
        switch error.flatMap({ LAError.Code(rawValue: $0.code) }) {
        case .biometryNotEnrolled: return .notEnrolled(kind)
        case .biometryLockout: return .lockedOut(kind)
        case .passcodeNotSet: return .passcodeNotSet
        default: return .unavailable
        }
    }

    /// Shows the system prompt and returns when the user has authenticated.
    ///
    /// - Parameters:
    ///   - reason: Why the app asks, shown in the prompt for Touch ID and the passcode. It must not
    ///     be empty; `LAContext` raises an exception for an empty reason, so it is checked first.
    ///   - policy: What the user may authenticate with.
    /// - Throws: ``BiometricError``; ``BiometricError/userCanceled`` when the user dismisses the
    ///   prompt.
    public func authenticate(reason: String, policy: Policy = .biometricsOrPasscode) async throws(BiometricError) {
        guard !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw .invalidReason
        }
        let context = makeContext()
        do {
            guard try await context.evaluatePolicy(policy.laPolicy, localizedReason: reason) else {
                throw BiometricError.authenticationFailed
            }
        } catch let error as BiometricError {
            throw error
        } catch {
            throw BiometricError(error)
        }
    }
}

/// An error from ``BiometricAuthenticator/authenticate(reason:policy:)``.
public enum BiometricError: Error, Sendable, Hashable, LocalizedError {
    /// The user tapped Cancel.
    case userCanceled
    /// The user chose the fallback button (for example "Enter Password").
    case userFallback
    /// The system or the app canceled the prompt, for example because another app came to the
    /// foreground.
    case systemCanceled
    /// The user did not provide valid credentials.
    case authenticationFailed
    /// Too many failed attempts; biometry is locked until the passcode is entered.
    case lockedOut
    /// No biometry is enrolled.
    case notEnrolled
    /// The device has no biometry, or the app may not use it (for example, a missing
    /// `NSFaceIDUsageDescription`).
    case unavailable
    /// The device has no passcode.
    case passcodeNotSet
    /// The reason text is empty.
    case invalidReason
    /// Another LocalAuthentication error, with its code.
    case other(Int)

    init(_ error: any Error) {
        guard let code = (error as? LAError)?.code ?? LAError.Code(rawValue: (error as NSError).code) else {
            self = .other((error as NSError).code)
            return
        }
        switch code {
        case .userCancel: self = .userCanceled
        case .userFallback: self = .userFallback
        case .systemCancel, .appCancel: self = .systemCanceled
        case .authenticationFailed: self = .authenticationFailed
        case .biometryLockout: self = .lockedOut
        case .biometryNotEnrolled: self = .notEnrolled
        case .biometryNotAvailable: self = .unavailable
        case .passcodeNotSet: self = .passcodeNotSet
        default: self = .other(code.rawValue)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .userCanceled: "Authentication was canceled."
        case .userFallback: "The user chose another way to sign in."
        case .systemCanceled: "The system canceled authentication."
        case .authenticationFailed: "The identity could not be confirmed."
        case .lockedOut: "Biometry is locked after too many attempts. Unlock the device with the passcode."
        case .notEnrolled: "No biometry is set up on this device."
        case .unavailable: "Biometric authentication is not available."
        case .passcodeNotSet: "The device has no passcode."
        case .invalidReason: "The authentication reason is empty."
        case .other(let code): "Authentication failed with LocalAuthentication error \(code)."
        }
    }
}

extension BiometricAuthenticator.BiometryKind {
    init(_ type: LABiometryType) {
        switch type {
        case .faceID: self = .faceID
        case .touchID: self = .touchID
        case .opticID: self = .opticID
        default: self = .none
        }
    }
}

/// The part of `LAContext` the authenticator uses, so tests can replace it.
protocol AuthenticationContext: AnyObject {
    var biometryType: LABiometryType { get }
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool
}

extension LAContext: AuthenticationContext {}
#endif
