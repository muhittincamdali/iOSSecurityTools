#if canImport(LocalAuthentication) && !os(tvOS) && !os(watchOS)
import Foundation
import LocalAuthentication
import Testing
@testable import iOSSecurityTools

/// An authentication context that answers like a device in a given state.
final class FakeAuthenticationContext: AuthenticationContext, @unchecked Sendable {
    var biometryType: LABiometryType
    let canEvaluateError: LAError.Code?
    let evaluateResult: Result<Bool, LAError>
    private(set) var evaluatedReasons: [String] = []
    private(set) var evaluatedPolicies: [LAPolicy] = []

    init(biometryType: LABiometryType = .faceID, canEvaluateError: LAError.Code? = nil, evaluateResult: Result<Bool, LAError> = .success(true)) {
        self.biometryType = biometryType
        self.canEvaluateError = canEvaluateError
        self.evaluateResult = evaluateResult
    }

    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        guard let code = canEvaluateError else { return true }
        error?.pointee = NSError(domain: LAError.errorDomain, code: code.rawValue)
        return false
    }

    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool {
        evaluatedReasons.append(localizedReason)
        evaluatedPolicies.append(policy)
        switch evaluateResult {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

@Suite("BiometricAuthenticator")
struct BiometricAuthenticatorTests {
    func authenticator(_ context: FakeAuthenticationContext) -> BiometricAuthenticator {
        BiometricAuthenticator { context }
    }

    @Test("reports availability with the biometry kind", arguments: [
        (LABiometryType.faceID, nil, BiometricAuthenticator.Availability.available(.faceID)),
        (.touchID, nil, .available(.touchID)),
        (.opticID, nil, .available(.opticID)),
        (.faceID, LAError.Code.biometryNotEnrolled, .notEnrolled(.faceID)),
        (.touchID, .biometryLockout, .lockedOut(.touchID)),
        (.none, .passcodeNotSet, .passcodeNotSet),
        (.none, .biometryNotAvailable, .unavailable),
        (.faceID, .invalidContext, .unavailable),
    ] as [(LABiometryType, LAError.Code?, BiometricAuthenticator.Availability)])
    func availability(type: LABiometryType, error: LAError.Code?, expected: BiometricAuthenticator.Availability) {
        #expect(authenticator(FakeAuthenticationContext(biometryType: type, canEvaluateError: error)).availability() == expected)
    }

    @Test("passes the reason and policy to the system and returns on success")
    func success() async throws {
        let context = FakeAuthenticationContext()
        try await authenticator(context).authenticate(reason: "Show saved cards", policy: .biometrics)
        #expect(context.evaluatedReasons == ["Show saved cards"])
        #expect(context.evaluatedPolicies == [.deviceOwnerAuthenticationWithBiometrics])
    }

    @Test("rejects an empty reason before calling the system", arguments: ["", "   ", "\n\t"])
    func emptyReason(reason: String) async {
        let context = FakeAuthenticationContext()
        await #expect(throws: BiometricError.invalidReason) {
            try await authenticator(context).authenticate(reason: reason)
        }
        #expect(context.evaluatedReasons.isEmpty)
    }

    @Test("maps LocalAuthentication errors", arguments: [
        (LAError.Code.userCancel, BiometricError.userCanceled),
        (.appCancel, .systemCanceled),
        (.systemCancel, .systemCanceled),
        (.userFallback, .userFallback),
        (.authenticationFailed, .authenticationFailed),
        (.biometryLockout, .lockedOut),
        (.biometryNotEnrolled, .notEnrolled),
        (.biometryNotAvailable, .unavailable),
        (.passcodeNotSet, .passcodeNotSet),
        (.invalidContext, .other(LAError.Code.invalidContext.rawValue)),
    ])
    func errors(code: LAError.Code, expected: BiometricError) async {
        let context = FakeAuthenticationContext(evaluateResult: .failure(LAError(code)))
        await #expect(throws: expected) {
            try await authenticator(context).authenticate(reason: "Unlock")
        }
    }

    @Test("a false result without an error counts as failed authentication")
    func falseResult() async {
        let context = FakeAuthenticationContext(evaluateResult: .success(false))
        await #expect(throws: BiometricError.authenticationFailed) {
            try await authenticator(context).authenticate(reason: "Unlock")
        }
    }

    @Test("errors from other domains keep their code")
    func foreignError() {
        #expect(BiometricError(NSError(domain: "Other", code: 12345)) == .other(12345))
    }

    @Test("the live authenticator answers like LAContext, without prompting", arguments: [
        BiometricAuthenticator.Policy.biometrics, .biometricsOrPasscode,
    ])
    func live(policy: BiometricAuthenticator.Policy) {
        // The answer depends on the machine, so it is checked against LAContext itself.
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(policy.laPolicy, error: &error)
        let availability = BiometricAuthenticator().availability(for: policy)
        if case .available(let kind) = availability {
            #expect(canEvaluate)
            #expect(kind == BiometricAuthenticator.BiometryKind(context.biometryType))
        } else {
            #expect(!canEvaluate)
        }
    }
}
#endif
