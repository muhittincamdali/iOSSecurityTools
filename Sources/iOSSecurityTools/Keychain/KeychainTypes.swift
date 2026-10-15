import Foundation
import Security

/// When a keychain value can be read (`kSecAttrAccessible`).
///
/// Values marked `ThisDeviceOnly` are not included in backups restored to another device and
/// never sync through iCloud Keychain.
public enum KeychainAccessibility: String, Sendable, Hashable, CaseIterable, CustomStringConvertible {
    /// Readable while the device is unlocked.
    case whenUnlocked
    /// Readable while the device is unlocked; stays on this device.
    case whenUnlockedThisDeviceOnly
    /// Readable after the first unlock since the device started, also while it is locked again.
    /// Suits values that background tasks need.
    case afterFirstUnlock
    /// Readable after the first unlock since the device started; stays on this device. The
    /// default of ``Keychain``.
    case afterFirstUnlockThisDeviceOnly
    /// Readable while the device is unlocked, and only while a passcode is set: removing the
    /// passcode deletes the value. Stays on this device.
    case whenPasscodeSetThisDeviceOnly

    var secValue: CFString {
        switch self {
        case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    var isThisDeviceOnly: Bool {
        switch self {
        case .whenUnlocked, .afterFirstUnlock: false
        case .whenUnlockedThisDeviceOnly, .afterFirstUnlockThisDeviceOnly, .whenPasscodeSetThisDeviceOnly: true
        }
    }

    public var description: String { rawValue }
}

/// A condition the user must meet before a keychain value is read: Face ID, Touch ID, Optic ID or
/// the device passcode.
///
/// The system checks the condition itself, inside the keychain, so a jailbreak tweak that makes
/// `LAContext.evaluatePolicy` return `true` does not unlock the value. That makes a protected
/// keychain item the right place for a secret that biometrics should guard; an `if` around a
/// successful ``BiometricAuthenticator/authenticate(reason:policy:)`` call is not.
public struct KeychainProtection: Sendable, Hashable {
    let flags: SecAccessControlCreateFlags

    private init(_ flags: SecAccessControlCreateFlags) {
        self.flags = flags
    }

    /// Any enrolled biometry or, as a fallback, the device passcode.
    public static let userPresence = KeychainProtection(.userPresence)
    /// Any enrolled biometry. Fingers or faces added later still unlock the value.
    public static let biometryAny = KeychainProtection(.biometryAny)
    /// The biometry enrolled when the value was stored. Adding or removing a finger or face makes
    /// the value unreadable, so someone who learns the passcode cannot enrol their own face to
    /// read it.
    public static let biometryCurrentSet = KeychainProtection(.biometryCurrentSet)
    /// The device passcode, without biometry.
    public static let devicePasscode = KeychainProtection(.devicePasscode)

    public static func == (lhs: KeychainProtection, rhs: KeychainProtection) -> Bool {
        lhs.flags.rawValue == rhs.flags.rawValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(flags.rawValue)
    }
}

/// An error from ``Keychain``.
public enum KeychainError: Error, Hashable, Sendable, LocalizedError {
    /// The key is empty or too long.
    case invalidKey(String)
    /// The store's settings cannot work together, for example synchronizable values that stay on
    /// the device.
    case invalidConfiguration(String)
    /// The app lacks the entitlement the keychain needs (`errSecMissingEntitlement`). On macOS,
    /// sign the app with a team or set ``Keychain/usesDataProtectionKeychain`` to `false`.
    case missingEntitlement
    /// The value cannot be read now: the device is locked, or the value needs authentication and
    /// the call did not allow a prompt (`errSecInteractionNotAllowed`).
    case interactionNotAllowed
    /// The user dismissed the authentication prompt (`errSecUserCanceled`).
    case userCanceled
    /// Authentication failed (`errSecAuthFailed`).
    case authenticationFailed
    /// The stored bytes are not what the method returns (for example, not UTF-8 text).
    case unexpectedData
    /// The value could not be encoded as JSON.
    case encodingFailed(String)
    /// The stored JSON could not be decoded as the requested type.
    case decodingFailed(String)
    /// Another `OSStatus` from the Security framework.
    case unhandled(OSStatus)

    init(status: OSStatus) {
        switch status {
        case errSecMissingEntitlement: self = .missingEntitlement
        case errSecInteractionNotAllowed: self = .interactionNotAllowed
        case errSecUserCanceled: self = .userCanceled
        case errSecAuthFailed: self = .authenticationFailed
        default: self = .unhandled(status)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidKey(let reason), .invalidConfiguration(let reason):
            reason
        case .missingEntitlement:
            "The app is missing the keychain entitlement. Sign it with a development team, or use the login keychain on macOS."
        case .interactionNotAllowed:
            "The keychain value cannot be read while the device is locked or without authentication."
        case .userCanceled:
            "Authentication was canceled."
        case .authenticationFailed:
            "Authentication failed."
        case .unexpectedData:
            "The keychain value has an unexpected format."
        case .encodingFailed(let reason):
            "The value could not be encoded: \(reason)"
        case .decodingFailed(let reason):
            "The keychain value could not be decoded: \(reason)"
        case .unhandled(let status):
            (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)."
        }
    }
}
