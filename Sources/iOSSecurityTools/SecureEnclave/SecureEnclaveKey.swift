import CryptoKit
import Foundation
import Security
#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication
#endif

/// A P-256 signing key that lives in the Secure Enclave and never leaves this device.
///
/// Use it to bind an account to a device: send ``publicKeyDER`` to your server once, then sign
/// the server's login challenges. A copied backup, another device or a memory dump cannot
/// produce the signatures, because the private key cannot be read — the app only holds an
/// encrypted handle (``dataRepresentation``) that this device's Secure Enclave alone can use.
///
/// ```swift
/// let keychain = Keychain(service: "com.example.app.device")
/// let key = try keychain.secureEnclaveKey(forKey: "device-key")
/// let signature = try key.signature(for: challenge)   // DER-encoded ECDSA (SHA-256)
/// ```
///
/// The Secure Enclave exists on iPhone, iPad, Apple silicon Macs, Apple Watch and Apple Vision
/// Pro, but not in the simulator; check ``isAvailable`` and fall back to another sign-in method.
public struct SecureEnclaveKey: Sendable, Hashable {
    /// Whether this device has a Secure Enclave the app can use.
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// The encrypted handle of the private key. Store it (``Keychain/secureEnclaveKey(forKey:protection:)``
    /// does) to use the same key later; it is useless on any other device.
    public let dataRepresentation: Data
    /// The public key in X9.63 form (`04 || X || Y`, 65 bytes).
    public let publicKeyX963: Data

    /// Creates a new key in the Secure Enclave.
    ///
    /// - Parameter protection: Require Face ID, Touch ID or the passcode for every signature, or
    ///   `nil` to sign while the device is unlocked.
    /// - Throws: ``SecureEnclaveError``.
    public init(protection: KeychainProtection? = nil) throws(SecureEnclaveError) {
        guard Self.isAvailable else { throw .unavailable }
        var flags: SecAccessControlCreateFlags = .privateKeyUsage
        if let protection { flags.formUnion(protection.flags) }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            error?.release()
            throw .keyCreationFailed("The access control could not be created.")
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control)
            self.dataRepresentation = key.dataRepresentation
            self.publicKeyX963 = key.publicKey.x963Representation
        } catch {
            throw .keyCreationFailed(String(describing: error))
        }
    }

    /// Restores a key from its ``dataRepresentation``.
    ///
    /// - Throws: ``SecureEnclaveError/invalidKeyData`` when the data was not made by this device's
    ///   Secure Enclave.
    public init(dataRepresentation: Data) throws(SecureEnclaveError) {
        guard Self.isAvailable else { throw .unavailable }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
            self.dataRepresentation = dataRepresentation
            self.publicKeyX963 = key.publicKey.x963Representation
        } catch {
            throw .invalidKeyData
        }
    }

    /// The public key, to verify signatures with CryptoKit.
    public var publicKey: P256.Signing.PublicKey {
        // The bytes come from CryptoKit itself, so they always parse.
        try! P256.Signing.PublicKey(x963Representation: publicKeyX963)
    }

    /// The public key as a DER SubjectPublicKeyInfo, the form servers usually expect.
    public var publicKeyDER: Data { publicKey.derRepresentation }

    /// Signs data with ECDSA over SHA-256.
    ///
    /// - Parameters:
    ///   - data: The data to sign, such as a server challenge.
    ///   - prompt: The reason shown when the key requires Face ID, Touch ID or the passcode.
    ///     Ignored on tvOS and watchOS.
    /// - Returns: The signature in DER form.
    /// - Throws: ``SecureEnclaveError/signingFailed(_:)``, for example when the user cancels the
    ///   prompt.
    public func signature(for data: some DataProtocol, prompt: String? = nil) throws(SecureEnclaveError) -> Data {
        do {
            let key: SecureEnclave.P256.Signing.PrivateKey
            #if canImport(LocalAuthentication) && !os(tvOS) && !os(watchOS)
            if let prompt, !prompt.isEmpty {
                let context = LAContext()
                context.localizedReason = prompt
                key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context)
            } else {
                key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
            }
            #else
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
            #endif
            return try key.signature(for: data).derRepresentation
        } catch {
            throw .signingFailed(String(describing: error))
        }
    }

    /// Returns whether a DER signature over `data` was made by this key.
    public func isValidSignature(_ signature: Data, for data: some DataProtocol) -> Bool {
        guard let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
        return publicKey.isValidSignature(parsed, for: data)
    }
}

/// An error from ``SecureEnclaveKey``.
public enum SecureEnclaveError: Error, Sendable, Hashable, LocalizedError {
    /// The device has no Secure Enclave (for example, the simulator).
    case unavailable
    /// The key could not be created.
    case keyCreationFailed(String)
    /// The stored data is not a key of this device's Secure Enclave.
    case invalidKeyData
    /// Signing failed, for example because the user canceled authentication.
    case signingFailed(String)
    /// The key could not be stored in or read from the keychain.
    case keychain(KeychainError)

    public var errorDescription: String? {
        switch self {
        case .unavailable: "This device has no Secure Enclave."
        case .keyCreationFailed(let reason): "The Secure Enclave key could not be created: \(reason)"
        case .invalidKeyData: "The stored key does not belong to this device's Secure Enclave."
        case .signingFailed(let reason): "Signing failed: \(reason)"
        case .keychain(let error): error.errorDescription
        }
    }
}

extension Keychain {
    /// Returns the Secure Enclave key stored under a name, creating one the first time.
    ///
    /// The keychain holds only the key's encrypted handle. When the stored handle no longer works
    /// (for example after the app was restored from a backup to a new device) the error is
    /// ``SecureEnclaveError/invalidKeyData``: remove the value and register a new key with your
    /// server.
    ///
    /// - Parameters:
    ///   - key: The keychain key.
    ///   - protection: For a new key, require Face ID, Touch ID or the passcode for every
    ///     signature. Ignored when the key exists.
    public func secureEnclaveKey(forKey key: String, protection: KeychainProtection? = nil) throws(SecureEnclaveError) -> SecureEnclaveKey {
        do {
            if let stored = try data(forKey: key) {
                return try SecureEnclaveKey(dataRepresentation: stored)
            }
            let created = try SecureEnclaveKey(protection: protection)
            if try add(created.dataRepresentation, forKey: key) {
                return created
            }
            guard let stored = try data(forKey: key) else { throw SecureEnclaveError.invalidKeyData }
            return try SecureEnclaveKey(dataRepresentation: stored)
        } catch let error as SecureEnclaveError {
            throw error
        } catch let error as KeychainError {
            throw .keychain(error)
        } catch {
            throw .keyCreationFailed(String(describing: error))
        }
    }
}
