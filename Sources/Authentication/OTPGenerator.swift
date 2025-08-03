import Foundation
import CryptoKit

/// OTP (One-Time Password) generator for TOTP and HOTP
public class OTPGenerator {
    
    // MARK: - Singleton
    public static let shared = OTPGenerator()
    
    // MARK: - Private Properties
    private let defaultDigits = 6
    private let defaultPeriod = 30
    private let defaultAlgorithm = "SHA1"
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate TOTP (Time-based One-Time Password)
    public func generateTOTP(secret: String, digits: Int = 6, period: Int = 30, algorithm: String = "SHA1") throws -> String {
        let counter = Int(Date().timeIntervalSince1970) / TimeInterval(period)
        return try generateHOTP(secret: secret, counter: counter, digits: digits, algorithm: algorithm)
    }
    
    /// Generate HOTP (HMAC-based One-Time Password)
    public func generateHOTP(secret: String, counter: Int, digits: Int = 6, algorithm: String = "SHA1") throws -> String {
        guard let secretData = base32Decode(secret) else {
            throw OTPError.invalidSecret
        }
        
        let counterData = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let hash = try createHMAC(data: counterData, key: secretData, algorithm: algorithm)
        
        let offset = Int(hash.last! & 0x0f)
        let binary = ((Int(hash[offset]) & 0x7f) << 24) |
                    ((Int(hash[offset + 1]) & 0xff) << 16) |
                    ((Int(hash[offset + 2]) & 0xff) << 8) |
                    (Int(hash[offset + 3]) & 0xff)
        
        let otp = binary % Int(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)d", otp)
    }
    
    /// Verify TOTP
    public func verifyTOTP(_ otp: String, secret: String, window: Int = 1, digits: Int = 6, period: Int = 30, algorithm: String = "SHA1") -> Bool {
        let currentTime = Int(Date().timeIntervalSince1970) / period
        
        for i in -window...window {
            let counter = currentTime + i
            do {
                let generatedOTP = try generateHOTP(secret: secret, counter: counter, digits: digits, algorithm: algorithm)
                if generatedOTP == otp {
                    return true
                }
            } catch {
                continue
            }
        }
        
        return false
    }
    
    /// Generate QR code URL for TOTP
    public func generateTOTPURL(secret: String, account: String, issuer: String, digits: Int = 6, period: Int = 30, algorithm: String = "SHA1") -> String {
        let algorithmParam = algorithm.lowercased()
        return "otpauth://totp/\(issuer):\(account)?secret=\(secret)&issuer=\(issuer)&algorithm=\(algorithmParam)&digits=\(digits)&period=\(period)"
    }
    
    /// Generate QR code URL for HOTP
    public func generateHOTPURL(secret: String, account: String, issuer: String, counter: Int = 0, digits: Int = 6, algorithm: String = "SHA1") -> String {
        let algorithmParam = algorithm.lowercased()
        return "otpauth://hotp/\(issuer):\(account)?secret=\(secret)&issuer=\(issuer)&algorithm=\(algorithmParam)&digits=\(digits)&counter=\(counter)"
    }
    
    /// Generate random secret
    public func generateSecret(length: Int = 32) -> String {
        let bytes = (0..<length).map { _ in UInt8.random(in: 0...255) }
        let data = Data(bytes)
        return base32Encode(data)
    }
    
    /// Validate secret format
    public func isValidSecret(_ secret: String) -> Bool {
        return base32Decode(secret) != nil
    }
    
    // MARK: - Private Methods
    
    private func createHMAC(data: Data, key: Data, algorithm: String) throws -> Data {
        switch algorithm.uppercased() {
        case "SHA1":
            let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Data(hmac)
        case "SHA256":
            let hmac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Data(hmac)
        case "SHA512":
            let hmac = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Data(hmac)
        default:
            throw OTPError.unsupportedAlgorithm
        }
    }
    
    private func base32Encode(_ data: Data) -> String {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result = ""
        var buffer = 0
        var bitsLeft = 0
        
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8
            
            while bitsLeft >= 5 {
                let index = (buffer >> (bitsLeft - 5)) & 31
                result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
                bitsLeft -= 5
            }
        }
        
        if bitsLeft > 0 {
            let index = (buffer << (5 - bitsLeft)) & 31
            result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
        }
        
        return result
    }
    
    private func base32Decode(_ string: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result = Data()
        var buffer = 0
        var bitsLeft = 0
        
        for char in string.uppercased() {
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            let value = alphabet.distance(from: alphabet.startIndex, to: index)
            
            buffer = (buffer << 5) | value
            bitsLeft += 5
            
            while bitsLeft >= 8 {
                let byte = (buffer >> (bitsLeft - 8)) & 255
                result.append(UInt8(byte))
                bitsLeft -= 8
            }
        }
        
        return result
    }
}

// MARK: - Supporting Types

/// OTP-related errors
public enum OTPError: LocalizedError {
    case invalidSecret
    case invalidCounter
    case invalidDigits
    case invalidPeriod
    case unsupportedAlgorithm
    case generationFailed
    case verificationFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidSecret:
            return "Invalid OTP secret"
        case .invalidCounter:
            return "Invalid OTP counter"
        case .invalidDigits:
            return "Invalid OTP digits"
        case .invalidPeriod:
            return "Invalid OTP period"
        case .unsupportedAlgorithm:
            return "Unsupported OTP algorithm"
        case .generationFailed:
            return "Failed to generate OTP"
        case .verificationFailed:
            return "Failed to verify OTP"
        }
    }
} 