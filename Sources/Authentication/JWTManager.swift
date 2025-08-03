import Foundation
import CryptoKit

/// JWT (JSON Web Token) manager for creating, verifying, and decoding tokens
public class JWTManager {
    
    // MARK: - Singleton
    public static let shared = JWTManager()
    
    // MARK: - Private Properties
    private let header = ["alg": "HS256", "typ": "JWT"]
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Create JWT token
    public func createJWT(payload: [String: Any], secret: String, expiresIn: TimeInterval = 3600) throws -> String {
        let now = Date()
        let expirationDate = now.addingTimeInterval(expiresIn)
        
        var jwtPayload = payload
        jwtPayload["iat"] = Int(now.timeIntervalSince1970)
        jwtPayload["exp"] = Int(expirationDate.timeIntervalSince1970)
        
        let headerData = try JSONSerialization.data(withJSONObject: header)
        let payloadData = try JSONSerialization.data(withJSONObject: jwtPayload)
        
        let headerBase64 = headerData.base64EncodedString().replacingOccurrences(of: "=", with: "")
        let payloadBase64 = payloadData.base64EncodedString().replacingOccurrences(of: "=", with: "")
        
        let signature = try createSignature(header: headerBase64, payload: payloadBase64, secret: secret)
        
        return "\(headerBase64).\(payloadBase64).\(signature)"
    }
    
    /// Verify JWT token
    public func verifyJWT(_ token: String, secret: String) throws -> Bool {
        let components = token.components(separatedBy: ".")
        guard components.count == 3 else {
            throw JWTError.invalidTokenFormat
        }
        
        let header = components[0]
        let payload = components[1]
        let signature = components[2]
        
        let expectedSignature = try createSignature(header: header, payload: payload, secret: secret)
        
        guard signature == expectedSignature else {
            return false
        }
        
        // Check expiration
        guard let payloadData = Data(base64Encoded: payload + String(repeating: "=", count: (4 - payload.count % 4) % 4)),
              let payloadDict = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
              let expiration = payloadDict["exp"] as? Int else {
            throw JWTError.invalidPayload
        }
        
        let currentTime = Int(Date().timeIntervalSince1970)
        guard currentTime < expiration else {
            throw JWTError.tokenExpired
        }
        
        return true
    }
    
    /// Decode JWT token
    public func decodeJWT(_ token: String) throws -> [String: Any] {
        let components = token.components(separatedBy: ".")
        guard components.count == 3 else {
            throw JWTError.invalidTokenFormat
        }
        
        let payload = components[1]
        let paddedPayload = payload + String(repeating: "=", count: (4 - payload.count % 4) % 4)
        
        guard let payloadData = Data(base64Encoded: paddedPayload),
              let payloadDict = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw JWTError.invalidPayload
        }
        
        return payloadDict
    }
    
    /// Get JWT expiration date
    public func getExpirationDate(_ token: String) throws -> Date {
        let payload = try decodeJWT(token)
        
        guard let expiration = payload["exp"] as? Int else {
            throw JWTError.invalidPayload
        }
        
        return Date(timeIntervalSince1970: TimeInterval(expiration))
    }
    
    /// Check if JWT is expired
    public func isExpired(_ token: String) throws -> Bool {
        let expirationDate = try getExpirationDate(token)
        return Date() > expirationDate
    }
    
    /// Refresh JWT token
    public func refreshToken(_ token: String, secret: String, expiresIn: TimeInterval = 3600) throws -> String {
        let payload = try decodeJWT(token)
        
        // Remove timestamp fields
        var newPayload = payload
        newPayload.removeValue(forKey: "iat")
        newPayload.removeValue(forKey: "exp")
        
        return try createJWT(payload: newPayload, secret: secret, expiresIn: expiresIn)
    }
    
    // MARK: - Private Methods
    
    private func createSignature(header: String, payload: String, secret: String) throws -> String {
        let message = "\(header).\(payload)"
        guard let messageData = message.data(using: .utf8),
              let secretData = secret.data(using: .utf8) else {
            throw JWTError.invalidData
        }
        
        let key = SymmetricKey(data: secretData)
        let signature = HMAC<SHA256>.authenticationCode(for: messageData, using: key)
        
        return Data(signature).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

// MARK: - Supporting Types

/// JWT-related errors
public enum JWTError: LocalizedError {
    case invalidTokenFormat
    case invalidPayload
    case invalidSignature
    case tokenExpired
    case invalidData
    case encodingFailed
    case decodingFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidTokenFormat:
            return "Invalid JWT token format"
        case .invalidPayload:
            return "Invalid JWT payload"
        case .invalidSignature:
            return "Invalid JWT signature"
        case .tokenExpired:
            return "JWT token has expired"
        case .invalidData:
            return "Invalid data for JWT operation"
        case .encodingFailed:
            return "Failed to encode JWT"
        case .decodingFailed:
            return "Failed to decode JWT"
        }
    }
} 