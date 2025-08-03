import Foundation
import CryptoKit

/// OAuth 2.0 manager for authentication flows
public class OAuthManager {
    
    // MARK: - Singleton
    public static let shared = OAuthManager()
    
    // MARK: - Private Properties
    private var stateStore: [String: String] = [:]
    private var codeVerifierStore: [String: String] = [:]
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Generate authorization URL for OAuth 2.0
    public func generateAuthorizationURL(
        clientID: String,
        redirectURI: String,
        scope: String,
        responseType: String = "code",
        state: String? = nil,
        usePKCE: Bool = true
    ) throws -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "accounts.google.com"
        components.path = "/o/oauth2/v2/auth"
        
        var queryItems: [URLQueryItem] = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: scope),
            URLQueryItem(name: "response_type", value: responseType)
        ]
        
        if let state = state {
            queryItems.append(URLQueryItem(name: "state", value: state))
            stateStore[state] = state
        }
        
        if usePKCE {
            let codeVerifier = generateCodeVerifier()
            let codeChallenge = generateCodeChallenge(from: codeVerifier)
            let stateKey = state ?? UUID().uuidString
            
            queryItems.append(URLQueryItem(name: "code_challenge", value: codeChallenge))
            queryItems.append(URLQueryItem(name: "code_challenge_method", value: "S256"))
            
            codeVerifierStore[stateKey] = codeVerifier
            if state == nil {
                stateStore[stateKey] = stateKey
            }
        }
        
        components.queryItems = queryItems
        
        guard let url = components.url else {
            throw OAuthError.invalidURL
        }
        
        return url
    }
    
    /// Exchange authorization code for access token
    public func exchangeCodeForToken(
        code: String,
        clientID: String,
        clientSecret: String,
        redirectURI: String,
        state: String? = nil
    ) async throws -> OAuthToken {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        var bodyComponents = URLComponents()
        bodyComponents.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "client_secret", value: clientSecret),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "redirect_uri", value: redirectURI)
        ]
        
        if let state = state,
           let codeVerifier = codeVerifierStore[state] {
            bodyComponents.queryItems?.append(URLQueryItem(name: "code_verifier", value: codeVerifier))
            codeVerifierStore.removeValue(forKey: state)
        }
        
        request.httpBody = bodyComponents.query?.data(using: .utf8)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw OAuthError.tokenExchangeFailed
        }
        
        let token = try JSONDecoder().decode(OAuthToken.self, from: data)
        return token
    }
    
    /// Refresh access token
    public func refreshToken(
        refreshToken: String,
        clientID: String,
        clientSecret: String
    ) async throws -> OAuthToken {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let bodyComponents = URLComponents()
        bodyComponents.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "client_secret", value: clientSecret),
            URLQueryItem(name: "refresh_token", value: refreshToken),
            URLQueryItem(name: "grant_type", value: "refresh_token")
        ]
        
        request.httpBody = bodyComponents.query?.data(using: .utf8)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw OAuthError.tokenRefreshFailed
        }
        
        let token = try JSONDecoder().decode(OAuthToken.self, from: data)
        return token
    }
    
    /// Revoke access token
    public func revokeToken(_ token: String) async throws {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/revoke")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let bodyComponents = URLComponents()
        bodyComponents.queryItems = [
            URLQueryItem(name: "token", value: token)
        ]
        
        request.httpBody = bodyComponents.query?.data(using: .utf8)
        
        let (_, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw OAuthError.tokenRevocationFailed
        }
    }
    
    /// Validate state parameter
    public func validateState(_ state: String) -> Bool {
        return stateStore[state] != nil
    }
    
    /// Clear stored state
    public func clearState(_ state: String) {
        stateStore.removeValue(forKey: state)
        codeVerifierStore.removeValue(forKey: state)
    }
    
    /// Get user info
    public func getUserInfo(accessToken: String) async throws -> [String: Any] {
        var request = URLRequest(url: URL(string: "https://www.googleapis.com/oauth2/v2/userinfo")!)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw OAuthError.userInfoFailed
        }
        
        guard let userInfo = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OAuthError.invalidUserInfo
        }
        
        return userInfo
    }
    
    // MARK: - Private Methods
    
    private func generateCodeVerifier() -> String {
        let bytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
    
    private func generateCodeChallenge(from codeVerifier: String) -> String {
        guard let data = codeVerifier.data(using: .utf8) else {
            return codeVerifier
        }
        
        let hash = SHA256.hash(data: data)
        return Data(hash).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

// MARK: - Supporting Types

/// OAuth token response
public struct OAuthToken: Codable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Int?
    public let refreshToken: String?
    public let scope: String?
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
    }
}

/// OAuth-related errors
public enum OAuthError: LocalizedError {
    case invalidURL
    case invalidClientID
    case invalidRedirectURI
    case invalidScope
    case invalidState
    case tokenExchangeFailed
    case tokenRefreshFailed
    case tokenRevocationFailed
    case userInfoFailed
    case invalidUserInfo
    case networkError
    case serverError
    
    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid OAuth URL"
        case .invalidClientID:
            return "Invalid OAuth client ID"
        case .invalidRedirectURI:
            return "Invalid OAuth redirect URI"
        case .invalidScope:
            return "Invalid OAuth scope"
        case .invalidState:
            return "Invalid OAuth state"
        case .tokenExchangeFailed:
            return "Failed to exchange code for token"
        case .tokenRefreshFailed:
            return "Failed to refresh token"
        case .tokenRevocationFailed:
            return "Failed to revoke token"
        case .userInfoFailed:
            return "Failed to get user info"
        case .invalidUserInfo:
            return "Invalid user info response"
        case .networkError:
            return "Network error occurred"
        case .serverError:
            return "Server error occurred"
        }
    }
} 