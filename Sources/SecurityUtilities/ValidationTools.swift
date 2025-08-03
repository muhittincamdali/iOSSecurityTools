import Foundation

/// Input validation and sanitization tools
public class ValidationTools {
    
    // MARK: - Singleton
    public static let shared = ValidationTools()
    
    // MARK: - Private Properties
    private let emailRegex = try! NSRegularExpression(pattern: "^[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    private let phoneRegex = try! NSRegularExpression(pattern: "^[+]?[0-9]{10,15}$")
    private let urlRegex = try! NSRegularExpression(pattern: "^(https?://)?([\\da-z.-]+)\\.([a-z.]{2,6})[/\\w .-]*/?$")
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Validate email address
    public func isValidEmail(_ email: String) -> Bool {
        let range = NSRange(location: 0, length: email.utf16.count)
        return emailRegex.firstMatch(in: email, range: range) != nil
    }
    
    /// Validate phone number
    public func isValidPhone(_ phone: String) -> Bool {
        let cleanPhone = phone.replacingOccurrences(of: "[^0-9+]", with: "", options: .regularExpression)
        let range = NSRange(location: 0, length: cleanPhone.utf16.count)
        return phoneRegex.firstMatch(in: cleanPhone, range: range) != nil
    }
    
    /// Validate URL
    public func isValidURL(_ url: String) -> Bool {
        let range = NSRange(location: 0, length: url.utf16.count)
        return urlRegex.firstMatch(in: url, range: range) != nil
    }
    
    /// Check password strength
    public func checkPasswordStrength(_ password: String) -> PasswordStrength {
        var score = 0
        var feedback: [String] = []
        
        // Length check
        if password.count >= 8 {
            score += 1
        } else {
            feedback.append("Password should be at least 8 characters long")
        }
        
        // Uppercase check
        if password.range(of: "[A-Z]", options: .regularExpression) != nil {
            score += 1
        } else {
            feedback.append("Password should contain at least one uppercase letter")
        }
        
        // Lowercase check
        if password.range(of: "[a-z]", options: .regularExpression) != nil {
            score += 1
        } else {
            feedback.append("Password should contain at least one lowercase letter")
        }
        
        // Number check
        if password.range(of: "[0-9]", options: .regularExpression) != nil {
            score += 1
        } else {
            feedback.append("Password should contain at least one number")
        }
        
        // Special character check
        if password.range(of: "[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]", options: .regularExpression) != nil {
            score += 1
        } else {
            feedback.append("Password should contain at least one special character")
        }
        
        return PasswordStrength(score: score, feedback: feedback)
    }
    
    /// Sanitize HTML input
    public func sanitizeHTML(_ input: String) -> String {
        var sanitized = input
        
        // Remove script tags
        sanitized = sanitized.replacingOccurrences(of: "<script[^>]*>.*?</script>", with: "", options: .regularExpression)
        
        // Remove other dangerous tags
        let dangerousTags = ["javascript:", "vbscript:", "onload", "onerror", "onclick"]
        for tag in dangerousTags {
            sanitized = sanitized.replacingOccurrences(of: tag, with: "", options: .caseInsensitive)
        }
        
        // Remove HTML entities
        sanitized = sanitized.replacingOccurrences(of: "&", with: "&amp;")
        sanitized = sanitized.replacingOccurrences(of: "<", with: "&lt;")
        sanitized = sanitized.replacingOccurrences(of: ">", with: "&gt;")
        sanitized = sanitized.replacingOccurrences(of: "\"", with: "&quot;")
        sanitized = sanitized.replacingOccurrences(of: "'", with: "&#x27;")
        
        return sanitized
    }
    
    /// Sanitize SQL input
    public func sanitizeSQLInput(_ input: String) -> String {
        var sanitized = input
        
        // Remove SQL injection patterns
        let sqlPatterns = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "UNION", "EXEC", "EXECUTE", "SCRIPT", "DECLARE", "CAST", "CONVERT"
        ]
        
        for pattern in sqlPatterns {
            sanitized = sanitized.replacingOccurrences(of: pattern, with: "", options: .caseInsensitive)
        }
        
        // Remove quotes and semicolons
        sanitized = sanitized.replacingOccurrences(of: "'", with: "''")
        sanitized = sanitized.replacingOccurrences(of: ";", with: "")
        
        return sanitized
    }
    
    /// Sanitize JavaScript input
    public func sanitizeJavaScript(_ input: String) -> String {
        var sanitized = input
        
        // Remove JavaScript code
        sanitized = sanitized.replacingOccurrences(of: "<script[^>]*>.*?</script>", with: "", options: .regularExpression)
        
        // Remove JavaScript functions
        let jsPatterns = [
            "alert\\(", "confirm\\(", "prompt\\(", "eval\\(", "setTimeout\\(", "setInterval\\(",
            "document\\.", "window\\.", "location\\.", "history\\."
        ]
        
        for pattern in jsPatterns {
            sanitized = sanitized.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
        }
        
        return sanitized
    }
    
    /// Sanitize URL input
    public func sanitizeURL(_ input: String) -> String {
        var sanitized = input
        
        // Remove dangerous protocols
        let dangerousProtocols = ["javascript:", "vbscript:", "data:", "file:"]
        for protocol in dangerousProtocols {
            sanitized = sanitized.replacingOccurrences(of: protocol, with: "", options: .caseInsensitive)
        }
        
        // Ensure proper URL format
        if !sanitized.hasPrefix("http://") && !sanitized.hasPrefix("https://") {
            sanitized = "https://" + sanitized
        }
        
        return sanitized
    }
    
    /// Validate credit card number
    public func isValidCreditCard(_ cardNumber: String) -> Bool {
        let cleanNumber = cardNumber.replacingOccurrences(of: "[^0-9]", with: "", options: .regularExpression)
        
        guard cleanNumber.count >= 13 && cleanNumber.count <= 19 else {
            return false
        }
        
        // Luhn algorithm
        var sum = 0
        let reversedDigits = cleanNumber.reversed().map { Int(String($0)) ?? 0 }
        
        for (index, digit) in reversedDigits.enumerated() {
            if index % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            } else {
                sum += digit
            }
        }
        
        return sum % 10 == 0
    }
    
    /// Validate social security number (US format)
    public func isValidSSN(_ ssn: String) -> Bool {
        let cleanSSN = ssn.replacingOccurrences(of: "[^0-9]", with: "", options: .regularExpression)
        
        guard cleanSSN.count == 9 else {
            return false
        }
        
        // Check for invalid patterns
        let invalidPatterns = [
            "000000000", "111111111", "222222222", "333333333", "444444444",
            "555555555", "666666666", "777777777", "888888888", "999999999"
        ]
        
        if invalidPatterns.contains(cleanSSN) {
            return false
        }
        
        return true
    }
    
    /// Validate postal code (US format)
    public func isValidPostalCode(_ postalCode: String) -> Bool {
        let cleanCode = postalCode.replacingOccurrences(of: "[^0-9]", with: "", options: .regularExpression)
        
        // US ZIP code format: 5 digits or 5+4 digits
        return cleanCode.count == 5 || cleanCode.count == 9
    }
    
    /// Validate date format
    public func isValidDate(_ dateString: String, format: String = "yyyy-MM-dd") -> Bool {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = format
        
        return dateFormatter.date(from: dateString) != nil
    }
    
    /// Validate numeric input
    public func isValidNumeric(_ input: String, min: Double? = nil, max: Double? = nil) -> Bool {
        guard let number = Double(input) else {
            return false
        }
        
        if let min = min, number < min {
            return false
        }
        
        if let max = max, number > max {
            return false
        }
        
        return true
    }
    
    /// Validate string length
    public func isValidLength(_ input: String, min: Int? = nil, max: Int? = nil) -> Bool {
        let length = input.count
        
        if let min = min, length < min {
            return false
        }
        
        if let max = max, length > max {
            return false
        }
        
        return true
    }
    
    /// Validate alphanumeric input
    public func isAlphanumeric(_ input: String) -> Bool {
        return input.range(of: "^[a-zA-Z0-9]+$", options: .regularExpression) != nil
    }
    
    /// Validate alphabetic input
    public func isAlphabetic(_ input: String) -> Bool {
        return input.range(of: "^[a-zA-Z]+$", options: .regularExpression) != nil
    }
    
    /// Validate numeric input
    public func isNumeric(_ input: String) -> Bool {
        return input.range(of: "^[0-9]+$", options: .regularExpression) != nil
    }
    
    /// Truncate string to safe length
    public func truncateString(_ input: String, maxLength: Int) -> String {
        guard input.count > maxLength else {
            return input
        }
        
        let index = input.index(input.startIndex, offsetBy: maxLength)
        return String(input[..<index])
    }
    
    /// Remove unsafe characters
    public func removeUnsafeCharacters(_ input: String) -> String {
        return input.replacingOccurrences(of: "[^a-zA-Z0-9\\s._-]", with: "", options: .regularExpression)
    }
}

// MARK: - Supporting Types

/// Password strength result
public struct PasswordStrength {
    public let score: Int
    public let feedback: [String]
    
    public var isStrong: Bool {
        return score >= 4
    }
    
    public var isMedium: Bool {
        return score >= 3
    }
    
    public var isWeak: Bool {
        return score < 3
    }
} 