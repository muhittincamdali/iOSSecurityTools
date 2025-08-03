import Foundation
import os.log

/// Security audit logger for tracking security events
public class AuditLogger {
    
    // MARK: - Singleton
    public static let shared = AuditLogger()
    
    // MARK: - Private Properties
    private let log = OSLog(subsystem: "com.muhittincamdali.iOSSecurityTools", category: "SecurityAudit")
    private let queue = DispatchQueue(label: "com.muhittincamdali.iOSSecurityTools.audit", qos: .utility)
    private let fileManager = FileManager.default
    private let logDirectory: URL
    
    // MARK: - Initialization
    private init() {
        let documentsPath = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
        logDirectory = documentsPath.appendingPathComponent("SecurityLogs")
        
        // Create log directory if it doesn't exist
        if !fileManager.fileExists(atPath: logDirectory.path) {
            try? fileManager.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        }
    }
    
    // MARK: - Public Methods
    
    /// Log security event
    public func logSecurityEvent(event: String, details: [String: Any] = [:], level: LogLevel = .info) {
        let logEntry = SecurityLogEntry(
            timestamp: Date(),
            event: event,
            details: details,
            level: level,
            deviceInfo: getDeviceInfo()
        )
        
        // Log to system log
        logToSystem(logEntry)
        
        // Log to file
        logToFile(logEntry)
        
        // Log to console in debug mode
        #if DEBUG
        logToConsole(logEntry)
        #endif
    }
    
    /// Log authentication event
    public func logAuthenticationEvent(userID: String, success: Bool, method: String, details: [String: Any] = [:]) {
        var eventDetails = details
        eventDetails["user_id"] = userID
        eventDetails["success"] = success
        eventDetails["method"] = method
        eventDetails["ip_address"] = getIPAddress()
        eventDetails["user_agent"] = getUserAgent()
        
        let event = success ? "authentication_success" : "authentication_failure"
        let level: LogLevel = success ? .info : .warning
        
        logSecurityEvent(event: event, details: eventDetails, level: level)
    }
    
    /// Log encryption event
    public func logEncryptionEvent(algorithm: String, keySize: Int, success: Bool, details: [String: Any] = [:]) {
        var eventDetails = details
        eventDetails["algorithm"] = algorithm
        eventDetails["key_size"] = keySize
        eventDetails["success"] = success
        
        let event = success ? "encryption_success" : "encryption_failure"
        let level: LogLevel = success ? .info : .error
        
        logSecurityEvent(event: event, details: eventDetails, level: level)
    }
    
    /// Log data access event
    public func logDataAccessEvent(dataType: String, accessType: String, success: Bool, details: [String: Any] = [:]) {
        var eventDetails = details
        eventDetails["data_type"] = dataType
        eventDetails["access_type"] = accessType
        eventDetails["success"] = success
        eventDetails["user_id"] = getCurrentUserID()
        
        let event = success ? "data_access_success" : "data_access_failure"
        let level: LogLevel = success ? .info : .warning
        
        logSecurityEvent(event: event, details: eventDetails, level: level)
    }
    
    /// Log security violation
    public func logSecurityViolation(violationType: String, severity: LogLevel, details: [String: Any] = [:]) {
        var eventDetails = details
        eventDetails["violation_type"] = violationType
        eventDetails["severity"] = severity.rawValue
        eventDetails["user_id"] = getCurrentUserID()
        eventDetails["ip_address"] = getIPAddress()
        
        logSecurityEvent(event: "security_violation", details: eventDetails, level: severity)
    }
    
    /// Log configuration change
    public func logConfigurationChange(parameter: String, oldValue: Any, newValue: Any, details: [String: Any] = [:]) {
        var eventDetails = details
        eventDetails["parameter"] = parameter
        eventDetails["old_value"] = oldValue
        eventDetails["new_value"] = newValue
        eventDetails["user_id"] = getCurrentUserID()
        
        logSecurityEvent(event: "configuration_change", details: eventDetails, level: .info)
    }
    
    /// Get audit logs
    public func getAuditLogs(from startDate: Date? = nil, to endDate: Date? = nil, level: LogLevel? = nil) -> [SecurityLogEntry] {
        let logFileURL = logDirectory.appendingPathComponent("security_audit.log")
        
        guard let logData = try? Data(contentsOf: logFileURL),
              let logString = String(data: logData, encoding: .utf8) else {
            return []
        }
        
        let lines = logString.components(separatedBy: .newlines)
        var logs: [SecurityLogEntry] = []
        
        for line in lines where !line.isEmpty {
            if let logEntry = parseLogEntry(from: line) {
                // Apply filters
                if let startDate = startDate, logEntry.timestamp < startDate {
                    continue
                }
                if let endDate = endDate, logEntry.timestamp > endDate {
                    continue
                }
                if let level = level, logEntry.level != level {
                    continue
                }
                
                logs.append(logEntry)
            }
        }
        
        return logs.sorted { $0.timestamp > $1.timestamp }
    }
    
    /// Clear audit logs
    public func clearAuditLogs() throws {
        let logFileURL = logDirectory.appendingPathComponent("security_audit.log")
        
        if fileManager.fileExists(atPath: logFileURL.path) {
            try fileManager.removeItem(at: logFileURL)
        }
    }
    
    /// Export audit logs
    public func exportAuditLogs() -> Data? {
        let logFileURL = logDirectory.appendingPathComponent("security_audit.log")
        
        guard fileManager.fileExists(atPath: logFileURL.path) else {
            return nil
        }
        
        return try? Data(contentsOf: logFileURL)
    }
    
    // MARK: - Private Methods
    
    private func logToSystem(_ entry: SecurityLogEntry) {
        let message = formatLogMessage(entry)
        
        switch entry.level {
        case .debug:
            os_log(.debug, log: log, "%{public}@", message)
        case .info:
            os_log(.info, log: log, "%{public}@", message)
        case .warning:
            os_log(.error, log: log, "%{public}@", message)
        case .error:
            os_log(.fault, log: log, "%{public}@", message)
        }
    }
    
    private func logToFile(_ entry: SecurityLogEntry) {
        queue.async {
            let logFileURL = self.logDirectory.appendingPathComponent("security_audit.log")
            let message = self.formatLogMessage(entry) + "\n"
            
            if let data = message.data(using: .utf8) {
                if self.fileManager.fileExists(atPath: logFileURL.path) {
                    if let fileHandle = try? FileHandle(forWritingTo: logFileURL) {
                        fileHandle.seekToEndOfFile()
                        fileHandle.write(data)
                        fileHandle.closeFile()
                    }
                } else {
                    try? data.write(to: logFileURL)
                }
            }
        }
    }
    
    private func logToConsole(_ entry: SecurityLogEntry) {
        let message = formatLogMessage(entry)
        print("[SecurityAudit] \(message)")
    }
    
    private func formatLogMessage(_ entry: SecurityLogEntry) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = dateFormatter.string(from: entry.timestamp)
        
        let detailsString = entry.details.isEmpty ? "" : " | Details: \(entry.details)"
        
        return "[\(timestamp)] [\(entry.level.rawValue.uppercased())] \(entry.event)\(detailsString)"
    }
    
    private func parseLogEntry(from line: String) -> SecurityLogEntry? {
        // Simple parsing - in production, use proper JSON parsing
        let components = line.components(separatedBy: " | ")
        guard components.count >= 2 else { return nil }
        
        let timestampString = components[0].replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: "")
        let levelString = components[1].replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: "")
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        
        guard let timestamp = dateFormatter.date(from: timestampString),
              let level = LogLevel(rawValue: levelString.lowercased()) else {
            return nil
        }
        
        let event = components.count > 2 ? components[2] : "unknown"
        
        return SecurityLogEntry(
            timestamp: timestamp,
            event: event,
            details: [:],
            level: level,
            deviceInfo: getDeviceInfo()
        )
    }
    
    private func getDeviceInfo() -> [String: Any] {
        return [
            "device_model": UIDevice.current.model,
            "system_version": UIDevice.current.systemVersion,
            "app_version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown",
            "build_number": Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown"
        ]
    }
    
    private func getIPAddress() -> String {
        // In a real app, you would get the actual IP address
        return "192.168.1.1"
    }
    
    private func getUserAgent() -> String {
        return "iOSSecurityTools/1.0.0"
    }
    
    private func getCurrentUserID() -> String {
        // In a real app, you would get the current user ID
        return "user_123"
    }
}

// MARK: - Supporting Types

/// Security log entry
public struct SecurityLogEntry {
    public let timestamp: Date
    public let event: String
    public let details: [String: Any]
    public let level: LogLevel
    public let deviceInfo: [String: Any]
}

/// Log levels
public enum LogLevel: String, CaseIterable {
    case debug = "debug"
    case info = "info"
    case warning = "warning"
    case error = "error"
} 