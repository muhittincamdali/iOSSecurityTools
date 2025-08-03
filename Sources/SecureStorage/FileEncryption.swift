import Foundation
import CryptoKit

/// File-level encryption utilities
public class FileEncryption {
    
    // MARK: - Singleton
    public static let shared = FileEncryption()
    
    // MARK: - Private Properties
    private let encryption = AESEncryption.shared
    private let keyGenerator = KeyGenerator.shared
    
    // MARK: - Initialization
    private init() {}
    
    // MARK: - Public Methods
    
    /// Encrypt file
    public func encryptFile(at fileURL: URL, with key: SymmetricKey) throws -> URL {
        let data = try Data(contentsOf: fileURL)
        let encryptedData = try encryption.encrypt(data, with: key)
        
        let encryptedFileURL = fileURL.appendingPathExtension("encrypted")
        try encryptedData.write(to: encryptedFileURL)
        
        return encryptedFileURL
    }
    
    /// Decrypt file
    public func decryptFile(at fileURL: URL, with key: SymmetricKey) throws -> URL {
        let encryptedData = try Data(contentsOf: fileURL)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        
        let decryptedFileURL = fileURL.deletingPathExtension()
        try decryptedData.write(to: decryptedFileURL)
        
        return decryptedFileURL
    }
    
    /// Encrypt file with password
    public func encryptFile(at fileURL: URL, withPassword password: String) throws -> URL {
        let key = try keyGenerator.generateAESKey(from: password)
        return try encryptFile(at: fileURL, with: key)
    }
    
    /// Decrypt file with password
    public func decryptFile(at fileURL: URL, withPassword password: String) throws -> URL {
        let key = try keyGenerator.generateAESKey(from: password)
        return try decryptFile(at: fileURL, with: key)
    }
    
    /// Encrypt large file in chunks
    public func encryptLargeFile(at fileURL: URL, with key: SymmetricKey, chunkSize: Int = 1024 * 1024) throws -> URL {
        let encryptedFileURL = fileURL.appendingPathExtension("encrypted")
        
        guard let inputStream = InputStream(url: fileURL),
              let outputStream = OutputStream(url: encryptedFileURL, append: false) else {
            throw FileEncryptionError.fileAccessFailed
        }
        
        inputStream.open()
        outputStream.open()
        
        defer {
            inputStream.close()
            outputStream.close()
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
        defer { buffer.deallocate() }
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(buffer, maxLength: chunkSize)
            
            if bytesRead > 0 {
                let chunkData = Data(bytes: buffer, count: bytesRead)
                let encryptedChunk = try encryption.encrypt(chunkData, with: key)
                _ = encryptedChunk.withUnsafeBytes { outputStream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: encryptedChunk.count) }
            }
        }
        
        return encryptedFileURL
    }
    
    /// Decrypt large file in chunks
    public func decryptLargeFile(at fileURL: URL, with key: SymmetricKey, chunkSize: Int = 1024 * 1024) throws -> URL {
        let decryptedFileURL = fileURL.deletingPathExtension()
        
        guard let inputStream = InputStream(url: fileURL),
              let outputStream = OutputStream(url: decryptedFileURL, append: false) else {
            throw FileEncryptionError.fileAccessFailed
        }
        
        inputStream.open()
        outputStream.open()
        
        defer {
            inputStream.close()
            outputStream.close()
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
        defer { buffer.deallocate() }
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(buffer, maxLength: chunkSize)
            
            if bytesRead > 0 {
                let chunkData = Data(bytes: buffer, count: bytesRead)
                let decryptedChunk = try encryption.decrypt(chunkData, with: key)
                _ = decryptedChunk.withUnsafeBytes { outputStream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: decryptedChunk.count) }
            }
        }
        
        return decryptedFileURL
    }
    
    /// Encrypt directory
    public func encryptDirectory(at directoryURL: URL, with key: SymmetricKey) throws -> URL {
        let encryptedDirectoryURL = directoryURL.appendingPathExtension("encrypted")
        
        try FileManager.default.createDirectory(at: encryptedDirectoryURL, withIntermediateDirectories: true)
        
        let fileURLs = try FileManager.default.contentsOfDirectory(at: directoryURL, includingPropertiesForKeys: nil)
        
        for fileURL in fileURLs {
            if fileURL.hasDirectoryPath {
                // Recursively encrypt subdirectories
                let encryptedSubDir = try encryptDirectory(at: fileURL, with: key)
                let relativePath = fileURL.lastPathComponent
                let targetURL = encryptedDirectoryURL.appendingPathComponent(relativePath)
                try FileManager.default.moveItem(at: encryptedSubDir, to: targetURL)
            } else {
                // Encrypt file
                let encryptedFileURL = try encryptFile(at: fileURL, with: key)
                let relativePath = fileURL.lastPathComponent
                let targetURL = encryptedDirectoryURL.appendingPathComponent(relativePath)
                try FileManager.default.moveItem(at: encryptedFileURL, to: targetURL)
            }
        }
        
        return encryptedDirectoryURL
    }
    
    /// Decrypt directory
    public func decryptDirectory(at directoryURL: URL, with key: SymmetricKey) throws -> URL {
        let decryptedDirectoryURL = directoryURL.deletingPathExtension()
        
        try FileManager.default.createDirectory(at: decryptedDirectoryURL, withIntermediateDirectories: true)
        
        let fileURLs = try FileManager.default.contentsOfDirectory(at: directoryURL, includingPropertiesForKeys: nil)
        
        for fileURL in fileURLs {
            if fileURL.hasDirectoryPath {
                // Recursively decrypt subdirectories
                let decryptedSubDir = try decryptDirectory(at: fileURL, with: key)
                let relativePath = fileURL.lastPathComponent
                let targetURL = decryptedDirectoryURL.appendingPathComponent(relativePath)
                try FileManager.default.moveItem(at: decryptedSubDir, to: targetURL)
            } else {
                // Decrypt file
                let decryptedFileURL = try decryptFile(at: fileURL, with: key)
                let relativePath = fileURL.lastPathComponent
                let targetURL = decryptedDirectoryURL.appendingPathComponent(relativePath)
                try FileManager.default.moveItem(at: decryptedFileURL, to: targetURL)
            }
        }
        
        return decryptedDirectoryURL
    }
    
    /// Get file encryption status
    public func isFileEncrypted(at fileURL: URL) -> Bool {
        return fileURL.pathExtension == "encrypted"
    }
    
    /// Get encrypted file size
    public func getEncryptedFileSize(at fileURL: URL) throws -> Int64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        return attributes[.size] as? Int64 ?? 0
    }
    
    /// Get original file size from encrypted file
    public func getOriginalFileSize(from encryptedFileURL: URL, with key: SymmetricKey) throws -> Int64 {
        // This is a simplified implementation
        // In production, you'd store the original size in the encrypted file header
        let encryptedData = try Data(contentsOf: encryptedFileURL)
        let decryptedData = try encryption.decrypt(encryptedData, with: key)
        return Int64(decryptedData.count)
    }
    
    /// Verify file integrity
    public func verifyFileIntegrity(at fileURL: URL, with key: SymmetricKey) throws -> Bool {
        let encryptedData = try Data(contentsOf: fileURL)
        
        do {
            _ = try encryption.decrypt(encryptedData, with: key)
            return true
        } catch {
            return false
        }
    }
    
    /// Create encrypted archive
    public func createEncryptedArchive(from directoryURL: URL, with key: SymmetricKey) throws -> URL {
        let archiveURL = directoryURL.appendingPathExtension("tar")
        
        // Create tar archive
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = ["-cf", archiveURL.path, "-C", directoryURL.deletingLastPathComponent().path, directoryURL.lastPathComponent]
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            throw FileEncryptionError.archiveCreationFailed
        }
        
        // Encrypt archive
        let encryptedArchiveURL = try encryptFile(at: archiveURL, with: key)
        
        // Clean up temporary archive
        try? FileManager.default.removeItem(at: archiveURL)
        
        return encryptedArchiveURL
    }
    
    /// Extract encrypted archive
    public func extractEncryptedArchive(at archiveURL: URL, with key: SymmetricKey, to destinationURL: URL) throws {
        // Decrypt archive
        let decryptedArchiveURL = try decryptFile(at: archiveURL, with: key)
        
        defer {
            try? FileManager.default.removeItem(at: decryptedArchiveURL)
        }
        
        // Extract archive
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = ["-xf", decryptedArchiveURL.path, "-C", destinationURL.path]
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            throw FileEncryptionError.archiveExtractionFailed
        }
    }
    
    /// Encrypt file with progress callback
    public func encryptFile(at fileURL: URL, with key: SymmetricKey, progress: @escaping (Double) -> Void) throws -> URL {
        let fileSize = try getEncryptedFileSize(at: fileURL)
        let encryptedFileURL = fileURL.appendingPathExtension("encrypted")
        
        guard let inputStream = InputStream(url: fileURL),
              let outputStream = OutputStream(url: encryptedFileURL, append: false) else {
            throw FileEncryptionError.fileAccessFailed
        }
        
        inputStream.open()
        outputStream.open()
        
        defer {
            inputStream.close()
            outputStream.close()
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 1024 * 1024)
        defer { buffer.deallocate() }
        
        var bytesProcessed: Int64 = 0
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(buffer, maxLength: 1024 * 1024)
            
            if bytesRead > 0 {
                let chunkData = Data(bytes: buffer, count: bytesRead)
                let encryptedChunk = try encryption.encrypt(chunkData, with: key)
                _ = encryptedChunk.withUnsafeBytes { outputStream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: encryptedChunk.count) }
                
                bytesProcessed += Int64(bytesRead)
                let progressValue = Double(bytesProcessed) / Double(fileSize)
                progress(progressValue)
            }
        }
        
        return encryptedFileURL
    }
    
    /// Decrypt file with progress callback
    public func decryptFile(at fileURL: URL, with key: SymmetricKey, progress: @escaping (Double) -> Void) throws -> URL {
        let fileSize = try getEncryptedFileSize(at: fileURL)
        let decryptedFileURL = fileURL.deletingPathExtension()
        
        guard let inputStream = InputStream(url: fileURL),
              let outputStream = OutputStream(url: decryptedFileURL, append: false) else {
            throw FileEncryptionError.fileAccessFailed
        }
        
        inputStream.open()
        outputStream.open()
        
        defer {
            inputStream.close()
            outputStream.close()
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 1024 * 1024)
        defer { buffer.deallocate() }
        
        var bytesProcessed: Int64 = 0
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(buffer, maxLength: 1024 * 1024)
            
            if bytesRead > 0 {
                let chunkData = Data(bytes: buffer, count: bytesRead)
                let decryptedChunk = try encryption.decrypt(chunkData, with: key)
                _ = decryptedChunk.withUnsafeBytes { outputStream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: decryptedChunk.count) }
                
                bytesProcessed += Int64(bytesRead)
                let progressValue = Double(bytesProcessed) / Double(fileSize)
                progress(progressValue)
            }
        }
        
        return decryptedFileURL
    }
}

// MARK: - Supporting Types

/// File encryption errors
public enum FileEncryptionError: LocalizedError {
    case fileAccessFailed
    case encryptionFailed
    case decryptionFailed
    case archiveCreationFailed
    case archiveExtractionFailed
    case invalidFileFormat
    case insufficientSpace
    
    public var errorDescription: String? {
        switch self {
        case .fileAccessFailed:
            return "Failed to access file"
        case .encryptionFailed:
            return "File encryption failed"
        case .decryptionFailed:
            return "File decryption failed"
        case .archiveCreationFailed:
            return "Archive creation failed"
        case .archiveExtractionFailed:
            return "Archive extraction failed"
        case .invalidFileFormat:
            return "Invalid file format"
        case .insufficientSpace:
            return "Insufficient disk space"
        }
    }
} 