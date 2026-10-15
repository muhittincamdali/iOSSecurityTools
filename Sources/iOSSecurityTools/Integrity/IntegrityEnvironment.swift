import Darwin
import Foundation
import MachO

/// What ``IntegrityInspector`` reads from the system. Tests replace it to cover every finding.
protocol IntegrityEnvironment: Sendable {
    var isJailbreakCheckApplicable: Bool { get }
    var isSimulator: Bool { get }
    func fileExists(atPath path: String) -> Bool
    func canWrite(inDirectory path: String) -> Bool
    func isDebuggerAttached() -> Bool?
    func environmentValue(_ name: String) -> String?
    func loadedImagePaths() -> [String]
    func systemProxy() -> String?
}

struct LiveIntegrityEnvironment: IntegrityEnvironment {
    var isJailbreakCheckApplicable: Bool {
        #if os(iOS) && !targetEnvironment(simulator) && !targetEnvironment(macCatalyst)
        // An iPad app running on a Mac sees the Mac's file system, where /bin/bash is normal.
        return !ProcessInfo.processInfo.isiOSAppOnMac
        #else
        return false
        #endif
    }

    var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    func fileExists(atPath path: String) -> Bool {
        // lstat instead of FileManager: it also sees a dangling symbolic link, and tweaks that hide
        // files usually hook the Foundation call first.
        var info = stat()
        return lstat(path, &info) == 0
    }

    func canWrite(inDirectory path: String) -> Bool {
        let probe = "\(path)/.integrity-\(UUID().uuidString)"
        let descriptor = open(probe, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard descriptor >= 0 else { return false }
        close(descriptor)
        unlink(probe)
        return true
    }

    func isDebuggerAttached() -> Bool? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = name.withUnsafeMutableBufferPointer { buffer in
            sysctl(buffer.baseAddress, u_int(buffer.count), &info, &size, nil, 0)
        }
        guard result == 0 else { return nil }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    func environmentValue(_ name: String) -> String? {
        guard let value = getenv(name) else { return nil }
        return String(cString: value)
    }

    func loadedImagePaths() -> [String] {
        (0..<_dyld_image_count()).compactMap { index in
            _dyld_get_image_name(index).map { String(cString: $0) }
        }
    }

    func systemProxy() -> String? {
        #if os(watchOS)
        return nil
        #else
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return nil
        }
        return Self.proxy(from: settings)
        #endif
    }

    /// Reads the HTTP proxy, HTTPS proxy or proxy auto-configuration URL from CFNetwork's settings.
    ///
    /// iOS reports a configured proxy with its host key alone; macOS also sets an `...Enable` flag,
    /// which is honoured when present.
    static func proxy(from settings: [String: Any]) -> String? {
        func isEnabled(_ key: String) -> Bool {
            guard let flag = settings[key] else { return true }
            return (flag as? NSNumber)?.boolValue ?? false
        }
        for (enable, host, port) in [("HTTPEnable", "HTTPProxy", "HTTPPort"), ("HTTPSEnable", "HTTPSProxy", "HTTPSPort")] {
            guard isEnabled(enable), let name = settings[host] as? String, !name.isEmpty else { continue }
            if let number = settings[port] as? NSNumber { return "\(name):\(number.intValue)" }
            return name
        }
        if isEnabled("ProxyAutoConfigEnable"), let url = settings["ProxyAutoConfigURLString"] as? String, !url.isEmpty {
            return url
        }
        return nil
    }
}
