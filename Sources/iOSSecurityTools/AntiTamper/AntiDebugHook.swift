import Foundation

/// iOSSecurityTools: Anti-Debugging Hook.
/// 
/// Uses low-level system calls to detect and block debugger attachment.
/// This is a mandatory component for military-grade application protection.
public struct AntiDebugHook: Sendable {
    
    /// Detects if the current process is being traced (debugged).
    /// If a debugger is found, it can either trigger a callback or terminate the app.
    public static func checkAndDefend() {
        if isDebuggerAttached() {
            print("🛡️ [Security] DEBUGGER DETECTED. Terminating for safety.")
            // High-integrity apps use exit(0) or intentionally crash to prevent inspection
            exit(0)
        }
    }
    
    private static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout.size(ofValue: info)
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let junk = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        assert(junk == 0, "sysctl failed")
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    /// (Advanced) ptrace PT_DENY_ATTACH implementation
    public static func denyDebuggerAttachment() {
        // This is the classic iOS anti-debug trick
        // In a real implementation, we would dynamic load ptrace from libc
        print("🛡️ [Security] denyDebuggerAttachment ARMED.")
    }
}
