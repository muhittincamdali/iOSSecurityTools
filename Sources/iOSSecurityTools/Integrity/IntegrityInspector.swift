import Foundation

/// Looks for signs that the app runs in an environment it should not trust: a jailbroken device,
/// an attached debugger, the simulator, injected hooking libraries or a system proxy.
///
/// ```swift
/// let report = IntegrityInspector().inspect()
/// if !report.isClean {
///     analytics.record("integrity", report.findings.map(\.description))
/// }
/// ```
///
/// Treat the result as a signal, not a verdict. Every check runs inside the process it inspects,
/// so an attacker who controls the device can hide from all of them, and a few legitimate setups
/// trip some of them (a debugger in development, the Main Thread Checker that Xcode injects, a
/// corporate proxy). Use the report to add friction — re-authentication, lower limits, a server
/// review — and use App Attest (`DCAppAttestService`) when your server needs proof that a request
/// comes from your genuine app.
///
/// The jailbreak checks run only on iOS and iPadOS devices; on the simulator, on macOS (including
/// iPad apps running on a Mac) and on other platforms they are skipped, because the files they
/// look for are normal there.
public struct IntegrityInspector: Sendable {
    let environment: any IntegrityEnvironment

    /// Creates an inspector for the current process.
    public init() {
        self.environment = LiveIntegrityEnvironment()
    }

    init(environment: any IntegrityEnvironment) {
        self.environment = environment
    }

    /// Runs the selected checks.
    ///
    /// - Parameter checks: The checks to run; all of them by default.
    /// - Returns: The findings, and which checks ran.
    public func inspect(_ checks: IntegrityChecks = .all) -> IntegrityReport {
        var findings: [IntegrityFinding] = []
        var ran: IntegrityChecks = []

        if checks.contains(.jailbreak), environment.isJailbreakCheckApplicable {
            ran.insert(.jailbreak)
            for path in Self.jailbreakArtifacts where environment.fileExists(atPath: path) {
                findings.append(.jailbreakArtifact(path: path))
            }
            for path in Self.protectedDirectories where environment.canWrite(inDirectory: path) {
                findings.append(.writableSystemLocation(path: path))
            }
        }
        if checks.contains(.debugger) {
            ran.insert(.debugger)
            if environment.isDebuggerAttached() == true {
                findings.append(.debuggerAttached)
            }
        }
        if checks.contains(.simulator) {
            ran.insert(.simulator)
            if environment.isSimulator {
                findings.append(.simulator)
            }
        }
        if checks.contains(.injectedLibraries) {
            ran.insert(.injectedLibraries)
            if let inserted = environment.environmentValue("DYLD_INSERT_LIBRARIES"), !inserted.isEmpty {
                findings.append(.insertedLibraries(inserted))
            }
            for path in environment.loadedImagePaths() {
                let name = (path as NSString).lastPathComponent
                if Self.isSuspiciousLibrary(name) {
                    findings.append(.suspiciousLibrary(name: name))
                }
            }
        }
        if checks.contains(.proxy) {
            ran.insert(.proxy)
            if let proxy = environment.systemProxy() {
                findings.append(.systemProxy(proxy))
            }
        }
        return IntegrityReport(findings: findings, checksRun: ran)
    }

    /// Files and folders that jailbreaks and package managers install (rootful and rootless).
    static let jailbreakArtifacts = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/substrate",
        "/usr/lib/TweakInject",
        "/usr/lib/libhooker.dylib",
        "/usr/libexec/cydia",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/var/jb",
        "/var/binpack",
        "/cores/binpack",
        "/.bootstrapped",
        "/.installed_dopamine",
    ]

    /// Folders outside the sandbox that a stock app cannot write to.
    static let protectedDirectories = ["/private", "/private/var/mobile"]

    /// Name fragments of hooking and instrumentation libraries, lowercased.
    static let suspiciousLibraryFragments = [
        "frida", "cynject", "libcycript", "cydiasubstrate", "mobilesubstrate", "substrateloader", "substrateinserter",
        "substratebootstrap", "libsubstitute", "libhooker", "tweakinject", "ellekit", "sslkillswitch",
        "rocketbootstrap", "libcephei",
    ]

    static func isSuspiciousLibrary(_ name: String) -> Bool {
        let lowercased = name.lowercased()
        return suspiciousLibraryFragments.contains { lowercased.contains($0) }
    }
}

/// The checks ``IntegrityInspector`` can run.
public struct IntegrityChecks: OptionSet, Sendable, Hashable, Codable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// Jailbreak files and writable system folders (iOS and iPadOS devices only).
    public static let jailbreak = IntegrityChecks(rawValue: 1 << 0)
    /// A debugger attached to the process.
    public static let debugger = IntegrityChecks(rawValue: 1 << 1)
    /// The app runs in the simulator.
    public static let simulator = IntegrityChecks(rawValue: 1 << 2)
    /// `DYLD_INSERT_LIBRARIES` and loaded libraries of known hooking tools (Frida, Substrate, ...).
    public static let injectedLibraries = IntegrityChecks(rawValue: 1 << 3)
    /// An HTTP, HTTPS or automatic proxy in the system settings, as used to intercept traffic.
    public static let proxy = IntegrityChecks(rawValue: 1 << 4)
    /// Every check.
    public static let all: IntegrityChecks = [.jailbreak, .debugger, .simulator, .injectedLibraries, .proxy]
}

/// The result of ``IntegrityInspector/inspect(_:)``.
public struct IntegrityReport: Sendable, Hashable, Codable {
    /// What the checks found, in the order they ran.
    public let findings: [IntegrityFinding]
    /// The checks that ran. A requested check that does not apply to the platform is missing.
    public let checksRun: IntegrityChecks

    /// Whether no check found anything.
    public var isClean: Bool { findings.isEmpty }

    /// Whether a check found something.
    public func hasFindings(in checks: IntegrityChecks) -> Bool {
        findings.contains { checks.contains($0.check) }
    }
}

/// One sign found by ``IntegrityInspector``.
public enum IntegrityFinding: Sendable, Hashable, Codable, CustomStringConvertible {
    /// A file or folder that jailbreaks install exists.
    case jailbreakArtifact(path: String)
    /// The app could create a file outside its sandbox.
    case writableSystemLocation(path: String)
    /// A debugger is attached.
    case debuggerAttached
    /// The app runs in the simulator.
    case simulator
    /// `DYLD_INSERT_LIBRARIES` is set, with this value.
    case insertedLibraries(String)
    /// A library of a known hooking tool is loaded.
    case suspiciousLibrary(name: String)
    /// The system routes HTTP traffic through this proxy (`host:port`, or the PAC URL).
    case systemProxy(String)

    /// The check that produced the finding.
    public var check: IntegrityChecks {
        switch self {
        case .jailbreakArtifact, .writableSystemLocation: .jailbreak
        case .debuggerAttached: .debugger
        case .simulator: .simulator
        case .insertedLibraries, .suspiciousLibrary: .injectedLibraries
        case .systemProxy: .proxy
        }
    }

    public var description: String {
        switch self {
        case .jailbreakArtifact(let path): "Jailbreak file present: \(path)"
        case .writableSystemLocation(let path): "Can write outside the sandbox: \(path)"
        case .debuggerAttached: "A debugger is attached"
        case .simulator: "Running in the simulator"
        case .insertedLibraries(let value): "DYLD_INSERT_LIBRARIES is set: \(value)"
        case .suspiciousLibrary(let name): "Hooking library loaded: \(name)"
        case .systemProxy(let proxy): "System proxy: \(proxy)"
        }
    }
}
