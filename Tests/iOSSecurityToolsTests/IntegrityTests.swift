import Foundation
import Testing
@testable import iOSSecurityTools

/// An environment whose answers the test sets.
struct FakeIntegrityEnvironment: IntegrityEnvironment {
    var isJailbreakCheckApplicable = true
    var isSimulator = false
    var existingFiles: Set<String> = []
    var writableDirectories: Set<String> = []
    var debugger: Bool? = false
    var environment: [String: String] = [:]
    var images: [String] = ["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Foundation.framework/Foundation"]
    var proxy: String?

    func fileExists(atPath path: String) -> Bool { existingFiles.contains(path) }
    func canWrite(inDirectory path: String) -> Bool { writableDirectories.contains(path) }
    func isDebuggerAttached() -> Bool? { debugger }
    func environmentValue(_ name: String) -> String? { environment[name] }
    func loadedImagePaths() -> [String] { images }
    func systemProxy() -> String? { proxy }
}

@Suite("IntegrityInspector")
struct IntegrityInspectorTests {
    @Test("a stock device has no findings and runs every check")
    func clean() {
        let report = IntegrityInspector(environment: FakeIntegrityEnvironment()).inspect()
        #expect(report.isClean)
        #expect(report.checksRun == .all)
    }

    @Test("reports each jailbreak file and writable system folder")
    func jailbreak() {
        var environment = FakeIntegrityEnvironment()
        environment.existingFiles = ["/var/jb", "/Applications/Sileo.app", "/not/listed"]
        environment.writableDirectories = ["/private"]
        let report = IntegrityInspector(environment: environment).inspect()
        #expect(report.findings == [
            .jailbreakArtifact(path: "/Applications/Sileo.app"),
            .jailbreakArtifact(path: "/var/jb"),
            .writableSystemLocation(path: "/private"),
        ])
        #expect(report.hasFindings(in: .jailbreak))
        #expect(!report.hasFindings(in: [.debugger, .proxy]))
    }

    @Test("skips jailbreak checks where they do not apply")
    func jailbreakNotApplicable() {
        var environment = FakeIntegrityEnvironment()
        environment.isJailbreakCheckApplicable = false
        environment.existingFiles = ["/bin/bash"]
        let report = IntegrityInspector(environment: environment).inspect()
        #expect(report.isClean)
        #expect(!report.checksRun.contains(.jailbreak))
    }

    @Test("reports a debugger, but not when the system cannot tell")
    func debugger() {
        var environment = FakeIntegrityEnvironment()
        environment.debugger = true
        #expect(IntegrityInspector(environment: environment).inspect(.debugger).findings == [.debuggerAttached])
        environment.debugger = nil
        #expect(IntegrityInspector(environment: environment).inspect(.debugger).isClean)
    }

    @Test("reports inserted libraries and known hooking tools by file name")
    func injectedLibraries() {
        var environment = FakeIntegrityEnvironment()
        environment.environment = ["DYLD_INSERT_LIBRARIES": "/tmp/hook.dylib"]
        environment.images += [
            "/usr/lib/FridaGadget.dylib",
            "/var/jb/usr/lib/TweakInject/SSLKillSwitch2.dylib",
            "/usr/lib/ellekit/libellekit.dylib",
            "/Applications/frida-tools/notes.txt/Helper.dylib",
        ]
        let report = IntegrityInspector(environment: environment).inspect(.injectedLibraries)
        #expect(report.findings == [
            .insertedLibraries("/tmp/hook.dylib"),
            .suspiciousLibrary(name: "FridaGadget.dylib"),
            .suspiciousLibrary(name: "SSLKillSwitch2.dylib"),
            .suspiciousLibrary(name: "libellekit.dylib"),
        ])
    }

    @Test("ignores an empty DYLD_INSERT_LIBRARIES")
    func emptyInsertedLibraries() {
        var environment = FakeIntegrityEnvironment()
        environment.environment = ["DYLD_INSERT_LIBRARIES": ""]
        #expect(IntegrityInspector(environment: environment).inspect(.injectedLibraries).isClean)
    }

    @Test("reports the simulator and a system proxy")
    func simulatorAndProxy() {
        var environment = FakeIntegrityEnvironment()
        environment.isSimulator = true
        environment.proxy = "10.0.0.5:8888"
        let report = IntegrityInspector(environment: environment).inspect([.simulator, .proxy])
        #expect(report.findings == [.simulator, .systemProxy("10.0.0.5:8888")])
        #expect(report.checksRun == [.simulator, .proxy])
    }

    @Test("runs only the requested checks")
    func selectedChecks() {
        var environment = FakeIntegrityEnvironment()
        environment.isSimulator = true
        environment.debugger = true
        let report = IntegrityInspector(environment: environment).inspect(.debugger)
        #expect(report.findings == [.debuggerAttached])
        #expect(report.checksRun == .debugger)
    }

    @Test("reports encode as JSON for a server")
    func codable() throws {
        var environment = FakeIntegrityEnvironment()
        environment.existingFiles = ["/var/jb"]
        environment.proxy = "proxy.local:3128"
        let report = IntegrityInspector(environment: environment).inspect()
        let decoded = try JSONDecoder().decode(IntegrityReport.self, from: JSONEncoder().encode(report))
        #expect(decoded == report)
        #expect(report.findings.map(\.description) == ["Jailbreak file present: /var/jb", "System proxy: proxy.local:3128"])
    }

    @Test("library names are compared without case and by fragment", arguments: [
        ("FridaGadget.dylib", true), ("frida-agent-64.dylib", true), ("MobileSubstrate.dylib", true),
        ("libsubstitute.dylib", true), ("libhooker.dylib", true), ("Foundation", false), ("libswiftCore.dylib", false),
        ("CydiaSubstrate", true), ("libSubstrateHelper.dylib", false),
    ])
    func libraryNames(name: String, suspicious: Bool) {
        #expect(IntegrityInspector.isSuspiciousLibrary(name) == suspicious)
    }
}

@Suite("Live integrity environment")
struct LiveIntegrityEnvironmentTests {
    let environment = LiveIntegrityEnvironment()

    @Test("reads the debugger flag and the loaded libraries of this process")
    func process() {
        #expect(environment.isDebuggerAttached() != nil)
        let images = environment.loadedImagePaths()
        #expect(images.contains { $0.hasSuffix("/Foundation") || $0.contains("Foundation.framework") })
    }

    @Test("sees files that exist and refuses to write outside the sandbox")
    func fileSystem() {
        #expect(environment.fileExists(atPath: "/"))
        #expect(!environment.fileExists(atPath: "/\(UUID().uuidString)"))
        #expect(!environment.canWrite(inDirectory: "/System"))
    }

    @Test("knows whether it runs in the simulator and skips jailbreak checks there and on macOS")
    func platform() {
        #if targetEnvironment(simulator)
        #expect(environment.isSimulator)
        #else
        #expect(!environment.isSimulator)
        #endif
        #if targetEnvironment(simulator) || os(macOS)
        #expect(!environment.isJailbreakCheckApplicable)
        #endif
    }

    @Test("reads HTTP, HTTPS and automatic proxy settings")
    func proxySettings() {
        #expect(LiveIntegrityEnvironment.proxy(from: [:]) == nil)
        #expect(LiveIntegrityEnvironment.proxy(from: ["HTTPProxy": "10.0.0.5", "HTTPPort": 8888]) == "10.0.0.5:8888")
        #expect(LiveIntegrityEnvironment.proxy(from: ["HTTPProxy": "10.0.0.5"]) == "10.0.0.5")
        #expect(LiveIntegrityEnvironment.proxy(from: ["HTTPEnable": 0, "HTTPProxy": "10.0.0.5"]) == nil)
        #expect(LiveIntegrityEnvironment.proxy(from: ["HTTPEnable": 1, "HTTPProxy": "", "HTTPSEnable": 1, "HTTPSProxy": "secure.proxy", "HTTPSPort": 443]) == "secure.proxy:443")
        #expect(LiveIntegrityEnvironment.proxy(from: ["ProxyAutoConfigEnable": 1, "ProxyAutoConfigURLString": "http://wpad/wpad.dat"]) == "http://wpad/wpad.dat")
        #expect(LiveIntegrityEnvironment.proxy(from: ["ProxyAutoConfigEnable": 0, "ProxyAutoConfigURLString": "http://wpad/wpad.dat"]) == nil)
        #expect(LiveIntegrityEnvironment.proxy(from: ["HTTPEnable": "yes", "HTTPProxy": "10.0.0.5"]) == nil)
    }
}
