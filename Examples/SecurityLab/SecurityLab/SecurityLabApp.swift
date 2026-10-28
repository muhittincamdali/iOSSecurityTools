import SwiftUI

@main
struct SecurityLabApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
                .tint(.blue)
        }
    }
}

/// The demo screens. `-screen <case>` on the command line opens one directly, and `-demo YES`
/// fills it with sample input; scripts/capture-example-screens.sh uses both.
enum Screen: String, CaseIterable, Identifiable, Hashable {
    case quickStart, integrity, vault, messages, codes, redaction, privacy, pinning

    var id: Self { self }

    var title: String {
        switch self {
        case .quickStart: "Quick start"
        case .integrity: "Integrity"
        case .vault: "Vault"
        case .messages: "Messages"
        case .codes: "One-time codes"
        case .redaction: "Redaction"
        case .privacy: "Privacy shield"
        case .pinning: "Certificate pinning"
        }
    }

    var subtitle: String {
        switch self {
        case .quickStart: "The README quick start"
        case .integrity: "Jailbreak, debugger, hooks, proxy"
        case .vault: "Keychain, encryption, PIN hash"
        case .messages: "End-to-end encryption, signatures, tokens"
        case .codes: "TOTP from an otpauth URI"
        case .redaction: "Hide secrets in log lines"
        case .privacy: "App switcher and screen recording"
        case .pinning: "Pin a server's public keys"
        }
    }

    var symbol: String {
        switch self {
        case .quickStart: "sparkles"
        case .integrity: "checkmark.shield"
        case .vault: "lock.rectangle.stack"
        case .messages: "envelope.badge.shield.half.filled"
        case .codes: "number.square"
        case .redaction: "eye.slash"
        case .privacy: "rectangle.dashed.badge.record"
        case .pinning: "pin"
        }
    }

    @MainActor @ViewBuilder
    var destination: some View {
        switch self {
        case .quickStart: ContentView()
        case .integrity: IntegrityScreen()
        case .vault: VaultScreen()
        case .messages: MessagesScreen()
        case .codes: CodesScreen()
        case .redaction: RedactionScreen()
        case .privacy: PrivacyScreen()
        case .pinning: PinningScreen()
        }
    }
}

enum LaunchOptions {
    static var screen: Screen? { UserDefaults.standard.string(forKey: "screen").flatMap(Screen.init(rawValue:)) }
    static var isDemo: Bool { UserDefaults.standard.bool(forKey: "demo") }
}

struct RootView: View {
    @State private var path: [Screen] = LaunchOptions.screen.map { [$0] } ?? []

    var body: some View {
        NavigationStack(path: $path) {
            List(Screen.allCases) { screen in
                NavigationLink(value: screen) {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(screen.title)
                            Text(screen.subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: screen.symbol)
                    }
                }
            }
            .navigationTitle("Security Lab")
            .navigationDestination(for: Screen.self) { screen in
                screen.destination
                    .navigationTitle(screen.title)
            }
        }
    }
}
