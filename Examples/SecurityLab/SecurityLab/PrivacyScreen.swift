import iOSSecurityTools
import SwiftUI

/// A card details view behind a privacy shield. The toggle shows the shield as the app switcher
/// would, by giving the modifier a background scene phase.
struct PrivacyScreen: View {
    @Environment(\.scenePhase) private var phase
    @State private var previewShield = LaunchOptions.isDemo
    @State private var screenshots = 0

    var body: some View {
        VStack(spacing: 20) {
            CardDetails()
                .privacyShield()
                .environment(\.scenePhase, previewShield ? .background : phase)
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .frame(height: 200)

            Toggle("Preview the app switcher shield", isOn: $previewShield)

            Text("Recording the screen or mirroring it with AirPlay also shows the shield.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            if screenshots > 0 {
                Text("Screenshots taken: \(screenshots)")
                    .font(.footnote)
            }
            Spacer()
        }
        .padding()
        .onScreenshot { screenshots += 1 }
    }
}

private struct CardDetails: View {
    var body: some View {
        ZStack(alignment: .topLeading) {
            LinearGradient(colors: [Color(red: 0.0, green: 0.44, blue: 0.89), Color(red: 0.04, green: 0.17, blue: 0.32)], startPoint: .topLeading, endPoint: .bottomTrailing)
            VStack(alignment: .leading, spacing: 12) {
                Text("Debit card")
                    .font(.headline)
                Spacer()
                Text("4242 4242 4242 4242")
                    .font(.title2.monospaced())
                HStack {
                    Text("Expires 09/29")
                    Spacer()
                    Text("CVC 123")
                }
                .font(.callout.monospaced())
            }
            .foregroundStyle(.white)
            .padding(20)
        }
    }
}
