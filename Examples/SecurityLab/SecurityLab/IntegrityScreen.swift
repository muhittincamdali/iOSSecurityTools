import iOSSecurityTools
import SwiftUI

struct IntegrityScreen: View {
    @State private var report: IntegrityReport?

    private static let checks: [(IntegrityChecks, String)] = [
        (.jailbreak, "Jailbreak"),
        (.debugger, "Debugger"),
        (.simulator, "Simulator"),
        (.injectedLibraries, "Injected libraries"),
        (.proxy, "System proxy"),
    ]

    var body: some View {
        List {
            if let report {
                Section {
                    ForEach(Self.checks, id: \.1) { check, name in
                        CheckRow(name: name, check: check, report: report)
                    }
                } footer: {
                    Text("Signals from inside the app. Use App Attest when your server needs proof.")
                }
                if !report.isClean {
                    Section("Findings") {
                        ForEach(report.findings, id: \.self) { finding in
                            Text(finding.description)
                                .font(.callout.monospaced())
                        }
                    }
                }
            }
        }
        .toolbar {
            Button("Run again", systemImage: "arrow.clockwise") {
                report = IntegrityInspector().inspect()
            }
        }
        .task {
            report = IntegrityInspector().inspect()
        }
    }
}

private struct CheckRow: View {
    let name: String
    let check: IntegrityChecks
    let report: IntegrityReport

    var body: some View {
        HStack {
            Text(name)
            Spacer()
            status
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var status: some View {
        if !report.checksRun.contains(check) {
            Label("Not applicable", systemImage: "minus.circle")
                .foregroundStyle(.secondary)
        } else if report.hasFindings(in: check) {
            Label("Found", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        } else {
            Label("Clear", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.tint)
        }
    }
}
