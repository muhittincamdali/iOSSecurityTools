import iOSSecurityTools
import Security
import SwiftUI

/// Connects to a host with pins and shows the decision and the pins the server presented.
struct PinningScreen: View {
    @State private var host = "letsencrypt.org"
    @State private var pinsText = """
        C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=
        diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=
        """
    @State private var outcome: Outcome?
    @State private var isConnecting = false

    struct Outcome {
        var decision: String
        var presented: [String]
    }

    var body: some View {
        Form {
            Section {
                TextField("Host", text: $host)
                    .autocorrectionDisabled()
                TextField("Pins, one per line", text: $pinsText, axis: .vertical)
                    .font(.caption.monospaced())
                    .autocorrectionDisabled()
                Button(isConnecting ? "Connecting…" : "Connect", action: connect)
                    .disabled(isConnecting || host.isEmpty)
            } footer: {
                Text("The default pins are the ISRG Root X1 and X2 keys of Let's Encrypt.")
            }
            if let outcome {
                Section("Result") {
                    Text(outcome.decision)
                }
                Section("Pins in the server's chain") {
                    ForEach(outcome.presented, id: \.self) { pin in
                        Text(pin)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func connect() {
        isConnecting = true
        let host = host
        let pins = pinsText.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        Task {
            let result = await Self.probe(host: host, pins: pins)
            outcome = result
            isConnecting = false
        }
    }

    private static func probe(host: String, pins: [String]) async -> Outcome {
        let policy: PinningPolicy
        do {
            policy = try PinningPolicy([PinnedDomain(host, pins: pins)])
        } catch {
            return Outcome(decision: error.localizedDescription, presented: [])
        }
        let recorder = ChainRecorder(policy: policy)
        let session = URLSession(configuration: .ephemeral, delegate: recorder, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (_, response) = try await session.data(from: URL(string: "https://\(host)/")!)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            return Outcome(decision: "\(recorder.decision) · HTTP \(status)", presented: recorder.presented)
        } catch {
            return Outcome(decision: "\(recorder.decision) · \(error.localizedDescription)", presented: recorder.presented)
        }
    }
}

/// Applies the policy like PinningURLSessionDelegate and also keeps the presented pins.
private final class ChainRecorder: NSObject, URLSessionDelegate, @unchecked Sendable {
    let policy: PinningPolicy
    private(set) var decision = "No TLS challenge"
    private(set) var presented: [String] = []

    init(policy: PinningPolicy) {
        self.policy = policy
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard let trust = challenge.protectionSpace.serverTrust else { return (.performDefaultHandling, nil) }
        let result = policy.evaluate(trust, host: challenge.protectionSpace.host)
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        presented = chain.compactMap { try? SPKIPin(certificate: $0).base64 }
        switch result {
        case .trusted(let pin):
            decision = "Trusted: matched \(pin.base64.prefix(12))…"
            return (.useCredential, URLCredential(trust: trust))
        case .rejected(let failure):
            decision = "Rejected: \(failure.localizedDescription)"
            return (.cancelAuthenticationChallenge, nil)
        case .reportOnly, .notPinned, .pinsExpired:
            decision = "Not enforced"
            return (.performDefaultHandling, nil)
        }
    }
}
