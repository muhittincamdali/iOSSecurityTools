#if canImport(SwiftUI)
import SwiftUI
#if canImport(UIKit) && !os(watchOS)
import UIKit
#endif

/// When ``SwiftUICore/View/privacyShield(when:)`` covers a view.
public struct PrivacyShieldConditions: OptionSet, Sendable, Hashable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// While the scene is inactive or in the background. This covers the snapshot that the app
    /// switcher shows, which is taken after the app leaves the foreground.
    public static let inactive = PrivacyShieldConditions(rawValue: 1 << 0)
    /// While the screen is recorded, mirrored with AirPlay or shared (iOS, iPadOS, tvOS and
    /// visionOS 17 or later; ignored elsewhere).
    public static let screenCaptured = PrivacyShieldConditions(rawValue: 1 << 1)
    /// Both conditions.
    public static let all: PrivacyShieldConditions = [.inactive, .screenCaptured]

    /// Whether a view is covered in a given state.
    static func isShielded(_ conditions: PrivacyShieldConditions, phase: ScenePhase, isCaptured: Bool) -> Bool {
        (conditions.contains(.inactive) && phase != .active) || (conditions.contains(.screenCaptured) && isCaptured)
    }
}

extension View {
    /// Covers the view with an opaque shield while the app is in the app switcher or the screen is
    /// recorded, so card numbers or messages do not end up in a snapshot or a recording.
    ///
    /// ```swift
    /// CardDetailsView(card: card)
    ///     .privacyShield()
    /// ```
    ///
    /// The shield hides the content from screen recordings and AirPlay mirroring, which the system
    /// reports. It cannot stop a screenshot: iOS reports a screenshot only after it is taken (see
    /// ``SwiftUICore/View/onScreenshot(perform:)``).
    ///
    /// - Parameter conditions: When to cover the view; both conditions by default.
    public func privacyShield(when conditions: PrivacyShieldConditions = .all) -> some View {
        modifier(PrivacyShieldModifier(conditions: conditions) { DefaultPrivacyShield() })
    }

    /// Covers the view with your own shield while the app is in the app switcher or the screen is
    /// recorded.
    ///
    /// - Parameters:
    ///   - conditions: When to cover the view.
    ///   - shield: The view shown instead. Make it opaque; a blur can leave text readable.
    public func privacyShield<Shield: View>(
        when conditions: PrivacyShieldConditions = .all,
        @ViewBuilder shield: @escaping () -> Shield
    ) -> some View {
        modifier(PrivacyShieldModifier(conditions: conditions, shield: shield))
    }

    /// Runs an action after the user takes a screenshot (iOS, iPadOS and visionOS; never called
    /// elsewhere).
    ///
    /// The screenshot already exists when the action runs. Use it to tell the user that the
    /// screen held sensitive data, or to record the event.
    public func onScreenshot(perform action: @escaping @MainActor () -> Void) -> some View {
        #if os(iOS) || os(visionOS)
        onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            action()
        }
        #else
        self
        #endif
    }
}

struct PrivacyShieldModifier<Shield: View>: ViewModifier {
    let conditions: PrivacyShieldConditions
    let shield: () -> Shield
    @Environment(\.scenePhase) private var phase
    @State private var isCaptured = false

    func body(content: Content) -> some View {
        let isShielded = PrivacyShieldConditions.isShielded(conditions, phase: phase, isCaptured: isCaptured)
        content
            .accessibilityHidden(isShielded)
            .overlay {
                if isShielded {
                    shield()
                }
            }
            .background {
                #if canImport(UIKit) && !os(watchOS)
                if conditions.contains(.screenCaptured) {
                    CaptureStateReader(isCaptured: $isCaptured)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
                #endif
            }
    }
}

/// The shield used when none is given: the system background with a lock symbol.
struct DefaultPrivacyShield: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
            Image(systemName: "lock.fill")
                .font(.largeTitle)
                .foregroundStyle(.tint)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Content hidden"))
    }
}

#if canImport(UIKit) && !os(watchOS)
/// Reports `UITraitCollection.sceneCaptureState` of the window the view is in.
private struct CaptureStateReader: UIViewRepresentable {
    @Binding var isCaptured: Bool

    func makeUIView(context: Context) -> CaptureStateView {
        let view = CaptureStateView()
        view.onChange = { isCaptured = $0 }
        return view
    }

    func updateUIView(_ view: CaptureStateView, context: Context) {
        view.onChange = { isCaptured = $0 }
    }
}

private final class CaptureStateView: UIView {
    var onChange: ((Bool) -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        registerForTraitChanges([UITraitSceneCaptureState.self]) { (view: CaptureStateView, _: UITraitCollection) in
            view.report()
        }
    }

    required init?(coder: NSCoder) { nil }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        report()
    }

    private func report() {
        let captured = traitCollection.sceneCaptureState == .active
        DispatchQueue.main.async { [onChange] in onChange?(captured) }
    }
}
#endif
#endif
