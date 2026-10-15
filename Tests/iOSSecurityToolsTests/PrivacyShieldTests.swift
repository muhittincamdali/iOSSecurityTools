#if canImport(SwiftUI)
import SwiftUI
import Testing
@testable import iOSSecurityTools

@Suite("PrivacyShield")
struct PrivacyShieldTests {
    @Test("covers the view in the states its conditions name", arguments: [
        (PrivacyShieldConditions.all, ScenePhase.active, false, false),
        (.all, .inactive, false, true),
        (.all, .background, false, true),
        (.all, .active, true, true),
        (.inactive, .active, true, false),
        (.inactive, .background, false, true),
        (.screenCaptured, .background, false, false),
        (.screenCaptured, .active, true, true),
        (PrivacyShieldConditions(), .background, true, false),
    ] as [(PrivacyShieldConditions, ScenePhase, Bool, Bool)])
    func conditions(conditions: PrivacyShieldConditions, phase: ScenePhase, isCaptured: Bool, expected: Bool) {
        #expect(PrivacyShieldConditions.isShielded(conditions, phase: phase, isCaptured: isCaptured) == expected)
    }

    @MainActor
    @Test("the shield is opaque: none of the content shows through")
    func shieldIsOpaque() throws {
        // Render a solid red view under the default shield in the inactive state and check that
        // no red pixel is left.
        let view = Color(red: 1, green: 0, blue: 0)
            .frame(width: 120, height: 120)
            .modifier(PrivacyShieldModifier(conditions: .all) { DefaultPrivacyShield() })
            .environment(\.scenePhase, .background)
        let renderer = ImageRenderer(content: view)
        renderer.scale = 1
        let image = try #require(renderer.cgImage)
        let pixels = try #require(RGBAPixels(image))
        #expect(pixels.count == 120 * 120)
        #expect(!pixels.contains { $0.red > 200 && $0.green < 60 && $0.blue < 60 })
    }

    @MainActor
    @Test("an active scene shows the content")
    func activeShowsContent() throws {
        let view = Color(red: 1, green: 0, blue: 0)
            .frame(width: 40, height: 40)
            .modifier(PrivacyShieldModifier(conditions: .all) { DefaultPrivacyShield() })
            .environment(\.scenePhase, .active)
        let renderer = ImageRenderer(content: view)
        renderer.scale = 1
        let image = try #require(renderer.cgImage)
        let pixels = try #require(RGBAPixels(image))
        #expect(pixels.allSatisfy { $0.red > 200 && $0.green < 60 && $0.blue < 60 })
    }
}

/// The pixels of an image in 8-bit RGBA.
struct RGBAPixels: RandomAccessCollection {
    struct Pixel { let red, green, blue, alpha: UInt8 }
    private let bytes: [UInt8]

    init?(_ image: CGImage) {
        let width = image.width
        let height = image.height
        var bytes = [UInt8](repeating: 0, count: width * height * 4)
        let drawn = bytes.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(
                data: buffer.baseAddress, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width * 4,
                space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            ) else { return false }
            context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }
        guard drawn else { return nil }
        self.bytes = bytes
    }

    var startIndex: Int { 0 }
    var endIndex: Int { bytes.count / 4 }
    subscript(index: Int) -> Pixel {
        Pixel(red: bytes[index * 4], green: bytes[index * 4 + 1], blue: bytes[index * 4 + 2], alpha: bytes[index * 4 + 3])
    }
}
#endif
