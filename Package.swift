// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "iOSSecurityTools",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .tvOS(.v17),
        .watchOS(.v10),
        .visionOS(.v1)
    ],
    products: [
        .library(name: "iOSSecurityTools", targets: ["iOSSecurityTools"])
    ],
    targets: [
        .target(
            name: "iOSSecurityTools",
            path: "Sources/iOSSecurityTools"
        ),
        .testTarget(
            name: "iOSSecurityToolsTests",
            dependencies: ["iOSSecurityTools"],
            resources: [.copy("Resources/ReviewProbes.jsonl")]
        )
    ]
)
