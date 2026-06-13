// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "iOSSecurityTools",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .watchOS(.v8),
        .tvOS(.v15)
    ],
    products: [
        .library(name: "iOSSecurityTools", targets: ["iOSSecurityTools"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "iOSSecurityTools",
            dependencies: [],
            path: "Sources/iOSSecurityTools",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "iOSSecurityToolsTests",
            dependencies: ["iOSSecurityTools"]
        )
    ]
)
