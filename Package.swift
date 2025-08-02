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
        .library(name: "Encryption", targets: ["Encryption"]),
        .library(name: "KeyManagement", targets: ["KeyManagement"]),
        .library(name: "Authentication", targets: ["Authentication"]),
        .library(name: "SecureStorage", targets: ["SecureStorage"]),
        .library(name: "SecurityMonitoring", targets: ["SecurityMonitoring"]),
        .library(name: "SecurityUtilities", targets: ["SecurityUtilities"])
    ],
    dependencies: [
        .package(url: "https://github.com/realm/SwiftLint.git", from: "0.54.0")
    ],
    targets: [
        .target(
            name: "iOSSecurityTools",
            dependencies: [
                "Encryption",
                "KeyManagement",
                "Authentication",
                "SecureStorage",
                "SecurityMonitoring",
                "SecurityUtilities"
            ]
        ),
        .target(
            name: "Encryption",
            dependencies: []
        ),
        .target(
            name: "KeyManagement",
            dependencies: []
        ),
        .target(
            name: "Authentication",
            dependencies: []
        ),
        .target(
            name: "SecureStorage",
            dependencies: []
        ),
        .target(
            name: "SecurityMonitoring",
            dependencies: []
        ),
        .target(
            name: "SecurityUtilities",
            dependencies: []
        ),
        .testTarget(
            name: "iOSSecurityToolsTests",
            dependencies: ["iOSSecurityTools"]
        )
    ]
) 