// swift-tools-version: 6.0
// StreamenCloudKit — the Swift client for Streamen Cloud: key derivation, the record
// envelope, canonical payloads, HPKE pairing, and a tiny async HTTP/WebSocket
// client. Foundation + CryptoKit only: the Streamen app consumes this as a local
// package, so it must never add a dependency to the app graph.

import PackageDescription

let package = Package(
    name: "StreamenCloudKit",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
        .tvOS(.v18),
        .visionOS(.v2),
    ],
    products: [
        // Automatic library type, like StreamenRecorderKit: Xcode links it statically into the app.
        .library(name: "StreamenCloudKit", targets: ["StreamenCloudKit"]),
    ],
    targets: [
        .target(
            name: "StreamenCloudKit",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "StreamenCloudKitTests",
            dependencies: ["StreamenCloudKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
