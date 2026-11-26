// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ForensicRecoverIOS",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "ForensicRecoverIOS", targets: ["ForensicRecoverIOS"]),
    ],
    targets: [
        .target(
            name: "ForensicRecoverIOS",
            path: "Sources/ForensicRecoverIOS"
        )
    ]
)
