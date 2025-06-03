// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Noise",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .visionOS(.v1),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "Noise",
            targets: ["Noise"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"4.0.0")
    ],
    targets: [
        .target(
            name: "Noise",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(
            name: "NoiseTests",
            dependencies: ["Noise"]
        ),
    ],
    swiftLanguageModes: [.v6]
)