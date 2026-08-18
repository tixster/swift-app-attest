// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "swift-app-attest",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .macCatalyst(.v14),
        .tvOS(.v15),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "AppAttestClient", targets: ["AppAttestClient"]),
        .library(name: "AppAttestServer", targets: ["AppAttestServer"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "AppAttestCore"
        ),
        .target(
            name: "AppAttestClient",
            dependencies: ["AppAttestCore"]
        ),
        .target(
            name: "AppAttestServer",
            dependencies: [
                "AppAttestCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .testTarget(
            name: "AppAttestCoreTests",
            dependencies: ["AppAttestCore"]
        ),
        .testTarget(
            name: "AppAttestClientTests",
            dependencies: ["AppAttestClient"]
        ),
        .testTarget(
            name: "AppAttestServerTests",
            dependencies: [
                "AppAttestServer",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
