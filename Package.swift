// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "SwiftBottle",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .tvOS(.v14),
        .watchOS(.v7)
    ],
    products: [
        .library(name: "SwiftBottle", targets: ["SwiftBottle"])
    ],
    dependencies: [
        .package(url: "https://github.com/valpackett/SwiftCBOR.git", from: "0.4.7")
    ],
    targets: [
        .target(
            name: "SwiftBottle",
            dependencies: ["SwiftCBOR"]
        ),
        .testTarget(
            name: "SwiftBottleTests",
            dependencies: ["SwiftBottle"]
        )
    ]
)
