// swift-tools-version: 6.0
// El núcleo de Túnel para Swift. `TunelCoreFFI.xcframework` y `Sources/TunelCore/tunel_mobile.swift`
// los genera scripts/compilar-ios.sh: no se editan a mano ni se guardan en git.
import PackageDescription

let package = Package(
    name: "TunelCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "TunelCore", targets: ["TunelCore"]),
    ],
    targets: [
        .binaryTarget(name: "tunel_mobileFFI", path: "TunelCoreFFI.xcframework"),
        .target(
            name: "TunelCore",
            dependencies: ["tunel_mobileFFI"],
            // El código generado aún no declara todo lo que pide la concurrencia estricta.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(name: "TunelCoreTests", dependencies: ["TunelCore"]),
    ]
)
