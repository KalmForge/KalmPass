// swift-tools-version: 5.9
import PackageDescription

// KalmVaultCore holds the storage and decryption shared with the AutoFill
// extension, which compiles those files directly. It has no Capacitor
// dependency for that reason.
let package = Package(
    name: "KalmVault",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "KalmVault",
            targets: ["KalmVaultPlugin"])
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "8.0.0")
    ],
    targets: [
        .target(
            name: "KalmVaultCore",
            path: "ios/Sources/KalmVaultCore"),
        .target(
            name: "KalmVaultPlugin",
            dependencies: [
                "KalmVaultCore",
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm")
            ],
            path: "ios/Sources/KalmVaultPlugin")
    ]
)
