// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "trzsz-ssh-rootshell",
    platforms: [
        .iOS("18.0"),
        .macCatalyst("18.0"),
        .macOS("15.0"),
        .visionOS("26.0"),
    ],
    products: [
        .library(name: "TrzszSSH", targets: ["TrzszSSH"]),
        .library(name: "VPNTunnel", targets: ["VPNTunnel"]),
    ],
    targets: [
        .binaryTarget(
            name: "TrzszSSH",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.8/TrzszSSH.xcframework.zip",
            checksum: "ba9a89c1350f1500709aa6165b224e4125fd994d67acc6232c771754f95fe6d7"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.8/VPNTunnel.xcframework.zip",
            checksum: "2ddd9f7a865175e8f6331e83822882cca7ef6278e8ac938d06b3e1642082831c"
        ),
    ]
)
