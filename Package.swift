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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.1/TrzszSSH.xcframework.zip",
            checksum: "1786112c6c6cf81c424b25e63bea9631f5eb6f27e5fe31b2e1ccab20ef318aaa"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.1/VPNTunnel.xcframework.zip",
            checksum: "4f26bd4357682307aff059916353a789bc4c407ae132a2b4e62fb95de87b5550"
        ),
    ]
)
