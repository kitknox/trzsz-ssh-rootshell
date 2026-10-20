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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.19/TrzszSSH.xcframework.zip",
            checksum: "7778f2d2b3926ddfb8a521a2ccd4c5133ffe8d895e4cb0811a9b1db37e493327"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.19/VPNTunnel.xcframework.zip",
            checksum: "6a4e228b7b6330e3ebf9c53417d1c9ef73fb88566c053f84545754b195c22c52"
        ),
    ]
)
