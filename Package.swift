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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.24/TrzszSSH.xcframework.zip",
            checksum: "aca7cec3634cc6f882a8b920cd717b15c148f26fac1ac556ca110cd669ffd1a5"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.24/VPNTunnel.xcframework.zip",
            checksum: "6dab350c4b73d27f5d6429a89386eaa94adda4b7e8cc03a6c879890371d67a5f"
        ),
    ]
)
