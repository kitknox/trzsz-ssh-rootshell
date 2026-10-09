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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.15/TrzszSSH.xcframework.zip",
            checksum: "141b6cc5cf12fa4c0d7f4516d63c640e5d6dd9cd19c7cec2f875c50a37a648cc"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.15/VPNTunnel.xcframework.zip",
            checksum: "4581edd383390195031d0762a5199ef32071211613b8e938de76f5a07bf9f365"
        ),
    ]
)
