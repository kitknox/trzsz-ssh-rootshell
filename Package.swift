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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.27/TrzszSSH.xcframework.zip",
            checksum: "d3c2827df8c41d7f1dbaf92af425c76ab659886fbd316de6f7df9a4a819be226"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.27/VPNTunnel.xcframework.zip",
            checksum: "345c59580f06e379b94055f435c19819f833c560ec399eb79b2f7b13a2a8517a"
        ),
    ]
)
