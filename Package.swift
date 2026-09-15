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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.6/TrzszSSH.xcframework.zip",
            checksum: "b8a47a09efc7d1812a68b07aa639d07b2e1217b604b32206b060b869bb71d990"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.6/VPNTunnel.xcframework.zip",
            checksum: "8cf7da2f6f67cc418fb672aa743dc39c606cf38e5a031f770c70ebe8c4897291"
        ),
    ]
)
