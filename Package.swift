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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.18/TrzszSSH.xcframework.zip",
            checksum: "02a95cb5c9d21b477338737c5160a49a3fc5ae05fa5f3bc6eceef607eecaa422"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.18/VPNTunnel.xcframework.zip",
            checksum: "7d7d72b62dfd70e6bfa9f349dc92b32289820f67acae2af1a90a5ecf71c688c8"
        ),
    ]
)
