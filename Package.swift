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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.26/TrzszSSH.xcframework.zip",
            checksum: "6f28bc9fdfbc79ebe90b70f62902793f7be767c4053fd110c47fa19aa2e6ccfe"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.26/VPNTunnel.xcframework.zip",
            checksum: "1e19216232ae86d5ff8dba45eafdd1b120c51dde92a441a4c8a5731642568430"
        ),
    ]
)
