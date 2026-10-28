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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.20/TrzszSSH.xcframework.zip",
            checksum: "0bf2b04cb1a67d310ffd162471d4d1661c30e9299be6d354fd18219009632d1a"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.20/VPNTunnel.xcframework.zip",
            checksum: "81db3b59f2905cec5d49cd66aa7da16b953165557f260040634915fee3b6114f"
        ),
    ]
)
