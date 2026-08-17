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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.0/TrzszSSH.xcframework.zip",
            checksum: "4716e6213bd8f8616e21bd6a9d9ebfa69455a6e4e2e4ba5349dfe29a9b95ec9e"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.0/VPNTunnel.xcframework.zip",
            checksum: "5dfe1686a340e141fd61dfa6393670e4a3bf919f044858ca46c0eb4cdd5375a3"
        ),
    ]
)
