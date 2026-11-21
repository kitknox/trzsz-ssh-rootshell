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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.28/TrzszSSH.xcframework.zip",
            checksum: "d07679165216b73a3cb3645f8fcbcaa3bac6b193f85f11291f376edb6fbbac2b"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.28/VPNTunnel.xcframework.zip",
            checksum: "46d7dac67688304923e219bbc984d392d2eef96a3ec6070562fc2db1a3006caa"
        ),
    ]
)
