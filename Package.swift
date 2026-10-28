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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.21/TrzszSSH.xcframework.zip",
            checksum: "8bcd8d1b0afa93dac791b35482d2813a6a63e3511e3b3e739b25edbc1c02992f"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.21/VPNTunnel.xcframework.zip",
            checksum: "0a371cf91cb6489f82afe13adc050a485ef71a9ee02d53b0d8d3c4b7c5a871e3"
        ),
    ]
)
