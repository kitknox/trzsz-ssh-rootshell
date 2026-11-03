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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.22/TrzszSSH.xcframework.zip",
            checksum: "31e2cf2e7c725b535c39da6f2f45a4d90a90a6ad8b724624597eb3136ce8042c"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.22/VPNTunnel.xcframework.zip",
            checksum: "fc3c926d4d3a635d4fa5d327e7f0e212035496456d0663b34a633476e826dbc6"
        ),
    ]
)
