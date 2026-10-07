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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.11/TrzszSSH.xcframework.zip",
            checksum: "13a7fdf4096f3707e683c59e9227f05d6fd8391d1e9dbd100370ae911270df71"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.11/VPNTunnel.xcframework.zip",
            checksum: "b16137fc27cb836d3aa95e014b164833867ca123729613e8245d3b75e30ba117"
        ),
    ]
)
