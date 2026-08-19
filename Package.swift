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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.2/TrzszSSH.xcframework.zip",
            checksum: "8290485b258da18bf5895e2ecc1c6c30d8050e6385a187a058af21402c21172c"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.2/VPNTunnel.xcframework.zip",
            checksum: "b998d313f5341db98c2b67217ce51ab46049fcb4c99c53cd6ac8f00fdd18fb0f"
        ),
    ]
)
