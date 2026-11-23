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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.29/TrzszSSH.xcframework.zip",
            checksum: "65add0ad401e7446fa9ebd6221218a82cfee724758aaaa5b4b48be15a68e642a"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.29/VPNTunnel.xcframework.zip",
            checksum: "b04f832a0e9ab475ae8472858e14911f8c26fa72d51193dada2535faf2706593"
        ),
    ]
)
