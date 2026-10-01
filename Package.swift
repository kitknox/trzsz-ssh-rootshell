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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.7/TrzszSSH.xcframework.zip",
            checksum: "ee8a872c18d9f098548fbf0afb5907f8b48ca4d623b2b28249265367e797c5bd"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.7/VPNTunnel.xcframework.zip",
            checksum: "ccec77f5c5fecae6e9228ec1982e809a2ad383624f09f5366f515d9d7b48aecb"
        ),
    ]
)
