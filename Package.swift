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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.17/TrzszSSH.xcframework.zip",
            checksum: "1cee265bcdc7cec4fe76549a650c5338e467fc50024ec827b65c4ba4ca9c5ce5"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.17/VPNTunnel.xcframework.zip",
            checksum: "7e2462ed9059b02651b06d637fa034e33d352e542436c81029eeb0a609c63bc1"
        ),
    ]
)
