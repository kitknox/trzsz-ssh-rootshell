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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.10/TrzszSSH.xcframework.zip",
            checksum: "7b3414b582ff1fda2cddbeb2a6e895acc00d30c8df716c91fa8f2d545a988074"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.10/VPNTunnel.xcframework.zip",
            checksum: "54fb4f2a0de50696186cc0bbb022372353674b51ccbab4a0d96ec4bf62eb7985"
        ),
    ]
)
