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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.12/TrzszSSH.xcframework.zip",
            checksum: "ac0717a06a92b437f4313db601159696dd9620d9fc53644af7de9198396a333f"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.12/VPNTunnel.xcframework.zip",
            checksum: "f78d78e8f3fcac31eff6c3e631b75e057ada2b97164b6945a49c61ebf1880f01"
        ),
    ]
)
