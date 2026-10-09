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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.13/TrzszSSH.xcframework.zip",
            checksum: "8c9840311b34d8a0e6678db5166a969a8c8457f1cffcecd070fd6293a7a6f289"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.13/VPNTunnel.xcframework.zip",
            checksum: "a51da50c7fbe3f58b01fc31cebe4088175a08be38eca2f49325789cdb33a8506"
        ),
    ]
)
