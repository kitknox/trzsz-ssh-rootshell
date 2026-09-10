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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.3/TrzszSSH.xcframework.zip",
            checksum: "075c09b7a187c2d39109d58b8cf081dce80d156102c4db4ecbf5a731deed1aec"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.3/VPNTunnel.xcframework.zip",
            checksum: "b3b6f22e06a073554ce647b2fffd426cc098a74a9ff1f6e5e7093066d47698f7"
        ),
    ]
)
