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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.5/TrzszSSH.xcframework.zip",
            checksum: "c6cd6b058fabee43b3018ccd1dafe9a49c6bb4d561eda502af98c17e3122b990"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.5/VPNTunnel.xcframework.zip",
            checksum: "22551615b1446df1a742b88017f7814b16b14164372e5abda7b09e59b69bd324"
        ),
    ]
)
