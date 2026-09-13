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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.4/TrzszSSH.xcframework.zip",
            checksum: "194c1d1d4702cf26ab0af7bcdce3615454d4eb72ac5ca37f027be04cc864a253"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.4/VPNTunnel.xcframework.zip",
            checksum: "e812684aae4669cd48ae0827798cd4a8fc8d23ded220b8c2bf18162b220d4fdc"
        ),
    ]
)
