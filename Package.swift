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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.25/TrzszSSH.xcframework.zip",
            checksum: "29b60c0015aaa6a70d9c583493a703570197b60bc56dc3de60e0c5ec8dbc8ca4"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.25/VPNTunnel.xcframework.zip",
            checksum: "9b640fa270334591f95512cfab954ec4c0ed8c8e307c792be732ed0551e50e93"
        ),
    ]
)
