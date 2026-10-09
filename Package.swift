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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.14/TrzszSSH.xcframework.zip",
            checksum: "edad583e1df48f1cd55331d4edebb259487f2347861d491f5149c3cf342b1153"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.14/VPNTunnel.xcframework.zip",
            checksum: "7b8b510d2b413d650b03d74c568b7ff78746465582b4040b7b1ea024efa972c9"
        ),
    ]
)
