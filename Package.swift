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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.23/TrzszSSH.xcframework.zip",
            checksum: "d498d9e21fa2bb1ca692f228c645be67d52aa9d332774dbb5bcfeef5ae86f3c4"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.23/VPNTunnel.xcframework.zip",
            checksum: "d42cf5d2b610a0e495197e3af761dd5c351e54f9ef31267217c3957fe076823a"
        ),
    ]
)
