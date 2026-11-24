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
        .library(name: "TsshKit", targets: ["TsshKit"]),
    ],
    targets: [
        .binaryTarget(
            name: "TrzszSSH",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.30/TrzszSSH.xcframework.zip",
            checksum: "734ae8d283ec98af3f5575536c49303f030c15efbe5bd5500a5022fb7f5debc5"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.30/VPNTunnel.xcframework.zip",
            checksum: "8a14c586c7aeed5170594a9a7f9c20333cdc307f589025701cb2335d38382eea"
        ),
        .binaryTarget(
            name: "TsshKit",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.30/TsshKit.xcframework.zip",
            checksum: "db62888c3ea869395b6a29bd3a2013436e52f9d199f499bcfb88593dbc30fafa"
        ),
    ]
)
