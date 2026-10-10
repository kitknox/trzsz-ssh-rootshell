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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.16/TrzszSSH.xcframework.zip",
            checksum: "a0b9219ea434cae97e3c8602c35b8bbb5656981183f292768bb5626cd1eff0df"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.16/VPNTunnel.xcframework.zip",
            checksum: "95950dbc418d3ab34f2cb76dd1856d40887d85d24887355b324b2928a4c0dc53"
        ),
    ]
)
