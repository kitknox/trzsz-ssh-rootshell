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
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.9/TrzszSSH.xcframework.zip",
            checksum: "c01e14d72ea4f9efe5e2414449965aba379be9a714db90414dc84f6ccb70cd78"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/kitknox/trzsz-ssh-rootshell/releases/download/v0.2.9/VPNTunnel.xcframework.zip",
            checksum: "12acf75bf505df6d7d8d6e24ffdd7d22380529931db1ff4a2255d67a1b27255f"
        ),
    ]
)
