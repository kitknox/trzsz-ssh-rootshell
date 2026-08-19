#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOSITORY="kitknox/trzsz-ssh-rootshell"

VERSION="${1:-}"
if [[ "$VERSION" == "-h" || "$VERSION" == "--help" ]]; then
    echo "Usage: $0 <version> [--publish] [--skip-build]"
    exit 0
fi
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [--publish] [--skip-build]" >&2
    exit 1
fi
shift

PUBLISH=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --publish) PUBLISH=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    echo "ERROR: version must be semantic versioning without a leading v" >&2
    exit 1
fi
TAG="v$VERSION"

[[ -x "$PACKAGE_DIR/scripts/build-trzsz-package.sh" ]] || {
    echo "ERROR: package builder is missing: $PACKAGE_DIR/scripts/build-trzsz-package.sh" >&2
    exit 1
}

for command in git ditto swift plutil; do
    command -v "$command" >/dev/null || { echo "ERROR: required command not found: $command" >&2; exit 1; }
done
if [[ "$PUBLISH" == true ]]; then
    command -v gh >/dev/null || { echo "ERROR: required command not found: gh" >&2; exit 1; }
    gh auth status >/dev/null
    for repository in "$REPOSITORY" kitknox/tsshd-rootshell kitknox/kcp-go-rootshell; do
        visibility="$(gh repo view "$repository" --json visibility --jq .visibility)"
        [[ "$visibility" == "PUBLIC" ]] || { echo "ERROR: $repository must be public before publishing" >&2; exit 1; }
    done
fi

STAGE="$PACKAGE_DIR/.build/releases/$VERSION"
mkdir -p "$STAGE"

if [[ "$SKIP_BUILD" == false ]]; then
    BUILD_ARGS=(--trzsz-source "$PACKAGE_DIR" --clean)
    if [[ "$PUBLISH" == true ]]; then
        BUILD_ARGS+=(--dependency-mode remote)
        rm -rf "$STAGE/go-mod-cache"
        GOMODCACHE="$STAGE/go-mod-cache" \
            "$PACKAGE_DIR/scripts/build-trzsz-package.sh" "${BUILD_ARGS[@]}"
    else
        BUILD_ARGS+=(
            --dependency-mode local
            --tsshd-source "$PACKAGE_DIR/../tsshd"
            --kcp-source "$PACKAGE_DIR/../trzsz-kcp-go"
        )
        "$PACKAGE_DIR/scripts/build-trzsz-package.sh" "${BUILD_ARGS[@]}"
    fi
fi

LOCAL_PACKAGE="$PACKAGE_DIR/.build/local-package"
[[ -f "$LOCAL_PACKAGE/Package.swift" ]] || { echo "ERROR: local package was not built" >&2; exit 1; }
TRZSZ_RELATIVE="$(sed -n 's/.*path: "\(Artifacts\/[^\"]*\/TrzszSSH\.xcframework\)".*/\1/p' "$LOCAL_PACKAGE/Package.swift")"
VPN_RELATIVE="$(sed -n 's/.*path: "\(Artifacts\/[^\"]*\/VPNTunnel\.xcframework\)".*/\1/p' "$LOCAL_PACKAGE/Package.swift")"
TRZSZ_XCF="$LOCAL_PACKAGE/$TRZSZ_RELATIVE"
VPN_XCF="$LOCAL_PACKAGE/$VPN_RELATIVE"
[[ -d "$TRZSZ_XCF" && -d "$VPN_XCF" ]] || { echo "ERROR: local package artifacts are incomplete" >&2; exit 1; }

rm -rf "$STAGE/artifacts"
mkdir -p "$STAGE/artifacts"
ditto "$TRZSZ_XCF" "$STAGE/artifacts/TrzszSSH.xcframework"
ditto "$VPN_XCF" "$STAGE/artifacts/VPNTunnel.xcframework"
find "$STAGE/artifacts" -name .DS_Store -delete
find "$STAGE/artifacts" -exec touch -h -t 202001010000 {} +

TRZSZ_ZIP="$STAGE/TrzszSSH.xcframework.zip"
VPN_ZIP="$STAGE/VPNTunnel.xcframework.zip"
rm -f "$TRZSZ_ZIP" "$VPN_ZIP"
COPYFILE_DISABLE=1 ditto -c -k --keepParent "$STAGE/artifacts/TrzszSSH.xcframework" "$TRZSZ_ZIP"
COPYFILE_DISABLE=1 ditto -c -k --keepParent "$STAGE/artifacts/VPNTunnel.xcframework" "$VPN_ZIP"
TRZSZ_CHECKSUM="$(swift package compute-checksum "$TRZSZ_ZIP")"
VPN_CHECKSUM="$(swift package compute-checksum "$VPN_ZIP")"

cat > "$STAGE/Package.swift" <<EOF
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
            url: "https://github.com/$REPOSITORY/releases/download/$TAG/TrzszSSH.xcframework.zip",
            checksum: "$TRZSZ_CHECKSUM"
        ),
        .binaryTarget(
            name: "VPNTunnel",
            url: "https://github.com/$REPOSITORY/releases/download/$TAG/VPNTunnel.xcframework.zip",
            checksum: "$VPN_CHECKSUM"
        ),
    ]
)
EOF

cp "$LOCAL_PACKAGE/provenance.json" "$STAGE/provenance.json"
swift package --package-path "$STAGE" dump-package >/dev/null

echo "Prepared Swift package $VERSION"
echo "  TrzszSSH: $TRZSZ_CHECKSUM"
echo "  VPNTunnel: $VPN_CHECKSUM"
echo "  Candidate: $STAGE/Package.swift"

if [[ "$PUBLISH" == false ]]; then
    echo "No GitHub changes were made. Re-run with --publish after all source repositories are public."
    exit 0
fi

if [[ -n "$(git -C "$PACKAGE_DIR" status --porcelain)" ]]; then
    echo "ERROR: trzsz-ssh repository must be clean before publishing" >&2
    exit 1
fi

BRANCH="$(git -C "$PACKAGE_DIR" branch --show-current)"
[[ -n "$BRANCH" ]] || { echo "ERROR: publish from a branch, not detached HEAD" >&2; exit 1; }
TRZSZ_REVISION="$(git -C "$PACKAGE_DIR" rev-parse HEAD)"
TSSHD_REPLACEMENT="$(awk '$1 == "replace" && $2 == "github.com/trzsz/tsshd" { print $(NF-1), $NF }' "$PACKAGE_DIR/go.mod")"
KCP_REPLACEMENT="$(awk '$1 == "replace" && $2 == "github.com/trzsz/kcp-go/v5" { print $(NF-1), $NF }' "$PACKAGE_DIR/go.mod")"

cat > "$STAGE/release-notes.md" <<EOF
Apple binary package built from:

- trzsz-ssh: $TRZSZ_REVISION
- tsshd replacement: $TSSHD_REPLACEMENT
- kcp-go replacement: $KCP_REPLACEMENT

Build provenance is attached as \`provenance.json\`.
EOF

if ! gh release view "$TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
    gh release create "$TAG" --repo "$REPOSITORY" --draft --target "$BRANCH" \
        --title "TrzszSSH and VPNTunnel $VERSION" --notes-file "$STAGE/release-notes.md"
fi
gh release upload "$TAG" "$TRZSZ_ZIP" "$VPN_ZIP" "$STAGE/provenance.json" \
    --repo "$REPOSITORY" --clobber

cp "$STAGE/Package.swift" "$PACKAGE_DIR/Package.swift"
swift package --package-path "$PACKAGE_DIR" dump-package >/dev/null

if git -C "$PACKAGE_DIR" rev-parse "$TAG" >/dev/null 2>&1; then
    [[ "$(git -C "$PACKAGE_DIR" rev-list -n 1 "$TAG")" == "$(git -C "$PACKAGE_DIR" rev-parse HEAD)" ]] || {
        echo "ERROR: existing $TAG does not point at HEAD" >&2
        exit 1
    }
    git -C "$PACKAGE_DIR" diff --exit-code -- Package.swift >/dev/null || {
        echo "ERROR: candidate manifest differs from the already-tagged release" >&2
        exit 1
    }
else
    git -C "$PACKAGE_DIR" add Package.swift
    git -C "$PACKAGE_DIR" commit -m "Publish Apple binary package $VERSION"
    git -C "$PACKAGE_DIR" tag "$TAG"
fi

git -C "$PACKAGE_DIR" push origin "$BRANCH" "$TAG"
gh release edit "$TAG" --repo "$REPOSITORY" --draft=false
echo "Published $REPOSITORY $TAG"
