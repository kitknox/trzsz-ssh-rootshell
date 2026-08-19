#!/bin/bash
set -euo pipefail

# Build TrzszSSH and VPNTunnel together and expose them as an ignored local
# Swift package. Publishing uses the same artifacts after a clean remote-mode
# rebuild.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TRZSZ_SSH_DIR="${TRZSZ_SSH_DIR:-}"
TSSHD_DIR="${TSSHD_DIR:-}"
KCP_GO_DIR="${KCP_GO_DIR:-}"
DEPENDENCY_MODE="${DEPENDENCY_MODE:-local}"
CLEAN=false
VERBOSE=false

usage() {
    echo "Usage: $0 [--trzsz-source <path>] [--tsshd-source <path>] [--kcp-source <path>]"
    echo "          [--dependency-mode local|remote] [--clean] [--verbose]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trzsz-source) TRZSZ_SSH_DIR="${2:-}"; shift 2 ;;
        --tsshd-source) TSSHD_DIR="${2:-}"; shift 2 ;;
        --kcp-source) KCP_GO_DIR="${2:-}"; shift 2 ;;
        --dependency-mode) DEPENDENCY_MODE="${2:-}"; shift 2 ;;
        --clean) CLEAN=true; shift ;;
        --verbose|-v) VERBOSE=true; shift ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 1 ;;
    esac
done

case "$DEPENDENCY_MODE" in local|remote) ;; *) echo "ERROR: dependency mode must be local or remote" >&2; exit 1 ;; esac

source "$SCRIPT_DIR/tssh-build-common.sh"
tssh_resolve_sources "$PROJECT_DIR"

OUTPUT_DIR="$PROJECT_DIR/.build/trzsz-package-frameworks"
COMMON_ARGS=(--trzsz-source "$TRZSZ_SSH_DIR" --dependency-mode "$DEPENDENCY_MODE" --output-dir "$OUTPUT_DIR")
if [[ "$DEPENDENCY_MODE" == "local" ]]; then
    COMMON_ARGS+=(--tsshd-source "$TSSHD_DIR" --kcp-source "$KCP_GO_DIR")
fi
[[ "$CLEAN" == true ]] && COMMON_ARGS+=(--clean)
[[ "$VERBOSE" == true ]] && COMMON_ARGS+=(--verbose)

"$SCRIPT_DIR/build-tssh-framework.sh" "${COMMON_ARGS[@]}"
"$SCRIPT_DIR/build-vpntunnel-framework.sh" "${COMMON_ARGS[@]}"

trzsz_revision="$(git -C "$TRZSZ_SSH_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
if [[ "$DEPENDENCY_MODE" == "local" ]]; then
    tsshd_revision="$(git -C "$TSSHD_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
    kcp_revision="$(git -C "$KCP_GO_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
else
    tsshd_revision="$(awk '$1 == "replace" && $2 == "github.com/trzsz/tsshd" { print $NF }' "$TRZSZ_SSH_DIR/go.mod")"
    kcp_revision="$(awk '$1 == "replace" && $2 == "github.com/trzsz/kcp-go/v5" { print $NF }' "$TRZSZ_SSH_DIR/go.mod")"
fi
build_id="${trzsz_revision}-${tsshd_revision##*-}-${kcp_revision##*-}"

PACKAGE_DIR="$PROJECT_DIR/.build/local-package"
ARTIFACT_DIR="$PACKAGE_DIR/Artifacts/$build_id"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
ditto "$OUTPUT_DIR/TrzszSSH.xcframework" "$ARTIFACT_DIR/TrzszSSH.xcframework"
ditto "$OUTPUT_DIR/VPNTunnel.xcframework" "$ARTIFACT_DIR/VPNTunnel.xcframework"

cat > "$PACKAGE_DIR/Package.swift" <<EOF
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
        .binaryTarget(name: "TrzszSSH", path: "Artifacts/$build_id/TrzszSSH.xcframework"),
        .binaryTarget(name: "VPNTunnel", path: "Artifacts/$build_id/VPNTunnel.xcframework"),
    ]
)
EOF

cat > "$PACKAGE_DIR/provenance.json" <<EOF
{
  "dependencyMode": "$DEPENDENCY_MODE",
  "trzszSSHRevision": "$trzsz_revision",
  "tsshdRevision": "$tsshd_revision",
  "kcpGoRevision": "$kcp_revision",
  "goVersion": "$(go env GOVERSION)",
  "gomobileVersion": "$TSSH_GOMOBILE_VERSION",
  "gobindVersion": "$TSSH_GOBIND_VERSION",
  "xcodeVersion": "$(xcodebuild -version | tr '\n' ' ')"
}
EOF

swift package --package-path "$PACKAGE_DIR" dump-package >/dev/null
echo "Local TrzszSSH/VPNTunnel package ready: $PACKAGE_DIR"
