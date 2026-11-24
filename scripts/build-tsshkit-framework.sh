#!/bin/bash
#
# Build script for TsshKit.xcframework
#
# One dynamic framework holding both iosbridge (tssh and the in-app Tailscale
# engine) and vpntunnel (the VPN extension). The app embeds it once and its
# VPN extension links the same copy, so the Go runtime and every shared Go
# package ship once instead of twice. Slices: iOS, iOS Simulator, visionOS,
# visionOS Simulator. Mac Catalyst and China builds keep static TrzszSSH, and
# the native macOS system extension keeps static VPNTunnel.
#
# Go has no c-shared build mode for ios, so each slice is built as a
# c-archive and relinked into a dylib with clang.
#
# Each run works in a new .build/tsshkit/<run> directory and never deletes
# anything; a previous output is moved into that run directory.
#
# Prerequisites:
#   - Go 1.27.4 (fetched through GOTOOLCHAIN when the host go is older)
#   - Xcode command line tools
#
# Usage:
#   ./scripts/build-tsshkit-framework.sh [options]
#
# Options:
#   --trzsz-source PATH  trzsz-ssh checkout
#   --tsshd-source PATH  tsshd checkout (local dependency mode)
#   --dependency-mode MODE  local or remote (default: local)
#   --output-dir PATH    framework destination
#   --device-only        Build only the iOS device slice
#   --verbose            Show detailed build output
#   --help               Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/tssh-build-common.sh"

# The in-app engine's feature set; it is a superset of the extension's, which
# only adds exit-node code the extension never calls.
TAILSCALE_FEATURES="netstack,dns,useroutes,ipnbus,health,tailnetlock,useexitnode,udptransport,nattraversal"

TRZSZ_SSH_DIR="${TRZSZ_SSH_DIR:-}"
TSSHD_DIR="${TSSHD_DIR:-}"
DEPENDENCY_MODE="${DEPENDENCY_MODE:-local}"
FRAMEWORK_NAME="TsshKit"
BUNDLE_IDENTIFIER="org.trzsz.TsshKit"
OUTPUT_DIR="${TSSH_OUTPUT_DIR:-$PROJECT_DIR/Frameworks}"
MIN_IOS_VERSION="18.0"
MIN_VISIONOS_VERSION="26.0"
DEVICE_ONLY=false
VERBOSE=false

# identifier|sdk|target triple|CFBundleSupportedPlatforms|minimum OS
SLICES=(
    "ios-arm64|iphoneos|arm64-apple-ios${MIN_IOS_VERSION}|iPhoneOS|${MIN_IOS_VERSION}"
    "ios-arm64-simulator|iphonesimulator|arm64-apple-ios${MIN_IOS_VERSION}-simulator|iPhoneSimulator|${MIN_IOS_VERSION}"
    "xros-arm64|xros|arm64-apple-xros${MIN_VISIONOS_VERSION}|XROS|${MIN_VISIONOS_VERSION}"
    "xros-arm64-simulator|xrsimulator|arm64-apple-xros${MIN_VISIONOS_VERSION}-simulator|XRSimulator|${MIN_VISIONOS_VERSION}"
)

usage() {
    echo "Usage: $0 [--trzsz-source <path>] [--tsshd-source <path>]"
    echo "          [--dependency-mode local|remote] [--output-dir <path>]"
    echo "          [--device-only] [--verbose]"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --trzsz-source) TRZSZ_SSH_DIR="${2:-}"; shift 2 ;;
        --tsshd-source) TSSHD_DIR="${2:-}"; shift 2 ;;
        --dependency-mode) DEPENDENCY_MODE="${2:-}"; shift 2 ;;
        --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
        --device-only) DEVICE_ONLY=true; shift ;;
        --verbose|-v) VERBOSE=true; shift ;;
        # Accepted for parity with the other framework scripts; every run is clean.
        --clean) shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

case "$DEPENDENCY_MODE" in
    local|remote) ;;
    *) tssh_error "dependency mode must be local or remote" ;;
esac
tssh_resolve_sources "$PROJECT_DIR"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

if [[ "$DEVICE_ONLY" == "true" ]]; then
    SLICES=("${SLICES[0]}")
fi

RUN_DIR="$PROJECT_DIR/.build/tsshkit/$(date '+%Y%m%d-%H%M%S')-$$"
WORK_DIR="$RUN_DIR/gobind"
mkdir -p "$WORK_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

check_prerequisites() {
    log "Checking prerequisites..."
    tssh_setup_toolchain "$PROJECT_DIR"
    tssh_prepare_build_module "$PROJECT_DIR" "$TRZSZ_SSH_DIR" tsshkit
    tssh_use_app_tailscale "$SCRIPT_DIR/_app-tailscale/mem_ios.go"

    xcode-select -p &> /dev/null || error "Xcode command line tools not installed. Run: xcode-select --install"
    [[ -f "$TRZSZ_SSH_DIR/iosbridge/transport.go" ]] || error "iosbridge package not found in $TRZSZ_SSH_DIR"
    [[ -f "$TRZSZ_SSH_DIR/vpntunnel/bridge.go" ]] || error "vpntunnel package not found in $TRZSZ_SSH_DIR"

    TS_TAGS="$(tssh_tailscale_build_tags "$TAILSCALE_FEATURES")" || error "could not resolve Tailscale feature tags"

    log "  Go version: $(GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" go env GOVERSION)"
    log "  Xcode: $(xcode-select -p)"
    log "  trzsz-ssh: $TRZSZ_SSH_DIR"
    log "  dependencies: $DEPENDENCY_MODE"
    log "  work: $RUN_DIR"
}

generate_bindings() {
    log "Generating binding code for iosbridge and vpntunnel..."
    (
        cd "$TRZSZ_SSH_DIR"
        PATH="$GOPATH/bin:$PATH" "$GOBIND" -lang=go,objc -outdir="$WORK_DIR" -tags=ios \
            ./iosbridge github.com/trzsz/trzsz-ssh/vpntunnel
    )
    tssh_write_generated_module \
        "$WORK_DIR/src/gobind" \
        github.com/trzsz/trzsz-ssh \
        "$TSSH_BUILD_MODULE_DIR" \
        "$TRZSZ_SSH_DIR/go.mod"

    local header
    for header in ref.h Universe.objc.h Iosbridge.objc.h Vpntunnel.objc.h; do
        [[ -f "$WORK_DIR/src/gobind/$header" ]] || error "gobind did not emit $header"
    done

    # Swift references only the binding classes and functions; the Go runtime
    # and cgo glue stay private to the dylib.
    cat > "$RUN_DIR/exports.txt" << 'EOF'
_OBJC_CLASS_$_Iosbridge*
_OBJC_METACLASS_$_Iosbridge*
_OBJC_CLASS_$_Vpntunnel*
_OBJC_METACLASS_$_Vpntunnel*
_OBJC_CLASS_$_Universe*
_OBJC_METACLASS_$_Universe*
_OBJC_CLASS_$_GoSeq*
_OBJC_METACLASS_$_GoSeq*
_Iosbridge*
_Vpntunnel*
_Universe*
EOF
}

write_bundle_files() {
    local framework="$1" platform="$2" minimum_os="$3"

    cp "$WORK_DIR"/src/gobind/{ref.h,Universe.objc.h,Iosbridge.objc.h,Vpntunnel.objc.h} "$framework/Headers/"
    # gobind declares `- (nullable instancetype)init;`, which conflicts with
    # NSObject's nonnull -init; Swift only uses the New...() constructors.
    sed -i '' 's/^- (nullable instancetype)init;/- (nonnull instancetype)init;/' "$framework"/Headers/*.objc.h

    cat > "$framework/Headers/$FRAMEWORK_NAME.h" << 'EOF'
// TsshKit umbrella header
#import "ref.h"
#import "Universe.objc.h"
#import "Iosbridge.objc.h"
#import "Vpntunnel.objc.h"
EOF

    cat > "$framework/Modules/module.modulemap" << EOF
framework module $FRAMEWORK_NAME {
    umbrella header "$FRAMEWORK_NAME.h"
    export *
}
EOF

    cat > "$framework/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_IDENTIFIER</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>$minimum_os</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>$platform</string>
    </array>
</dict>
</plist>
EOF

    # The Go runtime reads file metadata (stat family) and a monotonic clock
    # (mach_absolute_time); both are required-reason APIs.
    cat > "$framework/PrivacyInfo.xcprivacy" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyTrackingDomains</key>
    <array/>
    <key>NSPrivacyCollectedDataTypes</key>
    <array/>
    <key>NSPrivacyAccessedAPITypes</key>
    <array>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>C617.1</string>
            </array>
        </dict>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategorySystemBootTime</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>35F9.1</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
EOF
    plutil -lint "$framework/Info.plist" "$framework/PrivacyInfo.xcprivacy" > /dev/null
}

build_slice() {
    local identifier sdk triple platform minimum_os
    IFS='|' read -r identifier sdk triple platform minimum_os <<< "$1"
    log "Building $identifier ($triple)..."

    local slice_dir="$RUN_DIR/$identifier"
    local framework="$slice_dir/$FRAMEWORK_NAME.framework"
    mkdir -p "$framework/Headers" "$framework/Modules"

    local sdk_path cc
    sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"
    cc="$(xcrun --sdk "$sdk" --find clang)"

    local verbose_flag=()
    [[ "$VERBOSE" == "true" ]] && verbose_flag=(-v)

    (
        cd "$WORK_DIR/src/gobind"
        CGO_ENABLED=1 \
        GOOS=ios \
        GOARCH=arm64 \
        CC="$cc" \
        CGO_CFLAGS="-target $triple -isysroot $sdk_path" \
        CGO_LDFLAGS="-target $triple -isysroot $sdk_path" \
        GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
        go build ${verbose_flag[@]+"${verbose_flag[@]}"} -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" \
            -tags="ios,$TS_TAGS" -o "$slice_dir/libgo.a" .
    )

    log "  Relinking as a dynamic framework..."
    "$cc" -target "$triple" -isysroot "$sdk_path" \
        -dynamiclib -fapplication-extension \
        -Wl,-all_load "$slice_dir/libgo.a" \
        -framework Foundation -framework CoreFoundation -framework Security \
        -install_name "@rpath/$FRAMEWORK_NAME.framework/$FRAMEWORK_NAME" \
        -compatibility_version 1 -current_version 1 \
        -Wl,-exported_symbols_list,"$RUN_DIR/exports.txt" \
        -Wl,-x \
        -o "$framework/$FRAMEWORK_NAME"

    write_bundle_files "$framework" "$platform" "$minimum_os"
    verify_slice "$identifier" "$framework" "$minimum_os" "$sdk" "$triple"
    FRAMEWORK_ARGS+=(-framework "$framework")
}

verify_slice() {
    local identifier="$1" framework="$2" minimum_os="$3" sdk="$4" triple="$5"
    local binary="$framework/$FRAMEWORK_NAME"

    file "$binary" | grep -q 'dynamically linked shared library arm64' || error "$identifier is not an arm64 dylib"
    otool -hv "$binary" | grep -q 'APP_EXTENSION_SAFE' || error "$identifier is not marked app-extension safe"
    otool -D "$binary" | grep -qx "@rpath/$FRAMEWORK_NAME.framework/$FRAMEWORK_NAME" || error "$identifier has the wrong install name"

    local minimum_versions
    minimum_versions="$(otool -l "$binary" | awk '$1 == "minos" { print $2 }' | sort -u)"
    [[ "$minimum_versions" == "$minimum_os" ]] || error "$identifier minimum OS is '$minimum_versions', expected $minimum_os"

    # Every class and function the headers declare must be exported.
    local exported missing=0 name
    exported="$(nm -gU "$binary" | awk '{ print $NF }')"
    while IFS= read -r name; do
        grep -qx "_OBJC_CLASS_\$_$name" <<< "$exported" || { echo "  missing class export: $name" >&2; missing=1; }
    done < <(sed -n 's/^@interface \([A-Za-z_][A-Za-z0-9_]*\) .*/\1/p' "$framework"/Headers/*.h | sort -u)
    while IFS= read -r name; do
        grep -qx "_$name" <<< "$exported" || { echo "  missing symbol export: $name" >&2; missing=1; }
    done < <(sed -n 's/^FOUNDATION_EXPORT.*[ *]\([A-Za-z_][A-Za-z0-9_]*\) *[(;].*/\1/p' "$framework"/Headers/*.h | sort -u)
    [[ "$missing" -eq 0 ]] || error "$identifier does not export every declared binding"

    # Go keeps function names in pclntab even when stripped.
    local marker
    for marker in tailscale.com/wgengine.NewUserspaceEngine github.com/trzsz/trzsz-ssh/vpntunnel. github.com/trzsz/trzsz-ssh/iosbridge. ; do
        LC_ALL=C grep -a -q "$marker" "$binary" || error "$identifier is missing $marker"
    done
    # The runtime pool-ceiling switch only exists in the replacement mem_ios.go.
    LC_ALL=C grep -a -q '\.appex/' "$binary" || error "$identifier was not built with scripts/_app-tailscale/mem_ios.go"

    if [[ "$DEPENDENCY_MODE" == "remote" ]] && strings "$binary" | grep -Eq '/Users/|/home/[^/]+/'; then
        strings "$binary" | grep -E -m 10 '/Users/|/home/[^/]+' >&2 || true
        error "build-machine paths remain in $identifier"
    fi

    printf 'import %s\n_ = IosbridgeNewTransportConfig\n' "$FRAMEWORK_NAME" > "$RUN_DIR/$identifier-smoke.swift"
    xcrun --sdk "$sdk" swiftc -target "$triple" \
        -module-cache-path "$RUN_DIR/module-cache" \
        -F "$(dirname "$framework")" \
        -typecheck "$RUN_DIR/$identifier-smoke.swift" \
        || error "$identifier does not import from Swift"

    log "  ✓ $identifier ($(du -h "$binary" | cut -f1))"
}

assemble_xcframework() {
    log "Creating $FRAMEWORK_NAME.xcframework..."
    local xcframework="$RUN_DIR/$FRAMEWORK_NAME.xcframework"
    # create-xcframework can crash Xcode's build service from inside gobind sources.
    (cd "$RUN_DIR" && xcodebuild -create-xcframework "${FRAMEWORK_ARGS[@]}" -output "$xcframework")

    find "$xcframework" -name .DS_Store -type f -delete
    xattr -cr "$xcframework" 2>/dev/null || true

    local installed="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    if [[ -e "$installed" ]]; then
        mv "$installed" "$RUN_DIR/replaced-$FRAMEWORK_NAME.xcframework"
    fi
    ditto "$xcframework" "$installed"
    log "  Installed to: $installed"
}

main() {
    log "Starting $FRAMEWORK_NAME framework build..."
    check_prerequisites
    generate_bindings

    FRAMEWORK_ARGS=()
    local slice
    for slice in "${SLICES[@]}"; do
        build_slice "$slice"
    done

    assemble_xcframework

    echo ""
    echo "Swift import:"
    echo "  import $FRAMEWORK_NAME"
    echo "Intermediate files stay in $RUN_DIR"
}

main
