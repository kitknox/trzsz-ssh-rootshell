#!/bin/bash
#
# Build script for VPNTunnel.xcframework
#
# This script builds the vpntunnel Go library (gVisor netstack + tsshd)
# as an xcframework suitable for iOS, iOS Simulator, Mac Catalyst, and visionOS.
#
# Prerequisites:
#   - Go 1.26.3
#   - Xcode command line tools
#
# Usage:
#   ./scripts/build-vpntunnel-framework.sh [options]
#
# Options:
#   --trzsz-source PATH  trzsz-ssh checkout
#   --tsshd-source PATH  tsshd checkout (local dependency mode)
#   --kcp-source PATH    kcp-go checkout (local dependency mode)
#   --dependency-mode MODE  local or remote (default: local)
#   --output-dir PATH    framework destination
#   --verbose   Show detailed build output
#   --clean     Clean build artifacts before building
#   --help      Show this help message

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/tssh-build-common.sh"

TRZSZ_SSH_DIR="${TRZSZ_SSH_DIR:-}"
TSSHD_DIR="${TSSHD_DIR:-}"
KCP_GO_DIR="${KCP_GO_DIR:-}"
DEPENDENCY_MODE="${DEPENDENCY_MODE:-local}"
VPNTUNNEL_DIR="$TRZSZ_SSH_DIR/vpntunnel"
FRAMEWORK_NAME="VPNTunnel"
OUTPUT_DIR="${TSSH_OUTPUT_DIR:-$PROJECT_DIR/Frameworks}"

# Minimum iOS version for Mac Catalyst
MIN_IOS_VERSION="18.0"

# Minimum visionOS version
MIN_VISIONOS_VERSION="26.0"

# Minimum native macOS version (system-extension host + sysext, Standalone build)
MIN_MACOS_VERSION="15.0"

# Parse arguments
VERBOSE=false
CLEAN=false

usage() {
    echo "Usage: $0 [--trzsz-source <path>] [--tsshd-source <path>] [--kcp-source <path>]"
    echo "          [--dependency-mode local|remote] [--output-dir <path>]"
    echo "          [--clean] [--verbose]"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --trzsz-source)
            TRZSZ_SSH_DIR="${2:-}"
            shift 2
            ;;
        --tsshd-source)
            TSSHD_DIR="${2:-}"
            shift 2
            ;;
        --kcp-source)
            KCP_GO_DIR="${2:-}"
            shift 2
            ;;
        --dependency-mode)
            DEPENDENCY_MODE="${2:-}"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

case "$DEPENDENCY_MODE" in
    local|remote) ;;
    *) tssh_error "dependency mode must be local or remote" ;;
esac
tssh_resolve_sources "$PROJECT_DIR"
VPNTUNNEL_DIR="$TRZSZ_SSH_DIR/vpntunnel"
mkdir -p "$OUTPUT_DIR"

# Helper functions
log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

# Verify prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    tssh_setup_toolchain "$PROJECT_DIR"
    tssh_prepare_build_module "$PROJECT_DIR" "$VPNTUNNEL_DIR" vpntunnel

    log "  Go version: $(go env GOVERSION)"
    log "  gomobile: $GOMOBILE"
    log "  gobind: $GOBIND"

    if ! xcode-select -p &> /dev/null; then
        error "Xcode command line tools not installed. Run: xcode-select --install"
    fi
    log "  Xcode: $(xcode-select -p)"

    if [[ ! -d "$VPNTUNNEL_DIR" ]]; then
        error "vpntunnel directory not found: $VPNTUNNEL_DIR"
    fi
    log "  vpntunnel: $VPNTUNNEL_DIR"
    log "  dependencies: $DEPENDENCY_MODE"
    if [[ "$DEPENDENCY_MODE" == "local" ]]; then
        log "  tsshd: $TSSHD_DIR"
        log "  kcp-go: $KCP_GO_DIR"
    fi

    if [[ ! -f "$VPNTUNNEL_DIR/bridge.go" ]]; then
        error "bridge.go not found in vpntunnel"
    fi
    log "  bridge.go: found"
}

# Clean build artifacts
clean_build() {
    log "Cleaning build artifacts..."
    rm -rf "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    rm -rf "$VPNTUNNEL_DIR/$FRAMEWORK_NAME.xcframework"
    rm -rf "$TRZSZ_SSH_DIR/.gobind-vpn-work"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME"-*.a
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME"-*.h
}

# Build iOS and iOS Simulator using gomobile
build_ios_frameworks() {
    log "Building iOS and iOS Simulator frameworks..."

    cd "$TSSH_BUILD_MODULE_DIR"

    VERBOSE_FLAG=""
    if [[ "$VERBOSE" == "true" ]]; then
        VERBOSE_FLAG="-v"
    fi

    log "  Building for targets: ios,iossimulator"
    log "  This may take several minutes..."

    GOWORK="$TSSH_GOWORK" GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    "$GOMOBILE" bind \
        $VERBOSE_FLAG \
        -target="ios,iossimulator" \
        -trimpath \
        -ldflags="-s -w -buildid=" \
        -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" \
        .

    if [[ ! -d "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" ]]; then
        error "iOS framework build failed - output not found"
    fi

    log "  iOS and iOS Simulator build complete!"
}

# Build Mac Catalyst manually (workaround for gomobile's hardcoded ios13.0)
build_maccatalyst_framework() {
    log "Building Mac Catalyst framework..."

    local WORK_DIR="$TRZSZ_SSH_DIR/.gobind-vpn-work"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    cd "$VPNTUNNEL_DIR"

    # Generate binding code
    log "  Generating binding code..."
    PATH="$GOPATH/bin:$PATH" "$GOBIND" -lang=go,objc -outdir="$WORK_DIR" -tags=ios .

    tssh_write_generated_module \
        "$WORK_DIR/src/gobind" \
        github.com/trzsz/trzsz-ssh/vpntunnel \
        "$TSSH_BUILD_MODULE_DIR" \
        "$VPNTUNNEL_DIR/go.mod"
    cd "$WORK_DIR/src/gobind"

    local CATALYST_SDK=$(xcrun --sdk macosx --show-sdk-path)
    local CC=$(xcrun --sdk macosx --find clang)

    # Build for arm64 Mac Catalyst
    log "  Building arm64-apple-ios${MIN_IOS_VERSION}-macabi..."
    CGO_ENABLED=1 \
    GOOS=ios \
    GOARCH=arm64 \
    CC="$CC" \
    CGO_CFLAGS="-target arm64-apple-ios${MIN_IOS_VERSION}-macabi -isysroot $CATALYST_SDK" \
    CGO_LDFLAGS="-target arm64-apple-ios${MIN_IOS_VERSION}-macabi -isysroot $CATALYST_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-arm64.a" .

    # Build for x86_64 Mac Catalyst
    log "  Building x86_64-apple-ios${MIN_IOS_VERSION}-macabi..."
    CGO_ENABLED=1 \
    GOOS=ios \
    GOARCH=amd64 \
    CC="$CC" \
    CGO_CFLAGS="-target x86_64-apple-ios${MIN_IOS_VERSION}-macabi -isysroot $CATALYST_SDK" \
    CGO_LDFLAGS="-target x86_64-apple-ios${MIN_IOS_VERSION}-macabi -isysroot $CATALYST_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-amd64.a" .

    # Create universal binary
    log "  Creating universal binary..."
    lipo -create \
        "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-arm64.a" \
        "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-amd64.a" \
        -output "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst.a"

    # Create Mac Catalyst framework structure (deep bundle)
    local CATALYST_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.catalyst"
    rm -rf "$CATALYST_FW"

    mkdir -p "$CATALYST_FW/Versions/A/Headers"
    mkdir -p "$CATALYST_FW/Versions/A/Modules"
    mkdir -p "$CATALYST_FW/Versions/A/Resources"

    cp "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst.a" "$CATALYST_FW/Versions/A/$FRAMEWORK_NAME"

    # Copy headers from generated objc files
    cp "$WORK_DIR/src/gobind/Vpntunnel.objc.h" "$CATALYST_FW/Versions/A/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$CATALYST_FW/Versions/A/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$CATALYST_FW/Versions/A/Headers/"

    cat > "$CATALYST_FW/Versions/A/Headers/$FRAMEWORK_NAME.h" << 'EOF'
// VPNTunnel umbrella header
#import "Vpntunnel.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    cat > "$CATALYST_FW/Versions/A/Modules/module.modulemap" << EOF
framework module $FRAMEWORK_NAME {
    umbrella header "$FRAMEWORK_NAME.h"
    export *
}
EOF

    cat > "$CATALYST_FW/Versions/A/Resources/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.$FRAMEWORK_NAME</string>
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
    <string>${MIN_IOS_VERSION}</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
</dict>
</plist>
EOF

    cd "$CATALYST_FW/Versions"
    ln -sf A Current
    cd "$CATALYST_FW"
    ln -sf Versions/Current/$FRAMEWORK_NAME $FRAMEWORK_NAME
    ln -sf Versions/Current/Headers Headers
    ln -sf Versions/Current/Modules Modules
    ln -sf Versions/Current/Resources Resources

    # Clean up intermediate files
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-amd64.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-arm64.h"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-catalyst-amd64.h"
    rm -rf "$WORK_DIR"

    log "  Mac Catalyst framework build complete!"
}

# Build native macOS framework (arm64 + x86_64) for the system-extension host + sysext.
# GOOS=darwin (NOT ios) with -apple-macos target triples; no -tags=ios.
build_macos_framework() {
    log "Building native macOS framework..."

    local WORK_DIR="$TRZSZ_SSH_DIR/.gobind-vpn-work"

    if [[ ! -d "$WORK_DIR/src/gobind" ]]; then
        rm -rf "$WORK_DIR"
        mkdir -p "$WORK_DIR"
        cd "$VPNTUNNEL_DIR"
        log "  Generating binding code..."
        PATH="$GOPATH/bin:$PATH" "$GOBIND" -lang=go,objc -outdir="$WORK_DIR" -tags=ios .

        tssh_write_generated_module \
            "$WORK_DIR/src/gobind" \
            github.com/trzsz/trzsz-ssh/vpntunnel \
            "$TSSH_BUILD_MODULE_DIR" \
            "$VPNTUNNEL_DIR/go.mod"
    fi

    cd "$WORK_DIR/src/gobind"

    local MACOS_SDK=$(xcrun --sdk macosx --show-sdk-path)
    local MACOS_CC=$(xcrun --sdk macosx --find clang)

    log "  Building arm64-apple-macos${MIN_MACOS_VERSION}..."
    CGO_ENABLED=1 \
    GOOS=darwin \
    GOARCH=arm64 \
    CC="$MACOS_CC" \
    CGO_CFLAGS="-target arm64-apple-macos${MIN_MACOS_VERSION} -isysroot $MACOS_SDK" \
    CGO_LDFLAGS="-target arm64-apple-macos${MIN_MACOS_VERSION} -isysroot $MACOS_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-arm64.a" .

    log "  Building x86_64-apple-macos${MIN_MACOS_VERSION}..."
    CGO_ENABLED=1 \
    GOOS=darwin \
    GOARCH=amd64 \
    CC="$MACOS_CC" \
    CGO_CFLAGS="-target x86_64-apple-macos${MIN_MACOS_VERSION} -isysroot $MACOS_SDK" \
    CGO_LDFLAGS="-target x86_64-apple-macos${MIN_MACOS_VERSION} -isysroot $MACOS_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-amd64.a" .

    log "  Creating universal binary..."
    lipo -create \
        "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-arm64.a" \
        "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-amd64.a" \
        -output "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos.a"

    # macOS frameworks are deep (versioned) bundles, like the Catalyst one.
    local MACOS_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.macos"
    rm -rf "$MACOS_FW"
    mkdir -p "$MACOS_FW/Versions/A/Headers"
    mkdir -p "$MACOS_FW/Versions/A/Modules"
    mkdir -p "$MACOS_FW/Versions/A/Resources"

    cp "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos.a" "$MACOS_FW/Versions/A/$FRAMEWORK_NAME"
    cp "$WORK_DIR/src/gobind/Vpntunnel.objc.h" "$MACOS_FW/Versions/A/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$MACOS_FW/Versions/A/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$MACOS_FW/Versions/A/Headers/"

    cat > "$MACOS_FW/Versions/A/Headers/$FRAMEWORK_NAME.h" << 'EOF'
// VPNTunnel umbrella header
#import "Vpntunnel.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    cat > "$MACOS_FW/Versions/A/Modules/module.modulemap" << EOF
framework module $FRAMEWORK_NAME {
    umbrella header "$FRAMEWORK_NAME.h"
    export *
}
EOF

    cat > "$MACOS_FW/Versions/A/Resources/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.$FRAMEWORK_NAME</string>
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
    <key>LSMinimumSystemVersion</key>
    <string>${MIN_MACOS_VERSION}</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
</dict>
</plist>
EOF

    cd "$MACOS_FW/Versions"
    ln -sf A Current
    cd "$MACOS_FW"
    ln -sf Versions/Current/$FRAMEWORK_NAME $FRAMEWORK_NAME
    ln -sf Versions/Current/Headers Headers
    ln -sf Versions/Current/Modules Modules
    ln -sf Versions/Current/Resources Resources

    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-amd64.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-arm64.h"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-macos-amd64.h"

    log "  Native macOS framework build complete!"
}

# Build visionOS frameworks manually
build_visionos_frameworks() {
    log "Building visionOS frameworks..."

    local WORK_DIR="$TRZSZ_SSH_DIR/.gobind-vpn-work"

    if [[ ! -d "$WORK_DIR/src/gobind" ]]; then
        rm -rf "$WORK_DIR"
        mkdir -p "$WORK_DIR"
        cd "$VPNTUNNEL_DIR"
        log "  Generating binding code..."
        PATH="$GOPATH/bin:$PATH" "$GOBIND" -lang=go,objc -outdir="$WORK_DIR" -tags=ios .

        tssh_write_generated_module \
            "$WORK_DIR/src/gobind" \
            github.com/trzsz/trzsz-ssh/vpntunnel \
            "$TSSH_BUILD_MODULE_DIR" \
            "$VPNTUNNEL_DIR/go.mod"
    fi

    cd "$WORK_DIR/src/gobind"

    # visionOS Device
    log "  Building arm64-apple-xros${MIN_VISIONOS_VERSION} (device)..."
    local XROS_SDK=$(xcrun --sdk xros --show-sdk-path)
    local XROS_CC=$(xcrun --sdk xros --find clang)

    CGO_ENABLED=1 \
    GOOS=ios \
    GOARCH=arm64 \
    CC="$XROS_CC" \
    CGO_CFLAGS="-target arm64-apple-xros${MIN_VISIONOS_VERSION} -isysroot $XROS_SDK" \
    CGO_LDFLAGS="-target arm64-apple-xros${MIN_VISIONOS_VERSION} -isysroot $XROS_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-arm64.a" .

    # visionOS Simulator
    log "  Building arm64-apple-xros${MIN_VISIONOS_VERSION}-simulator..."
    local XROS_SIM_SDK=$(xcrun --sdk xrsimulator --show-sdk-path)
    local XROS_SIM_CC=$(xcrun --sdk xrsimulator --find clang)

    CGO_ENABLED=1 \
    GOOS=ios \
    GOARCH=arm64 \
    CC="$XROS_SIM_CC" \
    CGO_CFLAGS="-target arm64-apple-xros${MIN_VISIONOS_VERSION}-simulator -isysroot $XROS_SIM_SDK" \
    CGO_LDFLAGS="-target arm64-apple-xros${MIN_VISIONOS_VERSION}-simulator -isysroot $XROS_SIM_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-sim-arm64.a" .

    # Create visionOS device framework
    local XROS_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.xros"
    rm -rf "$XROS_FW"
    mkdir -p "$XROS_FW/Headers" "$XROS_FW/Modules"

    cp "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-arm64.a" "$XROS_FW/$FRAMEWORK_NAME"
    cp "$WORK_DIR/src/gobind/Vpntunnel.objc.h" "$XROS_FW/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$XROS_FW/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$XROS_FW/Headers/"

    cat > "$XROS_FW/Headers/$FRAMEWORK_NAME.h" << 'EOF'
// VPNTunnel umbrella header
#import "Vpntunnel.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    cat > "$XROS_FW/Modules/module.modulemap" << EOF
framework module $FRAMEWORK_NAME {
    umbrella header "$FRAMEWORK_NAME.h"
    export *
}
EOF

    cat > "$XROS_FW/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.$FRAMEWORK_NAME</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>MinimumOSVersion</key>
    <string>${MIN_VISIONOS_VERSION}</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>XROS</string>
    </array>
</dict>
</plist>
EOF

    # Create visionOS simulator framework
    local XROS_SIM_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.xros-simulator"
    rm -rf "$XROS_SIM_FW"
    mkdir -p "$XROS_SIM_FW/Headers" "$XROS_SIM_FW/Modules"

    cp "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-sim-arm64.a" "$XROS_SIM_FW/$FRAMEWORK_NAME"
    cp "$WORK_DIR/src/gobind/Vpntunnel.objc.h" "$XROS_SIM_FW/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$XROS_SIM_FW/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$XROS_SIM_FW/Headers/"

    cat > "$XROS_SIM_FW/Headers/$FRAMEWORK_NAME.h" << 'EOF'
// VPNTunnel umbrella header
#import "Vpntunnel.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    cat > "$XROS_SIM_FW/Modules/module.modulemap" << EOF
framework module $FRAMEWORK_NAME {
    umbrella header "$FRAMEWORK_NAME.h"
    export *
}
EOF

    cat > "$XROS_SIM_FW/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.$FRAMEWORK_NAME</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>MinimumOSVersion</key>
    <string>${MIN_VISIONOS_VERSION}</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>XRSimulator</string>
    </array>
</dict>
</plist>
EOF

    # Clean up
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-arm64.h"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-sim-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME-xros-sim-arm64.h"
    rm -rf "$WORK_DIR"

    log "  visionOS frameworks build complete!"
}

# Merge all platform frameworks into final xcframework
merge_frameworks() {
    log "Merging frameworks into xcframework..."

    local XCFW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework"
    local CATALYST_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.catalyst"
    local MACOS_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.macos"
    local XROS_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.xros"
    local XROS_SIM_FW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.framework.xros-simulator"

    # Add Mac Catalyst
    local CATALYST_DIR="$XCFW/ios-arm64_x86_64-maccatalyst"
    mkdir -p "$CATALYST_DIR"
    mv "$CATALYST_FW" "$CATALYST_DIR/$FRAMEWORK_NAME.framework"

    # Add native macOS
    local MACOS_DIR="$XCFW/macos-arm64_x86_64"
    mkdir -p "$MACOS_DIR"
    mv "$MACOS_FW" "$MACOS_DIR/$FRAMEWORK_NAME.framework"

    # Add visionOS device
    local XROS_DIR="$XCFW/xros-arm64"
    mkdir -p "$XROS_DIR"
    mv "$XROS_FW" "$XROS_DIR/$FRAMEWORK_NAME.framework"

    # Add visionOS simulator
    local XROS_SIM_DIR="$XCFW/xros-arm64-simulator"
    mkdir -p "$XROS_SIM_DIR"
    mv "$XROS_SIM_FW" "$XROS_SIM_DIR/$FRAMEWORK_NAME.framework"

    # Update Info.plist with all platforms
    cat > "$XCFW/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AvailableLibraries</key>
    <array>
        <dict>
            <key>BinaryPath</key>
            <string>VPNTunnel.framework/VPNTunnel</string>
            <key>LibraryIdentifier</key>
            <string>ios-arm64</string>
            <key>LibraryPath</key>
            <string>VPNTunnel.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>VPNTunnel.framework/VPNTunnel</string>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-simulator</string>
            <key>LibraryPath</key>
            <string>VPNTunnel.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
                <string>x86_64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
            <key>SupportedPlatformVariant</key>
            <string>simulator</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>VPNTunnel.framework/VPNTunnel</string>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-maccatalyst</string>
            <key>LibraryPath</key>
            <string>VPNTunnel.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
                <string>x86_64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
            <key>SupportedPlatformVariant</key>
            <string>maccatalyst</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>VPNTunnel.framework/VPNTunnel</string>
            <key>LibraryIdentifier</key>
            <string>macos-arm64_x86_64</string>
            <key>LibraryPath</key>
            <string>VPNTunnel.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
                <string>x86_64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>macos</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>VPNTunnel.framework/VPNTunnel</string>
            <key>LibraryIdentifier</key>
            <string>xros-arm64</string>
            <key>LibraryPath</key>
            <string>VPNTunnel.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>xros</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>VPNTunnel.framework/VPNTunnel</string>
            <key>LibraryIdentifier</key>
            <string>xros-arm64-simulator</string>
            <key>LibraryPath</key>
            <string>VPNTunnel.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>xros</string>
            <key>SupportedPlatformVariant</key>
            <string>simulator</string>
        </dict>
    </array>
    <key>CFBundlePackageType</key>
    <string>XFWK</string>
    <key>XCFrameworkFormatVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

    log "  Xcframework merge complete!"
}

# Copy framework to project
install_framework() {
    log "Installing framework to project..."

    rm -rf "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    cp -R "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" "$OUTPUT_DIR/"
    tssh_audit_framework "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework" "$FRAMEWORK_NAME"

    log "  Installed to: $OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    log "  Platforms:"
    for platform in "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"/*/; do
        platform_name=$(basename "$platform")
        if [[ "$platform_name" != "Info.plist" ]]; then
            log "    - $platform_name"
        fi
    done
}

# Verify the framework
verify_framework() {
    log "Verifying framework..."

    FRAMEWORK_PATH="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"

    if [[ ! -f "$FRAMEWORK_PATH/Info.plist" ]]; then
        error "Info.plist not found in xcframework"
    fi

    for slice in ios-arm64 "ios-arm64_x86_64-simulator" "ios-arm64_x86_64-maccatalyst" "macos-arm64_x86_64" xros-arm64 xros-arm64-simulator; do
        if [[ -d "$FRAMEWORK_PATH/$slice" ]]; then
            log "  OK $slice"
        else
            error "missing required slice: $slice"
        fi
    done

    # Check exported symbols
    BINARY_PATH=$(find "$FRAMEWORK_PATH/ios-arm64" -name "$FRAMEWORK_NAME" -type f | head -1)
    if [[ -n "$BINARY_PATH" ]]; then
        SYMBOL_COUNT=$(nm -g "$BINARY_PATH" 2>/dev/null | grep -c "VpntunnelStartTunnel\|VpntunnelStopTunnel\|VpntunnelInjectPacket" || echo "0")
        if [[ "$SYMBOL_COUNT" -gt 0 ]]; then
            log "  OK Go bindings exported ($SYMBOL_COUNT symbols found)"
        else
            error "Go bindings are not exported correctly"
        fi
    fi

    log "Framework verification complete!"
}

print_summary() {
    echo ""
    echo "============================================"
    echo "  VPNTunnel.xcframework Build Complete"
    echo "============================================"
    echo ""
    echo "Framework location:"
    echo "  $OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    echo ""
    echo "Swift import:"
    echo "  import VPNTunnel"
    echo ""
}

# Main execution
main() {
    log "Starting VPNTunnel framework build..."
    echo ""

    check_prerequisites
    echo ""

    if [[ "$CLEAN" == "true" ]]; then
        clean_build
        echo ""
    fi

    build_ios_frameworks
    echo ""

    build_maccatalyst_framework
    echo ""

    build_macos_framework
    echo ""

    build_visionos_frameworks
    echo ""

    merge_frameworks
    echo ""

    tssh_repackage_static_xcframework "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" "$FRAMEWORK_NAME"
    echo ""

    install_framework
    echo ""

    verify_framework

    print_summary
}

main
