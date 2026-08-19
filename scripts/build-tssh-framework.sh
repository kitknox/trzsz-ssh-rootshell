#!/bin/bash
#
# Build script for TrzszSSH.xcframework
#
# This script builds the trzsz-ssh Go library as an xcframework
# suitable for iOS, iOS Simulator, and Mac Catalyst.
#
# Prerequisites:
#   - Go 1.26.3
#   - Xcode command line tools
#
# Usage:
#   ./scripts/build-tssh-framework.sh [options]
#
# Options:
#   --trzsz-source PATH  trzsz-ssh checkout
#   --tsshd-source PATH  tsshd checkout (local dependency mode)
#   --kcp-source PATH    kcp-go checkout (local dependency mode)
#   --dependency-mode MODE  local or remote (default: local)
#   --output-dir PATH    framework destination
#   --debug     Build with debug symbols (larger binary, better debugging)
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
FRAMEWORK_NAME="TrzszSSH"
OUTPUT_DIR="${TSSH_OUTPUT_DIR:-$PROJECT_DIR/Frameworks}"

# Minimum iOS version for Mac Catalyst (must be 18.0+ for Xcode 26+)
MIN_IOS_VERSION="18.0"

# Minimum visionOS version
MIN_VISIONOS_VERSION="26.0"

# Parse arguments
DEBUG_BUILD=false
VERBOSE=false
CLEAN=false

usage() {
    echo "Usage: $0 [--trzsz-source <path>] [--tsshd-source <path>] [--kcp-source <path>]"
    echo "          [--dependency-mode local|remote] [--output-dir <path>]"
    echo "          [--debug] [--clean] [--verbose]"
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
        --debug)
            DEBUG_BUILD=true
            shift
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
    tssh_prepare_build_module "$PROJECT_DIR" "$TRZSZ_SSH_DIR" trzsz-ssh

    log "  Go version: $(go env GOVERSION)"
    log "  gomobile: $GOMOBILE"
    log "  gobind: $GOBIND"

    # Check Xcode
    if ! xcode-select -p &> /dev/null; then
        error "Xcode command line tools not installed. Run: xcode-select --install"
    fi
    log "  Xcode: $(xcode-select -p)"

    # Check trzsz-ssh directory
    if [[ ! -d "$TRZSZ_SSH_DIR" ]]; then
        error "trzsz-ssh directory not found: $TRZSZ_SSH_DIR"
    fi
    log "  trzsz-ssh: $TRZSZ_SSH_DIR"
    log "  dependencies: $DEPENDENCY_MODE"
    if [[ "$DEPENDENCY_MODE" == "local" ]]; then
        log "  tsshd: $TSSHD_DIR"
        log "  kcp-go: $KCP_GO_DIR"
    fi

    # Check iosbridge package
    if [[ ! -f "$TRZSZ_SSH_DIR/iosbridge/transport.go" ]]; then
        error "iosbridge package not found in trzsz-ssh"
    fi
    log "  iosbridge: found"
}

# Clean build artifacts
clean_build() {
    log "Cleaning build artifacts..."
    rm -rf "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    rm -rf "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework"
    rm -rf "$TRZSZ_SSH_DIR/.gobind-work"
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

    # Build using gomobile for iOS and iOS Simulator
    # Note: Mac Catalyst is built separately due to gomobile's hardcoded ios13.0
    GOWORK="$TSSH_GOWORK" GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    "$GOMOBILE" bind \
        $VERBOSE_FLAG \
        -trimpath \
        -ldflags="-s -w -buildid=" \
        -target="ios,iossimulator" \
        -o "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" \
        ./iosbridge

    if [[ ! -d "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" ]]; then
        error "iOS framework build failed - output not found"
    fi

    log "  iOS and iOS Simulator build complete!"
}

# Build Mac Catalyst manually (workaround for gomobile's hardcoded ios13.0)
build_maccatalyst_framework() {
    log "Building Mac Catalyst framework..."

    local WORK_DIR="$TRZSZ_SSH_DIR/.gobind-work"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    cd "$TRZSZ_SSH_DIR"

    # Generate binding code
    log "  Generating binding code..."
    PATH="$GOPATH/bin:$PATH" "$GOBIND" -lang=go,objc -outdir="$WORK_DIR" -tags=ios ./iosbridge

    # Create an isolated module for the generated binding code. This carries
    # the fork replacements that dependency go.mod files do not propagate.
    tssh_write_generated_module \
        "$WORK_DIR/src/gobind" \
        github.com/trzsz/trzsz-ssh \
        "$TSSH_BUILD_MODULE_DIR" \
        "$TRZSZ_SSH_DIR/go.mod"
    cd "$WORK_DIR/src/gobind"

    # Get SDK path
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
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-arm64.a" .

    # Build for x86_64 Mac Catalyst
    log "  Building x86_64-apple-ios${MIN_IOS_VERSION}-macabi..."
    CGO_ENABLED=1 \
    GOOS=ios \
    GOARCH=amd64 \
    CC="$CC" \
    CGO_CFLAGS="-target x86_64-apple-ios${MIN_IOS_VERSION}-macabi -isysroot $CATALYST_SDK" \
    CGO_LDFLAGS="-target x86_64-apple-ios${MIN_IOS_VERSION}-macabi -isysroot $CATALYST_SDK" \
    GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-amd64.a" .

    # Create universal binary
    log "  Creating universal binary..."
    lipo -create \
        "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-arm64.a" \
        "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-amd64.a" \
        -output "$TRZSZ_SSH_DIR/TrzszSSH-catalyst.a"

    # Create Mac Catalyst framework structure (deep bundle, not shallow)
    # Mac Catalyst uses macOS-style framework layout: Versions/Current/...
    local CATALYST_FW="$TRZSZ_SSH_DIR/TrzszSSH.framework.catalyst"
    rm -rf "$CATALYST_FW"

    # Create versioned directory structure
    mkdir -p "$CATALYST_FW/Versions/A/Headers"
    mkdir -p "$CATALYST_FW/Versions/A/Modules"
    mkdir -p "$CATALYST_FW/Versions/A/Resources"

    # Copy binary
    cp "$TRZSZ_SSH_DIR/TrzszSSH-catalyst.a" "$CATALYST_FW/Versions/A/TrzszSSH"

    # Copy headers from generated objc files
    cp "$WORK_DIR/src/gobind/Iosbridge.objc.h" "$CATALYST_FW/Versions/A/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$CATALYST_FW/Versions/A/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$CATALYST_FW/Versions/A/Headers/"

    # Create umbrella header
    cat > "$CATALYST_FW/Versions/A/Headers/TrzszSSH.h" << 'EOF'
// TrzszSSH umbrella header
#import "Iosbridge.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    # Create module map
    cat > "$CATALYST_FW/Versions/A/Modules/module.modulemap" << 'EOF'
framework module TrzszSSH {
    umbrella header "TrzszSSH.h"
    export *
}
EOF

    # Create Info.plist in Resources
    cat > "$CATALYST_FW/Versions/A/Resources/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>TrzszSSH</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.TrzszSSH</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>TrzszSSH</string>
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

    # Create symbolic links for versioned framework structure
    cd "$CATALYST_FW/Versions"
    ln -sf A Current
    cd "$CATALYST_FW"
    ln -sf Versions/Current/TrzszSSH TrzszSSH
    ln -sf Versions/Current/Headers Headers
    ln -sf Versions/Current/Modules Modules
    ln -sf Versions/Current/Resources Resources

    # Clean up intermediate files
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-amd64.a"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-catalyst.a"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-arm64.h"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-catalyst-amd64.h"
    rm -rf "$WORK_DIR"

    log "  Mac Catalyst framework build complete!"
}

# Build visionOS frameworks manually (gomobile doesn't support visionOS)
build_visionos_frameworks() {
    log "Building visionOS frameworks..."

    local WORK_DIR="$TRZSZ_SSH_DIR/.gobind-work"

    # Check if work dir exists (from Mac Catalyst build), if not create it
    if [[ ! -d "$WORK_DIR/src/gobind" ]]; then
        rm -rf "$WORK_DIR"
        mkdir -p "$WORK_DIR"
        cd "$TRZSZ_SSH_DIR"
        log "  Generating binding code..."
        PATH="$GOPATH/bin:$PATH" "$GOBIND" -lang=go,objc -outdir="$WORK_DIR" -tags=ios ./iosbridge

        tssh_write_generated_module \
            "$WORK_DIR/src/gobind" \
            github.com/trzsz/trzsz-ssh \
            "$TSSH_BUILD_MODULE_DIR" \
            "$TRZSZ_SSH_DIR/go.mod"
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
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/TrzszSSH-xros-arm64.a" .

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
    go build -trimpath -buildmode=c-archive -ldflags="-s -w -buildid=" -tags=ios -o "$TRZSZ_SSH_DIR/TrzszSSH-xros-sim-arm64.a" .

    # Create visionOS device framework
    local XROS_FW="$TRZSZ_SSH_DIR/TrzszSSH.framework.xros"
    rm -rf "$XROS_FW"
    mkdir -p "$XROS_FW/Headers"
    mkdir -p "$XROS_FW/Modules"

    cp "$TRZSZ_SSH_DIR/TrzszSSH-xros-arm64.a" "$XROS_FW/TrzszSSH"
    cp "$WORK_DIR/src/gobind/Iosbridge.objc.h" "$XROS_FW/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$XROS_FW/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$XROS_FW/Headers/"

    cat > "$XROS_FW/Headers/TrzszSSH.h" << 'EOF'
// TrzszSSH umbrella header
#import "Iosbridge.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    cat > "$XROS_FW/Modules/module.modulemap" << 'EOF'
framework module TrzszSSH {
    umbrella header "TrzszSSH.h"
    export *
}
EOF

    cat > "$XROS_FW/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>TrzszSSH</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.TrzszSSH</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>TrzszSSH</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
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
    local XROS_SIM_FW="$TRZSZ_SSH_DIR/TrzszSSH.framework.xros-simulator"
    rm -rf "$XROS_SIM_FW"
    mkdir -p "$XROS_SIM_FW/Headers"
    mkdir -p "$XROS_SIM_FW/Modules"

    cp "$TRZSZ_SSH_DIR/TrzszSSH-xros-sim-arm64.a" "$XROS_SIM_FW/TrzszSSH"
    cp "$WORK_DIR/src/gobind/Iosbridge.objc.h" "$XROS_SIM_FW/Headers/"
    cp "$WORK_DIR/src/gobind/Universe.objc.h" "$XROS_SIM_FW/Headers/"
    cp "$WORK_DIR/src/gobind/ref.h" "$XROS_SIM_FW/Headers/"

    cat > "$XROS_SIM_FW/Headers/TrzszSSH.h" << 'EOF'
// TrzszSSH umbrella header
#import "Iosbridge.objc.h"
#import "Universe.objc.h"
#import "ref.h"
EOF

    cat > "$XROS_SIM_FW/Modules/module.modulemap" << 'EOF'
framework module TrzszSSH {
    umbrella header "TrzszSSH.h"
    export *
}
EOF

    cat > "$XROS_SIM_FW/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>TrzszSSH</string>
    <key>CFBundleIdentifier</key>
    <string>org.trzsz.TrzszSSH</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>TrzszSSH</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>${MIN_VISIONOS_VERSION}</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>XRSimulator</string>
    </array>
</dict>
</plist>
EOF

    # Clean up intermediate files
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-xros-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-xros-arm64.h"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-xros-sim-arm64.a"
    rm -f "$TRZSZ_SSH_DIR/TrzszSSH-xros-sim-arm64.h"
    rm -rf "$WORK_DIR"

    log "  visionOS frameworks build complete!"
}

# Merge frameworks into final xcframework
merge_frameworks() {
    log "Merging frameworks into xcframework..."

    local XCFW="$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework"
    local CATALYST_FW="$TRZSZ_SSH_DIR/TrzszSSH.framework.catalyst"
    local XROS_FW="$TRZSZ_SSH_DIR/TrzszSSH.framework.xros"
    local XROS_SIM_FW="$TRZSZ_SSH_DIR/TrzszSSH.framework.xros-simulator"

    # Add Mac Catalyst to xcframework
    local CATALYST_DIR="$XCFW/ios-arm64_x86_64-maccatalyst"
    mkdir -p "$CATALYST_DIR"
    mv "$CATALYST_FW" "$CATALYST_DIR/TrzszSSH.framework"

    # Add visionOS device to xcframework
    local XROS_DIR="$XCFW/xros-arm64"
    mkdir -p "$XROS_DIR"
    mv "$XROS_FW" "$XROS_DIR/TrzszSSH.framework"

    # Add visionOS simulator to xcframework
    local XROS_SIM_DIR="$XCFW/xros-arm64-simulator"
    mkdir -p "$XROS_SIM_DIR"
    mv "$XROS_SIM_FW" "$XROS_SIM_DIR/TrzszSSH.framework"

    # Update xcframework Info.plist with all platforms
    cat > "$XCFW/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AvailableLibraries</key>
    <array>
        <dict>
            <key>BinaryPath</key>
            <string>TrzszSSH.framework/TrzszSSH</string>
            <key>LibraryIdentifier</key>
            <string>ios-arm64</string>
            <key>LibraryPath</key>
            <string>TrzszSSH.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>TrzszSSH.framework/TrzszSSH</string>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-simulator</string>
            <key>LibraryPath</key>
            <string>TrzszSSH.framework</string>
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
            <string>TrzszSSH.framework/TrzszSSH</string>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-maccatalyst</string>
            <key>LibraryPath</key>
            <string>TrzszSSH.framework</string>
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
            <string>TrzszSSH.framework/TrzszSSH</string>
            <key>LibraryIdentifier</key>
            <string>xros-arm64</string>
            <key>LibraryPath</key>
            <string>TrzszSSH.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>xros</string>
        </dict>
        <dict>
            <key>BinaryPath</key>
            <string>TrzszSSH.framework/TrzszSSH</string>
            <key>LibraryIdentifier</key>
            <string>xros-arm64-simulator</string>
            <key>LibraryPath</key>
            <string>TrzszSSH.framework</string>
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
# gobind emits `- (nullable instancetype)init;` on every generated class, which
# conflicts with NSObject's audited nonnull -init and warns on every app build.
# Swift only ever uses the IosbridgeNewXxx() constructors, so pinning the
# declaration to nonnull changes nothing on our side.
patch_gomobile_nullability() {
    log "Patching gobind header nullability..."
    local count=0
    while IFS= read -r header; do
        if grep -q '^- (nullable instancetype)init;' "$header"; then
            sed -i '' 's/^- (nullable instancetype)init;/- (nonnull instancetype)init;/' "$header"
            count=$((count + 1))
        fi
    done < <(find "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" -name '*.objc.h')
    log "  Patched $count header(s)"
}

install_framework() {
    log "Installing framework to project..."

    patch_gomobile_nullability

    # Remove old framework
    rm -rf "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"

    # Copy new framework
    cp -R "$TRZSZ_SSH_DIR/$FRAMEWORK_NAME.xcframework" "$OUTPUT_DIR/"
    tssh_audit_framework "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework" "$FRAMEWORK_NAME"

    # Verify installation
    log "  Installed to: $OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"

    # List platforms
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

    # Check Info.plist
    if [[ ! -f "$FRAMEWORK_PATH/Info.plist" ]]; then
        error "Info.plist not found in xcframework"
    fi

    # Check for iOS device slice
    if [[ ! -d "$FRAMEWORK_PATH/ios-arm64" ]]; then
        error "iOS device slice (ios-arm64) not found"
    fi
    log "  ✓ iOS device (arm64)"

    # Check for iOS simulator slice
    if [[ -d "$FRAMEWORK_PATH/ios-arm64_x86_64-simulator" ]]; then
        log "  ✓ iOS Simulator (arm64, x86_64)"
    elif [[ -d "$FRAMEWORK_PATH/ios-arm64-simulator" ]]; then
        log "  ✓ iOS Simulator (arm64)"
    else
        error "iOS Simulator slice not found"
    fi

    # Check for Mac Catalyst slice
    if [[ -d "$FRAMEWORK_PATH/ios-arm64_x86_64-maccatalyst" ]]; then
        log "  ✓ Mac Catalyst (arm64, x86_64)"
    else
        error "Mac Catalyst slice not found"
    fi

    # Check for visionOS device slice
    if [[ -d "$FRAMEWORK_PATH/xros-arm64" ]]; then
        log "  ✓ visionOS device (arm64)"
    else
        error "visionOS device slice not found"
    fi

    # Check for visionOS simulator slice
    if [[ -d "$FRAMEWORK_PATH/xros-arm64-simulator" ]]; then
        log "  ✓ visionOS Simulator (arm64)"
    else
        error "visionOS Simulator slice not found"
    fi

    # Check exported symbols
    log "  Checking exported symbols..."

    BINARY_PATH=$(find "$FRAMEWORK_PATH/ios-arm64" -name "$FRAMEWORK_NAME" -type f | head -1)
    if [[ -n "$BINARY_PATH" ]]; then
        SYMBOL_COUNT=$(nm -g "$BINARY_PATH" 2>/dev/null | grep -c "IosbridgeConnectTransport\|IosbridgeParseTransportConfig" || echo "0")
        if [[ "$SYMBOL_COUNT" -gt 0 ]]; then
            log "  ✓ Go bindings exported correctly"
        else
            error "Go bindings are not exported correctly"
        fi
    fi

    log "Framework verification complete!"
}

# Print build summary
print_summary() {
    echo ""
    echo "============================================"
    echo "  TrzszSSH.xcframework Build Complete"
    echo "============================================"
    echo ""
    echo "Framework location:"
    echo "  $OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
    echo ""
    echo "Use scripts/build-trzsz-package.sh to stage this framework in the local Swift package."
    echo ""
    echo "Swift import:"
    echo "  import TrzszSSH"
    echo ""
}

# Main execution
main() {
    log "Starting TrzszSSH framework build..."
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
