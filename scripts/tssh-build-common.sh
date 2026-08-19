#!/bin/bash

# Shared, reproducible toolchain and dependency handling for the Go Mobile
# frameworks used by the tssh and VPN integrations.

TSSH_GO_TOOLCHAIN_VERSION="${TSSH_GO_TOOLCHAIN_VERSION:-go1.26.3}"
TSSH_GOMOBILE_VERSION="${TSSH_GOMOBILE_VERSION:-v0.0.0-20260204172633-1dceadbbeea3}"
TSSH_GOBIND_VERSION="${TSSH_GOBIND_VERSION:-v0.0.0-20260211191516-dcd2a3258864}"
# Generated modules intentionally follow the source module's gomobile revision.
TSSH_X_MOBILE_VERSION="$TSSH_GOMOBILE_VERSION"

tssh_error() {
    echo "[ERROR] $*" >&2
    exit 1
}

tssh_resolve_sources() {
    local project_dir="$1"

    if [[ -z "${TRZSZ_SSH_DIR:-}" && -f "$project_dir/iosbridge/transport.go" ]]; then
        TRZSZ_SSH_DIR="$project_dir"
    elif [[ -z "${TRZSZ_SSH_DIR:-}" && -f "$project_dir/../trzsz-ssh/iosbridge/transport.go" ]]; then
        TRZSZ_SSH_DIR="$project_dir/../trzsz-ssh"
    fi
    if [[ -z "${TSSHD_DIR:-}" && -f "$project_dir/../tsshd/go.mod" ]]; then
        TSSHD_DIR="$project_dir/../tsshd"
    fi
    if [[ -z "${KCP_GO_DIR:-}" && -f "$project_dir/../trzsz-kcp-go/go.mod" ]]; then
        KCP_GO_DIR="$project_dir/../trzsz-kcp-go"
    fi

    [[ -n "${TRZSZ_SSH_DIR:-}" ]] || tssh_error "trzsz-ssh source was not found; pass --trzsz-source or set TRZSZ_SSH_DIR"
    TRZSZ_SSH_DIR="$(cd "$TRZSZ_SSH_DIR" 2>/dev/null && pwd)" || tssh_error "invalid trzsz-ssh source: $TRZSZ_SSH_DIR"

    if [[ "${DEPENDENCY_MODE:-local}" == "local" ]]; then
        [[ -n "${TSSHD_DIR:-}" ]] || tssh_error "tsshd source was not found; pass --tsshd-source or set TSSHD_DIR"
        [[ -n "${KCP_GO_DIR:-}" ]] || tssh_error "KCP source was not found; pass --kcp-source or set KCP_GO_DIR"
        TSSHD_DIR="$(cd "$TSSHD_DIR" 2>/dev/null && pwd)" || tssh_error "invalid tsshd source: $TSSHD_DIR"
        KCP_GO_DIR="$(cd "$KCP_GO_DIR" 2>/dev/null && pwd)" || tssh_error "invalid KCP source: $KCP_GO_DIR"
    fi
}

tssh_setup_toolchain() {
    local project_dir="$1"
    command -v go >/dev/null 2>&1 || tssh_error "Go is not installed"
    command -v xcrun >/dev/null 2>&1 || tssh_error "Xcode command-line tools are not installed"

    local actual_go
    actual_go="$(go env GOVERSION)"
    if [[ "$actual_go" != "$TSSH_GO_TOOLCHAIN_VERSION" ]]; then
        tssh_error "expected $TSSH_GO_TOOLCHAIN_VERSION; found $actual_go (override TSSH_GO_TOOLCHAIN_VERSION only for an intentional toolchain update)"
    fi

    local tools_dir="$project_dir/.build/tssh-tools/${TSSH_GOMOBILE_VERSION}_${TSSH_GOBIND_VERSION}"
    GOMOBILE="$tools_dir/bin/gomobile"
    GOBIND="$tools_dir/bin/gobind"

    local installed_version=""
    local installed_gobind_version=""
    if [[ -x "$GOMOBILE" && -x "$GOBIND" ]]; then
        installed_version="$(go version -m "$GOMOBILE" 2>/dev/null | awk '$1 == "mod" && $2 == "golang.org/x/mobile" { print $3; exit }')"
        installed_gobind_version="$(go version -m "$GOBIND" 2>/dev/null | awk '$1 == "mod" && $2 == "golang.org/x/mobile" { print $3; exit }')"
    fi

    if [[ "$installed_version" != "$TSSH_GOMOBILE_VERSION" || "$installed_gobind_version" != "$TSSH_GOBIND_VERSION" ]]; then
        echo "Installing pinned gomobile $TSSH_GOMOBILE_VERSION and gobind $TSSH_GOBIND_VERSION into $tools_dir..."
        mkdir -p "$tools_dir/bin"
        GOBIN="$tools_dir/bin" GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
            go install "golang.org/x/mobile/cmd/gomobile@$TSSH_GOMOBILE_VERSION"
        GOBIN="$tools_dir/bin" GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" \
            go install "golang.org/x/mobile/cmd/gobind@$TSSH_GOBIND_VERSION"
    fi

    GOPATH="$(go env GOPATH)"
    PATH="$tools_dir/bin:$PATH"
    export GOMOBILE GOBIND GOPATH PATH
}

tssh_prepare_build_module() {
    local project_dir="$1"
    local module_dir="$2"
    local workspace_name="$3"

    if [[ "${DEPENDENCY_MODE:-local}" == "remote" ]]; then
        TSSH_BUILD_MODULE_DIR="/private/tmp/rootshell-swift-package-source/$workspace_name"
    else
        TSSH_BUILD_MODULE_DIR="$project_dir/.build/tssh-module-copies/$workspace_name"
    fi

    # gomobile creates its own temporary module. Give it a disposable copy of
    # the source module. Local builds override fork dependencies there;
    # release builds use a stable, non-personal path because Go records local
    # main-module replacements in binary build metadata.
    rm -rf "$TSSH_BUILD_MODULE_DIR"
    mkdir -p "$TSSH_BUILD_MODULE_DIR"
    rsync -a \
        --exclude .git \
        --exclude .build \
        --exclude '*.xcframework' \
        --exclude '.gobind-work' \
        --exclude '*.framework.*' \
        "$module_dir/" "$TSSH_BUILD_MODULE_DIR/"
    if [[ "${DEPENDENCY_MODE:-local}" == "local" ]]; then
        (
            cd "$TSSH_BUILD_MODULE_DIR"
            GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" go mod edit \
                -replace="github.com/trzsz/tsshd=$TSSHD_DIR" \
                -replace="github.com/trzsz/kcp-go/v5=$KCP_GO_DIR"
        )
    fi
    TSSH_GOWORK=off
    export TSSH_BUILD_MODULE_DIR TSSH_GOWORK
}

tssh_write_generated_module() {
    local generated_dir="$1"
    local module_path="$2"
    local module_source="$3"
    local source_mod="$4"

    cat > "$generated_dir/go.mod" <<EOF
module gobind

go 1.25.0

require (
    $module_path v0.0.0
    golang.org/x/mobile $TSSH_X_MOBILE_VERSION
)

replace $module_path => $module_source
EOF

    if [[ "${DEPENDENCY_MODE:-local}" == "local" ]]; then
        printf 'replace github.com/trzsz/tsshd => %s\n' "$TSSHD_DIR" >> "$generated_dir/go.mod"
        printf 'replace github.com/trzsz/kcp-go/v5 => %s\n' "$KCP_GO_DIR" >> "$generated_dir/go.mod"
    else
        local replacements
        replacements="$(awk '$1 == "replace" && ($2 == "github.com/trzsz/tsshd" || $2 == "github.com/trzsz/kcp-go/v5") { print }' "$source_mod")"
        [[ "$replacements" == *"github.com/trzsz/tsshd"* ]] || tssh_error "missing public tsshd replacement in $source_mod"
        [[ "$replacements" == *"github.com/trzsz/kcp-go/v5"* ]] || tssh_error "missing public KCP replacement in $source_mod"
        printf '%s\n' "$replacements" >> "$generated_dir/go.mod"
    fi

    (
        cd "$generated_dir"
        GOWORK=off GOTOOLCHAIN="$TSSH_GO_TOOLCHAIN_VERSION" go mod tidy
    )
}

tssh_repackage_static_xcframework() {
    local xcframework="$1"
    local binary_name="$2"
    local stage="${xcframework}.static-stage"
    local output="${xcframework%.xcframework}.static.xcframework"
    local info_plist="$xcframework/Info.plist"
    local library_count
    local create_args=()

    [[ -f "$info_plist" ]] || tssh_error "invalid XCFramework: $xcframework"
    library_count="$(plutil -extract AvailableLibraries raw -o - "$info_plist")"
    rm -rf "$stage" "$output"
    mkdir -p "$stage"

    for ((index = 0; index < library_count; index++)); do
        local identifier framework_path framework library_dir headers_dir library module_map
        identifier="$(plutil -extract "AvailableLibraries.$index.LibraryIdentifier" raw -o - "$info_plist")"
        framework_path="$(plutil -extract "AvailableLibraries.$index.LibraryPath" raw -o - "$info_plist")"
        framework="$xcframework/$identifier/$framework_path"
        library_dir="$stage/libraries/$identifier"
        headers_dir="$stage/headers/$identifier"
        library="$library_dir/lib${binary_name}.a"
        module_map="$headers_dir/$binary_name/module.modulemap"

        [[ -f "$framework/$binary_name" ]] || tssh_error "missing $binary_name archive in $identifier"
        [[ -d "$framework/Headers" ]] || tssh_error "missing headers in $identifier"
        [[ -f "$framework/Modules/module.modulemap" ]] || tssh_error "missing module map in $identifier"
        mkdir -p "$library_dir" "$headers_dir/$binary_name"
        cp "$framework/$binary_name" "$library"
        cp -RL "$framework/Headers/." "$headers_dir/$binary_name/"
        cp "$framework/Modules/module.modulemap" "$module_map"
        sed -i '' \
            -e 's/^framework module /module /' \
            "$module_map"
        create_args+=(-library "$library" -headers "$headers_dir")
    done

    # The preceding Go builds leave us inside generated gobind sources. Xcode
    # 26 can crash its build service when create-xcframework inherits that cwd.
    (
        cd "$(dirname "$xcframework")"
        xcodebuild -create-xcframework "${create_args[@]}" -output "$output"
    )
    rm -rf "$xcframework"
    mv "$output" "$xcframework"
    rm -rf "$stage"
}

tssh_audit_framework() {
    local framework="$1"
    local binary_name="$2"
    local info_plist="$framework/Info.plist"
    local library_count

    find "$framework" -name .DS_Store -delete
    xattr -cr "$framework" 2>/dev/null || true
    plutil -lint "$info_plist" >/dev/null
    library_count="$(plutil -extract AvailableLibraries raw -o - "$info_plist")"

    local binary path_count
    for ((index = 0; index < library_count; index++)); do
        local identifier library_path headers_path headers minimum_versions
        identifier="$(plutil -extract "AvailableLibraries.$index.LibraryIdentifier" raw -o - "$info_plist")"
        library_path="$(plutil -extract "AvailableLibraries.$index.LibraryPath" raw -o - "$info_plist")"
        headers_path="$(plutil -extract "AvailableLibraries.$index.HeadersPath" raw -o - "$info_plist")"
        [[ "$library_path" == "lib${binary_name}.a" ]] || tssh_error "$identifier is not a static-library slice"
        [[ "$headers_path" == "Headers" ]] || tssh_error "$identifier has unexpected HeadersPath: $headers_path"
        binary="$framework/$identifier/$library_path"
        headers="$framework/$identifier/$headers_path"
        [[ -f "$binary" ]] || tssh_error "missing $library_path in $identifier"
        [[ -f "$headers/$binary_name/$binary_name.h" ]] || tssh_error "missing umbrella header in $identifier"
        [[ -f "$headers/$binary_name/module.modulemap" ]] || tssh_error "missing namespaced module map in $identifier"
        [[ ! -d "$framework/$identifier/$binary_name.framework" ]] || tssh_error "$identifier still wraps the archive in a framework"
        file "$binary" | grep -q 'current ar archive' || tssh_error "$identifier is not a static archive"

        minimum_versions="$(otool -l "$binary" 2>/dev/null | awk '$1 == "minos" { print $2 }' | sort -u)"
        case "$identifier" in
            xros-*) [[ "$minimum_versions" == "26.0" ]] || tssh_error "$identifier minimum versions are '$minimum_versions', expected 26.0" ;;
            *-maccatalyst) [[ "$minimum_versions" == "18.0" ]] || tssh_error "$identifier minimum versions are '$minimum_versions', expected 18.0" ;;
            macos-*) [[ "$minimum_versions" == "15.0" ]] || tssh_error "$identifier minimum versions are '$minimum_versions', expected 15.0" ;;
        esac

        path_count="$(strings "$binary" 2>/dev/null | grep -Ec '/Users/|/home/[^/]+/' || true)"
        if [[ "$path_count" -ne 0 ]]; then
            if [[ "${DEPENDENCY_MODE:-local}" == "remote" ]]; then
                echo "ERROR: build-machine paths remain in $binary" >&2
                strings "$binary" 2>/dev/null | grep -E -m 10 '/Users/|/home/[^/]+' >&2 || true
                exit 1
            fi
            echo "WARNING: local Go replacements are recorded in $(basename "$binary"); remote release builds reject host paths" >&2
        fi
    done

    local smoke_root simulator_slice
    simulator_slice="$(find "$framework" -mindepth 1 -maxdepth 1 -type d -name 'ios-*-simulator' -print -quit)"
    [[ -n "$simulator_slice" ]] || tssh_error "missing iOS simulator slice"
    smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/${binary_name}-module-audit.XXXXXX")"
    printf 'import %s\n' "$binary_name" > "$smoke_root/importer-smoke.swift"
    xcrun --sdk iphonesimulator swiftc \
        -target "arm64-apple-ios18.0-simulator" \
        -module-cache-path "$smoke_root/module-cache" \
        -I "$simulator_slice/Headers" \
        -typecheck "$smoke_root/importer-smoke.swift"
    rm -rf "$smoke_root"
}
