#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly CYAN='\033[0;36m'
readonly GREEN='\033[0;32m'
readonly NC='\033[0m'

declare PLATFORM=""
declare LIB_NAME=""
declare RUST_TARGET=""

error() {
    echo "❌ $*" >&2
}

set_target_info() {
    local target="$1"

    case "$target" in
        # macOS targets
        "aarch64-apple-darwin") PLATFORM="darwin-arm64"; LIB_NAME="libprotect_ffi.dylib" ;;
        "x86_64-apple-darwin") PLATFORM="darwin-x64"; LIB_NAME="libprotect_ffi.dylib" ;;

        # Linux targets
        "aarch64-unknown-linux-gnu") PLATFORM="linux-arm64-gnu"; LIB_NAME="libprotect_ffi.so" ;;
        "x86_64-unknown-linux-gnu") PLATFORM="linux-x64-gnu"; LIB_NAME="libprotect_ffi.so" ;;

        # Windows target
        "x86_64-pc-windows-msvc") PLATFORM="win32-x64-msvc"; LIB_NAME="protect_ffi.dll" ;;

        *) error "Unsupported target: [$target]"; exit 1 ;;
    esac

    RUST_TARGET="$target"
}

detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$os" in
        darwin)
            case "$arch" in
                arm64) set_target_info "aarch64-apple-darwin" ;;
                x86_64|amd64) set_target_info "x86_64-apple-darwin" ;;
                *) error "Unsupported macOS arch: [$arch]"; exit 1 ;;
            esac ;;
        linux)
            case "$arch" in
                aarch64) set_target_info "aarch64-unknown-linux-gnu" ;;
                x86_64|amd64) set_target_info "x86_64-unknown-linux-gnu" ;;
                *) error "Unsupported Linux arch: [$arch]"; exit 1 ;;
            esac ;;
        mingw*|msys*|cygwin*)
            case "$arch" in
                x86_64|amd64) set_target_info "x86_64-pc-windows-msvc" ;;
                *) error "Unsupported Windows arch: [$arch]"; exit 1 ;;
            esac ;;
        *) error "Unsupported platform: [$os-$arch]"; exit 1 ;;
    esac
}

build_library() {
    if [[ ! -f "Cargo.toml" ]]; then
        error "Cargo.toml not found"
        exit 1
    fi

    if ! command -v cargo &>/dev/null; then
        error "Cargo not installed. Install from: https://rustup.rs"
        exit 1
    fi

    local build_cmd="cargo build --release --target $RUST_TARGET"

    echo "🦀 Building library..."
    echo -e "   ${CYAN}▶ rustc --version${NC}"
    rustc --version | while IFS= read -r line; do
        echo "   $line"
    done
    echo ""
    echo -e "   ${CYAN}▶ $build_cmd${NC}"
    if ! $build_cmd; then
        echo ""
        error "Rust compilation failed. Check error output above."
        echo ""
        exit 1
    fi
    echo ""
}

copy_library() {
    local src="target/$RUST_TARGET/release/$LIB_NAME"
    local dest="platforms/$PLATFORM"

    if [[ ! -f "$src" ]]; then
        error "Library not found: [$src]"
        exit 1
    fi

    echo -e "📦 Copying ${CYAN}$LIB_NAME${NC} → ${GREEN}./platforms/$PLATFORM/${NC}"

    mkdir -p "$dest" || { error "Failed to create directory: [$dest]"; exit 1; }

    cp "$src" "$dest/" || { error "Failed to copy library"; exit 1; }
}

main() {
    cd "$ROOT_DIR"

    if [[ $# -gt 0 ]]; then
        local target="$1"
        echo -e "🎯 Using specified target: ${GREEN}$target${NC}"
        set_target_info "$target"
    else
        detect_platform
        echo -e "🎯 Using detected target: ${GREEN}$RUST_TARGET${NC}"
    fi

    build_library

    if [[ "$*" == *"--production"* ]]; then
        copy_library
    else
        echo -e "📦 Leaving ${CYAN}$LIB_NAME${NC} → ${GREEN}./target/$RUST_TARGET/release/${NC}"
    fi

    echo "🎉 Build complete!"
}

main "$@"
