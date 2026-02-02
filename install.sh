#!/bin/bash
set -e

# remotesearch installer script
# Usage: curl -sSL https://raw.githubusercontent.com/vosiander/remote-search/main/install.sh | bash

REPO="vosiander/remote-search"
BINARY="remotesearch"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="darwin";;
        MINGW*|MSYS*|CYGWIN*) OS="windows";;
        *)          error "Unsupported operating system: $(uname -s)";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   ARCH="amd64";;
        arm64|aarch64)  ARCH="arm64";;
        *)              error "Unsupported architecture: $(uname -m)";;
    esac
}

# Get latest version from GitHub
get_latest_version() {
    VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" | grep -i "location:" | sed 's/.*tag\///' | tr -d '\r\n')
    if [ -z "$VERSION" ]; then
        error "Could not determine latest version"
    fi
    info "Latest version: $VERSION"
}

# Download and install
install() {
    detect_os
    detect_arch
    get_latest_version

    # Construct download URL
    if [ "$OS" = "windows" ]; then
        ARCHIVE="${BINARY}_${VERSION#v}_${OS}_${ARCH}.zip"
    else
        ARCHIVE="${BINARY}_${VERSION#v}_${OS}_${ARCH}.tar.gz"
    fi
    
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
    
    info "Downloading ${BINARY} ${VERSION} for ${OS}/${ARCH}..."
    info "URL: $URL"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    # Download
    if ! curl -sL "$URL" -o "$TMP_DIR/$ARCHIVE"; then
        error "Failed to download $URL"
    fi

    # Extract
    info "Extracting..."
    cd "$TMP_DIR"
    if [ "$OS" = "windows" ]; then
        unzip -q "$ARCHIVE"
    else
        tar xzf "$ARCHIVE"
    fi

    # Install
    if [ "$OS" = "windows" ]; then
        BINARY_NAME="${BINARY}.exe"
    else
        BINARY_NAME="$BINARY"
    fi

    # Check if we can write to INSTALL_DIR
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BINARY_NAME" "$INSTALL_DIR/"
        info "Installed $BINARY to $INSTALL_DIR/$BINARY_NAME"
    else
        warn "Cannot write to $INSTALL_DIR, trying with sudo..."
        sudo mv "$BINARY_NAME" "$INSTALL_DIR/"
        info "Installed $BINARY to $INSTALL_DIR/$BINARY_NAME"
    fi

    # Verify installation
    if command -v "$BINARY" &> /dev/null; then
        info "Installation successful!"
        "$BINARY" --version
    else
        warn "Installation complete, but $BINARY not found in PATH"
        warn "You may need to add $INSTALL_DIR to your PATH"
    fi
}

# Run installer
install
