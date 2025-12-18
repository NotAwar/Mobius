#!/bin/bash
set -e

#===================================================================================
# Mobius Client Installation Script
# 
# Usage:
#   curl -sSL https://install.mobius.com/install.sh | sudo bash -s -- \
#     --server=https://mobius.example.com \
#     --key=ENROLLMENT_KEY
#
# Or download and run:
#   sudo bash install.sh --server=URL --key=KEY
#===================================================================================

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/mobius"
LOG_DIR="/var/log/mobius"
DATA_DIR="/var/lib/mobius"
SERVICE_USER="mobius"

MOBIUS_SERVER=""
ENROLLMENT_KEY=""
VERSION="latest"
DOWNLOAD_URL="https://releases.mobius.com"

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "================================================"
    echo "  Mobius Client Installation"
    echo "================================================"
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ${NC}  $1"
}

print_success() {
    echo -e "${GREEN}✓${NC}  $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

print_error() {
    echo -e "${RED}✗${NC}  $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ "$(uname -s)" = "Darwin" ]; then
        OS="darwin"
        OS_VERSION=$(sw_vers -productVersion)
    else
        print_error "Unable to detect operating system"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    print_info "Detected OS: $OS (${OS_VERSION}) on $ARCH"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --server=*)
                MOBIUS_SERVER="${1#*=}"
                ;;
            --key=*)
                ENROLLMENT_KEY="${1#*=}"
                ;;
            --version=*)
                VERSION="${1#*=}"
                ;;
            --server)
                MOBIUS_SERVER="$2"
                shift
                ;;
            --key)
                ENROLLMENT_KEY="$2"
                shift
                ;;
            --version)
                VERSION="$2"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Usage: $0 --server=URL --key=KEY [--version=VERSION]"
                exit 1
                ;;
        esac
        shift
    done
    
    if [ -z "$MOBIUS_SERVER" ]; then
        print_error "Server URL is required (--server=https://mobius.example.com)"
        exit 1
    fi
    
    if [ -z "$ENROLLMENT_KEY" ]; then
        print_error "Enrollment key is required (--key=YOUR_KEY)"
        exit 1
    fi
}

create_directories() {
    print_info "Creating directories..."
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    print_success "Directories created"
}

create_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        print_info "User $SERVICE_USER already exists"
    else
        print_info "Creating service user: $SERVICE_USER..."
        if [ "$OS" = "darwin" ]; then
            # macOS doesn't need a dedicated user (runs as root)
            print_info "Running on macOS, skipping user creation"
        else
            useradd --system --no-create-home --shell /bin/false "$SERVICE_USER" || true
            print_success "User $SERVICE_USER created"
        fi
    fi
}

download_binary() {
    print_info "Downloading Mobius client..."
    
    # Determine binary name
    if [ "$OS" = "darwin" ]; then
        BINARY_NAME="mobius-client-darwin-${ARCH}"
    else
        BINARY_NAME="mobius-client-linux-${ARCH}"
    fi
    
    # Download binary
    DOWNLOAD_FILE="$DOWNLOAD_URL/$VERSION/${BINARY_NAME}.tar.gz"
    TMP_DIR=$(mktemp -d)
    
    if command -v curl &> /dev/null; then
        curl -sSL -o "$TMP_DIR/mobius-client.tar.gz" "$DOWNLOAD_FILE" || {
            print_error "Failed to download client binary"
            print_info "Attempted to download from: $DOWNLOAD_FILE"
            rm -rf "$TMP_DIR"
            exit 1
        }
    elif command -v wget &> /dev/null; then
        wget -q -O "$TMP_DIR/mobius-client.tar.gz" "$DOWNLOAD_FILE" || {
            print_error "Failed to download client binary"
            rm -rf "$TMP_DIR"
            exit 1
        }
    else
        print_error "curl or wget required to download binary"
        exit 1
    fi
    
    # Extract and install
    tar -xzf "$TMP_DIR/mobius-client.tar.gz" -C "$TMP_DIR"
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/mobius-client"
    chmod +x "$INSTALL_DIR/mobius-client"
    
    # Cleanup
    rm -rf "$TMP_DIR"
    
    print_success "Binary installed to $INSTALL_DIR/mobius-client"
}

enroll_client() {
    print_info "Enrolling client with server..."
    
    "$INSTALL_DIR/mobius-client" enroll \
        --server="$MOBIUS_SERVER" \
        --key="$ENROLLMENT_KEY" \
        --config="$CONFIG_DIR/client.yaml" || {
        print_error "Enrollment failed"
        exit 1
    }
    
    print_success "Client enrolled successfully"
}

install_service() {
    print_info "Installing system service..."
    
    if [ "$OS" = "darwin" ]; then
        # macOS launchd
        cat > "/Library/LaunchDaemons/com.mobius.client.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mobius.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/mobius-client</string>
        <string>start</string>
        <string>--config=$CONFIG_DIR/client.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/client.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/client-error.log</string>
</dict>
</plist>
EOF
        chmod 644 "/Library/LaunchDaemons/com.mobius.client.plist"
        print_success "launchd service installed"
        
    elif command -v systemctl &> /dev/null; then
        # Linux systemd
        cat > "/etc/systemd/system/mobius-client.service" <<EOF
[Unit]
Description=Mobius Client Daemon
Documentation=https://docs.mobius.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/mobius-client start --config=$CONFIG_DIR/client.yaml
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/client.log
StandardError=append:$LOG_DIR/client-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR $LOG_DIR $DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "/etc/systemd/system/mobius-client.service"
        systemctl daemon-reload
        print_success "systemd service installed"
        
    else
        print_warning "Systemd not found, service not installed"
        print_warning "You'll need to start the client manually:"
        print_warning "  $INSTALL_DIR/mobius-client start --config=$CONFIG_DIR/client.yaml"
        return
    fi
}

start_service() {
    print_info "Starting Mobius client service..."
    
    if [ "$OS" = "darwin" ]; then
        launchctl load "/Library/LaunchDaemons/com.mobius.client.plist"
        print_success "Service started"
    elif command -v systemctl &> /dev/null; then
        systemctl enable mobius-client
        systemctl start mobius-client
        print_success "Service started and enabled"
    else
        print_warning "Please start the client manually"
    fi
}

show_status() {
    echo ""
    echo -e "${GREEN}"
    echo "================================================"
    echo "  Installation Complete!"
    echo "================================================"
    echo -e "${NC}"
    echo ""
    echo "Service status:"
    if [ "$OS" = "darwin" ]; then
        launchctl list | grep com.mobius.client || echo "  Service not running"
    elif command -v systemctl &> /dev/null; then
        systemctl status mobius-client --no-pager || true
    fi
    echo ""
    echo "Logs available at: $LOG_DIR/"
    echo "Configuration: $CONFIG_DIR/client.yaml"
    echo ""
    echo "Useful commands:"
    if [ "$OS" = "darwin" ]; then
        echo "  View logs:     tail -f $LOG_DIR/client.log"
        echo "  Restart:       sudo launchctl unload /Library/LaunchDaemons/com.mobius.client.plist && sudo launchctl load /Library/LaunchDaemons/com.mobius.client.plist"
        echo "  Stop:          sudo launchctl unload /Library/LaunchDaemons/com.mobius.client.plist"
    else
        echo "  View logs:     sudo journalctl -u mobius-client -f"
        echo "  Restart:       sudo systemctl restart mobius-client"
        echo "  Stop:          sudo systemctl stop mobius-client"
        echo "  Status:        sudo systemctl status mobius-client"
    fi
    echo ""
}

# Main installation
main() {
    print_header
    check_root
    detect_os
    parse_args "$@"
    create_directories
    create_user
    download_binary
    enroll_client
    install_service
    start_service
    show_status
}

main "$@"
