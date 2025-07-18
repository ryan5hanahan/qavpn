#!/bin/bash

# QAVPN Deployment Script
# This script helps deploy QAVPN in various configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
QAVPN_USER="qavpn"
QAVPN_HOME="/home/qavpn"
QAVPN_CONFIG_DIR="$QAVPN_HOME/.qavpn"
QAVPN_BINARY="/usr/local/bin/qavpn"
SYSTEMD_SERVICE="/etc/systemd/system/qavpn.service"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Found Go version: $GO_VERSION"
    
    # Check if systemctl is available (for systemd service)
    if ! command -v systemctl &> /dev/null; then
        log_warning "systemctl not found. Systemd service will not be installed."
    fi
    
    log_success "Dependencies check completed"
}

build_qavpn() {
    log_info "Building QAVPN..."
    
    if [[ ! -f "main.go" ]]; then
        log_error "main.go not found. Please run this script from the QAVPN source directory."
        exit 1
    fi
    
    # Build the binary
    go build -ldflags "-s -w" -o qavpn
    
    if [[ ! -f "qavpn" ]]; then
        log_error "Failed to build QAVPN binary"
        exit 1
    fi
    
    log_success "QAVPN built successfully"
}

create_user() {
    log_info "Creating QAVPN user..."
    
    # Create user if it doesn't exist
    if ! id "$QAVPN_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$QAVPN_HOME" "$QAVPN_USER"
        log_success "Created user: $QAVPN_USER"
    else
        log_info "User $QAVPN_USER already exists"
    fi
    
    # Create home directory
    mkdir -p "$QAVPN_HOME"
    mkdir -p "$QAVPN_CONFIG_DIR"
    
    # Set permissions
    chown -R "$QAVPN_USER:$QAVPN_USER" "$QAVPN_HOME"
    chmod 700 "$QAVPN_CONFIG_DIR"
    
    log_success "User setup completed"
}

install_binary() {
    log_info "Installing QAVPN binary..."
    
    # Copy binary to system location
    cp qavpn "$QAVPN_BINARY"
    chmod 755 "$QAVPN_BINARY"
    chown root:root "$QAVPN_BINARY"
    
    log_success "Binary installed to $QAVPN_BINARY"
}

create_config() {
    log_info "Creating default configuration..."
    
    # Create config file if it doesn't exist
    if [[ ! -f "$QAVPN_CONFIG_DIR/config" ]]; then
        cat > "$QAVPN_CONFIG_DIR/config" << EOF
# QAVPN Configuration File
# Lines starting with # are comments

# Client configuration
client_port=9050
desired_hops=3
protocol=tcp

# Relay configuration  
relay_port=9051

# Logging (0=quiet, 1=normal, 2=verbose)
log_level=1
EOF
        
        chown "$QAVPN_USER:$QAVPN_USER" "$QAVPN_CONFIG_DIR/config"
        chmod 600 "$QAVPN_CONFIG_DIR/config"
        
        log_success "Default configuration created"
    else
        log_info "Configuration file already exists"
    fi
}

create_systemd_service() {
    if ! command -v systemctl &> /dev/null; then
        log_warning "Systemctl not available, skipping systemd service creation"
        return
    fi
    
    log_info "Creating systemd service..."
    
    # Determine service type based on user input
    local service_type="client"
    if [[ "$1" == "relay" ]]; then
        service_type="relay"
    fi
    
    # Create systemd service file
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=Quantum Anonymous VPN ($service_type mode)
After=network.target
Wants=network.target

[Service]
Type=simple
User=$QAVPN_USER
Group=$QAVPN_USER
WorkingDirectory=$QAVPN_HOME
ExecStart=$QAVPN_BINARY $service_type
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$QAVPN_CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable qavpn.service
    
    log_success "Systemd service created and enabled"
}

configure_firewall() {
    log_info "Configuring firewall..."
    
    # Check if ufw is available
    if command -v ufw &> /dev/null; then
        # Allow QAVPN ports
        ufw allow 9050/tcp comment "QAVPN Client"
        ufw allow 9051/tcp comment "QAVPN Relay"
        log_success "UFW firewall rules added"
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL firewall
        firewall-cmd --permanent --add-port=9050/tcp
        firewall-cmd --permanent --add-port=9051/tcp
        firewall-cmd --reload
        log_success "Firewalld rules added"
    else
        log_warning "No supported firewall found. Please manually open ports 9050 and 9051"
    fi
}

run_tests() {
    log_info "Running tests..."
    
    # Run unit tests
    if go test -v ./...; then
        log_success "All tests passed"
    else
        log_error "Some tests failed"
        return 1
    fi
}

show_usage() {
    echo "QAVPN Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo ""
    echo "Commands:"
    echo "  install-client    Install QAVPN as a client"
    echo "  install-relay     Install QAVPN as a relay node"
    echo "  uninstall         Remove QAVPN installation"
    echo "  test              Run tests only"
    echo "  build             Build binary only"
    echo ""
    echo "Options:"
    echo "  --no-service      Don't create systemd service"
    echo "  --no-firewall     Don't configure firewall"
    echo "  --no-user         Don't create dedicated user"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 install-client                 # Install as VPN client"
    echo "  $0 install-relay --no-firewall    # Install as relay without firewall config"
    echo "  $0 test                           # Run tests only"
}

install_client() {
    log_info "Installing QAVPN Client..."
    
    check_dependencies
    build_qavpn
    
    if [[ "$NO_USER" != "true" ]]; then
        create_user
    fi
    
    install_binary
    create_config
    
    if [[ "$NO_SERVICE" != "true" ]]; then
        create_systemd_service "client"
    fi
    
    if [[ "$NO_FIREWALL" != "true" ]]; then
        configure_firewall
    fi
    
    log_success "QAVPN Client installation completed!"
    echo ""
    echo "Next steps:"
    echo "1. Edit configuration: $QAVPN_CONFIG_DIR/config"
    echo "2. Start service: sudo systemctl start qavpn"
    echo "3. Check status: sudo systemctl status qavpn"
    echo "4. View logs: journalctl -u qavpn -f"
}

install_relay() {
    log_info "Installing QAVPN Relay Node..."
    
    check_dependencies
    build_qavpn
    
    if [[ "$NO_USER" != "true" ]]; then
        create_user
    fi
    
    install_binary
    create_config
    
    if [[ "$NO_SERVICE" != "true" ]]; then
        create_systemd_service "relay"
    fi
    
    if [[ "$NO_FIREWALL" != "true" ]]; then
        configure_firewall
    fi
    
    log_success "QAVPN Relay Node installation completed!"
    echo ""
    echo "Next steps:"
    echo "1. Edit configuration: $QAVPN_CONFIG_DIR/config"
    echo "2. Start service: sudo systemctl start qavpn"
    echo "3. Check status: sudo systemctl status qavpn"
    echo "4. Monitor relay: $QAVPN_BINARY status"
}

uninstall() {
    log_info "Uninstalling QAVPN..."
    
    # Stop and disable service
    if command -v systemctl &> /dev/null && [[ -f "$SYSTEMD_SERVICE" ]]; then
        systemctl stop qavpn.service || true
        systemctl disable qavpn.service || true
        rm -f "$SYSTEMD_SERVICE"
        systemctl daemon-reload
        log_info "Systemd service removed"
    fi
    
    # Remove binary
    if [[ -f "$QAVPN_BINARY" ]]; then
        rm -f "$QAVPN_BINARY"
        log_info "Binary removed"
    fi
    
    # Remove user and home directory
    if id "$QAVPN_USER" &>/dev/null; then
        userdel -r "$QAVPN_USER" 2>/dev/null || true
        log_info "User removed"
    fi
    
    # Remove firewall rules
    if command -v ufw &> /dev/null; then
        ufw delete allow 9050/tcp 2>/dev/null || true
        ufw delete allow 9051/tcp 2>/dev/null || true
    fi
    
    log_success "QAVPN uninstalled successfully"
}

# Parse command line arguments
NO_SERVICE="false"
NO_FIREWALL="false"
NO_USER="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-service)
            NO_SERVICE="true"
            shift
            ;;
        --no-firewall)
            NO_FIREWALL="true"
            shift
            ;;
        --no-user)
            NO_USER="true"
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        install-client)
            COMMAND="install-client"
            shift
            ;;
        install-relay)
            COMMAND="install-relay"
            shift
            ;;
        uninstall)
            COMMAND="uninstall"
            shift
            ;;
        test)
            COMMAND="test"
            shift
            ;;
        build)
            COMMAND="build"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Execute command
case "$COMMAND" in
    install-client)
        check_root
        install_client
        ;;
    install-relay)
        check_root
        install_relay
        ;;
    uninstall)
        check_root
        uninstall
        ;;
    test)
        run_tests
        ;;
    build)
        build_qavpn
        ;;
    *)
        log_error "No command specified"
        show_usage
        exit 1
        ;;
esac