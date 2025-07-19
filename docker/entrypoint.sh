#!/bin/sh
set -e

# Hardened entrypoint script for QAVPN Relay
# Implements security best practices and proper startup sequence

# Security: Set strict umask
umask 077

# Environment validation
validate_environment() {
    echo "Validating environment..."
    
    # Check required directories exist
    if [ ! -d "/etc/qavpn" ]; then
        echo "ERROR: Configuration directory /etc/qavpn not found"
        exit 1
    fi
    
    # Validate binary exists and is executable
    if [ ! -x "/usr/local/bin/qavpn-relay" ]; then
        echo "ERROR: QAVPN relay binary not found or not executable"
        exit 1
    fi
    
    # Check network connectivity to bootstrap nodes
    echo "Testing connectivity to bootstrap nodes..."
    for node in bootstrap1.qavpn.net bootstrap2.qavpn.net bootstrap3.qavpn.net; do
        if nc -z -w5 "$node" 9051 2>/dev/null; then
            echo "✓ Connected to $node"
            break
        else
            echo "⚠ Cannot reach $node"
        fi
    done
    
    echo "Environment validation complete"
}

# Security hardening
apply_security_hardening() {
    echo "Applying security hardening..."
    
    # Set resource limits (if running as root, which we shouldn't be)
    if [ "$(id -u)" = "0" ]; then
        echo "WARNING: Running as root - this is not recommended"
        # Apply additional restrictions if somehow running as root
        ulimit -n 1024    # Limit file descriptors
        ulimit -u 32      # Limit processes
        ulimit -m 512000  # Limit memory (500MB)
    fi
    
    # Verify we're running as non-root user
    if [ "$(id -u)" = "0" ]; then
        echo "ERROR: Container should not run as root user"
        exit 1
    fi
    
    echo "Security hardening applied"
}

# Configuration setup
setup_configuration() {
    echo "Setting up configuration..."
    
    # Use environment variables to override config if provided
    CONFIG_FILE="/etc/qavpn/config"
    
    # Create runtime config from template
    if [ -f "$CONFIG_FILE" ]; then
        echo "Using existing configuration file"
    else
        echo "Creating default configuration"
        cat > "$CONFIG_FILE" << EOF
# QAVPN Relay Configuration - Docker Container
# Auto-generated configuration for hardened relay

# Relay configuration
relay_port=${QAVPN_RELAY_PORT:-9051}
protocol=${QAVPN_PROTOCOL:-tcp}

# Security settings
log_level=${QAVPN_LOG_LEVEL:-1}

# Network settings - optimized for container
desired_hops=3
client_port=9050

# Direct mode disabled for relay-only container
direct_mode_enabled=false
EOF
    fi
    
    # Set secure permissions
    chmod 600 "$CONFIG_FILE"
    
    echo "Configuration setup complete"
}

# Health check function
health_check() {
    echo "Performing health check..."
    
    # Check if relay process would start (dry run)
    if /usr/local/bin/qavpn-relay version >/dev/null 2>&1; then
        echo "✓ Binary health check passed"
    else
        echo "✗ Binary health check failed"
        return 1
    fi
    
    # Check port availability
    if netstat -ln 2>/dev/null | grep -q ":${QAVPN_RELAY_PORT:-9051}"; then
        echo "⚠ Port ${QAVPN_RELAY_PORT:-9051} already in use"
    else
        echo "✓ Port ${QAVPN_RELAY_PORT:-9051} available"
    fi
    
    echo "Health check complete"
}

# Signal handlers for graceful shutdown
cleanup() {
    echo "Received shutdown signal, cleaning up..."
    
    # Kill any background processes
    if [ -n "$RELAY_PID" ]; then
        echo "Stopping relay process (PID: $RELAY_PID)"
        kill -TERM "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi
    
    echo "Cleanup complete"
    exit 0
}

# Set up signal handlers
trap cleanup TERM INT QUIT

# Main execution
main() {
    echo "Starting QAVPN Hardened Relay Container"
    echo "======================================="
    
    # Run startup sequence
    validate_environment
    apply_security_hardening
    setup_configuration
    health_check
    
    echo "Starting QAVPN relay with arguments: $*"
    
    # Start the relay process
    if [ "$1" = "relay" ]; then
        # Default relay startup
        exec /usr/local/bin/qavpn-relay relay \
            -port "${QAVPN_RELAY_PORT:-9051}" \
            -protocol "${QAVPN_PROTOCOL:-tcp}" \
            ${QAVPN_VERBOSE:+-verbose}
    else
        # Pass through any other commands
        exec /usr/local/bin/qavpn-relay "$@"
    fi
}

# Execute main function with all arguments
main "$@"
