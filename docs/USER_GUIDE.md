# QAVPN Direct Connection Mode - User Guide

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Step-by-Step Setup](#step-by-step-setup)
3. [Use Cases and Examples](#use-cases-and-examples)
4. [OPSEC Best Practices](#opsec-best-practices)
5. [Migration from Relay Mode](#migration-from-relay-mode)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start Guide

### What is Direct Connection Mode?

QAVPN Direct Connection Mode allows two devices to create a secure, encrypted tunnel directly between each other without using relay servers. This provides:

- **Better Performance**: No relay server bottleneck
- **Enhanced Privacy**: Traffic doesn't pass through third-party servers
- **Lower Latency**: Direct peer-to-peer connection
- **Post-Quantum Security**: Protection against future quantum computers

### 5-Minute Setup

**On Device A (Listener):**
```bash
# 1. Start listening for connections
qavpn direct listen --port 8080

# 2. Generate invitation code
qavpn direct invite --expires 1h --single-use
# Copy the invitation code that appears
```

**On Device B (Connector):**
```bash
# 3. Connect using the invitation code
qavpn direct connect --invitation "eyJ2ZXJzaW9uIjoxLCJjb25uZWN0aW9uX2lkIjoi..."

# 4. Verify connection
qavpn direct status
```

**Both devices now have a secure direct tunnel!**

---

## Step-by-Step Setup

### Prerequisites

- QAVPN installed on both devices
- Network connectivity between devices (same network or internet)
- Secure channel to share invitation codes (Signal, encrypted email, etc.)

### Step 1: Choose Your Setup

#### Option A: Local Network (Recommended for beginners)
- Both devices on same WiFi/LAN
- Faster setup, no firewall configuration needed
- Best for home/office environments

#### Option B: Internet Connection
- Devices on different networks
- Requires port forwarding or UPnP
- Best for remote access scenarios

### Step 2: Configure the Listener

The listener is the device that accepts incoming connections.

```bash
# Basic listener setup
qavpn direct listen --port 8080 --protocol tcp

# Advanced listener with custom settings
qavpn direct listen \
  --port 8080 \
  --protocol tcp \
  --bind-address 0.0.0.0 \
  --max-connections 5 \
  --timeout 30s
```

**Configuration Options:**
- `--port`: Port to listen on (default: 8080)
- `--protocol`: tcp or udp (default: tcp)
- `--bind-address`: IP to bind to (default: 0.0.0.0)
- `--max-connections`: Maximum concurrent connections
- `--timeout`: Connection timeout

### Step 3: Generate Invitation Code

```bash
# Generate basic invitation
qavpn direct invite

# Generate invitation with custom settings
qavpn direct invite \
  --expires 24h \
  --single-use \
  --description "Home office connection" \
  --format qr
```

**Invitation Options:**
- `--expires`: Expiration time (1h, 24h, 7d)
- `--single-use`: Can only be used once
- `--multi-use`: Can be reused multiple times
- `--format`: text, qr, hex
- `--description`: Human-readable description

**Example Output:**
```
Invitation Code Generated Successfully!

Format: Base64 (copy and paste)
Code: eyJ2ZXJzaW9uIjoxLCJjb25uZWN0aW9uX2lkIjoiYWJjZGVmZ2hpams...

Format: QR Code (scan with phone)
[QR CODE DISPLAYED]

Expires: 2025-07-20 09:30:00 UTC
Single Use: Yes
Description: Home office connection

Share this invitation through a secure channel!
```

### Step 4: Share Invitation Securely

**Secure Methods:**
- Signal/WhatsApp encrypted message
- Encrypted email (ProtonMail, Tutanota)
- Password manager shared vault
- In-person QR code scan
- Secure file sharing (Tresorit, SpiderOak)

**Avoid These Methods:**
- Plain text email
- SMS/text messages
- Slack/Discord/Teams
- Social media
- Unencrypted cloud storage

### Step 5: Connect from Second Device

```bash
# Connect using invitation code
qavpn direct connect --invitation "eyJ2ZXJzaW9uIjox..."

# Connect with custom settings
qavpn direct connect \
  --invitation "eyJ2ZXJzaW9uIjox..." \
  --timeout 60s \
  --retry-attempts 3 \
  --profile "home-office"
```

**Connection Process:**
1. Validates invitation signature
2. Establishes network connection
3. Performs post-quantum key exchange
4. Creates encrypted tunnel
5. Starts SOCKS proxy

### Step 6: Verify Connection

```bash
# Check connection status
qavpn direct status

# Detailed connection information
qavpn direct status --verbose

# Monitor connection in real-time
qavpn direct monitor
```

**Example Status Output:**
```
QAVPN Direct Connection Status

Active Connections: 1
┌─────────────────┬──────────┬─────────────────┬──────────────┬─────────────┐
│ Connection ID   │ Role     │ Remote Address  │ Status       │ Uptime      │
├─────────────────┼──────────┼─────────────────┼──────────────┼─────────────┤
│ abc123...       │ Listener │ 192.168.1.100   │ Connected    │ 00:05:23    │
└─────────────────┴──────────┴─────────────────┴──────────────┴─────────────┘

Data Transfer:
  Sent: 1.2 MB
  Received: 856 KB
  
Security:
  Encryption: AES-256-GCM
  Key Exchange: Kyber-1024
  Last Key Rotation: 00:02:15 ago
```

### Step 7: Configure Applications

Once connected, configure your applications to use the SOCKS proxy:

**Proxy Settings:**
- Host: 127.0.0.1 (localhost)
- Port: 1080 (default SOCKS port)
- Type: SOCKS5

**Browser Configuration:**
- Firefox: Settings → Network Settings → Manual proxy
- Chrome: Use system proxy or extensions like SwitchyOmega
- Safari: System Preferences → Network → Advanced → Proxies

---

## Use Cases and Examples

### Use Case 1: Home Office to Corporate Network

**Scenario**: Connect home computer to office network securely.

**Setup:**
```bash
# Office computer (listener)
qavpn direct listen --port 8080 --description "Office gateway"
qavpn direct invite --expires 8h --single-use --description "Home office access"

# Home computer (connector)
qavpn direct connect --invitation "..." --profile "office-connection"
```

**Benefits:**
- Direct connection without VPN server
- Post-quantum encryption
- No corporate VPN client needed

### Use Case 2: Secure File Sharing

**Scenario**: Share files securely between two computers.

**Setup:**
```bash
# Computer A (file server)
qavpn direct listen --port 9090
qavpn direct invite --expires 2h --description "File sharing session"

# Computer B (file client)  
qavpn direct connect --invitation "..."

# Now use any file sharing tool through the secure tunnel
# Example: HTTP file server
python3 -m http.server 8000
# Access via: http://localhost:8000 (through SOCKS proxy)
```

### Use Case 3: Gaming with Friends

**Scenario**: Create secure gaming network for LAN games over internet.

**Setup:**
```bash
# Host computer
qavpn direct listen --port 7777 --protocol udp --max-connections 10
qavpn direct invite --expires 4h --multi-use --description "Gaming session"

# Each player
qavpn direct connect --invitation "..." --profile "gaming-$(date +%Y%m%d)"
```

**Benefits:**
- Low latency direct connections
- No need for dedicated game servers
- Secure communication

### Use Case 4: Remote Development

**Scenario**: Access development environment remotely.

**Setup:**
```bash
# Development server
qavpn direct listen --port 2222 --description "Dev environment"
qavpn direct invite --expires 12h --single-use

# Developer laptop
qavpn direct connect --invitation "..." --profile "dev-server"

# SSH through tunnel (configure SSH client to use SOCKS proxy)
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@dev-server
```

### Use Case 5: IoT Device Management

**Scenario**: Securely manage IoT devices across networks.

**Setup:**
```bash
# IoT gateway device
qavpn direct listen --port 8888 --bind-address 192.168.1.1
qavpn direct invite --expires 30d --multi-use --description "IoT management"

# Management station
qavpn direct connect --invitation "..." --profile "iot-gateway"

# Access IoT devices through secure tunnel
# Web interfaces, MQTT, etc. all work through SOCKS proxy
```

### Use Case 6: Temporary Secure Access

**Scenario**: Provide temporary access to internal resources.

**Setup:**
```bash
# Internal server
qavpn direct listen --port 6666
qavpn direct invite --expires 1h --single-use --description "Contractor access"

# External contractor
qavpn direct connect --invitation "..." --profile "temp-access-$(date +%H%M)"

# Automatic cleanup after expiration
```

---

## OPSEC Best Practices

### Operational Security Guidelines

#### Invitation Code Security

**DO:**
- Use single-use invitations for maximum security
- Set short expiration times (1-24 hours)
- Share invitations through encrypted channels only
- Verify invitation authenticity out-of-band when possible
- Generate new invitations for each connection session

**DON'T:**
- Share invitations through unencrypted channels
- Use long expiration times unless necessary
- Reuse invitations across different security contexts
- Store invitations in plain text files
- Share invitations with untrusted parties

#### Network Security

**Connection Timing:**
```bash
# Enable traffic obfuscation in hostile environments
qavpn direct listen --obfuscation enabled --timing-randomization high

# Use random delays for connection attempts
qavpn direct connect --invitation "..." --random-delay 5-30s
```

**Traffic Analysis Resistance:**
```bash
# Enable traffic padding and noise injection
qavpn direct listen --traffic-padding enabled --noise-injection medium

# Use variable keep-alive intervals
qavpn direct connect --invitation "..." --keepalive-jitter 30-120s
```

#### Configuration Security

**Secure Profile Management:**
```bash
# Use strong passwords for profile encryption
qavpn direct profile create --name "secure-profile" --encrypt-password

# Enable secure deletion of unused profiles
qavpn direct profile delete --name "old-profile" --secure-wipe

# Regular integrity checks
qavpn direct profile verify --all
```

**Backup Security:**
```bash
# Create encrypted backups with separate passwords
qavpn direct export --password "backup-password" --output secure-backup.enc

# Verify backup integrity
qavpn direct import --verify-only --input secure-backup.enc
```

#### Monitoring and Logging

**Security Monitoring:**
```bash
# Monitor for suspicious connection patterns
qavpn direct monitor --security-alerts enabled

# Check for role conflicts and resolution
qavpn direct status --security-summary
```

**Secure Logging:**
```bash
# Enable security audit logging (no sensitive data)
qavpn direct listen --audit-log enabled --log-level security

# Review security events
qavpn direct logs --filter security --last 24h
```

### Threat-Specific Mitigations

#### Against Traffic Analysis

1. **Timing Attacks**
   - Use randomized connection delays
   - Enable jitter in retry mechanisms
   - Vary keep-alive intervals

2. **Size Analysis**
   - Enable traffic padding
   - Use noise injection during idle periods
   - Implement packet sharding for large transfers

3. **Pattern Recognition**
   - Randomize protocol parameters
   - Use adaptive retry strategies
   - Vary connection establishment timing

#### Against Network Surveillance

1. **Connection Metadata**
   - Use traffic obfuscation
   - Implement protocol camouflage
   - Randomize connection patterns

2. **Endpoint Identification**
   - Use dynamic port allocation
   - Implement address rotation where possible
   - Avoid predictable connection schedules

#### Against Cryptographic Attacks

1. **Quantum Resistance**
   - Kyber-1024 post-quantum key exchange
   - Regular key rotation
   - Forward secrecy implementation

2. **Side-Channel Attacks**
   - Constant-time cryptographic operations
   - Secure memory handling
   - Proper key deletion

### Environment-Specific Guidelines

#### High-Security Environments

```bash
# Maximum security configuration
qavpn direct listen \
  --port 8080 \
  --obfuscation maximum \
  --timing-randomization high \
  --traffic-padding enabled \
  --noise-injection high \
  --key-rotation 15m \
  --audit-log enabled

# Single-use, short-lived invitations
qavpn direct invite \
  --expires 30m \
  --single-use \
  --format hex
```

#### Corporate Environments

```bash
# Balanced security and usability
qavpn direct listen \
  --port 8080 \
  --obfuscation medium \
  --traffic-padding enabled \
  --key-rotation 1h \
  --max-connections 10

# Longer-lived invitations for planned access
qavpn direct invite \
  --expires 8h \
  --single-use \
  --description "Business access"
```

#### Home/Personal Use

```bash
# Standard security with good usability
qavpn direct listen \
  --port 8080 \
  --obfuscation low \
  --key-rotation 4h

# Multi-use invitations for family/trusted users
qavpn direct invite \
  --expires 7d \
  --multi-use \
  --description "Family network"
```

---

## Migration from Relay Mode

### Understanding the Differences

| Feature | Relay Mode | Direct Mode |
|---------|------------|-------------|
| **Connection Path** | Client → Relay Server → Client | Client ↔ Client |
| **Performance** | Limited by relay bandwidth | Full peer bandwidth |
| **Latency** | Client-Relay-Client latency | Direct peer latency |
| **Privacy** | Relay sees metadata | No third-party visibility |
| **Setup Complexity** | Simple (just connect) | Moderate (invitation exchange) |
| **Firewall Requirements** | Outbound only | May need port forwarding |

### Migration Planning

#### Step 1: Assess Current Usage

```bash
# Review current relay connections
qavpn status --mode relay

# Check bandwidth and latency requirements
qavpn stats --detailed --last 7d

# Identify connection patterns
qavpn logs --filter connections --analyze
```

#### Step 2: Test Direct Mode

```bash
# Create test profile for direct mode
qavpn direct profile create --name "migration-test"

# Test connection with existing peer
qavpn direct listen --port 8080 --profile "migration-test"
qavpn direct invite --expires 1h --description "Migration test"

# Compare performance
qavpn direct monitor --compare-with-relay
```

#### Step 3: Gradual Migration

**Phase 1: Non-Critical Connections**
- Start with file sharing or development connections
- Test stability and performance
- Gather user feedback

**Phase 2: Regular Use Connections**
- Migrate daily-use connections
- Monitor for issues
- Keep relay as backup

**Phase 3: Critical Connections**
- Migrate business-critical connections
- Ensure redundancy plans
- Complete monitoring setup

### Migration Scenarios

#### Scenario 1: Single User, Multiple Devices

**Current State:**
```
Laptop ←→ Relay Server ←→ Desktop
```

**Target State:**
```
Laptop ←→ Desktop (Direct)
```

**Migration Steps:**
```bash
# On desktop (becomes listener)
qavpn direct listen --port 8080
qavpn direct invite --expires 24h --description "Laptop connection"

# On laptop (becomes connector)
qavpn direct connect --invitation "..."

# Verify and switch applications
qavpn direct status --compare-performance
```

#### Scenario 2: Small Team Network

**Current State:**
```
Device A ←→ Relay Server ←→ Device B
Device C ←→ Relay Server ←→ Device D
```

**Target State:**
```
Device A ←→ Device B (Direct)
Device C ←→ Device D (Direct)
```

**Migration Steps:**
```bash
# Coordinate migration timing
# Set up direct connections in parallel
# Test inter-device communication
# Switch applications gradually
```

#### Scenario 3: Hub-and-Spoke to Mesh

**Current State:**
```
        Relay Server
       /     |     \
   Dev A   Dev B   Dev C
```

**Target State:**
```
Dev A ←→ Dev B
  ↑       ↓
  └─ Dev C ←┘
```

**Migration Steps:**
```bash
# Identify primary connection pairs
# Set up direct connections between pairs
# Configure routing for multi-hop scenarios
# Test full mesh connectivity
```

### Configuration Migration

#### Export Existing Settings

```bash
# Export current configuration
qavpn config export --output current-config.json

# Extract relevant settings for direct mode
qavpn config convert --input current-config.json --output direct-config.json --mode direct
```

#### Adapt Configuration

```bash
# Review and modify direct mode configuration
qavpn direct config edit --file direct-config.json

# Key changes needed:
# - Remove relay server settings
# - Add listener/connector roles
# - Configure invitation parameters
# - Set security levels
```

#### Import and Test

```bash
# Import direct mode configuration
qavpn direct config import --file direct-config.json

# Test configuration
qavpn direct config validate

# Create test connections
qavpn direct test-config --dry-run
```

### Rollback Planning

#### Preparation

```bash
# Keep relay configuration as backup
cp ~/.qavpn/config.json ~/.qavpn/config-relay-backup.json

# Document current connection settings
qavpn config document --output migration-rollback-guide.txt
```

#### Rollback Procedure

```bash
# Stop direct mode connections
qavpn direct disconnect --all

# Restore relay configuration
cp ~/.qavpn/config-relay-backup.json ~/.qavpn/config.json

# Restart in relay mode
qavpn restart --mode relay

# Verify relay connections
qavpn status --verify-connectivity
```

### Performance Comparison

#### Metrics to Monitor

```bash
# Connection establishment time
qavpn direct benchmark --metric connection-time --samples 10

# Data transfer throughput
qavpn direct benchmark --metric throughput --duration 60s

# Latency measurements
qavpn direct benchmark --metric latency --samples 100

# Resource usage
qavpn direct benchmark --metric resources --duration 300s
```

#### Expected Improvements

- **Latency**: 50-80% reduction (no relay hop)
- **Throughput**: 2-5x improvement (no relay bottleneck)
- **Connection Time**: Similar or slightly longer (key exchange)
- **Resource Usage**: Similar CPU, potentially higher memory

---

## Troubleshooting

### Quick Diagnostic Commands

```bash
# Overall system status
qavpn direct diagnose --full-report

# Network connectivity test
qavpn direct test-network --target <peer-ip> --port <port>

# Configuration validation
qavpn direct validate-config --fix-issues

# Connection health check
qavpn direct health-check --connection-id <id>
```

### Common Issues and Solutions

#### "Connection Refused" Errors

**Symptoms:**
- Cannot establish connection to peer
- "Connection refused" or "No route to host" errors

**Diagnosis:**
```bash
# Test basic network connectivity
ping <peer-ip>
telnet <peer-ip> <port>

# Check firewall status
qavpn direct test-firewall --port <port>

# Verify listener is running
qavpn direct status --role listener
```

**Solutions:**
1. **Firewall Configuration:**
   ```bash
   # Linux (iptables)
   sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
   
   # macOS
   sudo pfctl -f /etc/pf.conf
   
   # Windows
   netsh advfirewall firewall add rule name="QAVPN Direct" dir=in action=allow protocol=TCP localport=8080
   ```

2. **Router/NAT Configuration:**
   - Enable UPnP if available
   - Configure port forwarding for listener port
   - Use DMZ as last resort

3. **Network Troubleshooting:**
   ```bash
   # Check routing
   traceroute <peer-ip>
   
   # Test different ports
   qavpn direct listen --port 443  # Try HTTPS port
   qavpn direct listen --port 80   # Try HTTP port
   ```

#### "Handshake Failed" Errors

**Symptoms:**
- Connection established but handshake fails
- Timeout during key exchange

**Diagnosis:**
```bash
# Check handshake details
qavpn direct status --handshake-debug

# Monitor handshake process
qavpn direct monitor --filter handshake

# Verify cryptographic libraries
qavpn direct test-crypto
```

**Solutions:**
1. **Version Compatibility:**
   ```bash
   # Check versions on both peers
   qavpn version --detailed
   
   # Update to latest version
   qavpn update
   ```

2. **Network Quality:**
   ```bash
   # Increase handshake timeout
   qavpn direct connect --invitation "..." --handshake-timeout 120s
   
   # Test with TCP instead of UDP
   qavpn direct listen --protocol tcp
   ```

3. **Clock Synchronization:**
   ```bash
   # Check system time
   date
   
   # Synchronize with NTP
   sudo ntpdate -s time.nist.gov
   ```

#### "Invalid Invitation" Errors

**Symptoms:**
- "Invalid invitation signature" errors
- "Invitation expired" messages
- "Malformed invitation code" errors

**Diagnosis:**
```bash
# Validate invitation format
qavpn direct validate --invitation "..." --verbose

# Check invitation details
qavpn direct inspect --invitation "..."

# Verify signing keys
qavpn direct verify-keys
```

**Solutions:**
1. **Invitation Integrity:**
   ```bash
   # Regenerate invitation
   qavpn direct invite --expires 2h --single-use
   
   # Use different encoding format
   qavpn direct invite --format hex
   
   # Verify copy/paste integrity
   echo "invitation-code" | base64 -d | hexdump -C
   ```

2. **Time Synchronization:**
   ```bash
   # Check time difference between peers
   qavpn direct time-sync --check
   
   # Generate invitation with longer validity
   qavpn direct invite --expires 24h
   ```

#### Performance Issues

**Symptoms:**
- Slow data transfer
- High latency
- Connection drops

**Diagnosis:**
```bash
# Performance benchmarking
qavpn direct benchmark --comprehensive

# Monitor resource usage
qavpn direct monitor --resources

# Check network quality
qavpn direct test-network --quality-check
```

**Solutions:**
1. **Protocol Optimization:**
   ```bash
   # Try UDP for lower latency
   qavpn direct listen --protocol udp
   
   # Adjust buffer sizes
   qavpn direct connect --buffer-size 64KB
   
   # Enable compression
   qavpn direct connect --compression enabled
   ```

2. **Network Tuning:**
   ```bash
   # Optimize TCP settings (Linux)
   echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
   sysctl -p
   
   # Adjust keep-alive settings
   qavpn direct connect --keepalive 30s
   ```

### Advanced Troubleshooting

#### Debug Mode

```bash
# Enable comprehensive debugging
qavpn direct --debug --log-level trace listen --port 8080

# Debug specific components
qavpn direct --debug-crypto --debug-network connect --invitation "..."

# Capture network traffic
qavpn direct --packet-capture /tmp/debug.pcap listen --port 8080
```

#### Log Analysis

```bash
# View recent logs
qavpn direct logs --tail 100

# Filter by error type
qavpn direct logs --filter error --last 1h

# Export logs for analysis
qavpn direct logs --export /tmp/qavpn-debug.log --detailed
```

#### System Information

```bash
# Collect system information
qavpn direct system-info --output system-report.txt

# Network configuration
qavpn direct network-info --detailed

# Cryptographic capabilities
qavpn direct crypto-info --test-performance
```

### Getting Help

#### Community Support

- GitHub Issues: Report bugs and feature requests
- Documentation: Check latest documentation for updates
- Examples: Review example configurations and use cases

#### Professional Support

- Enterprise Support: Available for business users
- Consulting: Architecture and deployment guidance
- Training: Security best practices and advanced usage

#### Self-Help Resources

```bash
# Built-in help system
qavpn direct help
qavpn direct help <command>

# Configuration examples
qavpn direct examples --list
qavpn direct examples --show <example-name>

# Best practices guide
qavpn direct best-practices --interactive
```

---

## Conclusion

QAVPN Direct Connection Mode provides a powerful, secure way to establish peer-to-peer encrypted tunnels. By following this user guide, you can:

- Set up secure direct connections quickly and safely
- Implement OPSEC best practices for maximum security
- Migrate from relay mode with minimal disruption
- Troubleshoot common issues effectively

Remember to always prioritize security when sharing invitation codes and configuring connections. When in doubt, use shorter expiration times and single-use invitations for maximum security.

For additional help, refer to the technical documentation and community resources.
