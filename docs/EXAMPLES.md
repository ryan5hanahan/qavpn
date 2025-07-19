# QAVPN Direct Connection Mode - Examples and Scenarios

## Table of Contents

1. [Basic Examples](#basic-examples)
2. [Advanced Configurations](#advanced-configurations)
3. [Real-World Scenarios](#real-world-scenarios)
4. [Automation Scripts](#automation-scripts)
5. [Integration Examples](#integration-examples)
6. [Security Configurations](#security-configurations)

---

## Basic Examples

### Example 1: Simple Home Network Connection

**Scenario**: Connect laptop to desktop computer on home network.

**Desktop (Listener):**
```bash
# Start listener on default port
qavpn direct listen --port 8080

# Generate invitation for laptop
qavpn direct invite --expires 2h --single-use --description "Laptop connection"
```

**Laptop (Connector):**
```bash
# Connect using invitation code
qavpn direct connect --invitation "eyJ2ZXJzaW9uIjoxLCJjb25uZWN0aW9uX2lkIjoi..."

# Verify connection
qavpn direct status
```

**Expected Output:**
```
Connection established successfully!
Role: Connector
Remote: 192.168.1.100:8080
Status: Connected
Encryption: AES-256-GCM with Kyber-1024
```

### Example 2: Quick File Transfer

**Scenario**: Transfer files securely between two computers.

**Computer A (File Server):**
```bash
# Start listener and file server
qavpn direct listen --port 9000 --description "File transfer"
qavpn direct invite --expires 30m --single-use

# Start HTTP file server in background
cd ~/Documents/shared
python3 -m http.server 8000 &
```

**Computer B (File Client):**
```bash
# Connect to file server
qavpn direct connect --invitation "..." --profile "file-transfer"

# Configure browser to use SOCKS proxy (127.0.0.1:1080)
# Then access: http://localhost:8000
```

### Example 3: Remote SSH Access

**Scenario**: SSH to remote computer through secure tunnel.

**Remote Server:**
```bash
# Start listener for SSH access
qavpn direct listen --port 2222 --description "SSH access"
qavpn direct invite --expires 4h --single-use --format qr
```

**Local Client:**
```bash
# Connect to remote server
qavpn direct connect --invitation "..." --profile "ssh-server"

# SSH through SOCKS proxy
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@remote-server
```

---

## Advanced Configurations

### High-Security Configuration

**Maximum Security Setup:**
```bash
# Listener with maximum security
qavpn direct listen \
  --port 8080 \
  --protocol tcp \
  --obfuscation maximum \
  --timing-randomization high \
  --traffic-padding enabled \
  --noise-injection high \
  --key-rotation 15m \
  --audit-log enabled \
  --max-connections 1

# Generate highly secure invitation
qavpn direct invite \
  --expires 30m \
  --single-use \
  --format hex \
  --description "High security session"
```

**Connector Configuration:**
```bash
# Connect with security options
qavpn direct connect \
  --invitation "..." \
  --random-delay 10-60s \
  --keepalive-jitter 30-120s \
  --handshake-timeout 120s \
  --profile "high-security"
```

### Performance-Optimized Configuration

**High-Throughput Setup:**
```bash
# Listener optimized for performance
qavpn direct listen \
  --port 8080 \
  --protocol tcp \
  --buffer-size 128KB \
  --max-connections 10 \
  --keepalive 30s \
  --compression enabled

# Generate performance-focused invitation
qavpn direct invite \
  --expires 8h \
  --multi-use \
  --description "High performance session"
```

**Connector Configuration:**
```bash
# Connect with performance options
qavpn direct connect \
  --invitation "..." \
  --buffer-size 128KB \
  --compression enabled \
  --keepalive 30s \
  --profile "high-performance"
```

### Multi-Protocol Configuration

**UDP and TCP Support:**
```bash
# Start multiple listeners
qavpn direct listen --port 8080 --protocol tcp --profile "tcp-listener" &
qavpn direct listen --port 8081 --protocol udp --profile "udp-listener" &

# Generate invitations for both
qavpn direct invite --expires 2h --description "TCP connection" --listener tcp-listener
qavpn direct invite --expires 2h --description "UDP connection" --listener udp-listener
```

---

## Real-World Scenarios

### Scenario 1: Remote Work Setup

**Company Office (Gateway):**
```bash
#!/bin/bash
# office-gateway.sh

# Start office gateway listener
qavpn direct listen \
  --port 8443 \
  --protocol tcp \
  --bind-address 0.0.0.0 \
  --max-connections 50 \
  --description "Office gateway" \
  --profile "office-gateway"

# Generate daily invitation for employees
qavpn direct invite \
  --expires 24h \
  --multi-use \
  --description "Daily office access $(date +%Y-%m-%d)" \
  --output "/shared/daily-invitation.txt"

echo "Office gateway started. Invitation saved to /shared/daily-invitation.txt"
```

**Employee Home Computer:**
```bash
#!/bin/bash
# connect-to-office.sh

# Read invitation from shared location
INVITATION=$(cat /shared/daily-invitation.txt)

# Connect to office
qavpn direct connect \
  --invitation "$INVITATION" \
  --profile "office-$(date +%Y%m%d)" \
  --retry-attempts 5 \
  --timeout 60s

# Verify connection
if qavpn direct status | grep -q "Connected"; then
    echo "Successfully connected to office network"
    # Configure applications to use proxy
    export http_proxy=socks5://127.0.0.1:1080
    export https_proxy=socks5://127.0.0.1:1080
else
    echo "Failed to connect to office network"
    exit 1
fi
```

### Scenario 2: Development Team Collaboration

**Development Server:**
```bash
#!/bin/bash
# dev-server-setup.sh

# Start development server listener
qavpn direct listen \
  --port 3000 \
  --protocol tcp \
  --max-connections 20 \
  --description "Development server" \
  --profile "dev-server"

# Generate team invitation (valid for one week)
qavpn direct invite \
  --expires 168h \
  --multi-use \
  --description "Dev team access - Week $(date +%U)" \
  --format qr \
  --output "dev-team-invitation.png"

# Start development services
docker-compose up -d
echo "Development server ready. QR code: dev-team-invitation.png"
```

**Developer Workstation:**
```bash
#!/bin/bash
# dev-connect.sh

# Connect to development server
qavpn direct connect \
  --invitation "$DEV_INVITATION" \
  --profile "dev-server-$(whoami)" \
  --timeout 30s

# Set up development environment
export DEV_SERVER_PROXY="socks5://127.0.0.1:1080"

# Configure Git to use proxy for private repositories
git config --global http.proxy $DEV_SERVER_PROXY
git config --global https.proxy $DEV_SERVER_PROXY

echo "Connected to development server"
```

### Scenario 3: Secure Gaming Network

**Game Host:**
```bash
#!/bin/bash
# gaming-host.sh

# Start gaming listener with UDP for low latency
qavpn direct listen \
  --port 7777 \
  --protocol udp \
  --max-connections 16 \
  --keepalive 10s \
  --description "Gaming session" \
  --profile "game-host"

# Generate gaming session invitation
qavpn direct invite \
  --expires 6h \
  --multi-use \
  --description "Gaming session - $(date)" \
  --format text \
  --output "game-invitation.txt"

# Start game server
./game-server --port 25565 --max-players 16

echo "Gaming server ready. Share: $(cat game-invitation.txt)"
```

**Game Client:**
```bash
#!/bin/bash
# gaming-client.sh

GAME_INVITATION="$1"

if [ -z "$GAME_INVITATION" ]; then
    echo "Usage: $0 <invitation-code>"
    exit 1
fi

# Connect to gaming session
qavpn direct connect \
  --invitation "$GAME_INVITATION" \
  --profile "gaming-$(date +%H%M)" \
  --keepalive 10s

# Configure game client to use proxy
echo "Connected to gaming network. Configure game client:"
echo "Proxy: 127.0.0.1:1080 (SOCKS5)"
```

### Scenario 4: IoT Device Management

**IoT Gateway:**
```bash
#!/bin/bash
# iot-gateway.sh

# Start IoT management listener
qavpn direct listen \
  --port 8888 \
  --protocol tcp \
  --bind-address 192.168.1.1 \
  --max-connections 5 \
  --description "IoT management gateway" \
  --profile "iot-gateway"

# Generate long-term management invitation
qavpn direct invite \
  --expires 720h \
  --multi-use \
  --description "IoT management access" \
  --output "/config/iot-management-invitation.txt"

# Start IoT services
systemctl start mosquitto  # MQTT broker
systemctl start node-red   # IoT automation
systemctl start grafana    # Monitoring dashboard

echo "IoT gateway ready. Management invitation saved."
```

**Management Station:**
```bash
#!/bin/bash
# iot-management.sh

# Connect to IoT gateway
qavpn direct connect \
  --invitation "$(cat iot-management-invitation.txt)" \
  --profile "iot-management" \
  --keepalive 60s

# Configure IoT management tools
export MQTT_BROKER="127.0.0.1:1883"  # Through SOCKS proxy
export GRAFANA_URL="http://127.0.0.1:3000"  # Through SOCKS proxy
export NODERED_URL="http://127.0.0.1:1880"  # Through SOCKS proxy

echo "Connected to IoT network. Management interfaces available."
```

---

## Automation Scripts

### Connection Health Monitor

```bash
#!/bin/bash
# connection-monitor.sh

PROFILE_NAME="$1"
CHECK_INTERVAL=30
MAX_FAILURES=3
FAILURE_COUNT=0

if [ -z "$PROFILE_NAME" ]; then
    echo "Usage: $0 <profile-name>"
    exit 1
fi

echo "Monitoring connection health for profile: $PROFILE_NAME"

while true; do
    if qavpn direct status --profile "$PROFILE_NAME" | grep -q "Connected"; then
        echo "$(date): Connection healthy"
        FAILURE_COUNT=0
    else
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
        echo "$(date): Connection failed (attempt $FAILURE_COUNT/$MAX_FAILURES)"
        
        if [ $FAILURE_COUNT -ge $MAX_FAILURES ]; then
            echo "$(date): Maximum failures reached. Attempting reconnection..."
            
            # Try to reconnect using saved profile
            if qavpn direct reconnect --profile "$PROFILE_NAME"; then
                echo "$(date): Reconnection successful"
                FAILURE_COUNT=0
            else
                echo "$(date): Reconnection failed. Manual intervention required."
                # Send notification (email, Slack, etc.)
                notify-send "QAVPN Connection Failed" "Profile $PROFILE_NAME requires attention"
            fi
        fi
    fi
    
    sleep $CHECK_INTERVAL
done
```

### Automatic Invitation Rotation

```bash
#!/bin/bash
# invitation-rotation.sh

ROTATION_INTERVAL=3600  # 1 hour
INVITATION_VALIDITY=7200  # 2 hours
OUTPUT_FILE="/shared/current-invitation.txt"

echo "Starting invitation rotation service"

while true; do
    echo "$(date): Generating new invitation"
    
    # Generate new invitation
    NEW_INVITATION=$(qavpn direct invite \
        --expires ${INVITATION_VALIDITY}s \
        --single-use \
        --description "Auto-rotated invitation $(date)" \
        --format text)
    
    if [ $? -eq 0 ]; then
        echo "$NEW_INVITATION" > "$OUTPUT_FILE"
        echo "$(date): New invitation saved to $OUTPUT_FILE"
        
        # Notify users of new invitation (optional)
        # send-notification "New QAVPN invitation available"
    else
        echo "$(date): Failed to generate invitation"
    fi
    
    sleep $ROTATION_INTERVAL
done
```

### Batch Connection Setup

```bash
#!/bin/bash
# batch-setup.sh

# Configuration file format:
# profile_name:invitation_code:description

CONFIG_FILE="$1"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Usage: $0 <config-file>"
    echo "Config file format: profile_name:invitation_code:description"
    exit 1
fi

echo "Setting up batch connections from $CONFIG_FILE"

while IFS=':' read -r profile invitation description; do
    echo "Setting up connection: $profile ($description)"
    
    # Connect using invitation
    if qavpn direct connect \
        --invitation "$invitation" \
        --profile "$profile" \
        --timeout 60s; then
        echo "✓ Successfully connected: $profile"
    else
        echo "✗ Failed to connect: $profile"
    fi
    
    # Small delay between connections
    sleep 5
done < "$CONFIG_FILE"

echo "Batch setup complete. Connection status:"
qavpn direct status --all
```

---

## Integration Examples

### Docker Integration

**Dockerfile for QAVPN Direct:**
```dockerfile
FROM alpine:latest

# Install QAVPN and dependencies
RUN apk add --no-cache qavpn curl netcat-openbsd

# Create qavpn user
RUN adduser -D -s /bin/sh qavpn

# Copy configuration and scripts
COPY config/ /home/qavpn/.qavpn/
COPY scripts/ /home/qavpn/scripts/

# Set permissions
RUN chown -R qavpn:qavpn /home/qavpn/

USER qavpn
WORKDIR /home/qavpn

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD qavpn direct status || exit 1

# Default command
CMD ["qavpn", "direct", "listen", "--port", "8080"]
```

**Docker Compose Example:**
```yaml
version: '3.8'

services:
  qavpn-listener:
    build: .
    ports:
      - "8080:8080"
    environment:
      - QAVPN_PORT=8080
      - QAVPN_PROTOCOL=tcp
    volumes:
      - ./config:/home/qavpn/.qavpn
      - ./invitations:/home/qavpn/invitations
    restart: unless-stopped
    
  qavpn-connector:
    build: .
    environment:
      - QAVPN_INVITATION_FILE=/invitations/current.txt
    volumes:
      - ./invitations:/invitations:ro
    depends_on:
      - qavpn-listener
    restart: unless-stopped
```

### Kubernetes Integration

**QAVPN Direct Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qavpn-direct-listener
spec:
  replicas: 1
  selector:
    matchLabels:
      app: qavpn-direct-listener
  template:
    metadata:
      labels:
        app: qavpn-direct-listener
    spec:
      containers:
      - name: qavpn
        image: qavpn:latest
        ports:
        - containerPort: 8080
        env:
        - name: QAVPN_MODE
          value: "listener"
        - name: QAVPN_PORT
          value: "8080"
        volumeMounts:
        - name: config
          mountPath: /home/qavpn/.qavpn
        - name: invitations
          mountPath: /invitations
      volumes:
      - name: config
        configMap:
          name: qavpn-config
      - name: invitations
        secret:
          secretName: qavpn-invitations
---
apiVersion: v1
kind: Service
metadata:
  name: qavpn-direct-service
spec:
  selector:
    app: qavpn-direct-listener
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
```

### Systemd Service Integration

**QAVPN Direct Service:**
```ini
# /etc/systemd/system/qavpn-direct.service
[Unit]
Description=QAVPN Direct Connection Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=qavpn
Group=qavpn
ExecStart=/usr/local/bin/qavpn direct listen --port 8080 --config /etc/qavpn/direct.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/qavpn

[Install]
WantedBy=multi-user.target
```

**Service Management:**
```bash
# Install and start service
sudo systemctl enable qavpn-direct
sudo systemctl start qavpn-direct

# Check status
sudo systemctl status qavpn-direct

# View logs
sudo journalctl -u qavpn-direct -f
```

---

## Security Configurations

### Maximum Security Profile

**Ultra-High Security Configuration:**
```bash
#!/bin/bash
# ultra-secure-setup.sh

# Generate new key pair for this session
qavpn direct keygen --algorithm ed25519 --output session-keys

# Start listener with maximum security
qavpn direct listen \
  --port 8080 \
  --protocol tcp \
  --key-file session-keys \
  --obfuscation maximum \
  --timing-randomization high \
  --traffic-padding enabled \
  --noise-injection maximum \
  --key-rotation 5m \
  --perfect-forward-secrecy \
  --audit-log enabled \
  --log-level security \
  --max-connections 1 \
  --single-session \
  --auto-disconnect 3600s

# Generate ultra-secure invitation
qavpn direct invite \
  --expires 15m \
  --single-use \
  --format hex \
  --require-confirmation \
  --description "Ultra-secure session $(date)"

echo "Ultra-secure session configured"
echo "Key rotation: 5 minutes"
echo "Auto-disconnect: 1 hour"
echo "Single connection only"
```

### Corporate Security Profile

**Enterprise Security Configuration:**
```bash
#!/bin/bash
# corporate-setup.sh

# Corporate security settings
qavpn direct listen \
  --port 8443 \
  --protocol tcp \
  --obfuscation medium \
  --traffic-padding enabled \
  --key-rotation 30m \
  --audit-log enabled \
  --log-level info \
  --max-connections 100 \
  --connection-timeout 8h \
  --idle-timeout 1h

# Generate business invitation
qavpn direct invite \
  --expires 24h \
  --multi-use \
  --description "Corporate access $(date +%Y-%m-%d)" \
  --require-approval \
  --notify-admin

echo "Corporate security profile active"
echo "Connection limit: 100 concurrent"
echo "Session timeout: 8 hours"
echo "Admin notifications enabled"
```

### Development Security Profile

**Development-Friendly Configuration:**
```bash
#!/bin/bash
# dev-setup.sh

# Balanced security for development
qavpn direct listen \
  --port 3000 \
  --protocol tcp \
  --obfuscation low \
  --key-rotation 2h \
  --audit-log enabled \
  --log-level debug \
  --max-connections 20 \
  --connection-timeout 12h

# Generate development invitation
qavpn direct invite \
  --expires 168h \
  --multi-use \
  --description "Development access - Week $(date +%U)" \
  --format qr

echo "Development security profile active"
echo "Extended session timeout for development work"
echo "Debug logging enabled"
```

### Monitoring and Alerting

**Security Monitoring Script:**
```bash
#!/bin/bash
# security-monitor.sh

LOG_FILE="/var/log/qavpn-security.log"
ALERT_EMAIL="admin@company.com"

# Monitor for security events
qavpn direct monitor --security-events | while read -r event; do
    echo "$(date): $event" >> "$LOG_FILE"
    
    case "$event" in
        *"FAILED_AUTHENTICATION"*)
            echo "Security Alert: Authentication failure detected" | \
                mail -s "QAVPN Security Alert" "$ALERT_EMAIL"
            ;;
        *"SUSPICIOUS_PATTERN"*)
            echo "Security Alert: Suspicious connection pattern" | \
                mail -s "QAVPN Security Alert" "$ALERT_EMAIL"
            ;;
        *"KEY_ROTATION_FAILED"*)
            echo "Security Alert: Key rotation failure" | \
                mail -s "QAVPN Security Alert" "$ALERT_EMAIL"
            ;;
    esac
done
```

---

## Conclusion

These examples demonstrate the flexibility and power of QAVPN Direct Connection Mode across various scenarios:

- **Basic Examples**: Simple setups for common use cases
- **Advanced Configurations**: High-security and high-performance setups
- **Real-World Scenarios**: Complete solutions for business and personal use
- **Automation Scripts**: Tools for managing connections at scale
- **Integration Examples**: Docker, Kubernetes, and systemd integration
- **Security Configurations**: Various security profiles for different environments

Each example can be adapted to your specific needs by modifying the configuration parameters and security settings. Remember to always prioritize security appropriate to your environment and use case.

For more detailed information about specific configuration options, refer to the Technical Documentation and User Guide.
