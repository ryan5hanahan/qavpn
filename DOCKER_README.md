# QAVPN Hardened Relay - Docker Deployment

A hardened Docker container for running QAVPN relay nodes with enhanced security, automatic relay functionality, and connection to the qavpn.net bootstrap network.

## 🔒 Security Features

### Container Hardening
- **Minimal Attack Surface**: Uses distroless base image with only essential components
- **Non-Root Execution**: Runs as unprivileged user (UID 65532)
- **Dropped Capabilities**: All Linux capabilities dropped except essential ones
- **Resource Limits**: CPU, memory, and file descriptor limits enforced
- **Read-Only Filesystem**: Configuration mounted read-only where possible

### Network Security
- **Post-Quantum Cryptography**: CRYSTALS-Kyber-1024 for quantum-resistant encryption
- **Traffic Analysis Resistance**: Packet sharding and noise injection enabled
- **Secure DNS**: Uses Cloudflare DNS (1.1.1.1) for enhanced privacy
- **Bootstrap Network**: Automatically connects to qavpn.net bootstrap nodes

### Application Security
- **Secure Error Handling**: Fail-secure design prevents data leakage
- **Memory Protection**: Sensitive data cleared from memory immediately
- **Connection Monitoring**: Real-time health checks and monitoring
- **Graceful Shutdown**: Proper cleanup on container termination

## 🚀 Quick Start

### Prerequisites
- Docker Engine 20.10+ or Docker Desktop
- Docker Compose v2 (uses `docker compose` command)
- Network connectivity to qavpn.net bootstrap nodes

### Build and Run

```bash
# Clone the repository
git clone <repository-url>
cd secure_connect

# Build and start the hardened relay
docker compose up --build -d

# Check container status
docker compose ps

# View logs
docker compose logs -f qavpn-relay

# Stop the relay
docker compose down
```

### Manual Docker Build

```bash
# Build the image
docker build -t qavpn-relay:latest .

# Run with security hardening
docker run -d \
  --name qavpn-relay-hardened \
  --user 65532:65532 \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --memory 512m \
  --cpus 1.0 \
  -p 9051:9051/tcp \
  -p 9051:9051/udp \
  -e QAVPN_VERBOSE=true \
  qavpn-relay:latest
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QAVPN_RELAY_PORT` | `9051` | Relay listening port |
| `QAVPN_PROTOCOL` | `tcp` | Transport protocol (tcp/udp) |
| `QAVPN_LOG_LEVEL` | `1` | Logging verbosity (0-3) |
| `QAVPN_VERBOSE` | `false` | Enable verbose logging |
| `TZ` | `UTC` | Container timezone |

### Docker Compose Override

Create `docker-compose.override.yml` for custom settings:

```yaml
version: '3.8'
services:
  qavpn-relay:
    environment:
      - QAVPN_RELAY_PORT=9052
      - QAVPN_PROTOCOL=udp
      - QAVPN_LOG_LEVEL=2
    ports:
      - "9052:9052/tcp"
      - "9052:9052/udp"
```

### Custom Configuration

Mount a custom configuration file:

```yaml
volumes:
  - ./my-relay-config.conf:/etc/qavpn/config:ro
```

## 🔍 Monitoring and Health Checks

### Built-in Health Checks

The container includes automatic health checks:

```bash
# Check health status
docker compose exec qavpn-relay /usr/local/bin/qavpn-relay status

# View health check logs
docker inspect qavpn-relay-hardened | jq '.[0].State.Health'
```

### Log Monitoring

```bash
# Follow logs in real-time
docker compose logs -f qavpn-relay

# View specific log levels
docker compose logs qavpn-relay | grep "ERROR\|WARN"

# Export logs for analysis
docker compose logs --no-color qavpn-relay > relay-logs.txt
```

### Performance Monitoring

```bash
# Container resource usage
docker stats qavpn-relay-hardened

# Network connections
docker compose exec qavpn-relay netstat -tlnp

# Process information
docker compose exec qavpn-relay ps aux
```

## 🌐 Network Configuration

### Bootstrap Network

The relay automatically connects to qavpn.net bootstrap nodes:
- `bootstrap1.qavpn.net:9051`
- `bootstrap2.qavpn.net:9051`
- `bootstrap3.qavpn.net:9051`

### Port Configuration

| Port | Protocol | Purpose |
|------|----------|---------|
| 9051 | TCP/UDP | Relay node communication |

### Firewall Rules

Ensure these ports are accessible:

```bash
# UFW (Ubuntu)
sudo ufw allow 9051/tcp
sudo ufw allow 9051/udp

# iptables
sudo iptables -A INPUT -p tcp --dport 9051 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9051 -j ACCEPT
```

## 🛡️ Security Considerations

### Production Deployment

1. **Network Isolation**: Deploy in isolated network segment
2. **Regular Updates**: Keep base images and dependencies updated
3. **Log Monitoring**: Monitor logs for security events
4. **Resource Limits**: Enforce appropriate resource constraints
5. **Backup Strategy**: Regular configuration backups

### Security Scanning

```bash
# Scan image for vulnerabilities
docker scout cves qavpn-relay:latest

# Check for security issues
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image qavpn-relay:latest
```

### Hardening Checklist

- [ ] Container runs as non-root user
- [ ] All unnecessary capabilities dropped
- [ ] Resource limits configured
- [ ] Security options enabled
- [ ] Logs properly configured
- [ ] Health checks working
- [ ] Network policies applied
- [ ] Regular security updates scheduled

## 🔧 Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check container logs
docker compose logs qavpn-relay

# Verify configuration
docker compose config

# Test connectivity to bootstrap nodes
docker compose exec qavpn-relay nc -zv bootstrap1.qavpn.net 9051
```

#### Network Connectivity Issues

```bash
# Check port binding
docker compose port qavpn-relay 9051

# Verify firewall rules
sudo ufw status
sudo iptables -L

# Test external connectivity
telnet <your-server-ip> 9051
```

#### Performance Issues

```bash
# Check resource usage
docker stats qavpn-relay-hardened

# Increase resource limits in docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 1G
```

### Debug Mode

Enable debug logging:

```bash
# Temporary debug mode
docker compose exec qavpn-relay /usr/local/bin/qavpn-relay relay -verbose

# Persistent debug mode
# Set QAVPN_LOG_LEVEL=2 in docker-compose.yml
```

### Container Shell Access

```bash
# Access container shell (limited in distroless)
docker compose exec qavpn-relay sh

# For debugging, use a debug image
docker run -it --rm --entrypoint sh qavpn-relay:latest
```

## 📊 Performance Tuning

### Resource Optimization

```yaml
# Optimized resource limits
deploy:
  resources:
    limits:
      cpus: '1.5'
      memory: 768M
    reservations:
      cpus: '0.5'
      memory: 256M
```

### Network Optimization

```yaml
# Network performance tuning
sysctls:
  - net.core.rmem_max=16777216
  - net.core.wmem_max=16777216
  - net.ipv4.tcp_rmem=4096 87380 16777216
  - net.ipv4.tcp_wmem=4096 65536 16777216
```

## 🔄 Updates and Maintenance

### Updating the Container

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker compose down
docker compose up --build -d

# Verify update
docker compose logs qavpn-relay | head -20
```

### Backup and Restore

```bash
# Backup configuration
docker compose exec qavpn-relay cat /etc/qavpn/config > backup-config.conf

# Backup logs
docker compose logs --no-color qavpn-relay > backup-logs.txt

# Restore configuration
docker compose down
# Edit docker/relay-config.conf
docker compose up -d
```

## 📝 Advanced Configuration

### Custom Entrypoint

Create custom entrypoint for advanced scenarios:

```dockerfile
COPY custom-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh
ENTRYPOINT ["/custom-entrypoint.sh"]
```

### Multi-Stage Builds

The Dockerfile uses multi-stage builds for security:

1. **Builder Stage**: Compiles Go binary with security flags
2. **Runtime Stage**: Minimal distroless image with only the binary

### Security Profiles

Apply additional security profiles:

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor:docker-default
  - seccomp:default
```

## 🆘 Support and Contributing

### Getting Help

1. Check the logs: `docker compose logs qavpn-relay`
2. Review this documentation
3. Check network connectivity to bootstrap nodes
4. Verify firewall and port configuration

### Contributing

1. Fork the repository
2. Create a feature branch
3. Test changes with Docker
4. Submit a pull request

### Security Issues

Report security issues privately to the maintainers.

## 📄 License

[License information would go here]

---

**Note**: This container automatically connects to the qavpn.net bootstrap network for peer discovery. Ensure your network policies allow outbound connections to qavpn.net on port 9051.
