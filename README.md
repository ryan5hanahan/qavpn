# Quantum Anonymous VPN (QAVPN)

A minimal, quantum-resistant VPN implementation that combines post-quantum cryptography, multi-hop routing, and advanced privacy features for complete anonymity.

## Features

- **Post-Quantum Cryptography**: Uses CRYSTALS-Kyber for quantum-resistant encryption
- **Multi-Hop Routing**: Routes traffic through 3+ relay nodes for maximum anonymity
- **Traffic Analysis Resistance**: Implements packet sharding and noise injection
- **Dual Protocol Support**: Supports both TCP and UDP protocols
- **Secure Error Handling**: Fail-secure error handling prevents data leakage
- **Automatic Recovery**: Intelligent failover and route recovery mechanisms
- **Minimal Attack Surface**: Clean, auditable codebase with minimal dependencies

## Quick Start

### Installation

1. **Prerequisites**:
   - Go 1.21 or later
   - Linux/macOS operating system

2. **Build from source**:
   ```bash
   git clone <repository-url>
   cd qavpn
   go build -o qavpn
   ```

3. **Install system-wide** (optional):
   ```bash
   sudo cp qavpn /usr/local/bin/
   ```

### Basic Usage

1. **Create configuration file**:
   ```bash
   ./qavpn config
   ```

2. **Start VPN client**:
   ```bash
   ./qavpn start
   ```

3. **Run as relay node**:
   ```bash
   ./qavpn relay
   ```

4. **Check status**:
   ```bash
   ./qavpn status
   ```

## Configuration

### Configuration File

QAVPN uses a simple configuration file located at `~/.qavpn/config`:

```ini
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
```

### Command Line Options

#### Client Mode
```bash
./qavpn start [options]
  -port <port>         Client listening port (default: 9050)
  -hops <number>       Number of relay hops (3-5, default: 3)
  -protocol <tcp|udp>  Transport protocol (default: tcp)
  -verbose             Enable verbose logging
```

#### Relay Mode
```bash
./qavpn relay [options]
  -port <port>         Relay listening port (default: 9051)
  -protocol <tcp|udp>  Transport protocol (default: tcp)
  -verbose             Enable verbose logging
```

## Usage Examples

### Example 1: Basic Client Setup

```bash
# Create default configuration
./qavpn config

# Start VPN client with default settings
./qavpn start

# In another terminal, configure your applications to use SOCKS proxy
# Point applications to localhost:9050
```

### Example 2: High-Security Setup

```bash
# Start client with maximum hops and UDP for lower latency
./qavpn start -hops 5 -protocol udp -verbose

# Monitor connection status
./qavpn status
```

### Example 3: Running a Relay Node

```bash
# Start relay node on custom port
./qavpn relay -port 9052 -verbose

# Relay will automatically register with bootstrap nodes
# and start accepting connections from clients
```

### Example 4: Custom Configuration

```bash
# Edit configuration file
nano ~/.qavpn/config

# Add custom settings:
# client_port=9055
# desired_hops=4
# protocol=udp
# log_level=2

# Start with custom configuration
./qavpn start
```

## Architecture Overview

### System Components

1. **Cryptographic Engine**: Handles post-quantum encryption using CRYSTALS-Kyber
2. **Network Engine**: Manages TCP/UDP tunnels and packet routing
3. **Node Manager**: Discovers and manages relay nodes
4. **Tunnel Manager**: Creates and maintains secure tunnels
5. **Error Handler**: Provides secure error handling and recovery
6. **Connection Monitor**: Monitors system health and performance

### Security Features

#### Post-Quantum Cryptography
- **Key Exchange**: CRYSTALS-Kyber-1024 for quantum-resistant key exchange
- **Symmetric Encryption**: AES-256-GCM for data encryption
- **Forward Secrecy**: New keys generated for each session

#### Anonymity Protection
- **Multi-Hop Routing**: Minimum 3 hops, maximum 5 hops
- **Packet Sharding**: Splits packets across multiple routes
- **Noise Injection**: Adds fake packets to obfuscate traffic patterns
- **Timing Resistance**: Random delays prevent timing analysis

#### Security Hardening
- **Fail-Secure Design**: Errors result in secure shutdown, not data exposure
- **Memory Protection**: Sensitive data cleared from memory immediately
- **Process Isolation**: Minimal privileges and resource limits
- **Secure Logging**: No sensitive data logged

## Network Protocol

### Connection Flow

1. **Bootstrap Discovery**: Client discovers relay nodes from bootstrap servers
2. **Route Selection**: Client selects 3+ relay nodes for multi-hop route
3. **Key Exchange**: Post-quantum key exchange with each relay
4. **Tunnel Establishment**: Secure tunnels created through relay chain
5. **Traffic Routing**: User traffic routed through encrypted tunnel chain

### Packet Format

```
[Header][Encrypted Payload][Authentication Tag]
```

- **Header**: Version, type, hop count, next hop (encrypted)
- **Payload**: User data encrypted with post-quantum algorithms
- **Tag**: Authentication tag for integrity verification

## Deployment Guide

### Production Deployment

#### System Requirements
- **CPU**: 1+ cores (2+ recommended for relay nodes)
- **RAM**: 512MB minimum (1GB+ recommended)
- **Network**: Stable internet connection
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+) or macOS

#### Security Considerations

1. **Firewall Configuration**:
   ```bash
   # Allow QAVPN ports
   sudo ufw allow 9050/tcp  # Client port
   sudo ufw allow 9051/tcp  # Relay port
   ```

2. **User Permissions**:
   ```bash
   # Create dedicated user for QAVPN
   sudo useradd -r -s /bin/false qavpn
   sudo mkdir -p /home/qavpn/.qavpn
   sudo chown -R qavpn:qavpn /home/qavpn
   ```

3. **Systemd Service** (Linux):
   ```ini
   # /etc/systemd/system/qavpn.service
   [Unit]
   Description=Quantum Anonymous VPN
   After=network.target

   [Service]
   Type=simple
   User=qavpn
   ExecStart=/usr/local/bin/qavpn start
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

   ```bash
   sudo systemctl enable qavpn
   sudo systemctl start qavpn
   ```

#### Monitoring and Maintenance

1. **Health Monitoring**:
   ```bash
   # Check system status
   ./qavpn status
   
   # Monitor logs
   tail -f ~/.qavpn/qavpn.log
   ```

2. **Performance Tuning**:
   ```bash
   # Increase file descriptor limits
   echo "qavpn soft nofile 65536" >> /etc/security/limits.conf
   echo "qavpn hard nofile 65536" >> /etc/security/limits.conf
   ```

### Relay Node Setup

#### Public Relay Node

1. **Network Configuration**:
   ```bash
   # Ensure port is accessible from internet
   sudo ufw allow 9051/tcp
   
   # Configure port forwarding if behind NAT
   # Forward external port 9051 to internal port 9051
   ```

2. **Start Relay**:
   ```bash
   ./qavpn relay -port 9051 -verbose
   ```

3. **Monitor Performance**:
   ```bash
   # Check relay statistics
   ./qavpn status
   
   # Monitor resource usage
   htop
   ```

#### Private Relay Network

For organizations wanting to run their own relay network:

1. **Bootstrap Node Setup**:
   ```bash
   # Configure bootstrap nodes in config.go
   var BootstrapNodes = []string{
       "relay1.yourorg.com:9051",
       "relay2.yourorg.com:9051",
       "relay3.yourorg.com:9051",
   }
   ```

2. **Build Custom Version**:
   ```bash
   go build -o qavpn-custom
   ```

## Troubleshooting

### Common Issues

#### Connection Problems

**Issue**: Client cannot connect to relay nodes
```bash
# Check network connectivity
ping relay1.qavpn.net

# Verify port accessibility
telnet relay1.qavpn.net 9051

# Check firewall settings
sudo ufw status
```

**Issue**: High latency or slow connections
```bash
# Try UDP protocol for lower latency
./qavpn start -protocol udp

# Reduce number of hops
./qavpn start -hops 3

# Check system resources
top
```

#### Relay Node Issues

**Issue**: Relay not accepting connections
```bash
# Check if port is bound
netstat -tlnp | grep 9051

# Verify relay is running
ps aux | grep qavpn

# Check logs for errors
tail -f ~/.qavpn/qavpn.log
```

#### Performance Issues

**Issue**: High memory usage
```bash
# Monitor memory usage
free -h

# Check for memory leaks
valgrind ./qavpn start

# Restart service if needed
sudo systemctl restart qavpn
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Start with maximum logging
./qavpn start -verbose

# Or edit config file
echo "log_level=2" >> ~/.qavpn/config
```

### Log Analysis

QAVPN logs are designed to be privacy-preserving:

```bash
# View recent logs
tail -100 ~/.qavpn/qavpn.log

# Search for errors
grep ERROR ~/.qavpn/qavpn.log

# Monitor real-time
tail -f ~/.qavpn/qavpn.log
```

## Security Considerations

### Threat Model

QAVPN is designed to protect against:
- **Network Surveillance**: ISP and government monitoring
- **Traffic Analysis**: Pattern analysis and correlation attacks
- **Quantum Computing**: Future quantum cryptanalysis
- **Relay Compromise**: Individual relay node compromise

### Limitations

QAVPN does NOT protect against:
- **Endpoint Compromise**: Malware on user's device
- **Application-Level Attacks**: Vulnerabilities in user applications
- **Timing Correlation**: Advanced timing analysis (partially mitigated)
- **Global Passive Adversary**: Adversary monitoring all network traffic

### Best Practices

1. **Use with Tor**: Combine QAVPN with Tor for maximum anonymity
2. **Regular Updates**: Keep QAVPN updated to latest version
3. **Secure Endpoints**: Ensure client devices are secure
4. **Diverse Routes**: Use different relay nodes regularly
5. **Monitor Logs**: Watch for unusual activity or errors

## Development

### Building from Source

```bash
# Clone repository
git clone <repository-url>
cd qavpn

# Install dependencies
go mod tidy

# Build
go build -o qavpn

# Run tests
go test ./...

# Run integration tests
go test -tags=integration ./...
```

### Testing

```bash
# Unit tests
go test -v ./...

# Crypto validation tests
go test -v -run TestCryptoImplementationValidation

# Performance tests
go test -v -run TestPerformanceBenchmarks

# Integration tests
go test -v -run TestEndToEndCommunication
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

## License

[License information would go here]

## Support

For support and questions:
- GitHub Issues: [Repository issues page]
- Documentation: [Documentation URL]
- Security Issues: [Security contact]

## Changelog

### Version 0.1.0
- Initial release
- Post-quantum cryptography implementation
- Multi-hop routing
- Traffic analysis resistance
- Integrated system architecture
- Comprehensive testing suite