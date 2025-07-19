# QAVPN Direct Connection Mode - Technical Documentation

## Table of Contents

1. [API Documentation](#api-documentation)
2. [Architecture Documentation](#architecture-documentation)
3. [Security Documentation](#security-documentation)
4. [Troubleshooting Guide](#troubleshooting-guide)

---

## API Documentation

### Core Interfaces

#### DirectConnectionManager

The primary interface for managing direct connections between peers.

```go
type DirectConnectionManager interface {
    // Connection lifecycle
    StartListener(config *ListenerConfig) error
    StartEnhancedListener(config *ListenerConfig) error
    ConnectToPeer(invitation *InvitationCode) error
    ConnectToPeerEnhanced(invitation *InvitationCode) error
    DisconnectPeer(connectionID string) error

    // Invitation management
    GenerateInvitation(config *InvitationConfig) (*InvitationCode, error)
    ProcessInvitation(invitationData string) (*InvitationCode, error)
    ValidateInvitation(invitation *InvitationCode) error

    // Connection management
    GetActiveConnections() []*DirectConnection
    GetConnectionStatus(connectionID string) (*ConnectionStatus, error)

    // Role management and conflict resolution
    DetectAndResolveRoleConflicts() ([]*RoleConflictResolution, error)
    GetRoleConflictGuidanceForConnection(connectionID string) (*RoleConflictResolution, error)
    ResolveRoleConflictForConnection(connectionID string, preferredRole ConnectionRole) error

    // Configuration
    SaveConnectionProfile(profile *ConnectionProfile) error
    LoadConnectionProfile(name string) (*ConnectionProfile, error)
    DeleteConnectionProfile(name string) error
}
```

**Key Methods:**

- `StartListener()`: Starts listening for incoming direct connections on specified port/protocol
- `ConnectToPeer()`: Establishes outbound connection using invitation code
- `GenerateInvitation()`: Creates cryptographically signed invitation codes for secure peer discovery
- `DetectAndResolveRoleConflicts()`: Automatically resolves role conflicts between listener/connector peers

#### DirectConnectionHandler

Manages individual direct connections with encryption and OPSEC features.

```go
type DirectConnectionHandler interface {
    // Connection management
    Establish() error
    Disconnect() error
    IsHealthy() bool

    // Data transmission
    SendData(data []byte) error
    ReceiveData() ([]byte, error)
    Close() error
    IsActive() bool

    // Handshake and role management
    InitiateHandshake() error
    ProcessHandshakeMessage(messageData []byte) (*HandshakeMessage, error)
    IsHandshakeComplete() bool
    GetHandshakeState() *HandshakeState
    GetRoleConflictGuidance() *RoleConflictResolution

    // OPSEC features
    EnableTrafficObfuscation() error
    SetKeepAliveInterval(interval time.Duration) error
    GetConnectionMetrics() *ConnectionMetrics
}
```

#### SecureConfigManager

Handles encrypted storage and management of connection profiles.

```go
type SecureConfigManager interface {
    // Basic profile management
    SaveProfile(profile *ConnectionProfile) error
    LoadProfile(name string) (*ConnectionProfile, error)
    DeleteProfile(name string) error
    ListProfiles() []string

    // Enhanced profile management
    ListProfilesWithMetadata() ([]*ProfileMetadata, error)
    SearchProfiles(criteria *SearchCriteria) ([]*ConnectionProfile, error)
    GetProfileStatistics() (*ProfileStatistics, error)

    // Security operations
    ChangeEncryptionKey(oldKey, newKey []byte) error
    VerifyIntegrity() error
    SecureWipe() error
    SecureDeleteProfile(name string) error

    // Backup/restore
    ExportProfiles(password []byte) ([]byte, error)
    ImportProfiles(data []byte, password []byte) error
    CreateBackup(password []byte, includeMetadata bool) (*BackupData, error)
    RestoreFromBackup(backupData *BackupData, password []byte, overwriteExisting bool) error
}
```

### Data Types

#### InvitationCode

Secure out-of-band key exchange mechanism with cryptographic signatures.

```go
type InvitationCode struct {
    Version         uint8           `json:"version"`
    ConnectionID    [16]byte        `json:"connection_id"`
    PublicKey       []byte          `json:"public_key"`        // Kyber-1024 public key
    NetworkConfig   *NetworkConfig  `json:"network_config"`
    SecurityParams  *SecurityParams `json:"security_params"`
    ExpirationTime  time.Time       `json:"expiration_time"`
    SingleUse       bool            `json:"single_use"`
    Signature       []byte          `json:"signature"`         // Ed25519 signature
    CreatedAt       time.Time       `json:"created_at"`
}
```

**Key Features:**
- Ed25519 cryptographic signatures for authenticity
- Kyber-1024 post-quantum public keys
- Configurable expiration and single-use enforcement
- JSON serialization with base64 encoding for transport

#### DirectConnection

Represents an active encrypted connection between two peers.

```go
type DirectConnection struct {
    ConnectionID     [16]byte
    Role            ConnectionRole    // Listener or Connector
    State           string
    RemoteAddress   string
    ConnectedAt     time.Time
    LastActivity    time.Time
    BytesSent       uint64
    BytesReceived   uint64
    // Internal fields for encryption and tunneling
}
```

#### ConnectionRole

Defines peer roles in direct connections with conflict resolution.

```go
type ConnectionRole int

const (
    RoleListener ConnectionRole = iota    // Accepts incoming connections
    RoleConnector                        // Initiates outbound connections
    RoleNegotiating                      // Role being negotiated
)
```

**Role Compatibility:**
- Listener ↔ Connector: Compatible
- Listener ↔ Listener: Conflict (auto-resolvable)
- Connector ↔ Connector: Conflict (auto-resolvable)

### Error Handling

The system uses structured error types for different failure categories:

```go
// Connection errors
type ConnectionError struct {
    Code      ErrorCode
    Message   string
    Operation string
    Retryable bool
}

// Cryptographic errors
type CryptographicError struct {
    Code      ErrorCode
    Message   string
    Operation string
}

// Invitation errors
type InvitationError struct {
    Code      ErrorCode
    Message   string
    Operation string
}
```

---

## Architecture Documentation

### System Overview

QAVPN Direct Connection Mode enables peer-to-peer encrypted tunnels without relay servers, using post-quantum cryptography and OPSEC-focused design.

```
┌─────────────────┐         ┌─────────────────┐
│   Peer A        │         │   Peer B        │
│  (Listener)     │◄────────┤  (Connector)    │
│                 │  Direct │                 │
│ ┌─────────────┐ │ Tunnel  │ ┌─────────────┐ │
│ │ Application │ │         │ │ Application │ │
│ └─────────────┘ │         │ └─────────────┘ │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │ SOCKS Proxy │ │         │ │ SOCKS Proxy │ │
│ └─────────────┘ │         │ └─────────────┘ │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │Direct Tunnel│ │         │ │Direct Tunnel│ │
│ └─────────────┘ │         │ └─────────────┘ │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │ Crypto Layer│ │         │ │ Crypto Layer│ │
│ └─────────────┘ │         │ └─────────────┘ │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │OPSEC Network│ │         │ │OPSEC Network│ │
│ └─────────────┘ │         │ └─────────────┘ │
└─────────────────┘         └─────────────────┘
```

### Component Architecture

#### 1. DirectConnectionManager
- **Purpose**: Orchestrates connection lifecycle and peer discovery
- **Responsibilities**:
  - Listener/connector role management
  - Invitation code generation and validation
  - Connection state tracking
  - Role conflict detection and resolution

#### 2. Invitation System
- **Purpose**: Secure out-of-band peer discovery
- **Components**:
  - `InvitationCode`: Cryptographically signed connection parameters
  - `InvitationCodeProcessor`: Encoding/decoding (base64, hex, QR codes)
  - `InvitationCodeSigner`: Ed25519 signature generation/verification

#### 3. Secure Configuration Management
- **Purpose**: Encrypted storage of connection profiles
- **Features**:
  - AES-256-GCM encryption at rest
  - PBKDF2 key derivation with high iteration count
  - HMAC-SHA256 integrity protection
  - Secure deletion with cryptographic wiping

#### 4. Post-Quantum Key Exchange
- **Purpose**: Forward-secure session key establishment
- **Algorithm**: Kyber-1024 (NIST PQC finalist)
- **Features**:
  - Mutual authentication
  - Perfect forward secrecy
  - Automatic key rotation
  - Session key derivation

#### 5. OPSEC Network Layer
- **Purpose**: Traffic analysis resistance
- **Features**:
  - Randomized connection delays
  - Traffic padding and noise injection
  - Exponential backoff with jitter
  - Suspicious pattern avoidance

### Connection Establishment Flow

```
Connector                    Listener
    │                           │
    │ 1. Generate Invitation    │
    │◄──────────────────────────│
    │                           │
    │ 2. TCP/UDP Connect        │
    │──────────────────────────►│
    │                           │
    │ 3. Handshake Init         │
    │──────────────────────────►│
    │                           │
    │ 4. Role Negotiation       │
    │◄─────────────────────────►│
    │                           │
    │ 5. Key Exchange (Kyber)   │
    │◄─────────────────────────►│
    │                           │
    │ 6. Session Established    │
    │◄─────────────────────────►│
    │                           │
    │ 7. Encrypted Data Flow    │
    │◄═════════════════════════►│
```

### Integration with Existing QAVPN

Direct mode integrates seamlessly with existing QAVPN components:

- **Configuration System**: Extended `Config` struct with direct mode parameters
- **SOCKS Proxy**: Direct tunnels work transparently with existing proxy
- **Error Handling**: Uses existing `SecureErrorHandler` framework
- **Logging**: Integrates with existing secure logging system
- **Recovery**: Works with `AutomaticRecoveryManager`

---

## Security Documentation

### Threat Model

#### Threats Addressed

1. **Network Traffic Analysis**
   - **Mitigation**: OPSEC network layer with timing randomization
   - **Implementation**: Random delays, traffic padding, jitter

2. **Man-in-the-Middle Attacks**
   - **Mitigation**: Cryptographic signatures on invitation codes
   - **Implementation**: Ed25519 signatures with out-of-band verification

3. **Quantum Computer Attacks**
   - **Mitigation**: Post-quantum cryptography
   - **Implementation**: Kyber-1024 key exchange

4. **Configuration Compromise**
   - **Mitigation**: Encrypted configuration storage
   - **Implementation**: AES-256-GCM with PBKDF2 key derivation

5. **Replay Attacks**
   - **Mitigation**: Single-use invitation codes with timestamps
   - **Implementation**: Expiration enforcement and nonce tracking

#### Assumptions

- Invitation codes are transmitted through secure out-of-band channels
- Initial peer authentication relies on invitation code signatures
- Network adversary cannot break post-quantum cryptographic primitives
- Local system security (file system permissions, memory protection)

### Cryptographic Implementation

#### Key Exchange Protocol

```
1. Invitation Generation:
   - Generate Kyber-1024 key pair
   - Create invitation with public key
   - Sign invitation with Ed25519 private key

2. Connection Establishment:
   - Verify invitation signature
   - Perform Kyber-1024 key exchange
   - Derive session keys using HKDF

3. Session Communication:
   - Encrypt data with AES-256-GCM
   - Authenticate with HMAC-SHA256
   - Rotate keys periodically
```

#### Key Derivation

```
Master Secret = Kyber-1024-Decapsulate(ciphertext, private_key)
Session Keys = HKDF-Expand(Master Secret, "QAVPN-Direct-v1", 96 bytes)
├── Encryption Key (32 bytes)
├── Authentication Key (32 bytes)
└── IV Seed (32 bytes)
```

#### Configuration Encryption

```
User Password → PBKDF2-SHA256 (100,000 iterations) → Encryption Key
Configuration → AES-256-GCM(key, nonce) → Encrypted Configuration
HMAC-SHA256(Encrypted Configuration) → Integrity Tag
```

### OPSEC Features

#### Traffic Obfuscation

1. **Connection Timing**
   - Random delays before connection attempts
   - Exponential backoff with jitter for retries
   - Randomized keep-alive intervals

2. **Traffic Patterns**
   - Padding to obscure message sizes
   - Noise injection during idle periods
   - Packet sharding for large transfers

3. **Fingerprinting Resistance**
   - Randomized protocol parameters
   - Variable connection establishment timing
   - Adaptive retry strategies

#### Secure Logging

- No sensitive network metadata in logs
- Connection events logged without IP addresses
- Diagnostic information sanitized
- Audit trail for security events only

### Security Best Practices

#### For Users

1. **Invitation Code Handling**
   - Transmit invitation codes through secure channels (Signal, encrypted email)
   - Verify invitation signatures out-of-band when possible
   - Use single-use invitations for maximum security
   - Set short expiration times (1-24 hours)

2. **Configuration Security**
   - Use strong passwords for configuration encryption
   - Enable secure deletion of unused profiles
   - Regular integrity checks of stored configurations
   - Backup configurations with separate passwords

3. **Network Security**
   - Use direct mode over trusted networks when possible
   - Enable traffic obfuscation in hostile environments
   - Monitor connection health and metrics
   - Implement connection timeouts appropriately

#### For Developers

1. **Key Management**
   - Secure key generation with proper entropy
   - Automatic key rotation implementation
   - Secure memory handling for cryptographic material
   - Proper key deletion and wiping

2. **Error Handling**
   - No sensitive information in error messages
   - Structured error types for different failure modes
   - Proper cleanup on connection failures
   - Graceful degradation strategies

---

## Troubleshooting Guide

### Common Issues and Solutions

#### Connection Establishment Problems

**Issue**: "Connection failed: no route to host"
- **Cause**: Network connectivity or firewall blocking
- **Solution**: 
  - Verify network connectivity between peers
  - Check firewall rules for configured ports
  - Try backup addresses if configured
  - Use network diagnostic tools (ping, traceroute)

**Issue**: "Handshake timeout"
- **Cause**: Network latency or packet loss
- **Solution**:
  - Increase handshake timeout in configuration
  - Check network quality and latency
  - Verify both peers are using compatible versions
  - Try different network protocols (TCP vs UDP)

**Issue**: "Role conflict: both listeners"
- **Cause**: Both peers configured as listeners
- **Solution**:
  - Reconfigure one peer as connector
  - Use automatic role negotiation
  - Check invitation code configuration
  - Verify network addresses and ports

#### Invitation Code Issues

**Issue**: "Invalid invitation signature"
- **Cause**: Corrupted invitation or wrong signing key
- **Solution**:
  - Regenerate invitation code
  - Verify invitation transmission integrity
  - Check signing key configuration
  - Validate invitation format (base64/hex)

**Issue**: "Invitation expired"
- **Cause**: Invitation used after expiration time
- **Solution**:
  - Generate new invitation with longer expiration
  - Synchronize clocks between peers
  - Use appropriate expiration times for use case
  - Check system time accuracy

**Issue**: "Single-use invitation already used"
- **Cause**: Attempting to reuse single-use invitation
- **Solution**:
  - Generate new invitation code
  - Use multi-use invitations if appropriate
  - Clear invitation cache if needed
  - Verify invitation uniqueness

#### Cryptographic Errors

**Issue**: "Key exchange failed"
- **Cause**: Incompatible cryptographic implementations
- **Solution**:
  - Verify both peers use same QAVPN version
  - Check post-quantum crypto library versions
  - Regenerate key pairs if corrupted
  - Verify network integrity during key exchange

**Issue**: "Decryption failed"
- **Cause**: Session key mismatch or corruption
- **Solution**:
  - Restart connection to re-establish keys
  - Check for network packet corruption
  - Verify key rotation is synchronized
  - Monitor connection health metrics

#### Configuration Problems

**Issue**: "Failed to load configuration"
- **Cause**: Corrupted or encrypted configuration file
- **Solution**:
  - Verify configuration file integrity
  - Check encryption password
  - Restore from backup if available
  - Regenerate configuration if necessary

**Issue**: "Profile not found"
- **Cause**: Missing or deleted connection profile
- **Solution**:
  - List available profiles
  - Check profile name spelling
  - Restore from backup
  - Create new profile if needed

### Diagnostic Commands

#### Connection Status
```bash
# Check active connections
qavpn direct status

# Get detailed connection information
qavpn direct status --verbose --connection-id <id>

# Monitor connection health
qavpn direct monitor --interval 5s
```

#### Profile Management
```bash
# List all profiles
qavpn direct profile list

# Validate profile integrity
qavpn direct profile validate --name <profile>

# Export profiles for backup
qavpn direct export --password <password> --output backup.enc
```

#### Network Diagnostics
```bash
# Test network connectivity
qavpn direct test-connection --address <ip:port> --protocol tcp

# Validate invitation code
qavpn direct validate --invitation <invitation-code>

# Generate diagnostic report
qavpn direct diagnose --output report.txt
```

### Performance Optimization

#### Connection Performance

1. **Protocol Selection**
   - Use TCP for reliability over unreliable networks
   - Use UDP for low-latency applications
   - Consider network conditions and requirements

2. **Buffer Sizes**
   - Increase buffer sizes for high-throughput applications
   - Optimize for network MTU and bandwidth
   - Monitor memory usage with large buffers

3. **Keep-Alive Settings**
   - Adjust keep-alive intervals based on network
   - Balance between responsiveness and overhead
   - Consider NAT timeout requirements

#### Cryptographic Performance

1. **Key Rotation**
   - Set appropriate key rotation intervals
   - Balance security and performance overhead
   - Monitor CPU usage during key exchange

2. **Encryption Overhead**
   - Profile encryption/decryption performance
   - Consider hardware acceleration if available
   - Optimize for target deployment environment

### Monitoring and Metrics

#### Connection Metrics
- Latency measurements
- Throughput statistics
- Packet loss rates
- Connection uptime
- Error rates and types

#### Security Metrics
- Key rotation frequency
- Handshake success rates
- Authentication failures
- Configuration integrity checks
- Invitation code usage patterns

#### System Metrics
- Memory usage for cryptographic operations
- CPU utilization during key exchange
- Network bandwidth utilization
- File system usage for configurations
- Process resource consumption

### Log Analysis

#### Important Log Events
- Connection establishment/termination
- Handshake phase transitions
- Key exchange completion
- Role conflict resolution
- Configuration changes
- Security events and errors

#### Log Levels
- **ERROR**: Critical failures requiring attention
- **WARN**: Potential issues or degraded performance
- **INFO**: Normal operational events
- **DEBUG**: Detailed diagnostic information

#### Security Considerations for Logs
- No IP addresses or network identifiers
- No cryptographic material or keys
- Sanitized error messages
- Audit trail for security events
- Secure log storage and rotation

---

## Conclusion

This technical documentation provides comprehensive coverage of QAVPN Direct Connection Mode's API, architecture, security model, and operational guidance. The system implements state-of-the-art post-quantum cryptography with OPSEC-focused design for secure peer-to-peer communication.

For additional support or questions, refer to the integration tests and example implementations in the codebase.
