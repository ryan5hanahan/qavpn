# Design Document

## Overview

The Quantum Anonymous VPN (QAVPN) is a minimal, security-first VPN implementation that combines post-quantum cryptography, multi-hop routing, and advanced privacy features. The design prioritizes simplicity, auditability, and maximum security with minimal code complexity.

## Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Node   │────│  Relay Nodes    │────│ Destination     │
│                 │    │  (Multi-hop)    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────── PQC Encrypted Tunnels ──────────────┘
```

The system consists of three main components:
1. **Client Node** - User's entry point with minimal CLI interface
2. **Relay Network** - Distributed nodes providing multi-hop routing
3. **Protocol Engine** - Core cryptographic and networking logic

### Minimal File Structure

```
qavpn/
├── main.go           # Entry point and CLI
├── crypto.go         # PQC implementation
├── network.go        # TCP/UDP handling and routing
├── node.go           # Node management and relay logic
└── config.go         # Configuration and constants
```

## Components and Interfaces

### 1. Cryptographic Engine (crypto.go)

**Purpose**: Handle all PQC operations with minimal dependencies

**Key Functions**:
- `GenerateKeyPair()` - CRYSTALS-Kyber key generation
- `EncryptPacket(data, pubkey)` - Packet-level encryption
- `DecryptPacket(encrypted, privkey)` - Packet decryption
- `GenerateNoise()` - Random noise packet generation

**Implementation Strategy**: Use Go's crypto/rand and implement CRYSTALS-Kyber directly to avoid external dependencies.

### 2. Network Engine (network.go)

**Purpose**: Handle TCP/UDP protocols and packet management

**Key Functions**:
- `CreateTunnel(protocol, endpoint)` - Establish encrypted tunnels
- `ShardPacket(data)` - Split packets across multiple routes
- `InjectNoise(packets)` - Add noise packets to traffic
- `RoutePacket(packet, hops)` - Multi-hop routing logic

**Implementation Strategy**: Use Go's net package for both TCP and UDP, implement custom packet sharding algorithm.

### 3. Node Management (node.go)

**Purpose**: Manage relay nodes and routing decisions

**Key Functions**:
- `DiscoverNodes()` - Find available relay nodes
- `SelectRoute(destination)` - Choose 3+ hop path
- `MaintainConnections()` - Keep relay connections alive
- `HandleRelay(packet)` - Process packets as relay node

**Implementation Strategy**: Simple peer discovery using hardcoded bootstrap nodes, dynamic route selection.

### 4. Configuration (config.go)

**Purpose**: System constants and minimal configuration

**Key Constants**:
- Default ports, crypto parameters, routing settings
- Bootstrap node addresses
- Network timeouts and retry logic

### 5. Main Interface (main.go)

**Purpose**: Minimal CLI for user interaction

**Commands**:
- `qavpn start` - Start VPN client
- `qavpn relay` - Run as relay node
- `qavpn status` - Show connection status

## Data Models

### Packet Structure
```go
type QAVPNPacket struct {
    Header    PacketHeader
    Payload   []byte
    Signature []byte
}

type PacketHeader struct {
    Version   uint8
    Type      uint8  // DATA, NOISE, CONTROL
    HopCount  uint8
    NextHop   [32]byte  // Encrypted next hop address
    Timestamp uint64
}
```

### Node Information
```go
type Node struct {
    ID        [32]byte
    PublicKey []byte
    Address   string
    Protocol  string  // "tcp" or "udp"
    LastSeen  time.Time
}
```

### Route Structure
```go
type Route struct {
    Hops      []Node
    Protocol  string
    CreatedAt time.Time
    Active    bool
}
```

## Error Handling

### Security-First Error Handling
- **Fail Secure**: All errors result in connection termination, no data leakage
- **Minimal Logging**: Only log essential operational data, never user traffic
- **Silent Failures**: Avoid revealing system internals to potential attackers

### Error Categories
1. **Crypto Errors**: Key generation, encryption/decryption failures
2. **Network Errors**: Connection timeouts, packet loss, routing failures
3. **Protocol Errors**: Malformed packets, version mismatches

### Recovery Strategy
- Automatic reconnection with new routes
- Fallback to different relay nodes
- Graceful degradation (fewer hops if necessary, but minimum 3)

## Testing Strategy

### Unit Testing
- **Crypto Module**: Test key generation, encryption/decryption roundtrips
- **Network Module**: Test packet sharding, noise injection, protocol handling
- **Node Module**: Test route selection, relay functionality

### Integration Testing
- **End-to-End**: Full client-to-destination communication through relays
- **Multi-Protocol**: Verify TCP and UDP both work correctly
- **Failure Scenarios**: Test network interruptions, node failures

### Security Testing
- **Traffic Analysis Resistance**: Verify noise injection effectiveness
- **Anonymity Verification**: Ensure no single node can correlate traffic
- **Crypto Validation**: Verify PQC implementation correctness

## Implementation Priorities

### Phase 1: Core Functionality
1. Basic PQC encryption/decryption
2. Simple TCP tunnel establishment
3. Single-hop routing (for testing)

### Phase 2: Privacy Features
1. Multi-hop routing (3+ hops)
2. Packet sharding implementation
3. Noise injection system

### Phase 3: Protocol Support
1. UDP protocol support
2. Protocol switching logic
3. Performance optimization

### Phase 4: Hardening
1. Error handling refinement
2. Security audit and fixes
3. Minimal CLI polish

## Security Considerations

### Threat Model
- **Adversary Capabilities**: Nation-state level surveillance, quantum computing
- **Protection Goals**: Complete anonymity, quantum-resistant encryption
- **Assumptions**: At least some relay nodes are honest, bootstrap nodes are trusted

### Key Security Properties
1. **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
2. **Traffic Analysis Resistance**: Noise injection and packet sharding prevent correlation
3. **Quantum Resistance**: PQC algorithms protect against future quantum attacks
4. **Minimal Attack Surface**: Fewer lines of code mean fewer potential vulnerabilities

### Implementation Security
- No external cryptographic libraries (implement PQC directly)
- Constant-time operations where possible
- Secure memory handling (zero sensitive data)
- Minimal privilege requirements