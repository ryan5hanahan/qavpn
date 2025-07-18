package main

import (
	"net"
	"time"
)

// Core data structures for Quantum Anonymous VPN

// Protocol constants
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// Packet types
const (
	PacketTypeData    = 1
	PacketTypeNoise   = 2
	PacketTypeControl = 3
)

// NodeID represents a unique identifier for a relay node
type NodeID [32]byte

// KeyPair represents post-quantum cryptographic keys for a node
type KeyPair struct {
	PublicKey  []byte // Post-quantum public key
	PrivateKey []byte // Post-quantum private key
}

// Node represents a relay node in the network
type Node struct {
	ID        NodeID        // Unique node identifier
	PublicKey []byte        // Post-quantum public key
	Address   string        // Network address (IP:port)
	Protocol  string        // "tcp" or "udp"
	LastSeen  time.Time     // Last successful communication
	Latency   time.Duration // Network latency to this node
}

// Route represents a multi-hop path through the network
type Route struct {
	Hops      []*Node   // Ordered list of relay nodes (minimum 3)
	Protocol  string    // Transport protocol for this route
	CreatedAt time.Time // Route creation timestamp
	Active    bool      // Whether route is currently usable
}

// QAVPNPacket represents the core packet structure
type QAVPNPacket struct {
	Header    PacketHeader // Packet metadata
	Payload   []byte       // Encrypted payload data
	Signature []byte       // Post-quantum signature
}

// PacketHeader contains packet metadata
type PacketHeader struct {
	Version   uint8    // Protocol version
	Type      uint8    // Packet type (DATA, NOISE, CONTROL)
	HopCount  uint8    // Number of remaining hops
	NextHop   [32]byte // Encrypted next hop address
	Timestamp uint64   // Packet creation timestamp
}

// Connection represents a client connection
type Connection struct {
	ID         [16]byte  // Connection identifier
	Route      *Route    // Multi-hop route for this connection
	LocalAddr  net.Addr  // Local endpoint address
	RemoteAddr net.Addr  // Remote endpoint address
	CreatedAt  time.Time // Connection creation time
}

// PacketShard represents a fragment of a sharded packet
type PacketShard struct {
	ShardID     [16]byte // Unique identifier for the original packet
	ShardNum    uint8    // Shard number (0-based)
	TotalShards uint8    // Total number of shards for this packet
	Data        []byte   // Shard payload data
}

// NoisePacket represents a fake packet for traffic analysis resistance
type NoisePacket struct {
	Data      []byte    // Noise packet data
	Timestamp int64     // Packet timestamp (nanoseconds)
	Size      int       // Size of the noise packet
}

// RelayInfo contains information about relay node capabilities
type RelayInfo struct {
	MaxConnections int           // Maximum concurrent connections
	Protocols      []string      // Supported protocols (tcp, udp)
	Uptime         time.Duration // Node uptime
	Load           float64       // Current load (0.0 to 1.0)
}

// CryptoContext holds cryptographic state for a connection
type CryptoContext struct {
	LocalKeyPair    KeyPair   // Local node's key pair
	RemotePublicKey []byte    // Remote node's public key
	SharedSecret    []byte    // Derived shared secret
	CreatedAt       time.Time // Context creation time
}
