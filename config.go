package main

// Version information
const (
	VersionMajor = 0
	VersionMinor = 1
	VersionPatch = 0
)

// Configuration constants for the Quantum Anonymous VPN
const (
	DefaultClientPort = 9050
	DefaultRelayPort  = 9051
	MinRelayHops      = 3
	MaxRelayHops      = 5
	KeySize           = 32 // bytes
	NonceSize         = 24 // bytes
	MaxPacketSize     = 1500

	// Network timeouts
	ConnectionTimeout    = 30 // seconds
	KeepAliveInterval    = 60 // seconds
	NodeDiscoveryTimeout = 10 // seconds

	// Crypto parameters
	KyberPublicKeySize  = 1568 // CRYSTALS-Kyber-1024 public key size
	KyberPrivateKeySize = 3168 // CRYSTALS-Kyber-1024 private key size
	KyberCiphertextSize = 1568 // CRYSTALS-Kyber-1024 ciphertext size

	// Traffic analysis resistance
	NoisePacketRatio = 0.2 // 20% noise packets
	MinPacketDelay   = 10  // milliseconds
	MaxPacketDelay   = 100 // milliseconds

	// Packet sharding constants
	MaxShardsPerPacket = 8   // Maximum number of shards per packet
	MinShardSize       = 64  // Minimum shard size in bytes
	ShardTimeout       = 300 // Shard reassembly timeout in seconds
)

// Bootstrap node addresses for initial peer discovery
var BootstrapNodes = []string{
	"bootstrap1.qavpn.net:9051",
	"bootstrap2.qavpn.net:9051",
	"bootstrap3.qavpn.net:9051",
}

// Config holds runtime configuration
type Config struct {
	ClientPort  int
	RelayMode   bool
	RelayPort   int
	DesiredHops int
	Protocol    string
	LogLevel    int
}

// NewDefaultConfig creates configuration with default values
func NewDefaultConfig() *Config {
	return &Config{
		ClientPort:  DefaultClientPort,
		RelayMode:   false,
		RelayPort:   DefaultRelayPort,
		DesiredHops: MinRelayHops,
		Protocol:    "tcp",
		LogLevel:    1,
	}
}
