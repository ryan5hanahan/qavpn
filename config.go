package main

import "fmt"

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
	
	// Direct mode configuration
	DirectMode   *DirectModeConfig `json:"direct_mode,omitempty"`
}

// DirectModeConfig holds direct connection mode configuration
type DirectModeConfig struct {
	Enabled           bool   `json:"enabled"`
	DefaultPort       int    `json:"default_port"`
	DefaultProtocol   string `json:"default_protocol"`
	MaxConnections    int    `json:"max_connections"`
	ConnectionTimeout int    `json:"connection_timeout_seconds"`
	KeepAliveInterval int    `json:"keepalive_interval_seconds"`
	EnableOPSEC       bool   `json:"enable_opsec"`
	ConfigPath        string `json:"config_path"`
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
		DirectMode: &DirectModeConfig{
			Enabled:           false,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        "~/.qavpn/direct",
		},
	}
}

// ValidateConfig validates the configuration for consistency and security
func ValidateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate port ranges with security considerations
	if err := validatePort(config.ClientPort, "client"); err != nil {
		return err
	}
	if err := validatePort(config.RelayPort, "relay"); err != nil {
		return err
	}
	
	// Check for port conflicts
	if config.ClientPort == config.RelayPort {
		return fmt.Errorf("client and relay ports cannot be the same: %d", config.ClientPort)
	}

	if config.DesiredHops < MinRelayHops || config.DesiredHops > MaxRelayHops {
		return fmt.Errorf("desired hops must be between %d and %d", MinRelayHops, MaxRelayHops)
	}

	// Validate protocol security
	if config.Protocol != "tcp" && config.Protocol != "udp" {
		return fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	// Validate log level
	if config.LogLevel < 0 || config.LogLevel > 3 {
		return fmt.Errorf("log level must be between 0 and 3")
	}

	// Validate direct mode configuration if enabled
	if config.DirectMode != nil {
		if err := ValidateDirectModeConfig(config.DirectMode); err != nil {
			return fmt.Errorf("direct mode configuration error: %w", err)
		}

		// Check for port conflicts with direct mode
		if config.DirectMode.Enabled {
			if config.DirectMode.DefaultPort == config.ClientPort {
				return fmt.Errorf("direct mode port conflicts with client port: %d", config.ClientPort)
			}
			if config.DirectMode.DefaultPort == config.RelayPort {
				return fmt.Errorf("direct mode port conflicts with relay port: %d", config.RelayPort)
			}
		}
	}

	return nil
}

// validatePort validates a port number with security considerations
func validatePort(port int, portType string) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid %s port: %d (must be 1-65535)", portType, port)
	}
	
	// Check for privileged ports (require special handling)
	if port < 1024 {
		return fmt.Errorf("%s port %d is privileged (requires root access)", portType, port)
	}
	
	// Check for commonly used system ports
	systemPorts := []int{22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
	for _, sysPort := range systemPorts {
		if port == sysPort {
			return fmt.Errorf("%s port %d conflicts with system service", portType, port)
		}
	}
	
	return nil
}

// ValidateDirectModeConfig validates direct mode specific configuration
func ValidateDirectModeConfig(config *DirectModeConfig) error {
	if config == nil {
		return nil // Direct mode is optional
	}

	if config.DefaultPort <= 0 || config.DefaultPort > 65535 {
		return fmt.Errorf("invalid direct mode port: %d", config.DefaultPort)
	}

	if config.DefaultProtocol != "tcp" && config.DefaultProtocol != "udp" {
		return fmt.Errorf("direct mode protocol must be 'tcp' or 'udp'")
	}

	if config.MaxConnections <= 0 || config.MaxConnections > 1000 {
		return fmt.Errorf("max connections must be between 1 and 1000")
	}

	if config.ConnectionTimeout <= 0 || config.ConnectionTimeout > 300 {
		return fmt.Errorf("connection timeout must be between 1 and 300 seconds")
	}

	if config.KeepAliveInterval <= 0 || config.KeepAliveInterval > 3600 {
		return fmt.Errorf("keep alive interval must be between 1 and 3600 seconds")
	}

	if config.ConfigPath == "" {
		return fmt.Errorf("direct mode config path cannot be empty")
	}

	return nil
}

// MigrateConfig migrates configuration from older versions
func MigrateConfig(config *Config) (*Config, error) {
	// Create a copy to avoid modifying the original
	migratedConfig := *config

	// Ensure DirectMode is initialized
	if migratedConfig.DirectMode == nil {
		migratedConfig.DirectMode = &DirectModeConfig{
			Enabled:           false,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        "~/.qavpn/direct",
		}
	}

	// Migrate any legacy settings
	// (This would include logic for migrating from older config formats)

	// Validate the migrated configuration
	if err := ValidateConfig(&migratedConfig); err != nil {
		return nil, fmt.Errorf("configuration migration failed validation: %w", err)
	}

	return &migratedConfig, nil
}
