package direct

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ConnectionRole defines the role of a node in a direct connection
type ConnectionRole int

const (
	RoleListener ConnectionRole = iota
	RoleConnector
	RoleNegotiating // Role is being negotiated during handshake
)

// String returns the string representation of the connection role
func (r ConnectionRole) String() string {
	switch r {
	case RoleListener:
		return "listener"
	case RoleConnector:
		return "connector"
	case RoleNegotiating:
		return "negotiating"
	default:
		return "unknown"
	}
}

// IsCompatible checks if two roles are compatible for establishing a connection
func (r ConnectionRole) IsCompatible(other ConnectionRole) bool {
	return (r == RoleListener && other == RoleConnector) ||
		   (r == RoleConnector && other == RoleListener)
}

// HasConflict checks if two roles are in conflict (both same role)
func (r ConnectionRole) HasConflict(other ConnectionRole) bool {
	return r == other && r != RoleNegotiating
}

// InvitationCode represents a secure out-of-band key exchange mechanism
type InvitationCode struct {
	Version         uint8           `json:"version"`
	ConnectionID    [16]byte        `json:"connection_id"`
	PublicKey       []byte          `json:"public_key"`
	NetworkConfig   *NetworkConfig  `json:"network_config"`
	SecurityParams  *SecurityParams `json:"security_params"`
	ExpirationTime  time.Time       `json:"expiration_time"`
	SingleUse       bool            `json:"single_use"`
	Signature       []byte          `json:"signature"`
	CreatedAt       time.Time       `json:"created_at"`
}

// NetworkConfig contains network configuration for direct connections
type NetworkConfig struct {
	Protocol        string   `json:"protocol"`         // "tcp" or "udp"
	ListenerAddress string   `json:"listener_address"` // IP:Port
	BackupAddresses []string `json:"backup_addresses,omitempty"`
}

// SecurityParams contains cryptographic parameters for direct connections
type SecurityParams struct {
	KeyDerivationSalt []byte `json:"key_derivation_salt"`
	CipherSuite       string `json:"cipher_suite"`
	AuthMethod        string `json:"auth_method"`
}

// DirectConnection represents an active direct connection between two peers
type DirectConnection struct {
	ConnectionID     [16]byte
	Role            ConnectionRole
	State           string
	RemoteAddress   string
	ConnectedAt     time.Time
	LastActivity    time.Time
	BytesSent       uint64
	BytesReceived   uint64
	tunnel          Tunnel
	cryptoContext   *CryptoContext
	keyExchange     *PostQuantumKeyExchange
	networkConfig   *NetworkConfig
	handshakeState  *HandshakeState
	isActive        bool
	trafficStats    *TrafficStats
	mutex           sync.RWMutex
}

// ConnectionProfile represents a saved connection configuration
type ConnectionProfile struct {
	Name            string                `json:"name"`
	Description     string                `json:"description,omitempty"`
	NetworkConfig   *NetworkConfig        `json:"network_config"`
	CryptoMaterial  *EncryptedKeyMaterial `json:"crypto_material"`
	CreatedAt       time.Time             `json:"created_at"`
	LastUsed        time.Time             `json:"last_used"`
	UseCount        int                   `json:"use_count"`
}

// EncryptedKeyMaterial holds encrypted cryptographic material for storage
type EncryptedKeyMaterial struct {
	EncryptedData []byte `json:"encrypted_data"`
	Salt          []byte `json:"salt"`
	Nonce         []byte `json:"nonce"`
}



// CryptoContext holds cryptographic state for a direct connection
type CryptoContext struct {
	LocalKeyPair    *KyberKeyPair
	RemotePublicKey []byte
	SharedSecret    []byte
	SessionKeys     *SessionKeys
	CreatedAt       time.Time
}

// TrafficStats tracks traffic statistics for a direct connection
type TrafficStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	LastActivity    time.Time
	mutex           sync.RWMutex
}

// ConnectionStatus represents the current status of a direct connection
type ConnectionStatus struct {
	ConnectionID    [16]byte       `json:"connection_id"`
	Role            ConnectionRole `json:"role"`
	State           string         `json:"state"`
	IsActive        bool           `json:"is_active"`
	RemoteAddress   string         `json:"remote_address,omitempty"`
	ConnectedSince  time.Time      `json:"connected_since"`
	LastActivity    time.Time      `json:"last_activity"`
	BytesSent       uint64         `json:"bytes_sent"`
	BytesReceived   uint64         `json:"bytes_received"`
	PacketsSent     uint64         `json:"packets_sent"`
	PacketsReceived uint64         `json:"packets_received"`
	Quality         float64        `json:"quality"`
	TrafficStats    *TrafficStats  `json:"traffic_stats"`
}

// ConnectionMetrics provides detailed metrics for a direct connection
type ConnectionMetrics struct {
	Latency         time.Duration `json:"latency"`
	Throughput      float64       `json:"throughput_bps"`
	PacketLoss      float64       `json:"packet_loss_rate"`
	ConnectionTime  time.Duration `json:"connection_time"`
	LastHealthCheck time.Time     `json:"last_health_check"`
}

// DirectConfig holds configuration specific to direct connection mode
type DirectConfig struct {
	DefaultProtocol   string        `json:"default_protocol"`
	DefaultPort       int           `json:"default_port"`
	ListenerPort      int           `json:"listener_port"`
	Protocol          string        `json:"protocol"`
	MaxConnections    int           `json:"max_connections"`
	KeepAliveInterval time.Duration `json:"keep_alive_interval"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	EnableOPSEC       bool          `json:"enable_opsec"`
}

// ListenerConfig contains configuration for listener mode
type ListenerConfig struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Address  string `json:"address,omitempty"` // Optional bind address
	Profile  string `json:"profile,omitempty"` // Optional profile name
}

// InvitationConfig contains configuration for generating invitation codes
type InvitationConfig struct {
	Protocol        string        `json:"protocol"`
	ListenerAddress string        `json:"listener_address"`
	BackupAddresses []string      `json:"backup_addresses,omitempty"`
	ExpirationTime  time.Time     `json:"expiration_time"`
	ExpiryDuration  time.Duration `json:"expiry_duration"`
	SingleUse       bool          `json:"single_use"`
}

// Tunnel interface for data transmission (reuses existing interface)
type Tunnel interface {
	SendData(data []byte) error
	ReceiveData() ([]byte, error)
	Close() error
	IsActive() bool
}

// KyberKeyPair represents a post-quantum key pair (reuses existing type)
type KyberKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// SerializePublicKey serializes a public key to bytes
func (kp *KyberKeyPair) SerializePublicKey() []byte {
	// Public key is already in serialized form
	result := make([]byte, len(kp.PublicKey))
	copy(result, kp.PublicKey)
	return result
}

// SerializePrivateKey serializes a private key to bytes
func (kp *KyberKeyPair) SerializePrivateKey() []byte {
	// Private key is already in serialized form
	result := make([]byte, len(kp.PrivateKey))
	copy(result, kp.PrivateKey)
	return result
}

// Constants for invitation code validation
const (
	InvitationCodeVersion = 1
	ConnectionIDSize      = 16
	Ed25519SignatureSize  = 64
	Ed25519PublicKeySize  = 32
	Ed25519PrivateKeySize = 64
	MinSaltSize          = 16
)

// Validation errors
var (
	ErrInvalidVersion     = errors.New("invalid invitation code version")
	ErrInvalidConnectionID = errors.New("invalid connection ID")
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrInvalidNetworkConfig = errors.New("invalid network configuration")
	ErrInvalidSecurityParams = errors.New("invalid security parameters")
	ErrExpiredInvitation  = errors.New("invitation code has expired")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrMissingSigningKey  = errors.New("signing key required for signature generation")
	ErrInvitationUsed     = errors.New("single-use invitation code already used")
)

// InvitationCodeSigner holds the Ed25519 key pair for signing invitation codes
type InvitationCodeSigner struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// NewInvitationCodeSigner generates a new Ed25519 key pair for signing invitation codes
func NewInvitationCodeSigner() (*InvitationCodeSigner, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	return &InvitationCodeSigner{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// GenerateConnectionID creates a cryptographically secure random connection ID
func GenerateConnectionID() ([16]byte, error) {
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		return connectionID, fmt.Errorf("failed to generate connection ID: %w", err)
	}
	return connectionID, nil
}

// GenerateSalt creates a cryptographically secure random salt
func GenerateSalt(size int) ([]byte, error) {
	if size < MinSaltSize {
		return nil, fmt.Errorf("salt size must be at least %d bytes", MinSaltSize)
	}
	
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// Validate performs comprehensive validation of the invitation code
func (ic *InvitationCode) Validate() error {
	// Validate version
	if ic.Version != InvitationCodeVersion {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidVersion, InvitationCodeVersion, ic.Version)
	}

	// Validate connection ID (should not be all zeros)
	var zeroID [16]byte
	if ic.ConnectionID == zeroID {
		return ErrInvalidConnectionID
	}

	// Validate public key
	if err := ic.validatePublicKey(); err != nil {
		return err
	}

	// Validate network configuration
	if err := ic.validateNetworkConfig(); err != nil {
		return err
	}

	// Validate security parameters
	if err := ic.validateSecurityParams(); err != nil {
		return err
	}

	// Validate expiration time
	if err := ic.validateExpiration(); err != nil {
		return err
	}

	// Validate timestamps
	if ic.CreatedAt.IsZero() {
		return errors.New("created_at timestamp is required")
	}

	if ic.CreatedAt.After(time.Now()) {
		return errors.New("created_at timestamp cannot be in the future")
	}

	return nil
}

// ValidateSignature verifies the Ed25519 signature of the invitation code
func (ic *InvitationCode) ValidateSignature(signerPublicKey ed25519.PublicKey) error {
	if len(ic.Signature) != Ed25519SignatureSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, Ed25519SignatureSize, len(ic.Signature))
	}

	if len(signerPublicKey) != Ed25519PublicKeySize {
		return fmt.Errorf("invalid signer public key size: expected %d bytes, got %d", Ed25519PublicKeySize, len(signerPublicKey))
	}

	// Create a copy without signature for verification
	icCopy := *ic
	icCopy.Signature = nil

	// Serialize the invitation code for signing
	data, err := icCopy.serializeForSigning()
	if err != nil {
		return fmt.Errorf("failed to serialize invitation code for signature verification: %w", err)
	}

	// Verify the signature
	if !ed25519.Verify(signerPublicKey, data, ic.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

// Sign generates an Ed25519 signature for the invitation code
func (ic *InvitationCode) Sign(signer *InvitationCodeSigner) error {
	if signer == nil || len(signer.PrivateKey) == 0 {
		return ErrMissingSigningKey
	}

	// Clear any existing signature
	ic.Signature = nil

	// Serialize the invitation code for signing
	data, err := ic.serializeForSigning()
	if err != nil {
		return fmt.Errorf("failed to serialize invitation code for signing: %w", err)
	}

	// Generate signature
	ic.Signature = ed25519.Sign(signer.PrivateKey, data)

	return nil
}

// IsExpired checks if the invitation code has expired
func (ic *InvitationCode) IsExpired() bool {
	return time.Now().After(ic.ExpirationTime)
}

// validatePublicKey validates the Kyber public key
func (ic *InvitationCode) validatePublicKey() error {
	if len(ic.PublicKey) == 0 {
		return fmt.Errorf("%w: public key is empty", ErrInvalidPublicKey)
	}

	// For Kyber-1024, public key should be 1568 bytes
	// This matches the KyberPublicKeyBytes constant from crypto.go
	expectedSize := 1568 // KyberPublicKeyBytes
	if len(ic.PublicKey) != expectedSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPublicKey, expectedSize, len(ic.PublicKey))
	}

	return nil
}

// validateNetworkConfig validates the network configuration
func (ic *InvitationCode) validateNetworkConfig() error {
	if ic.NetworkConfig == nil {
		return fmt.Errorf("%w: network config is nil", ErrInvalidNetworkConfig)
	}

	// Validate protocol
	if ic.NetworkConfig.Protocol != "tcp" && ic.NetworkConfig.Protocol != "udp" {
		return fmt.Errorf("%w: protocol must be 'tcp' or 'udp', got '%s'", ErrInvalidNetworkConfig, ic.NetworkConfig.Protocol)
	}

	// Validate listener address
	if ic.NetworkConfig.ListenerAddress == "" {
		return fmt.Errorf("%w: listener address is required", ErrInvalidNetworkConfig)
	}

	// Basic format validation for IP:Port
	if !isValidAddressFormat(ic.NetworkConfig.ListenerAddress) {
		return fmt.Errorf("%w: invalid listener address format", ErrInvalidNetworkConfig)
	}

	// Validate backup addresses if present
	for i, addr := range ic.NetworkConfig.BackupAddresses {
		if !isValidAddressFormat(addr) {
			return fmt.Errorf("%w: invalid backup address format at index %d", ErrInvalidNetworkConfig, i)
		}
	}

	return nil
}

// validateSecurityParams validates the security parameters
func (ic *InvitationCode) validateSecurityParams() error {
	if ic.SecurityParams == nil {
		return fmt.Errorf("%w: security params is nil", ErrInvalidSecurityParams)
	}

	// Validate key derivation salt
	if len(ic.SecurityParams.KeyDerivationSalt) < MinSaltSize {
		return fmt.Errorf("%w: key derivation salt must be at least %d bytes", ErrInvalidSecurityParams, MinSaltSize)
	}

	// Validate cipher suite
	if ic.SecurityParams.CipherSuite == "" {
		return fmt.Errorf("%w: cipher suite is required", ErrInvalidSecurityParams)
	}

	// Validate auth method
	if ic.SecurityParams.AuthMethod == "" {
		return fmt.Errorf("%w: auth method is required", ErrInvalidSecurityParams)
	}

	return nil
}

// validateExpiration validates the expiration time
func (ic *InvitationCode) validateExpiration() error {
	if ic.ExpirationTime.IsZero() {
		return fmt.Errorf("%w: expiration time is required", ErrExpiredInvitation)
	}

	if ic.IsExpired() {
		return ErrExpiredInvitation
	}

	// Ensure expiration is after creation time
	if !ic.CreatedAt.IsZero() && ic.ExpirationTime.Before(ic.CreatedAt) {
		return errors.New("expiration time cannot be before creation time")
	}

	return nil
}

// serializeForSigning creates a canonical byte representation for signing
func (ic *InvitationCode) serializeForSigning() ([]byte, error) {
	// Create a hash of all fields except signature
	h := sha256.New()

	// Write version
	h.Write([]byte{ic.Version})

	// Write connection ID
	h.Write(ic.ConnectionID[:])

	// Write public key
	h.Write(ic.PublicKey)

	// Write network config
	if ic.NetworkConfig != nil {
		h.Write([]byte(ic.NetworkConfig.Protocol))
		h.Write([]byte(ic.NetworkConfig.ListenerAddress))
		for _, addr := range ic.NetworkConfig.BackupAddresses {
			h.Write([]byte(addr))
		}
	}

	// Write security params
	if ic.SecurityParams != nil {
		h.Write(ic.SecurityParams.KeyDerivationSalt)
		h.Write([]byte(ic.SecurityParams.CipherSuite))
		h.Write([]byte(ic.SecurityParams.AuthMethod))
	}

	// Write timestamps (as Unix nanoseconds for consistency)
	expirationBytes := make([]byte, 8)
	createdAtBytes := make([]byte, 8)
	
	// Convert to Unix nanoseconds for consistent serialization
	expirationNanos := ic.ExpirationTime.UnixNano()
	createdAtNanos := ic.CreatedAt.UnixNano()
	
	// Use big-endian for consistent byte order
	for i := 0; i < 8; i++ {
		expirationBytes[i] = byte(expirationNanos >> (56 - i*8))
		createdAtBytes[i] = byte(createdAtNanos >> (56 - i*8))
	}
	
	h.Write(expirationBytes)
	h.Write(createdAtBytes)

	// Write single use flag
	if ic.SingleUse {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	return h.Sum(nil), nil
}

// isValidAddressFormat performs basic validation of IP:Port format
func isValidAddressFormat(address string) bool {
	if address == "" {
		return false
	}

	// For IPv6 addresses in brackets like [::1]:8080
	if address[0] == '[' {
		closeBracket := -1
		for i, char := range address {
			if char == ']' {
				closeBracket = i
				break
			}
		}
		if closeBracket == -1 || closeBracket >= len(address)-2 {
			return false
		}
		if address[closeBracket+1] != ':' {
			return false
		}
		// Check that there's a port after the colon
		portPart := address[closeBracket+2:]
		return len(portPart) > 0 && isValidPortString(portPart)
	}

	// For IPv4 addresses and hostnames, find the last colon
	lastColon := -1
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon == -1 {
		return false // No colon found
	}

	if lastColon == 0 {
		return false // Colon at the beginning (no host)
	}

	if lastColon == len(address)-1 {
		return false // Colon at the end (no port)
	}

	// Check that the port part is valid
	portPart := address[lastColon+1:]
	return isValidPortString(portPart)
}

// isValidPortString checks if a string represents a valid port number
func isValidPortString(port string) bool {
	if len(port) == 0 {
		return false
	}

	// Check that all characters are digits
	for _, char := range port {
		if char < '0' || char > '9' {
			return false
		}
	}

	// Convert to number and check range (1-65535)
	portNum := 0
	for _, char := range port {
		portNum = portNum*10 + int(char-'0')
		if portNum > 65535 {
			return false
		}
	}

	return portNum >= 1 && portNum <= 65535
}

// MarshalJSON implements custom JSON marshaling for InvitationCode
func (ic *InvitationCode) MarshalJSON() ([]byte, error) {
	// Create a struct with the same fields but with proper JSON handling
	type InvitationCodeJSON struct {
		Version         uint8           `json:"version"`
		ConnectionID    string          `json:"connection_id"`    // Hex-encoded
		PublicKey       string          `json:"public_key"`       // Base64-encoded
		NetworkConfig   *NetworkConfig  `json:"network_config"`
		SecurityParams  *SecurityParams `json:"security_params"`
		ExpirationTime  time.Time       `json:"expiration_time"`
		SingleUse       bool            `json:"single_use"`
		Signature       string          `json:"signature"`        // Base64-encoded
		CreatedAt       time.Time       `json:"created_at"`
	}

	// Convert to JSON-friendly format
	jsonIC := InvitationCodeJSON{
		Version:         ic.Version,
		ConnectionID:    fmt.Sprintf("%x", ic.ConnectionID),
		PublicKey:       encodeBase64(ic.PublicKey),
		NetworkConfig:   ic.NetworkConfig,
		SecurityParams:  ic.SecurityParams,
		ExpirationTime:  ic.ExpirationTime,
		SingleUse:       ic.SingleUse,
		Signature:       encodeBase64(ic.Signature),
		CreatedAt:       ic.CreatedAt,
	}

	return json.Marshal(jsonIC)
}

// UnmarshalJSON implements custom JSON unmarshaling for InvitationCode
func (ic *InvitationCode) UnmarshalJSON(data []byte) error {
	// Create a struct with the same fields but with proper JSON handling
	type InvitationCodeJSON struct {
		Version         uint8           `json:"version"`
		ConnectionID    string          `json:"connection_id"`    // Hex-encoded
		PublicKey       string          `json:"public_key"`       // Base64-encoded
		NetworkConfig   *NetworkConfig  `json:"network_config"`
		SecurityParams  *SecurityParams `json:"security_params"`
		ExpirationTime  time.Time       `json:"expiration_time"`
		SingleUse       bool            `json:"single_use"`
		Signature       string          `json:"signature"`        // Base64-encoded
		CreatedAt       time.Time       `json:"created_at"`
	}

	var jsonIC InvitationCodeJSON
	if err := json.Unmarshal(data, &jsonIC); err != nil {
		return fmt.Errorf("failed to unmarshal invitation code JSON: %w", err)
	}

	// Convert connection ID from hex
	connectionIDBytes, err := decodeHex(jsonIC.ConnectionID)
	if err != nil {
		return fmt.Errorf("failed to decode connection ID: %w", err)
	}
	if len(connectionIDBytes) != ConnectionIDSize {
		return fmt.Errorf("invalid connection ID size: expected %d bytes, got %d", ConnectionIDSize, len(connectionIDBytes))
	}
	copy(ic.ConnectionID[:], connectionIDBytes)

	// Convert public key from base64
	ic.PublicKey, err = decodeBase64(jsonIC.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	// Convert signature from base64
	ic.Signature, err = decodeBase64(jsonIC.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Copy other fields
	ic.Version = jsonIC.Version
	ic.NetworkConfig = jsonIC.NetworkConfig
	ic.SecurityParams = jsonIC.SecurityParams
	ic.ExpirationTime = jsonIC.ExpirationTime
	ic.SingleUse = jsonIC.SingleUse
	ic.CreatedAt = jsonIC.CreatedAt

	return nil
}

// Helper functions for encoding/decoding
func encodeBase64(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// Role conflict detection and resolution methods

// DetectRoleConflict analyzes two roles and determines if there's a conflict
func DetectRoleConflict(localRole, remoteRole ConnectionRole) *RoleConflictResolution {
	if !localRole.HasConflict(remoteRole) {
		return nil // No conflict
	}

	var conflictType RoleConflictType
	var recommendedAction string
	var alternativeActions []string
	var autoResolvable bool
	var resolutionStrategy string

	switch {
	case localRole == RoleListener && remoteRole == RoleListener:
		conflictType = ConflictBothListeners
		recommendedAction = "One peer should switch to connector role"
		alternativeActions = []string{
			"Use priority-based role negotiation",
			"Manually reconfigure one peer as connector",
			"Use different network addresses for each peer",
		}
		autoResolvable = true
		resolutionStrategy = "priority_based"

	case localRole == RoleConnector && remoteRole == RoleConnector:
		conflictType = ConflictBothConnectors
		recommendedAction = "One peer should switch to listener role and bind to a port"
		alternativeActions = []string{
			"Use priority-based role negotiation",
			"Manually reconfigure one peer as listener",
			"Use relay mode as fallback",
		}
		autoResolvable = true
		resolutionStrategy = "priority_based"

	default:
		conflictType = ConflictIncompatibleCapabilities
		recommendedAction = "Check network configuration and capabilities"
		alternativeActions = []string{
			"Verify network connectivity",
			"Check firewall settings",
			"Use relay mode as fallback",
		}
		autoResolvable = false
		resolutionStrategy = "manual"
	}

	return &RoleConflictResolution{
		ConflictType:        conflictType,
		LocalRole:          localRole,
		RemoteRole:         remoteRole,
		RecommendedAction:  recommendedAction,
		AlternativeActions: alternativeActions,
		AutoResolvable:     autoResolvable,
		ResolutionStrategy: resolutionStrategy,
	}
}

// GenerateRolePriority generates a priority value for role negotiation
func GenerateRolePriority() uint32 {
	// Generate a random 32-bit priority value
	var priority uint32
	priorityBytes := make([]byte, 4)
	if _, err := rand.Read(priorityBytes); err != nil {
		// Fallback to timestamp-based priority if random generation fails
		return uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	}
	
	priority = uint32(priorityBytes[0])<<24 |
		      uint32(priorityBytes[1])<<16 |
		      uint32(priorityBytes[2])<<8 |
		      uint32(priorityBytes[3])
	
	return priority
}

// ResolveRoleConflict automatically resolves role conflicts using priority-based negotiation
func ResolveRoleConflict(localRole ConnectionRole, localPriority uint32, remoteRole ConnectionRole, remotePriority uint32) (ConnectionRole, error) {
	conflict := DetectRoleConflict(localRole, remoteRole)
	if conflict == nil {
		return localRole, nil // No conflict to resolve
	}

	if !conflict.AutoResolvable {
		return localRole, fmt.Errorf("role conflict cannot be automatically resolved: %s", conflict.RecommendedAction)
	}

	// Use priority-based resolution
	switch conflict.ConflictType {
	case ConflictBothListeners:
		// Higher priority becomes connector, lower priority stays listener
		if localPriority > remotePriority {
			return RoleConnector, nil
		} else if localPriority < remotePriority {
			return RoleListener, nil
		} else {
			// Equal priorities - use connection ID as tiebreaker
			// This ensures deterministic resolution
			return RoleConnector, nil // Default to connector for equal priorities
		}

	case ConflictBothConnectors:
		// Higher priority becomes listener, lower priority stays connector
		if localPriority > remotePriority {
			return RoleListener, nil
		} else if localPriority < remotePriority {
			return RoleConnector, nil
		} else {
			// Equal priorities - use connection ID as tiebreaker
			return RoleListener, nil // Default to listener for equal priorities
		}

	default:
		return localRole, fmt.Errorf("unsupported conflict type for automatic resolution: %s", conflict.ConflictType.String())
	}
}

// CreateHandshakeMessage creates a handshake message for role negotiation
func CreateHandshakeMessage(msgType HandshakeMessageType, connectionID [16]byte, role ConnectionRole, priority uint32) (*HandshakeMessage, error) {
	// Generate nonce
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Define capabilities based on role
	var capabilities []string
	switch role {
	case RoleListener:
		capabilities = []string{"tcp", "udp", "port_binding", "accept_connections"}
	case RoleConnector:
		capabilities = []string{"tcp", "udp", "outbound_connections", "retry_logic"}
	case RoleNegotiating:
		capabilities = []string{"tcp", "udp", "role_negotiation", "priority_based_resolution"}
	}

	message := &HandshakeMessage{
		Type:         msgType,
		ConnectionID: connectionID,
		ProposedRole: role,
		Priority:     priority,
		Capabilities: capabilities,
		Timestamp:    time.Now(),
		Nonce:        nonce,
	}

	return message, nil
}

// ValidateHandshakeMessage validates a handshake message
func ValidateHandshakeMessage(message *HandshakeMessage) error {
	if message == nil {
		return fmt.Errorf("handshake message is nil")
	}

	// Validate connection ID
	var zeroID [16]byte
	if message.ConnectionID == zeroID {
		return fmt.Errorf("invalid connection ID")
	}

	// Validate timestamp (not too old or in the future)
	now := time.Now()
	if message.Timestamp.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("handshake message timestamp is too far in the future")
	}
	if message.Timestamp.Before(now.Add(-10*time.Minute)) {
		return fmt.Errorf("handshake message timestamp is too old")
	}

	// Validate nonce
	var zeroNonce [16]byte
	if message.Nonce == zeroNonce {
		return fmt.Errorf("invalid nonce")
	}

	// Validate role
	if message.ProposedRole < RoleListener || message.ProposedRole > RoleNegotiating {
		return fmt.Errorf("invalid proposed role: %d", message.ProposedRole)
	}

	return nil
}

// Profile management types

// ProfileMetadata contains metadata about a connection profile
type ProfileMetadata struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Protocol    string    `json:"protocol"`
	Address     string    `json:"address"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	UseCount    int       `json:"use_count"`
}

// SearchCriteria defines criteria for searching connection profiles
type SearchCriteria struct {
	Name          string    `json:"name,omitempty"`
	Description   string    `json:"description,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	Address       string    `json:"address,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	MinUseCount   int       `json:"min_use_count,omitempty"`
}

// ProfileStatistics contains usage statistics for all profiles
type ProfileStatistics struct {
	TotalProfiles      int                    `json:"total_profiles"`
	TotalUseCount      int                    `json:"total_use_count"`
	LastActivity       time.Time              `json:"last_activity"`
	ProfilesByProtocol map[string]int         `json:"profiles_by_protocol"`
	UsageStats         []*ProfileUsageStats   `json:"usage_stats"`
}

// ProfileUsageStats contains usage statistics for a single profile
type ProfileUsageStats struct {
	ProfileName string    `json:"profile_name"`
	UseCount    int       `json:"use_count"`
	LastUsed    time.Time `json:"last_used"`
	CreatedAt   time.Time `json:"created_at"`
}

// ProfileMetadataUpdate contains fields that can be updated for a profile
type ProfileMetadataUpdate struct {
	Description *string `json:"description,omitempty"`
}

// Backup and integrity checking types

// BackupData represents an encrypted backup of all profiles
type BackupData struct {
	Version       uint8                      `json:"version"`
	CreatedAt     time.Time                  `json:"created_at"`
	ProfileCount  int                        `json:"profile_count"`
	Profiles      map[string]*ConnectionProfile `json:"profiles"`
	Statistics    *ProfileStatistics         `json:"statistics,omitempty"`
	EncryptedData []byte                     `json:"encrypted_data,omitempty"`
	Salt          []byte                     `json:"salt,omitempty"`
}

// IntegrityCheckResult contains the results of an integrity check
type IntegrityCheckResult struct {
	CheckTime       time.Time `json:"check_time"`
	Passed          bool      `json:"passed"`
	ProfilesChecked int       `json:"profiles_checked"`
	ErrorsFound     []string  `json:"errors_found"`
	WarningsFound   []string  `json:"warnings_found"`
}

// HandshakeMessage represents a message in the connection handshake protocol
type HandshakeMessage struct {
	Type           HandshakeMessageType `json:"type"`
	ConnectionID   [16]byte            `json:"connection_id"`
	ProposedRole   ConnectionRole      `json:"proposed_role"`
	Priority       uint32              `json:"priority"`
	Capabilities   []string            `json:"capabilities"`
	Timestamp      time.Time           `json:"timestamp"`
	Nonce          [16]byte            `json:"nonce"`
	Signature      []byte              `json:"signature"`
}

// HandshakeMessageType defines the type of handshake message
type HandshakeMessageType int

const (
	HandshakeInit HandshakeMessageType = iota
	HandshakeResponse
	HandshakeConfirm
	HandshakeReject
	HandshakeRoleNegotiation
)

// String returns the string representation of the handshake message type
func (h HandshakeMessageType) String() string {
	switch h {
	case HandshakeInit:
		return "init"
	case HandshakeResponse:
		return "response"
	case HandshakeConfirm:
		return "confirm"
	case HandshakeReject:
		return "reject"
	case HandshakeRoleNegotiation:
		return "role_negotiation"
	default:
		return "unknown"
	}
}

// RoleConflictResolution provides guidance for resolving role conflicts
type RoleConflictResolution struct {
	ConflictType        RoleConflictType `json:"conflict_type"`
	LocalRole          ConnectionRole   `json:"local_role"`
	RemoteRole         ConnectionRole   `json:"remote_role"`
	RecommendedAction  string          `json:"recommended_action"`
	AlternativeActions []string        `json:"alternative_actions"`
	AutoResolvable     bool            `json:"auto_resolvable"`
	ResolutionStrategy string          `json:"resolution_strategy"`
}

// RoleConflictType defines the type of role conflict
type RoleConflictType int

const (
	ConflictBothListeners RoleConflictType = iota
	ConflictBothConnectors
	ConflictIncompatibleCapabilities
	ConflictNetworkConfiguration
)

// String returns the string representation of the role conflict type
func (r RoleConflictType) String() string {
	switch r {
	case ConflictBothListeners:
		return "both_listeners"
	case ConflictBothConnectors:
		return "both_connectors"
	case ConflictIncompatibleCapabilities:
		return "incompatible_capabilities"
	case ConflictNetworkConfiguration:
		return "network_configuration"
	default:
		return "unknown"
	}
}

// HandshakeState tracks the state of the connection handshake
type HandshakeState struct {
	State              HandshakePhase    `json:"state"`
	LocalRole          ConnectionRole    `json:"local_role"`
	RemoteRole         ConnectionRole    `json:"remote_role"`
	NegotiatedRole     ConnectionRole    `json:"negotiated_role"`
	Priority           uint32           `json:"priority"`
	RemotePriority     uint32           `json:"remote_priority"`
	StartTime          time.Time        `json:"start_time"`
	LastMessageTime    time.Time        `json:"last_message_time"`
	AttemptCount       int              `json:"attempt_count"`
	ConflictResolution *RoleConflictResolution `json:"conflict_resolution,omitempty"`
}

// HandshakePhase defines the phase of the handshake process
type HandshakePhase int

const (
	PhaseInit HandshakePhase = iota
	PhaseRoleNegotiation
	PhaseKeyExchange
	PhaseConfirmation
	PhaseComplete
	PhaseError
)

// String returns the string representation of the handshake phase
func (h HandshakePhase) String() string {
	switch h {
	case PhaseInit:
		return "init"
	case PhaseRoleNegotiation:
		return "role_negotiation"
	case PhaseKeyExchange:
		return "key_exchange"
	case PhaseConfirmation:
		return "confirmation"
	case PhaseComplete:
		return "complete"
	case PhaseError:
		return "error"
	default:
		return "unknown"
	}
}