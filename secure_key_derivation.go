package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// KeyDerivationAlgorithm represents supported key derivation algorithms
type KeyDerivationAlgorithm int

const (
	KDF_HKDF_SHA256 KeyDerivationAlgorithm = iota
	KDF_HKDF_SHA384
	KDF_HKDF_SHA512
)

// KeyDerivationContext provides context for key derivation operations
type KeyDerivationContext struct {
	Protocol    string    // "TCP" or "UDP"
	LocalPeer   []byte    // Local peer identifier
	RemotePeer  []byte    // Remote peer identifier
	SessionID   []byte    // Session identifier
	Timestamp   time.Time // Key derivation timestamp
}

// KeyDerivationConfig contains key derivation configuration
type KeyDerivationConfig struct {
	Algorithm    KeyDerivationAlgorithm `json:"algorithm"`
	EnableLegacy bool                   `json:"enable_legacy"`
	SaltSize     int                    `json:"salt_size"`
}

// DefaultKeyDerivationConfig returns secure default configuration
func DefaultKeyDerivationConfig() *KeyDerivationConfig {
	return &KeyDerivationConfig{
		Algorithm:    KDF_HKDF_SHA256,
		EnableLegacy: false,
		SaltSize:     32,
	}
}

// validateSharedSecret validates a shared secret before use
func validateSharedSecret(secret []byte, expectedSize int) error {
	if secret == nil {
		return errors.New("shared secret is nil")
	}
	if len(secret) == 0 {
		return errors.New("shared secret is empty")
	}
	if len(secret) != expectedSize {
		return fmt.Errorf("invalid shared secret size: got %d, expected %d", 
			len(secret), expectedSize)
	}
	
	// Check for all-zero secret (indicates potential failure)
	allZero := true
	for _, b := range secret {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errors.New("shared secret is all zeros")
	}
	
	return nil
}

// SecureCombineSharedSecrets securely combines two shared secrets using HKDF
func SecureCombineSharedSecrets(secret1, secret2 []byte, contextInfo []byte) ([]byte, error) {
	// Input validation
	if len(secret1) == 0 {
		return nil, errors.New("secret1 cannot be empty")
	}
	if len(secret2) == 0 {
		return nil, errors.New("secret2 cannot be empty")
	}
	if len(secret1) != len(secret2) {
		return nil, fmt.Errorf("secret length mismatch: secret1=%d, secret2=%d", 
			len(secret1), len(secret2))
	}

	// Validate shared secrets
	if err := validateSharedSecret(secret1, len(secret1)); err != nil {
		return nil, fmt.Errorf("invalid secret1: %w", err)
	}
	if err := validateSharedSecret(secret2, len(secret2)); err != nil {
		return nil, fmt.Errorf("invalid secret2: %w", err)
	}

	// Create input key material by concatenating secrets with domain separator
	domainSeparator := []byte("QAVPN-DUAL-KYBER-COMBINE-v1")
	ikm := make([]byte, 0, len(secret1)+len(secret2)+len(domainSeparator))
	ikm = append(ikm, domainSeparator...)
	ikm = append(ikm, secret1...)
	ikm = append(ikm, secret2...)
	
	// Use cryptographically secure salt
	salt := make([]byte, 32) // 256-bit salt
	if _, err := rand.Read(salt); err != nil {
		secureZeroBytes(ikm)
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Create context info with additional entropy
	info := make([]byte, 0, len(contextInfo)+32)
	info = append(info, contextInfo...)
	info = append(info, []byte("QAVPN-KEY-DERIVATION-v1")...)
	
	// Use HKDF-SHA256 for secure key derivation
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	
	// Derive 32-byte key for AES-256
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		secureZeroBytes(ikm)
		secureZeroBytes(salt)
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	
	// Securely clear intermediate values
	secureZeroBytes(ikm)
	secureZeroBytes(salt)
	
	return derivedKey, nil
}

// SecureCombineSharedSecretsWithAlgorithm combines secrets using specified algorithm
func SecureCombineSharedSecretsWithAlgorithm(secret1, secret2 []byte, contextInfo []byte, 
	algorithm KeyDerivationAlgorithm) ([]byte, error) {
	
	// Input validation
	if err := validateSharedSecret(secret1, len(secret1)); err != nil {
		return nil, fmt.Errorf("invalid secret1: %w", err)
	}
	if err := validateSharedSecret(secret2, len(secret2)); err != nil {
		return nil, fmt.Errorf("invalid secret2: %w", err)
	}
	
	var hashFunc func() hash.Hash
	var keySize int
	
	switch algorithm {
	case KDF_HKDF_SHA256:
		hashFunc = sha256.New
		keySize = 32
	case KDF_HKDF_SHA384:
		hashFunc = sha512.New384
		keySize = 48
	case KDF_HKDF_SHA512:
		hashFunc = sha512.New
		keySize = 64
	default:
		return nil, fmt.Errorf("unsupported key derivation algorithm: %d", algorithm)
	}
	
	// Create domain-separated input
	domainSeparator := []byte("QAVPN-DUAL-KYBER-v2")
	ikm := make([]byte, 0, len(domainSeparator)+len(secret1)+len(secret2))
	ikm = append(ikm, domainSeparator...)
	ikm = append(ikm, secret1...)
	ikm = append(ikm, secret2...)
	
	// Generate cryptographically secure salt
	saltSize := hashFunc().Size()
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		secureZeroBytes(ikm)
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Enhanced context info
	info := make([]byte, 0, len(contextInfo)+64)
	info = append(info, contextInfo...)
	info = append(info, []byte("QAVPN-KDF-v2")...)
	
	// Add algorithm identifier to context
	algorithmBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(algorithmBytes, uint32(algorithm))
	info = append(info, algorithmBytes...)
	
	// Perform HKDF
	hkdfReader := hkdf.New(hashFunc, ikm, salt, info)
	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		secureZeroBytes(ikm)
		secureZeroBytes(salt)
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	
	// Secure cleanup
	secureZeroBytes(ikm)
	secureZeroBytes(salt)
	
	return derivedKey, nil
}

// GenerateContextInfo creates context information for key derivation
func (kdc *KeyDerivationContext) GenerateContextInfo() []byte {
	info := make([]byte, 0, 256)
	
	// Add protocol
	info = append(info, []byte(kdc.Protocol)...)
	info = append(info, 0) // Null separator
	
	// Add peer identifiers
	if len(kdc.LocalPeer) > 0 {
		info = append(info, kdc.LocalPeer...)
	}
	info = append(info, 0)
	
	if len(kdc.RemotePeer) > 0 {
		info = append(info, kdc.RemotePeer...)
	}
	info = append(info, 0)
	
	// Add session ID
	if len(kdc.SessionID) > 0 {
		info = append(info, kdc.SessionID...)
	}
	info = append(info, 0)
	
	// Add timestamp
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(kdc.Timestamp.Unix()))
	info = append(info, timestampBytes...)
	
	return info
}

// SecureCombineSharedSecretsWithContext combines secrets with full context
func SecureCombineSharedSecretsWithContext(secret1, secret2 []byte, 
	context *KeyDerivationContext, algorithm KeyDerivationAlgorithm) ([]byte, error) {
	
	if context == nil {
		return nil, errors.New("key derivation context is nil")
	}
	
	contextInfo := context.GenerateContextInfo()
	return SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, algorithm)
}

// LegacyKeyDerivationMode controls backward compatibility (INSECURE - for testing only)
var LegacyKeyDerivationMode = false

// CombineSharedSecrets provides backward compatibility wrapper
// WARNING: This function is deprecated and should only be used for migration
func CombineSharedSecrets(secret1, secret2 []byte) ([]byte, error) {
	if LegacyKeyDerivationMode {
		// Log warning about legacy mode
		fmt.Printf("WARNING: Using legacy key derivation mode - INSECURE\n")
		
		// Use old implementation (for testing/migration only)
		if len(secret1) == 0 || len(secret2) == 0 {
			return nil, errors.New("empty secrets not allowed")
		}
		
		combined := make([]byte, len(secret1))
		for i := 0; i < len(secret1) && i < len(secret2); i++ {
			combined[i] = secret1[i] ^ secret2[i]
		}
		
		// Use the existing deriveSymmetricKey function with legacy mode marker
		result, err := deriveSymmetricKey(combined, nil, []byte("LEGACY-MODE"))
		secureZeroBytes(combined)
		return result, err
	}
	
	// Use secure implementation with default context
	contextInfo := []byte("DEFAULT-CONTEXT")
	return SecureCombineSharedSecrets(secret1, secret2, contextInfo)
}

// GetKeyDerivationAlgorithmName returns the name of a key derivation algorithm
func GetKeyDerivationAlgorithmName(algorithm KeyDerivationAlgorithm) string {
	switch algorithm {
	case KDF_HKDF_SHA256:
		return "HKDF-SHA256"
	case KDF_HKDF_SHA384:
		return "HKDF-SHA384"
	case KDF_HKDF_SHA512:
		return "HKDF-SHA512"
	default:
		return "UNKNOWN"
	}
}

// ValidateKeyDerivationConfig validates a key derivation configuration
func ValidateKeyDerivationConfig(config *KeyDerivationConfig) error {
	if config == nil {
		return errors.New("key derivation config is nil")
	}
	
	// Validate algorithm
	switch config.Algorithm {
	case KDF_HKDF_SHA256, KDF_HKDF_SHA384, KDF_HKDF_SHA512:
		// Valid algorithms
	default:
		return fmt.Errorf("unsupported key derivation algorithm: %d", config.Algorithm)
	}
	
	// Validate salt size
	if config.SaltSize < 16 || config.SaltSize > 64 {
		return fmt.Errorf("invalid salt size: %d (must be between 16 and 64)", config.SaltSize)
	}
	
	// Warn about legacy mode
	if config.EnableLegacy {
		fmt.Printf("WARNING: Legacy key derivation mode is enabled - INSECURE\n")
	}
	
	return nil
}

// KeyDerivationStats contains statistics about key derivation operations
type KeyDerivationStats struct {
	Algorithm         string    `json:"algorithm"`
	TotalDerivations  int64     `json:"total_derivations"`
	SuccessfulOps     int64     `json:"successful_operations"`
	FailedOps         int64     `json:"failed_operations"`
	LastOperation     time.Time `json:"last_operation"`
	AverageLatencyMs  float64   `json:"average_latency_ms"`
}

// Global key derivation statistics (for monitoring)
var globalKDFStats = &KeyDerivationStats{
	Algorithm: "HKDF-SHA256",
}

// UpdateKeyDerivationStats updates global key derivation statistics
func UpdateKeyDerivationStats(success bool, latency time.Duration) {
	globalKDFStats.TotalDerivations++
	globalKDFStats.LastOperation = time.Now()
	
	if success {
		globalKDFStats.SuccessfulOps++
	} else {
		globalKDFStats.FailedOps++
	}
	
	// Update average latency (simple moving average)
	if globalKDFStats.TotalDerivations == 1 {
		globalKDFStats.AverageLatencyMs = float64(latency.Nanoseconds()) / 1e6
	} else {
		// Exponential moving average with alpha = 0.1
		alpha := 0.1
		newLatencyMs := float64(latency.Nanoseconds()) / 1e6
		globalKDFStats.AverageLatencyMs = alpha*newLatencyMs + (1-alpha)*globalKDFStats.AverageLatencyMs
	}
}

// GetKeyDerivationStats returns current key derivation statistics
func GetKeyDerivationStats() KeyDerivationStats {
	return *globalKDFStats
}

// ResetKeyDerivationStats resets key derivation statistics
func ResetKeyDerivationStats() {
	globalKDFStats = &KeyDerivationStats{
		Algorithm: "HKDF-SHA256",
	}
}
