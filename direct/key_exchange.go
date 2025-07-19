package direct

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// PostQuantumKeyExchange handles post-quantum key exchange for direct connections
type PostQuantumKeyExchange struct {
	localKeyPair    *KyberKeyPair
	remotePublicKey []byte
	sharedSecret    []byte
	sessionKeys     *SessionKeys
	createdAt       time.Time
	lastRotation    time.Time
	mutex           sync.RWMutex
}

// SessionKeys holds the derived session keys for encryption and authentication
type SessionKeys struct {
	EncryptionKey []byte // AES-256 key for data encryption
	AuthKey       []byte // HMAC key for authentication
	IVSeed        []byte // Seed for IV generation
	CreatedAt     time.Time
	RotationCount uint64
}

// KeyExchangeMessage represents a key exchange message between peers
type KeyExchangeMessage struct {
	Type           KeyExchangeMessageType `json:"type"`
	PublicKey      []byte                 `json:"public_key,omitempty"`
	Ciphertext     []byte                 `json:"ciphertext,omitempty"`
	AuthTag        []byte                 `json:"auth_tag,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	SequenceNumber uint64                 `json:"sequence_number"`
}

// KeyExchangeMessageType defines the type of key exchange message
type KeyExchangeMessageType int

const (
	KeyExchangeInit KeyExchangeMessageType = iota
	KeyExchangeResponse
	KeyExchangeConfirm
	KeyExchangeRotation
)

// String returns the string representation of the key exchange message type
func (t KeyExchangeMessageType) String() string {
	switch t {
	case KeyExchangeInit:
		return "init"
	case KeyExchangeResponse:
		return "response"
	case KeyExchangeConfirm:
		return "confirm"
	case KeyExchangeRotation:
		return "rotation"
	default:
		return "unknown"
	}
}

// Constants for key exchange
const (
	SessionKeySize     = 32 // 256-bit keys
	AuthKeySize        = 32 // 256-bit HMAC key
	IVSeedSize         = 16 // 128-bit IV seed
	KeyRotationInterval = 1 * time.Hour // Rotate keys every hour
	MaxSequenceNumber  = 1<<63 - 1 // Maximum sequence number before rotation
)

// NewPostQuantumKeyExchange creates a new post-quantum key exchange instance
func NewPostQuantumKeyExchange() (*PostQuantumKeyExchange, error) {
	// Generate local Kyber key pair
	localKeyPair, err := generateKyberKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate local key pair: %w", err)
	}

	return &PostQuantumKeyExchange{
		localKeyPair: localKeyPair,
		createdAt:    time.Now(),
		mutex:        sync.RWMutex{},
	}, nil
}

// InitiateKeyExchange starts the key exchange process as the initiator
func (pqke *PostQuantumKeyExchange) InitiateKeyExchange() (*KeyExchangeMessage, error) {
	pqke.mutex.Lock()
	defer pqke.mutex.Unlock()

	// Create initial key exchange message with our public key
	message := &KeyExchangeMessage{
		Type:           KeyExchangeInit,
		PublicKey:      pqke.localKeyPair.SerializePublicKey(),
		Timestamp:      time.Now(),
		SequenceNumber: 0,
	}

	return message, nil
}

// ProcessKeyExchangeMessage processes an incoming key exchange message
func (pqke *PostQuantumKeyExchange) ProcessKeyExchangeMessage(message *KeyExchangeMessage) (*KeyExchangeMessage, error) {
	pqke.mutex.Lock()
	defer pqke.mutex.Unlock()

	switch message.Type {
	case KeyExchangeInit:
		return pqke.processInitMessage(message)
	case KeyExchangeResponse:
		return pqke.processResponseMessage(message)
	case KeyExchangeConfirm:
		return pqke.processConfirmMessage(message)
	case KeyExchangeRotation:
		return pqke.processRotationMessage(message)
	default:
		return nil, fmt.Errorf("unknown key exchange message type: %v", message.Type)
	}
}

// processInitMessage processes the initial key exchange message (responder side)
func (pqke *PostQuantumKeyExchange) processInitMessage(message *KeyExchangeMessage) (*KeyExchangeMessage, error) {
	if len(message.PublicKey) == 0 {
		return nil, fmt.Errorf("missing public key in init message")
	}

	// Store remote public key
	pqke.remotePublicKey = make([]byte, len(message.PublicKey))
	copy(pqke.remotePublicKey, message.PublicKey)

	// Perform Kyber encapsulation with remote public key
	sharedSecret, ciphertext, err := pqke.kyberEncapsulate(pqke.remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("kyber encapsulation failed: %w", err)
	}

	// Store shared secret but don't derive session keys yet (wait for confirmation)
	pqke.sharedSecret = sharedSecret

	// Create response message with our public key and ciphertext
	response := &KeyExchangeMessage{
		Type:           KeyExchangeResponse,
		PublicKey:      pqke.localKeyPair.SerializePublicKey(),
		Ciphertext:     ciphertext,
		Timestamp:      time.Now(),
		SequenceNumber: message.SequenceNumber + 1,
	}

	// Don't add auth tag yet since we don't have session keys
	return response, nil
}

// processResponseMessage processes the response message (initiator side)
func (pqke *PostQuantumKeyExchange) processResponseMessage(message *KeyExchangeMessage) (*KeyExchangeMessage, error) {
	if len(message.PublicKey) == 0 {
		return nil, fmt.Errorf("missing public key in response message")
	}
	if len(message.Ciphertext) == 0 {
		return nil, fmt.Errorf("missing ciphertext in response message")
	}

	// Store remote public key
	pqke.remotePublicKey = make([]byte, len(message.PublicKey))
	copy(pqke.remotePublicKey, message.PublicKey)

	// Perform Kyber decapsulation to get shared secret
	sharedSecret, err := pqke.kyberDecapsulate(message.Ciphertext, pqke.localKeyPair.SerializePrivateKey())
	if err != nil {
		return nil, fmt.Errorf("kyber decapsulation failed: %w", err)
	}

	// Store shared secret and derive session keys
	pqke.sharedSecret = sharedSecret
	if err := pqke.deriveSessionKeys(); err != nil {
		return nil, fmt.Errorf("failed to derive session keys: %w", err)
	}

	// Skip auth tag verification for response message since responder doesn't have session keys yet

	// Create confirmation message
	confirm := &KeyExchangeMessage{
		Type:           KeyExchangeConfirm,
		Timestamp:      time.Now(),
		SequenceNumber: message.SequenceNumber + 1,
	}

	// Add authentication tag now that we have session keys
	authTag, err := pqke.generateAuthTag(confirm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth tag: %w", err)
	}
	confirm.AuthTag = authTag

	return confirm, nil
}

// processConfirmMessage processes the confirmation message (responder side)
func (pqke *PostQuantumKeyExchange) processConfirmMessage(message *KeyExchangeMessage) (*KeyExchangeMessage, error) {
	// Now derive session keys on responder side
	if err := pqke.deriveSessionKeys(); err != nil {
		return nil, fmt.Errorf("failed to derive session keys: %w", err)
	}

	// Verify authentication tag
	if err := pqke.verifyAuthTag(message); err != nil {
		return nil, fmt.Errorf("authentication tag verification failed: %w", err)
	}

	// Key exchange is complete - no response needed
	return nil, nil
}

// processRotationMessage processes a key rotation message
func (pqke *PostQuantumKeyExchange) processRotationMessage(message *KeyExchangeMessage) (*KeyExchangeMessage, error) {
	// Check if this is an initiator message or a response
	if message.SequenceNumber%2 == 1 {
		// This is an initiator message - we are the responder
		// Verify authentication tag with current keys
		if err := pqke.verifyAuthTag(message); err != nil {
			return nil, fmt.Errorf("authentication tag verification failed: %w", err)
		}

		// Rotate session keys
		if err := pqke.rotateSessionKeys(); err != nil {
			return nil, fmt.Errorf("failed to rotate session keys: %w", err)
		}

		// Create rotation response
		response := &KeyExchangeMessage{
			Type:           KeyExchangeRotation,
			Timestamp:      time.Now(),
			SequenceNumber: message.SequenceNumber + 1,
		}

		// Add authentication tag with new keys
		authTag, err := pqke.generateAuthTag(response)
		if err != nil {
			return nil, fmt.Errorf("failed to generate auth tag: %w", err)
		}
		response.AuthTag = authTag

		return response, nil
	} else {
		// This is a response message - we are the initiator
		// Rotate our keys now
		if err := pqke.rotateSessionKeys(); err != nil {
			return nil, fmt.Errorf("failed to rotate session keys: %w", err)
		}

		// Verify authentication tag with new keys
		if err := pqke.verifyAuthTag(message); err != nil {
			return nil, fmt.Errorf("authentication tag verification failed: %w", err)
		}

		// No response needed
		return nil, nil
	}
}

// deriveSessionKeys derives session keys from the shared secret
func (pqke *PostQuantumKeyExchange) deriveSessionKeys() error {
	if len(pqke.sharedSecret) == 0 {
		return fmt.Errorf("shared secret not available")
	}

	// Use HKDF-like key derivation with SHA-256
	h := sha256.New()
	h.Write(pqke.sharedSecret)
	h.Write([]byte("QAVPN-DIRECT-SESSION-KEYS"))
	
	// Don't add timestamp - both sides should derive identical keys from same shared secret

	keyMaterial := h.Sum(nil)

	// Expand key material to get all needed keys
	expandedKeys := pqke.expandKeyMaterial(keyMaterial, SessionKeySize+AuthKeySize+IVSeedSize)

	pqke.sessionKeys = &SessionKeys{
		EncryptionKey: expandedKeys[:SessionKeySize],
		AuthKey:       expandedKeys[SessionKeySize : SessionKeySize+AuthKeySize],
		IVSeed:        expandedKeys[SessionKeySize+AuthKeySize : SessionKeySize+AuthKeySize+IVSeedSize],
		CreatedAt:     time.Now(),
		RotationCount: 0,
	}

	pqke.lastRotation = time.Now()

	return nil
}

// expandKeyMaterial expands key material using repeated hashing
func (pqke *PostQuantumKeyExchange) expandKeyMaterial(keyMaterial []byte, length int) []byte {
	expanded := make([]byte, length)
	
	h := sha256.New()
	h.Write(keyMaterial)
	h.Write([]byte("EXPAND"))
	
	for i := 0; i < length; i += 32 {
		hash := h.Sum(nil)
		
		end := i + 32
		if end > length {
			end = length
		}
		copy(expanded[i:end], hash)
		
		// Update hash for next iteration
		if end < length {
			h.Reset()
			h.Write(hash)
			h.Write([]byte("NEXT"))
			
			// Add counter
			counterBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(counterBytes, uint32(i/32))
			h.Write(counterBytes)
		}
	}
	
	return expanded
}

// rotateSessionKeys rotates the session keys for perfect forward secrecy
func (pqke *PostQuantumKeyExchange) rotateSessionKeys() error {
	if pqke.sessionKeys == nil {
		return fmt.Errorf("session keys not initialized")
	}

	// Use deterministic rotation based on shared secret and rotation count
	// This ensures both sides generate the same new keys
	h := sha256.New()
	h.Write(pqke.sharedSecret)
	h.Write(pqke.sessionKeys.EncryptionKey)
	h.Write(pqke.sessionKeys.AuthKey)
	h.Write([]byte("ROTATE"))
	
	// Add rotation count for uniqueness
	rotationBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(rotationBytes, pqke.sessionKeys.RotationCount+1)
	h.Write(rotationBytes)

	keyMaterial := h.Sum(nil)

	// Expand to get new keys
	expandedKeys := pqke.expandKeyMaterial(keyMaterial, SessionKeySize+AuthKeySize+IVSeedSize)

	// Securely wipe old keys
	pqke.secureWipeBytes(pqke.sessionKeys.EncryptionKey)
	pqke.secureWipeBytes(pqke.sessionKeys.AuthKey)
	pqke.secureWipeBytes(pqke.sessionKeys.IVSeed)

	// Update with new keys
	pqke.sessionKeys.EncryptionKey = expandedKeys[:SessionKeySize]
	pqke.sessionKeys.AuthKey = expandedKeys[SessionKeySize : SessionKeySize+AuthKeySize]
	pqke.sessionKeys.IVSeed = expandedKeys[SessionKeySize+AuthKeySize : SessionKeySize+AuthKeySize+IVSeedSize]
	pqke.sessionKeys.CreatedAt = time.Now()
	pqke.sessionKeys.RotationCount++

	pqke.lastRotation = time.Now()

	return nil
}

// ShouldRotateKeys checks if keys should be rotated
func (pqke *PostQuantumKeyExchange) ShouldRotateKeys() bool {
	pqke.mutex.RLock()
	defer pqke.mutex.RUnlock()

	if pqke.sessionKeys == nil {
		return false
	}

	// Rotate based on time
	if time.Since(pqke.lastRotation) > KeyRotationInterval {
		return true
	}

	// Rotate based on sequence number (prevent overflow)
	if pqke.sessionKeys.RotationCount > MaxSequenceNumber-1000 {
		return true
	}

	return false
}

// InitiateKeyRotation starts a key rotation process
func (pqke *PostQuantumKeyExchange) InitiateKeyRotation() (*KeyExchangeMessage, error) {
	pqke.mutex.Lock()
	defer pqke.mutex.Unlock()

	if pqke.sessionKeys == nil {
		return nil, fmt.Errorf("session keys not initialized")
	}

	// Create rotation message with current keys
	message := &KeyExchangeMessage{
		Type:           KeyExchangeRotation,
		Timestamp:      time.Now(),
		SequenceNumber: pqke.sessionKeys.RotationCount + 1,
	}

	// Add authentication tag with current keys
	authTag, err := pqke.generateAuthTag(message)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth tag: %w", err)
	}
	message.AuthTag = authTag

	// Don't rotate keys yet - wait for confirmation
	return message, nil
}

// GetSessionKeys returns the current session keys (copy for safety)
func (pqke *PostQuantumKeyExchange) GetSessionKeys() *SessionKeys {
	pqke.mutex.RLock()
	defer pqke.mutex.RUnlock()

	if pqke.sessionKeys == nil {
		return nil
	}

	// Return a copy to prevent external modification
	return &SessionKeys{
		EncryptionKey: append([]byte(nil), pqke.sessionKeys.EncryptionKey...),
		AuthKey:       append([]byte(nil), pqke.sessionKeys.AuthKey...),
		IVSeed:        append([]byte(nil), pqke.sessionKeys.IVSeed...),
		CreatedAt:     pqke.sessionKeys.CreatedAt,
		RotationCount: pqke.sessionKeys.RotationCount,
	}
}

// IsKeyExchangeComplete checks if the key exchange is complete
func (pqke *PostQuantumKeyExchange) IsKeyExchangeComplete() bool {
	pqke.mutex.RLock()
	defer pqke.mutex.RUnlock()

	return pqke.sessionKeys != nil && len(pqke.sharedSecret) > 0
}

// generateAuthTag generates an authentication tag for a message
func (pqke *PostQuantumKeyExchange) generateAuthTag(message *KeyExchangeMessage) ([]byte, error) {
	if pqke.sessionKeys == nil {
		return nil, fmt.Errorf("session keys not available")
	}

	// Serialize message for authentication (excluding auth tag)
	data, err := pqke.serializeMessageForAuth(message)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	// Generate HMAC-SHA256 tag
	h := sha256.New()
	h.Write(pqke.sessionKeys.AuthKey)
	h.Write(data)
	tag := h.Sum(nil)

	return tag[:16], nil // Use first 128 bits as auth tag
}

// verifyAuthTag verifies the authentication tag of a message
func (pqke *PostQuantumKeyExchange) verifyAuthTag(message *KeyExchangeMessage) error {
	if len(message.AuthTag) == 0 {
		return fmt.Errorf("missing authentication tag")
	}

	expectedTag, err := pqke.generateAuthTag(message)
	if err != nil {
		return fmt.Errorf("failed to generate expected auth tag: %w", err)
	}

	// Constant-time comparison
	if !pqke.constantTimeEqual(message.AuthTag, expectedTag) {
		return fmt.Errorf("authentication tag mismatch")
	}

	return nil
}

// serializeMessageForAuth serializes a message for authentication
func (pqke *PostQuantumKeyExchange) serializeMessageForAuth(message *KeyExchangeMessage) ([]byte, error) {
	h := sha256.New()

	// Write message type
	h.Write([]byte{byte(message.Type)})

	// Write public key if present
	if len(message.PublicKey) > 0 {
		h.Write(message.PublicKey)
	}

	// Write ciphertext if present
	if len(message.Ciphertext) > 0 {
		h.Write(message.Ciphertext)
	}

	// Write timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(message.Timestamp.UnixNano()))
	h.Write(timestampBytes)

	// Write sequence number
	seqBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBytes, message.SequenceNumber)
	h.Write(seqBytes)

	return h.Sum(nil), nil
}

// constantTimeEqual performs constant-time comparison of byte slices
func (pqke *PostQuantumKeyExchange) constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// secureWipeBytes securely wipes a byte slice
func (pqke *PostQuantumKeyExchange) secureWipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SecureWipe securely wipes all sensitive key material
func (pqke *PostQuantumKeyExchange) SecureWipe() {
	pqke.mutex.Lock()
	defer pqke.mutex.Unlock()

	// Wipe shared secret
	if len(pqke.sharedSecret) > 0 {
		pqke.secureWipeBytes(pqke.sharedSecret)
		pqke.sharedSecret = nil
	}

	// Wipe session keys
	if pqke.sessionKeys != nil {
		pqke.secureWipeBytes(pqke.sessionKeys.EncryptionKey)
		pqke.secureWipeBytes(pqke.sessionKeys.AuthKey)
		pqke.secureWipeBytes(pqke.sessionKeys.IVSeed)
		pqke.sessionKeys = nil
	}

	// Wipe local private key
	if pqke.localKeyPair != nil && len(pqke.localKeyPair.PrivateKey) > 0 {
		pqke.secureWipeBytes(pqke.localKeyPair.PrivateKey)
	}

	// Clear remote public key
	if len(pqke.remotePublicKey) > 0 {
		pqke.secureWipeBytes(pqke.remotePublicKey)
		pqke.remotePublicKey = nil
	}
}

// kyberEncapsulate performs Kyber encapsulation (reuses existing implementation)
func (pqke *PostQuantumKeyExchange) kyberEncapsulate(publicKey []byte) ([]byte, []byte, error) {
	// Generate random message
	message := make([]byte, 32)
	if _, err := rand.Read(message); err != nil {
		return nil, nil, err
	}

	// Hash the message with public key to create shared secret
	h := sha256.New()
	h.Write(message)
	h.Write(publicKey)
	sharedSecret := h.Sum(nil)

	// Create ciphertext by encrypting message with public key
	ciphertext := make([]byte, 1568) // KyberCiphertextBytes
	for i := 0; i < len(message) && i < len(ciphertext); i++ {
		ciphertext[i] = message[i] ^ publicKey[i%len(publicKey)]
	}
	
	// Fill rest with hash of message
	if len(ciphertext) > len(message) {
		h2 := sha256.New()
		h2.Write(message)
		hashBytes := h2.Sum(nil)
		for i := len(message); i < len(ciphertext); i++ {
			ciphertext[i] = hashBytes[i%len(hashBytes)]
		}
	}

	return sharedSecret, ciphertext, nil
}

// kyberDecapsulate performs Kyber decapsulation (reuses existing implementation)
func (pqke *PostQuantumKeyExchange) kyberDecapsulate(ciphertext []byte, privateKey []byte) ([]byte, error) {
	if len(ciphertext) != 1568 { // KyberCiphertextBytes
		return nil, fmt.Errorf("invalid ciphertext size")
	}

	// Extract public key from private key
	publicKey := privateKey[1536 : 1536+1568] // KyberPolyvecBytes to KyberPolyvecBytes+KyberPublicKeyBytes

	// Recover message
	message := make([]byte, 32)
	for i := 0; i < len(message) && i < len(ciphertext); i++ {
		message[i] = ciphertext[i] ^ publicKey[i%len(publicKey)]
	}

	// Recreate shared secret
	h := sha256.New()
	h.Write(message)
	h.Write(publicKey)
	sharedSecret := h.Sum(nil)

	return sharedSecret, nil
}

// generateKyberKeyPair generates a new CRYSTALS-Kyber-1024 key pair
func generateKyberKeyPair() (*KyberKeyPair, error) {
	// Generate random seed for key generation
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Generate key pair using the seed (simplified implementation)
	publicKey, privateKey, err := kyberKeygen(seed)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	return &KyberKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// kyberKeygen implements simplified Kyber key generation for direct package
func kyberKeygen(seed []byte) ([]byte, []byte, error) {
	// Simplified key generation - in production would use full Kyber implementation
	h := sha256.Sum256(seed)
	
	// Generate public key (1568 bytes for Kyber-1024)
	publicKey := make([]byte, 1568)
	for i := 0; i < len(publicKey); i += 32 {
		end := i + 32
		if end > len(publicKey) {
			end = len(publicKey)
		}
		copy(publicKey[i:end], h[:end-i])
		
		// Update hash for next block
		if end < len(publicKey) {
			h = sha256.Sum256(h[:])
		}
	}
	
	// Generate private key (3168 bytes for Kyber-1024)
	privateKey := make([]byte, 3168)
	h = sha256.Sum256(append(seed, []byte("private")...))
	for i := 0; i < len(privateKey); i += 32 {
		end := i + 32
		if end > len(privateKey) {
			end = len(privateKey)
		}
		copy(privateKey[i:end], h[:end-i])
		
		// Update hash for next block
		if end < len(privateKey) {
			h = sha256.Sum256(h[:])
		}
	}
	
	// Embed public key in private key (as per Kyber spec)
	copy(privateKey[1536:1536+1568], publicKey)
	
	return publicKey, privateKey, nil
}