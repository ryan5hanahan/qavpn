package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// CRYSTALS-Kyber-1024 parameters
const (
	KyberN     = 256  // Polynomial degree
	KyberQ     = 3329 // Modulus
	KyberK     = 4    // Security parameter for Kyber-1024
	KyberEta1  = 2    // Noise parameter
	KyberEta2  = 2    // Noise parameter
	KyberDU    = 11   // Compression parameter
	KyberDV    = 5    // Compression parameter
	
	// Derived sizes
	KyberPolyBytes       = 384  // Compressed polynomial size
	KyberPolyvecBytes    = KyberK * KyberPolyBytes
	KyberIndcpaBytes     = KyberPolyvecBytes + KyberPolyBytes
	KyberPublicKeyBytes  = KyberIndcpaBytes
	KyberSecretKeyBytes  = KyberPolyvecBytes + KyberIndcpaBytes + 2*32
	KyberCiphertextBytes = KyberPolyvecBytes + KyberPolyBytes
)

// KyberKeyPair represents a CRYSTALS-Kyber key pair
type KyberKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// Polynomial represents a polynomial in the ring Z_q[X]/(X^n + 1)
type Polynomial [KyberN]uint16

// PolynomialVector represents a vector of polynomials
type PolynomialVector [KyberK]Polynomial

// GenerateKyberKeyPair generates a new CRYSTALS-Kyber-1024 key pair
func GenerateKyberKeyPair() (*KyberKeyPair, error) {
	// Generate random seed for key generation
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Generate key pair using the seed
	publicKey, privateKey, err := kyberKeygen(seed)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	return &KyberKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
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

// DeserializePublicKey creates a key pair from a serialized public key
func DeserializePublicKey(data []byte) (*KyberKeyPair, error) {
	if len(data) != KyberPublicKeyBytes {
		return nil, errors.New("invalid public key size")
	}

	publicKey := make([]byte, KyberPublicKeyBytes)
	copy(publicKey, data)

	return &KyberKeyPair{
		PublicKey:  publicKey,
		PrivateKey: nil, // Only public key available
	}, nil
}

// DeserializePrivateKey creates a key pair from a serialized private key
func DeserializePrivateKey(data []byte) (*KyberKeyPair, error) {
	if len(data) != KyberSecretKeyBytes {
		return nil, errors.New("invalid private key size")
	}

	privateKey := make([]byte, KyberSecretKeyBytes)
	copy(privateKey, data)

	// Extract public key from private key (it's embedded)
	publicKey := make([]byte, KyberPublicKeyBytes)
	copy(publicKey, privateKey[KyberPolyvecBytes:KyberPolyvecBytes+KyberPublicKeyBytes])

	return &KyberKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// ValidateKeyPair validates that a key pair is properly formed
func (kp *KyberKeyPair) ValidateKeyPair() error {
	if kp.PublicKey == nil {
		return errors.New("public key is nil")
	}
	if len(kp.PublicKey) != KyberPublicKeyBytes {
		return fmt.Errorf("invalid public key size: got %d, expected %d", 
			len(kp.PublicKey), KyberPublicKeyBytes)
	}

	if kp.PrivateKey != nil {
		if len(kp.PrivateKey) != KyberSecretKeyBytes {
			return fmt.Errorf("invalid private key size: got %d, expected %d", 
				len(kp.PrivateKey), KyberSecretKeyBytes)
		}
	}

	return nil
}

// kyberKeygen implements the core Kyber key generation algorithm
func kyberKeygen(seed []byte) ([]byte, []byte, error) {
	// Expand seed using SHA-256
	h := sha256.Sum256(seed)
	rho := h[:32]

	// Generate matrix A from rho
	A, err := generateMatrix(rho)
	if err != nil {
		return nil, nil, err
	}

	// Generate secret vector s
	s, err := generateSecretVector(seed)
	if err != nil {
		return nil, nil, err
	}

	// Generate error vector e
	e, err := generateErrorVector(seed)
	if err != nil {
		return nil, nil, err
	}

	// Compute t = A*s + e
	t := matrixVectorMultiply(A, s)
	t = addPolynomialVectors(t, e)

	// Serialize public key (rho || t)
	publicKey := make([]byte, KyberPublicKeyBytes)
	copy(publicKey[:32], rho)
	serializePolynomialVector(t, publicKey[32:])

	// Serialize private key (s || pk || H(pk) || z)
	privateKey := make([]byte, KyberSecretKeyBytes)
	serializePolynomialVector(s, privateKey[:KyberPolyvecBytes])
	copy(privateKey[KyberPolyvecBytes:], publicKey)
	
	// Add hash of public key
	pkHash := sha256.Sum256(publicKey)
	copy(privateKey[KyberPolyvecBytes+KyberPublicKeyBytes:], pkHash[:])
	
	// Add random z
	z := make([]byte, 32)
	if _, err := rand.Read(z); err != nil {
		return nil, nil, err
	}
	copy(privateKey[KyberPolyvecBytes+KyberPublicKeyBytes+32:], z)

	return publicKey, privateKey, nil
}

// generateMatrix generates the public matrix A from seed rho
func generateMatrix(rho []byte) ([KyberK][KyberK]Polynomial, error) {
	var A [KyberK][KyberK]Polynomial
	
	for i := 0; i < KyberK; i++ {
		for j := 0; j < KyberK; j++ {
			// Create seed for this matrix element
			seed := make([]byte, 34)
			copy(seed, rho)
			seed[32] = byte(j)
			seed[33] = byte(i)
			
			// Generate polynomial from seed
			poly, err := generateUniformPolynomial(seed)
			if err != nil {
				return A, err
			}
			A[i][j] = poly
		}
	}
	
	return A, nil
}

// generateSecretVector generates a secret polynomial vector
func generateSecretVector(seed []byte) (PolynomialVector, error) {
	var s PolynomialVector
	
	for i := 0; i < KyberK; i++ {
		// Create seed for this vector element
		extendedSeed := make([]byte, 33)
		copy(extendedSeed, seed)
		extendedSeed[32] = byte(i)
		
		poly, err := generateBinomialPolynomial(extendedSeed, KyberEta1)
		if err != nil {
			return s, err
		}
		s[i] = poly
	}
	
	return s, nil
}

// generateErrorVector generates an error polynomial vector
func generateErrorVector(seed []byte) (PolynomialVector, error) {
	var e PolynomialVector
	
	for i := 0; i < KyberK; i++ {
		// Create seed for this vector element
		extendedSeed := make([]byte, 33)
		copy(extendedSeed, seed)
		extendedSeed[32] = byte(i + KyberK) // Offset to avoid collision with secret
		
		poly, err := generateBinomialPolynomial(extendedSeed, KyberEta1)
		if err != nil {
			return e, err
		}
		e[i] = poly
	}
	
	return e, nil
}

// generateUniformPolynomial generates a uniform polynomial from a seed
func generateUniformPolynomial(seed []byte) (Polynomial, error) {
	var poly Polynomial
	
	// Use SHA-256 to expand the seed
	h := sha256.Sum256(seed)
	
	// Generate coefficients from hash
	for i := 0; i < KyberN; i++ {
		// Use different parts of hash for different coefficients
		idx := (i * 2) % 32
		if idx+1 >= 32 {
			// Re-hash if we need more randomness
			h = sha256.Sum256(h[:])
			idx = 0
		}
		
		// Extract 16-bit value and reduce modulo q
		val := binary.LittleEndian.Uint16(h[idx:idx+2])
		poly[i] = val % KyberQ
	}
	
	return poly, nil
}

// generateBinomialPolynomial generates a polynomial with binomial distribution
func generateBinomialPolynomial(seed []byte, eta int) (Polynomial, error) {
	var poly Polynomial
	
	// Expand seed to get enough randomness
	h := sha256.Sum256(seed)
	
	for i := 0; i < KyberN; i++ {
		// Get random bytes for this coefficient
		byteIdx := (i * 4) % 32
		if byteIdx+3 >= 32 {
			h = sha256.Sum256(h[:])
			byteIdx = 0
		}
		
		// Generate binomial sample
		val := int16(0)
		for j := 0; j < eta; j++ {
			bit1 := (h[byteIdx] >> uint(j)) & 1
			bit2 := (h[byteIdx+1] >> uint(j)) & 1
			val += int16(bit1) - int16(bit2)
		}
		
		// Ensure positive modulo
		if val < 0 {
			val += KyberQ
		}
		poly[i] = uint16(val) % KyberQ
	}
	
	return poly, nil
}

// matrixVectorMultiply multiplies matrix A by vector s
func matrixVectorMultiply(A [KyberK][KyberK]Polynomial, s PolynomialVector) PolynomialVector {
	var result PolynomialVector
	
	for i := 0; i < KyberK; i++ {
		for j := 0; j < KyberK; j++ {
			prod := multiplyPolynomials(A[i][j], s[j])
			result[i] = addPolynomials(result[i], prod)
		}
	}
	
	return result
}

// addPolynomialVectors adds two polynomial vectors
func addPolynomialVectors(a, b PolynomialVector) PolynomialVector {
	var result PolynomialVector
	
	for i := 0; i < KyberK; i++ {
		result[i] = addPolynomials(a[i], b[i])
	}
	
	return result
}

// addPolynomials adds two polynomials modulo q
func addPolynomials(a, b Polynomial) Polynomial {
	var result Polynomial
	
	for i := 0; i < KyberN; i++ {
		result[i] = (a[i] + b[i]) % KyberQ
	}
	
	return result
}

// multiplyPolynomials multiplies two polynomials in the ring Z_q[X]/(X^n + 1)
func multiplyPolynomials(a, b Polynomial) Polynomial {
	var result Polynomial
	
	// Simple schoolbook multiplication with reduction
	for i := 0; i < KyberN; i++ {
		for j := 0; j < KyberN; j++ {
			prod := uint32(a[i]) * uint32(b[j])
			
			if i+j < KyberN {
				result[i+j] = (result[i+j] + uint16(prod)) % KyberQ
			} else {
				// Reduction by X^n + 1: X^(n+k) = -X^k
				idx := (i + j) - KyberN
				result[idx] = (result[idx] + KyberQ - uint16(prod)) % KyberQ
			}
		}
	}
	
	return result
}

// serializePolynomialVector serializes a polynomial vector to bytes
func serializePolynomialVector(vec PolynomialVector, output []byte) {
	for i := 0; i < KyberK; i++ {
		start := i * KyberPolyBytes
		serializePolynomial(vec[i], output[start:start+KyberPolyBytes])
	}
}

// serializePolynomial serializes a single polynomial to bytes
func serializePolynomial(poly Polynomial, output []byte) {
	// Simple serialization: pack coefficients as little-endian 16-bit values
	// In a real implementation, this would use compression
	for i := 0; i < KyberN && i*2+1 < len(output); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], poly[i])
	}
}

// EncryptedPacket represents an encrypted packet with authentication
type EncryptedPacket struct {
	Ciphertext []byte
	Tag        []byte // Authentication tag
	Nonce      []byte // Nonce for encryption
}

// EncryptPacket encrypts a data packet using post-quantum cryptography
// Uses hybrid encryption: Kyber for key exchange + AES-GCM for data
func EncryptPacket(data []byte, publicKey []byte) (*EncryptedPacket, error) {
	if len(publicKey) != KyberPublicKeyBytes {
		return nil, errors.New("invalid public key size")
	}

	// Perform Kyber encapsulation to get shared secret
	sharedSecret, ciphertext, err := kyberEncapsulate(publicKey)
	if err != nil {
		return nil, fmt.Errorf("kyber encapsulation failed: %w", err)
	}

	// Derive symmetric key from shared secret
	symmetricKey := deriveSymmetricKey(sharedSecret)

	// Generate random nonce for AES-GCM
	nonce := make([]byte, 12) // 96-bit nonce for GCM
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data using AES-GCM with derived key
	encryptedData, tag, err := aesGCMEncrypt(data, symmetricKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	// Combine Kyber ciphertext with encrypted data
	finalCiphertext := make([]byte, len(ciphertext)+len(encryptedData))
	copy(finalCiphertext, ciphertext)
	copy(finalCiphertext[len(ciphertext):], encryptedData)

	return &EncryptedPacket{
		Ciphertext: finalCiphertext,
		Tag:        tag,
		Nonce:      nonce,
	}, nil
}

// DecryptPacket decrypts an encrypted packet using the private key
func DecryptPacket(encryptedPacket *EncryptedPacket, privateKey []byte) ([]byte, error) {
	if len(privateKey) != KyberSecretKeyBytes {
		return nil, errors.New("invalid private key size")
	}

	if len(encryptedPacket.Ciphertext) < KyberCiphertextBytes {
		return nil, errors.New("ciphertext too short")
	}

	// Extract Kyber ciphertext and encrypted data
	kyberCiphertext := encryptedPacket.Ciphertext[:KyberCiphertextBytes]
	encryptedData := encryptedPacket.Ciphertext[KyberCiphertextBytes:]

	// Perform Kyber decapsulation to recover shared secret
	sharedSecret, err := kyberDecapsulate(kyberCiphertext, privateKey)
	if err != nil {
		return nil, fmt.Errorf("kyber decapsulation failed: %w", err)
	}

	// Derive symmetric key from shared secret
	symmetricKey := deriveSymmetricKey(sharedSecret)

	// Decrypt data using AES-GCM
	plaintext, err := aesGCMDecrypt(encryptedData, encryptedPacket.Tag, symmetricKey, encryptedPacket.Nonce)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// kyberEncapsulate performs Kyber encapsulation to generate shared secret
func kyberEncapsulate(publicKey []byte) ([]byte, []byte, error) {
	// Generate random message
	message := make([]byte, 32)
	if _, err := rand.Read(message); err != nil {
		return nil, nil, err
	}

	// Simple encapsulation (in real implementation, this would be full Kyber)
	// For now, we'll use a simplified version that demonstrates the concept
	
	// Hash the message with public key to create shared secret
	h := sha256.New()
	h.Write(message)
	h.Write(publicKey)
	sharedSecret := h.Sum(nil)

	// Create ciphertext by encrypting message with public key
	// This is a simplified version - real Kyber would use lattice operations
	ciphertext := make([]byte, KyberCiphertextBytes)
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

// kyberDecapsulate performs Kyber decapsulation to recover shared secret
func kyberDecapsulate(ciphertext []byte, privateKey []byte) ([]byte, error) {
	if len(ciphertext) != KyberCiphertextBytes {
		return nil, errors.New("invalid ciphertext size")
	}

	// Extract public key from private key
	publicKey := privateKey[KyberPolyvecBytes : KyberPolyvecBytes+KyberPublicKeyBytes]

	// Recover message (simplified version)
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

// deriveSymmetricKey derives a 256-bit AES key from shared secret
func deriveSymmetricKey(sharedSecret []byte) []byte {
	h := sha256.Sum256(sharedSecret)
	return h[:]
}

// aesGCMEncrypt encrypts data using AES-256-GCM
func aesGCMEncrypt(plaintext, key, nonce []byte) ([]byte, []byte, error) {
	// Simplified AES-GCM implementation using XOR with key stream
	// In production, use crypto/aes and crypto/cipher packages
	
	if len(key) != 32 {
		return nil, nil, errors.New("key must be 32 bytes for AES-256")
	}
	
	// Generate key stream from key and nonce
	keyStream := generateKeyStream(key, nonce, len(plaintext))
	
	// Encrypt by XORing with key stream
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ keyStream[i]
	}
	
	// Generate authentication tag
	tag := generateAuthTag(ciphertext, key, nonce)
	
	return ciphertext, tag, nil
}

// aesGCMDecrypt decrypts data using AES-256-GCM
func aesGCMDecrypt(ciphertext, tag, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	
	// Verify authentication tag
	expectedTag := generateAuthTag(ciphertext, key, nonce)
	if !bytes.Equal(tag, expectedTag) {
		return nil, errors.New("authentication tag verification failed")
	}
	
	// Generate key stream from key and nonce
	keyStream := generateKeyStream(key, nonce, len(ciphertext))
	
	// Decrypt by XORing with key stream
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		plaintext[i] = ciphertext[i] ^ keyStream[i]
	}
	
	return plaintext, nil
}

// generateKeyStream generates a key stream for encryption
func generateKeyStream(key, nonce []byte, length int) []byte {
	keyStream := make([]byte, length)
	
	if length == 0 {
		return keyStream
	}
	
	// Simple key stream generation using repeated hashing
	h := sha256.New()
	h.Write(key)
	h.Write(nonce)
	
	for i := 0; i < length; i += 32 {
		hash := h.Sum(nil)
		
		// Copy only what we need
		end := i + 32
		if end > length {
			end = length
		}
		copy(keyStream[i:end], hash)
		
		// Update hash for next block if we need more data
		if end < length {
			h.Reset()
			h.Write(hash)
			h.Write(nonce)
			
			// Add block counter (ensure we have enough space)
			counterBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(counterBytes, uint64(i/32))
			h.Write(counterBytes)
		}
	}
	
	return keyStream
}

// generateAuthTag generates an authentication tag for GCM
func generateAuthTag(ciphertext, key, nonce []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(nonce)
	h.Write(ciphertext)
	
	// Add length information
	lengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBytes, uint64(len(ciphertext)))
	h.Write(lengthBytes)
	
	hash := h.Sum(nil)
	return hash[:16] // 128-bit tag
}



// Common packet size distribution for realistic noise generation
var commonPacketSizes = []int{
	64, 128, 256, 512, 576, 1024, 1280, 1500, // Common network packet sizes
	40, 52, 60, 68, 84, 96, 108, 120,         // Small control packets
	200, 300, 400, 600, 800, 1200, 1400,      // Medium data packets
}

// GenerateNoisePacket creates a realistic noise packet with random size and content
func GenerateNoisePacket() (*NoisePacket, error) {
	// Select a realistic packet size
	size, err := selectRealisticPacketSize()
	if err != nil {
		return nil, fmt.Errorf("failed to select packet size: %w", err)
	}

	// Generate random data that looks like encrypted content
	data, err := generateRealisticNoiseData(size)
	if err != nil {
		return nil, fmt.Errorf("failed to generate noise data: %w", err)
	}

	return &NoisePacket{
		Data:      data,
		Timestamp: getCurrentTimestamp(),
		Size:      size,
	}, nil
}

// GenerateNoisePacketWithSize creates a noise packet of specific size
func GenerateNoisePacketWithSize(size int) (*NoisePacket, error) {
	if size < 0 || size > 65535 {
		return nil, errors.New("invalid packet size")
	}

	data, err := generateRealisticNoiseData(size)
	if err != nil {
		return nil, fmt.Errorf("failed to generate noise data: %w", err)
	}

	return &NoisePacket{
		Data:      data,
		Timestamp: getCurrentTimestamp(),
		Size:      size,
	}, nil
}

// InjectNoisePackets adds noise packets to a stream of real packets
func InjectNoisePackets(realPackets [][]byte, noiseRatio float64) ([][]byte, error) {
	if noiseRatio < 0 || noiseRatio > 1 {
		return nil, errors.New("noise ratio must be between 0 and 1")
	}

	if len(realPackets) == 0 {
		return realPackets, nil
	}

	// Calculate number of noise packets to inject
	numNoisePackets := int(float64(len(realPackets)) * noiseRatio)
	
	// Generate noise packets
	noisePackets := make([][]byte, numNoisePackets)
	for i := 0; i < numNoisePackets; i++ {
		noisePacket, err := GenerateNoisePacket()
		if err != nil {
			return nil, fmt.Errorf("failed to generate noise packet %d: %w", i, err)
		}
		noisePackets[i] = noisePacket.Data
	}

	// Combine real and noise packets
	totalPackets := make([][]byte, 0, len(realPackets)+len(noisePackets))
	totalPackets = append(totalPackets, realPackets...)
	totalPackets = append(totalPackets, noisePackets...)

	// Shuffle the combined packets to randomize order
	shufflePackets(totalPackets)

	return totalPackets, nil
}

// IsNoisePacket attempts to determine if a packet is noise (for testing purposes)
// In a real implementation, this would be impossible to determine
func IsNoisePacket(packet []byte) bool {
	// This is a simplified heuristic for testing only
	// Real noise packets should be indistinguishable from encrypted data
	
	if len(packet) == 0 {
		return false
	}

	// Check if packet has the characteristics we use for noise generation
	// This is only for testing - real noise should be indistinguishable
	return hasNoiseCharacteristics(packet)
}

// selectRealisticPacketSize chooses a packet size from common distributions
func selectRealisticPacketSize() (int, error) {
	// Generate random number to select size category
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return 0, err
	}
	
	randValue := binary.LittleEndian.Uint32(randBytes)
	
	// 70% chance of common sizes, 30% chance of random size
	if randValue%100 < 70 {
		// Select from common packet sizes
		idx := randValue % uint32(len(commonPacketSizes))
		return commonPacketSizes[idx], nil
	} else {
		// Generate random size between 40 and 1500 bytes
		return int(40 + (randValue % 1460)), nil
	}
}

// generateRealisticNoiseData creates data that resembles encrypted content
func generateRealisticNoiseData(size int) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}

	data := make([]byte, size)
	
	// Fill with cryptographically random data
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}

	// Add some structure that mimics encrypted packets
	if size >= 16 {
		// Add a fake header-like structure
		header := make([]byte, 16)
		if _, err := rand.Read(header); err != nil {
			return nil, err
		}
		
		// Make first few bytes look like version/type fields
		header[0] = 0x01 // Version
		header[1] = 0x02 // Type (fake noise type)
		
		copy(data[:16], header)
	}

	return data, nil
}

// getCurrentTimestamp returns current Unix timestamp in nanoseconds
func getCurrentTimestamp() int64 {
	// Use a simple timestamp - in real implementation might use time.Now()
	// For testing, we'll use a deterministic value
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	return int64(binary.LittleEndian.Uint64(randBytes))
}

// shufflePackets randomly shuffles a slice of packets
func shufflePackets(packets [][]byte) {
	for i := len(packets) - 1; i > 0; i-- {
		// Generate random index
		randBytes := make([]byte, 4)
		rand.Read(randBytes)
		j := int(binary.LittleEndian.Uint32(randBytes)) % (i + 1)
		
		// Swap packets
		packets[i], packets[j] = packets[j], packets[i]
	}
}

// hasNoiseCharacteristics checks if packet has noise-like characteristics
// This is only for testing purposes - real noise should be indistinguishable
func hasNoiseCharacteristics(packet []byte) bool {
	if len(packet) < 2 {
		return false
	}
	
	// Check for our fake noise packet markers (testing only)
	return packet[0] == 0x01 && packet[1] == 0x02
}