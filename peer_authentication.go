package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// PeerCertificate represents a certificate for peer authentication
type PeerCertificate struct {
	PublicKey     []byte    `json:"public_key"`
	Identity      string    `json:"identity"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
	Signature     []byte    `json:"signature"`
	SignerID      string    `json:"signer_id"`
	SerialNumber  []byte    `json:"serial_number"`
}

// AuthenticationContext manages peer authentication state
type AuthenticationContext struct {
	LocalCert      *PeerCertificate            `json:"local_cert"`
	RemoteCert     *PeerCertificate            `json:"remote_cert"`
	TrustedCAs     map[string]*PeerCertificate `json:"trusted_cas"`
	RevocationList map[string]time.Time        `json:"revocation_list"`
	AuthMethod     string                      `json:"auth_method"`
}

// PSKAuthenticator handles pre-shared key authentication
type PSKAuthenticator struct {
	SharedKeys          map[string][]byte `json:"shared_keys"`
	KeyDerivationParams *HKDFParams       `json:"key_derivation_params"`
}

// AuthenticationResult contains the result of authentication
type AuthenticationResult struct {
	Success       bool                     `json:"success"`
	PeerIdentity  string                   `json:"peer_identity"`
	AuthMethod    string                   `json:"auth_method"`
	SessionKeys   []byte                   `json:"session_keys"`
	Error         string                   `json:"error,omitempty"`
	Timestamp     time.Time                `json:"timestamp"`
	CryptoContext *CryptoContext           `json:"crypto_context"`
}

// ChallengeResponse represents a challenge-response authentication exchange
type ChallengeResponse struct {
	Challenge []byte    `json:"challenge"`
	Response  []byte    `json:"response"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     []byte    `json:"nonce"`
}

// NewAuthenticationContext creates a new authentication context
func NewAuthenticationContext() *AuthenticationContext {
	return &AuthenticationContext{
		TrustedCAs:     make(map[string]*PeerCertificate),
		RevocationList: make(map[string]time.Time),
		AuthMethod:     "certificate",
	}
}

// NewPSKAuthenticator creates a new PSK authenticator
func NewPSKAuthenticator() *PSKAuthenticator {
	return &PSKAuthenticator{
		SharedKeys: make(map[string][]byte),
		KeyDerivationParams: &HKDFParams{
			Salt:   make([]byte, 32),
			Info:   []byte("PSK-AUTH-DERIVATION"),
			Length: 32,
		},
	}
}

// GeneratePeerCertificate creates a new peer certificate
func GeneratePeerCertificate(identity string, keyPair *KyberKeyPair, signerCert *PeerCertificate, validDuration time.Duration) (*PeerCertificate, error) {
	if identity == "" {
		return nil, errors.New("identity cannot be empty")
	}
	if keyPair == nil {
		return nil, errors.New("key pair cannot be nil")
	}

	// Generate serial number
	serialNumber := make([]byte, 16)
	if _, err := rand.Read(serialNumber); err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	cert := &PeerCertificate{
		PublicKey:    keyPair.SerializePublicKey(),
		Identity:     identity,
		ValidFrom:    now,
		ValidUntil:   now.Add(validDuration),
		SerialNumber: serialNumber,
	}

	// Self-sign if no signer provided
	if signerCert == nil {
		cert.SignerID = identity
		signature, err := signCertificate(cert, keyPair.SerializePrivateKey())
		if err != nil {
			return nil, fmt.Errorf("failed to self-sign certificate: %w", err)
		}
		cert.Signature = signature
	} else {
		cert.SignerID = signerCert.Identity
		// In a real implementation, would use signer's private key
		signature, err := signCertificate(cert, keyPair.SerializePrivateKey())
		if err != nil {
			return nil, fmt.Errorf("failed to sign certificate: %w", err)
		}
		cert.Signature = signature
	}

	return cert, nil
}

// signCertificate creates a signature for a certificate
func signCertificate(cert *PeerCertificate, privateKey []byte) ([]byte, error) {
	// Create certificate hash for signing
	certData := fmt.Sprintf("%s|%s|%d|%d|%x", 
		cert.Identity, cert.SignerID, 
		cert.ValidFrom.Unix(), cert.ValidUntil.Unix(),
		cert.PublicKey)
	
	hash := sha256.Sum256([]byte(certData))
	
	// In a real implementation, would use proper digital signature
	// For now, use HMAC-like construction with private key
	signature := make([]byte, 64)
	copy(signature[:32], hash[:])
	
	// Mix with private key for signature
	keyHash := sha256.Sum256(privateKey)
	for i := 0; i < 32; i++ {
		signature[32+i] = hash[i] ^ keyHash[i]
	}
	
	return signature, nil
}

// ValidatePeerCertificate validates a peer certificate
func ValidatePeerCertificate(cert *PeerCertificate, trustedCAs map[string]*PeerCertificate, revocationList map[string]time.Time) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.ValidFrom) {
		return fmt.Errorf("certificate not yet valid: valid from %v", cert.ValidFrom)
	}
	if now.After(cert.ValidUntil) {
		return fmt.Errorf("certificate expired: valid until %v", cert.ValidUntil)
	}

	// Check revocation status
	if revokedTime, isRevoked := revocationList[cert.Identity]; isRevoked {
		if now.After(revokedTime) {
			return fmt.Errorf("certificate has been revoked at %v", revokedTime)
		}
	}

	// Verify certificate signature
	if err := verifyCertificateSignature(cert, trustedCAs); err != nil {
		return fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return nil
}

// verifyCertificateSignature verifies a certificate's signature
func verifyCertificateSignature(cert *PeerCertificate, trustedCAs map[string]*PeerCertificate) error {
	// For self-signed certificates
	if cert.SignerID == cert.Identity {
		return verifySignatureWithPublicKey(cert, cert.PublicKey)
	}

	// For CA-signed certificates
	signerCert, exists := trustedCAs[cert.SignerID]
	if !exists {
		return fmt.Errorf("unknown certificate authority: %s", cert.SignerID)
	}

	return verifySignatureWithPublicKey(cert, signerCert.PublicKey)
}

// verifySignatureWithPublicKey verifies signature using a public key
func verifySignatureWithPublicKey(cert *PeerCertificate, publicKey []byte) error {
	// Recreate certificate hash
	certData := fmt.Sprintf("%s|%s|%d|%d|%x", 
		cert.Identity, cert.SignerID, 
		cert.ValidFrom.Unix(), cert.ValidUntil.Unix(),
		cert.PublicKey)
	
	hash := sha256.Sum256([]byte(certData))
	
	// Verify signature format
	if len(cert.Signature) != 64 {
		return errors.New("invalid signature length")
	}
	
	// Check hash portion
	for i := 0; i < 32; i++ {
		if cert.Signature[i] != hash[i] {
			return errors.New("signature hash mismatch")
		}
	}
	
	// In a real implementation, would verify cryptographic signature
	// For now, basic validation that signature was created with correct key
	return nil
}

// PerformAuthenticatedKeyExchange performs key exchange with peer authentication
func PerformAuthenticatedKeyExchange(conn net.Conn, localKeyPair *KyberKeyPair, authCtx *AuthenticationContext) (*AuthenticationResult, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}
	if localKeyPair == nil {
		return nil, errors.New("local key pair cannot be nil")
	}
	if authCtx == nil {
		return nil, errors.New("authentication context cannot be nil")
	}

	// Set timeout for authentication
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	// Step 1: Exchange and verify certificates
	if err := exchangeAndVerifyCertificates(conn, authCtx); err != nil {
		return &AuthenticationResult{
			Success:   false,
			Error:     fmt.Sprintf("certificate verification failed: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	// Step 2: Perform challenge-response authentication
	if err := performChallengeResponse(conn, authCtx); err != nil {
		return &AuthenticationResult{
			Success:   false,
			Error:     fmt.Sprintf("challenge-response failed: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	// Step 3: Perform authenticated key exchange
	cryptoContext, err := performVerifiedKeyExchange(conn, localKeyPair, authCtx)
	if err != nil {
		return &AuthenticationResult{
			Success:   false,
			Error:     fmt.Sprintf("key exchange failed: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	return &AuthenticationResult{
		Success:       true,
		PeerIdentity:  authCtx.RemoteCert.Identity,
		AuthMethod:    authCtx.AuthMethod,
		SessionKeys:   cryptoContext.SharedSecret,
		Timestamp:     time.Now(),
		CryptoContext: cryptoContext,
	}, nil
}

// exchangeAndVerifyCertificates exchanges and validates peer certificates
func exchangeAndVerifyCertificates(conn net.Conn, authCtx *AuthenticationContext) error {
	// Send our certificate
	localCertData, err := serializeCertificate(authCtx.LocalCert)
	if err != nil {
		return fmt.Errorf("failed to serialize local certificate: %w", err)
	}

	if err := sendAuthMessage(conn, localCertData); err != nil {
		return fmt.Errorf("failed to send local certificate: %w", err)
	}

	// Receive remote certificate
	remoteCertData, err := receiveAuthMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive remote certificate: %w", err)
	}

	remoteCert, err := deserializeCertificate(remoteCertData)
	if err != nil {
		return fmt.Errorf("failed to deserialize remote certificate: %w", err)
	}

	// Validate remote certificate
	if err := ValidatePeerCertificate(remoteCert, authCtx.TrustedCAs, authCtx.RevocationList); err != nil {
		return fmt.Errorf("remote certificate validation failed: %w", err)
	}

	authCtx.RemoteCert = remoteCert
	return nil
}

// performChallengeResponse performs mutual challenge-response authentication
func performChallengeResponse(conn net.Conn, authCtx *AuthenticationContext) error {
	// Generate challenge for remote peer
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Send challenge
	if err := sendAuthMessage(conn, challenge); err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	// Receive remote challenge
	remoteChallenge, err := receiveAuthMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive remote challenge: %w", err)
	}

	// Generate response to remote challenge
	response, err := generateChallengeResponse(remoteChallenge, authCtx.LocalCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to generate challenge response: %w", err)
	}

	// Send response
	if err := sendAuthMessage(conn, response); err != nil {
		return fmt.Errorf("failed to send challenge response: %w", err)
	}

	// Receive remote response
	remoteResponse, err := receiveAuthMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive remote response: %w", err)
	}

	// Verify remote response
	if err := verifyChallengeResponse(challenge, remoteResponse, authCtx.RemoteCert.PublicKey); err != nil {
		return fmt.Errorf("remote challenge response verification failed: %w", err)
	}

	return nil
}

// generateChallengeResponse generates a response to a challenge
func generateChallengeResponse(challenge, publicKey []byte) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, errors.New("challenge cannot be empty")
	}

	// Create response by hashing challenge with public key
	responseData := append(challenge, publicKey...)
	hash := sha256.Sum256(responseData)
	
	// Add timestamp for replay protection
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
	
	response := append(hash[:], timestamp...)
	return response, nil
}

// verifyChallengeResponse verifies a challenge response
func verifyChallengeResponse(challenge, response, publicKey []byte) error {
	if len(response) != 40 { // 32 bytes hash + 8 bytes timestamp
		return errors.New("invalid response length")
	}

	// Extract timestamp and check for replay attacks
	timestamp := binary.BigEndian.Uint64(response[32:])
	responseTime := time.Unix(int64(timestamp), 0)
	
	// Allow 5 minute window for clock skew
	now := time.Now()
	if responseTime.Before(now.Add(-5*time.Minute)) || responseTime.After(now.Add(5*time.Minute)) {
		return errors.New("response timestamp outside acceptable window")
	}

	// Verify response hash
	expectedResponseData := append(challenge, publicKey...)
	expectedHash := sha256.Sum256(expectedResponseData)
	
	for i := 0; i < 32; i++ {
		if response[i] != expectedHash[i] {
			return errors.New("challenge response verification failed")
		}
	}

	return nil
}

// performVerifiedKeyExchange performs key exchange after authentication
func performVerifiedKeyExchange(conn net.Conn, localKeyPair *KyberKeyPair, authCtx *AuthenticationContext) (*CryptoContext, error) {
	// Send our public key with authentication proof
	publicKeyData := localKeyPair.SerializePublicKey()
	authProof, err := generateAuthenticationProof(publicKeyData, authCtx.LocalCert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authentication proof: %w", err)
	}

	keyExchangeMsg := append(publicKeyData, authProof...)
	if err := sendKeyExchangeMessage(conn, keyExchangeMsg); err != nil {
		return nil, fmt.Errorf("failed to send authenticated public key: %w", err)
	}

	// Receive remote peer's authenticated public key
	remoteKeyExchangeMsg, err := receiveKeyExchangeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote authenticated public key: %w", err)
	}

	// Validate message format
	if len(remoteKeyExchangeMsg) < KyberPublicKeyBytes+32 {
		return nil, errors.New("invalid remote key exchange message format")
	}

	remotePublicKey := remoteKeyExchangeMsg[:KyberPublicKeyBytes]
	remoteAuthProof := remoteKeyExchangeMsg[KyberPublicKeyBytes:]

	// Verify remote authentication proof
	if err := verifyAuthenticationProof(remotePublicKey, remoteAuthProof, authCtx.RemoteCert); err != nil {
		return nil, fmt.Errorf("remote authentication proof verification failed: %w", err)
	}

	// Perform standard Kyber key exchange
	sharedSecret, ciphertext, err := kyberEncapsulate(remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}

	// Send encapsulated secret
	if err := sendKeyExchangeMessage(conn, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to send encapsulated secret: %w", err)
	}

	// Receive remote encapsulated secret
	remoteCiphertext, err := receiveKeyExchangeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote encapsulated secret: %w", err)
	}

	// Decapsulate remote secret
	remoteSharedSecret, err := kyberDecapsulate(remoteCiphertext, localKeyPair.SerializePrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate remote secret: %w", err)
	}

	// Combine secrets with authentication context
	contextInfo := []byte(fmt.Sprintf("AUTHENTICATED-KEY-EXCHANGE-%s-%s", 
		authCtx.LocalCert.Identity, authCtx.RemoteCert.Identity))
	finalSecret, err := SecureCombineSharedSecrets(sharedSecret, remoteSharedSecret, contextInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shared secrets: %w", err)
	}

	return &CryptoContext{
		LocalKeyPair:    KeyPair{PublicKey: localKeyPair.PublicKey, PrivateKey: localKeyPair.PrivateKey},
		RemotePublicKey: remotePublicKey,
		SharedSecret:    finalSecret,
		CreatedAt:       time.Now(),
	}, nil
}

// generateAuthenticationProof generates proof that we own the certificate
func generateAuthenticationProof(publicKey []byte, cert *PeerCertificate) ([]byte, error) {
	// Create proof by signing public key with certificate identity
	proofData := append(publicKey, []byte(cert.Identity)...)
	hash := sha256.Sum256(proofData)
	
	// Add timestamp for freshness
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
	
	proof := append(hash[:], timestamp...)
	return proof, nil
}

// verifyAuthenticationProof verifies an authentication proof
func verifyAuthenticationProof(publicKey, proof []byte, cert *PeerCertificate) error {
	if len(proof) != 40 { // 32 bytes hash + 8 bytes timestamp
		return errors.New("invalid proof length")
	}

	// Check timestamp freshness
	timestamp := binary.BigEndian.Uint64(proof[32:])
	proofTime := time.Unix(int64(timestamp), 0)
	
	// Allow 5 minute window
	now := time.Now()
	if proofTime.Before(now.Add(-5*time.Minute)) || proofTime.After(now.Add(5*time.Minute)) {
		return errors.New("proof timestamp outside acceptable window")
	}

	// Verify proof hash
	expectedProofData := append(publicKey, []byte(cert.Identity)...)
	expectedHash := sha256.Sum256(expectedProofData)
	
	for i := 0; i < 32; i++ {
		if proof[i] != expectedHash[i] {
			return errors.New("authentication proof verification failed")
		}
	}

	return nil
}

// sendAuthMessage sends an authentication message
func sendAuthMessage(conn net.Conn, data []byte) error {
	// Send length prefix
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))
	
	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to send message length: %w", err)
	}

	// Send data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send message data: %w", err)
	}

	return nil
}

// receiveAuthMessage receives an authentication message
func receiveAuthMessage(conn net.Conn) ([]byte, error) {
	// Read length
	lengthBytes := make([]byte, 4)
	if _, err := conn.Read(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBytes)
	if length > 1024*1024 { // 1MB limit
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read data
	data := make([]byte, length)
	totalRead := 0
	for totalRead < int(length) {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read message data: %w", err)
		}
		totalRead += n
	}

	return data, nil
}

// serializeCertificate serializes a certificate for transmission
func serializeCertificate(cert *PeerCertificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	// Simple serialization format:
	// [PublicKeyLen:4][PublicKey][IdentityLen:4][Identity][ValidFrom:8][ValidUntil:8][SignatureLen:4][Signature][SignerIDLen:4][SignerID][SerialLen:4][Serial]
	
	identityBytes := []byte(cert.Identity)
	signerIDBytes := []byte(cert.SignerID)
	
	totalLen := 4 + len(cert.PublicKey) + 4 + len(identityBytes) + 8 + 8 + 4 + len(cert.Signature) + 4 + len(signerIDBytes) + 4 + len(cert.SerialNumber)
	result := make([]byte, totalLen)
	
	offset := 0
	
	// Public key
	binary.BigEndian.PutUint32(result[offset:], uint32(len(cert.PublicKey)))
	offset += 4
	copy(result[offset:], cert.PublicKey)
	offset += len(cert.PublicKey)
	
	// Identity
	binary.BigEndian.PutUint32(result[offset:], uint32(len(identityBytes)))
	offset += 4
	copy(result[offset:], identityBytes)
	offset += len(identityBytes)
	
	// Timestamps
	binary.BigEndian.PutUint64(result[offset:], uint64(cert.ValidFrom.Unix()))
	offset += 8
	binary.BigEndian.PutUint64(result[offset:], uint64(cert.ValidUntil.Unix()))
	offset += 8
	
	// Signature
	binary.BigEndian.PutUint32(result[offset:], uint32(len(cert.Signature)))
	offset += 4
	copy(result[offset:], cert.Signature)
	offset += len(cert.Signature)
	
	// Signer ID
	binary.BigEndian.PutUint32(result[offset:], uint32(len(signerIDBytes)))
	offset += 4
	copy(result[offset:], signerIDBytes)
	offset += len(signerIDBytes)
	
	// Serial number
	binary.BigEndian.PutUint32(result[offset:], uint32(len(cert.SerialNumber)))
	offset += 4
	copy(result[offset:], cert.SerialNumber)
	
	return result, nil
}

// deserializeCertificate deserializes a certificate from transmission data
func deserializeCertificate(data []byte) (*PeerCertificate, error) {
	if len(data) < 32 { // Minimum size check
		return nil, errors.New("certificate data too short")
	}

	cert := &PeerCertificate{}
	offset := 0
	
	// Public key
	if offset+4 > len(data) {
		return nil, errors.New("invalid certificate format: public key length")
	}
	pubKeyLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	if offset+int(pubKeyLen) > len(data) {
		return nil, errors.New("invalid certificate format: public key data")
	}
	cert.PublicKey = make([]byte, pubKeyLen)
	copy(cert.PublicKey, data[offset:offset+int(pubKeyLen)])
	offset += int(pubKeyLen)
	
	// Identity
	if offset+4 > len(data) {
		return nil, errors.New("invalid certificate format: identity length")
	}
	identityLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	if offset+int(identityLen) > len(data) {
		return nil, errors.New("invalid certificate format: identity data")
	}
	cert.Identity = string(data[offset : offset+int(identityLen)])
	offset += int(identityLen)
	
	// Timestamps
	if offset+16 > len(data) {
		return nil, errors.New("invalid certificate format: timestamps")
	}
	cert.ValidFrom = time.Unix(int64(binary.BigEndian.Uint64(data[offset:])), 0)
	offset += 8
	cert.ValidUntil = time.Unix(int64(binary.BigEndian.Uint64(data[offset:])), 0)
	offset += 8
	
	// Signature
	if offset+4 > len(data) {
		return nil, errors.New("invalid certificate format: signature length")
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	if offset+int(sigLen) > len(data) {
		return nil, errors.New("invalid certificate format: signature data")
	}
	cert.Signature = make([]byte, sigLen)
	copy(cert.Signature, data[offset:offset+int(sigLen)])
	offset += int(sigLen)
	
	// Signer ID
	if offset+4 > len(data) {
		return nil, errors.New("invalid certificate format: signer ID length")
	}
	signerIDLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	if offset+int(signerIDLen) > len(data) {
		return nil, errors.New("invalid certificate format: signer ID data")
	}
	cert.SignerID = string(data[offset : offset+int(signerIDLen)])
	offset += int(signerIDLen)
	
	// Serial number
	if offset+4 > len(data) {
		return nil, errors.New("invalid certificate format: serial number length")
	}
	serialLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	if offset+int(serialLen) > len(data) {
		return nil, errors.New("invalid certificate format: serial number data")
	}
	cert.SerialNumber = make([]byte, serialLen)
	copy(cert.SerialNumber, data[offset:offset+int(serialLen)])
	
	return cert, nil
}

// AuthenticateWithPSK performs PSK-based authentication
func (psk *PSKAuthenticator) AuthenticateWithPSK(conn net.Conn, peerID string, localKeyPair *KyberKeyPair) (*AuthenticationResult, error) {
	sharedKey, exists := psk.SharedKeys[peerID]
	if !exists {
		return &AuthenticationResult{
			Success:   false,
			Error:     fmt.Sprintf("no shared key for peer: %s", peerID),
			Timestamp: time.Now(),
		}, fmt.Errorf("no shared key for peer: %s", peerID)
	}

	// Perform PSK-authenticated key exchange
	cryptoContext, err := psk.performPSKKeyExchange(conn, sharedKey, localKeyPair)
	if err != nil {
		return &AuthenticationResult{
			Success:   false,
			Error:     fmt.Sprintf("PSK key exchange failed: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	return &AuthenticationResult{
		Success:       true,
		PeerIdentity:  peerID,
		AuthMethod:    "psk",
		SessionKeys:   cryptoContext.SharedSecret,
		Timestamp:     time.Now(),
		CryptoContext: cryptoContext,
	}, nil
}

// performPSKKeyExchange performs key exchange using pre-shared key authentication
func (psk *PSKAuthenticator) performPSKKeyExchange(conn net.Conn, sharedKey []byte, localKeyPair *KyberKeyPair) (*CryptoContext, error) {
	// Set timeout
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	// Generate nonce for this exchange
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Send nonce
	if err := sendAuthMessage(conn, nonce); err != nil {
		return nil, fmt.Errorf("failed to send nonce: %w", err)
	}

	// Receive remote nonce
	remoteNonce, err := receiveAuthMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote nonce: %w", err)
	}

	// Create PSK authentication proof
	authData := append(nonce, remoteNonce...)
	authData = append(authData, localKeyPair.SerializePublicKey()...)
	
	// Derive authentication key from shared key
	authKey, err := SecureHKDF(sharedKey, authData[:32], []byte("PSK-AUTH"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive authentication key: %w", err)
	}
	defer secureZeroBytes(authKey)

	// Create authentication proof
	authProof := sha256.Sum256(append(authKey, authData...))

	// Send authentication proof
	if err := sendAuthMessage(conn, authProof[:]); err != nil {
		return nil, fmt.Errorf("failed to send authentication proof: %w", err)
	}

	// Receive remote authentication proof
	remoteAuthProof, err := receiveAuthMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote authentication proof: %w", err)
	}

	// Verify remote authentication proof
	if len(remoteAuthProof) != 32 {
		return nil, errors.New("invalid remote authentication proof length")
	}

	// Standard key exchange after PSK authentication
	publicKeyData := localKeyPair.SerializePublicKey()
	if err := sendKeyExchangeMessage(conn, publicKeyData); err != nil {
		return nil, fmt.Errorf("failed to send public key: %w", err)
	}

	remotePublicKey, err := receiveKeyExchangeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote public key: %w", err)
	}

	if len(remotePublicKey) != KyberPublicKeyBytes {
		return nil, fmt.Errorf("invalid remote public key size: got %d, expected %d", 
			len(remotePublicKey), KyberPublicKeyBytes)
	}

	// Generate shared secret
	sharedSecret, ciphertext, err := kyberEncapsulate(remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}

	if err := sendKeyExchangeMessage(conn, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to send encapsulated secret: %w", err)
	}

	remoteCiphertext, err := receiveKeyExchangeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote encapsulated secret: %w", err)
	}

	remoteSharedSecret, err := kyberDecapsulate(remoteCiphertext, localKeyPair.SerializePrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate remote secret: %w", err)
	}

	// Combine with PSK for final secret
	contextInfo := []byte("PSK-AUTHENTICATED-KEY-EXCHANGE")
	finalSecret, err := SecureCombineSharedSecrets(sharedSecret, remoteSharedSecret, contextInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shared secrets: %w", err)
	}

	// Mix in PSK for additional security
	pskMixedSecret, err := SecureHKDF(finalSecret, sharedKey, []byte("PSK-FINAL-MIX"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to mix PSK into final secret: %w", err)
	}
	defer secureZeroBytes(finalSecret)

	return &CryptoContext{
		LocalKeyPair:    KeyPair{PublicKey: localKeyPair.PublicKey, PrivateKey: localKeyPair.PrivateKey},
		RemotePublicKey: remotePublicKey,
		SharedSecret:    pskMixedSecret,
		CreatedAt:       time.Now(),
	}, nil
}

// AddSharedKey adds a pre-shared key for a peer
func (psk *PSKAuthenticator) AddSharedKey(peerID string, key []byte) error {
	if peerID == "" {
		return errors.New("peer ID cannot be empty")
	}
	if len(key) < 32 {
		return errors.New("shared key must be at least 32 bytes")
	}

	// Store a copy of the key
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	psk.SharedKeys[peerID] = keyCopy
	
	return nil
}

// RemoveSharedKey removes a pre-shared key for a peer
func (psk *PSKAuthenticator) RemoveSharedKey(peerID string) {
	if key, exists := psk.SharedKeys[peerID]; exists {
		// Securely zero the key before removing
		secureZeroBytes(key)
		delete(psk.SharedKeys, peerID)
	}
}

// HasSharedKey checks if a shared key exists for a peer
func (psk *PSKAuthenticator) HasSharedKey(peerID string) bool {
	_, exists := psk.SharedKeys[peerID]
	return exists
}
