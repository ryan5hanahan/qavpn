package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// EnhancedTunnelManager provides secure tunnel management with comprehensive validation
type EnhancedTunnelManager struct {
	tcpTunnels    map[string]*TCPTunnel
	udpTunnels    map[string]*UDPTunnel
	mutex         sync.RWMutex
	maxTunnels    int
	rateLimiter   *RateLimiter
	connTracker   map[string]time.Time
	validator     *NetworkAddressValidator
	resourceMgr   *ResourceCleanupManager
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

// NewEnhancedTunnelManager creates a new enhanced tunnel manager
func NewEnhancedTunnelManager(maxTunnels int, rateLimit int) *EnhancedTunnelManager {
	return &EnhancedTunnelManager{
		tcpTunnels:  make(map[string]*TCPTunnel),
		udpTunnels:  make(map[string]*UDPTunnel),
		maxTunnels:  maxTunnels,
		rateLimiter: NewRateLimiter(rateLimit, time.Second),
		connTracker: make(map[string]time.Time),
		validator:   NewNetworkAddressValidator(),
		resourceMgr: NewResourceCleanupManager(),
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request is allowed under the rate limit
func (rl *RateLimiter) Allow(identifier string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	
	// Get existing requests for this identifier
	requests, exists := rl.requests[identifier]
	if !exists {
		rl.requests[identifier] = []time.Time{now}
		return true
	}

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, reqTime := range requests {
		if now.Sub(reqTime) <= rl.window {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if we're under the limit
	if len(validRequests) < rl.limit {
		validRequests = append(validRequests, now)
		rl.requests[identifier] = validRequests
		return true
	}

	return false
}

// CreateTCPTunnelSecure creates a TCP tunnel with enhanced security validation
func (etm *EnhancedTunnelManager) CreateTCPTunnelSecure(address string, timeout time.Duration) (*TCPTunnel, error) {
	// Validate address format and security
	if err := etm.validator.ValidateAddress(address); err != nil {
		return nil, fmt.Errorf("address validation failed: %w", err)
	}

	// Rate limiting check
	if !etm.rateLimiter.Allow(address) {
		return nil, errors.New("rate limit exceeded")
	}

	etm.mutex.Lock()
	defer etm.mutex.Unlock()

	// Connection limit enforcement
	if len(etm.tcpTunnels) >= etm.maxTunnels {
		return nil, errors.New("maximum tunnel limit reached")
	}

	// Check for connection flooding from same address
	if lastConn, exists := etm.connTracker[address]; exists {
		if time.Since(lastConn) < time.Second {
			return nil, errors.New("connection attempt too frequent")
		}
	}
	etm.connTracker[address] = time.Now()

	// Establish connection with enhanced security
	conn, err := etm.dialTCPSecure(address, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to establish secure TCP connection: %w", err)
	}

	// Generate local key pair for PQC key exchange
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate local key pair: %w", err)
	}

	// Register key pair for cleanup
	etm.resourceMgr.RegisterResource(localKeyPair)

	// Perform authenticated key exchange
	authCtx := &AuthenticationContext{
		Method:    "pqc-mutual-auth",
		Timestamp: time.Now(),
		Nonce:     make([]byte, 32),
	}
	
	if _, err := rand.Read(authCtx.Nonce); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate authentication nonce: %w", err)
	}

	cryptoContext, err := performAuthenticatedKeyExchangeWithContext(conn, localKeyPair, authCtx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("authenticated key exchange failed: %w", err)
	}

	// Create enhanced tunnel instance
	tunnel := &EnhancedTCPTunnel{
		TCPTunnel: &TCPTunnel{
			conn:          conn,
			cryptoContext: cryptoContext,
			localAddr:     conn.LocalAddr(),
			remoteAddr:    conn.RemoteAddr(),
			isActive:      true,
			createdAt:     time.Now(),
			lastActivity:  time.Now(),
		},
		validator:   etm.validator,
		rateLimiter: etm.rateLimiter,
	}

	// Add to tunnel manager
	tunnelID := generateTunnelID(tunnel.localAddr, tunnel.remoteAddr)
	etm.tcpTunnels[tunnelID] = tunnel.TCPTunnel

	return tunnel.TCPTunnel, nil
}

// dialTCPSecure establishes a secure TCP connection with enhanced validation
func (etm *EnhancedTunnelManager) dialTCPSecure(address string, timeout time.Duration) (net.Conn, error) {
	// Parse and validate the address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	// Validate port range
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}

	// Resolve address with security checks
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	// Additional security checks on resolved IP
	if err := etm.validateResolvedAddress(tcpAddr); err != nil {
		return nil, fmt.Errorf("resolved address security check failed: %w", err)
	}

	// Establish connection with timeout
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	// Configure connection for security and performance
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// Enable TCP_NODELAY for low latency
		if err := tcpConn.SetNoDelay(true); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to set TCP_NODELAY: %w", err)
		}

		// Set keep-alive parameters
		if err := tcpConn.SetKeepAlive(true); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to enable keep-alive: %w", err)
		}

		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to set keep-alive period: %w", err)
		}
	}

	return conn, nil
}

// validateResolvedAddress performs additional security checks on resolved addresses
func (etm *EnhancedTunnelManager) validateResolvedAddress(addr *net.TCPAddr) error {
	ip := addr.IP

	// Check for loopback addresses
	if ip.IsLoopback() {
		return errors.New("loopback addresses not allowed")
	}

	// Check for private network addresses in production mode
	if ip.IsPrivate() {
		return errors.New("private network addresses not allowed")
	}

	// Check for multicast addresses
	if ip.IsMulticast() {
		return errors.New("multicast addresses not allowed")
	}

	// Check for link-local addresses
	if ip.IsLinkLocalUnicast() {
		return errors.New("link-local addresses not allowed")
	}

	return nil
}

// CreateUDPTunnelSecure creates a UDP tunnel with enhanced security validation
func (etm *EnhancedTunnelManager) CreateUDPTunnelSecure(address string, timeout time.Duration) (*UDPTunnel, error) {
	// Validate address format and security
	if err := etm.validator.ValidateAddress(address); err != nil {
		return nil, fmt.Errorf("address validation failed: %w", err)
	}

	// Rate limiting check
	if !etm.rateLimiter.Allow(address) {
		return nil, errors.New("rate limit exceeded")
	}

	etm.mutex.Lock()
	defer etm.mutex.Unlock()

	// Connection limit enforcement
	if len(etm.udpTunnels) >= etm.maxTunnels {
		return nil, errors.New("maximum tunnel limit reached")
	}

	// Check for connection flooding
	if lastConn, exists := etm.connTracker[address]; exists {
		if time.Since(lastConn) < time.Second {
			return nil, errors.New("connection attempt too frequent")
		}
	}
	etm.connTracker[address] = time.Now()

	// Parse and validate remote address
	remoteAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Additional security validation
	if err := etm.validateUDPAddress(remoteAddr); err != nil {
		return nil, fmt.Errorf("UDP address validation failed: %w", err)
	}

	// Create UDP connection with security settings
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish UDP connection: %w", err)
	}

	// Set buffer limits to prevent amplification attacks
	if err := conn.SetReadBuffer(64 * 1024); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set read buffer: %w", err)
	}
	if err := conn.SetWriteBuffer(64 * 1024); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set write buffer: %w", err)
	}

	// Generate secure session ID
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate local key pair
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate local key pair: %w", err)
	}

	// Register for cleanup
	etm.resourceMgr.RegisterResource(localKeyPair)

	// Perform UDP key exchange with enhanced security
	cryptoContext, err := etm.performSecureUDPKeyExchange(conn, localKeyPair, sessionID, timeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("secure UDP key exchange failed: %w", err)
	}

	// Create enhanced tunnel instance
	tunnel := &EnhancedUDPTunnel{
		UDPTunnel: &UDPTunnel{
			conn:          conn,
			remoteAddr:    remoteAddr,
			cryptoContext: cryptoContext,
			localAddr:     conn.LocalAddr(),
			isActive:      true,
			createdAt:     time.Now(),
			lastActivity:  time.Now(),
			sessionID:     sessionID,
		},
		validator:   etm.validator,
		rateLimiter: etm.rateLimiter,
	}

	// Add to tunnel manager
	tunnelID := generateTunnelID(tunnel.localAddr, tunnel.remoteAddr)
	etm.udpTunnels[tunnelID] = tunnel.UDPTunnel

	return tunnel.UDPTunnel, nil
}

// validateUDPAddress performs UDP-specific address validation
func (etm *EnhancedTunnelManager) validateUDPAddress(addr *net.UDPAddr) error {
	ip := addr.IP

	// Check for dangerous addresses
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("unsafe UDP address: %s", ip.String())
	}

	// Check port range
	if addr.Port <= 0 || addr.Port > 65535 {
		return fmt.Errorf("invalid UDP port: %d", addr.Port)
	}

	return nil
}

// performSecureUDPKeyExchange performs enhanced UDP key exchange
func (etm *EnhancedTunnelManager) performSecureUDPKeyExchange(conn *net.UDPConn, localKeyPair *KyberKeyPair, sessionID [16]byte, timeout time.Duration) (*CryptoContext, error) {
	// Set timeout for key exchange
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{}) // Clear deadline after key exchange

	// Create authentication context
	authCtx := &AuthenticationContext{
		Method:    "udp-pqc-auth",
		Timestamp: time.Now(),
		Nonce:     make([]byte, 32),
		SessionID: sessionID[:],
	}
	
	if _, err := rand.Read(authCtx.Nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Send authenticated public key with session ID
	publicKeyData := localKeyPair.SerializePublicKey()
	authMessage := etm.createAuthenticatedMessage(publicKeyData, authCtx)
	
	if err := etm.sendSecureUDPMessage(conn, authMessage); err != nil {
		return nil, fmt.Errorf("failed to send authenticated public key: %w", err)
	}

	// Receive and validate remote peer's authenticated public key
	remoteMessage, err := etm.receiveSecureUDPMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote public key: %w", err)
	}

	remotePublicKey, remoteAuthCtx, err := etm.validateAuthenticatedMessage(remoteMessage)
	if err != nil {
		return nil, fmt.Errorf("remote message validation failed: %w", err)
	}

	// Verify session ID matches
	if !subtle.ConstantTimeCompare(remoteAuthCtx.SessionID, sessionID[:]) {
		return nil, errors.New("session ID mismatch")
	}

	// Perform key exchange with validated public key
	sharedSecret, ciphertext, err := kyberEncapsulate(remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}
	defer secureZeroBytes(sharedSecret)

	// Send encapsulated secret with authentication
	secretMessage := etm.createAuthenticatedMessage(ciphertext, authCtx)
	if err := etm.sendSecureUDPMessage(conn, secretMessage); err != nil {
		return nil, fmt.Errorf("failed to send encapsulated secret: %w", err)
	}

	// Receive remote peer's encapsulated secret
	remoteSecretMessage, err := etm.receiveSecureUDPMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote encapsulated secret: %w", err)
	}

	remoteCiphertext, _, err := etm.validateAuthenticatedMessage(remoteSecretMessage)
	if err != nil {
		return nil, fmt.Errorf("remote secret validation failed: %w", err)
	}

	// Decapsulate remote secret
	remoteSharedSecret, err := kyberDecapsulate(remoteCiphertext, localKeyPair.SerializePrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate remote secret: %w", err)
	}
	defer secureZeroBytes(remoteSharedSecret)

	// Combine shared secrets securely
	contextInfo := []byte("SECURE-UDP-KEY-EXCHANGE")
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

// createAuthenticatedMessage creates an authenticated message
func (etm *EnhancedTunnelManager) createAuthenticatedMessage(data []byte, authCtx *AuthenticationContext) []byte {
	// Simple authenticated message format: [SessionID:16][Timestamp:8][NonceLen:4][Nonce][DataLen:4][Data][HMAC:32]
	message := make([]byte, 0, 16+8+4+len(authCtx.Nonce)+4+len(data)+32)
	
	// Add session ID
	message = append(message, authCtx.SessionID...)
	
	// Add timestamp
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(authCtx.Timestamp.Unix()))
	message = append(message, timestampBytes...)
	
	// Add nonce
	nonceLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceLenBytes, uint32(len(authCtx.Nonce)))
	message = append(message, nonceLenBytes...)
	message = append(message, authCtx.Nonce...)
	
	// Add data
	dataLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dataLenBytes, uint32(len(data)))
	message = append(message, dataLenBytes...)
	message = append(message, data...)
	
	// Add HMAC (simplified - in production would use proper HMAC)
	hmac := etm.calculateSimpleHMAC(message)
	message = append(message, hmac...)
	
	return message
}

// validateAuthenticatedMessage validates an authenticated message
func (etm *EnhancedTunnelManager) validateAuthenticatedMessage(message []byte) ([]byte, *AuthenticationContext, error) {
	if len(message) < 16+8+4+4+32 { // Minimum size
		return nil, nil, errors.New("message too short")
	}
	
	offset := 0
	
	// Extract session ID
	sessionID := make([]byte, 16)
	copy(sessionID, message[offset:offset+16])
	offset += 16
	
	// Extract timestamp
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(message[offset:offset+8])), 0)
	offset += 8
	
	// Validate timestamp (within 5 minutes)
	if time.Since(timestamp) > 5*time.Minute || timestamp.After(time.Now().Add(5*time.Minute)) {
		return nil, nil, errors.New("timestamp outside acceptable window")
	}
	
	// Extract nonce
	nonceLen := binary.BigEndian.Uint32(message[offset:offset+4])
	offset += 4
	
	if nonceLen > 64 || offset+int(nonceLen) > len(message) {
		return nil, nil, errors.New("invalid nonce length")
	}
	
	nonce := make([]byte, nonceLen)
	copy(nonce, message[offset:offset+int(nonceLen)])
	offset += int(nonceLen)
	
	// Extract data
	if offset+4 > len(message) {
		return nil, nil, errors.New("invalid data length field")
	}
	
	dataLen := binary.BigEndian.Uint32(message[offset:offset+4])
	offset += 4
	
	if offset+int(dataLen)+32 > len(message) {
		return nil, nil, errors.New("invalid data length")
	}
	
	data := make([]byte, dataLen)
	copy(data, message[offset:offset+int(dataLen)])
	offset += int(dataLen)
	
	// Extract and verify HMAC
	receivedHMAC := message[offset:offset+32]
	expectedHMAC := etm.calculateSimpleHMAC(message[:offset])
	
	if !subtle.ConstantTimeCompare(receivedHMAC, expectedHMAC) {
		return nil, nil, errors.New("HMAC verification failed")
	}
	
	authCtx := &AuthenticationContext{
		Method:    "udp-pqc-auth",
		Timestamp: timestamp,
		Nonce:     nonce,
		SessionID: sessionID,
	}
	
	return data, authCtx, nil
}

// calculateSimpleHMAC calculates a simple HMAC (in production would use crypto/hmac)
func (etm *EnhancedTunnelManager) calculateSimpleHMAC(data []byte) []byte {
	// Simplified HMAC - in production would use proper HMAC-SHA256
	hmac := make([]byte, 32)
	key := []byte("secure-udp-key-exchange-hmac-key") // In production, would be derived securely
	
	for i, b := range data {
		hmac[i%32] ^= b ^ key[i%len(key)]
	}
	
	return hmac
}

// sendSecureUDPMessage sends a message over UDP with size validation
func (etm *EnhancedTunnelManager) sendSecureUDPMessage(conn *net.UDPConn, data []byte) error {
	if len(data) > 1400 { // Stay under MTU
		return errors.New("message too large for UDP")
	}
	
	_, err := conn.Write(data)
	return err
}

// receiveSecureUDPMessage receives a message over UDP with validation
func (etm *EnhancedTunnelManager) receiveSecureUDPMessage(conn *net.UDPConn) ([]byte, error) {
	buffer := make([]byte, 1500) // MTU size
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	
	if n < 64 { // Minimum message size
		return nil, errors.New("received message too short")
	}
	
	return buffer[:n], nil
}

// EnhancedTCPTunnel provides enhanced TCP tunnel with additional security
type EnhancedTCPTunnel struct {
	*TCPTunnel
	validator   *NetworkAddressValidator
	rateLimiter *RateLimiter
}

// EnhancedUDPTunnel provides enhanced UDP tunnel with additional security
type EnhancedUDPTunnel struct {
	*UDPTunnel
	validator   *NetworkAddressValidator
	rateLimiter *RateLimiter
}

// Close closes the enhanced TCP tunnel with comprehensive cleanup
func (ett *EnhancedTCPTunnel) Close() error {
	ett.mutex.Lock()
	defer ett.mutex.Unlock()

	if !ett.isActive {
		return nil // Already closed
	}

	ett.isActive = false
	
	var lastErr error
	
	// Close network connection
	if ett.conn != nil {
		if err := ett.conn.Close(); err != nil {
			lastErr = err
		}
		ett.conn = nil
	}
	
	// Clear all cryptographic material
	if ett.cryptoContext != nil {
		if ett.cryptoContext.SharedSecret != nil {
			secureZeroBytes(ett.cryptoContext.SharedSecret)
			ett.cryptoContext.SharedSecret = nil
		}
		if ett.cryptoContext.LocalKeyPair.PrivateKey != nil {
			secureZeroBytes(ett.cryptoContext.LocalKeyPair.PrivateKey)
			ett.cryptoContext.LocalKeyPair.PrivateKey = nil
		}
		ett.cryptoContext = nil
	}
	
	// Clear statistics (may contain timing information)
	ett.lastActivity = time.Time{}
	ett.createdAt = time.Time{}
	
	// Force garbage collection of sensitive data
	runtime.GC()
	
	return lastErr
}

// Close closes the enhanced UDP tunnel with comprehensive cleanup
func (eut *EnhancedUDPTunnel) Close() error {
	eut.mutex.Lock()
	defer eut.mutex.Unlock()

	if !eut.isActive {
		return nil // Already closed
	}

	eut.isActive = false
	
	var lastErr error
	
	// Close network connection
	if eut.conn != nil {
		if err := eut.conn.Close(); err != nil {
			lastErr = err
		}
		eut.conn = nil
	}
	
	// Clear all cryptographic material
	if eut.cryptoContext != nil {
		if eut.cryptoContext.SharedSecret != nil {
			secureZeroBytes(eut.cryptoContext.SharedSecret)
			eut.cryptoContext.SharedSecret = nil
		}
		if eut.cryptoContext.LocalKeyPair.PrivateKey != nil {
			secureZeroBytes(eut.cryptoContext.LocalKeyPair.PrivateKey)
			eut.cryptoContext.LocalKeyPair.PrivateKey = nil
		}
		eut.cryptoContext = nil
	}
	
	// Clear session ID
	for i := range eut.sessionID {
		eut.sessionID[i] = 0
	}
	
	// Clear statistics
	eut.lastActivity = time.Time{}
	eut.createdAt = time.Time{}
	
	// Force garbage collection
	runtime.GC()
	
	return lastErr
}

// TimingAttackResistantValidator provides constant-time validation operations
type TimingAttackResistantValidator struct {
	mutex sync.RWMutex
}

// NewTimingAttackResistantValidator creates a new timing attack resistant validator
func NewTimingAttackResistantValidator() *TimingAttackResistantValidator {
	return &TimingAttackResistantValidator{}
}

// ValidateChallengeResponse validates a challenge response in constant time
func (tarv *TimingAttackResistantValidator) ValidateChallengeResponse(challenge, response, publicKey []byte) error {
	tarv.mutex.RLock()
	defer tarv.mutex.RUnlock()

	if len(response) != 40 {
		// Perform dummy operations to maintain constant time
		tarv.performDummyValidation()
		return errors.New("invalid response length")
	}

	// Extract and validate timestamp
	timestamp := binary.BigEndian.Uint64(response[32:])
	responseTime := time.Unix(int64(timestamp), 0)
	
	now := time.Now()
	timeValid := responseTime.After(now.Add(-5*time.Minute)) && responseTime.Before(now.Add(5*time.Minute))
	
	// Generate expected response
	expectedResponseData := append(challenge, publicKey...)
	expectedHash := sha256Hash(expectedResponseData)
	
	// Constant-time comparison
	hashValid := subtle.ConstantTimeCompare(response[:32], expectedHash[:]) == 1
	
	// Combine validations in constant time
	valid := timeValid && hashValid
	
	if !valid {
		return errors.New("challenge response verification failed")
	}

	return nil
}

// performDummyValidation performs dummy operations to maintain constant time
func (tarv *TimingAttackResistantValidator) performDummyValidation() {
	// Perform operations similar to real validation to maintain timing
	dummyData := make([]byte, 64)
	rand.Read(dummyData)
	_ = sha256Hash(dummyData)
	
	// Dummy timestamp check
	now := time.Now()
	_ = now.Add(-5 * time.Minute)
}

// sha256Hash computes SHA-256 hash (simplified implementation)
func sha256Hash(data []byte) [32]byte {
	// In production, would use crypto/sha256
	var hash [32]byte
	for i, b := range data {
		hash[i%32] ^= b
	}
	return hash
}

// CertificateValidator provides enhanced certificate validation
type CertificateValidator struct {
	trustedCAs       map[string]*PeerCertificate
	revocationList   map[string]time.Time
	mutex            sync.RWMutex
	clockSkewTolerance time.Duration
}

// NewCertificateValidator creates a new certificate validator
func NewCertificateValidator() *CertificateValidator {
	return &CertificateValidator{
		trustedCAs:         make(map[string]*PeerCertificate),
		revocationList:     make(map[string]time.Time),
		clockSkewTolerance: 5 * time.Minute,
	}
}

// ValidatePeerCertificateEnhanced performs comprehensive certificate validation
func (cv *CertificateValidator) ValidatePeerCertificateEnhanced(cert *PeerCertificate) error {
	cv.mutex.RLock()
	defer cv.mutex.RUnlock()

	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Validate certificate structure
	if err := cv.validateCertificateStructure(cert); err != nil {
		return fmt.Errorf("certificate structure validation failed: %w", err)
	}

	// Time validation with clock skew tolerance
	now := time.Now()
	
	if now.Add(cv.clockSkewTolerance).Before(cert.ValidFrom) {
		return fmt.Errorf("certificate not yet valid: valid from %v (current time %v)", cert.ValidFrom, now)
	}
	if now.Add(-cv.clockSkewTolerance).After(cert.ValidUntil) {
		return fmt.Errorf("certificate expired: valid until %v (current time %v)", cert.ValidUntil, now)
	}

	// Revocation checking
	if err := cv.checkRevocationStatus(cert); err != nil {
		return fmt.Errorf("certificate revocation check failed: %w", err)
	}

	// Certificate chain validation
	if err := cv.validateCertificateChain(cert); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	// Key usage validation
	if err := cv.validateKeyUsage(cert); err != nil {
		return fmt.Errorf("key usage validation failed: %w", err)
	}

	// Cryptographic signature verification
	if err := cv.verifyCertificateSignature(cert); err != nil {
		return fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return nil
}

// validateCertificateStructure validates the basic structure of a certificate
func (cv *CertificateValidator) validateCertificateStructure(cert *PeerCertificate) error {
	if len(cert.PublicKey) == 0 {
		return errors.New("missing public key")
	}
	if cert.Identity == "" {
		return errors.New("missing identity")
	}
	if len(cert.SerialNumber) == 0 {
		return errors.New("missing serial number")
	}
	if len(cert.Signature) == 0 {
		return errors.New("missing signature")
	}
	return nil
}

// checkRevocationStatus checks if a certificate has been revoked
func (cv *CertificateValidator) checkRevocationStatus(cert *PeerCertificate) error {
	serialStr := fmt.Sprintf("%x", cert.SerialNumber)
	if revocationTime, revoked := cv.revocationList[serialStr]; revoked {
		return fmt.Errorf("certificate revoked at %v", revocationTime)
	}
	return nil
}

// validateCertificateChain validates the certificate chain
func (cv *CertificateValidator) validateCertificateChain(cert *PeerCertificate) error {
	// For self-signed certificates, verify against trusted CAs
	if cert.IssuerIdentity == cert.Identity {
		// Self-signed certificate
		if _, trusted := cv.trustedCAs[cert.Identity]; !trusted {
			return fmt.Errorf("self-signed certificate not in trusted CA list: %s", cert.Identity)
		}
		return nil
	}

	// For CA-signed certificates, verify issuer chain
	issuerCert, exists := cv.trustedCAs[cert.IssuerIdentity]
	if !exists {
		return fmt.Errorf("issuer certificate not found: %s", cert.IssuerIdentity)
	}

	// Recursively validate issuer certificate
	if err := cv.ValidatePeerCertificateEnhanced(issuerCert); err != nil {
		return fmt.Errorf("issuer certificate validation failed: %w", err)
	}

	return nil
}

// validateKeyUsage validates certificate key usage
func (cv *CertificateValidator) validateKeyUsage(cert *PeerCertificate) error {
	// Check if certificate allows the required key usage
	// This is a simplified check - in production would parse X.509 extensions
	if len(cert.KeyUsage) == 0 {
		return errors.New("certificate has no key usage specified")
	}

	// Verify key usage allows digital signatures and key agreement
	hasDigitalSignature := false
	hasKeyAgreement := false
	
	for _, usage := range cert.KeyUsage {
		if usage == "digital_signature" {
			hasDigitalSignature = true
		}
		if usage == "key_agreement" {
			hasKeyAgreement = true
		}
	}

	if !hasDigitalSignature {
		return errors.New("certificate does not allow digital signatures")
	}
	if !hasKeyAgreement {
		return errors.New("certificate does not allow key agreement")
	}

	return nil
}

// verifyCertificateSignature verifies the certificate's cryptographic signature
func (cv *CertificateValidator) verifyCertificateSignature(cert *PeerCertificate) error {
	// Get issuer's public key
	var issuerPublicKey []byte
	
	if cert.IssuerIdentity == cert.Identity {
		// Self-signed certificate
		issuerPublicKey = cert.PublicKey
	} else {
		// CA-signed certificate
		issuerCert, exists := cv.trustedCAs[cert.IssuerIdentity]
		if !exists {
			return fmt.Errorf("issuer certificate not found for signature verification: %s", cert.IssuerIdentity)
		}
		issuerPublicKey = issuerCert.PublicKey
	}

	// Create certificate data for signature verification
	certData := cv.createCertificateDataForSigning(cert)
	
	// Verify signature (simplified - in production would use proper crypto)
	if err := cv.verifySignature(certData, cert.Signature, issuerPublicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// createCertificateDataForSigning creates the data that was signed
func (cv *CertificateValidator) createCertificateDataForSigning(cert *PeerCertificate) []byte {
	// Simplified certificate data creation
	data := make([]byte, 0)
	data = append(data, []byte(cert.Identity)...)
	data = append(data, cert.PublicKey...)
	data = append(data, cert.SerialNumber...)
	
	// Add validity period
	validFromBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(validFromBytes, uint64(cert.ValidFrom.Unix()))
	data = append(data, validFromBytes...)
	
	validUntilBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(validUntilBytes, uint64(cert.ValidUntil.Unix()))
	data = append(data, validUntilBytes...)
	
	return data
}

// verifySignature verifies a digital signature
func (cv *CertificateValidator) verifySignature(data, signature, publicKey []byte) error {
	// Simplified signature verification - in production would use proper crypto
	if len(signature) != 64 {
		return errors.New("invalid signature length")
	}
	if len(publicKey) == 0 {
		return errors.New("missing public key for verification")
	}
	
	// Simple verification (in production would use Ed25519 or similar)
	expectedSig := cv.calculateSimpleSignature(data, publicKey)
	if !subtle.ConstantTimeCompare(signature, expectedSig) {
		return errors.New("signature verification failed")
	}
	
	return nil
}

// calculateSimpleSignature calculates a simple signature
func (cv *CertificateValidator) calculateSimpleSignature(data, privateKey []byte) []byte {
	// Simplified signature calculation - in production would use proper crypto
	signature := make([]byte, 64)
	for i, b := range data {
		signature[i%64] ^= b ^ privateKey[i%len(privateKey)]
	}
	return signature
}

// AddTrustedCA adds a trusted certificate authority
func (cv *CertificateValidator) AddTrustedCA(identity string, cert *PeerCertificate) {
	cv.mutex.Lock()
	defer cv.mutex.Unlock()
	cv.trustedCAs[identity] = cert
}

// RevokeCertificate adds a certificate to the revocation list
func (cv *CertificateValidator) RevokeCertificate(serialNumber []byte) {
	cv.mutex.Lock()
	defer cv.mutex.Unlock()
	serialStr := fmt.Sprintf("%x", serialNumber)
	cv.revocationList[serialStr] = time.Now()
}

// CleanupExpiredRevocations removes old revocation entries
func (cv *CertificateValidator) CleanupExpiredRevocations(maxAge time.Duration) {
	cv.mutex.Lock()
	defer cv.mutex.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	for serial, revocationTime := range cv.revocationList {
		if revocationTime.Before(cutoff) {
			delete(cv.revocationList, serial)
		}
	}
}
