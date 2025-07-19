package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPTunnel represents a secure TCP tunnel with PQC encryption
type TCPTunnel struct {
	conn          net.Conn
	cryptoContext *CryptoContext
	localAddr     net.Addr
	remoteAddr    net.Addr
	isActive      bool
	createdAt     time.Time
	lastActivity  time.Time
	mutex         sync.RWMutex
}

// UDPTunnel represents a secure UDP tunnel with PQC encryption
type UDPTunnel struct {
	conn          *net.UDPConn
	remoteAddr    *net.UDPAddr
	cryptoContext *CryptoContext
	localAddr     net.Addr
	isActive      bool
	createdAt     time.Time
	lastActivity  time.Time
	mutex         sync.RWMutex
	sessionID     [16]byte // Unique session identifier for UDP "connection"
}

// TunnelManager manages multiple TCP and UDP tunnels
type TunnelManager struct {
	tcpTunnels map[string]*TCPTunnel
	udpTunnels map[string]*UDPTunnel
	mutex      sync.RWMutex
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		tcpTunnels: make(map[string]*TCPTunnel),
		udpTunnels: make(map[string]*UDPTunnel),
	}
}

// CreateTCPTunnel establishes a new secure TCP tunnel with PQC key exchange
func (tm *TunnelManager) CreateTCPTunnel(address string, timeout time.Duration) (*TCPTunnel, error) {
	if address == "" {
		return nil, errors.New("address cannot be empty")
	}

	// Establish TCP connection with timeout
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TCP connection to %s: %w", address, err)
	}

	// Generate local key pair for PQC key exchange
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate local key pair: %w", err)
	}

	// Perform PQC key exchange
	cryptoContext, err := performKeyExchange(conn, localKeyPair)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("PQC key exchange failed: %w", err)
	}

	// Create tunnel instance
	tunnel := &TCPTunnel{
		conn:          conn,
		cryptoContext: cryptoContext,
		localAddr:     conn.LocalAddr(),
		remoteAddr:    conn.RemoteAddr(),
		isActive:      true,
		createdAt:     time.Now(),
		lastActivity:  time.Now(),
	}

	// Add to tunnel manager
	tunnelID := generateTunnelID(tunnel.localAddr, tunnel.remoteAddr)
	tm.mutex.Lock()
	tm.tcpTunnels[tunnelID] = tunnel
	tm.mutex.Unlock()

	return tunnel, nil
}

// CreateUDPTunnel establishes a new secure UDP tunnel with PQC key exchange
func (tm *TunnelManager) CreateUDPTunnel(address string, timeout time.Duration) (*UDPTunnel, error) {
	if address == "" {
		return nil, errors.New("address cannot be empty")
	}

	// Parse remote address
	remoteAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address %s: %w", address, err)
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish UDP connection to %s: %w", address, err)
	}

	// Generate session ID for UDP "connection"
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate local key pair for PQC key exchange
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate local key pair: %w", err)
	}

	// Perform PQC key exchange over UDP
	cryptoContext, err := performUDPKeyExchange(conn, localKeyPair, sessionID, timeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("UDP PQC key exchange failed: %w", err)
	}

	// Create tunnel instance
	tunnel := &UDPTunnel{
		conn:          conn,
		remoteAddr:    remoteAddr,
		cryptoContext: cryptoContext,
		localAddr:     conn.LocalAddr(),
		isActive:      true,
		createdAt:     time.Now(),
		lastActivity:  time.Now(),
		sessionID:     sessionID,
	}

	// Add to tunnel manager
	tunnelID := generateTunnelID(tunnel.localAddr, tunnel.remoteAddr)
	tm.mutex.Lock()
	tm.udpTunnels[tunnelID] = tunnel
	tm.mutex.Unlock()

	return tunnel, nil
}

// performUDPKeyExchange conducts PQC key exchange over UDP connection
func performUDPKeyExchange(conn *net.UDPConn, localKeyPair *KyberKeyPair, sessionID [16]byte, timeout time.Duration) (*CryptoContext, error) {
	// Set timeout for key exchange
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{}) // Clear deadline after key exchange

	// Send our public key with session ID to remote peer
	publicKeyData := localKeyPair.SerializePublicKey()
	keyExchangeMsg := make([]byte, 16+len(publicKeyData)) // session ID + public key
	copy(keyExchangeMsg[:16], sessionID[:])
	copy(keyExchangeMsg[16:], publicKeyData)
	
	if err := sendUDPKeyExchangeMessage(conn, keyExchangeMsg); err != nil {
		return nil, fmt.Errorf("failed to send public key: %w", err)
	}

	// Receive remote peer's public key
	remoteMsg, err := receiveUDPKeyExchangeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote public key: %w", err)
	}

	// Validate message format and extract public key
	if len(remoteMsg) < 16+KyberPublicKeyBytes {
		return nil, fmt.Errorf("invalid remote message size: got %d, expected at least %d", 
			len(remoteMsg), 16+KyberPublicKeyBytes)
	}
	
	remotePublicKey := remoteMsg[16:] // Skip session ID

	// Validate remote public key
	if len(remotePublicKey) != KyberPublicKeyBytes {
		return nil, fmt.Errorf("invalid remote public key size: got %d, expected %d", 
			len(remotePublicKey), KyberPublicKeyBytes)
	}

	// Generate shared secret using Kyber encapsulation
	sharedSecret, ciphertext, err := kyberEncapsulate(remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}

	// Send encapsulated secret with session ID to remote peer
	secretMsg := make([]byte, 16+len(ciphertext))
	copy(secretMsg[:16], sessionID[:])
	copy(secretMsg[16:], ciphertext)
	
	if err := sendUDPKeyExchangeMessage(conn, secretMsg); err != nil {
		return nil, fmt.Errorf("failed to send encapsulated secret: %w", err)
	}

	// Receive remote peer's encapsulated secret
	remoteSecretMsg, err := receiveUDPKeyExchangeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive remote encapsulated secret: %w", err)
	}

	// Extract ciphertext (skip session ID)
	if len(remoteSecretMsg) < 16 {
		return nil, errors.New("invalid remote secret message size")
	}
	remoteCiphertext := remoteSecretMsg[16:]

	// Decapsulate remote secret
	remoteSharedSecret, err := kyberDecapsulate(remoteCiphertext, localKeyPair.SerializePrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate remote secret: %w", err)
	}

	// Combine both shared secrets for final key derivation using secure HKDF
	contextInfo := []byte("UDP-KEY-EXCHANGE")
	finalSecret, err := SecureCombineSharedSecrets(sharedSecret, remoteSharedSecret, contextInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shared secrets: %w", err)
	}
	defer secureZeroBytes(finalSecret)

	return &CryptoContext{
		LocalKeyPair:    KeyPair{PublicKey: localKeyPair.PublicKey, PrivateKey: localKeyPair.PrivateKey},
		RemotePublicKey: remotePublicKey,
		SharedSecret:    finalSecret,
		CreatedAt:       time.Now(),
	}, nil
}

// sendUDPKeyExchangeMessage sends a message during UDP key exchange
func sendUDPKeyExchangeMessage(conn *net.UDPConn, data []byte) error {
	// UDP messages include length prefix for reliability
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(len(data) >> 24)
	lengthBytes[1] = byte(len(data) >> 16)
	lengthBytes[2] = byte(len(data) >> 8)
	lengthBytes[3] = byte(len(data))

	// Combine length and data into single UDP packet
	packet := make([]byte, 4+len(data))
	copy(packet[:4], lengthBytes)
	copy(packet[4:], data)

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("failed to send UDP message: %w", err)
	}

	return nil
}

// receiveUDPKeyExchangeMessage receives a message during UDP key exchange
func receiveUDPKeyExchangeMessage(conn *net.UDPConn) ([]byte, error) {
	// Read UDP packet (max size for key exchange)
	buffer := make([]byte, 10*1024) // 10KB buffer for key exchange messages
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read UDP message: %w", err)
	}

	if n < 4 {
		return nil, errors.New("UDP message too short")
	}

	// Parse message length
	length := int(buffer[0])<<24 | int(buffer[1])<<16 | int(buffer[2])<<8 | int(buffer[3])

	// Validate message length
	if length <= 0 || length > n-4 {
		return nil, fmt.Errorf("invalid UDP message length: %d", length)
	}

	// Extract message data
	data := make([]byte, length)
	copy(data, buffer[4:4+length])

	return data, nil
}

// performKeyExchange conducts authenticated PQC key exchange over the TCP connection
// This function now requires authentication context to prevent MITM attacks
func performKeyExchange(conn net.Conn, localKeyPair *KyberKeyPair) (*CryptoContext, error) {
	// Create default authentication context for backward compatibility
	authCtx := &AuthenticationContext{
		Method:    "pqc-mutual-auth",
		Timestamp: time.Now(),
		Nonce:     make([]byte, 32),
	}
	
	// Generate secure nonce
	if _, err := rand.Read(authCtx.Nonce); err != nil {
		return nil, fmt.Errorf("failed to generate authentication nonce: %w", err)
	}
	
	// Use authenticated key exchange with context
	return performAuthenticatedKeyExchangeWithContext(conn, localKeyPair, authCtx)
}

// performAuthenticatedKeyExchangeWithContext performs authenticated key exchange
func performAuthenticatedKeyExchangeWithContext(conn net.Conn, localKeyPair *KyberKeyPair, authCtx *AuthenticationContext) (*CryptoContext, error) {
	if authCtx == nil {
		return nil, errors.New("authentication context is required")
	}

	// Use the new authenticated key exchange
	result, err := PerformAuthenticatedKeyExchange(conn, localKeyPair, authCtx)
	if err != nil {
		return nil, fmt.Errorf("authenticated key exchange failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("authentication failed: %s", result.Error)
	}

	return result.CryptoContext, nil
}

// performPSKKeyExchangeWithAuth performs PSK-authenticated key exchange
func performPSKKeyExchangeWithAuth(conn net.Conn, localKeyPair *KyberKeyPair, psk *PSKAuthenticator, peerID string) (*CryptoContext, error) {
	if psk == nil {
		return nil, errors.New("PSK authenticator is required")
	}

	result, err := psk.AuthenticateWithPSK(conn, peerID, localKeyPair)
	if err != nil {
		return nil, fmt.Errorf("PSK authentication failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("PSK authentication failed: %s", result.Error)
	}

	return result.CryptoContext, nil
}

// sendKeyExchangeMessage sends a message during key exchange
func sendKeyExchangeMessage(conn net.Conn, data []byte) error {
	// Send message length first (4 bytes, big-endian)
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(len(data) >> 24)
	lengthBytes[1] = byte(len(data) >> 16)
	lengthBytes[2] = byte(len(data) >> 8)
	lengthBytes[3] = byte(len(data))

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to send message length: %w", err)
	}

	// Send message data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send message data: %w", err)
	}

	return nil
}

// receiveKeyExchangeMessage receives a message during key exchange
func receiveKeyExchangeMessage(conn net.Conn) ([]byte, error) {
	// Read message length (4 bytes)
	lengthBytes := make([]byte, 4)
	if _, err := conn.Read(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	// Parse message length
	length := int(lengthBytes[0])<<24 | int(lengthBytes[1])<<16 | int(lengthBytes[2])<<8 | int(lengthBytes[3])

	// Validate message length
	if length <= 0 || length > 10*1024*1024 { // Max 10MB
		return nil, fmt.Errorf("invalid message length: %d", length)
	}

	// Read message data
	data := make([]byte, length)
	totalRead := 0
	for totalRead < length {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read message data: %w", err)
		}
		totalRead += n
	}

	return data, nil
}


// generateTunnelID creates a unique identifier for a tunnel
func generateTunnelID(localAddr, remoteAddr net.Addr) string {
	return fmt.Sprintf("%s->%s", localAddr.String(), remoteAddr.String())
}

// SendData sends encrypted data through the tunnel
func (t *TCPTunnel) SendData(data []byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isActive {
		return errors.New("tunnel is not active")
	}

	// Encrypt data using the shared secret
	encryptedPacket, err := EncryptPacket(data, t.cryptoContext.RemotePublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Send encrypted packet
	if err := t.sendEncryptedPacket(encryptedPacket); err != nil {
		t.isActive = false // Mark tunnel as inactive on send failure
		return fmt.Errorf("failed to send encrypted packet: %w", err)
	}

	t.lastActivity = time.Now()
	return nil
}

// ReceiveData receives and decrypts data from the tunnel
func (t *TCPTunnel) ReceiveData() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isActive {
		return nil, errors.New("tunnel is not active")
	}

	// Receive encrypted packet
	encryptedPacket, err := t.receiveEncryptedPacket()
	if err != nil {
		t.isActive = false // Mark tunnel as inactive on receive failure
		return nil, fmt.Errorf("failed to receive encrypted packet: %w", err)
	}

	// Decrypt data using local private key
	data, err := DecryptPacket(encryptedPacket, t.cryptoContext.LocalKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	t.lastActivity = time.Now()
	return data, nil
}

// sendEncryptedPacket sends an encrypted packet over the connection
func (t *TCPTunnel) sendEncryptedPacket(packet *EncryptedPacket) error {
	// Create packet header with sizes
	header := make([]byte, 12) // 4 bytes each for ciphertext, tag, and nonce lengths
	
	// Write lengths in big-endian format
	writeBigEndian32(header[0:4], uint32(len(packet.Ciphertext)))
	writeBigEndian32(header[4:8], uint32(len(packet.Tag)))
	writeBigEndian32(header[8:12], uint32(len(packet.Nonce)))

	// Send header
	if _, err := t.conn.Write(header); err != nil {
		return fmt.Errorf("failed to send packet header: %w", err)
	}

	// Send ciphertext
	if _, err := t.conn.Write(packet.Ciphertext); err != nil {
		return fmt.Errorf("failed to send ciphertext: %w", err)
	}

	// Send tag
	if _, err := t.conn.Write(packet.Tag); err != nil {
		return fmt.Errorf("failed to send tag: %w", err)
	}

	// Send nonce
	if _, err := t.conn.Write(packet.Nonce); err != nil {
		return fmt.Errorf("failed to send nonce: %w", err)
	}

	return nil
}

// receiveEncryptedPacket receives an encrypted packet from the connection
func (t *TCPTunnel) receiveEncryptedPacket() (*EncryptedPacket, error) {
	// Read packet header (12 bytes)
	header := make([]byte, 12)
	if _, err := t.conn.Read(header); err != nil {
		return nil, fmt.Errorf("failed to read packet header: %w", err)
	}

	// Parse lengths
	ciphertextLen := readBigEndian32(header[0:4])
	tagLen := readBigEndian32(header[4:8])
	nonceLen := readBigEndian32(header[8:12])

	// Validate lengths
	if ciphertextLen > MaxPacketSize*2 || tagLen > 64 || nonceLen > 32 {
		return nil, errors.New("invalid packet lengths")
	}

	// Read ciphertext
	ciphertext := make([]byte, ciphertextLen)
	if err := readFull(t.conn, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// Read tag
	tag := make([]byte, tagLen)
	if err := readFull(t.conn, tag); err != nil {
		return nil, fmt.Errorf("failed to read tag: %w", err)
	}

	// Read nonce
	nonce := make([]byte, nonceLen)
	if err := readFull(t.conn, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	return &EncryptedPacket{
		Ciphertext: ciphertext,
		Tag:        tag,
		Nonce:      nonce,
	}, nil
}

// writeBigEndian32 writes a 32-bit integer in big-endian format
func writeBigEndian32(buf []byte, val uint32) {
	buf[0] = byte(val >> 24)
	buf[1] = byte(val >> 16)
	buf[2] = byte(val >> 8)
	buf[3] = byte(val)
}

// readBigEndian32 reads a 32-bit integer in big-endian format
func readBigEndian32(buf []byte) uint32 {
	return uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
}

// readFull reads exactly len(buf) bytes from the connection
func readFull(conn net.Conn, buf []byte) error {
	totalRead := 0
	for totalRead < len(buf) {
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			return err
		}
		totalRead += n
	}
	return nil
}

// Close closes the tunnel and cleans up resources
func (t *TCPTunnel) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isActive {
		return nil // Already closed
	}

	t.isActive = false
	
	// Clear sensitive data
	if t.cryptoContext != nil && t.cryptoContext.SharedSecret != nil {
		for i := range t.cryptoContext.SharedSecret {
			t.cryptoContext.SharedSecret[i] = 0
		}
	}

	return t.conn.Close()
}

// IsActive returns whether the tunnel is currently active
func (t *TCPTunnel) IsActive() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.isActive
}

// GetStats returns tunnel statistics
func (t *TCPTunnel) GetStats() TunnelStats {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return TunnelStats{
		LocalAddr:    t.localAddr.String(),
		RemoteAddr:   t.remoteAddr.String(),
		CreatedAt:    t.createdAt,
		LastActivity: t.lastActivity,
		IsActive:     t.isActive,
	}
}

// TunnelStats contains tunnel statistics
type TunnelStats struct {
	LocalAddr    string
	RemoteAddr   string
	CreatedAt    time.Time
	LastActivity time.Time
	IsActive     bool
}

// CloseTunnel closes a specific tunnel by ID and protocol
func (tm *TunnelManager) CloseTunnel(tunnelID, protocol string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if protocol == "tcp" {
		tunnel, exists := tm.tcpTunnels[tunnelID]
		if !exists {
			return errors.New("TCP tunnel not found")
		}
		err := tunnel.Close()
		delete(tm.tcpTunnels, tunnelID)
		return err
	} else if protocol == "udp" {
		tunnel, exists := tm.udpTunnels[tunnelID]
		if !exists {
			return errors.New("UDP tunnel not found")
		}
		err := tunnel.Close()
		delete(tm.udpTunnels, tunnelID)
		return err
	}

	return errors.New("unsupported protocol")
}

// GetActiveTunnels returns a list of all active tunnels
func (tm *TunnelManager) GetActiveTunnels() []TunnelStats {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	var stats []TunnelStats
	
	// Add TCP tunnels
	for _, tunnel := range tm.tcpTunnels {
		if tunnel.IsActive() {
			stats = append(stats, tunnel.GetStats())
		}
	}
	
	// Add UDP tunnels
	for _, tunnel := range tm.udpTunnels {
		if tunnel.IsActive() {
			stats = append(stats, tunnel.GetStats())
		}
	}

	return stats
}

// CloseAllTunnels closes all managed tunnels
func (tm *TunnelManager) CloseAllTunnels() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var lastError error
	
	// Close all TCP tunnels
	for tunnelID, tunnel := range tm.tcpTunnels {
		if err := tunnel.Close(); err != nil {
			lastError = err
		}
		delete(tm.tcpTunnels, tunnelID)
	}
	
	// Close all UDP tunnels
	for tunnelID, tunnel := range tm.udpTunnels {
		if err := tunnel.Close(); err != nil {
			lastError = err
		}
		delete(tm.udpTunnels, tunnelID)
	}

	return lastError
}

// MaintainTunnels performs periodic maintenance on all tunnels
func (tm *TunnelManager) MaintainTunnels() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	now := time.Now()
	
	// Maintain TCP tunnels
	for tunnelID, tunnel := range tm.tcpTunnels {
		// Check if tunnel has been inactive for too long
		if now.Sub(tunnel.lastActivity) > time.Duration(KeepAliveInterval)*time.Second {
			// Send keep-alive packet
			if err := tunnel.sendKeepAlive(); err != nil {
				// Mark tunnel as inactive if keep-alive fails
				tunnel.isActive = false
			}
		}

		// Remove inactive tunnels
		if !tunnel.isActive {
			tunnel.Close()
			delete(tm.tcpTunnels, tunnelID)
		}
	}
	
	// Maintain UDP tunnels
	for tunnelID, tunnel := range tm.udpTunnels {
		// Check if tunnel has been inactive for too long
		if now.Sub(tunnel.lastActivity) > time.Duration(KeepAliveInterval)*time.Second {
			// Send keep-alive packet
			if err := tunnel.sendKeepAlive(); err != nil {
				// Mark tunnel as inactive if keep-alive fails
				tunnel.isActive = false
			}
		}

		// Remove inactive tunnels
		if !tunnel.isActive {
			tunnel.Close()
			delete(tm.udpTunnels, tunnelID)
		}
	}
}

// CheckTunnelHealth performs health check on a specific tunnel
func (tm *TunnelManager) CheckTunnelHealth(tunnelID, protocol string) error {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	if protocol == "tcp" {
		tunnel, exists := tm.tcpTunnels[tunnelID]
		if !exists {
			return errors.New("TCP tunnel not found")
		}
		return tunnel.checkHealth()
	} else if protocol == "udp" {
		tunnel, exists := tm.udpTunnels[tunnelID]
		if !exists {
			return errors.New("UDP tunnel not found")
		}
		return tunnel.checkHealth()
	}

	return errors.New("unsupported protocol")
}

// ReconnectTunnel attempts to reconnect a failed tunnel
func (tm *TunnelManager) ReconnectTunnel(tunnelID, protocol string, timeout time.Duration) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if protocol == "tcp" {
		tunnel, exists := tm.tcpTunnels[tunnelID]
		if !exists {
			return errors.New("TCP tunnel not found")
		}
		
		// Get the remote address before closing
		remoteAddr := tunnel.remoteAddr.String()
		
		// Close the old tunnel
		tunnel.Close()
		delete(tm.tcpTunnels, tunnelID)
		
		// Create new tunnel to same address
		newTunnel, err := tm.CreateTCPTunnel(remoteAddr, timeout)
		if err != nil {
			return fmt.Errorf("failed to reconnect TCP tunnel: %w", err)
		}
		
		// Update tunnel ID if needed (addresses might have changed)
		newTunnelID := generateTunnelID(newTunnel.localAddr, newTunnel.remoteAddr)
		tm.tcpTunnels[newTunnelID] = newTunnel
		
		return nil
	} else if protocol == "udp" {
		tunnel, exists := tm.udpTunnels[tunnelID]
		if !exists {
			return errors.New("UDP tunnel not found")
		}
		
		// Get the remote address before closing
		remoteAddr := tunnel.remoteAddr.String()
		
		// Close the old tunnel
		tunnel.Close()
		delete(tm.udpTunnels, tunnelID)
		
		// Create new tunnel to same address
		newTunnel, err := tm.CreateUDPTunnel(remoteAddr, timeout)
		if err != nil {
			return fmt.Errorf("failed to reconnect UDP tunnel: %w", err)
		}
		
		// Update tunnel ID if needed
		newTunnelID := generateTunnelID(newTunnel.localAddr, newTunnel.remoteAddr)
		tm.udpTunnels[newTunnelID] = newTunnel
		
		return nil
	}

	return errors.New("unsupported protocol")
}

// sendKeepAlive sends a keep-alive packet to maintain the tunnel
func (t *TCPTunnel) sendKeepAlive() error {
	// Generate small random keep-alive data
	keepAliveData := make([]byte, 8)
	if _, err := rand.Read(keepAliveData); err != nil {
		return fmt.Errorf("failed to generate keep-alive data: %w", err)
	}

	// Send keep-alive through the tunnel
	return t.SendData(keepAliveData)
}

// checkHealth performs a health check on the TCP tunnel
func (t *TCPTunnel) checkHealth() error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if !t.isActive {
		return errors.New("tunnel is not active")
	}

	// Check if connection is still valid by attempting to set a deadline
	if err := t.conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("connection health check failed: %w", err)
	}

	// Clear the deadline
	t.conn.SetDeadline(time.Time{})

	// Check if tunnel has been inactive for too long
	if time.Since(t.lastActivity) > time.Duration(KeepAliveInterval*2)*time.Second {
		return errors.New("tunnel has been inactive for too long")
	}

	return nil
}

// UDP Tunnel Methods

// SendData sends encrypted data through the UDP tunnel
func (t *UDPTunnel) SendData(data []byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isActive {
		return errors.New("UDP tunnel is not active")
	}

	// Encrypt data using the shared secret
	encryptedPacket, err := EncryptPacket(data, t.cryptoContext.RemotePublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Send encrypted packet over UDP
	if err := t.sendEncryptedUDPPacket(encryptedPacket); err != nil {
		t.isActive = false // Mark tunnel as inactive on send failure
		return fmt.Errorf("failed to send encrypted UDP packet: %w", err)
	}

	t.lastActivity = time.Now()
	return nil
}

// ReceiveData receives and decrypts data from the UDP tunnel
func (t *UDPTunnel) ReceiveData() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isActive {
		return nil, errors.New("UDP tunnel is not active")
	}

	// Receive encrypted packet
	encryptedPacket, err := t.receiveEncryptedUDPPacket()
	if err != nil {
		t.isActive = false // Mark tunnel as inactive on receive failure
		return nil, fmt.Errorf("failed to receive encrypted UDP packet: %w", err)
	}

	// Decrypt data using local private key
	data, err := DecryptPacket(encryptedPacket, t.cryptoContext.LocalKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	t.lastActivity = time.Now()
	return data, nil
}

// sendEncryptedUDPPacket sends an encrypted packet over UDP
func (t *UDPTunnel) sendEncryptedUDPPacket(packet *EncryptedPacket) error {
	// Create UDP packet with session ID and encrypted data
	// Format: [SessionID:16][CiphertextLen:4][TagLen:4][NonceLen:4][Ciphertext][Tag][Nonce]
	headerSize := 16 + 12 // session ID + 3 length fields
	totalSize := headerSize + len(packet.Ciphertext) + len(packet.Tag) + len(packet.Nonce)
	
	udpPacket := make([]byte, totalSize)
	offset := 0
	
	// Add session ID
	copy(udpPacket[offset:], t.sessionID[:])
	offset += 16
	
	// Add lengths
	writeBigEndian32(udpPacket[offset:], uint32(len(packet.Ciphertext)))
	offset += 4
	writeBigEndian32(udpPacket[offset:], uint32(len(packet.Tag)))
	offset += 4
	writeBigEndian32(udpPacket[offset:], uint32(len(packet.Nonce)))
	offset += 4
	
	// Add encrypted data
	copy(udpPacket[offset:], packet.Ciphertext)
	offset += len(packet.Ciphertext)
	copy(udpPacket[offset:], packet.Tag)
	offset += len(packet.Tag)
	copy(udpPacket[offset:], packet.Nonce)

	// Send UDP packet
	if _, err := t.conn.Write(udpPacket); err != nil {
		return fmt.Errorf("failed to send UDP packet: %w", err)
	}

	return nil
}

// receiveEncryptedUDPPacket receives an encrypted packet from UDP
func (t *UDPTunnel) receiveEncryptedUDPPacket() (*EncryptedPacket, error) {
	// Read UDP packet
	buffer := make([]byte, MaxPacketSize*2) // Allow for encryption overhead
	n, err := t.conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read UDP packet: %w", err)
	}

	if n < 28 { // Minimum: 16 (session) + 12 (lengths) = 28 bytes
		return nil, errors.New("UDP packet too short")
	}

	// Verify session ID
	receivedSessionID := buffer[:16]
	for i, b := range t.sessionID {
		if receivedSessionID[i] != b {
			return nil, errors.New("invalid session ID in UDP packet")
		}
	}

	offset := 16

	// Parse lengths
	ciphertextLen := readBigEndian32(buffer[offset:])
	offset += 4
	tagLen := readBigEndian32(buffer[offset:])
	offset += 4
	nonceLen := readBigEndian32(buffer[offset:])
	offset += 4

	// Validate lengths
	if ciphertextLen > MaxPacketSize*2 || tagLen > 64 || nonceLen > 32 {
		return nil, errors.New("invalid UDP packet lengths")
	}

	expectedSize := 28 + int(ciphertextLen) + int(tagLen) + int(nonceLen)
	if n < expectedSize {
		return nil, errors.New("UDP packet truncated")
	}

	// Extract encrypted data
	ciphertext := make([]byte, ciphertextLen)
	copy(ciphertext, buffer[offset:offset+int(ciphertextLen)])
	offset += int(ciphertextLen)

	tag := make([]byte, tagLen)
	copy(tag, buffer[offset:offset+int(tagLen)])
	offset += int(tagLen)

	nonce := make([]byte, nonceLen)
	copy(nonce, buffer[offset:offset+int(nonceLen)])

	return &EncryptedPacket{
		Ciphertext: ciphertext,
		Tag:        tag,
		Nonce:      nonce,
	}, nil
}

// Close closes the UDP tunnel and cleans up resources
func (t *UDPTunnel) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isActive {
		return nil // Already closed
	}

	t.isActive = false
	
	// Clear sensitive data
	if t.cryptoContext != nil && t.cryptoContext.SharedSecret != nil {
		for i := range t.cryptoContext.SharedSecret {
			t.cryptoContext.SharedSecret[i] = 0
		}
	}
	
	// Clear session ID
	for i := range t.sessionID {
		t.sessionID[i] = 0
	}

	return t.conn.Close()
}

// IsActive returns whether the UDP tunnel is currently active
func (t *UDPTunnel) IsActive() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.isActive
}

// GetStats returns UDP tunnel statistics
func (t *UDPTunnel) GetStats() TunnelStats {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return TunnelStats{
		LocalAddr:    t.localAddr.String(),
		RemoteAddr:   t.remoteAddr.String(),
		CreatedAt:    t.createdAt,
		LastActivity: t.lastActivity,
		IsActive:     t.isActive,
	}
}

// sendKeepAlive sends a keep-alive packet to maintain the UDP tunnel
func (t *UDPTunnel) sendKeepAlive() error {
	// Generate small random keep-alive data
	keepAliveData := make([]byte, 8)
	if _, err := rand.Read(keepAliveData); err != nil {
		return fmt.Errorf("failed to generate keep-alive data: %w", err)
	}

	// Send keep-alive through the tunnel
	return t.SendData(keepAliveData)
}

// checkHealth performs a health check on the UDP tunnel
func (t *UDPTunnel) checkHealth() error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if !t.isActive {
		return errors.New("UDP tunnel is not active")
	}

	// Check if connection is still valid by attempting to set a deadline
	if err := t.conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("UDP connection health check failed: %w", err)
	}

	// Clear the deadline
	t.conn.SetDeadline(time.Time{})

	// Check if tunnel has been inactive for too long
	if time.Since(t.lastActivity) > time.Duration(KeepAliveInterval*2)*time.Second {
		return errors.New("UDP tunnel has been inactive for too long")
	}

	return nil
}

// Protocol Switching Logic

// CreateTunnel creates a tunnel using the specified protocol
func (tm *TunnelManager) CreateTunnel(address, protocol string, timeout time.Duration) (interface{}, error) {
	switch protocol {
	case "tcp":
		return tm.CreateTCPTunnel(address, timeout)
	case "udp":
		return tm.CreateUDPTunnel(address, timeout)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// SelectOptimalProtocol chooses the best protocol based on use case
func SelectOptimalProtocol(useCase string) string {
	switch useCase {
	case "streaming", "file-transfer", "reliable":
		return "tcp" // Use TCP for reliable data transfer
	case "gaming", "voip", "real-time", "low-latency":
		return "udp" // Use UDP for low-latency applications
	default:
		return "tcp" // Default to TCP for general use
	}
}

// GetProtocolCapabilities returns the capabilities of each protocol
func GetProtocolCapabilities() map[string][]string {
	return map[string][]string{
		"tcp": {"reliable", "ordered", "connection-oriented", "flow-control"},
		"udp": {"fast", "low-latency", "connectionless", "real-time"},
	}
}

// Packet Sharding Implementation

// ShardPacket splits a large packet into smaller shards for multi-route transmission
func ShardPacket(data []byte, maxShardSize int) ([]*PacketShard, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot shard empty packet")
	}
	
	if maxShardSize <= 0 {
		return nil, errors.New("invalid shard size")
	}

	// Generate unique shard ID for this packet
	var shardID [16]byte
	if _, err := rand.Read(shardID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate shard ID: %w", err)
	}

	// Calculate number of shards needed
	totalShards := (len(data) + maxShardSize - 1) / maxShardSize
	if totalShards > 255 {
		return nil, errors.New("packet too large: would require more than 255 shards")
	}

	shards := make([]*PacketShard, totalShards)
	
	for i := 0; i < totalShards; i++ {
		start := i * maxShardSize
		end := start + maxShardSize
		if end > len(data) {
			end = len(data)
		}

		shardData := make([]byte, end-start)
		copy(shardData, data[start:end])

		shards[i] = &PacketShard{
			ShardID:     shardID,
			ShardNum:    uint8(i),
			TotalShards: uint8(totalShards),
			Data:        shardData,
		}
	}

	return shards, nil
}

// ReassemblePacket reconstructs the original packet from its shards
func ReassemblePacket(shards []*PacketShard) ([]byte, error) {
	if len(shards) == 0 {
		return nil, errors.New("no shards provided")
	}

	// Validate all shards have the same ID and total count
	shardID := shards[0].ShardID
	totalShards := shards[0].TotalShards
	
	if int(totalShards) != len(shards) {
		return nil, fmt.Errorf("incomplete shard set: expected %d shards, got %d", 
			totalShards, len(shards))
	}

	// Create map to track received shards
	shardMap := make(map[uint8]*PacketShard)
	
	for _, shard := range shards {
		// Validate shard belongs to same packet
		if shard.ShardID != shardID {
			return nil, errors.New("shards have different IDs")
		}
		
		if shard.TotalShards != totalShards {
			return nil, errors.New("shards have different total counts")
		}
		
		if shard.ShardNum >= totalShards {
			return nil, fmt.Errorf("invalid shard number: %d >= %d", 
				shard.ShardNum, totalShards)
		}
		
		// Check for duplicate shards
		if _, exists := shardMap[shard.ShardNum]; exists {
			return nil, fmt.Errorf("duplicate shard number: %d", shard.ShardNum)
		}
		
		shardMap[shard.ShardNum] = shard
	}

	// Verify we have all shards
	for i := uint8(0); i < totalShards; i++ {
		if _, exists := shardMap[i]; !exists {
			return nil, fmt.Errorf("missing shard number: %d", i)
		}
	}

	// Calculate total size
	totalSize := 0
	for _, shard := range shards {
		totalSize += len(shard.Data)
	}

	// Reassemble packet in correct order
	result := make([]byte, 0, totalSize)
	for i := uint8(0); i < totalShards; i++ {
		shard := shardMap[i]
		result = append(result, shard.Data...)
	}

	return result, nil
}

// SerializePacketShard serializes a packet shard for transmission
func SerializePacketShard(shard *PacketShard) ([]byte, error) {
	if shard == nil {
		return nil, errors.New("shard is nil")
	}

	// Calculate total size: 16 (ID) + 1 (ShardNum) + 1 (TotalShards) + 4 (DataLen) + Data
	totalSize := 16 + 1 + 1 + 4 + len(shard.Data)
	result := make([]byte, totalSize)
	
	offset := 0
	
	// Copy shard ID
	copy(result[offset:], shard.ShardID[:])
	offset += 16
	
	// Copy shard number
	result[offset] = shard.ShardNum
	offset++
	
	// Copy total shards
	result[offset] = shard.TotalShards
	offset++
	
	// Copy data length (big-endian)
	dataLen := uint32(len(shard.Data))
	result[offset] = byte(dataLen >> 24)
	result[offset+1] = byte(dataLen >> 16)
	result[offset+2] = byte(dataLen >> 8)
	result[offset+3] = byte(dataLen)
	offset += 4
	
	// Copy data
	copy(result[offset:], shard.Data)
	
	return result, nil
}

// DeserializePacketShard deserializes a packet shard from transmission data
func DeserializePacketShard(data []byte) (*PacketShard, error) {
	if len(data) < 22 { // Minimum size: 16 + 1 + 1 + 4 = 22 bytes
		return nil, errors.New("data too short for packet shard")
	}

	shard := &PacketShard{}
	offset := 0
	
	// Read shard ID
	copy(shard.ShardID[:], data[offset:offset+16])
	offset += 16
	
	// Read shard number
	shard.ShardNum = data[offset]
	offset++
	
	// Read total shards
	shard.TotalShards = data[offset]
	offset++
	
	// Read data length
	dataLen := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | 
		uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4
	
	// Validate data length
	if int(dataLen) != len(data)-offset {
		return nil, fmt.Errorf("invalid data length: expected %d, got %d", 
			dataLen, len(data)-offset)
	}
	
	// Read data
	shard.Data = make([]byte, dataLen)
	copy(shard.Data, data[offset:])
	
	return shard, nil
}

// ShardedPacketManager manages packet sharding across multiple routes
type ShardedPacketManager struct {
	pendingPackets map[[16]byte]map[uint8]*PacketShard // ShardID -> ShardNum -> Shard
	mutex          sync.RWMutex
	maxPendingTime time.Duration
}

// NewShardedPacketManager creates a new sharded packet manager
func NewShardedPacketManager() *ShardedPacketManager {
	return &ShardedPacketManager{
		pendingPackets: make(map[[16]byte]map[uint8]*PacketShard),
		maxPendingTime: time.Minute * 5, // 5 minute timeout for incomplete packets
	}
}

// AddShard adds a received shard and returns the complete packet if all shards are received
func (spm *ShardedPacketManager) AddShard(shard *PacketShard) ([]byte, bool, error) {
	if shard == nil {
		return nil, false, errors.New("shard is nil")
	}

	spm.mutex.Lock()
	defer spm.mutex.Unlock()

	shardID := shard.ShardID
	
	// Initialize shard map for this packet if it doesn't exist
	if _, exists := spm.pendingPackets[shardID]; !exists {
		spm.pendingPackets[shardID] = make(map[uint8]*PacketShard)
	}
	
	shardMap := spm.pendingPackets[shardID]
	
	// Check for duplicate shard
	if _, exists := shardMap[shard.ShardNum]; exists {
		return nil, false, fmt.Errorf("duplicate shard %d for packet %x", 
			shard.ShardNum, shardID)
	}
	
	// Add the shard
	shardMap[shard.ShardNum] = shard
	
	// Check if we have all shards
	if len(shardMap) == int(shard.TotalShards) {
		// Convert map to slice for reassembly
		shards := make([]*PacketShard, shard.TotalShards)
		for i := uint8(0); i < shard.TotalShards; i++ {
			if shardMap[i] == nil {
				return nil, false, fmt.Errorf("missing shard %d", i)
			}
			shards[i] = shardMap[i]
		}
		
		// Reassemble packet
		packet, err := ReassemblePacket(shards)
		if err != nil {
			return nil, false, fmt.Errorf("failed to reassemble packet: %w", err)
		}
		
		// Clean up completed packet
		delete(spm.pendingPackets, shardID)
		
		return packet, true, nil
	}
	
	return nil, false, nil // Packet not yet complete
}

// CleanupExpiredPackets removes packets that have been pending too long
func (spm *ShardedPacketManager) CleanupExpiredPackets() {
	spm.mutex.Lock()
	defer spm.mutex.Unlock()
	
	// For simplicity, we'll clean up all pending packets
	// In a real implementation, we'd track timestamps and only clean expired ones
	for shardID := range spm.pendingPackets {
		delete(spm.pendingPackets, shardID)
	}
}

// GetPendingPacketCount returns the number of packets waiting for completion
func (spm *ShardedPacketManager) GetPendingPacketCount() int {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()
	return len(spm.pendingPackets)
}

// Traffic Analysis Resistance Integration (Task 6.1)

// ShardedTrafficStream represents a stream of packets with integrated sharding and noise
type ShardedTrafficStream struct {
	routes      []*Route          // Multiple routes for shard distribution
	noiseRatio  float64          // Ratio of noise packets to inject (0.0-1.0)
	maxShardSize int             // Maximum size per shard
	mutex       sync.RWMutex     // Thread safety
}

// NewShardedTrafficStream creates a new traffic stream with sharding and noise injection
func NewShardedTrafficStream(routes []*Route, noiseRatio float64, maxShardSize int) (*ShardedTrafficStream, error) {
	if len(routes) < 2 {
		return nil, errors.New("minimum 2 routes required for effective traffic analysis resistance")
	}
	if noiseRatio < 0 || noiseRatio > 1 {
		return nil, errors.New("noise ratio must be between 0.0 and 1.0")
	}
	if maxShardSize < 64 || maxShardSize > 1400 {
		return nil, errors.New("max shard size must be between 64 and 1400 bytes")
	}

	return &ShardedTrafficStream{
		routes:       routes,
		noiseRatio:   noiseRatio,
		maxShardSize: maxShardSize,
	}, nil
}

// SendPacketWithTrafficObfuscation sends a packet with integrated sharding and noise injection
func (sts *ShardedTrafficStream) SendPacketWithTrafficObfuscation(data []byte) error {
	sts.mutex.RLock()
	defer sts.mutex.RUnlock()

	if len(data) == 0 {
		return errors.New("cannot send empty packet")
	}

	// Step 1: Shard the packet
	shards, err := ShardPacket(data, sts.maxShardSize)
	if err != nil {
		return fmt.Errorf("failed to shard packet: %w", err)
	}

	// Step 2: Generate noise packets for each route
	noisePacketsPerRoute := make(map[int][][]byte)
	for i := range sts.routes {
		numNoisePackets := int(float64(len(shards)) * sts.noiseRatio / float64(len(sts.routes)))
		if numNoisePackets < 1 && sts.noiseRatio > 0 {
			numNoisePackets = 1 // Ensure at least one noise packet per route
		}

		noisePackets := make([][]byte, numNoisePackets)
		for j := 0; j < numNoisePackets; j++ {
			noisePacket, err := GenerateNoisePacket()
			if err != nil {
				return fmt.Errorf("failed to generate noise packet for route %d: %w", i, err)
			}
			noisePackets[j] = noisePacket.Data
		}
		noisePacketsPerRoute[i] = noisePackets
	}

	// Step 3: Distribute shards across routes with noise injection
	return sts.distributeShards(shards, noisePacketsPerRoute)
}

// distributeShards distributes packet shards across multiple routes with noise
func (sts *ShardedTrafficStream) distributeShards(shards []*PacketShard, noisePacketsPerRoute map[int][][]byte) error {
	// Create a distribution plan that spreads shards across routes
	shardDistribution := sts.createShardDistribution(shards)

	// Send shards and noise packets concurrently across routes
	var wg sync.WaitGroup
	errChan := make(chan error, len(sts.routes))

	for routeIdx, route := range sts.routes {
		wg.Add(1)
		go func(idx int, r *Route) {
			defer wg.Done()
			
			// Get shards assigned to this route
			routeShards := shardDistribution[idx]
			
			// Get noise packets for this route
			noisePackets := noisePacketsPerRoute[idx]
			
			// Combine shards and noise packets
			allPackets := make([][]byte, 0, len(routeShards)+len(noisePackets))
			
			// Add serialized shards
			for _, shard := range routeShards {
				serializedShard, err := SerializePacketShard(shard)
				if err != nil {
					errChan <- fmt.Errorf("failed to serialize shard for route %d: %w", idx, err)
					return
				}
				allPackets = append(allPackets, serializedShard)
			}
			
			// Add noise packets
			allPackets = append(allPackets, noisePackets...)
			
			// Shuffle packets to randomize transmission order
			shufflePackets(allPackets)
			
			// Send packets through this route
			if err := sts.sendPacketsOnRoute(allPackets, r); err != nil {
				errChan <- fmt.Errorf("failed to send packets on route %d: %w", idx, err)
			}
		}(routeIdx, route)
	}

	// Wait for all routes to complete
	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// createShardDistribution creates a distribution plan for shards across routes
func (sts *ShardedTrafficStream) createShardDistribution(shards []*PacketShard) map[int][]*PacketShard {
	distribution := make(map[int][]*PacketShard)
	
	// Initialize empty slices for each route
	for i := range sts.routes {
		distribution[i] = make([]*PacketShard, 0)
	}

	// Distribute shards using round-robin with randomization
	routeIndices := make([]int, len(sts.routes))
	for i := range routeIndices {
		routeIndices[i] = i
	}
	
	// Shuffle route indices to randomize distribution
	for i := len(routeIndices) - 1; i > 0; i-- {
		randBytes := make([]byte, 4)
		rand.Read(randBytes)
		j := int(binary.LittleEndian.Uint32(randBytes)) % (i + 1)
		routeIndices[i], routeIndices[j] = routeIndices[j], routeIndices[i]
	}

	// Assign shards to routes
	for i, shard := range shards {
		routeIdx := routeIndices[i%len(routeIndices)]
		distribution[routeIdx] = append(distribution[routeIdx], shard)
	}

	return distribution
}

// sendPacketsOnRoute sends a list of packets through a specific route
func (sts *ShardedTrafficStream) sendPacketsOnRoute(packets [][]byte, route *Route) error {
	if len(route.Hops) == 0 {
		return errors.New("route has no hops")
	}

	// For now, simulate sending through the route
	// In a full implementation, this would establish connections through each hop
	for _, packet := range packets {
		if err := sts.simulateRouteTransmission(packet, route); err != nil {
			return fmt.Errorf("failed to transmit packet through route: %w", err)
		}
		
		// Add small random delay between packets to prevent timing correlation
		delay := sts.generateRandomDelay()
		time.Sleep(delay)
	}

	return nil
}

// simulateRouteTransmission simulates sending a packet through a multi-hop route
func (sts *ShardedTrafficStream) simulateRouteTransmission(packet []byte, route *Route) error {
	// This is a simplified simulation - in real implementation would use actual network connections
	if len(packet) == 0 {
		return errors.New("cannot transmit empty packet")
	}
	
	// Simulate transmission through each hop
	for i, hop := range route.Hops {
		// Simulate network delay
		delay := time.Duration(hop.Latency.Nanoseconds()/2) // Half of round-trip latency
		time.Sleep(delay)
		
		// In real implementation, would encrypt packet for this hop and forward
		_ = i // Avoid unused variable warning
	}
	
	return nil
}

// generateRandomDelay generates a small random delay for timing obfuscation
func (sts *ShardedTrafficStream) generateRandomDelay() time.Duration {
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	
	// Generate delay between 1-50ms
	delayMs := 1 + (int(binary.LittleEndian.Uint32(randBytes)) % 50)
	return time.Duration(delayMs) * time.Millisecond
}

// GetTrafficStats returns statistics about the traffic stream
func (sts *ShardedTrafficStream) GetTrafficStats() TrafficStats {
	sts.mutex.RLock()
	defer sts.mutex.RUnlock()

	return TrafficStats{
		NumRoutes:    len(sts.routes),
		NoiseRatio:   sts.noiseRatio,
		MaxShardSize: sts.maxShardSize,
	}
}

// TrafficStats contains statistics about traffic obfuscation
type TrafficStats struct {
	NumRoutes    int     // Number of routes used
	NoiseRatio   float64 // Noise injection ratio
	MaxShardSize int     // Maximum shard size
}

// Timing Attack Resistance Implementation (Task 6.2)

// TimingResistantTransmitter handles packet transmission with timing attack resistance
type TimingResistantTransmitter struct {
	minDelay        time.Duration // Minimum delay between packets
	maxDelay        time.Duration // Maximum delay between packets
	targetPacketSize int          // Target packet size for padding
	jitterRange     time.Duration // Random jitter range
	mutex           sync.RWMutex  // Thread safety
}

// NewTimingResistantTransmitter creates a new timing-resistant transmitter
func NewTimingResistantTransmitter(minDelay, maxDelay time.Duration, targetPacketSize int, jitterRange time.Duration) (*TimingResistantTransmitter, error) {
	if minDelay < 0 || maxDelay < minDelay {
		return nil, errors.New("invalid delay configuration: maxDelay must be >= minDelay >= 0")
	}
	if targetPacketSize < 64 || targetPacketSize > 1500 {
		return nil, errors.New("target packet size must be between 64 and 1500 bytes")
	}
	if jitterRange < 0 {
		return nil, errors.New("jitter range must be non-negative")
	}

	return &TimingResistantTransmitter{
		minDelay:        minDelay,
		maxDelay:        maxDelay,
		targetPacketSize: targetPacketSize,
		jitterRange:     jitterRange,
	}, nil
}

// PadPacketToTargetSize pads a packet to the target size to prevent size analysis
func (trt *TimingResistantTransmitter) PadPacketToTargetSize(packet []byte) ([]byte, error) {
	trt.mutex.RLock()
	defer trt.mutex.RUnlock()

	if len(packet) > trt.targetPacketSize-4 {
		return nil, fmt.Errorf("packet size %d exceeds maximum allowed size %d (target size %d - 4 bytes for header)", 
			len(packet), trt.targetPacketSize-4, trt.targetPacketSize)
	}

	if len(packet) == trt.targetPacketSize-4 {
		// Packet is at maximum size that allows for header
		paddedPacket := make([]byte, trt.targetPacketSize)
		copy(paddedPacket, packet)
		
		// Add size header at the end
		originalSize := len(packet)
		paddedPacket[trt.targetPacketSize-4] = byte(originalSize >> 24)
		paddedPacket[trt.targetPacketSize-3] = byte(originalSize >> 16)
		paddedPacket[trt.targetPacketSize-2] = byte(originalSize >> 8)
		paddedPacket[trt.targetPacketSize-1] = byte(originalSize)
		
		return paddedPacket, nil
	}

	// Create padded packet
	paddedPacket := make([]byte, trt.targetPacketSize)
	
	// Copy original packet data
	copy(paddedPacket, packet)
	
	// Add padding header to indicate original size
	originalSize := len(packet)
	paddedPacket[trt.targetPacketSize-4] = byte(originalSize >> 24)
	paddedPacket[trt.targetPacketSize-3] = byte(originalSize >> 16)
	paddedPacket[trt.targetPacketSize-2] = byte(originalSize >> 8)
	paddedPacket[trt.targetPacketSize-1] = byte(originalSize)
	
	// Fill padding area with random data (except the last 4 bytes for size)
	paddingStart := originalSize
	paddingEnd := trt.targetPacketSize - 4
	
	if paddingEnd > paddingStart {
		paddingData := make([]byte, paddingEnd-paddingStart)
		if _, err := rand.Read(paddingData); err != nil {
			return nil, fmt.Errorf("failed to generate padding data: %w", err)
		}
		copy(paddedPacket[paddingStart:paddingEnd], paddingData)
	}

	return paddedPacket, nil
}

// UnpadPacket removes padding from a packet to recover original data
func (trt *TimingResistantTransmitter) UnpadPacket(paddedPacket []byte) ([]byte, error) {
	trt.mutex.RLock()
	defer trt.mutex.RUnlock()

	if len(paddedPacket) != trt.targetPacketSize {
		return nil, fmt.Errorf("padded packet size %d does not match target size %d", len(paddedPacket), trt.targetPacketSize)
	}

	// Extract original size from last 4 bytes
	originalSize := int(paddedPacket[trt.targetPacketSize-4])<<24 |
		int(paddedPacket[trt.targetPacketSize-3])<<16 |
		int(paddedPacket[trt.targetPacketSize-2])<<8 |
		int(paddedPacket[trt.targetPacketSize-1])

	// Validate original size
	if originalSize < 0 || originalSize > trt.targetPacketSize-4 {
		return nil, fmt.Errorf("invalid original packet size: %d", originalSize)
	}

	// Extract original packet
	originalPacket := make([]byte, originalSize)
	copy(originalPacket, paddedPacket[:originalSize])

	return originalPacket, nil
}

// GenerateRandomDelay generates a random delay within the configured range
func (trt *TimingResistantTransmitter) GenerateRandomDelay() time.Duration {
	trt.mutex.RLock()
	defer trt.mutex.RUnlock()

	// Generate random delay between min and max
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	randValue := binary.LittleEndian.Uint64(randBytes)
	
	delayRange := trt.maxDelay - trt.minDelay
	if delayRange == 0 {
		return trt.minDelay
	}
	
	randomDelay := time.Duration(randValue % uint64(delayRange))
	baseDelay := trt.minDelay + randomDelay
	
	// Add jitter if configured
	if trt.jitterRange > 0 {
		jitterBytes := make([]byte, 8)
		rand.Read(jitterBytes)
		jitterValue := binary.LittleEndian.Uint64(jitterBytes)
		
		// Jitter can be positive or negative
		jitter := time.Duration(int64(jitterValue%uint64(trt.jitterRange*2)) - int64(trt.jitterRange))
		baseDelay += jitter
		
		// Ensure delay doesn't go negative
		if baseDelay < 0 {
			baseDelay = time.Millisecond
		}
	}
	
	return baseDelay
}

// TransmitWithTimingResistance transmits packets with timing attack resistance
func (trt *TimingResistantTransmitter) TransmitWithTimingResistance(packets [][]byte, transmitFunc func([]byte) error) error {
	if len(packets) == 0 {
		return nil
	}

	for i, packet := range packets {
		// Pad packet to target size
		paddedPacket, err := trt.PadPacketToTargetSize(packet)
		if err != nil {
			return fmt.Errorf("failed to pad packet %d: %w", i, err)
		}

		// Add random delay before transmission (except for first packet)
		if i > 0 {
			delay := trt.GenerateRandomDelay()
			time.Sleep(delay)
		}

		// Transmit the padded packet
		if err := transmitFunc(paddedPacket); err != nil {
			return fmt.Errorf("failed to transmit packet %d: %w", i, err)
		}
	}

	return nil
}

// GetTimingStats returns statistics about timing resistance configuration
func (trt *TimingResistantTransmitter) GetTimingStats() TimingStats {
	trt.mutex.RLock()
	defer trt.mutex.RUnlock()

	return TimingStats{
		MinDelay:         trt.minDelay,
		MaxDelay:         trt.maxDelay,
		TargetPacketSize: trt.targetPacketSize,
		JitterRange:      trt.jitterRange,
	}
}

// TimingStats contains statistics about timing resistance
type TimingStats struct {
	MinDelay         time.Duration // Minimum delay between packets
	MaxDelay         time.Duration // Maximum delay between packets
	TargetPacketSize int           // Target packet size for padding
	JitterRange      time.Duration // Random jitter range
}

// Enhanced ShardedTrafficStream with timing resistance
type EnhancedShardedTrafficStream struct {
	*ShardedTrafficStream           // Embed original functionality
	timingTransmitter *TimingResistantTransmitter // Timing attack resistance
}

// NewEnhancedShardedTrafficStream creates a traffic stream with both sharding/noise and timing resistance
func NewEnhancedShardedTrafficStream(routes []*Route, noiseRatio float64, maxShardSize int, 
	minDelay, maxDelay time.Duration, targetPacketSize int, jitterRange time.Duration) (*EnhancedShardedTrafficStream, error) {
	
	// Create base sharded traffic stream
	baseStream, err := NewShardedTrafficStream(routes, noiseRatio, maxShardSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create base traffic stream: %w", err)
	}

	// Create timing resistant transmitter
	timingTransmitter, err := NewTimingResistantTransmitter(minDelay, maxDelay, targetPacketSize, jitterRange)
	if err != nil {
		return nil, fmt.Errorf("failed to create timing transmitter: %w", err)
	}

	return &EnhancedShardedTrafficStream{
		ShardedTrafficStream: baseStream,
		timingTransmitter:    timingTransmitter,
	}, nil
}

// SendPacketWithFullObfuscation sends a packet with complete traffic analysis resistance
func (ests *EnhancedShardedTrafficStream) SendPacketWithFullObfuscation(data []byte) error {
	if len(data) == 0 {
		return errors.New("cannot send empty packet")
	}

	// Step 1: Shard the packet
	shards, err := ShardPacket(data, ests.maxShardSize)
	if err != nil {
		return fmt.Errorf("failed to shard packet: %w", err)
	}

	// Step 2: Generate noise packets for each route
	noisePacketsPerRoute := make(map[int][][]byte)
	for i := range ests.routes {
		numNoisePackets := int(float64(len(shards)) * ests.noiseRatio / float64(len(ests.routes)))
		if numNoisePackets < 1 && ests.noiseRatio > 0 {
			numNoisePackets = 1
		}

		noisePackets := make([][]byte, numNoisePackets)
		for j := 0; j < numNoisePackets; j++ {
			noisePacket, err := GenerateNoisePacket()
			if err != nil {
				return fmt.Errorf("failed to generate noise packet for route %d: %w", i, err)
			}
			noisePackets[j] = noisePacket.Data
		}
		noisePacketsPerRoute[i] = noisePackets
	}

	// Step 3: Distribute shards with timing resistance
	return ests.distributeWithTimingResistance(shards, noisePacketsPerRoute)
}

// distributeWithTimingResistance distributes shards with both noise injection and timing resistance
func (ests *EnhancedShardedTrafficStream) distributeWithTimingResistance(shards []*PacketShard, noisePacketsPerRoute map[int][][]byte) error {
	shardDistribution := ests.createShardDistribution(shards)

	var wg sync.WaitGroup
	errChan := make(chan error, len(ests.routes))

	for routeIdx, route := range ests.routes {
		wg.Add(1)
		go func(idx int, r *Route) {
			defer wg.Done()
			
			routeShards := shardDistribution[idx]
			noisePackets := noisePacketsPerRoute[idx]
			
			// Combine and serialize packets
			allPackets := make([][]byte, 0, len(routeShards)+len(noisePackets))
			
			for _, shard := range routeShards {
				serializedShard, err := SerializePacketShard(shard)
				if err != nil {
					errChan <- fmt.Errorf("failed to serialize shard for route %d: %w", idx, err)
					return
				}
				allPackets = append(allPackets, serializedShard)
			}
			
			allPackets = append(allPackets, noisePackets...)
			shufflePackets(allPackets)
			
			// Transmit with timing resistance
			transmitFunc := func(packet []byte) error {
				return ests.simulateRouteTransmission(packet, r)
			}
			
			if err := ests.timingTransmitter.TransmitWithTimingResistance(allPackets, transmitFunc); err != nil {
				errChan <- fmt.Errorf("failed to transmit packets on route %d with timing resistance: %w", idx, err)
			}
		}(routeIdx, route)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// GetEnhancedTrafficStats returns comprehensive traffic obfuscation statistics
func (ests *EnhancedShardedTrafficStream) GetEnhancedTrafficStats() EnhancedTrafficStats {
	baseStats := ests.GetTrafficStats()
	timingStats := ests.timingTransmitter.GetTimingStats()

	return EnhancedTrafficStats{
		TrafficStats: baseStats,
		TimingStats:  timingStats,
	}
}

// EnhancedTrafficStats contains comprehensive traffic obfuscation statistics
type EnhancedTrafficStats struct {
	TrafficStats // Base traffic statistics
	TimingStats  // Timing resistance statistics
}
