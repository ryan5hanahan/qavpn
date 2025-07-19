package direct

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// ConnectionState represents the state of a direct connection
type ConnectionState int

const (
	StateIdle ConnectionState = iota
	StateInviting
	StateConnecting
	StateListening
	StateConnected
	StateDisconnected
	StateError
)

// String returns the string representation of the connection state
func (s ConnectionState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateInviting:
		return "inviting"
	case StateConnecting:
		return "connecting"
	case StateListening:
		return "listening"
	case StateConnected:
		return "connected"
	case StateDisconnected:
		return "disconnected"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// DirectConnectionManagerImpl implements the DirectConnectionManager interface
type DirectConnectionManagerImpl struct {
	config           *DirectConfig
	invitationCodes  map[string]*InvitationCode
	activeConnections map[string]*DirectConnection
	connectionStates map[string]ConnectionState
	listeners        map[string]net.Listener
	configManager    SecureConfigManager
	opsecLayer       OPSECNetworkLayer
	invitationProcessor InvitationCodeProcessor
	mutex            sync.RWMutex
	shutdownChan     chan struct{}
}

// NewDirectConnectionManager creates a new DirectConnectionManager instance
func NewDirectConnectionManager(config *DirectConfig) DirectConnectionManager {
	return &DirectConnectionManagerImpl{
		config:            config,
		invitationCodes:   make(map[string]*InvitationCode),
		activeConnections: make(map[string]*DirectConnection),
		connectionStates:  make(map[string]ConnectionState),
		listeners:         make(map[string]net.Listener),
		mutex:             sync.RWMutex{},
		shutdownChan:      make(chan struct{}),
	}
}

// StartListener starts listening for incoming direct connections
func (dcm *DirectConnectionManagerImpl) StartListener(config *ListenerConfig) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	// Validate listener configuration
	if config.Port <= 0 || config.Port > 65535 {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			fmt.Sprintf("invalid port number: %d", config.Port), 
			"start_listener")
	}

	if config.Protocol != "tcp" && config.Protocol != "udp" {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			fmt.Sprintf("unsupported protocol: %s", config.Protocol), 
			"start_listener")
	}

	// Create listener key for tracking
	listenerKey := fmt.Sprintf("%s:%d", config.Protocol, config.Port)
	
	// Check if listener already exists
	if _, exists := dcm.listeners[listenerKey]; exists {
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("listener already exists on %s:%d", config.Protocol, config.Port), 
			"start_listener", false)
	}

	// Determine bind address
	bindAddr := fmt.Sprintf(":%d", config.Port)
	if config.Address != "" {
		bindAddr = fmt.Sprintf("%s:%d", config.Address, config.Port)
	}

	// Create listener based on protocol
	var listener net.Listener
	var err error

	switch config.Protocol {
	case "tcp":
		listener, err = net.Listen("tcp", bindAddr)
		if err != nil {
			return NewConnectionError(ErrCodeConnectionFailed, 
				fmt.Sprintf("failed to start TCP listener on %s: %v", bindAddr, err), 
				"start_listener", true)
		}
	case "udp":
		// For UDP, we need to handle it differently as it's connectionless
		// We'll create a UDP listener that simulates connection behavior
		udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
		if err != nil {
			return NewConnectionError(ErrCodeConnectionFailed, 
				fmt.Sprintf("failed to resolve UDP address %s: %v", bindAddr, err), 
				"start_listener", true)
		}
		
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return NewConnectionError(ErrCodeConnectionFailed, 
				fmt.Sprintf("failed to start UDP listener on %s: %v", bindAddr, err), 
				"start_listener", true)
		}
		
		// Wrap UDP connection to implement net.Listener interface
		listener = &udpListener{conn: udpConn}
	default:
		return NewConfigurationError(ErrCodeInvalidConfig, 
			fmt.Sprintf("unsupported protocol: %s", config.Protocol), 
			"start_listener")
	}

	// Store listener
	dcm.listeners[listenerKey] = listener

	// Update connection state
	dcm.connectionStates[listenerKey] = StateListening

	// Start accept loop in goroutine
	go dcm.acceptLoop(listenerKey, listener, config.Protocol)

	return nil
}

// ConnectToPeerEnhanced establishes an enhanced connection to a peer with role negotiation
func (dcm *DirectConnectionManagerImpl) ConnectToPeerEnhanced(invitation *InvitationCode) error {
	// Validate invitation
	if err := dcm.ValidateInvitation(invitation); err != nil {
		return fmt.Errorf("invitation validation failed: %w", err)
	}

	connectionID := hex.EncodeToString(invitation.ConnectionID[:])

	dcm.mutex.Lock()
	// Check if connection already exists
	if _, exists := dcm.activeConnections[connectionID]; exists {
		dcm.mutex.Unlock()
		return NewConnectionError(ErrCodeConnectionFailed, 
			"connection already exists", 
			"connect_to_peer_enhanced", false)
	}

	// Update connection state to connecting
	dcm.connectionStates[connectionID] = StateConnecting
	dcm.mutex.Unlock()

	// Establish network connection with retry logic
	conn, err := dcm.establishEnhancedNetworkConnection(invitation.NetworkConfig)
	if err != nil {
		dcm.mutex.Lock()
		dcm.connectionStates[connectionID] = StateError
		dcm.mutex.Unlock()
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to establish network connection: %v", err), 
			"connect_to_peer_enhanced", true)
	}

	// Initialize post-quantum key exchange
	keyExchange, err := NewPostQuantumKeyExchange()
	if err != nil {
		conn.Close()
		dcm.mutex.Lock()
		dcm.connectionStates[connectionID] = StateError
		dcm.mutex.Unlock()
		return NewCryptographicError(ErrCodeEncryptionFailure, 
			fmt.Sprintf("failed to initialize key exchange: %v", err), 
			"connect_to_peer_enhanced")
	}

	// Create DirectConnection with handshake support
	directConn := &DirectConnection{
		ConnectionID:  invitation.ConnectionID,
		Role:         RoleConnector,
		State:        "connecting",
		tunnel:       &simpleTunnel{conn: conn},
		keyExchange:  keyExchange,
		networkConfig: invitation.NetworkConfig,
		handshakeState: &HandshakeState{
			State:           PhaseInit,
			LocalRole:       RoleConnector,
			Priority:        GenerateRolePriority(),
			StartTime:       time.Now(),
			AttemptCount:    1,
		},
		LastActivity: time.Now(),
		ConnectedAt:  time.Now(),
		isActive:     false,
		trafficStats: &TrafficStats{
			LastActivity: time.Now(),
		},
	}

	// Store the connection
	dcm.mutex.Lock()
	dcm.activeConnections[connectionID] = directConn
	dcm.connectionStates[connectionID] = StateConnecting
	dcm.mutex.Unlock()

	// Initiate handshake with role negotiation
	if err := directConn.InitiateHandshake(); err != nil {
		dcm.cleanupConnection(connectionID, directConn)
		return NewConnectionError(ErrCodeHandshakeFailure, 
			fmt.Sprintf("handshake initiation failed: %v", err), 
			"connect_to_peer_enhanced", true)
	}

	// Complete handshake process
	if err := dcm.completeConnectorHandshake(directConn); err != nil {
		dcm.cleanupConnection(connectionID, directConn)
		return NewConnectionError(ErrCodeHandshakeFailure, 
			fmt.Sprintf("handshake completion failed: %v", err), 
			"connect_to_peer_enhanced", true)
	}

	// Establish the connection after successful handshake
	if err := directConn.Establish(); err != nil {
		dcm.cleanupConnection(connectionID, directConn)
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to establish connection: %v", err), 
			"connect_to_peer_enhanced", true)
	}

	// Update connection state to connected
	dcm.mutex.Lock()
	dcm.connectionStates[connectionID] = StateConnected
	dcm.mutex.Unlock()

	// Start connection monitoring
	go dcm.monitorConnection(connectionID, directConn)

	return nil
}

// ConnectToPeer establishes a connection to a peer using an invitation code
func (dcm *DirectConnectionManagerImpl) ConnectToPeer(invitation *InvitationCode) error {
	// Validate invitation
	if err := dcm.ValidateInvitation(invitation); err != nil {
		return fmt.Errorf("invitation validation failed: %w", err)
	}

	connectionID := hex.EncodeToString(invitation.ConnectionID[:])

	dcm.mutex.Lock()
	// Check if connection already exists
	if _, exists := dcm.activeConnections[connectionID]; exists {
		dcm.mutex.Unlock()
		return NewConnectionError(ErrCodeConnectionFailed, 
			"connection already exists", 
			"connect_to_peer", false)
	}

	// Atomically update both state and reserve the connection slot
	dcm.connectionStates[connectionID] = StateConnecting
	// Reserve the slot to prevent race conditions
	dcm.activeConnections[connectionID] = nil
	dcm.mutex.Unlock()

	// Establish network connection to peer
	conn, err := dcm.establishNetworkConnection(invitation.NetworkConfig)
	if err != nil {
		dcm.mutex.Lock()
		delete(dcm.activeConnections, connectionID)
		dcm.connectionStates[connectionID] = StateError
		dcm.mutex.Unlock()
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to establish network connection: %v", err), 
			"connect_to_peer", true)
	}

	// Initialize post-quantum key exchange
	keyExchange, err := NewPostQuantumKeyExchange()
	if err != nil {
		conn.Close()
		dcm.mutex.Lock()
		delete(dcm.activeConnections, connectionID)
		dcm.connectionStates[connectionID] = StateError
		dcm.mutex.Unlock()
		return NewCryptographicError(ErrCodeEncryptionFailure, 
			fmt.Sprintf("failed to initialize key exchange: %v", err), 
			"connect_to_peer")
	}

	// Create DirectConnection instance
	directConn := &DirectConnection{
		ConnectionID:  invitation.ConnectionID,
		Role:         RoleConnector,
		State:        "connecting",
		tunnel:       &simpleTunnel{conn: conn},
		keyExchange:  keyExchange,
		networkConfig: invitation.NetworkConfig,
		LastActivity: time.Now(),
		ConnectedAt:  time.Now(),
		isActive:     false, // Will be set to true after key exchange
		trafficStats: &TrafficStats{
			LastActivity: time.Now(),
		},
	}

	// Atomically update the connection
	dcm.mutex.Lock()
	dcm.activeConnections[connectionID] = directConn
	dcm.connectionStates[connectionID] = StateConnecting
	dcm.mutex.Unlock()

	// Perform post-quantum key exchange
	if err := dcm.performKeyExchange(directConn, invitation); err != nil {
		// Clean up on failure
		directConn.Disconnect()
		dcm.mutex.Lock()
		delete(dcm.activeConnections, connectionID)
		dcm.connectionStates[connectionID] = StateError
		dcm.mutex.Unlock()
		return NewCryptographicError(ErrCodeEncryptionFailure, 
			fmt.Sprintf("key exchange failed: %v", err), 
			"connect_to_peer")
	}

	// Establish the connection (complete key exchange)
	if err := directConn.Establish(); err != nil {
		// Clean up on failure
		directConn.Disconnect()
		dcm.mutex.Lock()
		delete(dcm.activeConnections, connectionID)
		dcm.connectionStates[connectionID] = StateError
		dcm.mutex.Unlock()
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to establish connection: %v", err), 
			"connect_to_peer", true)
	}

	// Update connection state to connected
	dcm.mutex.Lock()
	dcm.connectionStates[connectionID] = StateConnected
	dcm.mutex.Unlock()

	// Start connection monitoring in background
	go dcm.monitorConnection(connectionID, directConn)

	return nil
}

// establishNetworkConnection creates a network connection based on the network configuration
func (dcm *DirectConnectionManagerImpl) establishNetworkConnection(networkConfig *NetworkConfig) (net.Conn, error) {
	var conn net.Conn
	var err error

	// Try primary address first
	switch networkConfig.Protocol {
	case "tcp":
		conn, err = net.DialTimeout("tcp", networkConfig.ListenerAddress, 30*time.Second)
	case "udp":
		conn, err = net.DialTimeout("udp", networkConfig.ListenerAddress, 30*time.Second)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", networkConfig.Protocol)
	}

	if err == nil {
		return conn, nil
	}

	// If primary address fails, try backup addresses
	for _, backupAddr := range networkConfig.BackupAddresses {
		switch networkConfig.Protocol {
		case "tcp":
			conn, err = net.DialTimeout("tcp", backupAddr, 30*time.Second)
		case "udp":
			conn, err = net.DialTimeout("udp", backupAddr, 30*time.Second)
		}

		if err == nil {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("failed to connect to any address: %v", err)
}

// monitorConnection monitors a connection and handles keep-alive
func (dcm *DirectConnectionManagerImpl) monitorConnection(connectionID string, directConn *DirectConnection) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-dcm.shutdownChan:
			return
		case <-ticker.C:
			// Check if connection is still active
			if !directConn.tunnel.IsActive() {
				// Connection is dead, clean up
				dcm.mutex.Lock()
				delete(dcm.activeConnections, connectionID)
				dcm.connectionStates[connectionID] = StateDisconnected
				dcm.mutex.Unlock()
				return
			}

			// Send keep-alive ping (simple implementation)
			err := directConn.tunnel.SendData([]byte("PING"))
			if err != nil {
				// Connection failed, clean up
				dcm.mutex.Lock()
				delete(dcm.activeConnections, connectionID)
				dcm.connectionStates[connectionID] = StateError
				dcm.mutex.Unlock()
				return
			}

			// Update last activity
			directConn.mutex.Lock()
			directConn.LastActivity = time.Now()
			directConn.trafficStats.LastActivity = time.Now()
			directConn.mutex.Unlock()
		}
	}
}

// DisconnectPeer disconnects from a specific peer
func (dcm *DirectConnectionManagerImpl) DisconnectPeer(connectionID string) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	connection, exists := dcm.activeConnections[connectionID]
	if !exists {
		return NewConnectionError(ErrCodeConnectionFailed, 
			"connection not found", 
			"disconnect_peer", false)
	}

	// Close the connection
	if err := connection.tunnel.Close(); err != nil {
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to close connection: %v", err), 
			"disconnect_peer", true)
	}

	// Remove from active connections
	delete(dcm.activeConnections, connectionID)

	return nil
}

// GenerateInvitation creates a new invitation code for establishing direct connections
func (dcm *DirectConnectionManagerImpl) GenerateInvitation(config *InvitationConfig) (*InvitationCode, error) {
	// Generate unique connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate connection ID", 
			"generate_invitation")
	}

	// TODO: Generate post-quantum key pair
	// For now, create placeholder public key
	publicKey := make([]byte, 1568) // Kyber-1024 public key size
	if _, err := rand.Read(publicKey); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate public key", 
			"generate_invitation")
	}

	// Create network configuration
	networkConfig := &NetworkConfig{
		Protocol:        config.Protocol,
		ListenerAddress: config.ListenerAddress,
		BackupAddresses: config.BackupAddresses,
	}

	// Generate security parameters
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate salt", 
			"generate_invitation")
	}

	securityParams := &SecurityParams{
		KeyDerivationSalt: salt,
		CipherSuite:       "kyber1024-aes256-gcm",
		AuthMethod:        "pqc-mutual-auth",
	}

	// Create invitation code
	invitation := &InvitationCode{
		Version:         1,
		ConnectionID:    connectionID,
		PublicKey:       publicKey,
		NetworkConfig:   networkConfig,
		SecurityParams:  securityParams,
		ExpirationTime:  config.ExpirationTime,
		SingleUse:       config.SingleUse,
		CreatedAt:       time.Now(),
	}

	// TODO: Generate cryptographic signature
	// For now, create placeholder signature
	signature := make([]byte, 64) // Ed25519 signature size
	if _, err := rand.Read(signature); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate signature", 
			"generate_invitation")
	}
	invitation.Signature = signature

	// Store invitation code
	invitationKey := hex.EncodeToString(connectionID[:])
	dcm.mutex.Lock()
	dcm.invitationCodes[invitationKey] = invitation
	dcm.mutex.Unlock()

	return invitation, nil
}

// ProcessInvitation processes an invitation code from string format
func (dcm *DirectConnectionManagerImpl) ProcessInvitation(invitationData string) (*InvitationCode, error) {
	// TODO: Implement invitation code processing
	// This would involve:
	// 1. Detecting format (base64, hex, QR code)
	// 2. Decoding the invitation data
	// 3. Validating the invitation structure
	// 4. Returning the parsed invitation

	return nil, NewInvitationError(ErrCodeMalformedInvitation, 
		"invitation processing not yet implemented", 
		"process_invitation")
}

// ValidateInvitation validates an invitation code
func (dcm *DirectConnectionManagerImpl) ValidateInvitation(invitation *InvitationCode) error {
	if invitation == nil {
		return NewInvitationError(ErrCodeInvalidInvitation, 
			"invitation is nil", 
			"validate_invitation")
	}

	// Check version
	if invitation.Version != 1 {
		return NewInvitationError(ErrCodeInvalidInvitation, 
			fmt.Sprintf("unsupported version: %d", invitation.Version), 
			"validate_invitation")
	}

	// Check expiration
	if time.Now().After(invitation.ExpirationTime) {
		return NewInvitationError(ErrCodeExpiredInvitation, 
			"invitation has expired", 
			"validate_invitation")
	}

	// Validate network configuration
	if invitation.NetworkConfig == nil {
		return NewInvitationError(ErrCodeInvalidInvitation, 
			"missing network configuration", 
			"validate_invitation")
	}

	if invitation.NetworkConfig.Protocol != "tcp" && invitation.NetworkConfig.Protocol != "udp" {
		return NewInvitationError(ErrCodeInvalidInvitation, 
			fmt.Sprintf("unsupported protocol: %s", invitation.NetworkConfig.Protocol), 
			"validate_invitation")
	}

	// Validate public key
	if len(invitation.PublicKey) == 0 {
		return NewInvitationError(ErrCodeInvalidInvitation, 
			"missing public key", 
			"validate_invitation")
	}

	// TODO: Validate cryptographic signature
	// This would involve verifying the signature against the invitation data

	return nil
}

// GetActiveConnections returns all active direct connections
func (dcm *DirectConnectionManagerImpl) GetActiveConnections() []*DirectConnection {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	connections := make([]*DirectConnection, 0, len(dcm.activeConnections))
	for _, conn := range dcm.activeConnections {
		connections = append(connections, conn)
	}

	return connections
}

// GetConnectionStatus returns the status of a specific connection
func (dcm *DirectConnectionManagerImpl) GetConnectionStatus(connectionID string) (*ConnectionStatus, error) {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	connection, exists := dcm.activeConnections[connectionID]
	if !exists {
		return nil, NewConnectionError(ErrCodeConnectionFailed, 
			"connection not found", 
			"get_connection_status", false)
	}

	// Create connection status
	status := &ConnectionStatus{
		ConnectionID:    connection.ConnectionID,
		Role:           connection.Role,
		State:          connection.State,
		IsActive:       connection.isActive,
		RemoteAddress:  connection.RemoteAddress,
		ConnectedSince: connection.ConnectedAt,
		LastActivity:   connection.LastActivity,
		BytesSent:      connection.BytesSent,
		BytesReceived:  connection.BytesReceived,
		TrafficStats:   connection.trafficStats,
	}

	return status, nil
}

// SaveConnectionProfile saves a connection profile
func (dcm *DirectConnectionManagerImpl) SaveConnectionProfile(profile *ConnectionProfile) error {
	if dcm.configManager == nil {
		return NewStorageError(ErrCodeStorageFailure, 
			"config manager not initialized", 
			"save_connection_profile", false)
	}

	return dcm.configManager.SaveProfile(profile)
}

// LoadConnectionProfile loads a connection profile by name
func (dcm *DirectConnectionManagerImpl) LoadConnectionProfile(name string) (*ConnectionProfile, error) {
	if dcm.configManager == nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			"config manager not initialized", 
			"load_connection_profile", false)
	}

	return dcm.configManager.LoadProfile(name)
}

// DeleteConnectionProfile deletes a connection profile by name
func (dcm *DirectConnectionManagerImpl) DeleteConnectionProfile(name string) error {
	if dcm.configManager == nil {
		return NewStorageError(ErrCodeStorageFailure, 
			"config manager not initialized", 
			"delete_connection_profile", false)
	}

	return dcm.configManager.DeleteProfile(name)
}

// udpListener wraps a UDP connection to implement the net.Listener interface
type udpListener struct {
	conn *net.UDPConn
}

func (ul *udpListener) Accept() (net.Conn, error) {
	// For UDP, we simulate connection behavior by reading the first packet
	// and creating a connection-like wrapper
	buffer := make([]byte, 1024)
	n, addr, err := ul.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	// Create a UDP connection wrapper that behaves like a connection
	return &udpConn{
		conn:       ul.conn,
		remoteAddr: addr,
		buffer:     buffer[:n],
	}, nil
}

func (ul *udpListener) Close() error {
	return ul.conn.Close()
}

func (ul *udpListener) Addr() net.Addr {
	return ul.conn.LocalAddr()
}

// udpConn wraps UDP communication to behave like a connection
type udpConn struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	buffer     []byte
	closed     bool
}

func (uc *udpConn) Read(b []byte) (int, error) {
	if uc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	// If we have buffered data from the initial packet, return it first
	if len(uc.buffer) > 0 {
		n := copy(b, uc.buffer)
		uc.buffer = uc.buffer[n:]
		return n, nil
	}

	// Read from UDP connection, filtering for our remote address
	for {
		buffer := make([]byte, len(b))
		n, addr, err := uc.conn.ReadFromUDP(buffer)
		if err != nil {
			return 0, err
		}

		// Only return data from our expected remote address
		if addr.String() == uc.remoteAddr.String() {
			return copy(b, buffer[:n]), nil
		}
	}
}

func (uc *udpConn) Write(b []byte) (int, error) {
	if uc.closed {
		return 0, fmt.Errorf("connection closed")
	}
	return uc.conn.WriteToUDP(b, uc.remoteAddr)
}

func (uc *udpConn) Close() error {
	uc.closed = true
	return nil
}

func (uc *udpConn) LocalAddr() net.Addr {
	return uc.conn.LocalAddr()
}

func (uc *udpConn) RemoteAddr() net.Addr {
	return uc.remoteAddr
}

func (uc *udpConn) SetDeadline(t time.Time) error {
	return uc.conn.SetDeadline(t)
}

func (uc *udpConn) SetReadDeadline(t time.Time) error {
	return uc.conn.SetReadDeadline(t)
}

func (uc *udpConn) SetWriteDeadline(t time.Time) error {
	return uc.conn.SetWriteDeadline(t)
}

// acceptLoop handles incoming connections for a listener
func (dcm *DirectConnectionManagerImpl) acceptLoop(listenerKey string, listener net.Listener, protocol string) {
	defer func() {
		dcm.mutex.Lock()
		delete(dcm.listeners, listenerKey)
		delete(dcm.connectionStates, listenerKey)
		dcm.mutex.Unlock()
	}()

	for {
		select {
		case <-dcm.shutdownChan:
			return
		default:
			// Accept incoming connection
			conn, err := listener.Accept()
			if err != nil {
				// Check if we're shutting down
				select {
				case <-dcm.shutdownChan:
					return
				default:
					// Log error and continue
					continue
				}
			}

			// Handle connection in separate goroutine
			go dcm.handleIncomingConnection(conn, protocol)
		}
	}
}

// performKeyExchange performs the post-quantum key exchange for a connector
func (dcm *DirectConnectionManagerImpl) performKeyExchange(directConn *DirectConnection, invitation *InvitationCode) error {
	// Initiate key exchange
	initMessage, err := directConn.keyExchange.InitiateKeyExchange()
	if err != nil {
		return fmt.Errorf("failed to initiate key exchange: %w", err)
	}

	// Send init message
	messageData, err := directConn.serializeKeyExchangeMessage(initMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize init message: %w", err)
	}

	if err := directConn.tunnel.SendData(messageData); err != nil {
		return fmt.Errorf("failed to send init message: %w", err)
	}

	// Wait for response
	responseData, err := directConn.tunnel.ReceiveData()
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	// Process response
	responseMessage, err := directConn.deserializeKeyExchangeMessage(responseData)
	if err != nil {
		return fmt.Errorf("failed to deserialize response: %w", err)
	}

	confirmMessage, err := directConn.keyExchange.ProcessKeyExchangeMessage(responseMessage)
	if err != nil {
		return fmt.Errorf("failed to process response: %w", err)
	}

	// Send confirmation if needed
	if confirmMessage != nil {
		confirmData, err := directConn.serializeKeyExchangeMessage(confirmMessage)
		if err != nil {
			return fmt.Errorf("failed to serialize confirm message: %w", err)
		}

		if err := directConn.tunnel.SendData(confirmData); err != nil {
			return fmt.Errorf("failed to send confirm message: %w", err)
		}
	}

	// Verify key exchange is complete
	if !directConn.keyExchange.IsKeyExchangeComplete() {
		return fmt.Errorf("key exchange not completed successfully")
	}

	return nil
}

// handleIncomingConnection processes an incoming direct connection
func (dcm *DirectConnectionManagerImpl) handleIncomingConnection(conn net.Conn, protocol string) {
	defer conn.Close()

	// Generate connection ID for this incoming connection
	connectionID, err := GenerateConnectionID()
	if err != nil {
		return
	}

	connectionIDStr := hex.EncodeToString(connectionID[:])

	// Initialize post-quantum key exchange
	keyExchange, err := NewPostQuantumKeyExchange()
	if err != nil {
		return
	}

	// Create DirectConnection instance
	directConn := &DirectConnection{
		ConnectionID:  connectionID,
		Role:         RoleListener,
		State:        "listening",
		RemoteAddress: conn.RemoteAddr().String(),
		tunnel:       &simpleTunnel{conn: conn},
		keyExchange:  keyExchange,
		networkConfig: &NetworkConfig{
			Protocol:        protocol,
			ListenerAddress: conn.LocalAddr().String(),
		},
		LastActivity: time.Now(),
		ConnectedAt:  time.Now(),
		isActive:     false, // Will be set to true after key exchange
		trafficStats: &TrafficStats{
			LastActivity: time.Now(),
		},
	}

	// Store the connection
	dcm.mutex.Lock()
	dcm.activeConnections[connectionIDStr] = directConn
	dcm.connectionStates[connectionIDStr] = StateConnecting
	dcm.mutex.Unlock()

	// Perform key exchange as responder
	if err := dcm.handleIncomingKeyExchange(directConn); err != nil {
		// Clean up on failure
		directConn.Disconnect()
		dcm.mutex.Lock()
		delete(dcm.activeConnections, connectionIDStr)
		delete(dcm.connectionStates, connectionIDStr)
		dcm.mutex.Unlock()
		return
	}

	// Establish the connection
	if err := directConn.Establish(); err != nil {
		// Clean up on failure
		directConn.Disconnect()
		dcm.mutex.Lock()
		delete(dcm.activeConnections, connectionIDStr)
		delete(dcm.connectionStates, connectionIDStr)
		dcm.mutex.Unlock()
		return
	}

	// Update connection state
	dcm.mutex.Lock()
	dcm.connectionStates[connectionIDStr] = StateConnected
	dcm.mutex.Unlock()

	// Handle connection data
	for {
		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		
		// Try to receive data through the DirectConnection interface
		_, err := directConn.ReceiveData()
		if err != nil {
			break
		}

		// Update last activity
		directConn.mutex.Lock()
		directConn.LastActivity = time.Now()
		directConn.trafficStats.LastActivity = time.Now()
		directConn.mutex.Unlock()
	}

	// Clean up connection
	directConn.Disconnect()
	dcm.mutex.Lock()
	delete(dcm.activeConnections, connectionIDStr)
	delete(dcm.connectionStates, connectionIDStr)
	dcm.mutex.Unlock()
}

// handleIncomingKeyExchange handles key exchange for incoming connections (responder)
func (dcm *DirectConnectionManagerImpl) handleIncomingKeyExchange(directConn *DirectConnection) error {
	// Wait for init message
	initData, err := directConn.tunnel.ReceiveData()
	if err != nil {
		return fmt.Errorf("failed to receive init message: %w", err)
	}

	// Process init message
	initMessage, err := directConn.deserializeKeyExchangeMessage(initData)
	if err != nil {
		return fmt.Errorf("failed to deserialize init message: %w", err)
	}

	responseMessage, err := directConn.keyExchange.ProcessKeyExchangeMessage(initMessage)
	if err != nil {
		return fmt.Errorf("failed to process init message: %w", err)
	}

	// Send response
	if responseMessage != nil {
		responseData, err := directConn.serializeKeyExchangeMessage(responseMessage)
		if err != nil {
			return fmt.Errorf("failed to serialize response: %w", err)
		}

		if err := directConn.tunnel.SendData(responseData); err != nil {
			return fmt.Errorf("failed to send response: %w", err)
		}
	}

	// Wait for confirmation
	confirmData, err := directConn.tunnel.ReceiveData()
	if err != nil {
		return fmt.Errorf("failed to receive confirmation: %w", err)
	}

	confirmMessage, err := directConn.deserializeKeyExchangeMessage(confirmData)
	if err != nil {
		return fmt.Errorf("failed to deserialize confirmation: %w", err)
	}

	_, err = directConn.keyExchange.ProcessKeyExchangeMessage(confirmMessage)
	if err != nil {
		return fmt.Errorf("failed to process confirmation: %w", err)
	}

	// Verify key exchange is complete
	if !directConn.keyExchange.IsKeyExchangeComplete() {
		return fmt.Errorf("key exchange not completed successfully")
	}

	return nil
}

// simpleTunnel implements the Tunnel interface for basic connections
type simpleTunnel struct {
	conn   net.Conn
	closed bool
	mutex  sync.Mutex
}

func (st *simpleTunnel) SendData(data []byte) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return fmt.Errorf("tunnel is closed")
	}

	_, err := st.conn.Write(data)
	return err
}

func (st *simpleTunnel) ReceiveData() ([]byte, error) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return nil, fmt.Errorf("tunnel is closed")
	}

	buffer := make([]byte, 4096)
	n, err := st.conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

func (st *simpleTunnel) Close() error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if st.closed {
		return nil
	}

	st.closed = true
	return st.conn.Close()
}

func (st *simpleTunnel) IsActive() bool {
	st.mutex.Lock()
	defer st.mutex.Unlock()
	return !st.closed
}

// DirectConnection methods for key exchange and secure communication

// Establish performs the key exchange and establishes secure communication
func (dc *DirectConnection) Establish() error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	if dc.keyExchange == nil {
		return fmt.Errorf("key exchange not initialized")
	}

	// Key exchange should already be completed during connection setup
	if !dc.keyExchange.IsKeyExchangeComplete() {
		return fmt.Errorf("key exchange not complete")
	}

	// Update crypto context with session keys
	sessionKeys := dc.keyExchange.GetSessionKeys()
	if sessionKeys == nil {
		return fmt.Errorf("session keys not available")
	}

	if dc.cryptoContext == nil {
		dc.cryptoContext = &CryptoContext{
			CreatedAt: time.Now(),
		}
	}
	dc.cryptoContext.SessionKeys = sessionKeys

	dc.isActive = true
	dc.LastActivity = time.Now()

	return nil
}

// Disconnect closes the direct connection
func (dc *DirectConnection) Disconnect() error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	if dc.tunnel != nil {
		if err := dc.tunnel.Close(); err != nil {
			return fmt.Errorf("failed to close tunnel: %w", err)
		}
	}

	// Securely wipe cryptographic material
	if dc.keyExchange != nil {
		dc.keyExchange.SecureWipe()
	}

	dc.isActive = false
	return nil
}

// IsHealthy checks if the connection is healthy
func (dc *DirectConnection) IsHealthy() bool {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	if !dc.isActive || dc.tunnel == nil {
		return false
	}

	// Check if tunnel is still active
	if !dc.tunnel.IsActive() {
		return false
	}

	// Check if key exchange is still valid
	if dc.keyExchange != nil && !dc.keyExchange.IsKeyExchangeComplete() {
		return false
	}

	// Check for recent activity (within last 5 minutes)
	if time.Since(dc.LastActivity) > 5*time.Minute {
		return false
	}

	return true
}

// SendData sends encrypted data through the direct connection
func (dc *DirectConnection) SendData(data []byte) error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	if !dc.isActive || dc.tunnel == nil {
		return fmt.Errorf("connection not active")
	}

	// Check if we need to rotate keys
	if dc.keyExchange != nil && dc.keyExchange.ShouldRotateKeys() {
		if err := dc.rotateKeys(); err != nil {
			return fmt.Errorf("key rotation failed: %w", err)
		}
	}

	// Encrypt data using session keys
	encryptedData, err := dc.encryptData(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Release lock during I/O operation to prevent blocking
	dc.mutex.Unlock()
	sendErr := dc.tunnel.SendData(encryptedData)
	dc.mutex.Lock()
	
	if sendErr != nil {
		return fmt.Errorf("tunnel send failed: %w", sendErr)
	}

	// Atomically update statistics
	now := time.Now()
	dc.trafficStats.BytesSent += uint64(len(data))
	dc.trafficStats.PacketsSent++
	dc.LastActivity = now
	dc.BytesSent += uint64(len(data))
	dc.trafficStats.LastActivity = now

	return nil
}

// ReceiveData receives and decrypts data from the direct connection
func (dc *DirectConnection) ReceiveData() ([]byte, error) {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	if !dc.isActive || dc.tunnel == nil {
		return nil, fmt.Errorf("connection not active")
	}

	// Receive from tunnel
	encryptedData, err := dc.tunnel.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("tunnel receive failed: %w", err)
	}

	// Check if this is a key exchange message
	if dc.isKeyExchangeMessage(encryptedData) {
		return dc.handleKeyExchangeMessage(encryptedData)
	}

	// Decrypt data using session keys
	decryptedData, err := dc.decryptData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Update statistics
	dc.trafficStats.BytesReceived += uint64(len(decryptedData))
	dc.trafficStats.PacketsReceived++
	dc.LastActivity = time.Now()
	dc.BytesReceived += uint64(len(decryptedData))
	dc.trafficStats.LastActivity = time.Now()

	return decryptedData, nil
}

// Close closes the direct connection
func (dc *DirectConnection) Close() error {
	return dc.Disconnect()
}

// IsActive returns whether the connection is active
func (dc *DirectConnection) IsActive() bool {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()
	return dc.isActive && dc.tunnel != nil && dc.tunnel.IsActive()
}

// EnableTrafficObfuscation enables traffic obfuscation for OPSEC
func (dc *DirectConnection) EnableTrafficObfuscation() error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	// TODO: Implement traffic obfuscation
	// This would integrate with the OPSEC network layer
	return nil
}

// SetKeepAliveInterval sets the keep-alive interval
func (dc *DirectConnection) SetKeepAliveInterval(interval time.Duration) error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	// TODO: Implement configurable keep-alive
	// This would be used by the connection monitoring
	return nil
}

// GetConnectionMetrics returns detailed connection metrics
func (dc *DirectConnection) GetConnectionMetrics() *ConnectionMetrics {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	// TODO: Implement detailed metrics collection
	return &ConnectionMetrics{
		Latency:         0, // Would measure actual latency
		Throughput:      0, // Would calculate based on traffic stats
		PacketLoss:      0, // Would track packet loss
		ConnectionTime:  time.Since(dc.cryptoContext.CreatedAt),
		LastHealthCheck: dc.LastActivity,
	}
}

// rotateKeys initiates key rotation
func (dc *DirectConnection) rotateKeys() error {
	if dc.keyExchange == nil {
		return fmt.Errorf("key exchange not initialized")
	}

	// Initiate key rotation
	rotationMessage, err := dc.keyExchange.InitiateKeyRotation()
	if err != nil {
		return fmt.Errorf("failed to initiate key rotation: %w", err)
	}

	// Send rotation message through tunnel
	messageData, err := dc.serializeKeyExchangeMessage(rotationMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize rotation message: %w", err)
	}

	if err := dc.tunnel.SendData(messageData); err != nil {
		return fmt.Errorf("failed to send rotation message: %w", err)
	}

	return nil
}

// encryptData encrypts data using the current session keys
func (dc *DirectConnection) encryptData(data []byte) ([]byte, error) {
	if dc.cryptoContext == nil || dc.cryptoContext.SessionKeys == nil {
		return nil, fmt.Errorf("session keys not available")
	}

	// Use AES-GCM encryption with session keys
	// This is a simplified implementation - in production would use crypto/aes
	sessionKeys := dc.cryptoContext.SessionKeys
	
	// Generate IV from IV seed and counter
	iv := dc.generateIV()
	
	// Encrypt using session key (simplified XOR for demo)
	encrypted := make([]byte, len(data)+len(iv)+16) // data + IV + auth tag
	copy(encrypted[:len(iv)], iv)
	
	for i, b := range data {
		encrypted[len(iv)+i] = b ^ sessionKeys.EncryptionKey[i%len(sessionKeys.EncryptionKey)] ^ iv[i%len(iv)]
	}
	
	// Add simple auth tag (in production would use proper HMAC)
	authTag := dc.generateAuthTag(encrypted[:len(iv)+len(data)])
	copy(encrypted[len(iv)+len(data):], authTag)

	return encrypted, nil
}

// decryptData decrypts data using the current session keys
func (dc *DirectConnection) decryptData(encryptedData []byte) ([]byte, error) {
	if dc.cryptoContext == nil || dc.cryptoContext.SessionKeys == nil {
		return nil, fmt.Errorf("session keys not available")
	}

	if len(encryptedData) < 16+16 { // IV + auth tag minimum
		return nil, fmt.Errorf("encrypted data too short")
	}

	sessionKeys := dc.cryptoContext.SessionKeys
	
	// Extract IV and auth tag
	iv := encryptedData[:16]
	authTag := encryptedData[len(encryptedData)-16:]
	ciphertext := encryptedData[16 : len(encryptedData)-16]
	
	// Verify auth tag
	expectedTag := dc.generateAuthTag(encryptedData[:len(encryptedData)-16])
	if !dc.constantTimeEqual(authTag, expectedTag) {
		return nil, fmt.Errorf("authentication failed")
	}
	
	// Decrypt (simplified XOR for demo)
	decrypted := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		decrypted[i] = b ^ sessionKeys.EncryptionKey[i%len(sessionKeys.EncryptionKey)] ^ iv[i%len(iv)]
	}

	return decrypted, nil
}

// generateIV generates an IV from the IV seed
func (dc *DirectConnection) generateIV() []byte {
	if dc.cryptoContext == nil || dc.cryptoContext.SessionKeys == nil {
		return make([]byte, 16) // Return zero IV if no session keys
	}

	// Simple IV generation - in production would use proper counter mode
	iv := make([]byte, 16)
	seed := dc.cryptoContext.SessionKeys.IVSeed
	timestamp := time.Now().UnixNano()
	
	for i := 0; i < 16; i++ {
		iv[i] = seed[i%len(seed)] ^ byte(timestamp>>(i*8))
	}
	
	return iv
}

// generateAuthTag generates an authentication tag
func (dc *DirectConnection) generateAuthTag(data []byte) []byte {
	if dc.cryptoContext == nil || dc.cryptoContext.SessionKeys == nil {
		return make([]byte, 16) // Return zero tag if no session keys
	}

	// Simple auth tag - in production would use proper HMAC
	tag := make([]byte, 16)
	authKey := dc.cryptoContext.SessionKeys.AuthKey
	
	for i, b := range data {
		tag[i%16] ^= b ^ authKey[i%len(authKey)]
	}
	
	return tag
}

// constantTimeEqual performs constant-time comparison
func (dc *DirectConnection) constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// isKeyExchangeMessage checks if data is a key exchange message
func (dc *DirectConnection) isKeyExchangeMessage(data []byte) bool {
	// Simple check - in production would have proper message framing
	return len(data) > 4 && data[0] == 0xCE && data[1] == 0xED // "KEY EXCHANGE" marker
}

// handleKeyExchangeMessage processes a key exchange message
func (dc *DirectConnection) handleKeyExchangeMessage(data []byte) ([]byte, error) {
	// Deserialize key exchange message
	message, err := dc.deserializeKeyExchangeMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key exchange message: %w", err)
	}

	// Process with key exchange handler
	response, err := dc.keyExchange.ProcessKeyExchangeMessage(message)
	if err != nil {
		return nil, fmt.Errorf("key exchange processing failed: %w", err)
	}

	// If there's a response, send it
	if response != nil {
		responseData, err := dc.serializeKeyExchangeMessage(response)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize response: %w", err)
		}

		if err := dc.tunnel.SendData(responseData); err != nil {
			return nil, fmt.Errorf("failed to send response: %w", err)
		}
	}

	// Update crypto context with new session keys if available
	if dc.keyExchange.IsKeyExchangeComplete() {
		sessionKeys := dc.keyExchange.GetSessionKeys()
		if sessionKeys != nil {
			if dc.cryptoContext == nil {
				dc.cryptoContext = &CryptoContext{CreatedAt: time.Now()}
			}
			dc.cryptoContext.SessionKeys = sessionKeys
		}
	}

	// Return empty data since this was a control message
	return []byte{}, nil
}

// serializeKeyExchangeMessage serializes a key exchange message
func (dc *DirectConnection) serializeKeyExchangeMessage(message *KeyExchangeMessage) ([]byte, error) {
	// Simple serialization - in production would use proper encoding
	data := make([]byte, 2) // Marker bytes
	data[0] = 0xCE // "KEY"
	data[1] = 0xED // "EXCHANGE"
	
	// Add message type
	data = append(data, byte(message.Type))
	
	// Add timestamp
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(message.Timestamp.UnixNano()))
	data = append(data, timestampBytes...)
	
	// Add sequence number
	seqBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBytes, message.SequenceNumber)
	data = append(data, seqBytes...)
	
	// Add public key if present
	if len(message.PublicKey) > 0 {
		keyLenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(keyLenBytes, uint32(len(message.PublicKey)))
		data = append(data, keyLenBytes...)
		data = append(data, message.PublicKey...)
	} else {
		data = append(data, []byte{0, 0, 0, 0}...) // Zero length
	}
	
	// Add ciphertext if present
	if len(message.Ciphertext) > 0 {
		ctLenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ctLenBytes, uint32(len(message.Ciphertext)))
		data = append(data, ctLenBytes...)
		data = append(data, message.Ciphertext...)
	} else {
		data = append(data, []byte{0, 0, 0, 0}...) // Zero length
	}
	
	// Add auth tag if present
	if len(message.AuthTag) > 0 {
		tagLenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(tagLenBytes, uint32(len(message.AuthTag)))
		data = append(data, tagLenBytes...)
		data = append(data, message.AuthTag...)
	} else {
		data = append(data, []byte{0, 0, 0, 0}...) // Zero length
	}
	
	return data, nil
}

// deserializeKeyExchangeMessage deserializes a key exchange message
func (dc *DirectConnection) deserializeKeyExchangeMessage(data []byte) (*KeyExchangeMessage, error) {
	if len(data) < 21 { // Minimum size: marker(2) + type(1) + timestamp(8) + seq(8) + lengths(2)
		return nil, fmt.Errorf("data too short for key exchange message")
	}
	
	// Check marker
	if data[0] != 0xCE || data[1] != 0xED {
		return nil, fmt.Errorf("invalid key exchange message marker")
	}
	
	offset := 2
	
	// Read message type
	msgType := KeyExchangeMessageType(data[offset])
	offset++
	
	// Read timestamp
	timestamp := time.Unix(0, int64(binary.LittleEndian.Uint64(data[offset:offset+8])))
	offset += 8
	
	// Read sequence number
	seqNum := binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	
	message := &KeyExchangeMessage{
		Type:           msgType,
		Timestamp:      timestamp,
		SequenceNumber: seqNum,
	}
	
	// Read public key
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for public key length")
	}
	keyLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	
	if keyLen > 0 {
		if offset+int(keyLen) > len(data) {
			return nil, fmt.Errorf("data too short for public key")
		}
		message.PublicKey = make([]byte, keyLen)
		copy(message.PublicKey, data[offset:offset+int(keyLen)])
		offset += int(keyLen)
	}
	
	// Read ciphertext
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for ciphertext length")
	}
	ctLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	
	if ctLen > 0 {
		if offset+int(ctLen) > len(data) {
			return nil, fmt.Errorf("data too short for ciphertext")
		}
		message.Ciphertext = make([]byte, ctLen)
		copy(message.Ciphertext, data[offset:offset+int(ctLen)])
		offset += int(ctLen)
	}
	
	// Read auth tag
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for auth tag length")
	}
	tagLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	
	if tagLen > 0 {
		if offset+int(tagLen) > len(data) {
			return nil, fmt.Errorf("data too short for auth tag")
		}
		message.AuthTag = make([]byte, tagLen)
		copy(message.AuthTag, data[offset:offset+int(tagLen)])
	}
	
	return message, nil
}

// Shutdown gracefully shuts down the DirectConnectionManager
func (dcm *DirectConnectionManagerImpl) Shutdown() error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	// Signal shutdown to all goroutines
	close(dcm.shutdownChan)

	// Close all active connections
	for connectionID, connection := range dcm.activeConnections {
		if err := connection.tunnel.Close(); err != nil {
			// Log error but continue cleanup
		}
		dcm.connectionStates[connectionID] = StateDisconnected
	}

	// Close all listeners
	for listenerKey, listener := range dcm.listeners {
		if err := listener.Close(); err != nil {
			// Log error but continue cleanup
		}
		dcm.connectionStates[listenerKey] = StateDisconnected
	}

	// Clear all maps
	dcm.activeConnections = make(map[string]*DirectConnection)
	dcm.listeners = make(map[string]net.Listener)
	dcm.invitationCodes = make(map[string]*InvitationCode)

	return nil
}

// GetConnectionState returns the current state of a connection
func (dcm *DirectConnectionManagerImpl) GetConnectionState(connectionID string) (ConnectionState, bool) {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	state, exists := dcm.connectionStates[connectionID]
	return state, exists
}

// GetAllConnectionStates returns all connection states
func (dcm *DirectConnectionManagerImpl) GetAllConnectionStates() map[string]ConnectionState {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	states := make(map[string]ConnectionState)
	for id, state := range dcm.connectionStates {
		states[id] = state
	}

	return states
}

// StopListener stops a specific listener
func (dcm *DirectConnectionManagerImpl) StopListener(protocol string, port int) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	listenerKey := fmt.Sprintf("%s:%d", protocol, port)
	
	listener, exists := dcm.listeners[listenerKey]
	if !exists {
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("listener not found on %s:%d", protocol, port), 
			"stop_listener", false)
	}

	// Close the listener
	if err := listener.Close(); err != nil {
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to close listener: %v", err), 
			"stop_listener", true)
	}

	// Remove from tracking
	delete(dcm.listeners, listenerKey)
	dcm.connectionStates[listenerKey] = StateDisconnected

	return nil
}

// GetActiveListeners returns information about active listeners
func (dcm *DirectConnectionManagerImpl) GetActiveListeners() map[string]net.Addr {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	listeners := make(map[string]net.Addr)
	for key, listener := range dcm.listeners {
		listeners[key] = listener.Addr()
	}

	return listeners
}

// Role management and handshake protocol methods

// InitiateHandshake starts the handshake protocol for role negotiation
func (dc *DirectConnection) InitiateHandshake() error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	if dc.handshakeState == nil {
		dc.handshakeState = &HandshakeState{
			State:           PhaseInit,
			LocalRole:       dc.Role,
			Priority:        GenerateRolePriority(),
			StartTime:       time.Now(),
			LastMessageTime: time.Now(),
			AttemptCount:    1,
		}
	}

	// Create handshake init message
	initMessage, err := CreateHandshakeMessage(
		HandshakeInit,
		dc.ConnectionID,
		dc.Role,
		dc.handshakeState.Priority,
	)
	if err != nil {
		return fmt.Errorf("failed to create handshake init message: %w", err)
	}

	// Serialize and send the message
	messageData, err := dc.serializeHandshakeMessage(initMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize handshake message: %w", err)
	}

	if err := dc.tunnel.SendData(messageData); err != nil {
		return fmt.Errorf("failed to send handshake init message: %w", err)
	}

	dc.handshakeState.State = PhaseRoleNegotiation
	dc.handshakeState.LastMessageTime = time.Now()

	return nil
}

// ProcessHandshakeMessage processes an incoming handshake message
func (dc *DirectConnection) ProcessHandshakeMessage(messageData []byte) (*HandshakeMessage, error) {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	// Deserialize the message
	message, err := dc.deserializeHandshakeMessage(messageData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize handshake message: %w", err)
	}

	// Validate the message
	if err := ValidateHandshakeMessage(message); err != nil {
		return nil, fmt.Errorf("invalid handshake message: %w", err)
	}

	// Initialize handshake state if not already done
	if dc.handshakeState == nil {
		dc.handshakeState = &HandshakeState{
			State:           PhaseInit,
			LocalRole:       dc.Role,
			Priority:        GenerateRolePriority(),
			StartTime:       time.Now(),
			AttemptCount:    1,
		}
	}

	dc.handshakeState.RemoteRole = message.ProposedRole
	dc.handshakeState.RemotePriority = message.Priority
	dc.handshakeState.LastMessageTime = time.Now()

	var responseMessage *HandshakeMessage

	switch message.Type {
	case HandshakeInit:
		responseMessage, err = dc.handleHandshakeInit(message)
	case HandshakeResponse:
		responseMessage, err = dc.handleHandshakeResponse(message)
	case HandshakeConfirm:
		responseMessage, err = dc.handleHandshakeConfirm(message)
	case HandshakeRoleNegotiation:
		responseMessage, err = dc.handleRoleNegotiation(message)
	case HandshakeReject:
		err = dc.handleHandshakeReject(message)
	default:
		err = fmt.Errorf("unsupported handshake message type: %s", message.Type.String())
	}

	if err != nil {
		dc.handshakeState.State = PhaseError
		return nil, err
	}

	return responseMessage, nil
}

// handleHandshakeInit processes a handshake init message
func (dc *DirectConnection) handleHandshakeInit(message *HandshakeMessage) (*HandshakeMessage, error) {
	// Check for role conflict
	conflict := DetectRoleConflict(dc.Role, message.ProposedRole)
	
	if conflict != nil {
		dc.handshakeState.ConflictResolution = conflict
		
		if conflict.AutoResolvable {
			// Attempt automatic resolution
			resolvedRole, err := ResolveRoleConflict(
				dc.Role, 
				dc.handshakeState.Priority,
				message.ProposedRole, 
				message.Priority,
			)
			if err != nil {
				// Send rejection message
				return dc.createRejectMessage(fmt.Sprintf("Role conflict resolution failed: %v", err))
			}

			// Update our role based on resolution
			dc.Role = resolvedRole
			dc.handshakeState.NegotiatedRole = resolvedRole
			dc.handshakeState.LocalRole = resolvedRole

			// Send role negotiation message
			return CreateHandshakeMessage(
				HandshakeRoleNegotiation,
				dc.ConnectionID,
				resolvedRole,
				dc.handshakeState.Priority,
			)
		} else {
			// Send rejection with guidance
			return dc.createRejectMessage(conflict.RecommendedAction)
		}
	}

	// No conflict, send response
	dc.handshakeState.State = PhaseKeyExchange
	return CreateHandshakeMessage(
		HandshakeResponse,
		dc.ConnectionID,
		dc.Role,
		dc.handshakeState.Priority,
	)
}

// handleHandshakeResponse processes a handshake response message
func (dc *DirectConnection) handleHandshakeResponse(message *HandshakeMessage) (*HandshakeMessage, error) {
	// Verify roles are compatible
	if !dc.Role.IsCompatible(message.ProposedRole) {
		return dc.createRejectMessage("Incompatible roles after negotiation")
	}

	// Move to key exchange phase
	dc.handshakeState.State = PhaseKeyExchange
	dc.handshakeState.NegotiatedRole = dc.Role

	// Send confirmation
	return CreateHandshakeMessage(
		HandshakeConfirm,
		dc.ConnectionID,
		dc.Role,
		dc.handshakeState.Priority,
	)
}

// handleHandshakeConfirm processes a handshake confirm message
func (dc *DirectConnection) handleHandshakeConfirm(message *HandshakeMessage) (*HandshakeMessage, error) {
	// Verify roles are still compatible
	if !dc.Role.IsCompatible(message.ProposedRole) {
		return dc.createRejectMessage("Role compatibility check failed")
	}

	// Complete handshake
	dc.handshakeState.State = PhaseComplete
	dc.handshakeState.NegotiatedRole = dc.Role

	return nil, nil // No response needed
}

// handleRoleNegotiation processes a role negotiation message
func (dc *DirectConnection) handleRoleNegotiation(message *HandshakeMessage) (*HandshakeMessage, error) {
	// The remote peer has resolved a role conflict and is informing us
	// We need to adjust our role to be compatible
	
	if message.ProposedRole == RoleListener {
		dc.Role = RoleConnector
	} else if message.ProposedRole == RoleConnector {
		dc.Role = RoleListener
	} else {
		return dc.createRejectMessage("Invalid role in negotiation message")
	}

	dc.handshakeState.LocalRole = dc.Role
	dc.handshakeState.NegotiatedRole = dc.Role
	dc.handshakeState.State = PhaseKeyExchange

	// Send confirmation of role change
	return CreateHandshakeMessage(
		HandshakeResponse,
		dc.ConnectionID,
		dc.Role,
		dc.handshakeState.Priority,
	)
}

// handleHandshakeReject processes a handshake reject message
func (dc *DirectConnection) handleHandshakeReject(message *HandshakeMessage) error {
	dc.handshakeState.State = PhaseError
	
	// Extract rejection reason from capabilities field (used as error message)
	var reason string
	if len(message.Capabilities) > 0 {
		reason = message.Capabilities[0]
	} else {
		reason = "Handshake rejected by remote peer"
	}

	return fmt.Errorf("handshake rejected: %s", reason)
}

// createRejectMessage creates a handshake reject message
func (dc *DirectConnection) createRejectMessage(reason string) (*HandshakeMessage, error) {
	message, err := CreateHandshakeMessage(
		HandshakeReject,
		dc.ConnectionID,
		dc.Role,
		dc.handshakeState.Priority,
	)
	if err != nil {
		return nil, err
	}

	// Use capabilities field to carry rejection reason
	message.Capabilities = []string{reason}
	
	return message, nil
}

// IsHandshakeComplete checks if the handshake is complete
func (dc *DirectConnection) IsHandshakeComplete() bool {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	return dc.handshakeState != nil && dc.handshakeState.State == PhaseComplete
}

// GetHandshakeState returns the current handshake state
func (dc *DirectConnection) GetHandshakeState() *HandshakeState {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	if dc.handshakeState == nil {
		return nil
	}

	// Return a copy to prevent external modification
	stateCopy := *dc.handshakeState
	if dc.handshakeState.ConflictResolution != nil {
		resolutionCopy := *dc.handshakeState.ConflictResolution
		stateCopy.ConflictResolution = &resolutionCopy
	}

	return &stateCopy
}

// GetRoleConflictGuidance provides guidance for resolving role conflicts
func (dc *DirectConnection) GetRoleConflictGuidance() *RoleConflictResolution {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	if dc.handshakeState == nil || dc.handshakeState.ConflictResolution == nil {
		return nil
	}

	// Return a copy
	resolutionCopy := *dc.handshakeState.ConflictResolution
	return &resolutionCopy
}

// serializeHandshakeMessage serializes a handshake message to bytes
func (dc *DirectConnection) serializeHandshakeMessage(message *HandshakeMessage) ([]byte, error) {
	// Use JSON serialization for handshake messages
	data, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal handshake message: %w", err)
	}

	// Add message type prefix for identification
	prefix := []byte("HANDSHAKE:")
	result := make([]byte, len(prefix)+len(data))
	copy(result, prefix)
	copy(result[len(prefix):], data)

	return result, nil
}

// deserializeHandshakeMessage deserializes bytes to a handshake message
func (dc *DirectConnection) deserializeHandshakeMessage(data []byte) (*HandshakeMessage, error) {
	// Check for handshake message prefix
	prefix := []byte("HANDSHAKE:")
	if len(data) < len(prefix) || !bytes.Equal(data[:len(prefix)], prefix) {
		return nil, fmt.Errorf("invalid handshake message format")
	}

	// Extract JSON data
	jsonData := data[len(prefix):]

	var message HandshakeMessage
	if err := json.Unmarshal(jsonData, &message); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake message: %w", err)
	}

	return &message, nil
}

// isHandshakeMessage checks if the received data is a handshake message
func (dc *DirectConnection) isHandshakeMessage(data []byte) bool {
	prefix := []byte("HANDSHAKE:")
	return len(data) >= len(prefix) && bytes.Equal(data[:len(prefix)], prefix)
}

// Enhanced listener role implementation

// StartEnhancedListener starts an enhanced listener with role management
func (dcm *DirectConnectionManagerImpl) StartEnhancedListener(config *ListenerConfig) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	// Validate listener configuration
	if err := dcm.validateListenerConfig(config); err != nil {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			fmt.Sprintf("invalid listener configuration: %v", err), 
			"start_enhanced_listener")
	}

	// Create listener key for tracking
	listenerKey := fmt.Sprintf("%s:%d", config.Protocol, config.Port)
	
	// Check if listener already exists
	if _, exists := dcm.listeners[listenerKey]; exists {
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("listener already exists on %s:%d", config.Protocol, config.Port), 
			"start_enhanced_listener", false)
	}

	// Determine bind address
	bindAddr := fmt.Sprintf(":%d", config.Port)
	if config.Address != "" {
		bindAddr = fmt.Sprintf("%s:%d", config.Address, config.Port)
	}

	// Create listener with enhanced error handling
	listener, err := dcm.createEnhancedListener(config.Protocol, bindAddr)
	if err != nil {
		return NewConnectionError(ErrCodeConnectionFailed, 
			fmt.Sprintf("failed to create enhanced listener: %v", err), 
			"start_enhanced_listener", true)
	}

	// Store listener
	dcm.listeners[listenerKey] = listener
	dcm.connectionStates[listenerKey] = StateListening

	// Start enhanced accept loop
	go dcm.enhancedAcceptLoop(listenerKey, listener, config)

	return nil
}

// validateListenerConfig validates listener configuration
func (dcm *DirectConnectionManagerImpl) validateListenerConfig(config *ListenerConfig) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", config.Port)
	}

	if config.Protocol != "tcp" && config.Protocol != "udp" {
		return fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	// Validate bind address if specified
	if config.Address != "" {
		if net.ParseIP(config.Address) == nil {
			return fmt.Errorf("invalid bind address: %s", config.Address)
		}
	}

	return nil
}

// createEnhancedListener creates a listener with enhanced capabilities
func (dcm *DirectConnectionManagerImpl) createEnhancedListener(protocol, bindAddr string) (net.Listener, error) {
	switch protocol {
	case "tcp":
		// Create TCP listener with enhanced options
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				// Set socket options for better performance and reliability
				return c.Control(func(fd uintptr) {
					// Enable SO_REUSEADDR to allow quick restart
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
					// Set TCP_NODELAY for low latency
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
				})
			},
		}
		return lc.Listen(context.Background(), "tcp", bindAddr)

	case "udp":
		// Create UDP listener with enhanced capabilities
		udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
		}
		
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP listener: %w", err)
		}
		
		// Set buffer sizes for better performance
		udpConn.SetReadBuffer(64 * 1024)  // 64KB read buffer
		udpConn.SetWriteBuffer(64 * 1024) // 64KB write buffer
		
		return &enhancedUDPListener{conn: udpConn}, nil

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// enhancedAcceptLoop handles incoming connections with role management
func (dcm *DirectConnectionManagerImpl) enhancedAcceptLoop(listenerKey string, listener net.Listener, config *ListenerConfig) {
	defer func() {
		dcm.mutex.Lock()
		delete(dcm.listeners, listenerKey)
		delete(dcm.connectionStates, listenerKey)
		dcm.mutex.Unlock()
		listener.Close()
	}()

	for {
		select {
		case <-dcm.shutdownChan:
			return
		default:
			// Set accept timeout to allow periodic shutdown checks
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				// Check if this is a timeout error
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Continue loop to check for shutdown
				}

				// Check if we're shutting down
				select {
				case <-dcm.shutdownChan:
					return
				default:
					// Log error and continue
					time.Sleep(100 * time.Millisecond) // Brief pause before retry
					continue
				}
			}

			// Handle connection with role management
			go dcm.handleEnhancedIncomingConnection(conn, config)
		}
	}
}

// handleEnhancedIncomingConnection processes incoming connections with handshake
func (dcm *DirectConnectionManagerImpl) handleEnhancedIncomingConnection(conn net.Conn, config *ListenerConfig) {
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Generate connection ID
	connectionID, err := GenerateConnectionID()
	if err != nil {
		return
	}

	connectionIDStr := hex.EncodeToString(connectionID[:])

	// Initialize key exchange
	keyExchange, err := NewPostQuantumKeyExchange()
	if err != nil {
		return
	}

	// Create DirectConnection with handshake support
	directConn := &DirectConnection{
		ConnectionID:  connectionID,
		Role:         RoleListener,
		State:        "listening",
		RemoteAddress: conn.RemoteAddr().String(),
		tunnel:       &simpleTunnel{conn: conn},
		keyExchange:  keyExchange,
		networkConfig: &NetworkConfig{
			Protocol:        config.Protocol,
			ListenerAddress: conn.LocalAddr().String(),
		},
		handshakeState: &HandshakeState{
			State:           PhaseInit,
			LocalRole:       RoleListener,
			Priority:        GenerateRolePriority(),
			StartTime:       time.Now(),
			AttemptCount:    1,
		},
		LastActivity: time.Now(),
		ConnectedAt:  time.Now(),
		isActive:     false,
		trafficStats: &TrafficStats{
			LastActivity: time.Now(),
		},
	}

	// Store connection
	dcm.mutex.Lock()
	dcm.activeConnections[connectionIDStr] = directConn
	dcm.connectionStates[connectionIDStr] = StateConnecting
	dcm.mutex.Unlock()

	// Perform enhanced handshake
	if err := dcm.performEnhancedHandshake(directConn); err != nil {
		dcm.cleanupConnection(connectionIDStr, directConn)
		return
	}

	// Establish connection after successful handshake
	if err := directConn.Establish(); err != nil {
		dcm.cleanupConnection(connectionIDStr, directConn)
		return
	}

	// Update connection state
	dcm.mutex.Lock()
	dcm.connectionStates[connectionIDStr] = StateConnected
	dcm.mutex.Unlock()

	// Start connection monitoring
	go dcm.monitorConnection(connectionIDStr, directConn)

	// Handle connection data
	dcm.handleConnectionData(directConn)

	// Cleanup when done
	dcm.cleanupConnection(connectionIDStr, directConn)
}

// performEnhancedHandshake performs handshake with role negotiation
func (dcm *DirectConnectionManagerImpl) performEnhancedHandshake(directConn *DirectConnection) error {
	// Wait for handshake init message
	data, err := directConn.tunnel.ReceiveData()
	if err != nil {
		return fmt.Errorf("failed to receive handshake init: %w", err)
	}

	// Check if this is a handshake message
	if !directConn.isHandshakeMessage(data) {
		return fmt.Errorf("expected handshake message, got regular data")
	}

	// Process handshake message
	responseMessage, err := directConn.ProcessHandshakeMessage(data)
	if err != nil {
		return fmt.Errorf("handshake processing failed: %w", err)
	}

	// Send response if needed
	if responseMessage != nil {
		responseData, err := directConn.serializeHandshakeMessage(responseMessage)
		if err != nil {
			return fmt.Errorf("failed to serialize handshake response: %w", err)
		}

		if err := directConn.tunnel.SendData(responseData); err != nil {
			return fmt.Errorf("failed to send handshake response: %w", err)
		}
	}

	// Continue handshake until complete
	for !directConn.IsHandshakeComplete() {
		// Set timeout for handshake completion
		if time.Since(directConn.handshakeState.StartTime) > 30*time.Second {
			return fmt.Errorf("handshake timeout")
		}

		// Wait for next message
		data, err := directConn.tunnel.ReceiveData()
		if err != nil {
			return fmt.Errorf("handshake communication error: %w", err)
		}

		if directConn.isHandshakeMessage(data) {
			responseMessage, err := directConn.ProcessHandshakeMessage(data)
			if err != nil {
				return fmt.Errorf("handshake processing error: %w", err)
			}

			if responseMessage != nil {
				responseData, err := directConn.serializeHandshakeMessage(responseMessage)
				if err != nil {
					return fmt.Errorf("failed to serialize handshake message: %w", err)
				}

				if err := directConn.tunnel.SendData(responseData); err != nil {
					return fmt.Errorf("failed to send handshake message: %w", err)
				}
			}
		}
	}

	return nil
}

// cleanupConnection cleans up a connection and removes it from tracking
func (dcm *DirectConnectionManagerImpl) cleanupConnection(connectionID string, directConn *DirectConnection) {
	if directConn != nil {
		directConn.Disconnect()
	}

	dcm.mutex.Lock()
	delete(dcm.activeConnections, connectionID)
	delete(dcm.connectionStates, connectionID)
	dcm.mutex.Unlock()
}

// handleConnectionData handles ongoing data communication
func (dcm *DirectConnectionManagerImpl) handleConnectionData(directConn *DirectConnection) {
	for directConn.IsHealthy() {
		// Set read timeout
		if tunnel, ok := directConn.tunnel.(*simpleTunnel); ok {
			tunnel.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		}

		// Receive data
		_, err := directConn.ReceiveData()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout is expected, continue monitoring
			}
			break // Other errors indicate connection failure
		}

		// Update activity timestamp
		directConn.mutex.Lock()
		directConn.LastActivity = time.Now()
		directConn.trafficStats.LastActivity = time.Now()
		directConn.mutex.Unlock()
	}
}

// enhancedUDPListener provides enhanced UDP listener capabilities
type enhancedUDPListener struct {
	conn   *net.UDPConn
	closed bool
	mutex  sync.Mutex
}

func (eul *enhancedUDPListener) Accept() (net.Conn, error) {
	eul.mutex.Lock()
	defer eul.mutex.Unlock()

	if eul.closed {
		return nil, fmt.Errorf("listener closed")
	}

	// Read first packet to establish "connection"
	buffer := make([]byte, 1500) // MTU size
	n, addr, err := eul.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	// Create enhanced UDP connection
	return &enhancedUDPConn{
		conn:       eul.conn,
		remoteAddr: addr,
		buffer:     buffer[:n],
		readBuffer: make([]byte, 64*1024),
	}, nil
}

func (eul *enhancedUDPListener) Close() error {
	eul.mutex.Lock()
	defer eul.mutex.Unlock()

	if eul.closed {
		return nil
	}

	eul.closed = true
	return eul.conn.Close()
}

func (eul *enhancedUDPListener) Addr() net.Addr {
	return eul.conn.LocalAddr()
}

// enhancedUDPConn provides enhanced UDP connection capabilities
type enhancedUDPConn struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	buffer     []byte
	readBuffer []byte
	closed     bool
	mutex      sync.Mutex
}

func (euc *enhancedUDPConn) Read(b []byte) (int, error) {
	euc.mutex.Lock()
	defer euc.mutex.Unlock()

	if euc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	// Return buffered data first
	if len(euc.buffer) > 0 {
		n := copy(b, euc.buffer)
		euc.buffer = euc.buffer[n:]
		return n, nil
	}

	// Read from UDP connection
	for {
		n, addr, err := euc.conn.ReadFromUDP(euc.readBuffer)
		if err != nil {
			return 0, err
		}

		// Filter for our remote address
		if addr.String() == euc.remoteAddr.String() {
			return copy(b, euc.readBuffer[:n]), nil
		}
	}
}

func (euc *enhancedUDPConn) Write(b []byte) (int, error) {
	euc.mutex.Lock()
	defer euc.mutex.Unlock()

	if euc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	return euc.conn.WriteToUDP(b, euc.remoteAddr)
}

func (euc *enhancedUDPConn) Close() error {
	euc.mutex.Lock()
	defer euc.mutex.Unlock()

	euc.closed = true
	return nil
}

func (euc *enhancedUDPConn) LocalAddr() net.Addr {
	return euc.conn.LocalAddr()
}

func (euc *enhancedUDPConn) RemoteAddr() net.Addr {
	return euc.remoteAddr
}

func (euc *enhancedUDPConn) SetDeadline(t time.Time) error {
	return euc.conn.SetDeadline(t)
}

func (euc *enhancedUDPConn) SetReadDeadline(t time.Time) error {
	return euc.conn.SetReadDeadline(t)
}

func (euc *enhancedUDPConn) SetWriteDeadline(t time.Time) error {
	return euc.conn.SetWriteDeadline(t)
}

// Enhanced connector role methods

// establishEnhancedNetworkConnection creates an enhanced network connection with retry logic
func (dcm *DirectConnectionManagerImpl) establishEnhancedNetworkConnection(networkConfig *NetworkConfig) (net.Conn, error) {
	var lastErr error
	maxRetries := 3
	baseDelay := 1 * time.Second

	// Try primary address first
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Apply exponential backoff with secure jitter
			delay := time.Duration(attempt) * baseDelay
			jitter := generateSecureJitter(delay / 2)
			time.Sleep(delay + jitter)
		}

		conn, err := dcm.dialWithTimeout(networkConfig.Protocol, networkConfig.ListenerAddress, 30*time.Second)
		if err == nil {
			return dcm.configureConnection(conn, networkConfig.Protocol)
		}
		lastErr = err
	}

	// If primary address fails, try backup addresses
	for _, backupAddr := range networkConfig.BackupAddresses {
		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				delay := time.Duration(attempt) * baseDelay
				jitter := generateSecureJitter(delay / 2)
				time.Sleep(delay + jitter)
			}

			conn, err := dcm.dialWithTimeout(networkConfig.Protocol, backupAddr, 30*time.Second)
			if err == nil {
				return dcm.configureConnection(conn, networkConfig.Protocol)
			}
			lastErr = err
		}
	}

	return nil, fmt.Errorf("failed to connect to any address after retries: %v", lastErr)
}

// generateSecureJitter generates cryptographically secure jitter for retry delays
func generateSecureJitter(maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return 0
	}
	
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback to no jitter on error
		return 0
	}
	
	randValue := binary.LittleEndian.Uint64(randBytes)
	return time.Duration(randValue % uint64(maxJitter))
}

// dialWithTimeout creates a connection with timeout
func (dcm *DirectConnectionManagerImpl) dialWithTimeout(protocol, address string, timeout time.Duration) (net.Conn, error) {
	switch protocol {
	case "tcp":
		return net.DialTimeout("tcp", address, timeout)
	case "udp":
		return net.DialTimeout("udp", address, timeout)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// configureConnection applies optimal settings to a connection
func (dcm *DirectConnectionManagerImpl) configureConnection(conn net.Conn, protocol string) (net.Conn, error) {
	switch protocol {
	case "tcp":
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			// Enable TCP_NODELAY for low latency
			tcpConn.SetNoDelay(true)
			// Set keep-alive
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	case "udp":
		// UDP connections don't need special configuration
		// but we could set buffer sizes if needed
	}

	return conn, nil
}

// completeConnectorHandshake completes the handshake process for connector role
func (dcm *DirectConnectionManagerImpl) completeConnectorHandshake(directConn *DirectConnection) error {
	// Wait for handshake responses
	for !directConn.IsHandshakeComplete() {
		// Check for timeout
		if time.Since(directConn.handshakeState.StartTime) > 30*time.Second {
			return fmt.Errorf("handshake timeout")
		}

		// Wait for response
		data, err := directConn.tunnel.ReceiveData()
		if err != nil {
			return fmt.Errorf("failed to receive handshake response: %w", err)
		}

		// Process handshake message if it's a handshake message
		if directConn.isHandshakeMessage(data) {
			responseMessage, err := directConn.ProcessHandshakeMessage(data)
			if err != nil {
				return fmt.Errorf("handshake processing failed: %w", err)
			}

			// Send response if needed
			if responseMessage != nil {
				responseData, err := directConn.serializeHandshakeMessage(responseMessage)
				if err != nil {
					return fmt.Errorf("failed to serialize handshake response: %w", err)
				}

				if err := directConn.tunnel.SendData(responseData); err != nil {
					return fmt.Errorf("failed to send handshake response: %w", err)
				}
			}
		}
	}

	// Verify final role assignment
	handshakeState := directConn.GetHandshakeState()
	if handshakeState == nil {
		return fmt.Errorf("handshake state not available")
	}

	// Check if role conflict was resolved
	if handshakeState.ConflictResolution != nil {
		if !handshakeState.ConflictResolution.AutoResolvable {
			return fmt.Errorf("unresolvable role conflict: %s", handshakeState.ConflictResolution.RecommendedAction)
		}
	}

	return nil
}

// Role conflict detection and guidance methods

// DetectAndResolveRoleConflicts detects role conflicts across all active connections
func (dcm *DirectConnectionManagerImpl) DetectAndResolveRoleConflicts() ([]*RoleConflictResolution, error) {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	var conflicts []*RoleConflictResolution

	// Check for conflicts between active connections
	connections := make([]*DirectConnection, 0, len(dcm.activeConnections))
	for _, conn := range dcm.activeConnections {
		connections = append(connections, conn)
	}

	// Check each pair of connections for conflicts
	for i := 0; i < len(connections); i++ {
		for j := i + 1; j < len(connections); j++ {
			conn1 := connections[i]
			conn2 := connections[j]

			if conflict := DetectRoleConflict(conn1.role, conn2.role); conflict != nil {
				conflicts = append(conflicts, conflict)
			}
		}
	}

	return conflicts, nil
}

// GetRoleConflictGuidanceForConnection provides guidance for a specific connection
func (dcm *DirectConnectionManagerImpl) GetRoleConflictGuidanceForConnection(connectionID string) (*RoleConflictResolution, error) {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	connection, exists := dcm.activeConnections[connectionID]
	if !exists {
		return nil, NewConnectionError(ErrCodeConnectionFailed, 
			"connection not found", 
			"get_role_conflict_guidance", false)
	}

	return connection.GetRoleConflictGuidance(), nil
}

// ResolveRoleConflictForConnection attempts to resolve a role conflict for a specific connection
func (dcm *DirectConnectionManagerImpl) ResolveRoleConflictForConnection(connectionID string, preferredRole ConnectionRole) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	connection, exists := dcm.activeConnections[connectionID]
	if !exists {
		return NewConnectionError(ErrCodeConnectionFailed, 
			"connection not found", 
			"resolve_role_conflict", false)
	}

	// Check if the connection has a role conflict
	guidance := connection.GetRoleConflictGuidance()
	if guidance == nil {
		return nil // No conflict to resolve
	}

	if !guidance.AutoResolvable {
		return fmt.Errorf("role conflict cannot be automatically resolved: %s", guidance.RecommendedAction)
	}

	// Update the connection's role
	connection.mutex.Lock()
	oldRole := connection.Role
	connection.Role = preferredRole
	if connection.handshakeState != nil {
		connection.handshakeState.LocalRole = preferredRole
		connection.handshakeState.NegotiatedRole = preferredRole
	}
	connection.mutex.Unlock()

	// If the connection is active, we may need to renegotiate
	if connection.isActive {
		// Send role negotiation message to peer
		if connection.handshakeState != nil {
			negotiationMessage, err := CreateHandshakeMessage(
				HandshakeRoleNegotiation,
				connection.connectionID,
				preferredRole,
				connection.handshakeState.Priority,
			)
			if err != nil {
				// Revert role change
				connection.mutex.Lock()
				connection.Role = oldRole
				connection.mutex.Unlock()
				return fmt.Errorf("failed to create role negotiation message: %w", err)
			}

			messageData, err := connection.serializeHandshakeMessage(negotiationMessage)
			if err != nil {
				// Revert role change
				connection.mutex.Lock()
				connection.Role = oldRole
				connection.mutex.Unlock()
				return fmt.Errorf("failed to serialize role negotiation message: %w", err)
			}

			if err := connection.tunnel.SendData(messageData); err != nil {
				// Revert role change
				connection.mutex.Lock()
				connection.Role = oldRole
				connection.mutex.Unlock()
				return fmt.Errorf("failed to send role negotiation message: %w", err)
			}
		}
	}

	return nil
}
