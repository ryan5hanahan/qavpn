package direct

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewDirectConnectionManager(t *testing.T) {
	config := &DirectConfig{
		ListenerPort:      8080,
		Protocol:          "tcp",
		MaxConnections:    10,
		KeepAliveInterval: 30 * time.Second,
		ConnectionTimeout: 60 * time.Second,
		EnableOPSEC:       true,
	}

	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	if impl.config != config {
		t.Error("Config not set correctly")
	}

	if impl.invitationCodes == nil {
		t.Error("Invitation codes map not initialized")
	}

	if impl.activeConnections == nil {
		t.Error("Active connections map not initialized")
	}

	if impl.connectionStates == nil {
		t.Error("Connection states map not initialized")
	}

	if impl.listeners == nil {
		t.Error("Listeners map not initialized")
	}

	if impl.shutdownChan == nil {
		t.Error("Shutdown channel not initialized")
	}
}

func TestStartListener_TCP(t *testing.T) {
	config := &DirectConfig{
		ListenerPort:      0, // Use any available port
		Protocol:          "tcp",
		MaxConnections:    10,
		KeepAliveInterval: 30 * time.Second,
		ConnectionTimeout: 60 * time.Second,
		EnableOPSEC:       true,
	}

	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Find an available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	listenerConfig := &ListenerConfig{
		Port:     port,
		Protocol: "tcp",
	}

	err = dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}

	// Verify listener is tracked
	listenerKey := fmt.Sprintf("tcp:%d", port)
	if _, exists := impl.listeners[listenerKey]; !exists {
		t.Error("Listener not tracked in listeners map")
	}

	// Verify connection state
	if state, exists := impl.connectionStates[listenerKey]; !exists || state != StateListening {
		t.Errorf("Expected state %v, got %v", StateListening, state)
	}

	// Clean up
	dcm.(*DirectConnectionManagerImpl).Shutdown()
}

func TestStartListener_UDP(t *testing.T) {
	config := &DirectConfig{
		ListenerPort:      0,
		Protocol:          "udp",
		MaxConnections:    10,
		KeepAliveInterval: 30 * time.Second,
		ConnectionTimeout: 60 * time.Second,
		EnableOPSEC:       true,
	}

	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Find an available port
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to find available UDP port: %v", err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	udpConn.Close()

	listenerConfig := &ListenerConfig{
		Port:     port,
		Protocol: "udp",
	}

	err = dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start UDP listener: %v", err)
	}

	// Verify listener is tracked
	listenerKey := fmt.Sprintf("udp:%d", port)
	if _, exists := impl.listeners[listenerKey]; !exists {
		t.Error("UDP listener not tracked in listeners map")
	}

	// Verify connection state
	if state, exists := impl.connectionStates[listenerKey]; !exists || state != StateListening {
		t.Errorf("Expected state %v, got %v", StateListening, state)
	}

	// Clean up
	dcm.(*DirectConnectionManagerImpl).Shutdown()
}

func TestStartListener_InvalidConfig(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)

	tests := []struct {
		name           string
		listenerConfig *ListenerConfig
		expectError    bool
	}{
		{
			name: "Invalid port - too low",
			listenerConfig: &ListenerConfig{
				Port:     0,
				Protocol: "tcp",
			},
			expectError: true,
		},
		{
			name: "Invalid port - too high",
			listenerConfig: &ListenerConfig{
				Port:     70000,
				Protocol: "tcp",
			},
			expectError: true,
		},
		{
			name: "Invalid protocol",
			listenerConfig: &ListenerConfig{
				Port:     8080,
				Protocol: "invalid",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dcm.StartListener(tt.listenerConfig)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGenerateInvitation(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)

	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: "127.0.0.1:8080",
		BackupAddresses: []string{"127.0.0.1:8081"},
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	if invitation == nil {
		t.Fatal("Generated invitation is nil")
	}

	if invitation.Version != 1 {
		t.Errorf("Expected version 1, got %d", invitation.Version)
	}

	if len(invitation.PublicKey) != 1568 {
		t.Errorf("Expected public key length 1568, got %d", len(invitation.PublicKey))
	}

	if invitation.NetworkConfig.Protocol != "tcp" {
		t.Errorf("Expected protocol tcp, got %s", invitation.NetworkConfig.Protocol)
	}

	if invitation.NetworkConfig.ListenerAddress != "127.0.0.1:8080" {
		t.Errorf("Expected listener address 127.0.0.1:8080, got %s", invitation.NetworkConfig.ListenerAddress)
	}

	if !invitation.SingleUse {
		t.Error("Expected single use to be true")
	}

	if len(invitation.Signature) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(invitation.Signature))
	}
}

func TestValidateInvitation(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)

	// Generate a valid invitation first
	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: "127.0.0.1:8080",
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	validInvitation, err := dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate valid invitation: %v", err)
	}

	tests := []struct {
		name        string
		invitation  *InvitationCode
		expectError bool
	}{
		{
			name:        "Valid invitation",
			invitation:  validInvitation,
			expectError: false,
		},
		{
			name:        "Nil invitation",
			invitation:  nil,
			expectError: true,
		},
		{
			name: "Invalid version",
			invitation: &InvitationCode{
				Version:        2,
				NetworkConfig:  validInvitation.NetworkConfig,
				PublicKey:      validInvitation.PublicKey,
				ExpirationTime: time.Now().Add(1 * time.Hour),
			},
			expectError: true,
		},
		{
			name: "Expired invitation",
			invitation: &InvitationCode{
				Version:        1,
				NetworkConfig:  validInvitation.NetworkConfig,
				PublicKey:      validInvitation.PublicKey,
				ExpirationTime: time.Now().Add(-1 * time.Hour),
			},
			expectError: true,
		},
		{
			name: "Missing network config",
			invitation: &InvitationCode{
				Version:        1,
				NetworkConfig:  nil,
				PublicKey:      validInvitation.PublicKey,
				ExpirationTime: time.Now().Add(1 * time.Hour),
			},
			expectError: true,
		},
		{
			name: "Missing public key",
			invitation: &InvitationCode{
				Version:        1,
				NetworkConfig:  validInvitation.NetworkConfig,
				PublicKey:      nil,
				ExpirationTime: time.Now().Add(1 * time.Hour),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dcm.ValidateInvitation(tt.invitation)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestConnectionStateManagement(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Test initial state
	states := dcm.(*DirectConnectionManagerImpl).GetAllConnectionStates()
	if len(states) != 0 {
		t.Error("Expected no initial connection states")
	}

	// Add some states manually for testing
	testConnectionID := "test-connection-1"
	impl.mutex.Lock()
	impl.connectionStates[testConnectionID] = StateConnecting
	impl.mutex.Unlock()

	// Test GetConnectionState
	state, exists := dcm.(*DirectConnectionManagerImpl).GetConnectionState(testConnectionID)
	if !exists {
		t.Error("Expected connection state to exist")
	}
	if state != StateConnecting {
		t.Errorf("Expected state %v, got %v", StateConnecting, state)
	}

	// Test GetAllConnectionStates
	states = dcm.(*DirectConnectionManagerImpl).GetAllConnectionStates()
	if len(states) != 1 {
		t.Errorf("Expected 1 connection state, got %d", len(states))
	}
	if states[testConnectionID] != StateConnecting {
		t.Errorf("Expected state %v, got %v", StateConnecting, states[testConnectionID])
	}
}

func TestShutdown(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Start a listener to test shutdown
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	listenerConfig := &ListenerConfig{
		Port:     port,
		Protocol: "tcp",
	}

	err = dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Verify listener exists
	listenerKey := fmt.Sprintf("tcp:%d", port)
	if _, exists := impl.listeners[listenerKey]; !exists {
		t.Error("Listener should exist before shutdown")
	}

	// Shutdown
	err = impl.Shutdown()
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Verify cleanup
	if len(impl.listeners) != 0 {
		t.Error("Listeners should be cleared after shutdown")
	}
	if len(impl.activeConnections) != 0 {
		t.Error("Active connections should be cleared after shutdown")
	}
	if len(impl.invitationCodes) != 0 {
		t.Error("Invitation codes should be cleared after shutdown")
	}
}

func TestStopListener(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Start a listener
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	listenerConfig := &ListenerConfig{
		Port:     port,
		Protocol: "tcp",
	}

	err = dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Verify listener exists
	listenerKey := fmt.Sprintf("tcp:%d", port)
	if _, exists := impl.listeners[listenerKey]; !exists {
		t.Error("Listener should exist before stopping")
	}

	// Stop the listener
	err = impl.StopListener("tcp", port)
	if err != nil {
		t.Errorf("Failed to stop listener: %v", err)
	}

	// Verify listener is removed
	if _, exists := impl.listeners[listenerKey]; exists {
		t.Error("Listener should be removed after stopping")
	}

	// Test stopping non-existent listener
	err = impl.StopListener("tcp", port+1)
	if err == nil {
		t.Error("Expected error when stopping non-existent listener")
	}
}

func TestGetActiveListeners(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Initially no listeners
	listeners := impl.GetActiveListeners()
	if len(listeners) != 0 {
		t.Error("Expected no active listeners initially")
	}

	// Start a listener
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	listenerConfig := &ListenerConfig{
		Port:     port,
		Protocol: "tcp",
	}

	err = dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Check active listeners
	listeners = impl.GetActiveListeners()
	if len(listeners) != 1 {
		t.Errorf("Expected 1 active listener, got %d", len(listeners))
	}

	listenerKey := fmt.Sprintf("tcp:%d", port)
	if _, exists := listeners[listenerKey]; !exists {
		t.Error("Expected listener key to exist in active listeners")
	}

	// Clean up
	impl.Shutdown()
}

func TestConnectionStateString(t *testing.T) {
	tests := []struct {
		state    ConnectionState
		expected string
	}{
		{StateIdle, "idle"},
		{StateInviting, "inviting"},
		{StateConnecting, "connecting"},
		{StateListening, "listening"},
		{StateConnected, "connected"},
		{StateDisconnected, "disconnected"},
		{StateError, "error"},
		{ConnectionState(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.state.String() != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.state.String())
			}
		})
	}
}

// Test concurrent access to ensure thread safety
func TestConcurrentAccess(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	var wg sync.WaitGroup
	numGoroutines := 10

	// Test concurrent state access
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			connectionID := fmt.Sprintf("test-connection-%d", id)
			
			// Set state
			impl.mutex.Lock()
			impl.connectionStates[connectionID] = StateConnecting
			impl.mutex.Unlock()
			
			// Get state
			state, exists := impl.GetConnectionState(connectionID)
			if !exists || state != StateConnecting {
				t.Errorf("Concurrent access failed for connection %s", connectionID)
			}
			
			// Get all states
			states := impl.GetAllConnectionStates()
			if len(states) == 0 {
				t.Error("Expected some connection states")
			}
		}(i)
	}

	wg.Wait()
}

func TestConnectToPeer_Integration(t *testing.T) {
	// This test requires two DirectConnectionManager instances
	// One acting as listener, one as connector

	config := &DirectConfig{
		ListenerPort:      0,
		Protocol:          "tcp",
		MaxConnections:    10,
		KeepAliveInterval: 30 * time.Second,
		ConnectionTimeout: 60 * time.Second,
		EnableOPSEC:       true,
	}

	// Create listener instance
	listenerDCM := NewDirectConnectionManager(config)
	defer listenerDCM.(*DirectConnectionManagerImpl).Shutdown()

	// Find an available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     port,
		Protocol: "tcp",
	}

	err = listenerDCM.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Give listener time to start
	time.Sleep(100 * time.Millisecond)

	// Create connector instance
	connectorDCM := NewDirectConnectionManager(config)
	defer connectorDCM.(*DirectConnectionManagerImpl).Shutdown()

	// Generate invitation
	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: fmt.Sprintf("127.0.0.1:%d", port),
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := listenerDCM.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	// Connect to peer
	err = connectorDCM.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect to peer: %v", err)
	}

	// Give connection time to establish
	time.Sleep(200 * time.Millisecond)

	// Verify connection exists on connector side
	connections := connectorDCM.GetActiveConnections()
	if len(connections) != 1 {
		t.Errorf("Expected 1 active connection on connector, got %d", len(connections))
	}

	if len(connections) > 0 {
		if connections[0].role != RoleConnector {
			t.Errorf("Expected connector role, got %v", connections[0].role)
		}
	}

	// Verify connection state
	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)
	state, exists := connectorDCM.(*DirectConnectionManagerImpl).GetConnectionState(connectionID)
	if !exists {
		t.Error("Connection state should exist")
	}
	if state != StateConnected {
		t.Errorf("Expected state %v, got %v", StateConnected, state)
	}
}

func TestEstablishNetworkConnection(t *testing.T) {
	config := &DirectConfig{}
	dcm := NewDirectConnectionManager(config)
	impl := dcm.(*DirectConnectionManagerImpl)

	// Start a test server
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Test successful connection
	networkConfig := &NetworkConfig{
		Protocol:        "tcp",
		ListenerAddress: fmt.Sprintf("127.0.0.1:%d", port),
	}

	conn, err := impl.establishNetworkConnection(networkConfig)
	if err != nil {
		t.Fatalf("Failed to establish connection: %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Error("Connection should not be nil")
	}

	// Test connection to non-existent address
	networkConfig.ListenerAddress = "127.0.0.1:99999"
	conn, err = impl.establishNetworkConnection(networkConfig)
	if err == nil {
		t.Error("Expected error for non-existent address")
		if conn != nil {
			conn.Close()
		}
	}

	// Test with backup addresses
	networkConfig.ListenerAddress = "127.0.0.1:99999" // This will fail
	networkConfig.BackupAddresses = []string{fmt.Sprintf("127.0.0.1:%d", port)} // This should work

	conn, err = impl.establishNetworkConnection(networkConfig)
	if err != nil {
		t.Fatalf("Failed to establish connection with backup address: %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Error("Connection should not be nil")
	}
}

func TestSimpleTunnel(t *testing.T) {
	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tunnel := &simpleTunnel{conn: client}

	// Test IsActive
	if !tunnel.IsActive() {
		t.Error("Tunnel should be active initially")
	}

	// Test SendData and reading from server side
	testData := []byte("Hello, World!")
	
	// Use a channel to synchronize the read operation
	readDone := make(chan bool)
	var readErr error
	var receivedData string

	go func() {
		buffer := make([]byte, 1024)
		n, err := server.Read(buffer)
		readErr = err
		if err == nil {
			receivedData = string(buffer[:n])
		}
		readDone <- true
	}()

	// Send data
	err := tunnel.SendData(testData)
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	// Wait for read to complete
	select {
	case <-readDone:
		if readErr != nil {
			t.Errorf("Failed to read from server: %v", readErr)
		} else if receivedData != string(testData) {
			t.Errorf("Expected %s, got %s", string(testData), receivedData)
		}
	case <-time.After(1 * time.Second):
		t.Error("Read operation timed out")
	}

	// Test Close
	err = tunnel.Close()
	if err != nil {
		t.Errorf("Failed to close tunnel: %v", err)
	}

	if tunnel.IsActive() {
		t.Error("Tunnel should not be active after close")
	}

	// Test operations after close
	err = tunnel.SendData(testData)
	if err == nil {
		t.Error("Expected error when sending data to closed tunnel")
	}
}

func TestUDPListener(t *testing.T) {
	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	listener := &udpListener{conn: udpConn}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	// Test Addr
	if listener.Addr().String() != udpConn.LocalAddr().String() {
		t.Error("Listener address should match UDP connection address")
	}

	// Send test data to trigger Accept
	go func() {
		time.Sleep(50 * time.Millisecond)
		clientConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Errorf("Failed to create UDP client: %v", err)
			return
		}
		defer clientConn.Close()

		_, err = clientConn.Write([]byte("test"))
		if err != nil {
			t.Errorf("Failed to write to UDP client: %v", err)
		}
	}()

	// Test Accept
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept UDP connection: %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Error("Accepted connection should not be nil")
	}

	// Test Close
	err = listener.Close()
	if err != nil {
		t.Errorf("Failed to close UDP listener: %v", err)
	}
}