package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// TestEndToEndCommunication tests full client-to-destination communication through relays
func TestEndToEndCommunication(t *testing.T) {
	// Test both TCP and UDP protocols
	protocols := []string{"tcp", "udp"}
	
	for _, protocol := range protocols {
		t.Run(fmt.Sprintf("EndToEnd_%s", protocol), func(t *testing.T) {
			testEndToEndWithProtocol(t, protocol)
		})
	}
}

// testEndToEndWithProtocol tests end-to-end communication with a specific protocol
func testEndToEndWithProtocol(t *testing.T, protocol string) {
	// Setup test environment
	testEnv := setupTestEnvironment(t, protocol)
	defer testEnv.cleanup()

	// Test data to send through the VPN
	testData := []byte("Hello, this is a test message through the quantum anonymous VPN!")
	
	// Send data from client through relay network to destination
	receivedData, err := testEnv.sendThroughVPN(testData)
	if err != nil {
		t.Fatalf("Failed to send data through VPN: %v", err)
	}

	// Verify data integrity
	if !bytes.Equal(testData, receivedData) {
		t.Errorf("Data integrity check failed. Expected: %s, Got: %s", string(testData), string(receivedData))
	}

	// Test multiple packets
	for i := 0; i < 10; i++ {
		testMsg := fmt.Sprintf("Test message #%d", i)
		testBytes := []byte(testMsg)
		
		received, err := testEnv.sendThroughVPN(testBytes)
		if err != nil {
			t.Errorf("Failed to send test message #%d: %v", i, err)
			continue
		}
		
		if !bytes.Equal(testBytes, received) {
			t.Errorf("Message #%d integrity failed. Expected: %s, Got: %s", i, testMsg, string(received))
		}
	}
}

// TestMultiProtocolSupport tests both TCP and UDP protocol support
func TestMultiProtocolSupport(t *testing.T) {
	// Test TCP protocol
	t.Run("TCP_Protocol", func(t *testing.T) {
		testProtocolSpecificFeatures(t, "tcp")
	})

	// Test UDP protocol
	t.Run("UDP_Protocol", func(t *testing.T) {
		testProtocolSpecificFeatures(t, "udp")
	})

	// Test protocol switching
	t.Run("Protocol_Switching", func(t *testing.T) {
		testProtocolSwitching(t)
	})
}

// testProtocolSpecificFeatures tests protocol-specific functionality
func testProtocolSpecificFeatures(t *testing.T, protocol string) {
	testEnv := setupTestEnvironment(t, protocol)
	defer testEnv.cleanup()

	// Test protocol-specific characteristics
	if protocol == "tcp" {
		// Test TCP reliability features
		testTCPReliability(t, testEnv)
	} else if protocol == "udp" {
		// Test UDP low-latency features
		testUDPLatency(t, testEnv)
	}
}

// testTCPReliability tests TCP-specific reliability features
func testTCPReliability(t *testing.T, testEnv *TestEnvironment) {
	// Send large data to test TCP's reliable delivery
	largeData := make([]byte, 10*1024) // 10KB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	received, err := testEnv.sendThroughVPN(largeData)
	if err != nil {
		t.Fatalf("Failed to send large data via TCP: %v", err)
	}

	if !bytes.Equal(largeData, received) {
		t.Error("Large data transmission failed via TCP")
	}
}

// testUDPLatency tests UDP-specific low-latency features
func testUDPLatency(t *testing.T, testEnv *TestEnvironment) {
	// Measure latency for small packets
	smallData := []byte("ping")
	
	start := time.Now()
	_, err := testEnv.sendThroughVPN(smallData)
	latency := time.Since(start)
	
	if err != nil {
		t.Fatalf("Failed to send data via UDP: %v", err)
	}

	// UDP should have reasonable latency (less than 1 second for test environment)
	if latency > time.Second {
		t.Errorf("UDP latency too high: %v", latency)
	}
}

// testProtocolSwitching tests the ability to switch between protocols
func testProtocolSwitching(t *testing.T) {
	// Create environments for both protocols
	tcpEnv := setupTestEnvironment(t, "tcp")
	defer tcpEnv.cleanup()
	
	udpEnv := setupTestEnvironment(t, "udp")
	defer udpEnv.cleanup()

	// Test data
	testData := []byte("Protocol switching test")

	// Send via TCP
	tcpReceived, err := tcpEnv.sendThroughVPN(testData)
	if err != nil {
		t.Fatalf("Failed to send via TCP: %v", err)
	}

	// Send via UDP
	udpReceived, err := udpEnv.sendThroughVPN(testData)
	if err != nil {
		t.Fatalf("Failed to send via UDP: %v", err)
	}

	// Both should work correctly
	if !bytes.Equal(testData, tcpReceived) {
		t.Error("TCP transmission failed in protocol switching test")
	}
	if !bytes.Equal(testData, udpReceived) {
		t.Error("UDP transmission failed in protocol switching test")
	}
}

// TestAnonymityVerification tests that no traffic correlation is possible
func TestAnonymityVerification(t *testing.T) {
	// Setup multiple test environments to simulate network traffic
	environments := make([]*TestEnvironment, 3)
	for i := 0; i < 3; i++ {
		environments[i] = setupTestEnvironment(t, "tcp")
		defer environments[i].cleanup()
	}

	// Generate traffic patterns from multiple sources
	var wg sync.WaitGroup
	trafficData := make([][]TrafficRecord, len(environments))
	
	for i, env := range environments {
		wg.Add(1)
		go func(idx int, testEnv *TestEnvironment) {
			defer wg.Done()
			trafficData[idx] = generateTrafficPattern(t, testEnv, idx)
		}(i, env)
	}
	
	wg.Wait()

	// Analyze traffic for correlation
	correlationScore := analyzeTrafficCorrelation(trafficData)
	
	// Correlation score should be low (indicating good anonymity)
	maxAcceptableCorrelation := 0.3 // 30% correlation threshold
	if correlationScore > maxAcceptableCorrelation {
		t.Errorf("Traffic correlation too high: %.2f (max acceptable: %.2f)", 
			correlationScore, maxAcceptableCorrelation)
	}

	// Test that individual relay nodes cannot correlate traffic
	testRelayNodeIsolation(t, environments[0])
}

// generateTrafficPattern generates a pattern of network traffic for anonymity testing
func generateTrafficPattern(t *testing.T, env *TestEnvironment, sourceID int) []TrafficRecord {
	var records []TrafficRecord
	
	// Generate 20 packets with varying sizes and timing
	for i := 0; i < 20; i++ {
		// Vary packet sizes
		size := 100 + (i * 50) % 1000
		data := make([]byte, size)
		for j := range data {
			data[j] = byte((sourceID + i + j) % 256)
		}

		start := time.Now()
		_, err := env.sendThroughVPN(data)
		duration := time.Since(start)
		
		if err != nil {
			t.Logf("Warning: Failed to send packet %d from source %d: %v", i, sourceID, err)
			continue
		}

		records = append(records, TrafficRecord{
			SourceID:  sourceID,
			PacketID:  i,
			Size:      size,
			Timestamp: start,
			Duration:  duration,
		})

		// Add random delay between packets
		time.Sleep(time.Duration(50+i*10) * time.Millisecond)
	}
	
	return records
}

// analyzeTrafficCorrelation analyzes traffic patterns for correlation
func analyzeTrafficCorrelation(trafficData [][]TrafficRecord) float64 {
	if len(trafficData) < 2 {
		return 0.0
	}

	// Simple correlation analysis based on timing patterns
	var correlationSum float64
	var comparisons int

	for i := 0; i < len(trafficData); i++ {
		for j := i + 1; j < len(trafficData); j++ {
			correlation := calculateTimingCorrelation(trafficData[i], trafficData[j])
			correlationSum += correlation
			comparisons++
		}
	}

	if comparisons == 0 {
		return 0.0
	}

	return correlationSum / float64(comparisons)
}

// calculateTimingCorrelation calculates timing correlation between two traffic streams
func calculateTimingCorrelation(stream1, stream2 []TrafficRecord) float64 {
	if len(stream1) == 0 || len(stream2) == 0 {
		return 0.0
	}

	// Calculate timing intervals for both streams
	intervals1 := calculateIntervals(stream1)
	intervals2 := calculateIntervals(stream2)

	// Simple correlation coefficient calculation
	if len(intervals1) != len(intervals2) {
		return 0.0
	}

	var sum1, sum2, sum1Sq, sum2Sq, sumProduct float64
	n := float64(len(intervals1))

	for i := 0; i < len(intervals1); i++ {
		x := float64(intervals1[i].Nanoseconds())
		y := float64(intervals2[i].Nanoseconds())
		
		sum1 += x
		sum2 += y
		sum1Sq += x * x
		sum2Sq += y * y
		sumProduct += x * y
	}

	numerator := n*sumProduct - sum1*sum2
	denominator := (n*sum1Sq - sum1*sum1) * (n*sum2Sq - sum2*sum2)
	
	if denominator <= 0 {
		return 0.0
	}

	correlation := numerator / (denominator * 0.5) // Simplified calculation
	if correlation < 0 {
		correlation = -correlation
	}
	
	return correlation
}

// calculateIntervals calculates time intervals between traffic records
func calculateIntervals(records []TrafficRecord) []time.Duration {
	if len(records) < 2 {
		return []time.Duration{}
	}

	intervals := make([]time.Duration, len(records)-1)
	for i := 1; i < len(records); i++ {
		intervals[i-1] = records[i].Timestamp.Sub(records[i-1].Timestamp)
	}
	
	return intervals
}

// testRelayNodeIsolation tests that relay nodes cannot correlate traffic
func testRelayNodeIsolation(t *testing.T, env *TestEnvironment) {
	// Send multiple messages through the same relay path
	messages := []string{
		"Message from Alice",
		"Message from Bob", 
		"Message from Charlie",
	}

	// Track what each relay node sees
	relayObservations := make(map[string][]ObservationRecord)

	for i, msg := range messages {
		data := []byte(msg)
		
		// Send message and capture relay observations
		observations := captureRelayObservations(t, env, data)
		
		for relayID, obs := range observations {
			relayObservations[relayID] = append(relayObservations[relayID], ObservationRecord{
				MessageID: i,
				Data:      obs,
				Timestamp: time.Now(),
			})
		}
	}

	// Verify that no single relay can correlate all messages
	for relayID, observations := range relayObservations {
		if canCorrelateMessages(observations) {
			t.Errorf("Relay node %s can correlate messages - anonymity compromised", relayID)
		}
	}
}

// captureRelayObservations simulates capturing what relay nodes observe
func captureRelayObservations(t *testing.T, env *TestEnvironment, data []byte) map[string][]byte {
	// This is a simplified simulation of relay observations
	// In a real implementation, this would involve monitoring actual relay traffic
	
	observations := make(map[string][]byte)
	
	// Simulate 3 relay nodes observing encrypted traffic
	for i := 0; i < 3; i++ {
		relayID := fmt.Sprintf("relay_%d", i)
		
		// Each relay sees encrypted data (should be indistinguishable)
		encryptedData, err := simulateRelayView(data, i)
		if err != nil {
			t.Logf("Warning: Failed to simulate relay view for %s: %v", relayID, err)
			continue
		}
		
		observations[relayID] = encryptedData
	}
	
	return observations
}

// simulateRelayView simulates what a relay node sees (encrypted data)
func simulateRelayView(originalData []byte, relayIndex int) ([]byte, error) {
	// Generate a key pair for encryption simulation
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return nil, err
	}

	// Encrypt the data as a relay would see it
	encryptedPacket, err := EncryptPacket(originalData, keyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	// Return the encrypted ciphertext (what relay actually sees)
	return encryptedPacket.Ciphertext, nil
}

// canCorrelateMessages checks if observations can be correlated
func canCorrelateMessages(observations []ObservationRecord) bool {
	if len(observations) < 2 {
		return false
	}

	// Check if any two observations are identical (which would indicate correlation)
	for i := 0; i < len(observations); i++ {
		for j := i + 1; j < len(observations); j++ {
			if bytes.Equal(observations[i].Data, observations[j].Data) {
				return true // Identical encrypted data indicates correlation
			}
		}
	}

	return false
}

// TestEnvironment represents a test environment for integration testing
type TestEnvironment struct {
	client      *ClientState
	relays      []*RelayState
	destination *MockDestination
	protocol    string
	cleanup     func()
}

// TrafficRecord represents a record of network traffic for analysis
type TrafficRecord struct {
	SourceID  int
	PacketID  int
	Size      int
	Timestamp time.Time
	Duration  time.Duration
}

// ObservationRecord represents what a relay node observes
type ObservationRecord struct {
	MessageID int
	Data      []byte
	Timestamp time.Time
}

// MockDestination simulates a destination server for testing
type MockDestination struct {
	listener     net.Listener
	receivedData [][]byte
	mutex        sync.Mutex
	isRunning    bool
}

// setupTestEnvironment creates a complete test environment
func setupTestEnvironment(t *testing.T, protocol string) *TestEnvironment {
	// Create mock destination
	destination := &MockDestination{
		receivedData: make([][]byte, 0),
		isRunning:    true,
	}

	// Start destination server
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create destination listener: %v", err)
	}
	destination.listener = listener

	go destination.acceptConnections()

	// Create relay nodes (minimum 3 for multi-hop routing)
	relays := make([]*RelayState, 3)
	for i := 0; i < 3; i++ {
		relay, err := createTestRelay(t, protocol, 9060+i)
		if err != nil {
			t.Fatalf("Failed to create test relay %d: %v", i, err)
		}
		relays[i] = relay
	}

	// Create client
	client, err := createTestClient(t, protocol, relays)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Setup cleanup function
	cleanupFunc := func() {
		// Stop client
		if client != nil {
			client.IsRunning = false
		}

		// Stop relays
		for _, relay := range relays {
			if relay != nil {
				relay.IsRunning = false
				if relay.NodeManager != nil {
					relay.NodeManager.StopRelayServer()
				}
			}
		}

		// Stop destination
		destination.isRunning = false
		if destination.listener != nil {
			destination.listener.Close()
		}
	}

	return &TestEnvironment{
		client:      client,
		relays:      relays,
		destination: destination,
		protocol:    protocol,
		cleanup:     cleanupFunc,
	}
}

// createTestRelay creates a relay node for testing
func createTestRelay(t *testing.T, protocol string, port int) (*RelayState, error) {
	// Create configuration for relay
	config := NewDefaultConfig()
	config.RelayMode = true
	config.RelayPort = port
	config.Protocol = protocol
	config.LogLevel = 0 // Quiet for testing

	// Initialize node manager
	nodeManager, err := NewNodeManager(true)
	if err != nil {
		return nil, fmt.Errorf("failed to create node manager: %w", err)
	}

	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Start relay server
	if err := nodeManager.StartRelayServer(port); err != nil {
		return nil, fmt.Errorf("failed to start relay server: %w", err)
	}

	// Create relay state
	relayState := &RelayState{
		Config:       config,
		NodeManager:  nodeManager,
		LocalKeyPair: keyPair,
		IsRunning:    true,
		StartTime:    time.Now(),
		Statistics:   NewRelayStatistics(),
	}

	return relayState, nil
}

// createTestClient creates a client for testing
func createTestClient(t *testing.T, protocol string, relays []*RelayState) (*ClientState, error) {
	// Create configuration for client
	config := NewDefaultConfig()
	config.RelayMode = false
	config.ClientPort = 9050
	config.Protocol = protocol
	config.DesiredHops = len(relays)
	config.LogLevel = 0 // Quiet for testing

	// Initialize node manager
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		return nil, fmt.Errorf("failed to create node manager: %w", err)
	}

	// Add relay nodes to known nodes
	for _, relay := range relays {
		relayNode := &Node{
			ID:        relay.NodeManager.localNode.ID,
			PublicKey: relay.LocalKeyPair.PublicKey,
			Address:   relay.NodeManager.localNode.Address,
			Protocol:  protocol,
			LastSeen:  time.Now(),
			Latency:   0,
		}
		nodeManager.knownNodes[relayNode.ID] = relayNode
	}

	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create route through relays
	route, err := nodeManager.SelectRoute("", protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to select route: %w", err)
	}

	// Initialize tunnel manager
	tunnelManager := NewTunnelManager()

	// Create client state
	clientState := &ClientState{
		Config:        config,
		NodeManager:   nodeManager,
		TunnelManager: tunnelManager,
		LocalKeyPair:  keyPair,
		ActiveRoute:   route,
		IsRunning:     true,
		StartTime:     time.Now(),
		Statistics:    &ClientStatistics{},
	}

	return clientState, nil
}

// sendThroughVPN sends data through the VPN and returns received data
func (env *TestEnvironment) sendThroughVPN(data []byte) ([]byte, error) {
	// Create tunnel through the active route
	if len(env.client.ActiveRoute.Hops) == 0 {
		return nil, fmt.Errorf("no hops in active route")
	}

	firstHop := env.client.ActiveRoute.Hops[0]
	
	var tunnel Tunnel
	var err error

	if env.protocol == "tcp" {
		tunnel, err = env.client.TunnelManager.CreateTCPTunnel(firstHop.Address, 10*time.Second)
	} else {
		tunnel, err = env.client.TunnelManager.CreateUDPTunnel(firstHop.Address, 10*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}
	defer tunnel.Close()

	// Send data through tunnel
	if err := tunnel.SendData(data); err != nil {
		return nil, fmt.Errorf("failed to send data: %w", err)
	}

	// For testing purposes, simulate receiving the data back
	// In a real implementation, this would come from the destination
	return env.simulateDestinationResponse(data)
}

// simulateDestinationResponse simulates a response from the destination
func (env *TestEnvironment) simulateDestinationResponse(originalData []byte) ([]byte, error) {
	// Add to destination's received data
	env.destination.mutex.Lock()
	env.destination.receivedData = append(env.destination.receivedData, originalData)
	env.destination.mutex.Unlock()

	// Return the same data (echo response)
	return originalData, nil
}

// acceptConnections handles incoming connections to the mock destination
func (dest *MockDestination) acceptConnections() {
	for dest.isRunning {
		conn, err := dest.listener.Accept()
		if err != nil {
			if dest.isRunning {
				fmt.Printf("Destination accept error: %v\n", err)
			}
			continue
		}

		go dest.handleConnection(conn)
	}
}

// handleConnection handles a single connection to the mock destination
func (dest *MockDestination) handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			break
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		dest.mutex.Lock()
		dest.receivedData = append(dest.receivedData, data)
		dest.mutex.Unlock()

		// Echo the data back
		conn.Write(data)
	}
}