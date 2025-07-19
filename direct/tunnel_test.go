package direct

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// MockTunnel implements the Tunnel interface for testing
type MockTunnel struct {
	sendData    []byte
	receiveData []byte
	isActive    bool
	sendError   error
	receiveError error
}

func (mt *MockTunnel) SendData(data []byte) error {
	if mt.sendError != nil {
		return mt.sendError
	}
	mt.sendData = make([]byte, len(data))
	copy(mt.sendData, data)
	return nil
}

func (mt *MockTunnel) ReceiveData() ([]byte, error) {
	if mt.receiveError != nil {
		return nil, mt.receiveError
	}
	return mt.receiveData, nil
}

func (mt *MockTunnel) Close() error {
	mt.isActive = false
	return nil
}

func (mt *MockTunnel) IsActive() bool {
	return mt.isActive
}

func TestNewDirectTunnel(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleListener)

	// Verify initialization
	if directTunnel == nil {
		t.Fatal("DirectTunnel should not be nil")
	}

	if !directTunnel.IsActive() {
		t.Error("DirectTunnel should be active")
	}

	if directTunnel.GetConnectionID() != connectionID {
		t.Error("Connection ID mismatch")
	}

	if directTunnel.GetRole() != RoleListener {
		t.Error("Role mismatch")
	}

	if directTunnel.multiplexer == nil {
		t.Error("Multiplexer should be initialized")
	}
}

func TestDirectTunnelSendReceive(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleConnector)

	// Test data
	testData := []byte("Hello, Direct Connection!")

	// Test SendData
	err := directTunnel.SendData(testData)
	if err != nil {
		t.Fatalf("SendData failed: %v", err)
	}

	// Verify data was sent to underlying tunnel
	if !bytes.Equal(mockTunnel.sendData, testData) {
		t.Error("Sent data mismatch")
	}

	// Setup receive data
	mockTunnel.receiveData = testData

	// Test ReceiveData
	receivedData, err := directTunnel.ReceiveData()
	if err != nil {
		t.Fatalf("ReceiveData failed: %v", err)
	}

	if !bytes.Equal(receivedData, testData) {
		t.Error("Received data mismatch")
	}
}

func TestDirectTunnelMetrics(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleListener)

	// Send some data to generate metrics
	testData := []byte("Test data for metrics")
	err := directTunnel.SendData(testData)
	if err != nil {
		t.Fatalf("SendData failed: %v", err)
	}

	// Get metrics
	metrics := directTunnel.GetMetrics()
	if metrics == nil {
		t.Fatal("Metrics should not be nil")
	}

	if metrics.BytesSent != uint64(len(testData)) {
		t.Errorf("Expected bytes sent: %d, got: %d", len(testData), metrics.BytesSent)
	}

	if metrics.PacketsSent != 1 {
		t.Errorf("Expected packets sent: 1, got: %d", metrics.PacketsSent)
	}

	if metrics.ConnectionTime <= 0 {
		t.Error("Connection time should be positive")
	}
}

func TestDirectTunnelClose(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleConnector)

	// Verify tunnel is active
	if !directTunnel.IsActive() {
		t.Error("DirectTunnel should be active before close")
	}

	// Close tunnel
	err := directTunnel.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify tunnel is inactive
	if directTunnel.IsActive() {
		t.Error("DirectTunnel should be inactive after close")
	}

	// Verify underlying tunnel was closed
	if mockTunnel.IsActive() {
		t.Error("Underlying tunnel should be inactive after close")
	}
}

func TestTunnelMultiplexer(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleListener)

	// Create multiplexed channel
	channel, err := directTunnel.CreateMultiplexChannel()
	if err != nil {
		t.Fatalf("CreateMultiplexChannel failed: %v", err)
	}

	if channel == nil {
		t.Fatal("Channel should not be nil")
	}

	if !channel.IsActive() {
		t.Error("Channel should be active")
	}

	// Test channel data transmission
	testData := []byte("Multiplexed data")
	err = channel.SendData(testData)
	if err != nil {
		t.Fatalf("Channel SendData failed: %v", err)
	}

	// List channels
	channels := directTunnel.ListMultiplexChannels()
	if len(channels) != 1 {
		t.Errorf("Expected 1 channel, got: %d", len(channels))
	}

	// Get channel by ID
	retrievedChannel, err := directTunnel.GetMultiplexChannel(channel.GetChannelID())
	if err != nil {
		t.Fatalf("GetMultiplexChannel failed: %v", err)
	}

	if retrievedChannel.GetChannelID() != channel.GetChannelID() {
		t.Error("Retrieved channel ID mismatch")
	}
}

func TestMultiplexChannelStats(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleConnector)

	// Create multiplexed channel
	channel, err := directTunnel.CreateMultiplexChannel()
	if err != nil {
		t.Fatalf("CreateMultiplexChannel failed: %v", err)
	}

	// Get channel stats
	stats := channel.GetStats()
	if stats == nil {
		t.Fatal("Channel stats should not be nil")
	}

	if stats.ChannelID != channel.GetChannelID() {
		t.Error("Channel ID mismatch in stats")
	}

	if !stats.IsActive {
		t.Error("Channel should be active in stats")
	}

	if stats.CreatedAt.IsZero() {
		t.Error("Created at timestamp should not be zero")
	}
}

func TestMultiplexFrameSerialization(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleListener)

	// Create test frame
	testData := []byte("Test frame data")
	frame := &MultiplexFrame{
		ChannelID: 123,
		FrameType: FrameTypeData,
		Length:    uint32(len(testData)),
		Data:      testData,
	}

	// Serialize frame
	serialized, err := directTunnel.multiplexer.serializeFrame(frame)
	if err != nil {
		t.Fatalf("Frame serialization failed: %v", err)
	}

	// Deserialize frame
	deserialized, err := directTunnel.multiplexer.deserializeFrame(serialized)
	if err != nil {
		t.Fatalf("Frame deserialization failed: %v", err)
	}

	// Verify frame data
	if deserialized.ChannelID != frame.ChannelID {
		t.Error("Channel ID mismatch after serialization")
	}

	if deserialized.FrameType != frame.FrameType {
		t.Error("Frame type mismatch after serialization")
	}

	if deserialized.Length != frame.Length {
		t.Error("Length mismatch after serialization")
	}

	if !bytes.Equal(deserialized.Data, frame.Data) {
		t.Error("Data mismatch after serialization")
	}
}

func TestDirectTunnelInactiveOperations(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleConnector)

	// Close the tunnel
	err := directTunnel.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Test operations on inactive tunnel
	testData := []byte("Test data")

	// SendData should fail
	err = directTunnel.SendData(testData)
	if err == nil {
		t.Error("SendData should fail on inactive tunnel")
	}

	// ReceiveData should fail
	_, err = directTunnel.ReceiveData()
	if err == nil {
		t.Error("ReceiveData should fail on inactive tunnel")
	}
}

func TestMultiplexChannelTimeout(t *testing.T) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleListener)

	// Create multiplexed channel
	channel, err := directTunnel.CreateMultiplexChannel()
	if err != nil {
		t.Fatalf("CreateMultiplexChannel failed: %v", err)
	}

	// Test receive timeout (should timeout since no data is available)
	start := time.Now()
	_, err = channel.ReceiveData()
	elapsed := time.Since(start)

	if err == nil {
		t.Error("ReceiveData should timeout when no data is available")
	}

	// Should timeout after approximately 30 seconds (with some tolerance)
	if elapsed < 25*time.Second || elapsed > 35*time.Second {
		t.Errorf("Timeout duration unexpected: %v", elapsed)
	}
}

func BenchmarkDirectTunnelSendReceive(b *testing.B) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		b.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleConnector)

	// Test data
	testData := make([]byte, 1024) // 1KB test data
	if _, err := rand.Read(testData); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	// Setup mock tunnel to return the same data
	mockTunnel.receiveData = testData

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Send data
		err := directTunnel.SendData(testData)
		if err != nil {
			b.Fatalf("SendData failed: %v", err)
		}

		// Receive data
		_, err = directTunnel.ReceiveData()
		if err != nil {
			b.Fatalf("ReceiveData failed: %v", err)
		}
	}
}

func BenchmarkMultiplexFrameSerialization(b *testing.B) {
	// Create mock underlying tunnel
	mockTunnel := &MockTunnel{isActive: true}
	
	// Generate connection ID
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		b.Fatalf("Failed to generate connection ID: %v", err)
	}

	// Create DirectTunnel
	directTunnel := NewDirectTunnel(mockTunnel, connectionID, RoleListener)

	// Create test frame
	testData := make([]byte, 1024) // 1KB test data
	if _, err := rand.Read(testData); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	frame := &MultiplexFrame{
		ChannelID: 123,
		FrameType: FrameTypeData,
		Length:    uint32(len(testData)),
		Data:      testData,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Serialize frame
		serialized, err := directTunnel.multiplexer.serializeFrame(frame)
		if err != nil {
			b.Fatalf("Frame serialization failed: %v", err)
		}

		// Deserialize frame
		_, err = directTunnel.multiplexer.deserializeFrame(serialized)
		if err != nil {
			b.Fatalf("Frame deserialization failed: %v", err)
		}
	}
}