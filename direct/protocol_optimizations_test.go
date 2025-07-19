package direct

import (
	"net"
	"testing"
	"time"
)

func TestNewProtocolOptimizer(t *testing.T) {
	optimizer := NewProtocolOptimizer()

	if optimizer == nil {
		t.Fatal("Protocol optimizer should not be nil")
	}

	if optimizer.tcpOptimizer == nil {
		t.Error("TCP optimizer should not be nil")
	}

	if optimizer.udpOptimizer == nil {
		t.Error("UDP optimizer should not be nil")
	}

	if optimizer.selector == nil {
		t.Error("Protocol selector should not be nil")
	}

	if optimizer.fallback == nil {
		t.Error("Fallback manager should not be nil")
	}
}

func TestNewTCPOptimizer(t *testing.T) {
	optimizer := NewTCPOptimizer()

	if optimizer == nil {
		t.Fatal("TCP optimizer should not be nil")
	}

	if !optimizer.keepAliveEnabled {
		t.Error("Keep-alive should be enabled by default")
	}

	if optimizer.keepAliveInterval != 60*time.Second {
		t.Errorf("Expected keep-alive interval: 60s, got: %v", optimizer.keepAliveInterval)
	}

	if !optimizer.noDelayEnabled {
		t.Error("No delay should be enabled by default")
	}

	if optimizer.bufferSizes == nil {
		t.Error("Buffer sizes should be initialized")
	}

	if optimizer.connectionPooling == nil {
		t.Error("Connection pooling should be initialized")
	}
}

func TestNewUDPOptimizer(t *testing.T) {
	optimizer := NewUDPOptimizer()

	if optimizer == nil {
		t.Fatal("UDP optimizer should not be nil")
	}

	if optimizer.connectionSimulation == nil {
		t.Error("Connection simulation should be initialized")
	}

	if optimizer.packetReordering == nil {
		t.Error("Packet reordering handler should be initialized")
	}

	if optimizer.duplicateDetection == nil {
		t.Error("Duplicate detection should be initialized")
	}

	if optimizer.fragmentationHandler == nil {
		t.Error("Fragmentation handler should be initialized")
	}

	if optimizer.bufferSizes == nil {
		t.Error("Buffer sizes should be initialized")
	}

	if optimizer.reliabilityLayer == nil {
		t.Error("Reliability layer should be initialized")
	}
}

func TestNewProtocolSelector(t *testing.T) {
	selector := NewProtocolSelector()

	if selector == nil {
		t.Fatal("Protocol selector should not be nil")
	}

	if selector.networkAnalyzer == nil {
		t.Error("Network analyzer should be initialized")
	}

	if selector.selectionCriteria == nil {
		t.Error("Selection criteria should be initialized")
	}

	if selector.currentProtocol != "tcp" {
		t.Errorf("Expected default protocol: tcp, got: %s", selector.currentProtocol)
	}

	if selector.analysisInterval != 30*time.Second {
		t.Errorf("Expected analysis interval: 30s, got: %v", selector.analysisInterval)
	}
}

func TestNewProtocolFallbackManager(t *testing.T) {
	manager := NewProtocolFallbackManager()

	if manager == nil {
		t.Fatal("Fallback manager should not be nil")
	}

	if len(manager.fallbackRules) == 0 {
		t.Error("Should have default fallback rules")
	}

	if manager.maxFallbackAttempts != 3 {
		t.Errorf("Expected max fallback attempts: 3, got: %d", manager.maxFallbackAttempts)
	}

	if manager.fallbackCooldown != 60*time.Second {
		t.Errorf("Expected fallback cooldown: 60s, got: %v", manager.fallbackCooldown)
	}
}

func TestTCPBufferSizes(t *testing.T) {
	optimizer := NewTCPOptimizer()

	expectedSendBuffer := 64 * 1024
	expectedReceiveBuffer := 64 * 1024
	expectedWindowSize := 128 * 1024

	if optimizer.bufferSizes.SendBuffer != expectedSendBuffer {
		t.Errorf("Expected send buffer: %d, got: %d", expectedSendBuffer, optimizer.bufferSizes.SendBuffer)
	}

	if optimizer.bufferSizes.ReceiveBuffer != expectedReceiveBuffer {
		t.Errorf("Expected receive buffer: %d, got: %d", expectedReceiveBuffer, optimizer.bufferSizes.ReceiveBuffer)
	}

	if optimizer.bufferSizes.WindowSize != expectedWindowSize {
		t.Errorf("Expected window size: %d, got: %d", expectedWindowSize, optimizer.bufferSizes.WindowSize)
	}
}

func TestUDPBufferSizes(t *testing.T) {
	optimizer := NewUDPOptimizer()

	expectedSendBuffer := 128 * 1024
	expectedReceiveBuffer := 128 * 1024
	expectedPacketSize := 1400

	if optimizer.bufferSizes.SendBuffer != expectedSendBuffer {
		t.Errorf("Expected send buffer: %d, got: %d", expectedSendBuffer, optimizer.bufferSizes.SendBuffer)
	}

	if optimizer.bufferSizes.ReceiveBuffer != expectedReceiveBuffer {
		t.Errorf("Expected receive buffer: %d, got: %d", expectedReceiveBuffer, optimizer.bufferSizes.ReceiveBuffer)
	}

	if optimizer.bufferSizes.PacketSize != expectedPacketSize {
		t.Errorf("Expected packet size: %d, got: %d", expectedPacketSize, optimizer.bufferSizes.PacketSize)
	}
}

func TestCreateUDPSession(t *testing.T) {
	optimizer := NewUDPOptimizer()

	remoteAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	sessionID := "test-session-1"
	session := optimizer.CreateUDPSession(sessionID, remoteAddr)

	if session == nil {
		t.Fatal("UDP session should not be nil")
	}

	if session.sessionID != sessionID {
		t.Errorf("Expected session ID: %s, got: %s", sessionID, session.sessionID)
	}

	if session.remoteAddr.String() != remoteAddr.String() {
		t.Errorf("Expected remote address: %s, got: %s", remoteAddr.String(), session.remoteAddr.String())
	}

	if !session.isActive {
		t.Error("Session should be active")
	}

	if session.sendWindow == nil {
		t.Error("Send window should be initialized")
	}

	if session.receiveWindow == nil {
		t.Error("Receive window should be initialized")
	}
}

func TestProtocolSelection(t *testing.T) {
	selector := NewProtocolSelector()

	// Test conditions favoring TCP
	tcpConditions := &NetworkConditions{
		Latency:    200 * time.Millisecond,
		PacketLoss: 0.005, // 0.5%
		Throughput: 500000, // 500 Kbps
		Jitter:     20 * time.Millisecond,
		Stability:  0.95,
	}

	selection, err := selector.SelectOptimalProtocol(tcpConditions)
	if err != nil {
		t.Fatalf("Protocol selection failed: %v", err)
	}

	if selection.Protocol != "tcp" {
		t.Errorf("Expected TCP selection for stable conditions, got: %s", selection.Protocol)
	}

	// Test conditions favoring UDP
	udpConditions := &NetworkConditions{
		Latency:    50 * time.Millisecond,
		PacketLoss: 0.02, // 2%
		Throughput: 2000000, // 2 Mbps
		Jitter:     10 * time.Millisecond,
		Stability:  0.85,
	}

	selection, err = selector.SelectOptimalProtocol(udpConditions)
	if err != nil {
		t.Fatalf("Protocol selection failed: %v", err)
	}

	if selection.Protocol != "udp" {
		t.Errorf("Expected UDP selection for low-latency conditions, got: %s", selection.Protocol)
	}
}

func TestCalculateProtocolScore(t *testing.T) {
	selector := NewProtocolSelector()

	// Test conditions that favor UDP (low latency, high throughput, low jitter)
	udpFavoringConditions := &NetworkConditions{
		Latency:    50 * time.Millisecond,  // Below threshold (100ms)
		PacketLoss: 0.02,                   // Above TCP threshold (0.01)
		Throughput: 1500000,                // Above threshold (1000000)
		Jitter:     20 * time.Millisecond,  // Below threshold (50ms)
		Stability:  0.85,                   // Below TCP preference (0.9)
	}

	tcpScore := selector.calculateProtocolScore("tcp", udpFavoringConditions)
	udpScore := selector.calculateProtocolScore("udp", udpFavoringConditions)

	if tcpScore < 0 || tcpScore > 1 {
		t.Errorf("TCP score should be between 0 and 1, got: %f", tcpScore)
	}

	if udpScore < 0 || udpScore > 1 {
		t.Errorf("UDP score should be between 0 and 1, got: %f", udpScore)
	}

	// For these conditions, UDP should score higher due to low latency and high throughput
	if udpScore <= tcpScore {
		t.Errorf("UDP should score higher for low-latency, high-throughput conditions. TCP: %f, UDP: %f", tcpScore, udpScore)
	}

	// Test conditions that favor TCP (low packet loss, high stability)
	tcpFavoringConditions := &NetworkConditions{
		Latency:    150 * time.Millisecond, // Above UDP threshold but below TCP threshold
		PacketLoss: 0.005,                  // Below TCP threshold (0.01)
		Throughput: 500000,                 // Below UDP threshold (1000000)
		Jitter:     60 * time.Millisecond,  // Above UDP threshold (50ms)
		Stability:  0.95,                   // Above TCP preference (0.9)
	}

	tcpScore2 := selector.calculateProtocolScore("tcp", tcpFavoringConditions)
	udpScore2 := selector.calculateProtocolScore("udp", tcpFavoringConditions)

	// For these conditions, TCP should score higher due to low packet loss and high stability
	if tcpScore2 <= udpScore2 {
		t.Errorf("TCP should score higher for low packet loss, high stability conditions. TCP: %f, UDP: %f", tcpScore2, udpScore2)
	}
}

func TestFallbackConditions(t *testing.T) {
	manager := NewProtocolFallbackManager()

	// Test high latency condition (should trigger TCP to UDP fallback)
	highLatencyConditions := &NetworkConditions{
		Latency:    600 * time.Millisecond, // Above 500ms threshold
		PacketLoss: 0.01,
		Throughput: 1000000,
		Jitter:     50 * time.Millisecond,
		Stability:  0.9,
	}

	rule, shouldFallback := manager.CheckFallbackConditions("tcp", highLatencyConditions)
	if !shouldFallback {
		t.Error("Should trigger fallback for high latency")
	}

	if rule == nil {
		t.Fatal("Fallback rule should not be nil")
	}

	if rule.ToProtocol != "udp" {
		t.Errorf("Expected fallback to UDP, got: %s", rule.ToProtocol)
	}

	// Test high packet loss condition (should trigger UDP to TCP fallback)
	highPacketLossConditions := &NetworkConditions{
		Latency:    100 * time.Millisecond,
		PacketLoss: 0.08, // Above 5% threshold
		Throughput: 1000000,
		Jitter:     30 * time.Millisecond,
		Stability:  0.8,
	}

	rule, shouldFallback = manager.CheckFallbackConditions("udp", highPacketLossConditions)
	if !shouldFallback {
		t.Error("Should trigger fallback for high packet loss")
	}

	if rule == nil {
		t.Fatal("Fallback rule should not be nil")
	}

	if rule.ToProtocol != "tcp" {
		t.Errorf("Expected fallback to TCP, got: %s", rule.ToProtocol)
	}
}

func TestExecuteFallback(t *testing.T) {
	manager := NewProtocolFallbackManager()

	rule := &FallbackRule{
		Name:         "test_fallback",
		FromProtocol: "tcp",
		ToProtocol:   "udp",
		Trigger: FallbackTrigger{
			Type:             "latency",
			LatencyThreshold: 500 * time.Millisecond,
		},
		Priority: 1,
	}

	conditions := &NetworkConditions{
		Latency:    600 * time.Millisecond,
		PacketLoss: 0.01,
		Throughput: 1000000,
		Jitter:     50 * time.Millisecond,
		Stability:  0.9,
	}

	event := manager.ExecuteFallback(rule, conditions)

	if event == nil {
		t.Fatal("Fallback event should not be nil")
	}

	if event.FromProtocol != "tcp" {
		t.Errorf("Expected from protocol: tcp, got: %s", event.FromProtocol)
	}

	if event.ToProtocol != "udp" {
		t.Errorf("Expected to protocol: udp, got: %s", event.ToProtocol)
	}

	if !event.Success {
		t.Error("Fallback should be successful")
	}

	if event.Timestamp.IsZero() {
		t.Error("Fallback timestamp should not be zero")
	}
}

func TestFragmentPacket(t *testing.T) {
	optimizer := NewUDPOptimizer()

	// Test small packet (no fragmentation needed)
	smallData := make([]byte, 100)
	fragments, err := optimizer.fragmentPacket(smallData)
	if err != nil {
		t.Fatalf("Fragmentation failed: %v", err)
	}

	if len(fragments) != 1 {
		t.Errorf("Expected 1 fragment for small packet, got: %d", len(fragments))
	}

	// Test large packet (fragmentation needed)
	largeData := make([]byte, 5000) // Larger than max packet size
	fragments, err = optimizer.fragmentPacket(largeData)
	if err != nil {
		t.Fatalf("Fragmentation failed: %v", err)
	}

	if len(fragments) <= 1 {
		t.Errorf("Expected multiple fragments for large packet, got: %d", len(fragments))
	}

	// Verify total size matches original
	totalSize := 0
	for _, fragment := range fragments {
		totalSize += len(fragment)
	}

	if totalSize != len(largeData) {
		t.Errorf("Fragment total size mismatch. Expected: %d, got: %d", len(largeData), totalSize)
	}
}

func TestCreateParseSequencedPacket(t *testing.T) {
	optimizer := NewUDPOptimizer()

	sequenceNumber := uint32(12345)
	originalData := []byte("test packet data")

	// Create sequenced packet
	packet := optimizer.createSequencedPacket(sequenceNumber, originalData)

	if len(packet) != 4+len(originalData) {
		t.Errorf("Expected packet size: %d, got: %d", 4+len(originalData), len(packet))
	}

	// Parse sequenced packet
	parsedSeq, parsedData, err := optimizer.parseSequencedPacket(packet)
	if err != nil {
		t.Fatalf("Failed to parse sequenced packet: %v", err)
	}

	if parsedSeq != sequenceNumber {
		t.Errorf("Expected sequence number: %d, got: %d", sequenceNumber, parsedSeq)
	}

	if string(parsedData) != string(originalData) {
		t.Errorf("Expected data: %s, got: %s", string(originalData), string(parsedData))
	}
}

func TestIsDuplicatePacket(t *testing.T) {
	optimizer := NewUDPOptimizer()

	sessionID := "test-session"
	sequenceNumber := uint32(123)

	// First packet should not be duplicate
	isDuplicate := optimizer.isDuplicatePacket(sessionID, sequenceNumber)
	if isDuplicate {
		t.Error("First packet should not be marked as duplicate")
	}

	// Same packet should be duplicate
	isDuplicate = optimizer.isDuplicatePacket(sessionID, sequenceNumber)
	if !isDuplicate {
		t.Error("Same packet should be marked as duplicate")
	}

	// Different sequence number should not be duplicate
	isDuplicate = optimizer.isDuplicatePacket(sessionID, sequenceNumber+1)
	if isDuplicate {
		t.Error("Different sequence number should not be marked as duplicate")
	}
}

func TestGenerateSelectionReason(t *testing.T) {
	selector := NewProtocolSelector()

	lowLatencyConditions := &NetworkConditions{
		Latency:    50 * time.Millisecond,
		PacketLoss: 0.01,
		Throughput: 1000000,
		Jitter:     20 * time.Millisecond,
		Stability:  0.9,
	}

	reason := selector.generateSelectionReason("udp", lowLatencyConditions)
	if reason == "" {
		t.Error("Selection reason should not be empty")
	}

	lowPacketLossConditions := &NetworkConditions{
		Latency:    200 * time.Millisecond,
		PacketLoss: 0.005,
		Throughput: 500000,
		Jitter:     30 * time.Millisecond,
		Stability:  0.95,
	}

	reason = selector.generateSelectionReason("tcp", lowPacketLossConditions)
	if reason == "" {
		t.Error("Selection reason should not be empty")
	}
}

func BenchmarkProtocolSelection(b *testing.B) {
	selector := NewProtocolSelector()

	conditions := &NetworkConditions{
		Latency:    100 * time.Millisecond,
		PacketLoss: 0.01,
		Throughput: 1000000,
		Jitter:     25 * time.Millisecond,
		Stability:  0.9,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := selector.SelectOptimalProtocol(conditions)
		if err != nil {
			b.Fatalf("Protocol selection failed: %v", err)
		}
	}
}

func BenchmarkPacketFragmentation(b *testing.B) {
	optimizer := NewUDPOptimizer()
	data := make([]byte, 5000) // Large packet requiring fragmentation

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := optimizer.fragmentPacket(data)
		if err != nil {
			b.Fatalf("Packet fragmentation failed: %v", err)
		}
	}
}

func BenchmarkSequencedPacketCreation(b *testing.B) {
	optimizer := NewUDPOptimizer()
	data := make([]byte, 1000)
	sequenceNumber := uint32(12345)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packet := optimizer.createSequencedPacket(sequenceNumber, data)
		_, _, err := optimizer.parseSequencedPacket(packet)
		if err != nil {
			b.Fatalf("Sequenced packet parsing failed: %v", err)
		}
	}
}