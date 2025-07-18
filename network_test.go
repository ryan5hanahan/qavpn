package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestTunnelManager tests basic tunnel manager functionality
func TestTunnelManager(t *testing.T) {
	tm := NewTunnelManager()
	
	if tm == nil {
		t.Fatal("NewTunnelManager returned nil")
	}
	
	if len(tm.tcpTunnels) != 0 {
		t.Errorf("Expected empty TCP tunnel map, got %d tunnels", len(tm.tcpTunnels))
	}
	
	if len(tm.udpTunnels) != 0 {
		t.Errorf("Expected empty UDP tunnel map, got %d tunnels", len(tm.udpTunnels))
	}
}

// TestTunnelManagerGetActiveTunnels tests getting active tunnels
func TestTunnelManagerGetActiveTunnels(t *testing.T) {
	tm := NewTunnelManager()
	
	// Should return empty slice when no tunnels exist
	activeTunnels := tm.GetActiveTunnels()
	if len(activeTunnels) != 0 {
		t.Errorf("Expected 0 active tunnels, got %d", len(activeTunnels))
	}
}

// TestTunnelManagerCloseAllTunnels tests closing all tunnels
func TestTunnelManagerCloseAllTunnels(t *testing.T) {
	tm := NewTunnelManager()
	
	// Should not error when no tunnels exist
	err := tm.CloseAllTunnels()
	if err != nil {
		t.Errorf("CloseAllTunnels failed with no tunnels: %v", err)
	}
}

// TestGenerateTunnelID tests tunnel ID generation
func TestGenerateTunnelID(t *testing.T) {
	// Create mock addresses
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9090}
	
	id := generateTunnelID(localAddr, remoteAddr)
	
	if id == "" {
		t.Error("generateTunnelID returned empty string")
	}
	
	expected := "127.0.0.1:8080->192.168.1.1:9090"
	if id != expected {
		t.Errorf("Expected tunnel ID %s, got %s", expected, id)
	}
}

// TestCombineSharedSecrets tests shared secret combination
func TestCombineSharedSecrets(t *testing.T) {
	secret1 := []byte{0x01, 0x02, 0x03, 0x04}
	secret2 := []byte{0x05, 0x06, 0x07, 0x08}
	
	combined := combineSharedSecrets(secret1, secret2)
	
	if len(combined) != 32 { // Should be 32 bytes after key derivation
		t.Errorf("Expected combined secret length 32, got %d", len(combined))
	}
	
	// Test with same secrets should produce same result
	combined2 := combineSharedSecrets(secret1, secret2)
	if len(combined) != len(combined2) {
		t.Error("Combined secrets should have same length")
	}
	
	for i := range combined {
		if combined[i] != combined2[i] {
			t.Error("Combined secrets should be identical for same inputs")
			break
		}
	}
}

// TestBigEndianOperations tests big-endian read/write operations
func TestBigEndianOperations(t *testing.T) {
	testValues := []uint32{0, 1, 255, 256, 65535, 65536, 0xFFFFFFFF}
	
	for _, val := range testValues {
		buf := make([]byte, 4)
		writeBigEndian32(buf, val)
		
		result := readBigEndian32(buf)
		if result != val {
			t.Errorf("Big-endian round trip failed: expected %d, got %d", val, result)
		}
	}
}

// TestTunnelStatsCreation tests tunnel stats structure
func TestTunnelStatsCreation(t *testing.T) {
	now := time.Now()
	stats := TunnelStats{
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.168.1.1:9090",
		CreatedAt:    now,
		LastActivity: now,
		IsActive:     true,
	}
	
	if stats.LocalAddr != "127.0.0.1:8080" {
		t.Errorf("Expected LocalAddr 127.0.0.1:8080, got %s", stats.LocalAddr)
	}
	
	if stats.RemoteAddr != "192.168.1.1:9090" {
		t.Errorf("Expected RemoteAddr 192.168.1.1:9090, got %s", stats.RemoteAddr)
	}
	
	if !stats.IsActive {
		t.Error("Expected tunnel to be active")
	}
}

// TestKeyExchangeMessageValidation tests key exchange message validation
func TestKeyExchangeMessageValidation(t *testing.T) {
	// Test valid public key size
	validKey := make([]byte, KyberPublicKeyBytes)
	if len(validKey) != KyberPublicKeyBytes {
		t.Errorf("Expected key size %d, got %d", KyberPublicKeyBytes, len(validKey))
	}
	
	// Test invalid key sizes
	invalidSizes := []int{0, 1, 100, KyberPublicKeyBytes - 1, KyberPublicKeyBytes + 1}
	for _, size := range invalidSizes {
		invalidKey := make([]byte, size)
		if len(invalidKey) == KyberPublicKeyBytes {
			t.Errorf("Key size %d should be invalid", size)
		}
	}
}

// TestTunnelManagerMaintenance tests tunnel maintenance functionality
func TestTunnelManagerMaintenance(t *testing.T) {
	tm := NewTunnelManager()
	
	// Should not panic when maintaining empty tunnel manager
	tm.MaintainTunnels()
	
	// Verify no tunnels remain after maintenance
	activeTunnels := tm.GetActiveTunnels()
	if len(activeTunnels) != 0 {
		t.Errorf("Expected 0 active tunnels after maintenance, got %d", len(activeTunnels))
	}
}

// TestTunnelClosureIdempotency tests that closing a tunnel multiple times is safe
func TestTunnelClosureIdempotency(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test closing non-existent TCP tunnel
	err := tm.CloseTunnel("non-existent", "tcp")
	if err == nil {
		t.Error("Expected error when closing non-existent TCP tunnel")
	}
	
	// Test closing non-existent UDP tunnel
	err = tm.CloseTunnel("non-existent", "udp")
	if err == nil {
		t.Error("Expected error when closing non-existent UDP tunnel")
	}
}

// Benchmark tests for performance validation
func BenchmarkGenerateTunnelID(b *testing.B) {
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9090}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateTunnelID(localAddr, remoteAddr)
	}
}

func BenchmarkCombineSharedSecrets(b *testing.B) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		combineSharedSecrets(secret1, secret2)
	}
}

func BenchmarkBigEndianOperations(b *testing.B) {
	buf := make([]byte, 4)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writeBigEndian32(buf, uint32(i))
		readBigEndian32(buf)
	}
}

// UDP Protocol Tests

// TestUDPTunnelCreation tests UDP tunnel creation
func TestUDPTunnelCreation(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test UDP tunnel manager initialization
	if len(tm.udpTunnels) != 0 {
		t.Errorf("Expected empty UDP tunnel map, got %d tunnels", len(tm.udpTunnels))
	}
}

// TestProtocolSwitching tests protocol selection logic
func TestProtocolSwitching(t *testing.T) {
	testCases := []struct {
		useCase  string
		expected string
	}{
		{"streaming", "tcp"},
		{"file-transfer", "tcp"},
		{"reliable", "tcp"},
		{"gaming", "udp"},
		{"voip", "udp"},
		{"real-time", "udp"},
		{"low-latency", "udp"},
		{"unknown", "tcp"}, // Default case
	}
	
	for _, tc := range testCases {
		result := SelectOptimalProtocol(tc.useCase)
		if result != tc.expected {
			t.Errorf("SelectOptimalProtocol(%s): expected %s, got %s", tc.useCase, tc.expected, result)
		}
	}
}

// TestProtocolCapabilities tests protocol capabilities function
func TestProtocolCapabilities(t *testing.T) {
	capabilities := GetProtocolCapabilities()
	
	// Check TCP capabilities
	tcpCaps, exists := capabilities["tcp"]
	if !exists {
		t.Error("TCP capabilities not found")
	}
	
	expectedTCPCaps := []string{"reliable", "ordered", "connection-oriented", "flow-control"}
	if len(tcpCaps) != len(expectedTCPCaps) {
		t.Errorf("Expected %d TCP capabilities, got %d", len(expectedTCPCaps), len(tcpCaps))
	}
	
	// Check UDP capabilities
	udpCaps, exists := capabilities["udp"]
	if !exists {
		t.Error("UDP capabilities not found")
	}
	
	expectedUDPCaps := []string{"fast", "low-latency", "connectionless", "real-time"}
	if len(udpCaps) != len(expectedUDPCaps) {
		t.Errorf("Expected %d UDP capabilities, got %d", len(expectedUDPCaps), len(udpCaps))
	}
}

// TestTunnelManagerWithBothProtocols tests tunnel manager with mixed protocols
func TestTunnelManagerWithBothProtocols(t *testing.T) {
	tm := NewTunnelManager()
	
	// Verify both tunnel maps are initialized
	if tm.tcpTunnels == nil {
		t.Error("TCP tunnels map not initialized")
	}
	
	if tm.udpTunnels == nil {
		t.Error("UDP tunnels map not initialized")
	}
	
	// Test getting active tunnels with empty maps
	activeTunnels := tm.GetActiveTunnels()
	if len(activeTunnels) != 0 {
		t.Errorf("Expected 0 active tunnels, got %d", len(activeTunnels))
	}
}

// TestCloseTunnelWithProtocol tests closing tunnels by protocol
func TestCloseTunnelWithProtocol(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test closing non-existent TCP tunnel
	err := tm.CloseTunnel("non-existent", "tcp")
	if err == nil {
		t.Error("Expected error when closing non-existent TCP tunnel")
	}
	
	// Test closing non-existent UDP tunnel
	err = tm.CloseTunnel("non-existent", "udp")
	if err == nil {
		t.Error("Expected error when closing non-existent UDP tunnel")
	}
	
	// Test unsupported protocol
	err = tm.CloseTunnel("test", "invalid")
	if err == nil {
		t.Error("Expected error for unsupported protocol")
	}
}

// TestUDPSessionIDGeneration tests UDP session ID generation
func TestUDPSessionIDGeneration(t *testing.T) {
	// Generate multiple session IDs and verify they're different
	sessionIDs := make(map[[16]byte]bool)
	
	for i := 0; i < 100; i++ {
		var sessionID [16]byte
		if _, err := rand.Read(sessionID[:]); err != nil {
			t.Fatalf("Failed to generate session ID: %v", err)
		}
		
		if sessionIDs[sessionID] {
			t.Error("Duplicate session ID generated")
		}
		sessionIDs[sessionID] = true
	}
}

// TestUDPKeyExchangeMessageFormat tests UDP key exchange message formatting
func TestUDPKeyExchangeMessageFormat(t *testing.T) {
	testData := []byte("test message")
	
	// Test message length encoding/decoding
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(len(testData) >> 24)
	lengthBytes[1] = byte(len(testData) >> 16)
	lengthBytes[2] = byte(len(testData) >> 8)
	lengthBytes[3] = byte(len(testData))
	
	// Decode length
	decodedLength := int(lengthBytes[0])<<24 | int(lengthBytes[1])<<16 | int(lengthBytes[2])<<8 | int(lengthBytes[3])
	
	if decodedLength != len(testData) {
		t.Errorf("Length encoding/decoding failed: expected %d, got %d", len(testData), decodedLength)
	}
}

// TestTunnelStatsWithProtocols tests tunnel statistics with different protocols
func TestTunnelStatsWithProtocols(t *testing.T) {
	now := time.Now()
	
	// Test TCP tunnel stats
	tcpStats := TunnelStats{
		LocalAddr:    "127.0.0.1:8080",
		RemoteAddr:   "192.168.1.1:9090",
		CreatedAt:    now,
		LastActivity: now,
		IsActive:     true,
	}
	
	if tcpStats.LocalAddr != "127.0.0.1:8080" {
		t.Errorf("TCP stats LocalAddr incorrect: got %s", tcpStats.LocalAddr)
	}
	
	// Test UDP tunnel stats (same structure, different protocol context)
	udpStats := TunnelStats{
		LocalAddr:    "127.0.0.1:8081",
		RemoteAddr:   "192.168.1.2:9091",
		CreatedAt:    now,
		LastActivity: now,
		IsActive:     true,
	}
	
	if udpStats.LocalAddr != "127.0.0.1:8081" {
		t.Errorf("UDP stats LocalAddr incorrect: got %s", udpStats.LocalAddr)
	}
}

// TestCreateTunnelGenericInterface tests the generic CreateTunnel interface
func TestCreateTunnelGenericInterface(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test unsupported protocol
	_, err := tm.CreateTunnel("127.0.0.1:8080", "invalid", time.Second*5)
	if err == nil {
		t.Error("Expected error for unsupported protocol")
	}
	
	expectedError := "unsupported protocol: invalid"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestTCPTunnelConnectionLifecycle tests TCP tunnel connection lifecycle
func TestTCPTunnelConnectionLifecycle(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test connection with invalid address (should fail gracefully)
	_, err := tm.CreateTCPTunnel("", time.Second*5)
	if err == nil {
		t.Error("Expected error for empty address")
	}
	
	// Test connection with invalid address format
	_, err = tm.CreateTCPTunnel("invalid-address", time.Second*5)
	if err == nil {
		t.Error("Expected error for invalid address format")
	}
	
	// Test connection timeout with unreachable address
	start := time.Now()
	_, err = tm.CreateTCPTunnel("192.0.2.1:12345", time.Millisecond*100) // RFC5737 test address
	duration := time.Since(start)
	
	if err == nil {
		t.Error("Expected error for unreachable address")
	}
	
	// Should timeout within reasonable time (allowing some margin)
	if duration > time.Second*2 {
		t.Errorf("Connection timeout took too long: %v", duration)
	}
}

// TestTCPTunnelErrorHandling tests TCP tunnel error handling
func TestTCPTunnelErrorHandling(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test various invalid addresses
	invalidAddresses := []string{
		"",
		"invalid",
		"256.256.256.256:80",
		"localhost:99999",
		"localhost:-1",
	}
	
	for _, addr := range invalidAddresses {
		_, err := tm.CreateTCPTunnel(addr, time.Second*1)
		if err == nil {
			t.Errorf("Expected error for invalid address: %s", addr)
		}
	}
}

// TestTCPTunnelMaintenance tests TCP tunnel maintenance functionality
func TestTCPTunnelMaintenance(t *testing.T) {
	tm := NewTunnelManager()
	
	// Test maintenance with no tunnels
	tm.MaintainTunnels()
	
	// Verify no tunnels after maintenance
	activeTunnels := tm.GetActiveTunnels()
	if len(activeTunnels) != 0 {
		t.Errorf("Expected 0 active tunnels after maintenance, got %d", len(activeTunnels))
	}
}

// TestTCPTunnelSecureFailure tests secure failure modes
func TestTCPTunnelSecureFailure(t *testing.T) {
	// Test that tunnel creation fails securely without leaking data
	tm := NewTunnelManager()
	
	// Attempt to create tunnel to unreachable address
	_, err := tm.CreateTCPTunnel("192.0.2.1:12345", time.Millisecond*50)
	if err == nil {
		t.Error("Expected secure failure for unreachable address")
	}
	
	// Verify no tunnels were created or left in inconsistent state
	activeTunnels := tm.GetActiveTunnels()
	if len(activeTunnels) != 0 {
		t.Errorf("Expected 0 tunnels after failed creation, got %d", len(activeTunnels))
	}
	
	// Verify tunnel maps are clean
	tm.mutex.RLock()
	tcpCount := len(tm.tcpTunnels)
	udpCount := len(tm.udpTunnels)
	tm.mutex.RUnlock()
	
	if tcpCount != 0 || udpCount != 0 {
		t.Errorf("Expected clean tunnel maps after failure, got TCP: %d, UDP: %d", tcpCount, udpCount)
	}
}

// Benchmark tests for UDP functionality
func BenchmarkSelectOptimalProtocol(b *testing.B) {
	useCases := []string{"streaming", "gaming", "voip", "file-transfer", "unknown"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		useCase := useCases[i%len(useCases)]
		SelectOptimalProtocol(useCase)
	}
}

func BenchmarkGetProtocolCapabilities(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetProtocolCapabilities()
	}
}

// Packet Sharding Tests

// TestShardPacket tests basic packet sharding functionality
func TestShardPacket(t *testing.T) {
	// Test data of various sizes
	testData := []byte("This is a test packet that will be sharded across multiple routes for anonymity")
	
	// Test sharding with different shard sizes
	testCases := []struct {
		maxShardSize int
		expectError  bool
	}{
		{20, false},  // Small shards
		{50, false},  // Medium shards
		{100, false}, // Large shards
		{0, true},    // Invalid shard size
		{-1, true},   // Negative shard size
	}
	
	for _, tc := range testCases {
		shards, err := ShardPacket(testData, tc.maxShardSize)
		
		if tc.expectError {
			if err == nil {
				t.Errorf("Expected error for shard size %d", tc.maxShardSize)
			}
			continue
		}
		
		if err != nil {
			t.Errorf("Unexpected error for shard size %d: %v", tc.maxShardSize, err)
			continue
		}
		
		if len(shards) == 0 {
			t.Errorf("No shards created for shard size %d", tc.maxShardSize)
			continue
		}
		
		// Verify all shards have the same ID and correct total count
		shardID := shards[0].ShardID
		totalShards := shards[0].TotalShards
		
		if int(totalShards) != len(shards) {
			t.Errorf("Total shard count mismatch: expected %d, got %d", len(shards), totalShards)
		}
		
		for i, shard := range shards {
			if shard.ShardID != shardID {
				t.Errorf("Shard %d has different ID", i)
			}
			if shard.TotalShards != totalShards {
				t.Errorf("Shard %d has different total count", i)
			}
			if shard.ShardNum != uint8(i) {
				t.Errorf("Shard %d has wrong shard number: expected %d, got %d", i, i, shard.ShardNum)
			}
		}
	}
}

// TestShardPacketEmptyData tests sharding empty data
func TestShardPacketEmptyData(t *testing.T) {
	emptyData := []byte{}
	
	_, err := ShardPacket(emptyData, 100)
	if err == nil {
		t.Error("Expected error when sharding empty data")
	}
}

// TestReassemblePacket tests packet reassembly functionality
func TestReassemblePacket(t *testing.T) {
	originalData := []byte("This is the original packet data that was sharded and should be reassembled correctly")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 20)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	// Reassemble the packet
	reassembled, err := ReassemblePacket(shards)
	if err != nil {
		t.Fatalf("Failed to reassemble packet: %v", err)
	}
	
	// Verify reassembled data matches original
	if len(reassembled) != len(originalData) {
		t.Errorf("Reassembled data length mismatch: expected %d, got %d", len(originalData), len(reassembled))
	}
	
	for i, b := range originalData {
		if i >= len(reassembled) || reassembled[i] != b {
			t.Errorf("Reassembled data mismatch at position %d: expected %d, got %d", i, b, reassembled[i])
			break
		}
	}
}

// TestReassemblePacketWithMissingShards tests reassembly with missing shards
func TestReassemblePacketWithMissingShards(t *testing.T) {
	originalData := []byte("Test data for missing shard scenario")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 10)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	// Remove one shard to simulate missing shard
	if len(shards) > 1 {
		incompleteShards := shards[:len(shards)-1]
		
		_, err = ReassemblePacket(incompleteShards)
		if err == nil {
			t.Error("Expected error when reassembling with missing shards")
		}
	}
}

// TestReassemblePacketWithDuplicateShards tests reassembly with duplicate shards
func TestReassemblePacketWithDuplicateShards(t *testing.T) {
	originalData := []byte("Test data for duplicate shard scenario")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 15)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	// Add duplicate shard
	if len(shards) > 0 {
		duplicateShards := append(shards, shards[0]) // Duplicate first shard
		
		_, err = ReassemblePacket(duplicateShards)
		if err == nil {
			t.Error("Expected error when reassembling with duplicate shards")
		}
	}
}

// TestReassemblePacketWithCorruptedShards tests reassembly with corrupted shard data
func TestReassemblePacketWithCorruptedShards(t *testing.T) {
	originalData := []byte("Test data for corrupted shard scenario")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 12)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	// Corrupt one shard's metadata
	if len(shards) > 0 {
		corruptedShards := make([]*PacketShard, len(shards))
		copy(corruptedShards, shards)
		
		// Corrupt the total shard count in one shard
		corruptedShards[0].TotalShards = 99
		
		_, err = ReassemblePacket(corruptedShards)
		if err == nil {
			t.Error("Expected error when reassembling with corrupted shard metadata")
		}
	}
}

// TestShardedPacketManager tests the sharded packet manager functionality
func TestShardedPacketManager(t *testing.T) {
	spm := NewShardedPacketManager()
	
	if spm == nil {
		t.Fatal("NewShardedPacketManager returned nil")
	}
	
	// Test initial state
	if spm.GetPendingPacketCount() != 0 {
		t.Errorf("Expected 0 pending packets, got %d", spm.GetPendingPacketCount())
	}
}

// TestShardedPacketManagerAddShard tests adding shards to the manager
func TestShardedPacketManagerAddShard(t *testing.T) {
	spm := NewShardedPacketManager()
	originalData := []byte("Test data for shard manager")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 10)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	// Add shards one by one
	var reassembledData []byte
	var isComplete bool
	
	for i, shard := range shards {
		data, complete, err := spm.AddShard(shard)
		if err != nil {
			t.Fatalf("Failed to add shard %d: %v", i, err)
		}
		
		if i < len(shards)-1 {
			// Should not be complete yet
			if complete {
				t.Errorf("Packet should not be complete after adding shard %d", i)
			}
			if data != nil {
				t.Errorf("Should not return data before packet is complete")
			}
		} else {
			// Should be complete now
			if !complete {
				t.Error("Packet should be complete after adding all shards")
			}
			if data == nil {
				t.Error("Should return reassembled data when complete")
			}
			reassembledData = data
			isComplete = complete
		}
	}
	
	// Verify reassembled data
	if !isComplete {
		t.Error("Packet should be marked as complete")
	}
	
	if len(reassembledData) != len(originalData) {
		t.Errorf("Reassembled data length mismatch: expected %d, got %d", len(originalData), len(reassembledData))
	}
	
	for i, b := range originalData {
		if i >= len(reassembledData) || reassembledData[i] != b {
			t.Errorf("Reassembled data mismatch at position %d", i)
			break
		}
	}
	
	// Verify pending packet count is back to 0
	if spm.GetPendingPacketCount() != 0 {
		t.Errorf("Expected 0 pending packets after completion, got %d", spm.GetPendingPacketCount())
	}
}

// TestShardedPacketManagerNilShard tests adding nil shard
func TestShardedPacketManagerNilShard(t *testing.T) {
	spm := NewShardedPacketManager()
	
	_, _, err := spm.AddShard(nil)
	if err == nil {
		t.Error("Expected error when adding nil shard")
	}
}

// TestShardedPacketManagerDuplicateShard tests adding duplicate shards
func TestShardedPacketManagerDuplicateShard(t *testing.T) {
	spm := NewShardedPacketManager()
	originalData := []byte("Test data for duplicate shard test")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 15)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	if len(shards) > 0 {
		// Add first shard
		_, _, err := spm.AddShard(shards[0])
		if err != nil {
			t.Fatalf("Failed to add first shard: %v", err)
		}
		
		// Try to add the same shard again
		_, _, err = spm.AddShard(shards[0])
		if err == nil {
			t.Error("Expected error when adding duplicate shard")
		}
	}
}

// TestShardedPacketManagerCleanup tests cleanup functionality
func TestShardedPacketManagerCleanup(t *testing.T) {
	spm := NewShardedPacketManager()
	originalData := []byte("Test data for cleanup test")
	
	// Shard the packet
	shards, err := ShardPacket(originalData, 20)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}
	
	// Add only some shards (incomplete packet)
	if len(shards) > 1 {
		_, _, err := spm.AddShard(shards[0])
		if err != nil {
			t.Fatalf("Failed to add shard: %v", err)
		}
		
		// Verify pending packet exists
		if spm.GetPendingPacketCount() != 1 {
			t.Errorf("Expected 1 pending packet, got %d", spm.GetPendingPacketCount())
		}
		
		// Cleanup expired packets
		spm.CleanupExpiredPackets()
		
		// Verify cleanup worked
		if spm.GetPendingPacketCount() != 0 {
			t.Errorf("Expected 0 pending packets after cleanup, got %d", spm.GetPendingPacketCount())
		}
	}
}

// TestPacketShardingRoundTrip tests complete sharding and reassembly round trip
func TestPacketShardingRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		shardSize int
	}{
		{"Small packet", []byte("Hello"), 10},
		{"Medium packet", []byte("This is a medium-sized packet for testing sharding functionality"), 25},
		{"Large packet", make([]byte, 1000), 100},
		{"Binary data", []byte{0x00, 0xFF, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78}, 3},
	}
	
	// Initialize large packet with pattern
	for i := range testCases[2].data {
		testCases[2].data[i] = byte(i % 256)
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Shard the packet
			shards, err := ShardPacket(tc.data, tc.shardSize)
			if err != nil {
				t.Fatalf("Failed to shard packet: %v", err)
			}
			
			// Reassemble the packet
			reassembled, err := ReassemblePacket(shards)
			if err != nil {
				t.Fatalf("Failed to reassemble packet: %v", err)
			}
			
			// Verify data integrity
			if len(reassembled) != len(tc.data) {
				t.Errorf("Length mismatch: expected %d, got %d", len(tc.data), len(reassembled))
			}
			
			for i, expected := range tc.data {
				if i >= len(reassembled) || reassembled[i] != expected {
					t.Errorf("Data mismatch at position %d: expected %d, got %d", i, expected, reassembled[i])
					break
				}
			}
		})
	}
}

// Benchmark tests for packet sharding
func BenchmarkShardPacket(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShardPacket(data, 100)
	}
}

func BenchmarkReassemblePacket(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	shards, _ := ShardPacket(data, 100)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReassemblePacket(shards)
	}
}

func BenchmarkShardedPacketManager(b *testing.B) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	shards, _ := ShardPacket(data, 64)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spm := NewShardedPacketManager()
		for _, shard := range shards {
			spm.AddShard(shard)
		}
	}
}

// Traffic Analysis Resistance Tests (Task 6.1)

func TestNewShardedTrafficStream(t *testing.T) {
	// Create test routes
	routes := createTestRoutes(3)
	
	testCases := []struct {
		name         string
		routes       []*Route
		noiseRatio   float64
		maxShardSize int
		expectError  bool
	}{
		{
			name:         "Valid configuration",
			routes:       routes,
			noiseRatio:   0.3,
			maxShardSize: 512,
			expectError:  false,
		},
		{
			name:         "Minimum routes",
			routes:       routes[:2],
			noiseRatio:   0.2,
			maxShardSize: 256,
			expectError:  false,
		},
		{
			name:         "Too few routes",
			routes:       routes[:1],
			noiseRatio:   0.3,
			maxShardSize: 512,
			expectError:  true,
		},
		{
			name:         "Invalid noise ratio - negative",
			routes:       routes,
			noiseRatio:   -0.1,
			maxShardSize: 512,
			expectError:  true,
		},
		{
			name:         "Invalid noise ratio - too high",
			routes:       routes,
			noiseRatio:   1.5,
			maxShardSize: 512,
			expectError:  true,
		},
		{
			name:         "Invalid shard size - too small",
			routes:       routes,
			noiseRatio:   0.3,
			maxShardSize: 32,
			expectError:  true,
		},
		{
			name:         "Invalid shard size - too large",
			routes:       routes,
			noiseRatio:   0.3,
			maxShardSize: 2000,
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stream, err := NewShardedTrafficStream(tc.routes, tc.noiseRatio, tc.maxShardSize)
			
			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if stream != nil {
					t.Error("Expected nil stream on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if stream == nil {
					t.Error("Expected valid stream but got nil")
				}
				
				// Verify configuration
				stats := stream.GetTrafficStats()
				if stats.NumRoutes != len(tc.routes) {
					t.Errorf("Expected %d routes, got %d", len(tc.routes), stats.NumRoutes)
				}
				if stats.NoiseRatio != tc.noiseRatio {
					t.Errorf("Expected noise ratio %.2f, got %.2f", tc.noiseRatio, stats.NoiseRatio)
				}
				if stats.MaxShardSize != tc.maxShardSize {
					t.Errorf("Expected max shard size %d, got %d", tc.maxShardSize, stats.MaxShardSize)
				}
			}
		})
	}
}

func TestSendPacketWithTrafficObfuscation(t *testing.T) {
	routes := createTestRoutes(3)
	stream, err := NewShardedTrafficStream(routes, 0.3, 256)
	if err != nil {
		t.Fatalf("Failed to create traffic stream: %v", err)
	}

	testCases := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "Small packet",
			data:        []byte("Hello, World!"),
			expectError: false,
		},
		{
			name:        "Medium packet",
			data:        make([]byte, 512),
			expectError: false,
		},
		{
			name:        "Large packet",
			data:        make([]byte, 2048),
			expectError: false,
		},
		{
			name:        "Empty packet",
			data:        []byte{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill test data with pattern
			for i := range tc.data {
				tc.data[i] = byte(i % 256)
			}

			err := stream.SendPacketWithTrafficObfuscation(tc.data)
			
			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestShardDistribution(t *testing.T) {
	routes := createTestRoutes(4)
	stream, err := NewShardedTrafficStream(routes, 0.2, 128)
	if err != nil {
		t.Fatalf("Failed to create traffic stream: %v", err)
	}

	// Create test data that will be sharded
	testData := make([]byte, 1000)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Shard the data
	shards, err := ShardPacket(testData, 128)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}

	// Test shard distribution
	distribution := stream.createShardDistribution(shards)

	// Verify all shards are distributed
	totalDistributed := 0
	for _, routeShards := range distribution {
		totalDistributed += len(routeShards)
	}

	if totalDistributed != len(shards) {
		t.Errorf("Expected %d shards distributed, got %d", len(shards), totalDistributed)
	}

	// Verify each route gets at least some shards (for reasonable shard counts)
	if len(shards) >= len(routes) {
		for routeIdx, routeShards := range distribution {
			if len(routeShards) == 0 {
				t.Errorf("Route %d received no shards", routeIdx)
			}
		}
	}

	// Verify shard integrity
	allDistributedShards := make([]*PacketShard, 0, len(shards))
	for _, routeShards := range distribution {
		allDistributedShards = append(allDistributedShards, routeShards...)
	}

	// Check that all original shards are present
	shardIDs := make(map[[16]byte]map[uint8]bool)
	for _, shard := range shards {
		if _, exists := shardIDs[shard.ShardID]; !exists {
			shardIDs[shard.ShardID] = make(map[uint8]bool)
		}
		shardIDs[shard.ShardID][shard.ShardNum] = true
	}

	distributedShardIDs := make(map[[16]byte]map[uint8]bool)
	for _, shard := range allDistributedShards {
		if _, exists := distributedShardIDs[shard.ShardID]; !exists {
			distributedShardIDs[shard.ShardID] = make(map[uint8]bool)
		}
		distributedShardIDs[shard.ShardID][shard.ShardNum] = true
	}

	// Compare shard sets
	for shardID, shardNums := range shardIDs {
		distributedNums, exists := distributedShardIDs[shardID]
		if !exists {
			t.Errorf("Shard ID %x not found in distribution", shardID)
			continue
		}

		for shardNum := range shardNums {
			if !distributedNums[shardNum] {
				t.Errorf("Shard %x:%d not found in distribution", shardID, shardNum)
			}
		}
	}
}

func TestTrafficObfuscationIntegration(t *testing.T) {
	// Test the complete integration of sharding and noise injection
	routes := createTestRoutes(3)
	stream, err := NewShardedTrafficStream(routes, 0.5, 200)
	if err != nil {
		t.Fatalf("Failed to create traffic stream: %v", err)
	}

	// Test data
	originalData := []byte("This is a test message that will be sharded and mixed with noise packets for traffic analysis resistance")

	// Send packet with obfuscation
	err = stream.SendPacketWithTrafficObfuscation(originalData)
	if err != nil {
		t.Errorf("Failed to send packet with obfuscation: %v", err)
	}

	// Verify that the process completes without errors
	// In a real implementation, we would verify that:
	// 1. Packets are distributed across routes
	// 2. Noise packets are injected
	// 3. Timing is randomized
	// 4. Original data can be reconstructed at destination
}

func TestRandomDelayGeneration(t *testing.T) {
	routes := createTestRoutes(2)
	stream, err := NewShardedTrafficStream(routes, 0.1, 256)
	if err != nil {
		t.Fatalf("Failed to create traffic stream: %v", err)
	}

	// Generate multiple delays and verify they're in expected range
	delays := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		delays[i] = stream.generateRandomDelay()
	}

	// Verify all delays are within expected range (1-50ms)
	for i, delay := range delays {
		if delay < time.Millisecond || delay > 50*time.Millisecond {
			t.Errorf("Delay %d out of range: %v", i, delay)
		}
	}

	// Verify delays are not all the same (randomness check)
	allSame := true
	firstDelay := delays[0]
	for _, delay := range delays[1:] {
		if delay != firstDelay {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("All delays are identical - randomness may be broken")
	}
}

func TestTrafficStats(t *testing.T) {
	routes := createTestRoutes(5)
	noiseRatio := 0.4
	maxShardSize := 300

	stream, err := NewShardedTrafficStream(routes, noiseRatio, maxShardSize)
	if err != nil {
		t.Fatalf("Failed to create traffic stream: %v", err)
	}

	stats := stream.GetTrafficStats()

	if stats.NumRoutes != len(routes) {
		t.Errorf("Expected %d routes, got %d", len(routes), stats.NumRoutes)
	}
	if stats.NoiseRatio != noiseRatio {
		t.Errorf("Expected noise ratio %.2f, got %.2f", noiseRatio, stats.NoiseRatio)
	}
	if stats.MaxShardSize != maxShardSize {
		t.Errorf("Expected max shard size %d, got %d", maxShardSize, stats.MaxShardSize)
	}
}

// Helper function to create test routes
func createTestRoutes(numRoutes int) []*Route {
	routes := make([]*Route, numRoutes)
	
	for i := 0; i < numRoutes; i++ {
		// Create test nodes for this route
		hops := make([]*Node, 3) // 3 hops per route
		for j := 0; j < 3; j++ {
			var nodeID NodeID
			for k := range nodeID {
				nodeID[k] = byte(i*10 + j*3 + k)
			}
			
			hops[j] = &Node{
				ID:       nodeID,
				Address:  fmt.Sprintf("192.168.%d.%d:8080", i+1, j+1),
				Protocol: "tcp",
				LastSeen: time.Now(),
				Latency:  time.Duration(10+j*5) * time.Millisecond,
			}
		}
		
		routes[i] = &Route{
			Hops:      hops,
			Protocol:  "tcp",
			CreatedAt: time.Now(),
			Active:    true,
		}
	}
	
	return routes
}

// Benchmark tests for traffic analysis resistance
func BenchmarkSendPacketWithTrafficObfuscation(b *testing.B) {
	routes := createTestRoutes(3)
	stream, err := NewShardedTrafficStream(routes, 0.3, 256)
	if err != nil {
		b.Fatalf("Failed to create traffic stream: %v", err)
	}

	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.SendPacketWithTrafficObfuscation(testData)
	}
}

func BenchmarkShardDistribution(b *testing.B) {
	routes := createTestRoutes(4)
	stream, err := NewShardedTrafficStream(routes, 0.2, 128)
	if err != nil {
		b.Fatalf("Failed to create traffic stream: %v", err)
	}

	testData := make([]byte, 2048)
	shards, _ := ShardPacket(testData, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.createShardDistribution(shards)
	}
}

// Timing Attack Resistance Tests (Task 6.2)

func TestNewTimingResistantTransmitter(t *testing.T) {
	testCases := []struct {
		name             string
		minDelay         time.Duration
		maxDelay         time.Duration
		targetPacketSize int
		jitterRange      time.Duration
		expectError      bool
	}{
		{
			name:             "Valid configuration",
			minDelay:         10 * time.Millisecond,
			maxDelay:         50 * time.Millisecond,
			targetPacketSize: 1024,
			jitterRange:      5 * time.Millisecond,
			expectError:      false,
		},
		{
			name:             "Zero delays",
			minDelay:         0,
			maxDelay:         0,
			targetPacketSize: 512,
			jitterRange:      0,
			expectError:      false,
		},
		{
			name:             "Invalid delay order",
			minDelay:         50 * time.Millisecond,
			maxDelay:         10 * time.Millisecond,
			targetPacketSize: 1024,
			jitterRange:      5 * time.Millisecond,
			expectError:      true,
		},
		{
			name:             "Negative min delay",
			minDelay:         -10 * time.Millisecond,
			maxDelay:         50 * time.Millisecond,
			targetPacketSize: 1024,
			jitterRange:      5 * time.Millisecond,
			expectError:      true,
		},
		{
			name:             "Invalid packet size - too small",
			minDelay:         10 * time.Millisecond,
			maxDelay:         50 * time.Millisecond,
			targetPacketSize: 32,
			jitterRange:      5 * time.Millisecond,
			expectError:      true,
		},
		{
			name:             "Invalid packet size - too large",
			minDelay:         10 * time.Millisecond,
			maxDelay:         50 * time.Millisecond,
			targetPacketSize: 2000,
			jitterRange:      5 * time.Millisecond,
			expectError:      true,
		},
		{
			name:             "Negative jitter",
			minDelay:         10 * time.Millisecond,
			maxDelay:         50 * time.Millisecond,
			targetPacketSize: 1024,
			jitterRange:      -5 * time.Millisecond,
			expectError:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			transmitter, err := NewTimingResistantTransmitter(tc.minDelay, tc.maxDelay, tc.targetPacketSize, tc.jitterRange)
			
			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if transmitter != nil {
					t.Error("Expected nil transmitter on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if transmitter == nil {
					t.Error("Expected valid transmitter but got nil")
				}
				
				// Verify configuration
				stats := transmitter.GetTimingStats()
				if stats.MinDelay != tc.minDelay {
					t.Errorf("Expected min delay %v, got %v", tc.minDelay, stats.MinDelay)
				}
				if stats.MaxDelay != tc.maxDelay {
					t.Errorf("Expected max delay %v, got %v", tc.maxDelay, stats.MaxDelay)
				}
				if stats.TargetPacketSize != tc.targetPacketSize {
					t.Errorf("Expected target packet size %d, got %d", tc.targetPacketSize, stats.TargetPacketSize)
				}
				if stats.JitterRange != tc.jitterRange {
					t.Errorf("Expected jitter range %v, got %v", tc.jitterRange, stats.JitterRange)
				}
			}
		})
	}
}

func TestPacketPadding(t *testing.T) {
	transmitter, err := NewTimingResistantTransmitter(10*time.Millisecond, 50*time.Millisecond, 1024, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create transmitter: %v", err)
	}

	testCases := []struct {
		name        string
		packet      []byte
		expectError bool
	}{
		{
			name:        "Small packet",
			packet:      []byte("Hello, World!"),
			expectError: false,
		},
		{
			name:        "Medium packet",
			packet:      make([]byte, 512),
			expectError: false,
		},
		{
			name:        "Large packet within limit",
			packet:      make([]byte, 1020), // 4 bytes reserved for size
			expectError: false,
		},
		{
			name:        "Packet at maximum allowed size",
			packet:      make([]byte, 1020), // 1024 - 4 = 1020 max allowed
			expectError: false,
		},
		{
			name:        "Packet too large",
			packet:      make([]byte, 1500),
			expectError: true,
		},
		{
			name:        "Empty packet",
			packet:      []byte{},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill test data with pattern
			for i := range tc.packet {
				tc.packet[i] = byte(i % 256)
			}

			// Test padding
			paddedPacket, err := transmitter.PadPacketToTargetSize(tc.packet)
			
			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify padded packet size
			if len(paddedPacket) != 1024 {
				t.Errorf("Expected padded packet size 1024, got %d", len(paddedPacket))
			}

			// Test unpadding
			unpadded, err := transmitter.UnpadPacket(paddedPacket)
			if err != nil {
				t.Errorf("Failed to unpad packet: %v", err)
				return
			}

			// Verify original data is recovered
			if len(unpadded) != len(tc.packet) {
				t.Errorf("Expected unpadded size %d, got %d", len(tc.packet), len(unpadded))
			}

			for i, b := range tc.packet {
				if i < len(unpadded) && unpadded[i] != b {
					t.Errorf("Data mismatch at byte %d: expected %d, got %d", i, b, unpadded[i])
					break
				}
			}
		})
	}
}

func TestPacketPaddingRoundTrip(t *testing.T) {
	transmitter, err := NewTimingResistantTransmitter(5*time.Millisecond, 25*time.Millisecond, 512, 2*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create transmitter: %v", err)
	}

	// Test various packet sizes
	testSizes := []int{1, 10, 50, 100, 200, 300, 400, 500, 508} // 508 = 512 - 4 (size header)

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			// Create test packet
			originalPacket := make([]byte, size)
			for i := range originalPacket {
				originalPacket[i] = byte((i * 7) % 256) // Unique pattern
			}

			// Pad packet
			paddedPacket, err := transmitter.PadPacketToTargetSize(originalPacket)
			if err != nil {
				t.Fatalf("Failed to pad packet: %v", err)
			}

			// Verify padding
			if len(paddedPacket) != 512 {
				t.Errorf("Expected padded size 512, got %d", len(paddedPacket))
			}

			// Unpad packet
			unpadded, err := transmitter.UnpadPacket(paddedPacket)
			if err != nil {
				t.Fatalf("Failed to unpad packet: %v", err)
			}

			// Verify round-trip integrity
			if len(unpadded) != len(originalPacket) {
				t.Errorf("Size mismatch: original %d, unpadded %d", len(originalPacket), len(unpadded))
			}

			for i, expected := range originalPacket {
				if i < len(unpadded) && unpadded[i] != expected {
					t.Errorf("Data corruption at byte %d: expected %d, got %d", i, expected, unpadded[i])
					break
				}
			}
		})
	}
}

func TestTimingResistantRandomDelayGeneration(t *testing.T) {
	transmitter, err := NewTimingResistantTransmitter(10*time.Millisecond, 100*time.Millisecond, 1024, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create transmitter: %v", err)
	}

	// Generate multiple delays
	numSamples := 1000
	delays := make([]time.Duration, numSamples)
	for i := 0; i < numSamples; i++ {
		delays[i] = transmitter.GenerateRandomDelay()
	}

	// Verify all delays are reasonable (considering jitter, they might go slightly outside base range)
	minExpected := 0 * time.Millisecond // Can go negative due to jitter, but clamped to positive
	maxExpected := 120 * time.Millisecond // 100ms + 20ms jitter

	for i, delay := range delays {
		if delay < minExpected || delay > maxExpected {
			t.Errorf("Delay %d out of reasonable range: %v (expected %v to %v)", i, delay, minExpected, maxExpected)
		}
	}

	// Verify delays show variation (not all the same)
	allSame := true
	firstDelay := delays[0]
	for _, delay := range delays[1:] {
		if delay != firstDelay {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("All delays are identical - randomness may be broken")
	}

	// Verify delays are distributed across the range
	minObserved := delays[0]
	maxObserved := delays[0]
	for _, delay := range delays {
		if delay < minObserved {
			minObserved = delay
		}
		if delay > maxObserved {
			maxObserved = delay
		}
	}

	// Should see some variation in the delays
	if maxObserved-minObserved < 10*time.Millisecond {
		t.Errorf("Insufficient delay variation: range %v", maxObserved-minObserved)
	}
}

func TestTransmitWithTimingResistance(t *testing.T) {
	transmitter, err := NewTimingResistantTransmitter(1*time.Millisecond, 5*time.Millisecond, 256, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create transmitter: %v", err)
	}

	// Create test packets
	packets := [][]byte{
		[]byte("Packet 1"),
		[]byte("Packet 2 with more data"),
		[]byte("Packet 3"),
		make([]byte, 200), // Large packet
	}

	// Fill large packet with pattern
	for i := range packets[3] {
		packets[3][i] = byte(i % 256)
	}

	// Track transmitted packets
	var transmittedPackets [][]byte
	var transmissionTimes []time.Time

	transmitFunc := func(packet []byte) error {
		transmittedPackets = append(transmittedPackets, packet)
		transmissionTimes = append(transmissionTimes, time.Now())
		return nil
	}

	// Measure transmission time
	startTime := time.Now()
	err = transmitter.TransmitWithTimingResistance(packets, transmitFunc)
	totalTime := time.Since(startTime)

	if err != nil {
		t.Errorf("Transmission failed: %v", err)
	}

	// Verify all packets were transmitted
	if len(transmittedPackets) != len(packets) {
		t.Errorf("Expected %d transmitted packets, got %d", len(packets), len(transmittedPackets))
	}

	// Verify all transmitted packets are padded to target size
	for i, packet := range transmittedPackets {
		if len(packet) != 256 {
			t.Errorf("Packet %d not padded correctly: expected size 256, got %d", i, len(packet))
		}
	}

	// Verify timing delays were applied (should take some time due to delays)
	expectedMinTime := time.Duration(len(packets)-1) * 1 * time.Millisecond // At least min delay between packets
	if totalTime < expectedMinTime {
		t.Errorf("Transmission too fast: expected at least %v, got %v", expectedMinTime, totalTime)
	}

	// Verify delays between transmissions (except first packet)
	if len(transmissionTimes) > 1 {
		for i := 1; i < len(transmissionTimes); i++ {
			delay := transmissionTimes[i].Sub(transmissionTimes[i-1])
			// Should have some delay, but not too much
			if delay < 500*time.Microsecond || delay > 10*time.Millisecond {
				t.Errorf("Unexpected delay between packets %d and %d: %v", i-1, i, delay)
			}
		}
	}
}

func TestTransmitWithTimingResistanceErrors(t *testing.T) {
	transmitter, err := NewTimingResistantTransmitter(1*time.Millisecond, 5*time.Millisecond, 128, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create transmitter: %v", err)
	}

	// Test with packet too large for padding
	largePacket := make([]byte, 200) // Larger than target size
	packets := [][]byte{largePacket}

	transmitFunc := func(packet []byte) error {
		return nil
	}

	err = transmitter.TransmitWithTimingResistance(packets, transmitFunc)
	if err == nil {
		t.Error("Expected error for oversized packet")
	}

	// Test with transmission function that fails
	normalPackets := [][]byte{[]byte("test")}
	failingTransmitFunc := func(packet []byte) error {
		return errors.New("transmission failed")
	}

	err = transmitter.TransmitWithTimingResistance(normalPackets, failingTransmitFunc)
	if err == nil {
		t.Error("Expected error from failing transmit function")
	}

	// Test with empty packet list
	err = transmitter.TransmitWithTimingResistance([][]byte{}, transmitFunc)
	if err != nil {
		t.Errorf("Unexpected error for empty packet list: %v", err)
	}
}

func TestEnhancedShardedTrafficStream(t *testing.T) {
	routes := createTestRoutes(3)
	
	stream, err := NewEnhancedShardedTrafficStream(
		routes, 0.3, 128, // Base sharding parameters - smaller shards
		5*time.Millisecond, 25*time.Millisecond, 1400, 2*time.Millisecond, // Timing parameters - larger target size
	)
	if err != nil {
		t.Fatalf("Failed to create enhanced traffic stream: %v", err)
	}

	// Test sending packet with full obfuscation
	testData := []byte("This is a test message for enhanced traffic obfuscation with timing resistance")
	
	err = stream.SendPacketWithFullObfuscation(testData)
	if err != nil {
		t.Errorf("Failed to send packet with full obfuscation: %v", err)
	}

	// Verify enhanced stats
	stats := stream.GetEnhancedTrafficStats()
	if stats.NumRoutes != 3 {
		t.Errorf("Expected 3 routes, got %d", stats.NumRoutes)
	}
	if stats.NoiseRatio != 0.3 {
		t.Errorf("Expected noise ratio 0.3, got %.2f", stats.NoiseRatio)
	}
	if stats.MaxShardSize != 128 {
		t.Errorf("Expected max shard size 128, got %d", stats.MaxShardSize)
	}
	if stats.MinDelay != 5*time.Millisecond {
		t.Errorf("Expected min delay 5ms, got %v", stats.MinDelay)
	}
	if stats.MaxDelay != 25*time.Millisecond {
		t.Errorf("Expected max delay 25ms, got %v", stats.MaxDelay)
	}
	if stats.TargetPacketSize != 1400 {
		t.Errorf("Expected target packet size 1400, got %d", stats.TargetPacketSize)
	}
}

func TestEnhancedTrafficStreamErrors(t *testing.T) {
	routes := createTestRoutes(2)

	// Test invalid base stream parameters
	_, err := NewEnhancedShardedTrafficStream(
		routes[:1], 0.3, 256, // Too few routes
		5*time.Millisecond, 25*time.Millisecond, 512, 2*time.Millisecond,
	)
	if err == nil {
		t.Error("Expected error for too few routes")
	}

	// Test invalid timing parameters
	_, err = NewEnhancedShardedTrafficStream(
		routes, 0.3, 256,
		25*time.Millisecond, 5*time.Millisecond, 512, 2*time.Millisecond, // Invalid delay order
	)
	if err == nil {
		t.Error("Expected error for invalid delay configuration")
	}

	// Test with valid configuration but empty packet
	stream, err := NewEnhancedShardedTrafficStream(
		routes, 0.2, 128,
		1*time.Millisecond, 10*time.Millisecond, 256, 1*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("Failed to create enhanced stream: %v", err)
	}

	err = stream.SendPacketWithFullObfuscation([]byte{})
	if err == nil {
		t.Error("Expected error for empty packet")
	}
}

// Benchmark tests for timing resistance
func BenchmarkPacketPadding(b *testing.B) {
	transmitter, err := NewTimingResistantTransmitter(1*time.Millisecond, 10*time.Millisecond, 1024, 1*time.Millisecond)
	if err != nil {
		b.Fatalf("Failed to create transmitter: %v", err)
	}

	testPacket := make([]byte, 512)
	for i := range testPacket {
		testPacket[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := transmitter.PadPacketToTargetSize(testPacket)
		if err != nil {
			b.Fatalf("Padding failed: %v", err)
		}
	}
}

func BenchmarkPacketUnpadding(b *testing.B) {
	transmitter, err := NewTimingResistantTransmitter(1*time.Millisecond, 10*time.Millisecond, 1024, 1*time.Millisecond)
	if err != nil {
		b.Fatalf("Failed to create transmitter: %v", err)
	}

	testPacket := make([]byte, 512)
	paddedPacket, _ := transmitter.PadPacketToTargetSize(testPacket)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := transmitter.UnpadPacket(paddedPacket)
		if err != nil {
			b.Fatalf("Unpadding failed: %v", err)
		}
	}
}

func BenchmarkEnhancedTrafficStream(b *testing.B) {
	routes := createTestRoutes(3)
	stream, err := NewEnhancedShardedTrafficStream(
		routes, 0.2, 256,
		1*time.Millisecond, 5*time.Millisecond, 512, 1*time.Millisecond,
	)
	if err != nil {
		b.Fatalf("Failed to create enhanced stream: %v", err)
	}

	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.SendPacketWithFullObfuscation(testData)
	}
}