package direct

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestNewOPSECNetworkLayer(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	if layer == nil {
		t.Fatal("NewOPSECNetworkLayer returned nil")
	}
	
	// Check default configuration
	if layer.baseConnectionDelay != 100*time.Millisecond {
		t.Errorf("Expected base connection delay 100ms, got %v", layer.baseConnectionDelay)
	}
	
	if layer.jitterFactor != 0.3 {
		t.Errorf("Expected jitter factor 0.3, got %v", layer.jitterFactor)
	}
	
	if !layer.enablePadding {
		t.Error("Expected padding to be enabled by default")
	}
}

func TestNewOPSECNetworkLayerWithConfig(t *testing.T) {
	config := &TrafficObfuscationConfig{
		EnablePadding:      false,
		PaddingMinSize:     32,
		PaddingMaxSize:     512,
		NoiseInjectionRate: 0.2,
		EnableSharding:     false,
		MaxShardSize:       2048,
		MinShardSize:       128,
	}
	
	layer := NewOPSECNetworkLayerWithConfig(config)
	
	if layer.enablePadding {
		t.Error("Expected padding to be disabled")
	}
	
	if layer.paddingMinSize != 32 {
		t.Errorf("Expected padding min size 32, got %d", layer.paddingMinSize)
	}
	
	if layer.noiseInjectionRate != 0.2 {
		t.Errorf("Expected noise injection rate 0.2, got %v", layer.noiseInjectionRate)
	}
}

func TestCalculateConnectionDelay(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test multiple delays to ensure randomization
	delays := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		delays[i] = layer.CalculateConnectionDelay()
	}
	
	// Check that delays are within expected range
	for i, delay := range delays {
		if delay < 0 {
			t.Errorf("Delay %d is negative: %v", i, delay)
		}
		
		// Should be at least base delay minus jitter
		minExpected := time.Duration(float64(layer.baseConnectionDelay) * 0.7) // 30% jitter
		if delay < minExpected {
			t.Errorf("Delay %d too small: %v (expected >= %v)", i, delay, minExpected)
		}
		
		// Should not exceed max delay plus jitter
		maxExpected := time.Duration(float64(layer.maxConnectionDelay) * 1.3) // 30% jitter
		if delay > maxExpected {
			t.Errorf("Delay %d too large: %v (expected <= %v)", i, delay, maxExpected)
		}
	}
	
	// Check that delays are different (randomized)
	allSame := true
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[0] {
			allSame = false
			break
		}
	}
	
	if allSame {
		t.Error("All delays are the same - randomization not working")
	}
}

func TestCalculateRetryDelay(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test exponential backoff
	delay1 := layer.CalculateRetryDelay(1)
	delay2 := layer.CalculateRetryDelay(2)
	_ = layer.CalculateRetryDelay(3) // Test that it doesn't panic
	
	// Delays should generally increase (accounting for jitter)
	if delay1 <= 0 {
		t.Errorf("First retry delay should be positive, got %v", delay1)
	}
	
	// Second delay should be roughly double the first (accounting for jitter)
	expectedDelay2 := 2 * layer.baseRetryDelay
	if delay2 < expectedDelay2/2 || delay2 > expectedDelay2*2 {
		t.Errorf("Second retry delay %v not in expected range around %v", delay2, expectedDelay2)
	}
	
	// Test zero attempt
	delay0 := layer.CalculateRetryDelay(0)
	if delay0 != 0 {
		t.Errorf("Zero attempt should return zero delay, got %v", delay0)
	}
}

func TestAddRandomJitter(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	baseDelay := 1 * time.Second
	
	// Test multiple jitter applications
	jitteredDelays := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		jitteredDelays[i] = layer.AddRandomJitter(baseDelay)
	}
	
	// Check that all delays are positive
	for i, delay := range jitteredDelays {
		if delay < 0 {
			t.Errorf("Jittered delay %d is negative: %v", i, delay)
		}
	}
	
	// Check that delays vary (randomization working)
	allSame := true
	for i := 1; i < len(jitteredDelays); i++ {
		if jitteredDelays[i] != jitteredDelays[0] {
			allSame = false
			break
		}
	}
	
	if allSame {
		t.Error("All jittered delays are the same - randomization not working")
	}
}

func TestShouldRetry(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test with network error (should retry)
	networkErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	if !layer.ShouldRetry(1, networkErr) {
		t.Error("Should retry on network error")
	}
	
	// Test with too many attempts (should not retry)
	if layer.ShouldRetry(10, networkErr) {
		t.Error("Should not retry after too many attempts")
	}
	
	// Test with cryptographic error (should not retry)
	cryptoErr := NewCryptographicError(ErrCodeKeyExchangeFailure, "Key exchange failed", "test")
	if layer.ShouldRetry(1, cryptoErr) {
		t.Error("Should not retry on cryptographic error")
	}
}

func TestObfuscateAndDeobfuscateTraffic(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	originalData := []byte("Hello, World! This is test data for traffic obfuscation.")
	
	// Test obfuscation
	obfuscatedData, err := layer.ObfuscateTraffic(originalData)
	if err != nil {
		t.Fatalf("ObfuscateTraffic failed: %v", err)
	}
	
	// Obfuscated data should be different from original (due to padding)
	if bytes.Equal(originalData, obfuscatedData) {
		t.Error("Obfuscated data is identical to original data")
	}
	
	// Test deobfuscation
	deobfuscatedData, err := layer.DeobfuscateTraffic(obfuscatedData)
	if err != nil {
		t.Fatalf("DeobfuscateTraffic failed: %v", err)
	}
	
	// Deobfuscated data should match original
	if !bytes.Equal(originalData, deobfuscatedData) {
		t.Errorf("Deobfuscated data doesn't match original.\nOriginal: %s\nDeobfuscated: %s", 
			string(originalData), string(deobfuscatedData))
	}
}

func TestObfuscateEmptyData(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	emptyData := []byte{}
	
	obfuscated, err := layer.ObfuscateTraffic(emptyData)
	if err != nil {
		t.Fatalf("ObfuscateTraffic failed on empty data: %v", err)
	}
	
	deobfuscated, err := layer.DeobfuscateTraffic(obfuscated)
	if err != nil {
		t.Fatalf("DeobfuscateTraffic failed on empty data: %v", err)
	}
	
	if !bytes.Equal(emptyData, deobfuscated) {
		t.Error("Empty data not preserved through obfuscation/deobfuscation")
	}
}

func TestGenerateSecureKeepAlive(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	keepAlive1, interval1 := layer.GenerateSecureKeepAlive()
	keepAlive2, interval2 := layer.GenerateSecureKeepAlive()
	
	// Check that keep-alive packets are generated
	if len(keepAlive1) == 0 {
		t.Error("Keep-alive packet is empty")
	}
	
	if len(keepAlive2) == 0 {
		t.Error("Keep-alive packet is empty")
	}
	
	// Check that packets have keep-alive marker
	if !layer.IsKeepAlivePacket(keepAlive1) {
		t.Error("Generated packet is not recognized as keep-alive")
	}
	
	if !layer.IsKeepAlivePacket(keepAlive2) {
		t.Error("Generated packet is not recognized as keep-alive")
	}
	
	// Check that intervals are positive
	if interval1 <= 0 {
		t.Errorf("Keep-alive interval should be positive, got %v", interval1)
	}
	
	if interval2 <= 0 {
		t.Errorf("Keep-alive interval should be positive, got %v", interval2)
	}
	
	// Check that packets and intervals vary (randomization)
	if bytes.Equal(keepAlive1, keepAlive2) {
		t.Error("Keep-alive packets are identical - randomization not working")
	}
	
	if interval1 == interval2 {
		t.Error("Keep-alive intervals are identical - randomization not working")
	}
}

func TestIsKeepAlivePacket(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test with keep-alive packet
	keepAlive, _ := layer.GenerateSecureKeepAlive()
	if !layer.IsKeepAlivePacket(keepAlive) {
		t.Error("Failed to identify keep-alive packet")
	}
	
	// Test with regular data
	regularData := []byte("This is regular data")
	if layer.IsKeepAlivePacket(regularData) {
		t.Error("Regular data incorrectly identified as keep-alive")
	}
	
	// Test with empty data
	emptyData := []byte{}
	if layer.IsKeepAlivePacket(emptyData) {
		t.Error("Empty data incorrectly identified as keep-alive")
	}
}

func TestShardAndReassemblePacket(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test with data that should be sharded
	largeData := make([]byte, 2048) // Larger than max shard size
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	
	// Shard the packet
	shards, err := layer.ShardPacket(largeData)
	if err != nil {
		t.Fatalf("ShardPacket failed: %v", err)
	}
	
	// Should have multiple shards
	if len(shards) <= 1 {
		t.Error("Large data should be split into multiple shards")
	}
	
	// Reassemble the shards
	reassembled, err := layer.ReassembleShards(shards)
	if err != nil {
		t.Fatalf("ReassembleShards failed: %v", err)
	}
	
	// Reassembled data should match original
	if !bytes.Equal(largeData, reassembled) {
		t.Error("Reassembled data doesn't match original")
	}
}

func TestShardSmallPacket(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test with small data that shouldn't be sharded
	smallData := []byte("Small data")
	
	shards, err := layer.ShardPacket(smallData)
	if err != nil {
		t.Fatalf("ShardPacket failed: %v", err)
	}
	
	// Should have only one shard
	if len(shards) != 1 {
		t.Errorf("Small data should not be sharded, got %d shards", len(shards))
	}
	
	// Shard should be identical to original data
	if !bytes.Equal(smallData, shards[0]) {
		t.Error("Single shard doesn't match original data")
	}
}

func TestRetryStateManagement(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	connectionID := "test-connection-123"
	
	// Initially no retry state
	state := layer.GetRetryState(connectionID)
	if state != nil {
		t.Error("Should have no retry state initially")
	}
	
	// Update retry state
	testErr := NewNetworkError(ErrCodeConnectionTimeout, "Test error", "test", true)
	layer.UpdateRetryState(connectionID, 1, testErr)
	
	// Should now have retry state
	state = layer.GetRetryState(connectionID)
	if state == nil {
		t.Fatal("Should have retry state after update")
	}
	
	if state.AttemptCount != 1 {
		t.Errorf("Expected attempt count 1, got %d", state.AttemptCount)
	}
	
	if state.LastError != testErr {
		t.Error("Last error not stored correctly")
	}
	
	// Update with more attempts
	layer.UpdateRetryState(connectionID, 3, testErr)
	state = layer.GetRetryState(connectionID)
	if state.AttemptCount != 3 {
		t.Errorf("Expected attempt count 3, got %d", state.AttemptCount)
	}
}

func TestCleanupRetryState(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Add some retry states
	layer.UpdateRetryState("conn1", 1, nil)
	layer.UpdateRetryState("conn2", 1, nil)
	
	// Verify they exist
	if layer.GetRetryState("conn1") == nil {
		t.Error("conn1 state should exist")
	}
	if layer.GetRetryState("conn2") == nil {
		t.Error("conn2 state should exist")
	}
	
	// Cleanup with very short max age (should remove all)
	layer.CleanupRetryState(1 * time.Nanosecond)
	
	// States should be cleaned up
	if layer.GetRetryState("conn1") != nil {
		t.Error("conn1 state should be cleaned up")
	}
	if layer.GetRetryState("conn2") != nil {
		t.Error("conn2 state should be cleaned up")
	}
}

func TestConfigurationMethods(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Test timing configuration
	layer.SetTimingConfiguration(
		200*time.Millisecond, // base connection
		10*time.Second,       // max connection
		2*time.Second,        // base retry
		600*time.Second,      // max retry
		0.5,                  // jitter factor
	)
	
	if layer.baseConnectionDelay != 200*time.Millisecond {
		t.Error("Base connection delay not updated")
	}
	
	if layer.jitterFactor != 0.5 {
		t.Error("Jitter factor not updated")
	}
	
	// Test traffic obfuscation configuration
	config := &TrafficObfuscationConfig{
		EnablePadding:      false,
		PaddingMinSize:     64,
		PaddingMaxSize:     1024,
		NoiseInjectionRate: 0.05,
		EnableSharding:     false,
		MaxShardSize:       4096,
		MinShardSize:       256,
	}
	
	layer.SetTrafficObfuscationConfiguration(config)
	
	if layer.enablePadding {
		t.Error("Padding should be disabled")
	}
	
	if layer.paddingMinSize != 64 {
		t.Error("Padding min size not updated")
	}
	
	// Test keep-alive configuration
	layer.SetKeepAliveConfiguration(60*time.Second, 15*time.Second)
	
	if layer.keepAliveInterval != 60*time.Second {
		t.Error("Keep-alive interval not updated")
	}
	
	if layer.keepAliveJitter != 15*time.Second {
		t.Error("Keep-alive jitter not updated")
	}
}

func TestGetConfiguration(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	config := layer.GetConfiguration()
	
	// Check that configuration contains expected keys
	expectedKeys := []string{
		"base_connection_delay",
		"max_connection_delay",
		"base_retry_delay",
		"max_retry_delay",
		"jitter_factor",
		"enable_padding",
		"padding_min_size",
		"padding_max_size",
		"noise_injection_rate",
		"keep_alive_interval",
		"keep_alive_jitter",
		"enable_sharding",
		"max_shard_size",
		"min_shard_size",
	}
	
	for _, key := range expectedKeys {
		if _, exists := config[key]; !exists {
			t.Errorf("Configuration missing key: %s", key)
		}
	}
}

func TestErrorClassification(t *testing.T) {
	// Test temporary error detection
	tempErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	if !IsTemporaryError(tempErr) {
		t.Error("Connection timeout should be classified as temporary")
	}
	
	// Test blocking error detection
	blockingErr := NewOPSECError(ErrCodeSuspiciousPattern, "Suspicious pattern", "test")
	if !IsBlockingError(blockingErr) {
		t.Error("Suspicious pattern should be classified as blocking")
	}
	
	// Test non-temporary error
	cryptoErr := NewCryptographicError(ErrCodeKeyExchangeFailure, "Key exchange failed", "test")
	if IsTemporaryError(cryptoErr) {
		t.Error("Cryptographic error should not be classified as temporary")
	}
}

func TestGetOPSECMetrics(t *testing.T) {
	layer := NewOPSECNetworkLayer()
	
	// Add some retry states
	layer.UpdateRetryState("conn1", 1, nil)
	layer.UpdateRetryState("conn2", 2, nil)
	
	metrics := layer.GetOPSECMetrics()
	
	if metrics == nil {
		t.Fatal("GetOPSECMetrics returned nil")
	}
	
	if metrics.ActiveConnections != 2 {
		t.Errorf("Expected 2 active connections, got %d", metrics.ActiveConnections)
	}
	
	if metrics.TrafficObfuscated != layer.enablePadding {
		t.Error("Traffic obfuscated flag doesn't match layer configuration")
	}
}

// Tests for RetryManager functionality

func TestNewRetryManager(t *testing.T) {
	rm := NewRetryManager()
	
	if rm == nil {
		t.Fatal("NewRetryManager returned nil")
	}
	
	if rm.maxRetries != 5 {
		t.Errorf("Expected max retries 5, got %d", rm.maxRetries)
	}
	
	if rm.baseDelay != 1*time.Second {
		t.Errorf("Expected base delay 1s, got %v", rm.baseDelay)
	}
	
	if rm.rateLimitWindow != 60*time.Second {
		t.Errorf("Expected rate limit window 60s, got %v", rm.rateLimitWindow)
	}
}

func TestShouldRetryConnection_BasicRetry(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-conn-1"
	remoteAddr := "192.168.1.100:8080"
	
	// Test first attempt with retryable error
	retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	decision, err := rm.ShouldRetryConnection(connectionID, 1, retryableErr, remoteAddr)
	
	if err != nil {
		t.Fatalf("ShouldRetryConnection failed: %v", err)
	}
	
	if !decision.ShouldRetry {
		t.Error("Should retry on first attempt with retryable error")
	}
	
	if decision.Delay <= 0 {
		t.Error("Retry delay should be positive")
	}
	
	if decision.RiskLevel != "low" {
		t.Errorf("Expected low risk level for first attempt, got %s", decision.RiskLevel)
	}
}

func TestShouldRetryConnection_MaxRetriesExceeded(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-conn-2"
	remoteAddr := "192.168.1.100:8080"
	
	retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	
	// Test with attempt count exceeding max retries
	decision, err := rm.ShouldRetryConnection(connectionID, 10, retryableErr, remoteAddr)
	
	if err != nil {
		t.Fatalf("ShouldRetryConnection failed: %v", err)
	}
	
	if decision.ShouldRetry {
		t.Error("Should not retry when max retries exceeded")
	}
	
	if decision.Reason != "Maximum retry attempts exceeded" {
		t.Errorf("Expected max retries reason, got: %s", decision.Reason)
	}
}

func TestShouldRetryConnection_NonRetryableError(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-conn-3"
	remoteAddr := "192.168.1.100:8080"
	
	// Test with non-retryable error
	cryptoErr := NewCryptographicError(ErrCodeKeyExchangeFailure, "Key exchange failed", "test")
	decision, err := rm.ShouldRetryConnection(connectionID, 1, cryptoErr, remoteAddr)
	
	if err != nil {
		t.Fatalf("ShouldRetryConnection failed: %v", err)
	}
	
	if decision.ShouldRetry {
		t.Error("Should not retry on non-retryable error")
	}
	
	if decision.Reason != "Error is not retryable" {
		t.Errorf("Expected non-retryable reason, got: %s", decision.Reason)
	}
}

func TestShouldRetryConnection_BlockingError(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-conn-4"
	remoteAddr := "192.168.1.100:8080"
	
	// Test with blocking error
	opsecErr := NewOPSECError(ErrCodeSuspiciousPattern, "Suspicious pattern detected", "test")
	decision, err := rm.ShouldRetryConnection(connectionID, 1, opsecErr, remoteAddr)
	
	if err != nil {
		t.Fatalf("ShouldRetryConnection failed: %v", err)
	}
	
	if decision.ShouldRetry {
		t.Error("Should not retry on blocking error")
	}
	
	if decision.RiskLevel != "high" {
		t.Errorf("Expected high risk level for blocking error, got %s", decision.RiskLevel)
	}
	
	if len(decision.Recommendations) == 0 {
		t.Error("Expected recommendations for blocking error")
	}
}

func TestRateLimiting(t *testing.T) {
	rm := NewRetryManager()
	rm.maxAttemptsPerWindow = 3 // Lower limit for testing
	rm.rateLimitWindow = 1 * time.Second
	
	connectionID := "test-conn-rate-limit"
	remoteAddr := "192.168.1.100:8080"
	retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	
	// Make attempts up to the limit
	for i := 1; i <= 3; i++ {
		decision, err := rm.ShouldRetryConnection(connectionID, i, retryableErr, remoteAddr)
		if err != nil {
			t.Fatalf("ShouldRetryConnection failed on attempt %d: %v", i, err)
		}
		
		if !decision.ShouldRetry {
			t.Errorf("Should retry on attempt %d (within rate limit)", i)
		}
	}
	
	// Next attempt should be rate limited
	decision, err := rm.ShouldRetryConnection(connectionID, 4, retryableErr, remoteAddr)
	if err != nil {
		t.Fatalf("ShouldRetryConnection failed: %v", err)
	}
	
	if decision.ShouldRetry {
		t.Error("Should not retry when rate limited")
	}
	
	if decision.Reason != "Rate limited to avoid suspicious patterns" {
		t.Errorf("Expected rate limit reason, got: %s", decision.Reason)
	}
}

func TestSuspiciousPatternDetection(t *testing.T) {
	rm := NewRetryManager()
	rm.suspiciousPatternThreshold = 1 // Very low threshold for testing
	
	connectionID := "test-conn-suspicious"
	remoteAddr := "192.168.1.100:8080"
	
	// Create rapid successive failures to trigger suspicious pattern
	// Use very small delays to ensure rapid pattern detection
	for i := 1; i <= 5; i++ {
		retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
		_, err := rm.ShouldRetryConnection(connectionID, i, retryableErr, remoteAddr)
		if err != nil {
			t.Fatalf("ShouldRetryConnection failed on attempt %d: %v", i, err)
		}
		
		// Very small delay to create rapid pattern (less than 10 seconds total)
		time.Sleep(100 * time.Microsecond)
	}
	
	// Next attempt should detect suspicious pattern
	retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	decision, err := rm.ShouldRetryConnection(connectionID, 6, retryableErr, remoteAddr)
	if err != nil {
		t.Fatalf("ShouldRetryConnection failed: %v", err)
	}
	
	if decision.ShouldRetry {
		t.Error("Should not retry when suspicious patterns detected")
	}
	
	if decision.RiskLevel != "high" {
		t.Errorf("Expected high risk level for suspicious patterns, got %s", decision.RiskLevel)
	}
}

func TestRetryDelayCalculation(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-conn-delay"
	
	// Test exponential backoff
	delay1 := rm.calculateOPSECRetryDelay(connectionID, 1)
	delay2 := rm.calculateOPSECRetryDelay(connectionID, 2)
	delay3 := rm.calculateOPSECRetryDelay(connectionID, 3)
	
	// Delays should generally increase (accounting for jitter)
	if delay1 <= 0 {
		t.Error("First delay should be positive")
	}
	
	// Second delay should be roughly double (accounting for jitter)
	expectedDelay2 := 2 * rm.baseDelay
	if delay2 < expectedDelay2/2 || delay2 > expectedDelay2*3 {
		t.Errorf("Second delay %v not in expected range around %v", delay2, expectedDelay2)
	}
	
	// Third delay should be roughly quadruple (accounting for jitter)
	expectedDelay3 := 4 * rm.baseDelay
	if delay3 < expectedDelay3/2 || delay3 > expectedDelay3*3 {
		t.Errorf("Third delay %v not in expected range around %v", delay3, expectedDelay3)
	}
}

func TestRetryManagerErrorClassification(t *testing.T) {
	rm := NewRetryManager()
	
	// Test retryable errors
	timeoutErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	if !rm.isRetryableError(timeoutErr) {
		t.Error("Timeout error should be retryable")
	}
	
	// Test non-retryable errors
	cryptoErr := NewCryptographicError(ErrCodeKeyExchangeFailure, "Key exchange failed", "test")
	if rm.isRetryableError(cryptoErr) {
		t.Error("Cryptographic error should not be retryable")
	}
	
	// Test blocking errors
	opsecErr := NewOPSECError(ErrCodeSuspiciousPattern, "Suspicious pattern", "test")
	if !rm.isBlockingError(opsecErr) {
		t.Error("OPSEC error should be blocking")
	}
	
	// Test error classification
	if rm.classifyError(timeoutErr) != "timeout" {
		t.Error("Timeout error not classified correctly")
	}
}

func TestCleanupRetryHistory(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-conn-cleanup"
	remoteAddr := "192.168.1.100:8080"
	
	// Add some retry history
	retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	for i := 1; i <= 3; i++ {
		_, err := rm.ShouldRetryConnection(connectionID, i, retryableErr, remoteAddr)
		if err != nil {
			t.Fatalf("ShouldRetryConnection failed: %v", err)
		}
	}
	
	// Verify history exists
	if len(rm.attemptHistory[connectionID]) != 3 {
		t.Errorf("Expected 3 attempts in history, got %d", len(rm.attemptHistory[connectionID]))
	}
	
	// Cleanup with very short max age
	rm.CleanupRetryHistory(1 * time.Nanosecond)
	
	// History should be cleaned up
	if len(rm.attemptHistory[connectionID]) != 0 {
		t.Error("Retry history should be cleaned up")
	}
}

func TestGetRetryStatistics(t *testing.T) {
	rm := NewRetryManager()
	
	// Add some retry attempts
	connectionIDs := []string{"conn1", "conn2", "conn3"}
	remoteAddr := "192.168.1.100:8080"
	retryableErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	
	for _, connID := range connectionIDs {
		for i := 1; i <= 2; i++ {
			_, err := rm.ShouldRetryConnection(connID, i, retryableErr, remoteAddr)
			if err != nil {
				t.Fatalf("ShouldRetryConnection failed: %v", err)
			}
		}
	}
	
	stats := rm.GetRetryStatistics()
	
	if stats.ActiveConnections != 3 {
		t.Errorf("Expected 3 active connections, got %d", stats.ActiveConnections)
	}
	
	if stats.TotalAttempts != 6 {
		t.Errorf("Expected 6 total attempts, got %d", stats.TotalAttempts)
	}
	
	expectedAvg := 2.0
	if stats.AverageAttemptsPerConnection != expectedAvg {
		t.Errorf("Expected average %.1f, got %.1f", expectedAvg, stats.AverageAttemptsPerConnection)
	}
}

func TestPatternDetection(t *testing.T) {
	rm := NewRetryManager()
	
	// Create attempts with rapid successive failures
	attempts := []*ConnectionAttempt{
		{Timestamp: time.Now().Add(-30 * time.Second), Error: NewNetworkError(ErrCodeConnectionTimeout, "timeout", "test", true)},
		{Timestamp: time.Now().Add(-25 * time.Second), Error: NewNetworkError(ErrCodeConnectionTimeout, "timeout", "test", true)},
		{Timestamp: time.Now().Add(-20 * time.Second), Error: NewNetworkError(ErrCodeConnectionTimeout, "timeout", "test", true)},
	}
	
	patterns := rm.detectPatterns(attempts)
	
	// Should detect rapid successive failures
	found := false
	for _, pattern := range patterns {
		if pattern == "rapid_successive_failures" {
			found = true
			break
		}
	}
	
	if !found {
		t.Error("Should detect rapid successive failures pattern")
	}
}

func TestRiskLevelAssessment(t *testing.T) {
	rm := NewRetryManager()
	connectionID := "test-risk-assessment"
	
	// Test low risk (few attempts)
	risk1 := rm.assessRiskLevel(connectionID, 1)
	if risk1 != "low" {
		t.Errorf("Expected low risk for 1 attempt, got %s", risk1)
	}
	
	// Test medium risk (moderate attempts)
	risk3 := rm.assessRiskLevel(connectionID, 3)
	if risk3 != "medium" {
		t.Errorf("Expected medium risk for 3 attempts, got %s", risk3)
	}
	
	// Test high risk (many attempts)
	risk5 := rm.assessRiskLevel(connectionID, 5)
	if risk5 != "high" {
		t.Errorf("Expected high risk for 5 attempts, got %s", risk5)
	}
}

// Tests for secure logging and monitoring functionality

func TestNewOPSECLogger(t *testing.T) {
	logger := NewOPSECLogger()
	
	if logger == nil {
		t.Fatal("NewOPSECLogger returned nil")
	}
	
	if logger.logLevel != LogLevelInfo {
		t.Errorf("Expected log level Info, got %v", logger.logLevel)
	}
	
	if logger.maxAuditEvents != 1000 {
		t.Errorf("Expected max audit events 1000, got %d", logger.maxAuditEvents)
	}
	
	// Check that all categories are enabled by default
	for category := LogCategoryConnection; category <= LogCategoryAudit; category++ {
		if !logger.enabledCategories[category] {
			t.Errorf("Category %v should be enabled by default", category)
		}
	}
	
	// Check that default sanitization rules are added
	if len(logger.sanitizationRules) == 0 {
		t.Error("Expected default sanitization rules to be added")
	}
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelError, "ERROR"},
		{LogLevelWarn, "WARN"},
		{LogLevelInfo, "INFO"},
		{LogLevelDebug, "DEBUG"},
	}
	
	for _, test := range tests {
		if test.level.String() != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, test.level.String())
		}
	}
}

func TestLogCategoryString(t *testing.T) {
	tests := []struct {
		category LogCategory
		expected string
	}{
		{LogCategoryConnection, "CONNECTION"},
		{LogCategoryRetry, "RETRY"},
		{LogCategorySecurity, "SECURITY"},
		{LogCategoryPerformance, "PERFORMANCE"},
		{LogCategoryDiagnostic, "DIAGNOSTIC"},
		{LogCategoryAudit, "AUDIT"},
	}
	
	for _, test := range tests {
		if test.category.String() != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, test.category.String())
		}
	}
}

func TestOPSECLoggerSetLogLevel(t *testing.T) {
	logger := NewOPSECLogger()
	
	logger.SetLogLevel(LogLevelError)
	if logger.logLevel != LogLevelError {
		t.Errorf("Expected log level Error, got %v", logger.logLevel)
	}
	
	logger.SetLogLevel(LogLevelDebug)
	if logger.logLevel != LogLevelDebug {
		t.Errorf("Expected log level Debug, got %v", logger.logLevel)
	}
}

func TestOPSECLoggerEnableCategory(t *testing.T) {
	logger := NewOPSECLogger()
	
	// Disable a category
	logger.EnableCategory(LogCategoryConnection, false)
	if logger.enabledCategories[LogCategoryConnection] {
		t.Error("Connection category should be disabled")
	}
	
	// Re-enable it
	logger.EnableCategory(LogCategoryConnection, true)
	if !logger.enabledCategories[LogCategoryConnection] {
		t.Error("Connection category should be enabled")
	}
}

func TestLogConnectionEvent(t *testing.T) {
	logger := NewOPSECLogger()
	
	metadata := map[string]interface{}{
		"protocol": "tcp",
		"port":     8080,
	}
	
	// This should not panic and should handle the logging
	logger.LogConnectionEvent("conn-123", "established", "Connection successful", metadata)
	
	// Test with nil metadata
	logger.LogConnectionEvent("conn-456", "closed", "Connection closed", nil)
}

func TestLogRetryEvent(t *testing.T) {
	logger := NewOPSECLogger()
	
	decision := &RetryDecision{
		ShouldRetry: true,
		Delay:       5 * time.Second,
		Reason:      "Network timeout",
		RiskLevel:   "medium",
	}
	
	err := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	
	// This should not panic
	logger.LogRetryEvent("conn-123", 2, decision, err)
	
	// Test with nil error
	logger.LogRetryEvent("conn-456", 1, decision, nil)
}

func TestLogSecurityEvent(t *testing.T) {
	logger := NewOPSECLogger()
	
	metadata := map[string]interface{}{
		"pattern_type": "rapid_retry",
		"attempts":     5,
	}
	
	// This should not panic and should add to audit trail
	logger.LogSecurityEvent("suspicious_pattern", "Rapid retry pattern detected", "high", metadata)
	
	// Check that audit event was added
	auditTrail := logger.GetAuditTrail()
	if len(auditTrail) != 1 {
		t.Errorf("Expected 1 audit event, got %d", len(auditTrail))
	}
	
	if auditTrail[0].EventType != "suspicious_pattern" {
		t.Errorf("Expected event type 'suspicious_pattern', got %s", auditTrail[0].EventType)
	}
	
	if auditTrail[0].RiskLevel != "high" {
		t.Errorf("Expected risk level 'high', got %s", auditTrail[0].RiskLevel)
	}
}

func TestAuditTrailLimit(t *testing.T) {
	logger := NewOPSECLogger()
	logger.maxAuditEvents = 3 // Set low limit for testing
	
	// Add more events than the limit
	for i := 0; i < 5; i++ {
		logger.LogSecurityEvent(fmt.Sprintf("event_%d", i), "Test event", "low", nil)
	}
	
	auditTrail := logger.GetAuditTrail()
	if len(auditTrail) != 3 {
		t.Errorf("Expected audit trail to be limited to 3 events, got %d", len(auditTrail))
	}
	
	// Check that the latest events are kept
	if auditTrail[0].EventType != "event_2" {
		t.Errorf("Expected first event to be 'event_2', got %s", auditTrail[0].EventType)
	}
}

func TestClassifyErrorForLogging(t *testing.T) {
	logger := NewOPSECLogger()
	
	// Test with DirectModeError
	directErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)
	classification := logger.classifyErrorForLogging(directErr)
	if classification != "network" {
		t.Errorf("Expected 'network', got %s", classification)
	}
	
	// Test with nil error
	classification = logger.classifyErrorForLogging(nil)
	if classification != "none" {
		t.Errorf("Expected 'none' for nil error, got %s", classification)
	}
	
	// Test with generic error
	genericErr := fmt.Errorf("connection timeout occurred")
	classification = logger.classifyErrorForLogging(genericErr)
	if classification != "timeout" {
		t.Errorf("Expected 'timeout', got %s", classification)
	}
}

func TestConnectionHealthMonitor(t *testing.T) {
	monitor := NewConnectionHealthMonitor()
	
	if monitor == nil {
		t.Fatal("NewConnectionHealthMonitor returned nil")
	}
	
	connectionID := "test-conn-health"
	
	// Initially no health data
	health := monitor.GetHealth(connectionID)
	if health != nil {
		t.Error("Should have no health data initially")
	}
	
	// Update health with success
	monitor.UpdateHealth(connectionID, 100*time.Millisecond, true)
	
	health = monitor.GetHealth(connectionID)
	if health == nil {
		t.Fatal("Should have health data after update")
	}
	
	if health.ConnectionID != connectionID {
		t.Errorf("Expected connection ID %s, got %s", connectionID, health.ConnectionID)
	}
	
	if health.SuccessCount != 1 {
		t.Errorf("Expected success count 1, got %d", health.SuccessCount)
	}
	
	if health.ErrorCount != 0 {
		t.Errorf("Expected error count 0, got %d", health.ErrorCount)
	}
	
	if health.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", health.Status)
	}
}

func TestConnectionHealthScoring(t *testing.T) {
	monitor := NewConnectionHealthMonitor()
	monitor.alertThresholds.MaxErrorRate = 0.25 // 25% error rate threshold for this test
	connectionID := "test-conn-scoring"
	
	// Add successful requests
	for i := 0; i < 8; i++ {
		monitor.UpdateHealth(connectionID, 50*time.Millisecond, true)
	}
	
	// Add some failures (20% error rate, below threshold)
	for i := 0; i < 2; i++ {
		monitor.UpdateHealth(connectionID, 50*time.Millisecond, false)
	}
	
	health := monitor.GetHealth(connectionID)
	if health == nil {
		t.Fatal("Should have health data")
	}
	
	// Health score should be 0.8 (8 successes out of 10 total)
	expectedScore := 0.8
	if health.HealthScore != expectedScore {
		t.Errorf("Expected health score %.1f, got %.1f", expectedScore, health.HealthScore)
	}
	
	// Status should be healthy (error rate below threshold)
	if health.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", health.Status)
	}
}

func TestConnectionHealthDegradation(t *testing.T) {
	monitor := NewConnectionHealthMonitor()
	monitor.alertThresholds.MaxErrorRate = 0.3 // 30% error rate threshold
	
	connectionID := "test-conn-degraded"
	
	// Add requests with high error rate
	for i := 0; i < 3; i++ {
		monitor.UpdateHealth(connectionID, 50*time.Millisecond, true)
	}
	for i := 0; i < 7; i++ {
		monitor.UpdateHealth(connectionID, 50*time.Millisecond, false)
	}
	
	health := monitor.GetHealth(connectionID)
	if health == nil {
		t.Fatal("Should have health data")
	}
	
	// Status should be degraded due to high error rate
	if health.Status != "degraded" {
		t.Errorf("Expected status 'degraded', got %s", health.Status)
	}
}

func TestHealthSummary(t *testing.T) {
	monitor := NewConnectionHealthMonitor()
	
	// Add healthy connection (100% success rate)
	for i := 0; i < 10; i++ {
		monitor.UpdateHealth("conn-healthy", 50*time.Millisecond, true)
	}
	
	// Add degraded connection (50% error rate, above 10% threshold)
	for i := 0; i < 5; i++ {
		monitor.UpdateHealth("conn-degraded", 50*time.Millisecond, true)
	}
	for i := 0; i < 5; i++ {
		monitor.UpdateHealth("conn-degraded", 50*time.Millisecond, false)
	}
	
	summary := monitor.GetHealthSummary()
	if summary == nil {
		t.Fatal("GetHealthSummary returned nil")
	}
	
	if summary.TotalConnections != 2 {
		t.Errorf("Expected 2 total connections, got %d", summary.TotalConnections)
	}
	
	if summary.HealthyConnections != 1 {
		t.Errorf("Expected 1 healthy connection, got %d", summary.HealthyConnections)
	}
	
	if summary.DegradedConnections != 1 {
		t.Errorf("Expected 1 degraded connection, got %d", summary.DegradedConnections)
	}
}

func TestDiagnosticCollector(t *testing.T) {
	collector := NewDiagnosticCollector()
	
	if collector == nil {
		t.Fatal("NewDiagnosticCollector returned nil")
	}
	
	connectionID := "test-conn-diagnostic"
	
	// Initially no diagnostic data
	diagnostic := collector.GetDiagnostics(connectionID)
	if diagnostic != nil {
		t.Error("Should have no diagnostic data initially")
	}
	
	// Collect diagnostics
	networkMetrics := &NetworkMetrics{
		BytesSent:       1024,
		BytesReceived:   2048,
		PacketsSent:     10,
		PacketsReceived: 20,
		AverageLatency:  50 * time.Millisecond,
		PacketLossRate:  0.01,
	}
	
	perfMetrics := &PerformanceMetrics{
		ConnectionTime:    100 * time.Millisecond,
		Throughput:        1000000, // 1 Mbps
		CPUUsage:          25.5,
		MemoryUsage:       1024 * 1024, // 1 MB
		ActiveConnections: 5,
	}
	
	errors := []error{
		NewNetworkError(ErrCodeConnectionTimeout, "Timeout", "test", true),
		fmt.Errorf("generic error"),
	}
	
	collector.CollectDiagnostics(connectionID, networkMetrics, perfMetrics, errors)
	
	diagnostic = collector.GetDiagnostics(connectionID)
	if diagnostic == nil {
		t.Fatal("Should have diagnostic data after collection")
	}
	
	if diagnostic.ConnectionID != connectionID {
		t.Errorf("Expected connection ID %s, got %s", connectionID, diagnostic.ConnectionID)
	}
	
	if diagnostic.NetworkMetrics.BytesSent != 1024 {
		t.Errorf("Expected bytes sent 1024, got %d", diagnostic.NetworkMetrics.BytesSent)
	}
	
	if diagnostic.PerformanceMetrics.Throughput != 1000000 {
		t.Errorf("Expected throughput 1000000, got %.0f", diagnostic.PerformanceMetrics.Throughput)
	}
	
	if diagnostic.ErrorSummary.TotalErrors != 2 {
		t.Errorf("Expected 2 total errors, got %d", diagnostic.ErrorSummary.TotalErrors)
	}
}

func TestErrorSummaryCreation(t *testing.T) {
	collector := NewDiagnosticCollector()
	
	errors := []error{
		NewNetworkError(ErrCodeConnectionTimeout, "Timeout 1", "test", true),
		NewNetworkError(ErrCodeConnectionTimeout, "Timeout 2", "test", true),
		NewCryptographicError(ErrCodeKeyExchangeFailure, "Crypto error", "test"),
		fmt.Errorf("connection refused"),
		nil, // Should be ignored
	}
	
	summary := collector.createErrorSummary(errors)
	
	if summary.TotalErrors != 4 { // nil error should be ignored
		t.Errorf("Expected 4 total errors, got %d", summary.TotalErrors)
	}
	
	// Check error type classification
	if summary.ErrorsByType["network"] != 2 {
		t.Errorf("Expected 2 network errors, got %d", summary.ErrorsByType["network"])
	}
	
	if summary.ErrorsByType["cryptographic"] != 1 {
		t.Errorf("Expected 1 cryptographic error, got %d", summary.ErrorsByType["cryptographic"])
	}
	
	if summary.ErrorsByType["connection"] != 1 {
		t.Errorf("Expected 1 connection error, got %d", summary.ErrorsByType["connection"])
	}
}

func TestOPSECLoggerIntegration(t *testing.T) {
	logger := NewOPSECLogger()
	
	// Test connection health monitoring
	logger.UpdateConnectionHealth("conn-integration", 100*time.Millisecond, true)
	health := logger.GetConnectionHealth("conn-integration")
	
	if health == nil {
		t.Fatal("Should have health data")
	}
	
	if health.SuccessCount != 1 {
		t.Errorf("Expected 1 success, got %d", health.SuccessCount)
	}
	
	// Test diagnostic collection
	networkMetrics := &NetworkMetrics{
		BytesSent:     512,
		BytesReceived: 1024,
	}
	
	perfMetrics := &PerformanceMetrics{
		Throughput: 500000,
	}
	
	logger.CollectDiagnostics("conn-integration", networkMetrics, perfMetrics, nil)
	diagnostic := logger.GetDiagnostics("conn-integration")
	
	if diagnostic == nil {
		t.Fatal("Should have diagnostic data")
	}
	
	if diagnostic.NetworkMetrics.BytesSent != 512 {
		t.Errorf("Expected bytes sent 512, got %d", diagnostic.NetworkMetrics.BytesSent)
	}
	
	// Test health summary
	summary := logger.GetHealthSummary()
	if summary.TotalConnections != 1 {
		t.Errorf("Expected 1 connection in summary, got %d", summary.TotalConnections)
	}
}