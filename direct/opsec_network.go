package direct

import (
	"crypto/rand"
	"fmt"
	"math"
	mathrand "math/rand"
	"sync"
	"time"
)

// OPSECNetworkLayerImpl implements the OPSECNetworkLayer interface
type OPSECNetworkLayerImpl struct {
	// Connection timing configuration
	baseConnectionDelay time.Duration
	maxConnectionDelay  time.Duration
	baseRetryDelay      time.Duration
	maxRetryDelay       time.Duration
	jitterFactor        float64

	// Traffic obfuscation configuration
	enablePadding       bool
	paddingMinSize      int
	paddingMaxSize      int
	noiseInjectionRate  float64

	// Keep-alive configuration
	keepAliveInterval   time.Duration
	keepAliveJitter     time.Duration

	// Retry state tracking
	retryState          map[string]*RetryState
	retryMutex          sync.RWMutex

	// Random source for timing variations
	randSource          *mathrand.Rand
	randMutex           sync.Mutex

	// Packet sharding configuration
	enableSharding      bool
	maxShardSize        int
	minShardSize        int

	mutex               sync.RWMutex
}

// RetryState tracks retry attempts for connections
type RetryState struct {
	AttemptCount        int
	FirstAttemptTime    time.Time
	LastAttemptTime     time.Time
	LastError           error
	BackoffMultiplier   float64
	SuspiciousPatterns  []SuspiciousPattern
}

// SuspiciousPattern represents a detected suspicious retry pattern
type SuspiciousPattern struct {
	Type        string
	DetectedAt  time.Time
	Description string
	Severity    string
}

// TrafficObfuscationConfig holds configuration for traffic obfuscation
type TrafficObfuscationConfig struct {
	EnablePadding      bool
	PaddingMinSize     int
	PaddingMaxSize     int
	NoiseInjectionRate float64
	EnableSharding     bool
	MaxShardSize       int
	MinShardSize       int
}

// NewOPSECNetworkLayer creates a new OPSEC network layer with default configuration
func NewOPSECNetworkLayer() *OPSECNetworkLayerImpl {
	// Create a seeded random source for timing variations
	seed := time.Now().UnixNano()
	randSource := mathrand.New(mathrand.NewSource(seed))

	return &OPSECNetworkLayerImpl{
		// Default timing configuration
		baseConnectionDelay: 100 * time.Millisecond,
		maxConnectionDelay:  5 * time.Second,
		baseRetryDelay:      1 * time.Second,
		maxRetryDelay:       300 * time.Second, // 5 minutes max
		jitterFactor:        0.3, // 30% jitter

		// Default traffic obfuscation configuration
		enablePadding:       true,
		paddingMinSize:      16,
		paddingMaxSize:      256,
		noiseInjectionRate:  0.1, // 10% noise injection rate

		// Default keep-alive configuration
		keepAliveInterval:   30 * time.Second,
		keepAliveJitter:     10 * time.Second,

		// Default packet sharding configuration
		enableSharding:      true,
		maxShardSize:        1024,
		minShardSize:        64,

		// Initialize state tracking
		retryState:          make(map[string]*RetryState),
		randSource:          randSource,
	}
}

// NewOPSECNetworkLayerWithConfig creates a new OPSEC network layer with custom configuration
func NewOPSECNetworkLayerWithConfig(config *TrafficObfuscationConfig) *OPSECNetworkLayerImpl {
	layer := NewOPSECNetworkLayer()
	
	if config != nil {
		layer.enablePadding = config.EnablePadding
		layer.paddingMinSize = config.PaddingMinSize
		layer.paddingMaxSize = config.PaddingMaxSize
		layer.noiseInjectionRate = config.NoiseInjectionRate
		layer.enableSharding = config.EnableSharding
		layer.maxShardSize = config.MaxShardSize
		layer.minShardSize = config.MinShardSize
	}

	return layer
}

// CalculateConnectionDelay implements randomized connection delays to prevent timing analysis
func (o *OPSECNetworkLayerImpl) CalculateConnectionDelay() time.Duration {
	o.randMutex.Lock()
	defer o.randMutex.Unlock()

	// Generate a random delay between base and max
	delayRange := o.maxConnectionDelay - o.baseConnectionDelay
	randomDelay := time.Duration(o.randSource.Int63n(int64(delayRange)))
	baseDelay := o.baseConnectionDelay + randomDelay

	// Add jitter to prevent predictable patterns (inline to avoid mutex deadlock)
	jitterRange := time.Duration(float64(baseDelay) * o.jitterFactor)
	jitter := time.Duration(o.randSource.Int63n(int64(2*jitterRange))) - jitterRange
	
	result := baseDelay + jitter
	
	// Ensure result is not negative
	if result < 0 {
		result = time.Duration(o.randSource.Int63n(int64(baseDelay/2)))
	}

	return result
}

// CalculateRetryDelay implements exponential backoff with random jitter for connection retries
func (o *OPSECNetworkLayerImpl) CalculateRetryDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	o.randMutex.Lock()
	defer o.randMutex.Unlock()

	// Exponential backoff: baseDelay * 2^(attempt-1)
	exponentialDelay := float64(o.baseRetryDelay) * math.Pow(2, float64(attempt-1))
	
	// Cap at maximum retry delay
	if exponentialDelay > float64(o.maxRetryDelay) {
		exponentialDelay = float64(o.maxRetryDelay)
	}

	baseDelay := time.Duration(exponentialDelay)
	
	// Add jitter to prevent thundering herd and timing correlation (inline)
	jitterRange := time.Duration(float64(baseDelay) * o.jitterFactor)
	jitter := time.Duration(o.randSource.Int63n(int64(2*jitterRange))) - jitterRange
	
	result := baseDelay + jitter
	
	// Ensure result is not negative
	if result < 0 {
		result = time.Duration(o.randSource.Int63n(int64(baseDelay/2)))
	}

	return result
}

// AddRandomJitter adds random jitter to a base delay to prevent timing correlation
func (o *OPSECNetworkLayerImpl) AddRandomJitter(baseDelay time.Duration) time.Duration {
	o.randMutex.Lock()
	defer o.randMutex.Unlock()

	// Calculate jitter range (±jitterFactor of base delay)
	jitterRange := time.Duration(float64(baseDelay) * o.jitterFactor)
	
	// Generate random jitter between -jitterRange and +jitterRange
	jitter := time.Duration(o.randSource.Int63n(int64(2*jitterRange))) - jitterRange
	
	result := baseDelay + jitter
	
	// Ensure result is not negative
	if result < 0 {
		result = time.Duration(o.randSource.Int63n(int64(baseDelay/2)))
	}

	return result
}

// ShouldRetry determines if a connection should be retried based on OPSEC considerations
func (o *OPSECNetworkLayerImpl) ShouldRetry(attempt int, lastError error) bool {
	// Maximum retry attempts to avoid suspicious patterns
	const maxRetryAttempts = 5
	
	if attempt >= maxRetryAttempts {
		return false
	}

	// Check for suspicious patterns that might indicate detection
	if o.detectSuspiciousPattern(attempt, lastError) {
		return false
	}

	// Allow retry for network-related errors
	return IsNetworkError(lastError) || IsTemporaryError(lastError)
}

// GetNextRetryTime calculates the next retry time with OPSEC considerations
func (o *OPSECNetworkLayerImpl) GetNextRetryTime(attempt int) time.Time {
	delay := o.CalculateRetryDelay(attempt)
	return time.Now().Add(delay)
}

// ResetRetryState resets the retry state for a connection
func (o *OPSECNetworkLayerImpl) ResetRetryState() {
	o.retryMutex.Lock()
	defer o.retryMutex.Unlock()
	
	// Clear all retry state
	o.retryState = make(map[string]*RetryState)
}

// ObfuscateTraffic applies traffic obfuscation techniques to data
func (o *OPSECNetworkLayerImpl) ObfuscateTraffic(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	copy(result, data)

	// Apply padding if enabled
	if o.enablePadding {
		result = o.addTrafficPadding(result)
	}

	// Apply noise injection if enabled
	if o.noiseInjectionRate > 0 {
		result = o.injectTrafficNoise(result)
	}

	return result, nil
}

// DeobfuscateTraffic removes traffic obfuscation from data
func (o *OPSECNetworkLayerImpl) DeobfuscateTraffic(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	copy(result, data)

	// Remove noise injection if it was applied
	if o.noiseInjectionRate > 0 {
		result = o.removeTrafficNoise(result)
	}

	// Remove padding if it was applied
	if o.enablePadding {
		result = o.removeTrafficPadding(result)
	}

	return result, nil
}

// addTrafficPadding adds random padding to traffic data
func (o *OPSECNetworkLayerImpl) addTrafficPadding(data []byte) []byte {
	o.randMutex.Lock()
	defer o.randMutex.Unlock()

	// Calculate random padding size
	paddingRange := o.paddingMaxSize - o.paddingMinSize
	paddingSize := o.paddingMinSize + o.randSource.Intn(paddingRange+1)

	// Generate random padding
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		// Fallback to pseudo-random if crypto/rand fails
		o.randSource.Read(padding)
	}

	// Create padded data with length prefix
	paddedData := make([]byte, 4+len(data)+paddingSize)
	
	// Store original data length (big-endian)
	paddedData[0] = byte(len(data) >> 24)
	paddedData[1] = byte(len(data) >> 16)
	paddedData[2] = byte(len(data) >> 8)
	paddedData[3] = byte(len(data))
	
	// Copy original data
	copy(paddedData[4:4+len(data)], data)
	
	// Copy padding
	copy(paddedData[4+len(data):], padding)

	return paddedData
}

// removeTrafficPadding removes padding from traffic data
func (o *OPSECNetworkLayerImpl) removeTrafficPadding(data []byte) []byte {
	if len(data) < 4 {
		return data // Not padded or invalid format
	}

	// Extract original data length (big-endian)
	originalLength := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	
	// Validate length
	if originalLength < 0 || originalLength > len(data)-4 {
		return data // Invalid padding format
	}

	// Extract original data
	return data[4 : 4+originalLength]
}

// injectTrafficNoise injects random noise into traffic patterns
func (o *OPSECNetworkLayerImpl) injectTrafficNoise(data []byte) []byte {
	o.randMutex.Lock()
	defer o.randMutex.Unlock()

	// Determine if noise should be injected based on rate
	if o.randSource.Float64() > o.noiseInjectionRate {
		return data // No noise injection this time
	}

	// Generate noise data (10-50% of original data size)
	noiseSize := len(data)/10 + o.randSource.Intn(len(data)/2)
	if noiseSize == 0 {
		noiseSize = 1
	}

	noise := make([]byte, noiseSize)
	if _, err := rand.Read(noise); err != nil {
		// Fallback to pseudo-random if crypto/rand fails
		o.randSource.Read(noise)
	}

	// Create data with noise marker
	noisyData := make([]byte, 1+len(data)+noiseSize)
	noisyData[0] = 0xFF // Noise marker
	copy(noisyData[1:1+len(data)], data)
	copy(noisyData[1+len(data):], noise)

	return noisyData
}

// removeTrafficNoise removes injected noise from traffic data
func (o *OPSECNetworkLayerImpl) removeTrafficNoise(data []byte) []byte {
	if len(data) < 1 || data[0] != 0xFF {
		return data // No noise marker found
	}

	// For simplicity, we'll assume the noise is at the end
	// In a real implementation, we'd need a more sophisticated approach
	// to identify and remove noise while preserving data integrity
	
	// This is a simplified implementation - in practice, you'd need
	// a more robust protocol to distinguish data from noise
	return data[1:] // Remove noise marker and return rest
}

// detectSuspiciousPattern analyzes retry patterns for suspicious behavior
func (o *OPSECNetworkLayerImpl) detectSuspiciousPattern(attempt int, lastError error) bool {
	// Check for rapid successive failures that might indicate detection
	if attempt > 3 {
		return true
	}

	// Check for specific error patterns that might indicate blocking
	if IsBlockingError(lastError) {
		return true
	}

	// Check for timing-based detection patterns
	if o.isTimingPatternSuspicious(attempt) {
		return true
	}

	return false
}

// isTimingPatternSuspicious checks if retry timing patterns are suspicious
func (o *OPSECNetworkLayerImpl) isTimingPatternSuspicious(attempt int) bool {
	// If retries are happening too quickly, it might be suspicious
	// This is a simple heuristic - real implementation would be more sophisticated
	return attempt > 2 && time.Since(time.Now()) < time.Second
}

// GenerateSecureKeepAlive creates a keep-alive packet with random timing
func (o *OPSECNetworkLayerImpl) GenerateSecureKeepAlive() ([]byte, time.Duration) {
	// Generate random keep-alive interval with jitter
	interval := o.AddRandomJitter(o.keepAliveInterval)
	
	// Create keep-alive packet with random padding
	o.randMutex.Lock()
	defer o.randMutex.Unlock()
	
	// Random keep-alive payload size (8-32 bytes)
	payloadSize := 8 + o.randSource.Intn(25)
	payload := make([]byte, payloadSize)
	
	if _, err := rand.Read(payload); err != nil {
		// Fallback to pseudo-random
		o.randSource.Read(payload)
	}
	
	// Mark as keep-alive packet
	keepAlive := make([]byte, 1+len(payload))
	keepAlive[0] = 0xFE // Keep-alive marker
	copy(keepAlive[1:], payload)
	
	return keepAlive, interval
}

// IsKeepAlivePacket checks if a packet is a keep-alive packet
func (o *OPSECNetworkLayerImpl) IsKeepAlivePacket(data []byte) bool {
	return len(data) > 0 && data[0] == 0xFE
}

// ShardPacket splits large packets into smaller shards for transmission
func (o *OPSECNetworkLayerImpl) ShardPacket(data []byte) ([][]byte, error) {
	if !o.enableSharding || len(data) <= o.maxShardSize {
		return [][]byte{data}, nil
	}

	var shards [][]byte
	remaining := data
	shardIndex := uint16(0)
	
	// Generate random shard ID (same for all shards of this packet)
	shardIDBytes := make([]byte, 2)
	if _, err := rand.Read(shardIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate shard ID: %w", err)
	}
	packetShardID := uint16(shardIDBytes[0])<<8 | uint16(shardIDBytes[1])

	for len(remaining) > 0 {
		// Calculate shard size with some randomization
		shardSize := o.calculateShardSize(len(remaining))
		
		if shardSize > len(remaining) {
			shardSize = len(remaining)
		}

		// Create shard header: [shard_id:2][total_shards:2][shard_index:2][data_length:2]
		shard := make([]byte, 8+shardSize)
		
		// Shard ID (2 bytes) - same for all shards of this packet
		shard[0] = byte(packetShardID >> 8)
		shard[1] = byte(packetShardID & 0xFF)
		
		// Total shards (will be updated after we know the count)
		// Shard index (2 bytes)
		shard[4] = byte(shardIndex >> 8)
		shard[5] = byte(shardIndex & 0xFF)
		
		// Data length (2 bytes)
		shard[6] = byte(shardSize >> 8)
		shard[7] = byte(shardSize & 0xFF)
		
		// Copy data
		copy(shard[8:], remaining[:shardSize])
		
		shards = append(shards, shard)
		remaining = remaining[shardSize:]
		shardIndex++
	}

	// Update total shard count in all shards
	totalShards := uint16(len(shards))
	for _, shard := range shards {
		shard[2] = byte(totalShards >> 8)
		shard[3] = byte(totalShards & 0xFF)
	}

	return shards, nil
}

// ReassembleShards reassembles packet shards back into original data
func (o *OPSECNetworkLayerImpl) ReassembleShards(shards [][]byte) ([]byte, error) {
	if len(shards) == 0 {
		return nil, fmt.Errorf("no shards provided")
	}

	if len(shards) == 1 && len(shards[0]) < 8 {
		// Single packet without sharding
		return shards[0], nil
	}

	// Parse shard headers and organize by shard ID
	shardGroups := make(map[uint16][][]byte)
	
	for _, shard := range shards {
		if len(shard) < 8 {
			continue // Invalid shard
		}
		
		// Extract shard ID
		shardID := uint16(shard[0])<<8 | uint16(shard[1])
		
		if shardGroups[shardID] == nil {
			shardGroups[shardID] = make([][]byte, 0)
		}
		shardGroups[shardID] = append(shardGroups[shardID], shard)
	}

	// Reassemble each shard group
	var results [][]byte
	
	for _, group := range shardGroups {
		if len(group) == 0 {
			continue
		}
		
		// Get total shard count from first shard
		totalShards := uint16(group[0][2])<<8 | uint16(group[0][3])
		
		if len(group) != int(totalShards) {
			continue // Incomplete shard group
		}
		
		// Sort shards by index
		shardMap := make(map[uint16][]byte)
		for _, shard := range group {
			shardIndex := uint16(shard[4])<<8 | uint16(shard[5])
			dataLength := uint16(shard[6])<<8 | uint16(shard[7])
			
			if len(shard) >= 8+int(dataLength) {
				shardMap[shardIndex] = shard[8 : 8+dataLength]
			}
		}
		
		// Reassemble in order
		var reassembled []byte
		for i := uint16(0); i < totalShards; i++ {
			if data, exists := shardMap[i]; exists {
				reassembled = append(reassembled, data...)
			} else {
				// Missing shard
				break
			}
		}
		
		if len(reassembled) > 0 {
			results = append(results, reassembled)
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("failed to reassemble any complete packets")
	}

	// Return the first successfully reassembled packet
	return results[0], nil
}

// calculateShardSize calculates an appropriate shard size with randomization
func (o *OPSECNetworkLayerImpl) calculateShardSize(remainingBytes int) int {
	o.randMutex.Lock()
	defer o.randMutex.Unlock()

	// Base shard size with some randomization
	baseSize := o.minShardSize + o.randSource.Intn(o.maxShardSize-o.minShardSize+1)
	
	// Don't exceed remaining bytes
	if baseSize > remainingBytes {
		baseSize = remainingBytes
	}
	
	// Add some randomization to avoid predictable shard sizes
	variation := baseSize / 10 // 10% variation
	if variation > 0 {
		adjustment := o.randSource.Intn(2*variation) - variation
		baseSize += adjustment
	}
	
	// Ensure minimum size
	if baseSize < o.minShardSize {
		baseSize = o.minShardSize
	}
	
	// Ensure we don't exceed maximum or remaining bytes
	if baseSize > o.maxShardSize {
		baseSize = o.maxShardSize
	}
	if baseSize > remainingBytes {
		baseSize = remainingBytes
	}

	return baseSize
}

// UpdateRetryState updates the retry state for a connection
func (o *OPSECNetworkLayerImpl) UpdateRetryState(connectionID string, attempt int, err error) {
	o.retryMutex.Lock()
	defer o.retryMutex.Unlock()

	state, exists := o.retryState[connectionID]
	if !exists {
		state = &RetryState{
			FirstAttemptTime:  time.Now(),
			BackoffMultiplier: 1.0,
			SuspiciousPatterns: make([]SuspiciousPattern, 0),
		}
		o.retryState[connectionID] = state
	}

	state.AttemptCount = attempt
	state.LastAttemptTime = time.Now()
	state.LastError = err

	// Check for suspicious patterns
	if o.detectSuspiciousPattern(attempt, err) {
		pattern := SuspiciousPattern{
			Type:        "rapid_retry",
			DetectedAt:  time.Now(),
			Description: fmt.Sprintf("Rapid retry pattern detected after %d attempts", attempt),
			Severity:    "medium",
		}
		state.SuspiciousPatterns = append(state.SuspiciousPatterns, pattern)
	}
}

// GetRetryState gets the current retry state for a connection
func (o *OPSECNetworkLayerImpl) GetRetryState(connectionID string) *RetryState {
	o.retryMutex.RLock()
	defer o.retryMutex.RUnlock()

	if state, exists := o.retryState[connectionID]; exists {
		// Return a copy to avoid race conditions
		stateCopy := *state
		return &stateCopy
	}

	return nil
}

// CleanupRetryState removes old retry state entries
func (o *OPSECNetworkLayerImpl) CleanupRetryState(maxAge time.Duration) {
	o.retryMutex.Lock()
	defer o.retryMutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	
	for connectionID, state := range o.retryState {
		if state.LastAttemptTime.Before(cutoff) {
			delete(o.retryState, connectionID)
		}
	}
}

// SetTimingConfiguration updates timing configuration
func (o *OPSECNetworkLayerImpl) SetTimingConfiguration(baseConnection, maxConnection, baseRetry, maxRetry time.Duration, jitter float64) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.baseConnectionDelay = baseConnection
	o.maxConnectionDelay = maxConnection
	o.baseRetryDelay = baseRetry
	o.maxRetryDelay = maxRetry
	o.jitterFactor = jitter
}

// SetTrafficObfuscationConfiguration updates traffic obfuscation configuration
func (o *OPSECNetworkLayerImpl) SetTrafficObfuscationConfiguration(config *TrafficObfuscationConfig) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if config != nil {
		o.enablePadding = config.EnablePadding
		o.paddingMinSize = config.PaddingMinSize
		o.paddingMaxSize = config.PaddingMaxSize
		o.noiseInjectionRate = config.NoiseInjectionRate
		o.enableSharding = config.EnableSharding
		o.maxShardSize = config.MaxShardSize
		o.minShardSize = config.MinShardSize
	}
}

// SetKeepAliveConfiguration updates keep-alive configuration
func (o *OPSECNetworkLayerImpl) SetKeepAliveConfiguration(interval, jitter time.Duration) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.keepAliveInterval = interval
	o.keepAliveJitter = jitter
}

// GetConfiguration returns the current OPSEC configuration
func (o *OPSECNetworkLayerImpl) GetConfiguration() map[string]interface{} {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	return map[string]interface{}{
		"base_connection_delay": o.baseConnectionDelay,
		"max_connection_delay":  o.maxConnectionDelay,
		"base_retry_delay":      o.baseRetryDelay,
		"max_retry_delay":       o.maxRetryDelay,
		"jitter_factor":         o.jitterFactor,
		"enable_padding":        o.enablePadding,
		"padding_min_size":      o.paddingMinSize,
		"padding_max_size":      o.paddingMaxSize,
		"noise_injection_rate":  o.noiseInjectionRate,
		"keep_alive_interval":   o.keepAliveInterval,
		"keep_alive_jitter":     o.keepAliveJitter,
		"enable_sharding":       o.enableSharding,
		"max_shard_size":        o.maxShardSize,
		"min_shard_size":        o.minShardSize,
	}
}

// Helper functions for error classification

// IsTemporaryError checks if an error is temporary and retryable
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// Check for DirectModeError types that are temporary
	if directErr, ok := err.(*DirectModeError); ok {
		switch directErr.Code {
		case ErrCodeConnectionTimeout, ErrCodeNetworkUnavailable:
			return true
		case ErrCodeAddressUnreachable:
			return true // Might be temporary network issue
		default:
			return directErr.Recoverable
		}
	}

	// Check for standard Go network errors
	errorStr := err.Error()
	temporaryPatterns := []string{
		"timeout",
		"connection refused",
		"network unreachable",
		"temporary failure",
		"try again",
	}

	for _, pattern := range temporaryPatterns {
		if contains(errorStr, pattern) {
			return true
		}
	}

	return false
}

// IsBlockingError checks if an error indicates potential blocking/detection
func IsBlockingError(err error) bool {
	if err == nil {
		return false
	}

	// Check for DirectModeError types that indicate blocking
	if directErr, ok := err.(*DirectModeError); ok {
		switch directErr.Code {
		case ErrCodeSuspiciousPattern, ErrCodeTimingAnalysisRisk:
			return true
		default:
			return false
		}
	}

	// Check for error patterns that might indicate blocking
	errorStr := err.Error()
	blockingPatterns := []string{
		"connection reset",
		"connection aborted",
		"access denied",
		"forbidden",
		"blocked",
		"filtered",
	}

	for _, pattern := range blockingPatterns {
		if contains(errorStr, pattern) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	// Simple case-insensitive substring check
	sLower := toLower(s)
	substrLower := toLower(substr)
	
	return stringContains(sLower, substrLower)
}

// toLower converts a string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i, b := range []byte(s) {
		if b >= 'A' && b <= 'Z' {
			result[i] = b + 32
		} else {
			result[i] = b
		}
	}
	return string(result)
}

// stringContains checks if string s contains substring substr
func stringContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Additional OPSEC utility functions

// GenerateConnectionFingerprint creates a unique fingerprint for connection tracking
func (o *OPSECNetworkLayerImpl) GenerateConnectionFingerprint(remoteAddr string, localRole ConnectionRole) string {
	// Create a fingerprint that doesn't expose sensitive information
	// but allows for connection tracking and pattern detection
	
	h := make([]byte, 32) // Simple hash placeholder
	
	// Use a combination of factors that don't reveal network details
	factors := fmt.Sprintf("%s:%s:%d", 
		remoteAddr[:minInt(len(remoteAddr), 8)], // Truncated address
		localRole.String(),
		time.Now().Unix()/3600) // Hour-based timestamp
	
	// Simple hash function (in production, use crypto/sha256)
	for i, b := range []byte(factors) {
		h[i%32] ^= b
	}
	
	return fmt.Sprintf("%x", h[:8]) // Return first 8 bytes as hex
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AnalyzeTrafficPattern analyzes traffic patterns for OPSEC compliance
func (o *OPSECNetworkLayerImpl) AnalyzeTrafficPattern(connectionID string, dataSize int, timestamp time.Time) *TrafficAnalysis {
	analysis := &TrafficAnalysis{
		ConnectionID: connectionID,
		Timestamp:    timestamp,
		DataSize:     dataSize,
		Patterns:     make([]string, 0),
		RiskLevel:    "low",
	}

	// Analyze for suspicious patterns
	if dataSize > 10000 {
		analysis.Patterns = append(analysis.Patterns, "large_packet")
	}

	// Check timing patterns (simplified)
	if o.isHighFrequencyTraffic(connectionID, timestamp) {
		analysis.Patterns = append(analysis.Patterns, "high_frequency")
		analysis.RiskLevel = "medium"
	}

	return analysis
}

// isHighFrequencyTraffic checks if traffic frequency is suspiciously high
func (o *OPSECNetworkLayerImpl) isHighFrequencyTraffic(connectionID string, timestamp time.Time) bool {
	// Simplified implementation - in practice, this would track
	// traffic frequency over time windows
	return false
}

// TrafficAnalysis represents the result of traffic pattern analysis
type TrafficAnalysis struct {
	ConnectionID string    `json:"connection_id"`
	Timestamp    time.Time `json:"timestamp"`
	DataSize     int       `json:"data_size"`
	Patterns     []string  `json:"patterns"`
	RiskLevel    string    `json:"risk_level"`
}

// GetOPSECMetrics returns current OPSEC metrics
func (o *OPSECNetworkLayerImpl) GetOPSECMetrics() *OPSECMetrics {
	o.retryMutex.RLock()
	defer o.retryMutex.RUnlock()

	metrics := &OPSECMetrics{
		ActiveConnections:    len(o.retryState),
		SuspiciousPatterns:   0,
		AverageRetryDelay:    o.baseRetryDelay,
		TrafficObfuscated:    o.enablePadding,
		LastAnalysisTime:     time.Now(),
	}

	// Count suspicious patterns
	for _, state := range o.retryState {
		metrics.SuspiciousPatterns += len(state.SuspiciousPatterns)
	}

	return metrics
}

// OPSECMetrics represents OPSEC-related metrics
type OPSECMetrics struct {
	ActiveConnections  int           `json:"active_connections"`
	SuspiciousPatterns int           `json:"suspicious_patterns"`
	AverageRetryDelay  time.Duration `json:"average_retry_delay"`
	TrafficObfuscated  bool          `json:"traffic_obfuscated"`
	LastAnalysisTime   time.Time     `json:"last_analysis_time"`
}

// Advanced retry logic with OPSEC considerations

// RetryManagerImpl handles sophisticated retry logic with OPSEC considerations
type RetryManagerImpl struct {
	maxRetries              int
	baseDelay               time.Duration
	maxDelay                time.Duration
	jitterFactor            float64
	suspiciousPatternThreshold int
	rateLimitWindow         time.Duration
	maxAttemptsPerWindow    int
	
	// Connection attempt tracking
	attemptHistory          map[string][]*ConnectionAttempt
	rateLimitState          map[string]*RateLimitState
	suspiciousConnections   map[string]*SuspiciousConnectionState
	
	mutex                   sync.RWMutex
}

// ConnectionAttempt represents a single connection attempt
type ConnectionAttempt struct {
	Timestamp    time.Time
	RemoteAddr   string
	Error        error
	Duration     time.Duration
	AttemptIndex int
}

// RateLimitState tracks rate limiting for a connection
type RateLimitState struct {
	WindowStart     time.Time
	AttemptsInWindow int
	LastAttempt     time.Time
	Blocked         bool
	BlockedUntil    time.Time
}

// SuspiciousConnectionState tracks suspicious connection patterns
type SuspiciousConnectionState struct {
	FirstDetected    time.Time
	PatternCount     int
	LastPattern      time.Time
	Severity         string
	Patterns         []string
	Blocked          bool
}

// NewRetryManager creates a new retry manager with OPSEC considerations
func NewRetryManager() *RetryManager {
	return &RetryManager{
		maxRetries:                 5,
		baseDelay:                  1 * time.Second,
		maxDelay:                   300 * time.Second, // 5 minutes
		jitterFactor:               0.3,
		suspiciousPatternThreshold: 3,
		rateLimitWindow:            60 * time.Second, // 1 minute window
		maxAttemptsPerWindow:       10,
		
		attemptHistory:        make(map[string][]*ConnectionAttempt),
		rateLimitState:        make(map[string]*RateLimitState),
		suspiciousConnections: make(map[string]*SuspiciousConnectionState),
	}
}

// ShouldRetryConnection determines if a connection should be retried with OPSEC considerations
func (rm *RetryManager) ShouldRetryConnection(connectionID string, attempt int, lastError error, remoteAddr string) (*RetryDecision, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	decision := &RetryDecision{
		ShouldRetry:    false,
		Delay:          0,
		Reason:         "",
		RiskLevel:      "low",
		Recommendations: make([]string, 0),
	}

	// Record this attempt
	rm.recordConnectionAttempt(connectionID, remoteAddr, lastError, attempt)

	// Check for suspicious patterns first (highest priority)
	if rm.isSuspiciousConnection(connectionID) {
		decision.Reason = "Suspicious connection patterns detected"
		decision.RiskLevel = "high"
		decision.Recommendations = append(decision.Recommendations,
			"Stop connection attempts temporarily",
			"Review connection parameters",
			"Consider using relay mode")
		return decision, nil
	}

	// Check rate limiting
	if rm.isRateLimited(connectionID) {
		decision.Reason = "Rate limited to avoid suspicious patterns"
		decision.RiskLevel = "medium"
		decision.Recommendations = append(decision.Recommendations, 
			"Wait longer before retrying", 
			"Consider using different connection parameters")
		return decision, nil
	}

	// Check basic retry limits
	if attempt >= rm.maxRetries {
		decision.Reason = "Maximum retry attempts exceeded"
		decision.RiskLevel = "low"
		return decision, nil
	}

	// Check for blocking indicators first (higher priority than retryable check)
	if rm.isBlockingError(lastError) {
		decision.Reason = "Error indicates potential blocking"
		decision.RiskLevel = "high"
		decision.Recommendations = append(decision.Recommendations,
			"Stop retrying to avoid detection",
			"Wait significantly longer before next attempt",
			"Consider changing connection parameters")
		return decision, nil
	}

	// Check if error is retryable
	if !rm.isRetryableError(lastError) {
		decision.Reason = "Error is not retryable"
		decision.RiskLevel = "low"
		return decision, nil
	}

	// Calculate retry delay with OPSEC considerations
	delay := rm.calculateOPSECRetryDelay(connectionID, attempt)
	
	decision.ShouldRetry = true
	decision.Delay = delay
	decision.Reason = "Retry approved with OPSEC delay"
	decision.RiskLevel = rm.assessRiskLevel(connectionID, attempt)
	
	// Add recommendations based on risk level
	switch decision.RiskLevel {
	case "medium":
		decision.Recommendations = append(decision.Recommendations,
			"Monitor for suspicious patterns",
			"Consider longer delays between attempts")
	case "high":
		decision.Recommendations = append(decision.Recommendations,
			"Use maximum delays between attempts",
			"Monitor closely for blocking indicators",
			"Prepare fallback connection method")
	}

	return decision, nil
}

// recordConnectionAttempt records a connection attempt for analysis
func (rm *RetryManager) recordConnectionAttempt(connectionID, remoteAddr string, err error, attempt int) {
	now := time.Now()
	
	attemptRecord := &ConnectionAttempt{
		Timestamp:    now,
		RemoteAddr:   remoteAddr,
		Error:        err,
		AttemptIndex: attempt,
	}

	// Add to attempt history
	if rm.attemptHistory[connectionID] == nil {
		rm.attemptHistory[connectionID] = make([]*ConnectionAttempt, 0)
	}
	rm.attemptHistory[connectionID] = append(rm.attemptHistory[connectionID], attemptRecord)

	// Keep only recent attempts (last 24 hours)
	cutoff := now.Add(-24 * time.Hour)
	filtered := make([]*ConnectionAttempt, 0)
	for _, attempt := range rm.attemptHistory[connectionID] {
		if attempt.Timestamp.After(cutoff) {
			filtered = append(filtered, attempt)
		}
	}
	rm.attemptHistory[connectionID] = filtered

	// Update rate limit state
	rm.updateRateLimitState(connectionID, now)
	
	// Check for suspicious patterns
	rm.checkForSuspiciousPatterns(connectionID, err)
}

// isRateLimited checks if a connection is currently rate limited
func (rm *RetryManager) isRateLimited(connectionID string) bool {
	state, exists := rm.rateLimitState[connectionID]
	if !exists {
		return false
	}

	now := time.Now()
	
	// Check if blocked period has expired
	if state.Blocked && now.After(state.BlockedUntil) {
		state.Blocked = false
		state.BlockedUntil = time.Time{}
	}

	return state.Blocked
}

// updateRateLimitState updates the rate limiting state for a connection
func (rm *RetryManager) updateRateLimitState(connectionID string, now time.Time) {
	state, exists := rm.rateLimitState[connectionID]
	if !exists {
		state = &RateLimitState{
			WindowStart:      now,
			AttemptsInWindow: 0,
		}
		rm.rateLimitState[connectionID] = state
	}

	// Reset window if expired
	if now.Sub(state.WindowStart) > rm.rateLimitWindow {
		state.WindowStart = now
		state.AttemptsInWindow = 0
	}

	state.AttemptsInWindow++
	state.LastAttempt = now

	// Check if rate limit exceeded
	if state.AttemptsInWindow > rm.maxAttemptsPerWindow {
		state.Blocked = true
		// Block for 2x the window duration
		state.BlockedUntil = now.Add(2 * rm.rateLimitWindow)
	}
}

// isSuspiciousConnection checks if a connection shows suspicious patterns
func (rm *RetryManager) isSuspiciousConnection(connectionID string) bool {
	state, exists := rm.suspiciousConnections[connectionID]
	if !exists {
		return false
	}

	// Check if suspicion has expired (after 1 hour of no new patterns)
	if time.Since(state.LastPattern) > time.Hour {
		state.Blocked = false
		state.PatternCount = 0
	}

	return state.Blocked
}

// checkForSuspiciousPatterns analyzes connection attempts for suspicious patterns
func (rm *RetryManager) checkForSuspiciousPatterns(connectionID string, err error) {
	attempts := rm.attemptHistory[connectionID]
	if len(attempts) < 3 {
		return // Need at least 3 attempts to detect patterns
	}

	state, exists := rm.suspiciousConnections[connectionID]
	if !exists {
		state = &SuspiciousConnectionState{
			FirstDetected: time.Now(),
			Patterns:      make([]string, 0),
		}
		rm.suspiciousConnections[connectionID] = state
	}

	patterns := rm.detectPatterns(attempts)
	
	for _, pattern := range patterns {
		// Check if this is a new pattern
		isNew := true
		for _, existingPattern := range state.Patterns {
			if existingPattern == pattern {
				isNew = false
				break
			}
		}
		
		if isNew {
			state.Patterns = append(state.Patterns, pattern)
			state.PatternCount++
			state.LastPattern = time.Now()
		}
	}

	// Determine if connection should be blocked
	if state.PatternCount >= rm.suspiciousPatternThreshold {
		state.Blocked = true
		state.Severity = "high"
	} else if state.PatternCount >= 2 {
		state.Severity = "medium"
	} else {
		state.Severity = "low"
	}
}

// detectPatterns analyzes connection attempts to detect suspicious patterns
func (rm *RetryManager) detectPatterns(attempts []*ConnectionAttempt) []string {
	patterns := make([]string, 0)

	if len(attempts) < 3 {
		return patterns
	}

	// Check for rapid successive failures
	recentAttempts := attempts[len(attempts)-3:]
	allFailed := true
	maxInterval := time.Duration(0)
	
	for i, attempt := range recentAttempts {
		if attempt.Error == nil {
			allFailed = false
		}
		if i > 0 {
			interval := attempt.Timestamp.Sub(recentAttempts[i-1].Timestamp)
			if interval > maxInterval {
				maxInterval = interval
			}
		}
	}

	if allFailed && maxInterval < 10*time.Second {
		patterns = append(patterns, "rapid_successive_failures")
	}

	// Check for consistent error types (might indicate blocking)
	if len(attempts) >= 5 {
		recentErrors := make(map[string]int)
		for _, attempt := range attempts[len(attempts)-5:] {
			if attempt.Error != nil {
				errorType := rm.classifyError(attempt.Error)
				recentErrors[errorType]++
			}
		}
		
		for errorType, count := range recentErrors {
			if count >= 4 && (errorType == "connection_refused" || errorType == "timeout") {
				patterns = append(patterns, "consistent_"+errorType)
			}
		}
	}

	// Check for timing patterns that might indicate automated detection
	if len(attempts) >= 4 {
		intervals := make([]time.Duration, 0)
		for i := 1; i < len(attempts); i++ {
			interval := attempts[i].Timestamp.Sub(attempts[i-1].Timestamp)
			intervals = append(intervals, interval)
		}
		
		// Check if intervals are suspiciously regular
		if rm.areIntervalsRegular(intervals) {
			patterns = append(patterns, "regular_timing_pattern")
		}
	}

	return patterns
}

// areIntervalsRegular checks if timing intervals are suspiciously regular
func (rm *RetryManager) areIntervalsRegular(intervals []time.Duration) bool {
	if len(intervals) < 3 {
		return false
	}

	// Calculate variance in intervals
	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	avg := sum / time.Duration(len(intervals))

	var variance float64
	for _, interval := range intervals {
		diff := float64(interval - avg)
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// If variance is very low, intervals are too regular
	stdDev := math.Sqrt(variance)
	return stdDev < float64(avg)/10 // Less than 10% variation
}

// calculateOPSECRetryDelay calculates retry delay with OPSEC considerations
func (rm *RetryManager) calculateOPSECRetryDelay(connectionID string, attempt int) time.Duration {
	// Base exponential backoff
	baseDelay := time.Duration(float64(rm.baseDelay) * math.Pow(2, float64(attempt-1)))
	
	// Cap at maximum delay
	if baseDelay > rm.maxDelay {
		baseDelay = rm.maxDelay
	}

	// Add OPSEC considerations
	opsecMultiplier := 1.0
	
	// Increase delay if connection shows suspicious patterns
	if state, exists := rm.suspiciousConnections[connectionID]; exists {
		switch state.Severity {
		case "medium":
			opsecMultiplier = 2.0
		case "high":
			opsecMultiplier = 5.0
		}
	}

	// Increase delay if rate limited
	if rm.isRateLimited(connectionID) {
		opsecMultiplier *= 3.0
	}

	adjustedDelay := time.Duration(float64(baseDelay) * opsecMultiplier)
	
	// Add jitter
	jitterRange := time.Duration(float64(adjustedDelay) * rm.jitterFactor)
	jitter := time.Duration(mathrand.Int63n(int64(2*jitterRange))) - jitterRange
	
	finalDelay := adjustedDelay + jitter
	
	// Ensure minimum delay
	if finalDelay < rm.baseDelay {
		finalDelay = rm.baseDelay
	}

	return finalDelay
}

// isRetryableError checks if an error is retryable
func (rm *RetryManager) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check DirectModeError types
	if directErr, ok := err.(*DirectModeError); ok {
		switch directErr.Type {
		case ErrorTypeNetwork:
			return directErr.Recoverable
		case ErrorTypeConnection:
			return directErr.Recoverable
		case ErrorTypeCryptographic:
			return false // Crypto errors are usually not retryable
		case ErrorTypeOPSEC:
			return false // OPSEC errors should not be retried
		default:
			return directErr.Recoverable
		}
	}

	// Check standard error patterns
	errorStr := err.Error()
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"network unreachable",
		"temporary failure",
		"try again",
		"no route to host",
	}

	for _, pattern := range retryablePatterns {
		if contains(errorStr, pattern) {
			return true
		}
	}

	return false
}

// isBlockingError checks if an error indicates potential blocking
func (rm *RetryManager) isBlockingError(err error) bool {
	// Use the existing IsBlockingError function
	return IsBlockingError(err)
}

// classifyError classifies an error into a category for pattern detection
func (rm *RetryManager) classifyError(err error) string {
	if err == nil {
		return "success"
	}

	errorStr := err.Error()
	
	if contains(errorStr, "timeout") {
		return "timeout"
	}
	if contains(errorStr, "connection refused") {
		return "connection_refused"
	}
	if contains(errorStr, "network unreachable") {
		return "network_unreachable"
	}
	if contains(errorStr, "host unreachable") {
		return "host_unreachable"
	}
	if contains(errorStr, "connection reset") {
		return "connection_reset"
	}
	
	return "other"
}

// assessRiskLevel assesses the risk level for a connection
func (rm *RetryManager) assessRiskLevel(connectionID string, attempt int) string {
	// Base risk on attempt count
	riskLevel := "low"
	if attempt >= 3 {
		riskLevel = "medium"
	}
	if attempt >= 5 {
		riskLevel = "high"
	}

	// Increase risk if suspicious patterns detected
	if state, exists := rm.suspiciousConnections[connectionID]; exists {
		if state.Severity == "high" {
			riskLevel = "high"
		} else if state.Severity == "medium" && riskLevel == "low" {
			riskLevel = "medium"
		}
	}

	// Increase risk if rate limited
	if rm.isRateLimited(connectionID) {
		if riskLevel == "low" {
			riskLevel = "medium"
		} else if riskLevel == "medium" {
			riskLevel = "high"
		}
	}

	return riskLevel
}


// CleanupRetryHistory removes old retry history to prevent memory leaks
func (rm *RetryManager) CleanupRetryHistory(maxAge time.Duration) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	// Clean attempt history
	for connectionID, attempts := range rm.attemptHistory {
		filtered := make([]*ConnectionAttempt, 0)
		for _, attempt := range attempts {
			if attempt.Timestamp.After(cutoff) {
				filtered = append(filtered, attempt)
			}
		}
		
		if len(filtered) == 0 {
			delete(rm.attemptHistory, connectionID)
		} else {
			rm.attemptHistory[connectionID] = filtered
		}
	}

	// Clean rate limit state
	for connectionID, state := range rm.rateLimitState {
		if state.LastAttempt.Before(cutoff) {
			delete(rm.rateLimitState, connectionID)
		}
	}

	// Clean suspicious connection state
	for connectionID, state := range rm.suspiciousConnections {
		if state.LastPattern.Before(cutoff) {
			delete(rm.suspiciousConnections, connectionID)
		}
	}
}

// GetRetryStatistics returns statistics about retry behavior
func (rm *RetryManager) GetRetryStatistics() *RetryStatistics {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	stats := &RetryStatistics{
		ActiveConnections:     len(rm.attemptHistory),
		RateLimitedConnections: 0,
		SuspiciousConnections: 0,
		TotalAttempts:         0,
		AverageAttemptsPerConnection: 0,
	}

	// Count rate limited connections
	for _, state := range rm.rateLimitState {
		if state.Blocked {
			stats.RateLimitedConnections++
		}
	}

	// Count suspicious connections
	for _, state := range rm.suspiciousConnections {
		if state.Blocked {
			stats.SuspiciousConnections++
		}
	}

	// Count total attempts
	totalAttempts := 0
	for _, attempts := range rm.attemptHistory {
		totalAttempts += len(attempts)
	}
	stats.TotalAttempts = totalAttempts

	// Calculate average attempts per connection
	if len(rm.attemptHistory) > 0 {
		stats.AverageAttemptsPerConnection = float64(totalAttempts) / float64(len(rm.attemptHistory))
	}

	return stats
}


// Secure logging and monitoring with OPSEC considerations

// OPSECLoggerImpl handles secure logging that excludes sensitive network metadata
type OPSECLoggerImpl struct {
	logLevel            LogLevel
	enabledCategories   map[LogCategory]bool
	sanitizationRules   []SanitizationRule
	auditTrail          []*AuditEvent
	maxAuditEvents      int
	
	// Connection health monitoring
	healthMonitor       *ConnectionHealthMonitorImpl
	
	// Diagnostic collection
	diagnosticCollector *DiagnosticCollectorImpl
	
	mutex               sync.RWMutex
}

// LogLevel defines the logging level
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelError:
		return "ERROR"
	case LogLevelWarn:
		return "WARN"
	case LogLevelInfo:
		return "INFO"
	case LogLevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// LogCategory defines categories of log messages
type LogCategory int

const (
	LogCategoryConnection LogCategory = iota
	LogCategoryRetry
	LogCategorySecurity
	LogCategoryPerformance
	LogCategoryDiagnostic
	LogCategoryAudit
)

// String returns the string representation of the log category
func (c LogCategory) String() string {
	switch c {
	case LogCategoryConnection:
		return "CONNECTION"
	case LogCategoryRetry:
		return "RETRY"
	case LogCategorySecurity:
		return "SECURITY"
	case LogCategoryPerformance:
		return "PERFORMANCE"
	case LogCategoryDiagnostic:
		return "DIAGNOSTIC"
	case LogCategoryAudit:
		return "AUDIT"
	default:
		return "UNKNOWN"
	}
}

// SanitizationRule defines rules for sanitizing log data
type SanitizationRule struct {
	Pattern     string
	Replacement string
	Category    LogCategory
}

// LogEntry represents a sanitized log entry
type LogEntry struct {
	Timestamp   time.Time   `json:"timestamp"`
	Level       LogLevel    `json:"level"`
	Category    LogCategory `json:"category"`
	Message     string      `json:"message"`
	Context     string      `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}


// ConnectionHealthMonitorImpl monitors connection health without exposing internal state
type ConnectionHealthMonitorImpl struct {
	connections         map[string]*ConnectionHealth
	healthCheckInterval time.Duration
	alertThresholds     *HealthThresholds
	lastHealthCheck     time.Time
	mutex               sync.RWMutex
}


// HealthThresholds defines thresholds for health monitoring
type HealthThresholds struct {
	MaxResponseTime     time.Duration `json:"max_response_time"`
	MaxErrorRate        float64       `json:"max_error_rate"`
	MinHealthScore      float64       `json:"min_health_score"`
	InactivityTimeout   time.Duration `json:"inactivity_timeout"`
}

// DiagnosticCollectorImpl collects diagnostic information for troubleshooting
type DiagnosticCollectorImpl struct {
	diagnosticData      map[string]*DiagnosticInfo
	collectionInterval  time.Duration
	maxDiagnosticAge    time.Duration
	lastCollection      time.Time
	mutex               sync.RWMutex
}




// NewOPSECLogger creates a new OPSEC-compliant logger
func NewOPSECLogger() *OPSECLogger {
	logger := &OPSECLogger{
		logLevel:          LogLevelInfo,
		enabledCategories: make(map[LogCategory]bool),
		sanitizationRules: make([]SanitizationRule, 0),
		auditTrail:        make([]*AuditEvent, 0),
		maxAuditEvents:    1000,
		healthMonitor:     NewConnectionHealthMonitor(),
		diagnosticCollector: NewDiagnosticCollector(),
	}

	// Enable all categories by default
	for category := LogCategoryConnection; category <= LogCategoryAudit; category++ {
		logger.enabledCategories[category] = true
	}

	// Add default sanitization rules
	logger.addDefaultSanitizationRules()

	return logger
}


// addDefaultSanitizationRules adds default rules for sanitizing log data
func (ol *OPSECLogger) addDefaultSanitizationRules() {
	// Sanitize IP addresses (replace with generic identifiers)
	ol.sanitizationRules = append(ol.sanitizationRules, SanitizationRule{
		Pattern:     `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
		Replacement: "[IP_ADDRESS]",
		Category:    LogCategoryConnection,
	})

	// Sanitize IPv6 addresses
	ol.sanitizationRules = append(ol.sanitizationRules, SanitizationRule{
		Pattern:     `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`,
		Replacement: "[IPV6_ADDRESS]",
		Category:    LogCategoryConnection,
	})

	// Sanitize port numbers (keep only generic ranges)
	ol.sanitizationRules = append(ol.sanitizationRules, SanitizationRule{
		Pattern:     `:(\d{4,5})\b`,
		Replacement: ":[PORT]",
		Category:    LogCategoryConnection,
	})

	// Sanitize connection IDs (keep only prefix)
	ol.sanitizationRules = append(ol.sanitizationRules, SanitizationRule{
		Pattern:     `conn-[a-fA-F0-9]{8,}`,
		Replacement: "conn-[ID]",
		Category:    LogCategoryConnection,
	})

	// Sanitize cryptographic material
	ol.sanitizationRules = append(ol.sanitizationRules, SanitizationRule{
		Pattern:     `[a-fA-F0-9]{32,}`,
		Replacement: "[CRYPTO_DATA]",
		Category:    LogCategorySecurity,
	})
}

// Log creates a sanitized log entry
func (ol *OPSECLogger) Log(level LogLevel, category LogCategory, message, context string, metadata map[string]interface{}) {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	// Check if logging is enabled for this level and category
	if level > ol.logLevel || !ol.enabledCategories[category] {
		return
	}

	// Sanitize the message and context
	sanitizedMessage := ol.sanitizeData(message, category)
	sanitizedContext := ol.sanitizeData(context, category)

	// Sanitize metadata
	sanitizedMetadata := ol.sanitizeMetadata(metadata, category)

	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Category:  category,
		Message:   sanitizedMessage,
		Context:   sanitizedContext,
		Metadata:  sanitizedMetadata,
	}

	// In a real implementation, this would write to a log file or system
	// For now, we'll just store it (in production, use a proper logging framework)
	ol.processLogEntry(entry)
}

// sanitizeData applies sanitization rules to data
func (ol *OPSECLogger) sanitizeData(data string, category LogCategory) string {
	sanitized := data
	
	for _, rule := range ol.sanitizationRules {
		if rule.Category == category || rule.Category == LogCategoryConnection {
			// Simple string replacement (in production, use regex)
			sanitized = ol.simpleReplace(sanitized, rule.Pattern, rule.Replacement)
		}
	}
	
	return sanitized
}

// sanitizeMetadata sanitizes metadata map
func (ol *OPSECLogger) sanitizeMetadata(metadata map[string]interface{}, category LogCategory) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	
	for key, value := range metadata {
		// Sanitize key and value
		sanitizedKey := ol.sanitizeData(key, category)
		
		var sanitizedValue interface{}
		if strValue, ok := value.(string); ok {
			sanitizedValue = ol.sanitizeData(strValue, category)
		} else {
			sanitizedValue = value
		}
		
		sanitized[sanitizedKey] = sanitizedValue
	}
	
	return sanitized
}

// simpleReplace performs simple string replacement (placeholder for regex)
func (ol *OPSECLogger) simpleReplace(text, pattern, replacement string) string {
	// This is a simplified implementation
	// In production, use proper regex matching
	return text // For now, return as-is
}

// processLogEntry processes a log entry (placeholder for actual logging)
func (ol *OPSECLogger) processLogEntry(entry *LogEntry) {
	// In production, this would write to log files, send to logging service, etc.
	// For testing, we can just store or print
}

// LogConnectionEvent logs a connection-related event
func (ol *OPSECLogger) LogConnectionEvent(connectionID, event, details string, metadata map[string]interface{}) {
	ol.Log(LogLevelInfo, LogCategoryConnection, 
		fmt.Sprintf("Connection event: %s", event), 
		fmt.Sprintf("Connection: %s, Details: %s", connectionID, details),
		metadata)
}

// LogRetryEvent logs a retry-related event
func (ol *OPSECLogger) LogRetryEvent(connectionID string, attempt int, decision *RetryDecision, err error) {
	level := LogLevelInfo
	if decision.RiskLevel == "high" {
		level = LogLevelWarn
	}

	metadata := map[string]interface{}{
		"attempt":     attempt,
		"should_retry": decision.ShouldRetry,
		"risk_level":  decision.RiskLevel,
		"delay":       decision.Delay.String(),
	}

	if err != nil {
		metadata["error_type"] = ol.classifyErrorForLogging(err)
	}

	ol.Log(level, LogCategoryRetry,
		fmt.Sprintf("Retry decision: %s", decision.Reason),
		fmt.Sprintf("Connection: %s, Attempt: %d", connectionID, attempt),
		metadata)
}

// LogSecurityEvent logs a security-related event
func (ol *OPSECLogger) LogSecurityEvent(eventType, description string, riskLevel string, metadata map[string]interface{}) {
	level := LogLevelWarn
	if riskLevel == "high" {
		level = LogLevelError
	}

	ol.Log(level, LogCategorySecurity,
		fmt.Sprintf("Security event: %s", eventType),
		description,
		metadata)

	// Also add to audit trail
	ol.addAuditEvent(eventType, description, riskLevel, metadata)
}

// addAuditEvent adds an event to the audit trail
func (ol *OPSECLogger) addAuditEvent(eventType, description, riskLevel string, metadata map[string]interface{}) {
	event := &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		Description: description,
		RiskLevel:   riskLevel,
		Metadata:    ol.sanitizeMetadata(metadata, LogCategoryAudit),
	}

	ol.auditTrail = append(ol.auditTrail, event)

	// Limit audit trail size
	if len(ol.auditTrail) > ol.maxAuditEvents {
		ol.auditTrail = ol.auditTrail[len(ol.auditTrail)-ol.maxAuditEvents:]
	}
}

// classifyErrorForLogging classifies errors for logging without exposing sensitive details
func (ol *OPSECLogger) classifyErrorForLogging(err error) string {
	if err == nil {
		return "none"
	}

	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type.String()
	}

	// Generic classification based on error message patterns
	errorStr := err.Error()
	if contains(errorStr, "timeout") {
		return "timeout"
	}
	if contains(errorStr, "connection") {
		return "connection"
	}
	if contains(errorStr, "network") {
		return "network"
	}

	return "other"
}

// UpdateConnectionHealth updates health metrics for a connection
func (ol *OPSECLogger) UpdateConnectionHealth(connectionID string, responseTime time.Duration, success bool) {
	ol.healthMonitor.UpdateHealth(connectionID, responseTime, success)
}

// GetConnectionHealth returns health information for a connection
func (ol *OPSECLogger) GetConnectionHealth(connectionID string) *ConnectionHealth {
	return ol.healthMonitor.GetHealth(connectionID)
}

// GetHealthSummary returns a summary of all connection health
func (ol *OPSECLogger) GetHealthSummary() *HealthSummary {
	return ol.healthMonitor.GetHealthSummary()
}

// CollectDiagnostics collects diagnostic information for a connection
func (ol *OPSECLogger) CollectDiagnostics(connectionID string, networkMetrics *NetworkMetrics, perfMetrics *PerformanceMetrics, errors []error) {
	ol.diagnosticCollector.CollectDiagnostics(connectionID, networkMetrics, perfMetrics, errors)
}

// GetDiagnostics returns diagnostic information for a connection
func (ol *OPSECLogger) GetDiagnostics(connectionID string) *DiagnosticInfo {
	return ol.diagnosticCollector.GetDiagnostics(connectionID)
}

// GetAuditTrail returns the audit trail
func (ol *OPSECLogger) GetAuditTrail() []*AuditEvent {
	ol.mutex.RLock()
	defer ol.mutex.RUnlock()

	// Return a copy to prevent modification
	trail := make([]*AuditEvent, len(ol.auditTrail))
	copy(trail, ol.auditTrail)
	return trail
}

// SetLogLevel sets the logging level
func (ol *OPSECLogger) SetLogLevel(level LogLevel) {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()
	ol.logLevel = level
}

// EnableCategory enables logging for a specific category
func (ol *OPSECLogger) EnableCategory(category LogCategory, enabled bool) {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()
	ol.enabledCategories[category] = enabled
}

// Connection Health Monitor implementation

// UpdateHealth updates health metrics for a connection
func (chm *ConnectionHealthMonitor) UpdateHealth(connectionID string, responseTime time.Duration, success bool) {
	chm.mutex.Lock()
	defer chm.mutex.Unlock()

	health, exists := chm.connections[connectionID]
	if !exists {
		health = &ConnectionHealth{
			ConnectionID:    connectionID,
			Status:          "active",
			LastActivity:    time.Now(),
			HealthScore:     1.0,
		}
		chm.connections[connectionID] = health
	}

	health.LastActivity = time.Now()
	health.ResponseTime = responseTime
	health.LastHealthCheck = time.Now()

	if success {
		health.SuccessCount++
	} else {
		health.ErrorCount++
	}

	// Calculate health score
	health.HealthScore = chm.calculateHealthScore(health)

	// Update status based on health score and thresholds
	health.Status = chm.determineHealthStatus(health)
}

// calculateHealthScore calculates a health score for a connection
func (chm *ConnectionHealthMonitor) calculateHealthScore(health *ConnectionHealth) float64 {
	totalRequests := health.SuccessCount + health.ErrorCount
	if totalRequests == 0 {
		return 1.0
	}

	// Base score on success rate
	successRate := float64(health.SuccessCount) / float64(totalRequests)
	score := successRate

	// Penalize high response times
	if health.ResponseTime > chm.alertThresholds.MaxResponseTime {
		score *= 0.8
	}

	// Penalize inactivity
	if time.Since(health.LastActivity) > chm.alertThresholds.InactivityTimeout {
		score *= 0.5
	}

	return score
}

// determineHealthStatus determines the health status based on metrics
func (chm *ConnectionHealthMonitor) determineHealthStatus(health *ConnectionHealth) string {
	// Check inactivity first
	if time.Since(health.LastActivity) > chm.alertThresholds.InactivityTimeout {
		return "inactive"
	}

	// Check error rate for degraded status
	totalRequests := health.SuccessCount + health.ErrorCount
	if totalRequests > 0 {
		errorRate := float64(health.ErrorCount) / float64(totalRequests)
		if errorRate > chm.alertThresholds.MaxErrorRate {
			return "degraded"
		}
	}

	// Check overall health score for unhealthy status
	if health.HealthScore < chm.alertThresholds.MinHealthScore {
		return "unhealthy"
	}

	return "healthy"
}

// GetHealth returns health information for a connection
func (chm *ConnectionHealthMonitor) GetHealth(connectionID string) *ConnectionHealth {
	chm.mutex.RLock()
	defer chm.mutex.RUnlock()

	if health, exists := chm.connections[connectionID]; exists {
		// Return a copy to prevent modification
		healthCopy := *health
		return &healthCopy
	}

	return nil
}

// GetHealthSummary returns a summary of all connection health
func (chm *ConnectionHealthMonitor) GetHealthSummary() *HealthSummary {
	chm.mutex.RLock()
	defer chm.mutex.RUnlock()

	summary := &HealthSummary{
		TotalConnections:    len(chm.connections),
		HealthyConnections:  0,
		DegradedConnections: 0,
		UnhealthyConnections: 0,
		InactiveConnections: 0,
		AverageHealthScore:  0,
		LastHealthCheck:     chm.lastHealthCheck,
	}

	totalScore := 0.0
	for _, health := range chm.connections {
		totalScore += health.HealthScore

		switch health.Status {
		case "healthy":
			summary.HealthyConnections++
		case "degraded":
			summary.DegradedConnections++
		case "unhealthy":
			summary.UnhealthyConnections++
		case "inactive":
			summary.InactiveConnections++
		}
	}

	if len(chm.connections) > 0 {
		summary.AverageHealthScore = totalScore / float64(len(chm.connections))
	}

	return summary
}


// Diagnostic Collector implementation

// CollectDiagnostics collects diagnostic information for a connection
func (dc *DiagnosticCollector) CollectDiagnostics(connectionID string, networkMetrics *NetworkMetrics, perfMetrics *PerformanceMetrics, errors []error) {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	errorSummary := dc.createErrorSummary(errors)

	diagnostic := &DiagnosticInfo{
		ConnectionID:       connectionID,
		CollectedAt:        time.Now(),
		NetworkMetrics:     networkMetrics,
		PerformanceMetrics: perfMetrics,
		ErrorSummary:       errorSummary,
		ConfigurationInfo:  make(map[string]interface{}),
	}

	dc.diagnosticData[connectionID] = diagnostic
	dc.lastCollection = time.Now()

	// Clean up old diagnostic data
	dc.cleanupOldDiagnostics()
}

// createErrorSummary creates a sanitized error summary
func (dc *DiagnosticCollector) createErrorSummary(errors []error) *ErrorSummary {
	summary := &ErrorSummary{
		TotalErrors:      0, // Will be counted in the loop
		ErrorsByType:     make(map[string]int),
		ErrorsByCategory: make(map[string]int),
	}

	for _, err := range errors {
		if err == nil {
			continue
		}
		
		summary.TotalErrors++

		// Classify error without exposing sensitive details
		errorType := "other"
		errorCategory := "general"

		if directErr, ok := err.(*DirectModeError); ok {
			errorType = directErr.Type.String()
			errorCategory = directErr.Code
		} else {
			// Generic classification
			errorStr := err.Error()
			if contains(errorStr, "timeout") {
				errorType = "timeout"
			} else if contains(errorStr, "connection") {
				errorType = "connection"
			} else if contains(errorStr, "network") {
				errorType = "network"
			}
		}

		summary.ErrorsByType[errorType]++
		summary.ErrorsByCategory[errorCategory]++

		// Store last error (sanitized)
		summary.LastError = errorType
		summary.LastErrorTime = time.Now()
	}

	return summary
}

// GetDiagnostics returns diagnostic information for a connection
func (dc *DiagnosticCollector) GetDiagnostics(connectionID string) *DiagnosticInfo {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	if diagnostic, exists := dc.diagnosticData[connectionID]; exists {
		// Return a copy to prevent modification
		diagnosticCopy := *diagnostic
		return &diagnosticCopy
	}

	return nil
}

// cleanupOldDiagnostics removes old diagnostic data
func (dc *DiagnosticCollector) cleanupOldDiagnostics() {
	cutoff := time.Now().Add(-dc.maxDiagnosticAge)

	for connectionID, diagnostic := range dc.diagnosticData {
		if diagnostic.CollectedAt.Before(cutoff) {
			delete(dc.diagnosticData, connectionID)
		}
	}
}
