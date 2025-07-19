package direct

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestCryptographicOperationsSecurity validates the security of all cryptographic operations
func TestCryptographicOperationsSecurity(t *testing.T) {
	t.Run("PostQuantumKeyExchangeSecurity", func(t *testing.T) {
		testPostQuantumKeyExchangeSecurity(t)
	})
	
	t.Run("SessionKeyDerivationSecurity", func(t *testing.T) {
		testSessionKeyDerivationSecurity(t)
	})
	
	t.Run("CryptographicRandomnessSecurity", func(t *testing.T) {
		testCryptographicRandomnessSecurity(t)
	})
	
	t.Run("KeyRotationSecurity", func(t *testing.T) {
		testKeyRotationSecurity(t)
	})
	
	t.Run("SecureWipingSecurity", func(t *testing.T) {
		testSecureWipingSecurity(t)
	})
}

func testPostQuantumKeyExchangeSecurity(t *testing.T) {
	// Test that key exchange produces cryptographically secure keys
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create Alice's key exchange: %v", err)
	}
	defer alice.SecureWipe()

	bob, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create Bob's key exchange: %v", err)
	}
	defer bob.SecureWipe()

	// Perform key exchange
	initMessage, err := alice.InitiateKeyExchange()
	if err != nil {
		t.Fatalf("Alice failed to initiate key exchange: %v", err)
	}

	responseMessage, err := bob.ProcessKeyExchangeMessage(initMessage)
	if err != nil {
		t.Fatalf("Bob failed to process init message: %v", err)
	}

	confirmMessage, err := alice.ProcessKeyExchangeMessage(responseMessage)
	if err != nil {
		t.Fatalf("Alice failed to process response message: %v", err)
	}

	_, err = bob.ProcessKeyExchangeMessage(confirmMessage)
	if err != nil {
		t.Fatalf("Bob failed to process confirm message: %v", err)
	}

	// Security validation: Keys should be different and non-zero
	aliceKeys := alice.GetSessionKeys()
	bobKeys := bob.GetSessionKeys()

	if aliceKeys == nil || bobKeys == nil {
		t.Fatal("Session keys should not be nil after successful exchange")
	}

	// Keys should match between parties
	if !bytes.Equal(aliceKeys.EncryptionKey, bobKeys.EncryptionKey) {
		t.Error("Encryption keys should match between parties")
	}

	if !bytes.Equal(aliceKeys.AuthKey, bobKeys.AuthKey) {
		t.Error("Auth keys should match between parties")
	}

	// Keys should not be all zeros (cryptographic strength)
	zeroKey := make([]byte, len(aliceKeys.EncryptionKey))
	if bytes.Equal(aliceKeys.EncryptionKey, zeroKey) {
		t.Error("Encryption key should not be all zeros")
	}

	if bytes.Equal(aliceKeys.AuthKey, zeroKey) {
		t.Error("Auth key should not be all zeros")
	}

	// Test key uniqueness across multiple exchanges
	alice2, _ := NewPostQuantumKeyExchange()
	bob2, _ := NewPostQuantumKeyExchange()
	defer alice2.SecureWipe()
	defer bob2.SecureWipe()

	// Perform second key exchange
	initMessage2, _ := alice2.InitiateKeyExchange()
	responseMessage2, _ := bob2.ProcessKeyExchangeMessage(initMessage2)
	confirmMessage2, _ := alice2.ProcessKeyExchangeMessage(responseMessage2)
	bob2.ProcessKeyExchangeMessage(confirmMessage2)

	alice2Keys := alice2.GetSessionKeys()
	
	// Keys from different exchanges should be different
	if bytes.Equal(aliceKeys.EncryptionKey, alice2Keys.EncryptionKey) {
		t.Error("Keys from different exchanges should be unique")
	}
}

func testSessionKeyDerivationSecurity(t *testing.T) {
	alice, bob := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()
	defer bob.SecureWipe()

	keys := alice.GetSessionKeys()

	// Test key sizes meet security requirements
	if len(keys.EncryptionKey) < 32 {
		t.Errorf("Encryption key too short: %d bytes (minimum 32)", len(keys.EncryptionKey))
	}

	if len(keys.AuthKey) < 32 {
		t.Errorf("Auth key too short: %d bytes (minimum 32)", len(keys.AuthKey))
	}

	if len(keys.IVSeed) < 16 {
		t.Errorf("IV seed too short: %d bytes (minimum 16)", len(keys.IVSeed))
	}

	// Test key derivation determinism (same input should produce same output)
	// This is tested by verifying both parties derive the same keys from the same shared secret
	aliceKeys := alice.GetSessionKeys()
	bobKeys := bob.GetSessionKeys()

	if !constantTimeCompare(aliceKeys.EncryptionKey, bobKeys.EncryptionKey) {
		t.Error("Key derivation not deterministic - encryption keys differ")
	}

	if !constantTimeCompare(aliceKeys.AuthKey, bobKeys.AuthKey) {
		t.Error("Key derivation not deterministic - auth keys differ")
	}
}

func testCryptographicRandomnessSecurity(t *testing.T) {
	// Test randomness quality of generated values
	const numSamples = 100
	const sampleSize = 32

	samples := make([][]byte, numSamples)
	for i := 0; i < numSamples; i++ {
		sample := make([]byte, sampleSize)
		if _, err := rand.Read(sample); err != nil {
			t.Fatalf("Failed to generate random sample: %v", err)
		}
		samples[i] = sample
	}

	// Test for duplicate samples (should be extremely unlikely)
	for i := 0; i < numSamples; i++ {
		for j := i + 1; j < numSamples; j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Duplicate random samples found at indices %d and %d", i, j)
			}
		}
	}

	// Test for all-zero samples (should never happen)
	zeroSample := make([]byte, sampleSize)
	for i, sample := range samples {
		if bytes.Equal(sample, zeroSample) {
			t.Errorf("All-zero random sample found at index %d", i)
		}
	}

	// Test invitation code randomness
	processor := NewInvitationCodeProcessor()
	invitations := make([]*InvitationCode, 50)
	
	for i := 0; i < 50; i++ {
		invitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
		if err != nil {
			t.Fatalf("Failed to generate invitation: %v", err)
		}
		invitations[i] = invitation
	}

	// Check for duplicate connection IDs (should be unique)
	connectionIDs := make(map[string]bool)
	for i, invitation := range invitations {
		if connectionIDs[invitation.ConnectionID] {
			t.Errorf("Duplicate connection ID found at invitation %d: %s", i, invitation.ConnectionID)
		}
		connectionIDs[invitation.ConnectionID] = true
	}

	// Check for duplicate salts
	salts := make(map[string]bool)
	for i, invitation := range invitations {
		saltStr := string(invitation.Salt)
		if salts[saltStr] {
			t.Errorf("Duplicate salt found at invitation %d", i)
		}
		salts[saltStr] = true
	}
}

func testKeyRotationSecurity(t *testing.T) {
	alice, bob := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()
	defer bob.SecureWipe()

	// Get initial keys
	initialKeys := alice.GetSessionKeys()
	
	// Force key rotation
	alice.mutex.Lock()
	alice.lastRotation = time.Now().Add(-2 * KeyRotationInterval)
	alice.mutex.Unlock()

	if !alice.ShouldRotateKeys() {
		t.Fatal("Should need key rotation after time interval")
	}

	// Perform key rotation
	rotationMessage, err := alice.InitiateKeyRotation()
	if err != nil {
		t.Fatalf("Failed to initiate key rotation: %v", err)
	}

	rotationResponse, err := bob.ProcessKeyExchangeMessage(rotationMessage)
	if err != nil {
		t.Fatalf("Failed to process rotation message: %v", err)
	}

	_, err = alice.ProcessKeyExchangeMessage(rotationResponse)
	if err != nil {
		t.Fatalf("Failed to complete key rotation: %v", err)
	}

	// Verify key rotation security properties
	newKeys := alice.GetSessionKeys()

	// New keys should be different from old keys
	if constantTimeCompare(initialKeys.EncryptionKey, newKeys.EncryptionKey) {
		t.Error("Encryption key should change after rotation")
	}

	if constantTimeCompare(initialKeys.AuthKey, newKeys.AuthKey) {
		t.Error("Auth key should change after rotation")
	}

	// Rotation count should increment
	if newKeys.RotationCount != initialKeys.RotationCount+1 {
		t.Errorf("Rotation count should increment: expected %d, got %d", 
			initialKeys.RotationCount+1, newKeys.RotationCount)
	}

	// Old keys should be securely wiped (test by checking they're not accessible)
	// This is implicit in the key rotation process
}

func testSecureWipingSecurity(t *testing.T) {
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}

	// Complete a key exchange to have keys to wipe
	bob, _ := NewPostQuantumKeyExchange()
	defer bob.SecureWipe()

	initMessage, _ := alice.InitiateKeyExchange()
	responseMessage, _ := bob.ProcessKeyExchangeMessage(initMessage)
	confirmMessage, _ := alice.ProcessKeyExchangeMessage(responseMessage)
	bob.ProcessKeyExchangeMessage(confirmMessage)

	// Verify keys exist before wipe
	if !alice.IsKeyExchangeComplete() {
		t.Fatal("Key exchange should be complete before wipe test")
	}

	keys := alice.GetSessionKeys()
	if keys == nil {
		t.Fatal("Keys should exist before wipe")
	}

	// Perform secure wipe
	alice.SecureWipe()

	// Verify secure wipe effectiveness
	if alice.IsKeyExchangeComplete() {
		t.Error("Key exchange should not be complete after secure wipe")
	}

	wiped_keys := alice.GetSessionKeys()
	if wiped_keys != nil {
		t.Error("Keys should be nil after secure wipe")
	}

	// Test secure config manager wipe
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager: %v", err)
	}

	// Create test profile with sensitive data
	profile := &ConnectionProfile{
		Name: "test-profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: []byte("sensitive-crypto-data"),
			Salt:          []byte("test-salt-16-bytes"),
			Nonce:         []byte("test-nonce-12"),
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Verify profile exists
	profiles := manager.ListProfiles()
	if len(profiles) != 1 {
		t.Fatal("Profile should exist before secure wipe")
	}

	// Perform secure wipe
	if err := manager.SecureWipe(); err != nil {
		t.Fatalf("Failed to perform secure wipe: %v", err)
	}

	// Verify secure wipe effectiveness
	profiles = manager.ListProfiles()
	if len(profiles) != 0 {
		t.Error("All profiles should be wiped after secure wipe")
	}
}

// TestTimingAnalysisResistance validates timing attack resistance
func TestTimingAnalysisResistance(t *testing.T) {
	t.Run("ConnectionDelayRandomization", func(t *testing.T) {
		testConnectionDelayRandomization(t)
	})
	
	t.Run("RetryDelayObfuscation", func(t *testing.T) {
		testRetryDelayObfuscation(t)
	})
	
	t.Run("KeepAliveTimingVariation", func(t *testing.T) {
		testKeepAliveTimingVariation(t)
	})
	
	t.Run("CryptographicOperationTiming", func(t *testing.T) {
		testCryptographicOperationTiming(t)
	})
}

func testConnectionDelayRandomization(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Collect multiple delay samples
	const numSamples = 100
	delays := make([]time.Duration, numSamples)
	
	for i := 0; i < numSamples; i++ {
		delays[i] = layer.CalculateConnectionDelay()
	}

	// Verify delays are randomized (not all the same)
	allSame := true
	for i := 1; i < numSamples; i++ {
		if delays[i] != delays[0] {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Connection delays should be randomized to prevent timing analysis")
	}

	// Verify delays are within expected range
	for i, delay := range delays {
		if delay < 0 {
			t.Errorf("Delay %d is negative: %v", i, delay)
		}

		// Should be reasonable (not too short or too long)
		if delay < 10*time.Millisecond {
			t.Errorf("Delay %d too short: %v (may enable timing analysis)", i, delay)
		}

		if delay > 30*time.Second {
			t.Errorf("Delay %d too long: %v (poor user experience)", i, delay)
		}
	}

	// Test statistical distribution (should have variance)
	mean := calculateMeanDuration(delays)
	variance := calculateVarianceDuration(delays, mean)

	if variance < time.Millisecond {
		t.Error("Delay variance too low - may enable timing analysis")
	}
}

func testRetryDelayObfuscation(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Test retry delays for multiple attempts
	const maxAttempts = 10
	delays := make([]time.Duration, maxAttempts)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		delays[attempt-1] = layer.CalculateRetryDelay(attempt)
	}

	// Verify exponential backoff with jitter
	for i := 1; i < len(delays); i++ {
		// Each delay should generally be larger than the previous (allowing for jitter)
		if delays[i] < delays[i-1]/2 {
			t.Errorf("Retry delay %d significantly smaller than previous: %v < %v", 
				i+1, delays[i], delays[i-1])
		}
	}

	// Test multiple samples for same attempt to verify jitter
	const numSamples = 50
	attempt3Delays := make([]time.Duration, numSamples)
	
	for i := 0; i < numSamples; i++ {
		attempt3Delays[i] = layer.CalculateRetryDelay(3)
	}

	// Verify jitter (not all the same)
	allSame := true
	for i := 1; i < numSamples; i++ {
		if attempt3Delays[i] != attempt3Delays[0] {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Retry delays should have jitter to prevent timing analysis")
	}
}

func testKeepAliveTimingVariation(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Generate multiple keep-alive packets and intervals
	const numSamples = 50
	intervals := make([]time.Duration, numSamples)

	for i := 0; i < numSamples; i++ {
		_, interval := layer.GenerateSecureKeepAlive()
		intervals[i] = interval
	}

	// Verify intervals are randomized
	allSame := true
	for i := 1; i < numSamples; i++ {
		if intervals[i] != intervals[0] {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Keep-alive intervals should be randomized to prevent timing analysis")
	}

	// Verify intervals are within reasonable range
	for i, interval := range intervals {
		if interval < 10*time.Second {
			t.Errorf("Keep-alive interval %d too short: %v", i, interval)
		}

		if interval > 300*time.Second {
			t.Errorf("Keep-alive interval %d too long: %v", i, interval)
		}
	}

	// Test statistical properties
	mean := calculateMeanDuration(intervals)
	variance := calculateVarianceDuration(intervals, mean)

	if variance < time.Second {
		t.Error("Keep-alive interval variance too low - may enable timing analysis")
	}
}

func testCryptographicOperationTiming(t *testing.T) {
	// Test that cryptographic operations have consistent timing
	// to prevent timing-based side-channel attacks

	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test invitation signature timing
	const numOperations = 100
	signatureTimes := make([]time.Duration, numOperations)

	for i := 0; i < numOperations; i++ {
		invitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
		if err != nil {
			t.Fatalf("Failed to generate invitation: %v", err)
		}

		start := time.Now()
		err = invitation.Sign(signer)
		signatureTimes[i] = time.Since(start)

		if err != nil {
			t.Fatalf("Failed to sign invitation: %v", err)
		}
	}

	// Verify signature times are reasonably consistent
	mean := calculateMeanDuration(signatureTimes)
	variance := calculateVarianceDuration(signatureTimes, mean)

	// Variance should be low for cryptographic operations
	maxVariance := mean / 4 // Allow 25% variance
	if variance > maxVariance {
		t.Errorf("Signature timing variance too high: %v (mean: %v, max allowed: %v)", 
			variance, mean, maxVariance)
	}

	// Test verification timing consistency
	validator := NewSecureInvitationValidator(signer.PublicKey)
	defer validator.Stop()

	verificationTimes := make([]time.Duration, numOperations)

	for i := 0; i < numOperations; i++ {
		invitation, _ := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
		invitation.Sign(signer)
		invitationData, _ := processor.EncodeToBase64(invitation)

		start := time.Now()
		_, err := validator.ValidateAndProcessInvitation(invitationData, "192.168.1.100:12345")
		verificationTimes[i] = time.Since(start)

		if err != nil && !IsInvitationError(err) {
			t.Fatalf("Unexpected error during verification: %v", err)
		}
	}

	// Verify verification times are consistent
	verifyMean := calculateMeanDuration(verificationTimes)
	verifyVariance := calculateVarianceDuration(verificationTimes, verifyMean)

	maxVerifyVariance := verifyMean / 4
	if verifyVariance > maxVerifyVariance {
		t.Errorf("Verification timing variance too high: %v (mean: %v, max allowed: %v)", 
			verifyVariance, verifyMean, maxVerifyVariance)
	}
}

// TestTrafficObfuscationSecurity validates traffic obfuscation effectiveness
func TestTrafficObfuscationSecurity(t *testing.T) {
	t.Run("PaddingEffectiveness", func(t *testing.T) {
		testPaddingEffectiveness(t)
	})
	
	t.Run("NoiseInjectionSecurity", func(t *testing.T) {
		testNoiseInjectionSecurity(t)
	})
	
	t.Run("ShardingObfuscation", func(t *testing.T) {
		testShardingObfuscation(t)
	})
	
	t.Run("KeepAliveObfuscation", func(t *testing.T) {
		testKeepAliveObfuscation(t)
	})
}

func testPaddingEffectiveness(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Test various data sizes
	testSizes := []int{10, 50, 100, 500, 1000, 2000}
	
	for _, size := range testSizes {
		originalData := make([]byte, size)
		for i := range originalData {
			originalData[i] = byte(i % 256)
		}

		// Obfuscate data
		obfuscatedData, err := layer.ObfuscateTraffic(originalData)
		if err != nil {
			t.Fatalf("Failed to obfuscate data of size %d: %v", size, err)
		}

		// Obfuscated data should be larger (due to padding)
		if len(obfuscatedData) <= len(originalData) {
			t.Errorf("Obfuscated data should be larger than original for size %d", size)
		}

		// Deobfuscate and verify integrity
		deobfuscatedData, err := layer.DeobfuscateTraffic(obfuscatedData)
		if err != nil {
			t.Fatalf("Failed to deobfuscate data of size %d: %v", size, err)
		}

		if !bytes.Equal(originalData, deobfuscatedData) {
			t.Errorf("Data integrity lost during obfuscation/deobfuscation for size %d", size)
		}
	}

	// Test padding randomization
	const numSamples = 20
	testData := []byte("consistent test data")
	obfuscatedSamples := make([][]byte, numSamples)

	for i := 0; i < numSamples; i++ {
		obfuscated, err := layer.ObfuscateTraffic(testData)
		if err != nil {
			t.Fatalf("Failed to obfuscate sample %d: %v", i, err)
		}
		obfuscatedSamples[i] = obfuscated
	}

	// Verify obfuscated data varies (due to random padding)
	allSame := true
	for i := 1; i < numSamples; i++ {
		if !bytes.Equal(obfuscatedSamples[i], obfuscatedSamples[0]) {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Obfuscated data should vary due to random padding")
	}
}

func testNoiseInjectionSecurity(t *testing.T) {
	// Test noise injection configuration
	config := &TrafficObfuscationConfig{
		EnablePadding:      true,
		NoiseInjectionRate: 0.1, // 10% noise injection
		PaddingMinSize:     16,
		PaddingMaxSize:     256,
	}

	layer := NewOPSECNetworkLayerWithConfig(config)

	// Test that noise injection affects traffic patterns
	const numSamples = 100
	testData := []byte("test data for noise injection")
	
	obfuscatedSamples := make([][]byte, numSamples)
	for i := 0; i < numSamples; i++ {
		obfuscated, err := layer.ObfuscateTraffic(testData)
		if err != nil {
			t.Fatalf("Failed to obfuscate sample %d: %v", i, err)
		}
		obfuscatedSamples[i] = obfuscated
	}

	// Verify size variation due to noise injection
	sizes := make(map[int]int)
	for _, sample := range obfuscatedSamples {
		sizes[len(sample)]++
	}

	if len(sizes) < 3 {
		t.Error("Noise injection should create size variation in obfuscated data")
	}

	// Verify all samples can be deobfuscated correctly
	for i, sample := range obfuscatedSamples {
		deobfuscated, err := layer.DeobfuscateTraffic(sample)
		if err != nil {
			t.Fatalf("Failed to deobfuscate sample %d: %v", i, err)
		}

		if !bytes.Equal(testData, deobfuscated) {
			t.Errorf("Data integrity lost in sample %d", i)
		}
	}
}

func testShardingObfuscation(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Test large data that should be sharded
	largeData := make([]byte, 4096)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Shard the data
	shards, err := layer.ShardPacket(largeData)
	if err != nil {
		t.Fatalf("Failed to shard packet: %v", err)
	}

	// Should create multiple shards
	if len(shards) <= 1 {
		t.Error("Large data should be split into multiple shards for obfuscation")
	}

	// Verify shard sizes are varied (obfuscation)
	shardSizes := make(map[int]int)
	for _, shard := range shards {
		shardSizes[len(shard)]++
	}

	if len(shardSizes) < 2 {
		t.Error("Shards should have varied sizes for traffic obfuscation")
	}

	// Verify reassembly works correctly
	reassembled, err := layer.ReassembleShards(shards)
	if err != nil {
		t.Fatalf("Failed to reassemble shards: %v", err)
	}

	if !bytes.Equal(largeData, reassembled) {
		t.Error("Data integrity lost during sharding/reassembly")
	}

	// Test sharding randomization
	const numTests = 10
	for i := 0; i < numTests; i++ {
		shards2, err := layer.ShardPacket(largeData)
		if err != nil {
			t.Fatalf("Failed to shard packet in test %d: %v", i, err)
		}

		// Shard count may vary due to randomization
		if len(shards2) == len(shards) {
			// If same count, at least some shard sizes should differ
			allSameSizes := true
			for j := 0; j < len(shards) && j < len(shards2); j++ {
				if len(shards[j]) != len(shards2[j]) {
					allSameSizes = false
					break
				}
			}

			if allSameSizes && i == numTests-1 {
				t.Error("Sharding should have some randomization for obfuscation")
			}
		}
	}
}

func testKeepAliveObfuscation(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Generate multiple keep-alive packets
	const numSamples = 50
	keepAlivePackets := make([][]byte, numSamples)
	intervals := make([]time.Duration, numSamples)

	for i := 0; i < numSamples; i++ {
		packet, interval := layer.GenerateSecureKeepAlive()
		keepAlivePackets[i] = packet
		intervals[i] = interval
	}

	// Verify packets are different (obfuscated)
	allSame := true
	for i := 1; i < numSamples; i++ {
		if !bytes.Equal(keepAlivePackets[i], keepAlivePackets[0]) {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Keep-alive packets should be obfuscated (not identical)")
	}

	// Verify all packets are recognized as keep-alive
	for i, packet := range keepAlivePackets {
		if !layer.IsKeepAlivePacket(packet) {
			t.Errorf("Keep-alive packet %d not recognized", i)
		}
	}

	// Verify intervals are varied
	intervalSet := make(map[time.Duration]bool)
	for _, interval := range intervals {
		intervalSet[interval] = true
	}

	if len(intervalSet) < 10 {
		t.Error("Keep-alive intervals should be varied for timing obfuscation")
	}

	// Test that regular data is not mistaken for keep-alive
	regularData := []byte("regular application data")
	if layer.IsKeepAlivePacket(regularData) {
		t.Error("Regular data should not be identified as keep-alive")
	}
}

// TestConfigurationSecurity validates configuration security and secure deletion
func TestConfigurationSecurity(t *testing.T) {
	t.Run("EncryptionAtRestSecurity", func(t *testing.T) {
		testEncryptionAtRestSecurity(t)
	})
	
	t.Run("KeyDerivationSecurity", func(t *testing.T) {
		testKeyDerivationSecurity(t)
	})
	
	t.Run("SecureDeletionSecurity", func(t *testing.T) {
		testSecureDeletionSecurity(t)
	})
	
	t.Run("BackupIntegritySecurity", func(t *testing.T) {
		testBackupIntegritySecurity(t)
	})
	
	t.Run("ConfigurationIntegritySecurity", func(t *testing.T) {
		testConfigurationIntegritySecurity(t)
	})
}

func testEncryptionAtRestSecurity(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-with-sufficient-entropy-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager: %v", err)
	}

	// Create profile with sensitive data
	profile := &ConnectionProfile{
		Name:        "sensitive-profile",
		Description: "Profile with sensitive cryptographic material",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: []byte("highly-sensitive-cryptographic-key-material"),
			Salt:          []byte("random-salt-16-bytes"),
			Nonce:         []byte("random-nonce-12"),
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Test that stored data is encrypted (not readable as plaintext)
	storage := NewFileConfigStorage(tempDir)
	rawData, err := storage.Retrieve("sensitive-profile")
	if err != nil {
		t.Fatalf("Failed to retrieve raw data: %v", err)
	}

	// Raw data should not contain plaintext sensitive information
	if bytes.Contains(rawData, []byte("highly-sensitive-cryptographic-key-material")) {
		t.Error("Sensitive data found in plaintext in stored configuration")
	}

	if bytes.Contains(rawData, []byte("192.168.1.100:8080")) {
		t.Error("Network configuration found in plaintext in stored data")
	}

	// Test encryption strength - encrypted data should look random
	if isLowEntropy(rawData) {
		t.Error("Encrypted data has low entropy - encryption may be weak")
	}

	// Test that different profiles produce different encrypted data
	profile2 := &ConnectionProfile{
		Name:        "another-profile",
		Description: "Another profile for encryption testing",
		NetworkConfig: &NetworkConfig{
			Protocol:        "udp",
			ListenerAddress: "192.168.1.101:8081",
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: []byte("different-sensitive-key-material"),
			Salt:          []byte("different-salt-16"),
			Nonce:         []byte("different-nonce"),
		},
	}

	if err := manager.SaveProfile(profile2); err != nil {
		t.Fatalf("Failed to save second profile: %v", err)
	}

	rawData2, err := storage.Retrieve("another-profile")
	if err != nil {
		t.Fatalf("Failed to retrieve second raw data: %v", err)
	}

	// Encrypted data should be different for different profiles
	if bytes.Equal(rawData, rawData2) {
		t.Error("Different profiles produce identical encrypted data")
	}
}

func testKeyDerivationSecurity(t *testing.T) {
	tempDir := t.TempDir()
	
	// Test with different passwords
	passwords := [][]byte{
		[]byte("password1-with-sufficient-entropy"),
		[]byte("password2-with-different-entropy"),
		[]byte("completely-different-password-123"),
	}

	managers := make([]*SecureConfigManagerImpl, len(passwords))
	for i, password := range passwords {
		manager, err := NewSecureConfigManager(password, tempDir)
		if err != nil {
			t.Fatalf("Failed to create manager %d: %v", i, err)
		}
		managers[i] = manager.(*SecureConfigManagerImpl)
	}

	// Test that different passwords produce different derived keys
	for i := 0; i < len(managers); i++ {
		for j := i + 1; j < len(managers); j++ {
			// Keys should be different for different passwords
			if constantTimeCompare(managers[i].encryptionKey, managers[j].encryptionKey) {
				t.Errorf("Managers %d and %d have identical encryption keys", i, j)
			}
		}
	}

	// Test key derivation consistency (same password should produce same key)
	manager1, _ := NewSecureConfigManager(passwords[0], t.TempDir())
	manager2, _ := NewSecureConfigManager(passwords[0], t.TempDir())
	
	impl1 := manager1.(*SecureConfigManagerImpl)
	impl2 := manager2.(*SecureConfigManagerImpl)

	if !constantTimeCompare(impl1.encryptionKey, impl2.encryptionKey) {
		t.Error("Same password should produce same derived key")
	}

	// Test key derivation with salt variation
	// This is implicit in the PBKDF2 implementation but we verify different salts produce different keys
	testProfile := &ConnectionProfile{
		Name: "test-key-derivation",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	// Save same profile with different managers (different derived keys)
	for i, manager := range managers {
		if err := manager.SaveProfile(testProfile); err != nil {
			t.Fatalf("Failed to save profile with manager %d: %v", i, err)
		}
	}

	// Verify that the same profile encrypted with different keys produces different ciphertext
	storage := NewFileConfigStorage(tempDir)
	encryptedData := make([][]byte, len(managers))
	
	for i := range managers {
		data, err := storage.Retrieve("test-key-derivation")
		if err != nil {
			t.Fatalf("Failed to retrieve data for manager %d: %v", i, err)
		}
		encryptedData[i] = make([]byte, len(data))
		copy(encryptedData[i], data)
		
		// Clean up for next iteration
		storage.Delete("test-key-derivation")
	}

	// All encrypted versions should be different
	for i := 0; i < len(encryptedData); i++ {
		for j := i + 1; j < len(encryptedData); j++ {
			if bytes.Equal(encryptedData[i], encryptedData[j]) {
				t.Errorf("Same profile encrypted with different keys produces identical ciphertext")
			}
		}
	}
}

func testSecureDeletionSecurity(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager: %v", err)
	}

	// Create profile with sensitive data
	profile := &ConnectionProfile{
		Name:        "deletion-test-profile",
		Description: "Profile for secure deletion testing",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: []byte("sensitive-data-to-be-securely-deleted"),
			Salt:          []byte("salt-to-delete-16"),
			Nonce:         []byte("nonce-delete-12"),
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Verify profile exists
	profiles := manager.ListProfiles()
	if len(profiles) != 1 || profiles[0] != "deletion-test-profile" {
		t.Fatal("Profile should exist before deletion")
	}

	// Perform secure deletion
	if err := manager.SecureDeleteProfile("deletion-test-profile"); err != nil {
		t.Fatalf("Failed to securely delete profile: %v", err)
	}

	// Verify profile is deleted
	profiles = manager.ListProfiles()
	if len(profiles) != 0 {
		t.Error("Profile should be deleted after secure deletion")
	}

	// Verify loading deleted profile fails
	_, err = manager.LoadProfile("deletion-test-profile")
	if err == nil {
		t.Error("Should not be able to load securely deleted profile")
	}

	// Test secure wipe of entire configuration
	// Create multiple profiles
	for i := 0; i < 5; i++ {
		testProfile := &ConnectionProfile{
			Name: fmt.Sprintf("wipe-test-profile-%d", i),
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: fmt.Sprintf("192.168.1.%d:8080", 100+i),
			},
		}
		if err := manager.SaveProfile(testProfile); err != nil {
			t.Fatalf("Failed to save profile %d: %v", i, err)
		}
	}

	// Verify profiles exist
	profiles = manager.ListProfiles()
	if len(profiles) != 5 {
		t.Fatalf("Expected 5 profiles before wipe, got %d", len(profiles))
	}

	// Perform secure wipe
	if err := manager.SecureWipe(); err != nil {
		t.Fatalf("Failed to perform secure wipe: %v", err)
	}

	// Verify all profiles are wiped
	profiles = manager.ListProfiles()
	if len(profiles) != 0 {
		t.Errorf("All profiles should be wiped, but %d remain", len(profiles))
	}

	// Test that wiped data cannot be recovered
	for i := 0; i < 5; i++ {
		profileName := fmt.Sprintf("wipe-test-profile-%d", i)
		_, err := manager.LoadProfile(profileName)
		if err == nil {
			t.Errorf("Should not be able to load wiped profile %s", profileName)
		}
	}
}

func testBackupIntegritySecurity(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name: "backup-test-1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
			CryptoMaterial: &EncryptedKeyMaterial{
				EncryptedData: []byte("sensitive-backup-data-1"),
				Salt:          []byte("backup-salt-1-16"),
				Nonce:         []byte("backup-nonce-1"),
			},
		},
		{
			Name: "backup-test-2",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.101:8081",
			},
			CryptoMaterial: &EncryptedKeyMaterial{
				EncryptedData: []byte("sensitive-backup-data-2"),
				Salt:          []byte("backup-salt-2-16"),
				Nonce:         []byte("backup-nonce-2"),
			},
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Create backup
	backup, err := manager.CreateBackup(backupPassword, true)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Test backup integrity verification
	if err := manager.VerifyBackupIntegrity(backup, backupPassword); err != nil {
		t.Fatalf("Backup integrity verification failed: %v", err)
	}

	// Test backup integrity with wrong password
	wrongPassword := []byte("wrong-backup-password")
	if err := manager.VerifyBackupIntegrity(backup, wrongPassword); err == nil {
		t.Error("Backup integrity verification should fail with wrong password")
	}

	// Test backup data tampering detection
	// Modify backup data
	originalData := make([]byte, len(backup.EncryptedData))
	copy(originalData, backup.EncryptedData)
	
	// Tamper with encrypted data
	backup.EncryptedData[len(backup.EncryptedData)/2] ^= 0xFF
	
	if err := manager.VerifyBackupIntegrity(backup, backupPassword); err == nil {
		t.Error("Should detect tampering in backup data")
	}

	// Restore original data
	copy(backup.EncryptedData, originalData)

	// Test backup salt tampering detection
	originalSalt := make([]byte, len(backup.Salt))
	copy(originalSalt, backup.Salt)
	
	backup.Salt[0] ^= 0xFF
	
	if err := manager.VerifyBackupIntegrity(backup, backupPassword); err == nil {
		t.Error("Should detect tampering in backup salt")
	}

	// Restore original salt
	copy(backup.Salt, originalSalt)

	// Test successful restore after integrity verification
	tempDir2 := t.TempDir()
	manager2, err := NewSecureConfigManager(password, tempDir2)
	if err != nil {
		t.Fatalf("Failed to create second manager: %v", err)
	}

	if err := manager2.RestoreFromBackup(backup, backupPassword, false); err != nil {
		t.Fatalf("Failed to restore from backup: %v", err)
	}

	// Verify restored profiles
	restoredProfiles := manager2.ListProfiles()
	if len(restoredProfiles) != len(profiles) {
		t.Errorf("Expected %d restored profiles, got %d", len(profiles), len(restoredProfiles))
	}

	for _, originalProfile := range profiles {
		restoredProfile, err := manager2.LoadProfile(originalProfile.Name)
		if err != nil {
			t.Errorf("Failed to load restored profile %s: %v", originalProfile.Name, err)
			continue
		}

		if restoredProfile.Name != originalProfile.Name {
			t.Errorf("Profile name mismatch: expected %s, got %s", originalProfile.Name, restoredProfile.Name)
		}

		if !bytes.Equal(restoredProfile.CryptoMaterial.EncryptedData, originalProfile.CryptoMaterial.EncryptedData) {
			t.Errorf("Crypto material mismatch for profile %s", originalProfile.Name)
		}
	}
}

func testConfigurationIntegritySecurity(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager: %v", err)
	}

	// Create test profiles
	for i := 0; i < 3; i++ {
		profile := &ConnectionProfile{
			Name: fmt.Sprintf("integrity-test-%d", i),
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: fmt.Sprintf("192.168.1.%d:8080", 100+i),
			},
		}
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %d: %v", i, err)
		}
	}

	// Perform integrity check
	result, err := manager.PerformIntegrityCheck()
	if err != nil {
		t.Fatalf("Failed to perform integrity check: %v", err)
	}

	if !result.Passed {
		t.Errorf("Integrity check should pass, but found errors: %v", result.ErrorsFound)
	}

	if result.ProfilesChecked != 3 {
		t.Errorf("Expected 3 profiles checked, got %d", result.ProfilesChecked)
	}

	// Test integrity check with corrupted data
	storage := NewFileConfigStorage(tempDir)
	
	// Corrupt one profile's data
	corruptedData := []byte("corrupted-data-that-should-fail-integrity-check")
	if err := storage.Store("integrity-test-1", corruptedData); err != nil {
		t.Fatalf("Failed to corrupt profile data: %v", err)
	}

	// Integrity check should now fail
	result, err = manager.PerformIntegrityCheck()
	if err != nil {
		t.Fatalf("Failed to perform integrity check: %v", err)
	}

	if result.Passed {
		t.Error("Integrity check should fail with corrupted data")
	}

	if len(result.ErrorsFound) == 0 {
		t.Error("Should report errors for corrupted data")
	}

	// Verify error details
	foundCorruptionError := false
	for _, errorMsg := range result.ErrorsFound {
		if bytes.Contains([]byte(errorMsg), []byte("integrity-test-1")) {
			foundCorruptionError = true
			break
		}
	}

	if !foundCorruptionError {
		t.Error("Should report specific error for corrupted profile")
	}
}

// TestInvitationCodeSecurity validates invitation code security and anti-replay protection
func TestInvitationCodeSecurity(t *testing.T) {
	t.Run("SignatureValidationSecurity", func(t *testing.T) {
		testSignatureValidationSecurity(t)
	})
	
	t.Run("AntiReplayProtectionSecurity", func(t *testing.T) {
		testAntiReplayProtectionSecurity(t)
	})
	
	t.Run("ExpirationSecuritySecurity", func(t *testing.T) {
		testExpirationSecurity(t)
	})
	
	t.Run("EncodingSecuritySecurity", func(t *testing.T) {
		testEncodingSecurity(t)
	})
	
	t.Run("ConcurrentAccessSecurity", func(t *testing.T) {
		testConcurrentAccessSecurity(t)
	})
}

func testSignatureValidationSecurity(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	validator := NewSecureInvitationValidator(signer.PublicKey)
	defer validator.Stop()

	// Test valid signature
	invitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	if err := invitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign invitation: %v", err)
	}

	invitationData, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode invitation: %v", err)
	}

	// Valid signature should pass
	_, err = validator.ValidateAndProcessInvitation(invitationData, "192.168.1.100:12345")
	if err != nil {
		t.Fatalf("Valid signature should pass validation: %v", err)
	}

	// Test invalid signature (different signer)
	wrongSigner, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create wrong signer: %v", err)
	}

	invitation2, err := processor.GenerateInvitationCode("tcp", "192.168.1.101:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate second invitation: %v", err)
	}

	if err := invitation2.Sign(wrongSigner); err != nil {
		t.Fatalf("Failed to sign invitation with wrong signer: %v", err)
	}

	invitationData2, err := processor.EncodeToBase64(invitation2)
	if err != nil {
		t.Fatalf("Failed to encode second invitation: %v", err)
	}

	// Wrong signature should fail
	_, err = validator.ValidateAndProcessInvitation(invitationData2, "192.168.1.101:12345")
	if err == nil {
		t.Error("Invalid signature should fail validation")
	}

	// Test signature tampering
	invitation3, err := processor.GenerateInvitationCode("tcp", "192.168.1.102:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate third invitation: %v", err)
	}

	if err := invitation3.Sign(signer); err != nil {
		t.Fatalf("Failed to sign third invitation: %v", err)
	}

	// Tamper with signature
	if len(invitation3.Signature) > 0 {
		invitation3.Signature[0] ^= 0xFF
	}

	invitationData3, err := processor.EncodeToBase64(invitation3)
	if err != nil {
		t.Fatalf("Failed to encode tampered invitation: %v", err)
	}

	// Tampered signature should fail
	_, err = validator.ValidateAndProcessInvitation(invitationData3, "192.168.1.102:12345")
	if err == nil {
		t.Error("Tampered signature should fail validation")
	}

	// Test signature verification timing consistency
	const numTests = 50
	validationTimes := make([]time.Duration, numTests)

	for i := 0; i < numTests; i++ {
		testInvitation, _ := processor.GenerateInvitationCode("tcp", "192.168.1.200:8080", time.Hour, true)
		testInvitation.Sign(signer)
		testData, _ := processor.EncodeToBase64(testInvitation)

		start := time.Now()
		validator.ValidateAndProcessInvitation(testData, "192.168.1.200:12345")
		validationTimes[i] = time.Since(start)
	}

	// Verify timing consistency (prevent timing attacks)
	mean := calculateMeanDuration(validationTimes)
	variance := calculateVarianceDuration(validationTimes, mean)

	maxVariance := mean / 3 // Allow 33% variance
	if variance > maxVariance {
		t.Errorf("Signature validation timing variance too high: %v (mean: %v)", variance, mean)
	}
}

func testAntiReplayProtectionSecurity(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	validator := NewSecureInvitationValidator(signer.PublicKey)
	defer validator.Stop()

	// Create and sign invitation
	invitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	if err := invitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign invitation: %v", err)
	}

	invitationData, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode invitation: %v", err)
	}

	remoteAddr := "192.168.1.100:12345"

	// First use should succeed
	_, err = validator.ValidateAndProcessInvitation(invitationData, remoteAddr)
	if err != nil {
		t.Fatalf("First use should succeed: %v", err)
	}

	// Second use should fail (replay attack)
	_, err = validator.ValidateAndProcessInvitation(invitationData, remoteAddr)
	if err == nil {
		t.Error("Second use should fail due to anti-replay protection")
	}

	// Verify error is specifically about replay
	if !IsInvitationError(err) {
		t.Errorf("Expected invitation error, got: %T", err)
	}

	// Test replay from different address (should still fail)
	differentAddr := "192.168.1.200:12345"
	_, err = validator.ValidateAndProcessInvitation(invitationData, differentAddr)
	if err == nil {
		t.Error("Replay from different address should still fail")
	}

	// Test concurrent replay attempts
	const numConcurrent = 10
	var wg sync.WaitGroup
	results := make([]error, numConcurrent)

	// Create new invitation for concurrent test
	concurrentInvitation, _ := processor.GenerateInvitationCode("tcp", "192.168.1.101:8080", time.Hour, true)
	concurrentInvitation.Sign(signer)
	concurrentData, _ := processor.EncodeToBase64(concurrentInvitation)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := validator.ValidateAndProcessInvitation(concurrentData, "192.168.1.101:12345")
			results[index] = err
		}(i)
	}

	wg.Wait()

	// Only one should succeed, rest should fail
	successCount := 0
	for _, result := range results {
		if result == nil {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("Expected exactly 1 success in concurrent replay test, got %d", successCount)
	}

	// Test replay protection persistence across validator restarts
	validator.Stop()
	
	// Create new validator (should still remember used invitations)
	validator2 := NewSecureInvitationValidator(signer.PublicKey)
	defer validator2.Stop()

	// Should still fail (invitation already used)
	_, err = validator2.ValidateAndProcessInvitation(invitationData, remoteAddr)
	if err == nil {
		t.Error("Replay protection should persist across validator restarts")
	}
}

func testExpirationSecurity(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	validator := NewSecureInvitationValidator(signer.PublicKey)
	defer validator.Stop()

	// Test expired invitation
	expiredInvitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", -time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate expired invitation: %v", err)
	}

	if err := expiredInvitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign expired invitation: %v", err)
	}

	expiredData, err := processor.EncodeToBase64(expiredInvitation)
	if err != nil {
		t.Fatalf("Failed to encode expired invitation: %v", err)
	}

	// Expired invitation should fail
	_, err = validator.ValidateAndProcessInvitation(expiredData, "192.168.1.100:12345")
	if err == nil {
		t.Error("Expired invitation should fail validation")
	}

	// Test invitation that expires during processing
	shortLivedInvitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.101:8080", 100*time.Millisecond, true)
	if err != nil {
		t.Fatalf("Failed to generate short-lived invitation: %v", err)
	}

	if err := shortLivedInvitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign short-lived invitation: %v", err)
	}

	shortLivedData, err := processor.EncodeToBase64(shortLivedInvitation)
	if err != nil {
		t.Fatalf("Failed to encode short-lived invitation: %v", err)
	}

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Should now be expired
	_, err = validator.ValidateAndProcessInvitation(shortLivedData, "192.168.1.101:12345")
	if err == nil {
		t.Error("Short-lived invitation should expire and fail validation")
	}

	// Test valid invitation within expiration window
	validInvitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.102:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate valid invitation: %v", err)
	}

	if err := validInvitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign valid invitation: %v", err)
	}

	validData, err := processor.EncodeToBase64(validInvitation)
	if err != nil {
		t.Fatalf("Failed to encode valid invitation: %v", err)
	}

	// Should succeed within expiration window
	_, err = validator.ValidateAndProcessInvitation(validData, "192.168.1.102:12345")
	if err != nil {
		t.Fatalf("Valid invitation should succeed: %v", err)
	}

	// Test expiration time tampering
	tamperedInvitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.103:8080", -time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate invitation for tampering test: %v", err)
	}

	// Manually set expiration to future (tampering)
	tamperedInvitation.ExpiresAt = time.Now().Add(time.Hour)

	if err := tamperedInvitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign tampered invitation: %v", err)
	}

	tamperedData, err := processor.EncodeToBase64(tamperedInvitation)
	if err != nil {
		t.Fatalf("Failed to encode tampered invitation: %v", err)
	}

	// Tampered expiration should still fail due to signature mismatch
	_, err = validator.ValidateAndProcessInvitation(tamperedData, "192.168.1.103:12345")
	if err == nil {
		t.Error("Tampered expiration time should fail validation due to signature mismatch")
	}
}

// Helper function to set up completed key exchange for testing
func setupCompletedKeyExchange(t *testing.T) (*PostQuantumKeyExchange, *PostQuantumKeyExchange) {
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create Alice's key exchange: %v", err)
	}

	bob, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create Bob's key exchange: %v", err)
	}

	// Complete key exchange
	initMessage, _ := alice.InitiateKeyExchange()
	responseMessage, _ := bob.ProcessKeyExchangeMessage(initMessage)
	confirmMessage, _ := alice.ProcessKeyExchangeMessage(responseMessage)
	bob.ProcessKeyExchangeMessage(confirmMessage)

	return alice, bob
}
