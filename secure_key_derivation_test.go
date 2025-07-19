package main

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// TestSecureCombineSharedSecrets tests the secure key combination function
func TestSecureCombineSharedSecrets(t *testing.T) {
	t.Run("ValidInputs", func(t *testing.T) {
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		
		contextInfo := []byte("TEST-CONTEXT")
		
		result, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
		if err != nil {
			t.Fatalf("SecureCombineSharedSecrets failed: %v", err)
		}
		
		if len(result) != 32 {
			t.Errorf("Expected 32-byte result, got %d bytes", len(result))
		}
		
		// Result should not be all zeros
		allZero := true
		for _, b := range result {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("Result is all zeros")
		}
	})
	
	t.Run("DifferentInputsProduceDifferentOutputs", func(t *testing.T) {
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		secret3 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		rand.Read(secret3)
		
		contextInfo := []byte("TEST-CONTEXT")
		
		result1, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
		if err != nil {
			t.Fatalf("First combination failed: %v", err)
		}
		
		result2, err := SecureCombineSharedSecrets(secret1, secret3, contextInfo)
		if err != nil {
			t.Fatalf("Second combination failed: %v", err)
		}
		
		if bytes.Equal(result1, result2) {
			t.Error("Different inputs produced same output")
		}
	})
	
	t.Run("SameInputsProduceDifferentOutputs", func(t *testing.T) {
		// Due to random salt, same inputs should produce different outputs
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		
		contextInfo := []byte("TEST-CONTEXT")
		
		result1, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
		if err != nil {
			t.Fatalf("First combination failed: %v", err)
		}
		
		result2, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
		if err != nil {
			t.Fatalf("Second combination failed: %v", err)
		}
		
		if bytes.Equal(result1, result2) {
			t.Error("Same inputs produced same output (salt not working)")
		}
	})
	
	t.Run("InvalidInputs", func(t *testing.T) {
		validSecret := make([]byte, 32)
		rand.Read(validSecret)
		contextInfo := []byte("TEST-CONTEXT")
		
		// Test nil inputs
		_, err := SecureCombineSharedSecrets(nil, validSecret, contextInfo)
		if err == nil {
			t.Error("Expected error for nil secret1")
		}
		
		_, err = SecureCombineSharedSecrets(validSecret, nil, contextInfo)
		if err == nil {
			t.Error("Expected error for nil secret2")
		}
		
		// Test empty inputs
		_, err = SecureCombineSharedSecrets([]byte{}, validSecret, contextInfo)
		if err == nil {
			t.Error("Expected error for empty secret1")
		}
		
		// Test mismatched lengths
		shortSecret := make([]byte, 16)
		rand.Read(shortSecret)
		_, err = SecureCombineSharedSecrets(validSecret, shortSecret, contextInfo)
		if err == nil {
			t.Error("Expected error for mismatched secret lengths")
		}
		
		// Test all-zero secret
		zeroSecret := make([]byte, 32)
		_, err = SecureCombineSharedSecrets(zeroSecret, validSecret, contextInfo)
		if err == nil {
			t.Error("Expected error for all-zero secret")
		}
	})
}

// TestKeyDerivationSecurityProperties tests cryptographic security properties
func TestKeyDerivationSecurityProperties(t *testing.T) {
	t.Run("EntropyPreservation", func(t *testing.T) {
		// Test that output has sufficient entropy
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		
		contextInfo := []byte("ENTROPY-TEST")
		
		// Generate multiple outputs
		outputs := make([][]byte, 100)
		for i := 0; i < 100; i++ {
			result, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
			if err != nil {
				t.Fatalf("Key derivation failed: %v", err)
			}
			outputs[i] = result
		}
		
		// Check that all outputs are different (due to random salt)
		for i := 0; i < len(outputs); i++ {
			for j := i + 1; j < len(outputs); j++ {
				if bytes.Equal(outputs[i], outputs[j]) {
					t.Errorf("Outputs %d and %d are identical", i, j)
				}
			}
		}
	})
	
	t.Run("DomainSeparation", func(t *testing.T) {
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		
		// Different contexts should produce different results
		result1, err := SecureCombineSharedSecrets(secret1, secret2, []byte("CONTEXT-1"))
		if err != nil {
			t.Fatalf("First derivation failed: %v", err)
		}
		
		result2, err := SecureCombineSharedSecrets(secret1, secret2, []byte("CONTEXT-2"))
		if err != nil {
			t.Fatalf("Second derivation failed: %v", err)
		}
		
		if bytes.Equal(result1, result2) {
			t.Error("Different contexts produced same result")
		}
	})
}

// TestSecureCombineSharedSecretsWithAlgorithm tests algorithm-specific key derivation
func TestSecureCombineSharedSecretsWithAlgorithm(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)
	contextInfo := []byte("ALGORITHM-TEST")
	
	t.Run("SHA256", func(t *testing.T) {
		result, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, KDF_HKDF_SHA256)
		if err != nil {
			t.Fatalf("SHA256 derivation failed: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected 32-byte result for SHA256, got %d", len(result))
		}
	})
	
	t.Run("SHA384", func(t *testing.T) {
		result, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, KDF_HKDF_SHA384)
		if err != nil {
			t.Fatalf("SHA384 derivation failed: %v", err)
		}
		if len(result) != 48 {
			t.Errorf("Expected 48-byte result for SHA384, got %d", len(result))
		}
	})
	
	t.Run("SHA512", func(t *testing.T) {
		result, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, KDF_HKDF_SHA512)
		if err != nil {
			t.Fatalf("SHA512 derivation failed: %v", err)
		}
		if len(result) != 64 {
			t.Errorf("Expected 64-byte result for SHA512, got %d", len(result))
		}
	})
	
	t.Run("InvalidAlgorithm", func(t *testing.T) {
		_, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, KeyDerivationAlgorithm(999))
		if err == nil {
			t.Error("Expected error for invalid algorithm")
		}
	})
	
	t.Run("DifferentAlgorithmsProduceDifferentResults", func(t *testing.T) {
		result256, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, KDF_HKDF_SHA256)
		if err != nil {
			t.Fatalf("SHA256 derivation failed: %v", err)
		}
		
		result384, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, KDF_HKDF_SHA384)
		if err != nil {
			t.Fatalf("SHA384 derivation failed: %v", err)
		}
		
		// Compare first 32 bytes (both should be different)
		if bytes.Equal(result256, result384[:32]) {
			t.Error("Different algorithms produced same result")
		}
	})
}

// TestKeyDerivationContext tests context-based key derivation
func TestKeyDerivationContext(t *testing.T) {
	t.Run("GenerateContextInfo", func(t *testing.T) {
		context := &KeyDerivationContext{
			Protocol:   "TCP",
			LocalPeer:  []byte("local-peer-id"),
			RemotePeer: []byte("remote-peer-id"),
			SessionID:  []byte("session-123"),
			Timestamp:  time.Now(),
		}
		
		info := context.GenerateContextInfo()
		if len(info) == 0 {
			t.Error("Generated context info is empty")
		}
		
		// Should contain protocol
		if !bytes.Contains(info, []byte("TCP")) {
			t.Error("Context info does not contain protocol")
		}
	})
	
	t.Run("SecureCombineWithContext", func(t *testing.T) {
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		
		context := &KeyDerivationContext{
			Protocol:   "UDP",
			LocalPeer:  []byte("peer1"),
			RemotePeer: []byte("peer2"),
			SessionID:  []byte("session-456"),
			Timestamp:  time.Now(),
		}
		
		result, err := SecureCombineSharedSecretsWithContext(secret1, secret2, context, KDF_HKDF_SHA256)
		if err != nil {
			t.Fatalf("Context-based derivation failed: %v", err)
		}
		
		if len(result) != 32 {
			t.Errorf("Expected 32-byte result, got %d", len(result))
		}
	})
	
	t.Run("NilContext", func(t *testing.T) {
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)
		
		_, err := SecureCombineSharedSecretsWithContext(secret1, secret2, nil, KDF_HKDF_SHA256)
		if err == nil {
			t.Error("Expected error for nil context")
		}
	})
}

// TestValidateSharedSecret tests shared secret validation
func TestValidateSharedSecret(t *testing.T) {
	t.Run("ValidSecret", func(t *testing.T) {
		secret := make([]byte, 32)
		rand.Read(secret)
		
		err := validateSharedSecret(secret, 32)
		if err != nil {
			t.Errorf("Valid secret failed validation: %v", err)
		}
	})
	
	t.Run("NilSecret", func(t *testing.T) {
		err := validateSharedSecret(nil, 32)
		if err == nil {
			t.Error("Expected error for nil secret")
		}
	})
	
	t.Run("EmptySecret", func(t *testing.T) {
		err := validateSharedSecret([]byte{}, 32)
		if err == nil {
			t.Error("Expected error for empty secret")
		}
	})
	
	t.Run("WrongSize", func(t *testing.T) {
		secret := make([]byte, 16)
		rand.Read(secret)
		
		err := validateSharedSecret(secret, 32)
		if err == nil {
			t.Error("Expected error for wrong size secret")
		}
	})
	
	t.Run("AllZeroSecret", func(t *testing.T) {
		secret := make([]byte, 32)
		// Leave all zeros
		
		err := validateSharedSecret(secret, 32)
		if err == nil {
			t.Error("Expected error for all-zero secret")
		}
	})
}

// TestLegacyMode tests backward compatibility
func TestLegacyMode(t *testing.T) {
	// Save original state
	originalMode := LegacyKeyDerivationMode
	defer func() {
		LegacyKeyDerivationMode = originalMode
	}()
	
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)
	
	t.Run("SecureMode", func(t *testing.T) {
		LegacyKeyDerivationMode = false
		
		result, err := CombineSharedSecrets(secret1, secret2)
		if err != nil {
			t.Fatalf("Secure mode failed: %v", err)
		}
		
		if len(result) != 32 {
			t.Errorf("Expected 32-byte result, got %d", len(result))
		}
	})
	
	t.Run("LegacyMode", func(t *testing.T) {
		LegacyKeyDerivationMode = true
		
		result, err := CombineSharedSecrets(secret1, secret2)
		if err != nil {
			t.Fatalf("Legacy mode failed: %v", err)
		}
		
		if len(result) != 32 {
			t.Errorf("Expected 32-byte result, got %d", len(result))
		}
	})
	
	t.Run("ModesProduceDifferentResults", func(t *testing.T) {
		LegacyKeyDerivationMode = false
		secureResult, err := CombineSharedSecrets(secret1, secret2)
		if err != nil {
			t.Fatalf("Secure mode failed: %v", err)
		}
		
		LegacyKeyDerivationMode = true
		legacyResult, err := CombineSharedSecrets(secret1, secret2)
		if err != nil {
			t.Fatalf("Legacy mode failed: %v", err)
		}
		
		if bytes.Equal(secureResult, legacyResult) {
			t.Error("Secure and legacy modes produced same result")
		}
	})
}

// TestKeyDerivationConfig tests configuration validation
func TestKeyDerivationConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultKeyDerivationConfig()
		if config == nil {
			t.Fatal("Default config is nil")
		}
		
		err := ValidateKeyDerivationConfig(config)
		if err != nil {
			t.Errorf("Default config validation failed: %v", err)
		}
		
		if config.Algorithm != KDF_HKDF_SHA256 {
			t.Error("Default algorithm should be SHA256")
		}
		
		if config.EnableLegacy {
			t.Error("Default should not enable legacy mode")
		}
		
		if config.SaltSize != 32 {
			t.Errorf("Expected salt size 32, got %d", config.SaltSize)
		}
	})
	
	t.Run("ValidConfig", func(t *testing.T) {
		config := &KeyDerivationConfig{
			Algorithm:    KDF_HKDF_SHA384,
			EnableLegacy: false,
			SaltSize:     48,
		}
		
		err := ValidateKeyDerivationConfig(config)
		if err != nil {
			t.Errorf("Valid config validation failed: %v", err)
		}
	})
	
	t.Run("InvalidAlgorithm", func(t *testing.T) {
		config := &KeyDerivationConfig{
			Algorithm:    KeyDerivationAlgorithm(999),
			EnableLegacy: false,
			SaltSize:     32,
		}
		
		err := ValidateKeyDerivationConfig(config)
		if err == nil {
			t.Error("Expected error for invalid algorithm")
		}
	})
	
	t.Run("InvalidSaltSize", func(t *testing.T) {
		config := &KeyDerivationConfig{
			Algorithm:    KDF_HKDF_SHA256,
			EnableLegacy: false,
			SaltSize:     8, // Too small
		}
		
		err := ValidateKeyDerivationConfig(config)
		if err == nil {
			t.Error("Expected error for invalid salt size")
		}
	})
	
	t.Run("NilConfig", func(t *testing.T) {
		err := ValidateKeyDerivationConfig(nil)
		if err == nil {
			t.Error("Expected error for nil config")
		}
	})
}

// TestGetKeyDerivationAlgorithmName tests algorithm name retrieval
func TestGetKeyDerivationAlgorithmName(t *testing.T) {
	tests := []struct {
		algorithm KeyDerivationAlgorithm
		expected  string
	}{
		{KDF_HKDF_SHA256, "HKDF-SHA256"},
		{KDF_HKDF_SHA384, "HKDF-SHA384"},
		{KDF_HKDF_SHA512, "HKDF-SHA512"},
		{KeyDerivationAlgorithm(999), "UNKNOWN"},
	}
	
	for _, test := range tests {
		name := GetKeyDerivationAlgorithmName(test.algorithm)
		if name != test.expected {
			t.Errorf("Expected %s, got %s for algorithm %d", test.expected, name, test.algorithm)
		}
	}
}

// TestKeyDerivationStats tests statistics tracking
func TestKeyDerivationStats(t *testing.T) {
	// Reset stats for clean test
	ResetKeyDerivationStats()
	
	t.Run("InitialStats", func(t *testing.T) {
		stats := GetKeyDerivationStats()
		if stats.TotalDerivations != 0 {
			t.Errorf("Expected 0 total derivations, got %d", stats.TotalDerivations)
		}
		if stats.SuccessfulOps != 0 {
			t.Errorf("Expected 0 successful ops, got %d", stats.SuccessfulOps)
		}
		if stats.FailedOps != 0 {
			t.Errorf("Expected 0 failed ops, got %d", stats.FailedOps)
		}
	})
	
	t.Run("UpdateStats", func(t *testing.T) {
		// Update with successful operation
		UpdateKeyDerivationStats(true, time.Millisecond*10)
		
		stats := GetKeyDerivationStats()
		if stats.TotalDerivations != 1 {
			t.Errorf("Expected 1 total derivation, got %d", stats.TotalDerivations)
		}
		if stats.SuccessfulOps != 1 {
			t.Errorf("Expected 1 successful op, got %d", stats.SuccessfulOps)
		}
		if stats.FailedOps != 0 {
			t.Errorf("Expected 0 failed ops, got %d", stats.FailedOps)
		}
		if stats.AverageLatencyMs <= 0 {
			t.Error("Expected positive average latency")
		}
		
		// Update with failed operation
		UpdateKeyDerivationStats(false, time.Millisecond*5)
		
		stats = GetKeyDerivationStats()
		if stats.TotalDerivations != 2 {
			t.Errorf("Expected 2 total derivations, got %d", stats.TotalDerivations)
		}
		if stats.SuccessfulOps != 1 {
			t.Errorf("Expected 1 successful op, got %d", stats.SuccessfulOps)
		}
		if stats.FailedOps != 1 {
			t.Errorf("Expected 1 failed op, got %d", stats.FailedOps)
		}
	})
	
	t.Run("ResetStats", func(t *testing.T) {
		ResetKeyDerivationStats()
		
		stats := GetKeyDerivationStats()
		if stats.TotalDerivations != 0 {
			t.Errorf("Expected 0 total derivations after reset, got %d", stats.TotalDerivations)
		}
	})
}

// BenchmarkSecureCombineSharedSecrets benchmarks the secure key derivation
func BenchmarkSecureCombineSharedSecrets(b *testing.B) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)
	contextInfo := []byte("BENCHMARK-CONTEXT")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

// BenchmarkSecureCombineSharedSecretsWithAlgorithm benchmarks different algorithms
func BenchmarkSecureCombineSharedSecretsWithAlgorithm(b *testing.B) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)
	contextInfo := []byte("BENCHMARK-CONTEXT")
	
	algorithms := []struct {
		name string
		alg  KeyDerivationAlgorithm
	}{
		{"SHA256", KDF_HKDF_SHA256},
		{"SHA384", KDF_HKDF_SHA384},
		{"SHA512", KDF_HKDF_SHA512},
	}
	
	for _, algo := range algorithms {
		b.Run(algo.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := SecureCombineSharedSecretsWithAlgorithm(secret1, secret2, contextInfo, algo.alg)
				if err != nil {
					b.Fatalf("Benchmark failed: %v", err)
				}
			}
		})
	}
}

// TestMemoryCleanup tests that sensitive data is properly cleared
func TestMemoryCleanup(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)
	
	// Make copies to verify cleanup
	secret1Copy := make([]byte, 32)
	secret2Copy := make([]byte, 32)
	copy(secret1Copy, secret1)
	copy(secret2Copy, secret2)
	
	contextInfo := []byte("CLEANUP-TEST")
	
	result, err := SecureCombineSharedSecrets(secret1, secret2, contextInfo)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}
	
	// Verify result is valid
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d", len(result))
	}
	
	// Original secrets should still be intact (function doesn't modify inputs)
	if !bytes.Equal(secret1, secret1Copy) {
		t.Error("Input secret1 was modified")
	}
	if !bytes.Equal(secret2, secret2Copy) {
		t.Error("Input secret2 was modified")
	}
	
	// Clean up result
	secureZeroBytes(result)
	
	// Verify result was cleared
	for i, b := range result {
		if b != 0 {
			t.Errorf("Result byte %d was not cleared: %d", i, b)
		}
	}
}
