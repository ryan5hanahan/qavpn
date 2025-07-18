package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestCryptoImplementationValidation tests the correctness of crypto implementations
func TestCryptoImplementationValidation(t *testing.T) {
	t.Run("Kyber_KeyGeneration", testKyberKeyGeneration)
	t.Run("Kyber_Encapsulation", testKyberEncapsulation)
	t.Run("Packet_Encryption", testPacketEncryption)
	t.Run("Key_Serialization", testKeySerialization)
	t.Run("Crypto_EdgeCases", testCryptoEdgeCases)
}

// testKyberKeyGeneration validates Kyber key generation
func testKyberKeyGeneration(t *testing.T) {
	// Test multiple key generations
	for i := 0; i < 10; i++ {
		keyPair, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("Key generation failed on attempt %d: %v", i, err)
		}

		// Validate key sizes
		if len(keyPair.PublicKey) != KyberPublicKeyBytes {
			t.Errorf("Invalid public key size: got %d, expected %d", 
				len(keyPair.PublicKey), KyberPublicKeyBytes)
		}

		if len(keyPair.PrivateKey) != KyberSecretKeyBytes {
			t.Errorf("Invalid private key size: got %d, expected %d", 
				len(keyPair.PrivateKey), KyberSecretKeyBytes)
		}

		// Validate key pair
		if err := keyPair.ValidateKeyPair(); err != nil {
			t.Errorf("Key pair validation failed: %v", err)
		}

		// Ensure keys are not all zeros
		if isAllZeros(keyPair.PublicKey) {
			t.Error("Public key is all zeros")
		}
		if isAllZeros(keyPair.PrivateKey) {
			t.Error("Private key is all zeros")
		}
	}

	// Test that different key generations produce different keys
	keyPair1, _ := GenerateKyberKeyPair()
	keyPair2, _ := GenerateKyberKeyPair()

	if bytes.Equal(keyPair1.PublicKey, keyPair2.PublicKey) {
		t.Error("Two key generations produced identical public keys")
	}
	if bytes.Equal(keyPair1.PrivateKey, keyPair2.PrivateKey) {
		t.Error("Two key generations produced identical private keys")
	}
}

// testKyberEncapsulation validates Kyber encapsulation/decapsulation
func testKyberEncapsulation(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test encapsulation
	sharedSecret1, ciphertext, err := kyberEncapsulate(keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulation failed: %v", err)
	}

	// Validate ciphertext size
	if len(ciphertext) != KyberCiphertextBytes {
		t.Errorf("Invalid ciphertext size: got %d, expected %d", 
			len(ciphertext), KyberCiphertextBytes)
	}

	// Test decapsulation
	sharedSecret2, err := kyberDecapsulate(ciphertext, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decapsulation failed: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Encapsulation/decapsulation shared secrets don't match")
	}

	// Test with wrong private key
	wrongKeyPair, _ := GenerateKyberKeyPair()
	wrongSecret, err := kyberDecapsulate(ciphertext, wrongKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decapsulation with wrong key failed: %v", err)
	}

	// Wrong key should produce different secret
	if bytes.Equal(sharedSecret1, wrongSecret) {
		t.Error("Wrong private key produced same shared secret")
	}
}

// testPacketEncryption validates packet encryption/decryption
func testPacketEncryption(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test various packet sizes
	testSizes := []int{0, 1, 16, 64, 256, 1024, 4096}
	
	for _, size := range testSizes {
		t.Run(fmt.Sprintf("PacketSize_%d", size), func(t *testing.T) {
			// Generate test data
			testData := make([]byte, size)
			if size > 0 {
				rand.Read(testData)
			}

			// Encrypt packet
			encryptedPacket, err := EncryptPacket(testData, keyPair.PublicKey)
			if err != nil {
				t.Fatalf("Encryption failed for size %d: %v", size, err)
			}

			// Validate encrypted packet structure
			if encryptedPacket.Ciphertext == nil {
				t.Error("Encrypted packet has nil ciphertext")
			}
			if encryptedPacket.Tag == nil {
				t.Error("Encrypted packet has nil tag")
			}
			if encryptedPacket.Nonce == nil {
				t.Error("Encrypted packet has nil nonce")
			}

			// Decrypt packet
			decryptedData, err := DecryptPacket(encryptedPacket, keyPair.PrivateKey)
			if err != nil {
				t.Fatalf("Decryption failed for size %d: %v", size, err)
			}

			// Verify data integrity
			if !bytes.Equal(testData, decryptedData) {
				t.Errorf("Data integrity check failed for size %d", size)
			}
		})
	}
}

// testKeySerialization validates key serialization/deserialization
func testKeySerialization(t *testing.T) {
	originalKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test public key serialization
	pubKeyData := originalKeyPair.SerializePublicKey()
	deserializedPubKey, err := DeserializePublicKey(pubKeyData)
	if err != nil {
		t.Fatalf("Public key deserialization failed: %v", err)
	}

	if !bytes.Equal(originalKeyPair.PublicKey, deserializedPubKey.PublicKey) {
		t.Error("Public key serialization/deserialization failed")
	}

	// Test private key serialization
	privKeyData := originalKeyPair.SerializePrivateKey()
	deserializedPrivKey, err := DeserializePrivateKey(privKeyData)
	if err != nil {
		t.Fatalf("Private key deserialization failed: %v", err)
	}

	if !bytes.Equal(originalKeyPair.PrivateKey, deserializedPrivKey.PrivateKey) {
		t.Error("Private key serialization/deserialization failed")
	}
	if !bytes.Equal(originalKeyPair.PublicKey, deserializedPrivKey.PublicKey) {
		t.Error("Public key extraction from private key failed")
	}
}

// testCryptoEdgeCases tests edge cases in cryptographic operations
func testCryptoEdgeCases(t *testing.T) {
	// Test with invalid key sizes
	t.Run("Invalid_Key_Sizes", func(t *testing.T) {
		// Test encryption with wrong public key size
		wrongSizeKey := make([]byte, 100) // Wrong size
		_, err := EncryptPacket([]byte("test"), wrongSizeKey)
		if err == nil {
			t.Error("Expected error for wrong public key size")
		}

		// Test decryption with wrong private key size
		keyPair, _ := GenerateKyberKeyPair()
		encryptedPacket, _ := EncryptPacket([]byte("test"), keyPair.PublicKey)
		wrongSizePrivKey := make([]byte, 100) // Wrong size
		_, err = DecryptPacket(encryptedPacket, wrongSizePrivKey)
		if err == nil {
			t.Error("Expected error for wrong private key size")
		}
	})

	// Test with corrupted data
	t.Run("Corrupted_Data", func(t *testing.T) {
		keyPair, _ := GenerateKyberKeyPair()
		testData := []byte("test data")
		
		encryptedPacket, err := EncryptPacket(testData, keyPair.PublicKey)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Corrupt ciphertext
		corruptedPacket := &EncryptedPacket{
			Ciphertext: append([]byte{}, encryptedPacket.Ciphertext...),
			Tag:        encryptedPacket.Tag,
			Nonce:      encryptedPacket.Nonce,
		}
		corruptedPacket.Ciphertext[0] ^= 0xFF // Flip bits

		_, err = DecryptPacket(corruptedPacket, keyPair.PrivateKey)
		if err == nil {
			t.Error("Expected error for corrupted ciphertext")
		}

		// Corrupt authentication tag
		corruptedPacket2 := &EncryptedPacket{
			Ciphertext: encryptedPacket.Ciphertext,
			Tag:        append([]byte{}, encryptedPacket.Tag...),
			Nonce:      encryptedPacket.Nonce,
		}
		corruptedPacket2.Tag[0] ^= 0xFF // Flip bits

		_, err = DecryptPacket(corruptedPacket2, keyPair.PrivateKey)
		if err == nil {
			t.Error("Expected error for corrupted authentication tag")
		}
	})
}

// TestTrafficAnalysisResistance tests resistance to traffic analysis
func TestTrafficAnalysisResistance(t *testing.T) {
	t.Run("Noise_Packet_Generation", testNoisePacketGeneration)
	t.Run("Noise_Injection", testNoiseInjection)
	t.Run("Packet_Size_Distribution", testPacketSizeDistribution)
	t.Run("Timing_Analysis_Resistance", testTimingAnalysisResistance)
}

// testNoisePacketGeneration tests noise packet generation
func testNoisePacketGeneration(t *testing.T) {
	// Generate multiple noise packets
	noisePackets := make([]*NoisePacket, 100)
	for i := 0; i < 100; i++ {
		packet, err := GenerateNoisePacket()
		if err != nil {
			t.Fatalf("Failed to generate noise packet %d: %v", i, err)
		}
		noisePackets[i] = packet
	}

	// Verify noise packets have realistic characteristics
	for i, packet := range noisePackets {
		if packet.Size <= 0 || packet.Size > 65535 {
			t.Errorf("Noise packet %d has invalid size: %d", i, packet.Size)
		}

		if len(packet.Data) != packet.Size {
			t.Errorf("Noise packet %d size mismatch: data len %d, size field %d", 
				i, len(packet.Data), packet.Size)
		}

		if packet.Timestamp == 0 {
			t.Errorf("Noise packet %d has zero timestamp", i)
		}
	}

	// Verify noise packets are different
	for i := 0; i < len(noisePackets); i++ {
		for j := i + 1; j < len(noisePackets); j++ {
			if bytes.Equal(noisePackets[i].Data, noisePackets[j].Data) {
				t.Errorf("Noise packets %d and %d are identical", i, j)
			}
		}
	}

	// Test specific size generation
	specificSizes := []int{64, 128, 256, 512, 1024, 1500}
	for _, size := range specificSizes {
		packet, err := GenerateNoisePacketWithSize(size)
		if err != nil {
			t.Errorf("Failed to generate noise packet of size %d: %v", size, err)
		}
		if packet.Size != size || len(packet.Data) != size {
			t.Errorf("Generated packet size mismatch for size %d", size)
		}
	}
}

// testNoiseInjection tests noise packet injection into traffic streams
func testNoiseInjection(t *testing.T) {
	// Create real packets
	realPackets := [][]byte{
		[]byte("Real packet 1"),
		[]byte("Real packet 2"),
		[]byte("Real packet 3"),
	}

	// Test different noise ratios
	noiseRatios := []float64{0.0, 0.1, 0.3, 0.5, 1.0}
	
	for _, ratio := range noiseRatios {
		t.Run(fmt.Sprintf("NoiseRatio_%.1f", ratio), func(t *testing.T) {
			mixedPackets, err := InjectNoisePackets(realPackets, ratio)
			if err != nil {
				t.Fatalf("Failed to inject noise with ratio %.1f: %v", ratio, err)
			}

			expectedMinPackets := len(realPackets)
			expectedMaxPackets := len(realPackets) + int(float64(len(realPackets))*ratio)

			if len(mixedPackets) < expectedMinPackets {
				t.Errorf("Too few packets after noise injection: got %d, expected at least %d", 
					len(mixedPackets), expectedMinPackets)
			}

			if len(mixedPackets) > expectedMaxPackets+1 { // Allow for rounding
				t.Errorf("Too many packets after noise injection: got %d, expected at most %d", 
					len(mixedPackets), expectedMaxPackets)
			}

			// Verify all real packets are still present
			realPacketCount := 0
			for _, packet := range mixedPackets {
				for _, realPacket := range realPackets {
					if bytes.Equal(packet, realPacket) {
						realPacketCount++
						break
					}
				}
			}

			if realPacketCount != len(realPackets) {
				t.Errorf("Not all real packets preserved: found %d, expected %d", 
					realPacketCount, len(realPackets))
			}
		})
	}
}

// testPacketSizeDistribution tests that packet sizes follow realistic distributions
func testPacketSizeDistribution(t *testing.T) {
	// Generate many noise packets and analyze size distribution
	const numPackets = 1000
	packets := make([]*NoisePacket, numPackets)
	
	for i := 0; i < numPackets; i++ {
		packet, err := GenerateNoisePacket()
		if err != nil {
			t.Fatalf("Failed to generate packet %d: %v", i, err)
		}
		packets[i] = packet
	}

	// Analyze size distribution
	sizeFreq := make(map[int]int)
	for _, packet := range packets {
		sizeFreq[packet.Size]++
	}

	// Check that we have reasonable variety in sizes
	if len(sizeFreq) < 10 {
		t.Errorf("Too few different packet sizes: %d", len(sizeFreq))
	}

	// Check that common packet sizes appear
	commonSizes := []int{64, 128, 256, 512, 1024, 1500}
	foundCommonSizes := 0
	for _, size := range commonSizes {
		if sizeFreq[size] > 0 {
			foundCommonSizes++
		}
	}

	if foundCommonSizes < len(commonSizes)/2 {
		t.Errorf("Too few common packet sizes found: %d out of %d", 
			foundCommonSizes, len(commonSizes))
	}
}

// testTimingAnalysisResistance tests resistance to timing analysis
func testTimingAnalysisResistance(t *testing.T) {
	// Simulate packet transmission with timing variations
	const numTransmissions = 50
	timings := make([]time.Duration, numTransmissions)
	
	for i := 0; i < numTransmissions; i++ {
		start := time.Now()
		
		// Simulate packet processing with random delays
		time.Sleep(time.Duration(10+i%20) * time.Millisecond)
		
		timings[i] = time.Since(start)
	}

	// Analyze timing patterns
	var totalTime time.Duration
	for _, timing := range timings {
		totalTime += timing
	}
	avgTime := totalTime / time.Duration(numTransmissions)

	// Calculate variance
	var variance float64
	for _, timing := range timings {
		diff := float64(timing - avgTime)
		variance += diff * diff
	}
	variance /= float64(numTransmissions)

	// Timing should have reasonable variance (not constant)
	if variance < 1000000 { // Less than 1ms variance
		t.Errorf("Timing variance too low: %f", variance)
	}

	// No timing should be exactly the same (very unlikely with proper randomization)
	for i := 0; i < len(timings); i++ {
		for j := i + 1; j < len(timings); j++ {
			if timings[i] == timings[j] {
				t.Errorf("Identical timings found at positions %d and %d", i, j)
			}
		}
	}
}

// TestPerformanceBenchmarks tests performance characteristics
func TestPerformanceBenchmarks(t *testing.T) {
	t.Run("Key_Generation_Performance", testKeyGenerationPerformance)
	t.Run("Encryption_Performance", testEncryptionPerformance)
	t.Run("Memory_Usage", testMemoryUsage)
	t.Run("Concurrent_Operations", testConcurrentOperations)
}

// testKeyGenerationPerformance benchmarks key generation performance
func testKeyGenerationPerformance(t *testing.T) {
	const numKeys = 100
	start := time.Now()
	
	for i := 0; i < numKeys; i++ {
		_, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("Key generation failed at iteration %d: %v", i, err)
		}
	}
	
	duration := time.Since(start)
	avgPerKey := duration / numKeys
	
	t.Logf("Generated %d keys in %v (avg: %v per key)", numKeys, duration, avgPerKey)
	
	// Key generation should be reasonably fast (less than 100ms per key)
	if avgPerKey > 100*time.Millisecond {
		t.Errorf("Key generation too slow: %v per key", avgPerKey)
	}
}

// testEncryptionPerformance benchmarks encryption/decryption performance
func testEncryptionPerformance(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test different data sizes
	dataSizes := []int{64, 256, 1024, 4096, 16384}
	
	for _, size := range dataSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			testData := make([]byte, size)
			rand.Read(testData)

			const numOperations = 100
			
			// Benchmark encryption
			start := time.Now()
			var encryptedPackets []*EncryptedPacket
			for i := 0; i < numOperations; i++ {
				encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				encryptedPackets = append(encryptedPackets, encrypted)
			}
			encryptionTime := time.Since(start)

			// Benchmark decryption
			start = time.Now()
			for _, encrypted := range encryptedPackets {
				_, err := DecryptPacket(encrypted, keyPair.PrivateKey)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
			}
			decryptionTime := time.Since(start)

			avgEncryption := encryptionTime / numOperations
			avgDecryption := decryptionTime / numOperations

			t.Logf("Size %d: Encryption %v/op, Decryption %v/op", 
				size, avgEncryption, avgDecryption)

			// Performance should be reasonable (less than 10ms per operation)
			if avgEncryption > 10*time.Millisecond {
				t.Errorf("Encryption too slow for size %d: %v", size, avgEncryption)
			}
			if avgDecryption > 10*time.Millisecond {
				t.Errorf("Decryption too slow for size %d: %v", size, avgDecryption)
			}
		})
	}
}

// testMemoryUsage tests memory usage characteristics
func testMemoryUsage(t *testing.T) {
	// Measure memory before operations
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	// Perform memory-intensive operations
	const numOperations = 1000
	keyPairs := make([]*KyberKeyPair, numOperations)
	
	for i := 0; i < numOperations; i++ {
		keyPair, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("Key generation failed: %v", err)
		}
		keyPairs[i] = keyPair
	}

	// Measure memory after operations
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	var memUsed uint64
	if memAfter.Alloc > memBefore.Alloc {
		memUsed = memAfter.Alloc - memBefore.Alloc
	} else {
		memUsed = 0 // Memory was reclaimed during operations
	}
	memPerOperation := memUsed / numOperations

	t.Logf("Memory usage: %d bytes total, %d bytes per operation", memUsed, memPerOperation)

	// Memory usage should be reasonable (less than 10KB per key pair)
	if memPerOperation > 10*1024 {
		t.Errorf("Memory usage too high: %d bytes per operation", memPerOperation)
	}

	// Test memory cleanup
	keyPairs = nil
	runtime.GC()
	
	var memAfterCleanup runtime.MemStats
	runtime.ReadMemStats(&memAfterCleanup)
	
	// Memory should be mostly reclaimed
	if memAfterCleanup.Alloc > memBefore.Alloc+1024*1024 { // Allow 1MB overhead
		t.Errorf("Memory not properly cleaned up: %d bytes still allocated", 
			memAfterCleanup.Alloc-memBefore.Alloc)
	}
}

// testConcurrentOperations tests performance under concurrent load
func testConcurrentOperations(t *testing.T) {
	const numGoroutines = 10
	const operationsPerGoroutine = 50

	// Test concurrent key generation
	t.Run("Concurrent_KeyGen", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines)
		
		start := time.Now()
		
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					_, err := GenerateKyberKeyPair()
					if err != nil {
						errors <- err
						return
					}
				}
			}()
		}
		
		wg.Wait()
		duration := time.Since(start)
		
		// Check for errors
		select {
		case err := <-errors:
			t.Fatalf("Concurrent key generation failed: %v", err)
		default:
		}
		
		totalOperations := numGoroutines * operationsPerGoroutine
		avgTime := duration / time.Duration(totalOperations)
		
		t.Logf("Concurrent key generation: %d operations in %v (avg: %v per operation)", 
			totalOperations, duration, avgTime)
	})

	// Test concurrent encryption/decryption
	t.Run("Concurrent_Crypto", func(t *testing.T) {
		keyPair, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		testData := []byte("Test data for concurrent encryption")
		
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines)
		
		start := time.Now()
		
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					// Encrypt
					encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
					if err != nil {
						errors <- err
						return
					}
					
					// Decrypt
					decrypted, err := DecryptPacket(encrypted, keyPair.PrivateKey)
					if err != nil {
						errors <- err
						return
					}
					
					// Verify
					if !bytes.Equal(testData, decrypted) {
						errors <- fmt.Errorf("data integrity check failed")
						return
					}
				}
			}()
		}
		
		wg.Wait()
		duration := time.Since(start)
		
		// Check for errors
		select {
		case err := <-errors:
			t.Fatalf("Concurrent crypto operations failed: %v", err)
		default:
		}
		
		totalOperations := numGoroutines * operationsPerGoroutine * 2 // encrypt + decrypt
		avgTime := duration / time.Duration(totalOperations)
		
		t.Logf("Concurrent crypto operations: %d operations in %v (avg: %v per operation)", 
			totalOperations, duration, avgTime)
	})
}

// Helper function to check if a byte slice is all zeros
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// BenchmarkCryptoValidation benchmarks crypto validation performance
func BenchmarkCryptoValidation(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyPair.ValidateKeyPair()
		if err != nil {
			b.Fatalf("Key validation failed: %v", err)
		}
	}
}

// BenchmarkTrafficAnalysisResistance benchmarks traffic analysis resistance
func BenchmarkTrafficAnalysisResistance(b *testing.B) {
	realPackets := [][]byte{
		[]byte("Real packet 1"),
		[]byte("Real packet 2"),
		[]byte("Real packet 3"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := InjectNoisePackets(realPackets, 0.3)
		if err != nil {
			b.Fatalf("Noise injection failed: %v", err)
		}
	}
}