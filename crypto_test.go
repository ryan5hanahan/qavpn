package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGenerateKyberKeyPair(t *testing.T) {
	// Test basic key generation
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Validate key pair
	if err := keyPair.ValidateKeyPair(); err != nil {
		t.Fatalf("Generated key pair is invalid: %v", err)
	}

	// Check key sizes
	if len(keyPair.PublicKey) != KyberPublicKeyBytes {
		t.Errorf("Public key size mismatch: got %d, expected %d", 
			len(keyPair.PublicKey), KyberPublicKeyBytes)
	}

	if len(keyPair.PrivateKey) != KyberSecretKeyBytes {
		t.Errorf("Private key size mismatch: got %d, expected %d", 
			len(keyPair.PrivateKey), KyberSecretKeyBytes)
	}
}

func TestKeyPairUniqueness(t *testing.T) {
	// Generate multiple key pairs and ensure they're different
	keyPair1, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("First key generation failed: %v", err)
	}

	keyPair2, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Second key generation failed: %v", err)
	}

	// Public keys should be different
	if bytes.Equal(keyPair1.PublicKey, keyPair2.PublicKey) {
		t.Error("Generated public keys are identical (should be unique)")
	}

	// Private keys should be different
	if bytes.Equal(keyPair1.PrivateKey, keyPair2.PrivateKey) {
		t.Error("Generated private keys are identical (should be unique)")
	}
}

func TestPublicKeySerialization(t *testing.T) {
	// Generate a key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Serialize public key
	serialized := keyPair.SerializePublicKey()
	if len(serialized) != KyberPublicKeyBytes {
		t.Errorf("Serialized public key size mismatch: got %d, expected %d", 
			len(serialized), KyberPublicKeyBytes)
	}

	// Deserialize public key
	deserialized, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("Public key deserialization failed: %v", err)
	}

	// Compare original and deserialized
	if !bytes.Equal(keyPair.PublicKey, deserialized.PublicKey) {
		t.Error("Public key serialization/deserialization roundtrip failed")
	}

	// Deserialized should not have private key
	if deserialized.PrivateKey != nil {
		t.Error("Deserialized public key should not contain private key")
	}
}

func TestPrivateKeySerialization(t *testing.T) {
	// Generate a key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Serialize private key
	serialized := keyPair.SerializePrivateKey()
	if len(serialized) != KyberSecretKeyBytes {
		t.Errorf("Serialized private key size mismatch: got %d, expected %d", 
			len(serialized), KyberSecretKeyBytes)
	}

	// Deserialize private key
	deserialized, err := DeserializePrivateKey(serialized)
	if err != nil {
		t.Fatalf("Private key deserialization failed: %v", err)
	}

	// Compare original and deserialized
	if !bytes.Equal(keyPair.PrivateKey, deserialized.PrivateKey) {
		t.Error("Private key serialization/deserialization roundtrip failed")
	}

	// Deserialized should also have public key
	if !bytes.Equal(keyPair.PublicKey, deserialized.PublicKey) {
		t.Error("Public key not properly extracted from private key")
	}
}

func TestKeyValidation(t *testing.T) {
	// Test validation of valid key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	if err := keyPair.ValidateKeyPair(); err != nil {
		t.Errorf("Valid key pair failed validation: %v", err)
	}

	// Test validation with nil public key
	invalidKeyPair := &KyberKeyPair{
		PublicKey:  nil,
		PrivateKey: keyPair.PrivateKey,
	}
	if err := invalidKeyPair.ValidateKeyPair(); err == nil {
		t.Error("Validation should fail for nil public key")
	}

	// Test validation with wrong public key size
	invalidKeyPair = &KyberKeyPair{
		PublicKey:  make([]byte, 100), // Wrong size
		PrivateKey: keyPair.PrivateKey,
	}
	if err := invalidKeyPair.ValidateKeyPair(); err == nil {
		t.Error("Validation should fail for wrong public key size")
	}

	// Test validation with wrong private key size
	invalidKeyPair = &KyberKeyPair{
		PublicKey:  keyPair.PublicKey,
		PrivateKey: make([]byte, 100), // Wrong size
	}
	if err := invalidKeyPair.ValidateKeyPair(); err == nil {
		t.Error("Validation should fail for wrong private key size")
	}
}

func TestInvalidDeserialization(t *testing.T) {
	// Test deserializing invalid public key size
	invalidData := make([]byte, 100) // Wrong size
	_, err := DeserializePublicKey(invalidData)
	if err == nil {
		t.Error("Should fail to deserialize invalid public key size")
	}

	// Test deserializing invalid private key size
	_, err = DeserializePrivateKey(invalidData)
	if err == nil {
		t.Error("Should fail to deserialize invalid private key size")
	}
}

func TestPolynomialOperations(t *testing.T) {
	// Test polynomial addition
	var a, b Polynomial
	for i := 0; i < KyberN; i++ {
		a[i] = uint16(i % KyberQ)
		b[i] = uint16((i * 2) % KyberQ)
	}

	result := addPolynomials(a, b)
	for i := 0; i < KyberN; i++ {
		expected := (a[i] + b[i]) % KyberQ
		if result[i] != expected {
			t.Errorf("Polynomial addition failed at index %d: got %d, expected %d", 
				i, result[i], expected)
		}
	}
}

func TestPolynomialVectorOperations(t *testing.T) {
	// Test polynomial vector addition
	var a, b PolynomialVector
	for i := 0; i < KyberK; i++ {
		for j := 0; j < KyberN; j++ {
			a[i][j] = uint16((i + j) % KyberQ)
			b[i][j] = uint16((i * j) % KyberQ)
		}
	}

	result := addPolynomialVectors(a, b)
	for i := 0; i < KyberK; i++ {
		for j := 0; j < KyberN; j++ {
			expected := (a[i][j] + b[i][j]) % KyberQ
			if result[i][j] != expected {
				t.Errorf("Polynomial vector addition failed at [%d][%d]: got %d, expected %d", 
					i, j, result[i][j], expected)
			}
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKyberKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

func BenchmarkKeySerialization(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = keyPair.SerializePublicKey()
		_ = keyPair.SerializePrivateKey()
	}
}

// Tests for PQC packet encryption/decryption (Task 2.2)

func TestPacketEncryptionDecryption(t *testing.T) {
	// Generate a key pair for testing
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test data
	testData := []byte("Hello, Quantum World! This is a test message for PQC encryption.")

	// Encrypt the packet
	encryptedPacket, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Packet encryption failed: %v", err)
	}

	// Verify encrypted packet structure
	if encryptedPacket == nil {
		t.Fatal("Encrypted packet is nil")
	}
	if len(encryptedPacket.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}
	if len(encryptedPacket.Tag) == 0 {
		t.Error("Authentication tag is empty")
	}
	if len(encryptedPacket.Nonce) == 0 {
		t.Error("Nonce is empty")
	}

	// Decrypt the packet
	decryptedData, err := DecryptPacket(encryptedPacket, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Packet decryption failed: %v", err)
	}

	// Verify decrypted data matches original
	if !bytes.Equal(testData, decryptedData) {
		t.Errorf("Decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", 
			string(testData), string(decryptedData))
	}
}

func TestPacketEncryptionWithDifferentSizes(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test different packet sizes
	testSizes := []int{0, 1, 16, 64, 256, 1024, 4096}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			// Generate test data of specific size
			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			// Encrypt and decrypt
			encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
			if err != nil {
				t.Fatalf("Encryption failed for size %d: %v", size, err)
			}

			decrypted, err := DecryptPacket(encrypted, keyPair.PrivateKey)
			if err != nil {
				t.Fatalf("Decryption failed for size %d: %v", size, err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Errorf("Data mismatch for size %d", size)
			}
		})
	}
}

func TestPacketEncryptionUniqueness(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	testData := []byte("Same message encrypted multiple times")

	// Encrypt the same message multiple times
	encrypted1, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Ciphertexts should be different (due to random nonces)
	if bytes.Equal(encrypted1.Ciphertext, encrypted2.Ciphertext) {
		t.Error("Identical ciphertexts for same message (should be different due to randomness)")
	}

	// Nonces should be different
	if bytes.Equal(encrypted1.Nonce, encrypted2.Nonce) {
		t.Error("Identical nonces (should be random)")
	}

	// Both should decrypt to the same original message
	decrypted1, err := DecryptPacket(encrypted1, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := DecryptPacket(encrypted2, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted1, decrypted2) {
		t.Error("Decrypted messages don't match")
	}

	if !bytes.Equal(testData, decrypted1) {
		t.Error("Decrypted message doesn't match original")
	}
}

func TestPacketEncryptionWithWrongKey(t *testing.T) {
	// Generate two different key pairs
	keyPair1, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("First key generation failed: %v", err)
	}

	keyPair2, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Second key generation failed: %v", err)
	}

	testData := []byte("Secret message")

	// Encrypt with first key pair
	encrypted, err := EncryptPacket(testData, keyPair1.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong private key
	_, err = DecryptPacket(encrypted, keyPair2.PrivateKey)
	if err == nil {
		t.Error("Decryption should fail with wrong private key")
	}
}

func TestPacketEncryptionInvalidInputs(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	testData := []byte("Test message")

	// Test encryption with invalid public key size
	invalidPublicKey := make([]byte, 100) // Wrong size
	_, err = EncryptPacket(testData, invalidPublicKey)
	if err == nil {
		t.Error("Encryption should fail with invalid public key size")
	}

	// Test decryption with invalid private key size
	encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	invalidPrivateKey := make([]byte, 100) // Wrong size
	_, err = DecryptPacket(encrypted, invalidPrivateKey)
	if err == nil {
		t.Error("Decryption should fail with invalid private key size")
	}
}

func TestPacketEncryptionTampering(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	testData := []byte("Important message")

	// Encrypt the packet
	encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Test tampering with ciphertext
	tamperedEncrypted := &EncryptedPacket{
		Ciphertext: append([]byte{}, encrypted.Ciphertext...), // Copy
		Tag:        encrypted.Tag,
		Nonce:      encrypted.Nonce,
	}
	if len(tamperedEncrypted.Ciphertext) > 0 {
		tamperedEncrypted.Ciphertext[0] ^= 1 // Flip one bit
	}

	_, err = DecryptPacket(tamperedEncrypted, keyPair.PrivateKey)
	if err == nil {
		t.Error("Decryption should fail with tampered ciphertext")
	}

	// Test tampering with authentication tag
	tamperedEncrypted = &EncryptedPacket{
		Ciphertext: encrypted.Ciphertext,
		Tag:        append([]byte{}, encrypted.Tag...), // Copy
		Nonce:      encrypted.Nonce,
	}
	if len(tamperedEncrypted.Tag) > 0 {
		tamperedEncrypted.Tag[0] ^= 1 // Flip one bit
	}

	_, err = DecryptPacket(tamperedEncrypted, keyPair.PrivateKey)
	if err == nil {
		t.Error("Decryption should fail with tampered authentication tag")
	}
}

func BenchmarkPacketEncryption(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	testData := make([]byte, 1024) // 1KB test data
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptPacket(testData, keyPair.PublicKey)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkPacketDecryption(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	testData := make([]byte, 1024) // 1KB test data
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptPacket(encrypted, keyPair.PrivateKey)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// Tests for noise packet generation (Task 2.3)

func TestGenerateNoisePacket(t *testing.T) {
	// Test basic noise packet generation
	noisePacket, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("Noise packet generation failed: %v", err)
	}

	// Verify packet structure
	if noisePacket == nil {
		t.Fatal("Generated noise packet is nil")
	}
	if len(noisePacket.Data) == 0 {
		t.Error("Noise packet data is empty")
	}
	if noisePacket.Size != len(noisePacket.Data) {
		t.Errorf("Noise packet size mismatch: size field %d, actual data length %d", 
			noisePacket.Size, len(noisePacket.Data))
	}
	if noisePacket.Timestamp == 0 {
		t.Error("Noise packet timestamp is zero")
	}

	// Verify packet size is realistic
	if noisePacket.Size < 40 || noisePacket.Size > 1500 {
		t.Errorf("Unrealistic noise packet size: %d (should be between 40-1500)", noisePacket.Size)
	}
}

func TestGenerateNoisePacketWithSize(t *testing.T) {
	testSizes := []int{0, 1, 64, 256, 512, 1024, 1500}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			noisePacket, err := GenerateNoisePacketWithSize(size)
			if err != nil {
				t.Fatalf("Noise packet generation failed for size %d: %v", size, err)
			}

			if len(noisePacket.Data) != size {
				t.Errorf("Generated packet size mismatch: expected %d, got %d", 
					size, len(noisePacket.Data))
			}
			if noisePacket.Size != size {
				t.Errorf("Size field mismatch: expected %d, got %d", size, noisePacket.Size)
			}
		})
	}
}

func TestGenerateNoisePacketInvalidSize(t *testing.T) {
	invalidSizes := []int{-1, -100, 65536, 100000}

	for _, size := range invalidSizes {
		t.Run(fmt.Sprintf("InvalidSize_%d", size), func(t *testing.T) {
			_, err := GenerateNoisePacketWithSize(size)
			if err == nil {
				t.Errorf("Should fail for invalid size %d", size)
			}
		})
	}
}

func TestNoisePacketUniqueness(t *testing.T) {
	// Generate multiple noise packets and verify they're different
	packet1, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("First noise packet generation failed: %v", err)
	}

	packet2, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("Second noise packet generation failed: %v", err)
	}

	// Data should be different (cryptographically random)
	if bytes.Equal(packet1.Data, packet2.Data) {
		t.Error("Generated noise packets have identical data (should be random)")
	}

	// Timestamps should be different
	if packet1.Timestamp == packet2.Timestamp {
		t.Error("Generated noise packets have identical timestamps")
	}
}

func TestNoisePacketRealisticSizes(t *testing.T) {
	// Generate many packets and verify size distribution is realistic
	const numPackets = 100
	sizeCounts := make(map[int]int)

	for i := 0; i < numPackets; i++ {
		packet, err := GenerateNoisePacket()
		if err != nil {
			t.Fatalf("Noise packet generation failed at iteration %d: %v", i, err)
		}
		sizeCounts[packet.Size]++
	}

	// Verify we have some variety in sizes
	if len(sizeCounts) < 5 {
		t.Errorf("Insufficient size variety: only %d different sizes in %d packets", 
			len(sizeCounts), numPackets)
	}

	// Verify all sizes are within realistic bounds
	for size := range sizeCounts {
		if size < 40 || size > 1500 {
			t.Errorf("Unrealistic packet size generated: %d", size)
		}
	}
}

func TestInjectNoisePackets(t *testing.T) {
	// Create some real packets
	realPackets := [][]byte{
		[]byte("Real packet 1"),
		[]byte("Real packet 2"),
		[]byte("Real packet 3"),
	}

	// Test different noise ratios
	testRatios := []float64{0.0, 0.1, 0.5, 1.0}

	for _, ratio := range testRatios {
		t.Run(fmt.Sprintf("Ratio_%.1f", ratio), func(t *testing.T) {
			result, err := InjectNoisePackets(realPackets, ratio)
			if err != nil {
				t.Fatalf("Noise injection failed for ratio %.1f: %v", ratio, err)
			}

			expectedTotal := len(realPackets) + int(float64(len(realPackets))*ratio)
			if len(result) != expectedTotal {
				t.Errorf("Unexpected total packet count: expected %d, got %d", 
					expectedTotal, len(result))
			}

			// Verify all original packets are still present
			realPacketCount := 0
			for _, packet := range result {
				for _, realPacket := range realPackets {
					if bytes.Equal(packet, realPacket) {
						realPacketCount++
						break
					}
				}
			}

			if realPacketCount != len(realPackets) {
				t.Errorf("Not all real packets preserved: expected %d, found %d", 
					len(realPackets), realPacketCount)
			}
		})
	}
}

func TestInjectNoisePacketsInvalidRatio(t *testing.T) {
	realPackets := [][]byte{[]byte("test")}
	invalidRatios := []float64{-0.1, -1.0, 1.1, 2.0}

	for _, ratio := range invalidRatios {
		t.Run(fmt.Sprintf("InvalidRatio_%.1f", ratio), func(t *testing.T) {
			_, err := InjectNoisePackets(realPackets, ratio)
			if err == nil {
				t.Errorf("Should fail for invalid ratio %.1f", ratio)
			}
		})
	}
}

func TestInjectNoisePacketsEmptyInput(t *testing.T) {
	// Test with empty packet list
	result, err := InjectNoisePackets([][]byte{}, 0.5)
	if err != nil {
		t.Fatalf("Noise injection failed for empty input: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected empty result for empty input, got %d packets", len(result))
	}
}

func TestIsNoisePacketForTesting(t *testing.T) {
	// Generate a noise packet
	noisePacket, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("Noise packet generation failed: %v", err)
	}

	// Test noise detection (this is only for testing purposes)
	if !IsNoisePacket(noisePacket.Data) {
		t.Error("Generated noise packet not detected as noise")
	}

	// Test with real data
	realData := []byte("This is real encrypted data")
	if IsNoisePacket(realData) {
		t.Error("Real data incorrectly detected as noise")
	}

	// Test with empty data
	if IsNoisePacket([]byte{}) {
		t.Error("Empty data incorrectly detected as noise")
	}
}

func TestNoisePacketIndistinguishability(t *testing.T) {
	// This test verifies that noise packets have characteristics similar to encrypted data
	noisePacket, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("Noise packet generation failed: %v", err)
	}

	// Verify noise data appears random (basic entropy check)
	data := noisePacket.Data
	if len(data) < 16 {
		t.Skip("Packet too small for entropy analysis")
	}

	// Count byte frequency distribution
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// For random data, we expect reasonable distribution
	// (This is a basic check - real analysis would be more sophisticated)
	if len(freq) < len(data)/8 { // Expect at least 1/8 unique bytes
		t.Error("Noise data appears to have low entropy (not random enough)")
	}

	// Verify no obvious patterns (check for repeated sequences)
	hasPattern := false
	if len(data) >= 8 {
		for i := 0; i < len(data)-4; i++ {
			pattern := data[i : i+4]
			for j := i + 4; j < len(data)-3; j++ {
				if bytes.Equal(pattern, data[j:j+4]) {
					hasPattern = true
					break
				}
			}
			if hasPattern {
				break
			}
		}
	}

	if hasPattern {
		t.Error("Noise data contains obvious patterns (should appear random)")
	}
}

func TestNoisePacketSizeDistribution(t *testing.T) {
	// Test that noise packets follow realistic size distributions
	const numSamples = 1000
	sizes := make([]int, numSamples)

	for i := 0; i < numSamples; i++ {
		packet, err := GenerateNoisePacket()
		if err != nil {
			t.Fatalf("Noise packet generation failed at sample %d: %v", i, err)
		}
		sizes[i] = packet.Size
	}

	// Verify we have common network packet sizes represented
	commonSizes := []int{64, 128, 256, 512, 1024, 1500}
	foundCommonSizes := 0

	for _, commonSize := range commonSizes {
		for _, size := range sizes {
			if size == commonSize {
				foundCommonSizes++
				break
			}
		}
	}

	if foundCommonSizes < len(commonSizes)/2 {
		t.Errorf("Not enough common packet sizes found: %d out of %d", 
			foundCommonSizes, len(commonSizes))
	}

	// Verify size range is reasonable
	minSize, maxSize := sizes[0], sizes[0]
	for _, size := range sizes {
		if size < minSize {
			minSize = size
		}
		if size > maxSize {
			maxSize = size
		}
	}

	if minSize < 40 || maxSize > 1500 {
		t.Errorf("Size range unrealistic: min=%d, max=%d (expected 40-1500)", 
			minSize, maxSize)
	}
}

func BenchmarkGenerateNoisePacket(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateNoisePacket()
		if err != nil {
			b.Fatalf("Noise packet generation failed: %v", err)
		}
	}
}

func BenchmarkInjectNoisePackets(b *testing.B) {
	// Create test packets
	realPackets := make([][]byte, 100)
	for i := range realPackets {
		realPackets[i] = make([]byte, 512)
		for j := range realPackets[i] {
			realPackets[i][j] = byte(i + j)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := InjectNoisePackets(realPackets, 0.3)
		if err != nil {
			b.Fatalf("Noise injection failed: %v", err)
		}
	}
}