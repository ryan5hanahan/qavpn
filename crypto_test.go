package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestKyberKeyGeneration tests real Kyber key pair generation
func TestKyberKeyGeneration(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	// Validate key pair
	if err := keyPair.ValidateKeyPair(); err != nil {
		t.Fatalf("Generated key pair is invalid: %v", err)
	}

	// Check key sizes
	if len(keyPair.PublicKey) != KyberPublicKeyBytes {
		t.Errorf("Public key size mismatch: got %d, expected %d", len(keyPair.PublicKey), KyberPublicKeyBytes)
	}

	if len(keyPair.PrivateKey) != KyberSecretKeyBytes {
		t.Errorf("Private key size mismatch: got %d, expected %d", len(keyPair.PrivateKey), KyberSecretKeyBytes)
	}

	// Test secure cleanup
	keyPair.SecureZero()
	if keyPair.PublicKey != nil || keyPair.PrivateKey != nil {
		t.Error("SecureZero did not properly clear keys")
	}
}

// TestKyberKeySerialization tests key serialization and deserialization
func TestKyberKeySerialization(t *testing.T) {
	// Generate original key pair
	originalKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	defer originalKeyPair.SecureZero()

	// Test public key serialization/deserialization
	pubKeyBytes := originalKeyPair.SerializePublicKey()
	deserializedPubKeyPair, err := DeserializePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}
	defer deserializedPubKeyPair.SecureZero()

	if !bytes.Equal(originalKeyPair.PublicKey, deserializedPubKeyPair.PublicKey) {
		t.Error("Public key serialization/deserialization failed")
	}

	// Test private key serialization/deserialization
	privKeyBytes := originalKeyPair.SerializePrivateKey()
	deserializedPrivKeyPair, err := DeserializePrivateKey(privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize private key: %v", err)
	}
	defer deserializedPrivKeyPair.SecureZero()

	if !bytes.Equal(originalKeyPair.PrivateKey, deserializedPrivKeyPair.PrivateKey) {
		t.Error("Private key serialization/deserialization failed")
	}

	if !bytes.Equal(originalKeyPair.PublicKey, deserializedPrivKeyPair.PublicKey) {
		t.Error("Public key derived from private key doesn't match")
	}
}

// TestKyberEncapsulationDecapsulation tests the core Kyber KEM operations
func TestKyberEncapsulationDecapsulation(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	defer keyPair.SecureZero()

	// Test encapsulation
	sharedSecret1, ciphertext, err := kyberEncapsulate(keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulation failed: %v", err)
	}
	defer secureZeroBytes(sharedSecret1)

	// Verify ciphertext size
	if len(ciphertext) != KyberCiphertextBytes {
		t.Errorf("Ciphertext size mismatch: got %d, expected %d", len(ciphertext), KyberCiphertextBytes)
	}

	// Verify shared secret size
	if len(sharedSecret1) != KyberSharedSecretSize {
		t.Errorf("Shared secret size mismatch: got %d, expected %d", len(sharedSecret1), KyberSharedSecretSize)
	}

	// Test decapsulation
	sharedSecret2, err := kyberDecapsulate(ciphertext, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decapsulation failed: %v", err)
	}
	defer secureZeroBytes(sharedSecret2)

	// Verify shared secrets match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Shared secrets from encapsulation and decapsulation don't match")
	}
}

// TestHKDFKeyDerivation tests HKDF key derivation
func TestHKDFKeyDerivation(t *testing.T) {
	// Generate test shared secret
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("Failed to generate test shared secret: %v", err)
	}
	defer secureZeroBytes(sharedSecret)

	// Test key derivation with different info
	key1, err := deriveSymmetricKey(sharedSecret, nil, []byte("TEST-KEY-1"))
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}
	defer secureZeroBytes(key1)

	key2, err := deriveSymmetricKey(sharedSecret, nil, []byte("TEST-KEY-2"))
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}
	defer secureZeroBytes(key2)

	// Keys should be different with different info
	if bytes.Equal(key1, key2) {
		t.Error("Keys derived with different info should be different")
	}

	// Keys should be deterministic
	key1Again, err := deriveSymmetricKey(sharedSecret, nil, []byte("TEST-KEY-1"))
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}
	defer secureZeroBytes(key1Again)

	if !bytes.Equal(key1, key1Again) {
		t.Error("Key derivation should be deterministic")
	}

	// Verify key length
	if len(key1) != 32 {
		t.Errorf("Derived key length mismatch: got %d, expected 32", len(key1))
	}
}

// TestAESGCMEncryptionDecryption tests real AES-GCM operations
func TestAESGCMEncryptionDecryption(t *testing.T) {
	// Generate test key and nonce
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	defer secureZeroBytes(key)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate test nonce: %v", err)
	}

	// Test data
	plaintext := []byte("This is a test message for AES-GCM encryption")

	// Test encryption
	ciphertext, tag, err := aesGCMEncrypt(plaintext, key, nonce)
	if err != nil {
		t.Fatalf("AES-GCM encryption failed: %v", err)
	}

	// Verify tag length
	if len(tag) != 16 {
		t.Errorf("Authentication tag length mismatch: got %d, expected 16", len(tag))
	}

	// Test decryption
	decryptedText, err := aesGCMDecrypt(ciphertext, tag, key, nonce)
	if err != nil {
		t.Fatalf("AES-GCM decryption failed: %v", err)
	}

	// Verify decrypted text matches original
	if !bytes.Equal(plaintext, decryptedText) {
		t.Error("Decrypted text doesn't match original plaintext")
	}

	// Test authentication failure with wrong tag
	wrongTag := make([]byte, 16)
	if _, err := rand.Read(wrongTag); err != nil {
		t.Fatalf("Failed to generate wrong tag: %v", err)
	}

	_, err = aesGCMDecrypt(ciphertext, wrongTag, key, nonce)
	if err == nil {
		t.Error("AES-GCM decryption should fail with wrong authentication tag")
	}

	// Test with wrong key
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}
	defer secureZeroBytes(wrongKey)

	_, err = aesGCMDecrypt(ciphertext, tag, wrongKey, nonce)
	if err == nil {
		t.Error("AES-GCM decryption should fail with wrong key")
	}
}

// TestEndToEndEncryption tests complete packet encryption/decryption
func TestEndToEndEncryption(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	defer keyPair.SecureZero()

	// Test data
	originalData := []byte("This is a test message for end-to-end encryption using post-quantum cryptography")

	// Encrypt packet
	encryptedPacket, err := EncryptPacket(originalData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Packet encryption failed: %v", err)
	}

	// Verify encrypted packet structure
	if len(encryptedPacket.Ciphertext) <= KyberCiphertextBytes {
		t.Error("Encrypted packet ciphertext too short")
	}
	if len(encryptedPacket.Tag) != 16 {
		t.Errorf("Authentication tag length mismatch: got %d, expected 16", len(encryptedPacket.Tag))
	}
	if len(encryptedPacket.Nonce) != 12 {
		t.Errorf("Nonce length mismatch: got %d, expected 12", len(encryptedPacket.Nonce))
	}

	// Decrypt packet
	decryptedData, err := DecryptPacket(encryptedPacket, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Packet decryption failed: %v", err)
	}

	// Verify decrypted data matches original
	if !bytes.Equal(originalData, decryptedData) {
		t.Error("Decrypted data doesn't match original data")
	}
}

// TestEncryptionWithDifferentKeys tests that different keys produce different results
func TestEncryptionWithDifferentKeys(t *testing.T) {
	// Generate two different key pairs
	keyPair1, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate first key pair: %v", err)
	}
	defer keyPair1.SecureZero()

	keyPair2, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	defer keyPair2.SecureZero()

	// Test data
	testData := []byte("Test message for different keys")

	// Encrypt with first key
	encrypted1, err := EncryptPacket(testData, keyPair1.PublicKey)
	if err != nil {
		t.Fatalf("Encryption with first key failed: %v", err)
	}

	// Encrypt with second key
	encrypted2, err := EncryptPacket(testData, keyPair2.PublicKey)
	if err != nil {
		t.Fatalf("Encryption with second key failed: %v", err)
	}

	// Ciphertexts should be different
	if bytes.Equal(encrypted1.Ciphertext, encrypted2.Ciphertext) {
		t.Error("Encryptions with different keys should produce different ciphertexts")
	}

	// Decryption with wrong key should fail
	_, err = DecryptPacket(encrypted1, keyPair2.PrivateKey)
	if err == nil {
		t.Error("Decryption with wrong private key should fail")
	}

	_, err = DecryptPacket(encrypted2, keyPair1.PrivateKey)
	if err == nil {
		t.Error("Decryption with wrong private key should fail")
	}
}

// TestNoisePacketGeneration tests noise packet generation
func TestNoisePacketGeneration(t *testing.T) {
	// Test random size noise packet
	noisePacket1, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("Failed to generate noise packet: %v", err)
	}

	if noisePacket1.Size != len(noisePacket1.Data) {
		t.Error("Noise packet size doesn't match data length")
	}

	if noisePacket1.Size < 40 || noisePacket1.Size > 1500 {
		t.Errorf("Noise packet size out of expected range: %d", noisePacket1.Size)
	}

	// Test specific size noise packet
	testSize := 256
	noisePacket2, err := GenerateNoisePacketWithSize(testSize)
	if err != nil {
		t.Fatalf("Failed to generate noise packet with specific size: %v", err)
	}

	if noisePacket2.Size != testSize {
		t.Errorf("Noise packet size mismatch: got %d, expected %d", noisePacket2.Size, testSize)
	}

	if len(noisePacket2.Data) != testSize {
		t.Errorf("Noise packet data length mismatch: got %d, expected %d", len(noisePacket2.Data), testSize)
	}

	// Test that different noise packets are different
	noisePacket3, err := GenerateNoisePacket()
	if err != nil {
		t.Fatalf("Failed to generate third noise packet: %v", err)
	}

	if bytes.Equal(noisePacket1.Data, noisePacket3.Data) && noisePacket1.Size == noisePacket3.Size {
		t.Error("Different noise packets should be different")
	}
}

// TestNoisePacketInjection tests noise packet injection into real packet streams
func TestNoisePacketInjection(t *testing.T) {
	// Create some real packets
	realPackets := [][]byte{
		[]byte("Real packet 1"),
		[]byte("Real packet 2"),
		[]byte("Real packet 3"),
	}

	// Test noise injection
	noiseRatio := 0.5 // 50% noise
	mixedPackets, err := InjectNoisePackets(realPackets, noiseRatio)
	if err != nil {
		t.Fatalf("Failed to inject noise packets: %v", err)
	}

	// Should have more packets than original
	expectedMinPackets := len(realPackets)
	expectedMaxPackets := len(realPackets) * 2
	if len(mixedPackets) < expectedMinPackets || len(mixedPackets) > expectedMaxPackets {
		t.Errorf("Mixed packet count out of expected range: got %d, expected %d-%d", 
			len(mixedPackets), expectedMinPackets, expectedMaxPackets)
	}

	// All original packets should still be present
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
		t.Errorf("Not all real packets preserved: got %d, expected %d", realPacketCount, len(realPackets))
	}
}

// TestSecureMemoryClearing tests that sensitive data is properly cleared
func TestSecureMemoryClearing(t *testing.T) {
	// Create test data
	testData := []byte("sensitive data that should be cleared")
	originalData := make([]byte, len(testData))
	copy(originalData, testData)

	// Clear the data
	secureZeroBytes(testData)

	// Verify data is cleared
	for i, b := range testData {
		if b != 0 {
			t.Errorf("Byte at index %d not cleared: got %d, expected 0", i, b)
		}
	}

	// Verify original data was actually different
	allZero := true
	for _, b := range originalData {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Test data was already all zeros, test is invalid")
	}
}

// TestInvalidInputHandling tests error handling for invalid inputs
func TestInvalidInputHandling(t *testing.T) {
	// Test invalid public key size for encryption
	invalidPubKey := make([]byte, 10) // Wrong size
	testData := []byte("test data")
	
	_, err := EncryptPacket(testData, invalidPubKey)
	if err == nil {
		t.Error("EncryptPacket should fail with invalid public key size")
	}

	// Test invalid private key size for decryption
	validKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate valid key pair: %v", err)
	}
	defer validKeyPair.SecureZero()

	validEncrypted, err := EncryptPacket(testData, validKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with valid key: %v", err)
	}

	invalidPrivKey := make([]byte, 10) // Wrong size
	_, err = DecryptPacket(validEncrypted, invalidPrivKey)
	if err == nil {
		t.Error("DecryptPacket should fail with invalid private key size")
	}

	// Test invalid noise packet size
	_, err = GenerateNoisePacketWithSize(-1)
	if err == nil {
		t.Error("GenerateNoisePacketWithSize should fail with negative size")
	}

	_, err = GenerateNoisePacketWithSize(70000)
	if err == nil {
		t.Error("GenerateNoisePacketWithSize should fail with oversized packet")
	}

	// Test invalid noise ratio
	realPackets := [][]byte{[]byte("test")}
	_, err = InjectNoisePackets(realPackets, -0.1)
	if err == nil {
		t.Error("InjectNoisePackets should fail with negative noise ratio")
	}

	_, err = InjectNoisePackets(realPackets, 1.1)
	if err == nil {
		t.Error("InjectNoisePackets should fail with noise ratio > 1")
	}
}

// BenchmarkKyberKeyGeneration benchmarks key generation performance
func BenchmarkKyberKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		keyPair, err := GenerateKyberKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
		keyPair.SecureZero()
	}
}

// BenchmarkEncryptDecrypt benchmarks end-to-end encryption/decryption
func BenchmarkEncryptDecrypt(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}
	defer keyPair.SecureZero()

	testData := make([]byte, 1024) // 1KB test data
	if _, err := rand.Read(testData); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptPacket(testData, keyPair.PublicKey)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		_, err = DecryptPacket(encrypted, keyPair.PrivateKey)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
