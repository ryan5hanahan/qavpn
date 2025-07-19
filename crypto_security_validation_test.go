package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestAESGCMRoundtrip validates encryption/decryption roundtrip
func TestAESGCMRoundtrip(t *testing.T) {
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte("test")},
		{"Medium", []byte("This is a test message for AES-GCM encryption")},
		{"Long", bytes.Repeat([]byte("A"), 1024)},
		{"Binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate random key and nonce
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			nonce := make([]byte, 12)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatalf("Failed to generate nonce: %v", err)
			}

			// Encrypt
			ciphertext, tag, err := aesGCMEncrypt(tc.plaintext, key, nonce)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			decrypted, err := aesGCMDecrypt(ciphertext, tag, key, nonce)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("Plaintext mismatch: got %x, want %x", decrypted, tc.plaintext)
			}
		})
	}
}

// TestAESGCMAuthentication validates authentication tag verification
func TestAESGCMAuthentication(t *testing.T) {
	plaintext := []byte("test message")
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	// Encrypt
	ciphertext, tag, err := aesGCMEncrypt(plaintext, key, nonce)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Run("TamperedCiphertext", func(t *testing.T) {
		// Tamper with ciphertext
		if len(ciphertext) > 0 {
			tamperedCiphertext := make([]byte, len(ciphertext))
			copy(tamperedCiphertext, ciphertext)
			tamperedCiphertext[0] ^= 0x01

			// Should fail decryption
			_, err := aesGCMDecrypt(tamperedCiphertext, tag, key, nonce)
			if err == nil {
				t.Error("Expected decryption to fail with tampered ciphertext")
			}
		}
	})

	t.Run("TamperedTag", func(t *testing.T) {
		// Tamper with tag
		tamperedTag := make([]byte, len(tag))
		copy(tamperedTag, tag)
		tamperedTag[0] ^= 0x01

		// Should fail decryption
		_, err := aesGCMDecrypt(ciphertext, tamperedTag, key, nonce)
		if err == nil {
			t.Error("Expected decryption to fail with tampered tag")
		}
	})

	t.Run("WrongKey", func(t *testing.T) {
		// Use wrong key
		wrongKey := make([]byte, 32)
		rand.Read(wrongKey)

		// Should fail decryption
		_, err := aesGCMDecrypt(ciphertext, tag, wrongKey, nonce)
		if err == nil {
			t.Error("Expected decryption to fail with wrong key")
		}
	})

	t.Run("WrongNonce", func(t *testing.T) {
		// Use wrong nonce
		wrongNonce := make([]byte, 12)
		rand.Read(wrongNonce)

		// Should fail decryption
		_, err := aesGCMDecrypt(ciphertext, tag, key, wrongNonce)
		if err == nil {
			t.Error("Expected decryption to fail with wrong nonce")
		}
	})
}

// TestHKDFKeyDerivation validates key derivation function
func TestHKDFKeyDerivation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	t.Run("DeterministicDerivation", func(t *testing.T) {
		// Same inputs should produce same output
		key1, err := deriveSymmetricKey(sharedSecret, nil, []byte("test-info"))
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		key2, err := deriveSymmetricKey(sharedSecret, nil, []byte("test-info"))
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		if !bytes.Equal(key1, key2) {
			t.Error("Key derivation is not deterministic")
		}
	})

	t.Run("DifferentInfoProducesDifferentKeys", func(t *testing.T) {
		key1, err := deriveSymmetricKey(sharedSecret, nil, []byte("info1"))
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		key2, err := deriveSymmetricKey(sharedSecret, nil, []byte("info2"))
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		if bytes.Equal(key1, key2) {
			t.Error("Different info parameters should produce different keys")
		}
	})

	t.Run("KeyLengthValidation", func(t *testing.T) {
		key, err := deriveSymmetricKey(sharedSecret, nil, []byte("test"))
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		if len(key) != 32 {
			t.Errorf("Expected key length 32, got %d", len(key))
		}
	})
}

// TestKyberKeyPairGeneration validates Kyber key pair generation
func TestKyberKeyPairGeneration(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key pair generation failed: %v", err)
	}
	defer keyPair.SecureZero()

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
}

// TestKyberEncapsulationDecapsulation validates Kyber operations
func TestKyberEncapsulationDecapsulation(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key pair generation failed: %v", err)
	}
	defer keyPair.SecureZero()

	// Encapsulate
	sharedSecret1, ciphertext, err := kyberEncapsulate(keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulation failed: %v", err)
	}
	defer secureZeroBytes(sharedSecret1)

	// Decapsulate
	sharedSecret2, err := kyberDecapsulate(ciphertext, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decapsulation failed: %v", err)
	}
	defer secureZeroBytes(sharedSecret2)

	// Verify shared secrets match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Shared secrets don't match")
	}

	// Verify shared secret size
	if len(sharedSecret1) != KyberSharedSecretSize {
		t.Errorf("Invalid shared secret size: got %d, expected %d", 
			len(sharedSecret1), KyberSharedSecretSize)
	}
}

// TestPacketEncryptionDecryption validates full packet encryption
func TestPacketEncryptionDecryption(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Key pair generation failed: %v", err)
	}
	defer keyPair.SecureZero()

	testData := []byte("This is a test packet for encryption")

	// Encrypt packet
	encryptedPacket, err := EncryptPacket(testData, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Packet encryption failed: %v", err)
	}

	// Decrypt packet
	decryptedData, err := DecryptPacket(encryptedPacket, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Packet decryption failed: %v", err)
	}

	// Verify data
	if !bytes.Equal(testData, decryptedData) {
		t.Error("Decrypted data doesn't match original")
	}
}

// TestSecureMemoryClearing validates memory clearing
func TestSecureMemoryClearing(t *testing.T) {
	// Create test data
	data := []byte("sensitive data")
	originalData := make([]byte, len(data))
	copy(originalData, data)

	// Clear memory
	secureZeroBytes(data)

	// Verify data is cleared
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d not cleared: got %d", i, b)
		}
	}

	// Verify original data was different
	allZero := true
	for _, b := range originalData {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Test data was already all zeros")
	}
}

// TestNoisePacketGeneration validates noise packet generation
func TestNoisePacketGeneration(t *testing.T) {
	t.Run("RandomSize", func(t *testing.T) {
		packet, err := GenerateNoisePacket()
		if err != nil {
			t.Fatalf("Noise packet generation failed: %v", err)
		}

		if packet.Size < 40 || packet.Size > 1500 {
			t.Errorf("Invalid packet size: %d", packet.Size)
		}

		if len(packet.Data) != packet.Size {
			t.Errorf("Data length mismatch: got %d, expected %d", 
				len(packet.Data), packet.Size)
		}
	})

	t.Run("SpecificSize", func(t *testing.T) {
		size := 100
		packet, err := GenerateNoisePacketWithSize(size)
		if err != nil {
			t.Fatalf("Noise packet generation failed: %v", err)
		}

		if packet.Size != size {
			t.Errorf("Size mismatch: got %d, expected %d", packet.Size, size)
		}

		if len(packet.Data) != size {
			t.Errorf("Data length mismatch: got %d, expected %d", 
				len(packet.Data), size)
		}
	})

	t.Run("Randomness", func(t *testing.T) {
		// Generate multiple packets and verify they're different
		packets := make([]*NoisePacket, 10)
		for i := range packets {
			var err error
			packets[i], err = GenerateNoisePacketWithSize(64)
			if err != nil {
				t.Fatalf("Noise packet generation failed: %v", err)
			}
		}

		// Check that packets are different
		for i := 0; i < len(packets); i++ {
			for j := i + 1; j < len(packets); j++ {
				if bytes.Equal(packets[i].Data, packets[j].Data) {
					t.Error("Generated identical noise packets")
				}
			}
		}
	})
}

// TestInputValidation validates input parameter validation
func TestInputValidation(t *testing.T) {
	t.Run("AESGCMInvalidKeySize", func(t *testing.T) {
		plaintext := []byte("test")
		invalidKey := make([]byte, 16) // Wrong size
		nonce := make([]byte, 12)

		_, _, err := aesGCMEncrypt(plaintext, invalidKey, nonce)
		if err == nil {
			t.Error("Expected error for invalid key size")
		}
	})

	t.Run("AESGCMInvalidNonceSize", func(t *testing.T) {
		plaintext := []byte("test")
		key := make([]byte, 32)
		invalidNonce := make([]byte, 8) // Wrong size

		_, _, err := aesGCMEncrypt(plaintext, key, invalidNonce)
		if err == nil {
			t.Error("Expected error for invalid nonce size")
		}
	})

	t.Run("KyberInvalidPublicKeySize", func(t *testing.T) {
		invalidKey := make([]byte, 100) // Wrong size
		_, err := EncryptPacket([]byte("test"), invalidKey)
		if err == nil {
			t.Error("Expected error for invalid public key size")
		}
	})

	t.Run("NoisePacketInvalidSize", func(t *testing.T) {
		_, err := GenerateNoisePacketWithSize(-1)
		if err == nil {
			t.Error("Expected error for negative size")
		}

		_, err = GenerateNoisePacketWithSize(70000)
		if err == nil {
			t.Error("Expected error for oversized packet")
		}
	})
}

// BenchmarkAESGCMEncryption benchmarks AES-GCM encryption performance
func BenchmarkAESGCMEncryption(b *testing.B) {
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := aesGCMEncrypt(plaintext, key, nonce)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkKyberEncapsulation benchmarks Kyber encapsulation performance
func BenchmarkKyberEncapsulation(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Key pair generation failed: %v", err)
	}
	defer keyPair.SecureZero()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sharedSecret, _, err := kyberEncapsulate(keyPair.PublicKey)
		if err != nil {
			b.Fatalf("Encapsulation failed: %v", err)
		}
		secureZeroBytes(sharedSecret)
	}
}
