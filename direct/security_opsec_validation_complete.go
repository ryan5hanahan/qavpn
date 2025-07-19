package direct

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Complete the remaining security validation test functions

func testEncodingSecurity(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test various encoding formats
	invitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	if err := invitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign invitation: %v", err)
	}

	// Test Base64 encoding
	base64Data, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	// Base64 data should not contain raw binary
	if bytes.Contains([]byte(base64Data), []byte{0x00}) {
		t.Error("Base64 encoded data should not contain null bytes")
	}

	// Test Hex encoding
	hexData, err := processor.EncodeToHex(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	// Hex data should only contain valid hex characters
	for _, char := range hexData {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			t.Errorf("Invalid hex character found: %c", char)
		}
	}

	// Test encoding consistency (same invitation should produce same encoding)
	base64Data2, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64 second time: %v", err)
	}

	if base64Data != base64Data2 {
		t.Error("Base64 encoding should be consistent for same invitation")
	}

	// Test decoding
	decodedInvitation, err := processor.DecodeFromBase64(base64Data)
	if err != nil {
		t.Fatalf("Failed to decode from base64: %v", err)
	}

	if decodedInvitation.ConnectionID != invitation.ConnectionID {
		t.Error("Decoded invitation should match original")
	}

	// Test encoding tampering detection
	tamperedBase64 := base64Data[:len(base64Data)-5] + "XXXXX"
	_, err = processor.DecodeFromBase64(tamperedBase64)
	if err == nil {
		t.Error("Should detect tampering in encoded data")
	}

	// Test QR code generation (should not fail)
	qrCode, err := processor.GenerateQRCode(invitation)
	if err != nil {
		t.Fatalf("Failed to generate QR code: %v", err)
	}

	if len(qrCode) == 0 {
		t.Error("QR code should not be empty")
	}
}

func testConcurrentAccessSecurity(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	validator := NewSecureInvitationValidator(signer.PublicKey)
	defer validator.Stop()

	// Test concurrent invitation generation
	const numConcurrent = 50
	var wg sync.WaitGroup
	invitations := make([]*InvitationCode, numConcurrent)
	errors := make([]error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			invitation, err := processor.GenerateInvitationCode("tcp", fmt.Sprintf("192.168.1.%d:8080", 100+index), time.Hour, true)
			if err != nil {
				errors[index] = err
				return
			}
			
			if err := invitation.Sign(signer); err != nil {
				errors[index] = err
				return
			}
			
			invitations[index] = invitation
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Errorf("Concurrent invitation generation failed at index %d: %v", i, err)
		}
	}

	// Verify all invitations are unique
	connectionIDs := make(map[string]bool)
	for i, invitation := range invitations {
		if invitation == nil {
			continue
		}
		
		if connectionIDs[invitation.ConnectionID] {
			t.Errorf("Duplicate connection ID found in concurrent generation: %s", invitation.ConnectionID)
		}
		connectionIDs[invitation.ConnectionID] = true
	}

	// Test concurrent validation
	validationResults := make([]error, numConcurrent)
	
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if invitations[index] == nil {
				return
			}
			
			invitationData, err := processor.EncodeToBase64(invitations[index])
			if err != nil {
				validationResults[index] = err
				return
			}
			
			_, err = validator.ValidateAndProcessInvitation(invitationData, fmt.Sprintf("192.168.1.%d:12345", 100+index))
			validationResults[index] = err
		}(i)
	}

	wg.Wait()

	// Check validation results
	successCount := 0
	for i, err := range validationResults {
		if invitations[i] == nil {
			continue
		}
		
		if err == nil {
			successCount++
		} else {
			t.Errorf("Concurrent validation failed at index %d: %v", i, err)
		}
	}

	if successCount == 0 {
		t.Error("No concurrent validations succeeded")
	}

	// Test concurrent access to security manager
	securityManager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer securityManager.Stop()

	concurrentInvitation, _ := processor.GenerateInvitationCode("tcp", "192.168.1.200:8080", time.Hour, true)
	concurrentInvitation.Sign(signer)

	concurrentResults := make([]error, numConcurrent)
	
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			err := securityManager.ValidateAndMarkUsed(concurrentInvitation, fmt.Sprintf("192.168.1.%d:12345", 200+index))
			concurrentResults[index] = err
		}(i)
	}

	wg.Wait()

	// Only one should succeed (single-use invitation)
	successCount = 0
	for _, err := range concurrentResults {
		if err == nil {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("Expected exactly 1 success in concurrent single-use test, got %d", successCount)
	}
}

// Additional security validation functions for comprehensive coverage

func TestSecurityValidationComprehensive(t *testing.T) {
	t.Run("CryptographicStrengthValidation", func(t *testing.T) {
		testCryptographicStrengthValidation(t)
	})
	
	t.Run("MemorySecurityValidation", func(t *testing.T) {
		testMemorySecurityValidation(t)
	})
	
	t.Run("NetworkSecurityValidation", func(t *testing.T) {
		testNetworkSecurityValidation(t)
	})
}

func testCryptographicStrengthValidation(t *testing.T) {
	// Test key sizes meet minimum security requirements
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}
	defer alice.SecureWipe()

	bob, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}
	defer bob.SecureWipe()

	// Complete key exchange
	initMessage, _ := alice.InitiateKeyExchange()
	responseMessage, _ := bob.ProcessKeyExchangeMessage(initMessage)
	confirmMessage, _ := alice.ProcessKeyExchangeMessage(responseMessage)
	bob.ProcessKeyExchangeMessage(confirmMessage)

	keys := alice.GetSessionKeys()

	// Validate cryptographic strength
	if len(keys.EncryptionKey) < 32 {
		t.Errorf("Encryption key too short for security: %d bytes", len(keys.EncryptionKey))
	}

	if len(keys.AuthKey) < 32 {
		t.Errorf("Auth key too short for security: %d bytes", len(keys.AuthKey))
	}

	// Test entropy of generated keys
	if isLowEntropy(keys.EncryptionKey) {
		t.Error("Encryption key has low entropy")
	}

	if isLowEntropy(keys.AuthKey) {
		t.Error("Auth key has low entropy")
	}

	// Test invitation code cryptographic strength
	processor := NewInvitationCodeProcessor()
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	invitation, err := processor.GenerateInvitationCode("tcp", "192.168.1.100:8080", time.Hour, true)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	// Check salt entropy
	if len(invitation.Salt) < 16 {
		t.Errorf("Invitation salt too short: %d bytes", len(invitation.Salt))
	}

	if isLowEntropy(invitation.Salt) {
		t.Error("Invitation salt has low entropy")
	}

	// Check signature strength
	if err := invitation.Sign(signer); err != nil {
		t.Fatalf("Failed to sign invitation: %v", err)
	}

	if len(invitation.Signature) < 64 {
		t.Errorf("Signature too short: %d bytes", len(invitation.Signature))
	}
}

func testMemorySecurityValidation(t *testing.T) {
	// Test that sensitive data is properly cleared from memory
	tempDir := t.TempDir()
	password := []byte("test-password-for-memory-security")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager: %v", err)
	}

	// Create profile with sensitive data
	sensitiveData := []byte("extremely-sensitive-cryptographic-material-that-must-be-wiped")
	profile := &ConnectionProfile{
		Name: "memory-test-profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: sensitiveData,
			Salt:          []byte("memory-test-salt"),
			Nonce:         []byte("memory-nonce"),
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Load profile to get it in memory
	loadedProfile, err := manager.LoadProfile("memory-test-profile")
	if err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	// Verify data is correct
	if !bytes.Equal(loadedProfile.CryptoMaterial.EncryptedData, sensitiveData) {
		t.Error("Loaded profile data doesn't match original")
	}

	// Perform secure deletion
	if err := manager.SecureDeleteProfile("memory-test-profile"); err != nil {
		t.Fatalf("Failed to securely delete profile: %v", err)
	}

	// Test key exchange memory security
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}

	bob, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}

	// Complete key exchange
	initMessage, _ := alice.InitiateKeyExchange()
	responseMessage, _ := bob.ProcessKeyExchangeMessage(initMessage)
	confirmMessage, _ := alice.ProcessKeyExchangeMessage(responseMessage)
	bob.ProcessKeyExchangeMessage(confirmMessage)

	// Get keys before wipe
	keys := alice.GetSessionKeys()
	if keys == nil {
		t.Fatal("Keys should exist before wipe")
	}

	// Perform secure wipe
	alice.SecureWipe()
	bob.SecureWipe()

	// Keys should be nil after wipe
	wipedKeys := alice.GetSessionKeys()
	if wipedKeys != nil {
		t.Error("Keys should be nil after secure wipe")
	}
}

func testNetworkSecurityValidation(t *testing.T) {
	layer := NewOPSECNetworkLayer()

	// Test that network layer provides adequate security
	testData := []byte("sensitive-network-data-requiring-protection")

	// Test traffic obfuscation
	obfuscated, err := layer.ObfuscateTraffic(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate traffic: %v", err)
	}

	// Obfuscated data should be significantly different
	if bytes.Equal(testData, obfuscated) {
		t.Error("Traffic obfuscation should change the data")
	}

	// Should be larger due to padding
	if len(obfuscated) <= len(testData) {
		t.Error("Obfuscated data should be larger due to padding")
	}

	// Test deobfuscation
	deobfuscated, err := layer.DeobfuscateTraffic(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate traffic: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Error("Deobfuscated data should match original")
	}

	// Test timing randomization
	delays := make([]time.Duration, 20)
	for i := 0; i < 20; i++ {
		delays[i] = layer.CalculateConnectionDelay()
	}

	// Verify randomization
	allSame := true
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[0] {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Connection delays should be randomized for security")
	}

	// Test keep-alive security
	keepAlive1, interval1 := layer.GenerateSecureKeepAlive()
	keepAlive2, interval2 := layer.GenerateSecureKeepAlive()

	// Keep-alive packets should be different
	if bytes.Equal(keepAlive1, keepAlive2) {
		t.Error("Keep-alive packets should be randomized")
	}

	// Intervals should be different
	if interval1 == interval2 {
		t.Error("Keep-alive intervals should be randomized")
	}

	// Both should be recognized as keep-alive
	if !layer.IsKeepAlivePacket(keepAlive1) {
		t.Error("Generated keep-alive packet not recognized")
	}

	if !layer.IsKeepAlivePacket(keepAlive2) {
		t.Error("Generated keep-alive packet not recognized")
	}

	// Regular data should not be mistaken for keep-alive
	if layer.IsKeepAlivePacket(testData) {
		t.Error("Regular data incorrectly identified as keep-alive")
	}
}
