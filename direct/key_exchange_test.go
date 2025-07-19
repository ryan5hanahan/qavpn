package direct

import (
	"bytes"
	"testing"
	"time"
)

func TestPostQuantumKeyExchange_Creation(t *testing.T) {
	pqke, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create PostQuantumKeyExchange: %v", err)
	}

	if pqke.localKeyPair == nil {
		t.Error("Local key pair should be initialized")
	}

	if pqke.IsKeyExchangeComplete() {
		t.Error("Key exchange should not be complete initially")
	}
}

func TestPostQuantumKeyExchange_FullExchange(t *testing.T) {
	// Create two key exchange instances (Alice and Bob)
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

	// Step 1: Alice initiates key exchange
	initMessage, err := alice.InitiateKeyExchange()
	if err != nil {
		t.Fatalf("Alice failed to initiate key exchange: %v", err)
	}

	if initMessage.Type != KeyExchangeInit {
		t.Errorf("Expected init message type, got %v", initMessage.Type)
	}

	if len(initMessage.PublicKey) == 0 {
		t.Error("Init message should contain public key")
	}

	// Step 2: Bob processes init message and responds
	responseMessage, err := bob.ProcessKeyExchangeMessage(initMessage)
	if err != nil {
		t.Fatalf("Bob failed to process init message: %v", err)
	}

	if responseMessage.Type != KeyExchangeResponse {
		t.Errorf("Expected response message type, got %v", responseMessage.Type)
	}

	if len(responseMessage.PublicKey) == 0 {
		t.Error("Response message should contain public key")
	}

	if len(responseMessage.Ciphertext) == 0 {
		t.Error("Response message should contain ciphertext")
	}

	// Response message doesn't have auth tag yet since responder doesn't have session keys

	// Step 3: Alice processes response and sends confirmation
	confirmMessage, err := alice.ProcessKeyExchangeMessage(responseMessage)
	if err != nil {
		t.Fatalf("Alice failed to process response message: %v", err)
	}

	if confirmMessage.Type != KeyExchangeConfirm {
		t.Errorf("Expected confirm message type, got %v", confirmMessage.Type)
	}

	if len(confirmMessage.AuthTag) == 0 {
		t.Error("Confirm message should contain auth tag")
	}

	// Step 4: Bob processes confirmation
	finalMessage, err := bob.ProcessKeyExchangeMessage(confirmMessage)
	if err != nil {
		t.Fatalf("Bob failed to process confirm message: %v", err)
	}

	if finalMessage != nil {
		t.Error("Final message should be nil (no response needed)")
	}

	// Verify both sides have completed key exchange
	if !alice.IsKeyExchangeComplete() {
		t.Error("Alice's key exchange should be complete")
	}

	if !bob.IsKeyExchangeComplete() {
		t.Error("Bob's key exchange should be complete")
	}

	// Verify both sides have session keys
	aliceKeys := alice.GetSessionKeys()
	bobKeys := bob.GetSessionKeys()

	if aliceKeys == nil {
		t.Error("Alice should have session keys")
	}

	if bobKeys == nil {
		t.Error("Bob should have session keys")
	}

	// Verify keys are the same (they should derive the same shared secret)
	if !bytes.Equal(aliceKeys.EncryptionKey, bobKeys.EncryptionKey) {
		t.Error("Encryption keys should match")
	}

	if !bytes.Equal(aliceKeys.AuthKey, bobKeys.AuthKey) {
		t.Error("Auth keys should match")
	}

	if !bytes.Equal(aliceKeys.IVSeed, bobKeys.IVSeed) {
		t.Error("IV seeds should match")
	}
}

func TestPostQuantumKeyExchange_KeyRotation(t *testing.T) {
	// Set up completed key exchange
	alice, bob := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()
	defer bob.SecureWipe()

	// Get initial keys
	initialAliceKeys := alice.GetSessionKeys()
	initialBobKeys := bob.GetSessionKeys()

	// Alice initiates key rotation
	rotationMessage, err := alice.InitiateKeyRotation()
	if err != nil {
		t.Fatalf("Alice failed to initiate key rotation: %v", err)
	}

	if rotationMessage.Type != KeyExchangeRotation {
		t.Errorf("Expected rotation message type, got %v", rotationMessage.Type)
	}

	// Bob processes rotation message
	rotationResponse, err := bob.ProcessKeyExchangeMessage(rotationMessage)
	if err != nil {
		t.Fatalf("Bob failed to process rotation message: %v", err)
	}

	if rotationResponse.Type != KeyExchangeRotation {
		t.Errorf("Expected rotation response type, got %v", rotationResponse.Type)
	}

	// Alice processes rotation response
	_, err = alice.ProcessKeyExchangeMessage(rotationResponse)
	if err != nil {
		t.Fatalf("Alice failed to process rotation response: %v", err)
	}

	// Verify keys have been rotated
	newAliceKeys := alice.GetSessionKeys()
	newBobKeys := bob.GetSessionKeys()

	// Keys should be different from initial keys
	if bytes.Equal(initialAliceKeys.EncryptionKey, newAliceKeys.EncryptionKey) {
		t.Error("Encryption key should have changed after rotation")
	}

	if bytes.Equal(initialBobKeys.AuthKey, newBobKeys.AuthKey) {
		t.Error("Auth key should have changed after rotation")
	}

	// New keys should match between Alice and Bob
	if !bytes.Equal(newAliceKeys.EncryptionKey, newBobKeys.EncryptionKey) {
		t.Error("New encryption keys should match")
	}

	if !bytes.Equal(newAliceKeys.AuthKey, newBobKeys.AuthKey) {
		t.Error("New auth keys should match")
	}

	// Rotation count should have increased
	if newAliceKeys.RotationCount != initialAliceKeys.RotationCount+1 {
		t.Error("Rotation count should have increased")
	}
}

func TestPostQuantumKeyExchange_ShouldRotateKeys(t *testing.T) {
	alice, _ := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()

	// Initially should not need rotation
	if alice.ShouldRotateKeys() {
		t.Error("Should not need key rotation initially")
	}

	// Simulate time passage by modifying last rotation time
	alice.mutex.Lock()
	alice.lastRotation = time.Now().Add(-2 * KeyRotationInterval)
	alice.mutex.Unlock()

	// Now should need rotation
	if !alice.ShouldRotateKeys() {
		t.Error("Should need key rotation after time interval")
	}
}

func TestPostQuantumKeyExchange_AuthenticationFailure(t *testing.T) {
	alice, bob := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()
	defer bob.SecureWipe()

	// Create a message with invalid auth tag
	message := &KeyExchangeMessage{
		Type:           KeyExchangeRotation,
		Timestamp:      time.Now(),
		SequenceNumber: 1,
		AuthTag:        []byte("invalid_tag"),
	}

	// Should fail authentication
	_, err := bob.ProcessKeyExchangeMessage(message)
	if err == nil {
		t.Error("Should fail with invalid auth tag")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("authentication")) {
		t.Errorf("Error should mention authentication failure: %v", err)
	}
}

func TestPostQuantumKeyExchange_SessionKeys(t *testing.T) {
	alice, _ := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()

	keys := alice.GetSessionKeys()
	if keys == nil {
		t.Fatal("Session keys should not be nil")
	}

	// Verify key sizes
	if len(keys.EncryptionKey) != SessionKeySize {
		t.Errorf("Encryption key size should be %d, got %d", SessionKeySize, len(keys.EncryptionKey))
	}

	if len(keys.AuthKey) != AuthKeySize {
		t.Errorf("Auth key size should be %d, got %d", AuthKeySize, len(keys.AuthKey))
	}

	if len(keys.IVSeed) != IVSeedSize {
		t.Errorf("IV seed size should be %d, got %d", IVSeedSize, len(keys.IVSeed))
	}

	// Verify keys are not all zeros
	allZeros := make([]byte, SessionKeySize)
	if bytes.Equal(keys.EncryptionKey, allZeros) {
		t.Error("Encryption key should not be all zeros")
	}

	if bytes.Equal(keys.AuthKey, allZeros) {
		t.Error("Auth key should not be all zeros")
	}

	// Verify returned keys are copies (modifying them shouldn't affect internal state)
	originalKey := make([]byte, len(keys.EncryptionKey))
	copy(originalKey, keys.EncryptionKey)

	// Modify returned key
	keys.EncryptionKey[0] = 0xFF

	// Get keys again and verify they haven't changed
	newKeys := alice.GetSessionKeys()
	if !bytes.Equal(newKeys.EncryptionKey, originalKey) {
		t.Error("Returned keys should be copies, not references")
	}
}

func TestPostQuantumKeyExchange_SecureWipe(t *testing.T) {
	alice, _ := setupCompletedKeyExchange(t)

	// Verify keys exist before wipe
	if !alice.IsKeyExchangeComplete() {
		t.Fatal("Key exchange should be complete before wipe")
	}

	keys := alice.GetSessionKeys()
	if keys == nil {
		t.Fatal("Session keys should exist before wipe")
	}

	// Perform secure wipe
	alice.SecureWipe()

	// Verify keys are wiped
	if alice.IsKeyExchangeComplete() {
		t.Error("Key exchange should not be complete after wipe")
	}

	keys = alice.GetSessionKeys()
	if keys != nil {
		t.Error("Session keys should be nil after wipe")
	}
}

func TestKeyExchangeMessageType_String(t *testing.T) {
	tests := []struct {
		msgType  KeyExchangeMessageType
		expected string
	}{
		{KeyExchangeInit, "init"},
		{KeyExchangeResponse, "response"},
		{KeyExchangeConfirm, "confirm"},
		{KeyExchangeRotation, "rotation"},
		{KeyExchangeMessageType(999), "unknown"},
	}

	for _, test := range tests {
		result := test.msgType.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s for message type %d", test.expected, result, test.msgType)
		}
	}
}

func TestPostQuantumKeyExchange_InvalidMessages(t *testing.T) {
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}
	defer alice.SecureWipe()

	// Test processing init message without public key
	invalidInit := &KeyExchangeMessage{
		Type:      KeyExchangeInit,
		Timestamp: time.Now(),
	}

	_, err = alice.ProcessKeyExchangeMessage(invalidInit)
	if err == nil {
		t.Error("Should fail with missing public key in init message")
	}

	// Test processing response message without public key
	invalidResponse := &KeyExchangeMessage{
		Type:      KeyExchangeResponse,
		Timestamp: time.Now(),
	}

	_, err = alice.ProcessKeyExchangeMessage(invalidResponse)
	if err == nil {
		t.Error("Should fail with missing public key in response message")
	}

	// Test processing response message without ciphertext
	invalidResponse2 := &KeyExchangeMessage{
		Type:      KeyExchangeResponse,
		PublicKey: make([]byte, 1568),
		Timestamp: time.Now(),
	}

	_, err = alice.ProcessKeyExchangeMessage(invalidResponse2)
	if err == nil {
		t.Error("Should fail with missing ciphertext in response message")
	}

	// Test unknown message type
	unknownMessage := &KeyExchangeMessage{
		Type:      KeyExchangeMessageType(999),
		Timestamp: time.Now(),
	}

	_, err = alice.ProcessKeyExchangeMessage(unknownMessage)
	if err == nil {
		t.Error("Should fail with unknown message type")
	}
}

// Helper function to set up a completed key exchange between two parties
func setupCompletedKeyExchange(t *testing.T) (*PostQuantumKeyExchange, *PostQuantumKeyExchange) {
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create Alice's key exchange: %v", err)
	}

	bob, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create Bob's key exchange: %v", err)
	}

	// Perform full key exchange
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

	return alice, bob
}

func TestPostQuantumKeyExchange_ConcurrentAccess(t *testing.T) {
	alice, bob := setupCompletedKeyExchange(t)
	defer alice.SecureWipe()
	defer bob.SecureWipe()

	// Test concurrent access to session keys
	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 100; i++ {
			keys := alice.GetSessionKeys()
			if keys == nil {
				t.Error("Session keys should not be nil")
			}
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			if alice.ShouldRotateKeys() {
				// This is fine, just checking concurrent access
			}
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done
}

func TestPostQuantumKeyExchange_KeyDerivation(t *testing.T) {
	alice, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange: %v", err)
	}
	defer alice.SecureWipe()

	// Set a test shared secret
	alice.sharedSecret = []byte("test_shared_secret_32_bytes_long")

	// Derive session keys
	err = alice.deriveSessionKeys()
	if err != nil {
		t.Fatalf("Failed to derive session keys: %v", err)
	}

	keys := alice.GetSessionKeys()
	if keys == nil {
		t.Fatal("Session keys should not be nil after derivation")
	}

	// Derive again with same shared secret
	err = alice.deriveSessionKeys()
	if err != nil {
		t.Fatalf("Failed to derive session keys again: %v", err)
	}

	newKeys := alice.GetSessionKeys()
	if newKeys == nil {
		t.Fatal("New session keys should not be nil")
	}

	// Keys should be the same since derivation is now deterministic from shared secret
	if !bytes.Equal(keys.EncryptionKey, newKeys.EncryptionKey) {
		t.Error("Keys should be the same when derived from same shared secret")
	}
}