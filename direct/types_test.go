package direct

import (
	"encoding/json"
	"testing"
	"time"
)

func TestGenerateConnectionID(t *testing.T) {
	// Test that we can generate connection IDs
	id1, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	id2, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate second connection ID: %v", err)
	}

	// IDs should be different
	if id1 == id2 {
		t.Error("Generated connection IDs should be different")
	}

	// IDs should not be all zeros
	var zeroID [16]byte
	if id1 == zeroID {
		t.Error("Connection ID should not be all zeros")
	}
}

func TestGenerateSalt(t *testing.T) {
	// Test valid salt generation
	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt))
	}

	// Test minimum size enforcement
	_, err = GenerateSalt(8) // Less than MinSaltSize (16)
	if err == nil {
		t.Error("Expected error for salt size less than minimum")
	}
}

func TestNewInvitationCodeSigner(t *testing.T) {
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create invitation code signer: %v", err)
	}

	if len(signer.PublicKey) != Ed25519PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", Ed25519PublicKeySize, len(signer.PublicKey))
	}

	if len(signer.PrivateKey) != Ed25519PrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", Ed25519PrivateKeySize, len(signer.PrivateKey))
	}
}

func TestInvitationCodeValidation(t *testing.T) {
	// Create a valid invitation code
	connectionID, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	publicKey := make([]byte, 1568) // Kyber public key size
	for i := range publicKey {
		publicKey[i] = byte(i % 256)
	}

	now := time.Now()
	expiration := now.Add(24 * time.Hour)

	ic := &InvitationCode{
		Version:      InvitationCodeVersion,
		ConnectionID: connectionID,
		PublicKey:    publicKey,
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
			BackupAddresses: []string{"192.168.1.101:8080"},
		},
		SecurityParams: &SecurityParams{
			KeyDerivationSalt: salt,
			CipherSuite:       "kyber1024-aes256-gcm",
			AuthMethod:        "pqc-mutual-auth",
		},
		ExpirationTime: expiration,
		SingleUse:      true,
		CreatedAt:      now,
	}

	// Test valid invitation code
	if err := ic.Validate(); err != nil {
		t.Errorf("Valid invitation code failed validation: %v", err)
	}

	// Test invalid version
	icInvalidVersion := *ic
	icInvalidVersion.Version = 99
	if err := icInvalidVersion.Validate(); err == nil {
		t.Error("Expected validation error for invalid version")
	}

	// Test zero connection ID
	icZeroID := *ic
	icZeroID.ConnectionID = [16]byte{}
	if err := icZeroID.Validate(); err == nil {
		t.Error("Expected validation error for zero connection ID")
	}

	// Test invalid public key size
	icInvalidKey := *ic
	icInvalidKey.PublicKey = []byte{1, 2, 3}
	if err := icInvalidKey.Validate(); err == nil {
		t.Error("Expected validation error for invalid public key size")
	}

	// Test invalid protocol
	icInvalidProtocol := *ic
	icInvalidProtocol.NetworkConfig.Protocol = "invalid"
	if err := icInvalidProtocol.Validate(); err == nil {
		t.Error("Expected validation error for invalid protocol")
	}

	// Test expired invitation
	icExpired := *ic
	icExpired.ExpirationTime = now.Add(-1 * time.Hour)
	if err := icExpired.Validate(); err == nil {
		t.Error("Expected validation error for expired invitation")
	}
}

func TestInvitationCodeSigning(t *testing.T) {
	// Create a signer
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create a valid invitation code
	connectionID, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	publicKey := make([]byte, 1568)
	for i := range publicKey {
		publicKey[i] = byte(i % 256)
	}

	now := time.Now()
	ic := &InvitationCode{
		Version:      InvitationCodeVersion,
		ConnectionID: connectionID,
		PublicKey:    publicKey,
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
		SecurityParams: &SecurityParams{
			KeyDerivationSalt: salt,
			CipherSuite:       "kyber1024-aes256-gcm",
			AuthMethod:        "pqc-mutual-auth",
		},
		ExpirationTime: now.Add(24 * time.Hour),
		SingleUse:      true,
		CreatedAt:      now,
	}

	// Sign the invitation code
	if err := ic.Sign(signer); err != nil {
		t.Fatalf("Failed to sign invitation code: %v", err)
	}

	// Verify signature length
	if len(ic.Signature) != Ed25519SignatureSize {
		t.Errorf("Expected signature size %d, got %d", Ed25519SignatureSize, len(ic.Signature))
	}

	// Verify the signature
	if err := ic.ValidateSignature(signer.PublicKey); err != nil {
		t.Errorf("Failed to validate signature: %v", err)
	}

	// Test signature validation with wrong key
	wrongSigner, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create wrong signer: %v", err)
	}

	if err := ic.ValidateSignature(wrongSigner.PublicKey); err == nil {
		t.Error("Expected signature validation to fail with wrong key")
	}

	// Test signing without signer
	icNoSigner := *ic
	icNoSigner.Signature = nil
	if err := icNoSigner.Sign(nil); err == nil {
		t.Error("Expected error when signing without signer")
	}
}

func TestInvitationCodeJSONMarshaling(t *testing.T) {
	// Create a valid invitation code
	connectionID, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	publicKey := make([]byte, 1568)
	for i := range publicKey {
		publicKey[i] = byte(i % 256)
	}

	now := time.Now().Truncate(time.Second) // Truncate for JSON comparison
	ic := &InvitationCode{
		Version:      InvitationCodeVersion,
		ConnectionID: connectionID,
		PublicKey:    publicKey,
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
			BackupAddresses: []string{"192.168.1.101:8080"},
		},
		SecurityParams: &SecurityParams{
			KeyDerivationSalt: salt,
			CipherSuite:       "kyber1024-aes256-gcm",
			AuthMethod:        "pqc-mutual-auth",
		},
		ExpirationTime: now.Add(24 * time.Hour),
		SingleUse:      true,
		CreatedAt:      now,
		Signature:      make([]byte, Ed25519SignatureSize),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(ic)
	if err != nil {
		t.Fatalf("Failed to marshal invitation code to JSON: %v", err)
	}

	// Unmarshal from JSON
	var icUnmarshaled InvitationCode
	if err := json.Unmarshal(jsonData, &icUnmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal invitation code from JSON: %v", err)
	}

	// Compare fields
	if icUnmarshaled.Version != ic.Version {
		t.Errorf("Version mismatch: expected %d, got %d", ic.Version, icUnmarshaled.Version)
	}

	if icUnmarshaled.ConnectionID != ic.ConnectionID {
		t.Error("Connection ID mismatch after JSON round-trip")
	}

	if len(icUnmarshaled.PublicKey) != len(ic.PublicKey) {
		t.Errorf("Public key length mismatch: expected %d, got %d", len(ic.PublicKey), len(icUnmarshaled.PublicKey))
	}

	if icUnmarshaled.NetworkConfig.Protocol != ic.NetworkConfig.Protocol {
		t.Errorf("Protocol mismatch: expected %s, got %s", ic.NetworkConfig.Protocol, icUnmarshaled.NetworkConfig.Protocol)
	}

	if icUnmarshaled.SingleUse != ic.SingleUse {
		t.Errorf("SingleUse mismatch: expected %t, got %t", ic.SingleUse, icUnmarshaled.SingleUse)
	}
}

func TestIsValidAddressFormat(t *testing.T) {
	validAddresses := []string{
		"192.168.1.1:8080",
		"10.0.0.1:443",
		"127.0.0.1:22",
		"[::1]:8080",
		"[2001:db8::1]:443",
		"example.com:80",
		"localhost:3000",
	}

	invalidAddresses := []string{
		"",
		"192.168.1.1",      // No port
		":8080",            // No IP
		"192.168.1.1:",     // No port number
		"[::1",             // Incomplete IPv6
		"192.168.1.1:abc",  // Non-numeric port
		"192.168.1.1:0",    // Invalid port (0)
		"192.168.1.1:65536", // Invalid port (too high)
	}

	for _, addr := range validAddresses {
		if !isValidAddressFormat(addr) {
			t.Errorf("Expected address %s to be valid", addr)
		}
	}

	for _, addr := range invalidAddresses {
		if isValidAddressFormat(addr) {
			t.Errorf("Expected address %s to be invalid", addr)
		}
	}
}

func TestInvitationCodeExpiration(t *testing.T) {
	now := time.Now()
	
	// Test non-expired invitation
	ic := &InvitationCode{
		ExpirationTime: now.Add(1 * time.Hour),
	}
	
	if ic.IsExpired() {
		t.Error("Expected invitation code to not be expired")
	}
	
	// Test expired invitation
	ic.ExpirationTime = now.Add(-1 * time.Hour)
	
	if !ic.IsExpired() {
		t.Error("Expected invitation code to be expired")
	}
}

func TestSecurityParamsValidation(t *testing.T) {
	// Test with valid security params
	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	sp := &SecurityParams{
		KeyDerivationSalt: salt,
		CipherSuite:       "kyber1024-aes256-gcm",
		AuthMethod:        "pqc-mutual-auth",
	}

	ic := &InvitationCode{
		SecurityParams: sp,
	}

	if err := ic.validateSecurityParams(); err != nil {
		t.Errorf("Valid security params failed validation: %v", err)
	}

	// Test with short salt
	spShortSalt := &SecurityParams{
		KeyDerivationSalt: []byte{1, 2, 3}, // Too short
		CipherSuite:       "kyber1024-aes256-gcm",
		AuthMethod:        "pqc-mutual-auth",
	}

	ic.SecurityParams = spShortSalt
	if err := ic.validateSecurityParams(); err == nil {
		t.Error("Expected validation error for short salt")
	}

	// Test with empty cipher suite
	spEmptyCipher := &SecurityParams{
		KeyDerivationSalt: salt,
		CipherSuite:       "",
		AuthMethod:        "pqc-mutual-auth",
	}

	ic.SecurityParams = spEmptyCipher
	if err := ic.validateSecurityParams(); err == nil {
		t.Error("Expected validation error for empty cipher suite")
	}

	// Test with empty auth method
	spEmptyAuth := &SecurityParams{
		KeyDerivationSalt: salt,
		CipherSuite:       "kyber1024-aes256-gcm",
		AuthMethod:        "",
	}

	ic.SecurityParams = spEmptyAuth
	if err := ic.validateSecurityParams(); err == nil {
		t.Error("Expected validation error for empty auth method")
	}
}