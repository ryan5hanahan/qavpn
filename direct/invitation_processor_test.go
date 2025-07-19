package direct

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func createTestInvitationCode(t *testing.T) *InvitationCode {
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

	now := time.Now().Truncate(time.Second) // Truncate for consistent testing
	return &InvitationCode{
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
}

func TestNewInvitationCodeProcessor(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	if processor == nil {
		t.Error("Expected non-nil processor")
	}
}

func TestEncodeDecodeBase64(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test encoding
	encoded, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	// Check that it has the correct prefix
	if !strings.HasPrefix(encoded, FormatPrefix) {
		t.Errorf("Expected prefix %s, got: %s", FormatPrefix, encoded[:len(FormatPrefix)])
	}

	// Test decoding
	decoded, err := processor.DecodeFromBase64(encoded)
	if err != nil {
		t.Fatalf("Failed to decode from base64: %v", err)
	}

	// Compare key fields
	if decoded.Version != invitation.Version {
		t.Errorf("Version mismatch: expected %d, got %d", invitation.Version, decoded.Version)
	}

	if decoded.ConnectionID != invitation.ConnectionID {
		t.Error("Connection ID mismatch after base64 round-trip")
	}

	if decoded.NetworkConfig.Protocol != invitation.NetworkConfig.Protocol {
		t.Errorf("Protocol mismatch: expected %s, got %s", 
			invitation.NetworkConfig.Protocol, decoded.NetworkConfig.Protocol)
	}

	if decoded.SingleUse != invitation.SingleUse {
		t.Errorf("SingleUse mismatch: expected %t, got %t", invitation.SingleUse, decoded.SingleUse)
	}
}

func TestEncodeDecodeHex(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test encoding
	encoded, err := processor.EncodeToHex(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	// Check that it has the correct prefix and hex indicator
	expectedPrefix := FormatPrefix + "hex:"
	if !strings.HasPrefix(encoded, expectedPrefix) {
		t.Errorf("Expected prefix %s, got: %s", expectedPrefix, encoded[:len(expectedPrefix)])
	}

	// Test decoding
	decoded, err := processor.DecodeFromHex(encoded)
	if err != nil {
		t.Fatalf("Failed to decode from hex: %v", err)
	}

	// Compare key fields
	if decoded.Version != invitation.Version {
		t.Errorf("Version mismatch: expected %d, got %d", invitation.Version, decoded.Version)
	}

	if decoded.ConnectionID != invitation.ConnectionID {
		t.Error("Connection ID mismatch after hex round-trip")
	}

	if decoded.NetworkConfig.ListenerAddress != invitation.NetworkConfig.ListenerAddress {
		t.Errorf("Listener address mismatch: expected %s, got %s", 
			invitation.NetworkConfig.ListenerAddress, decoded.NetworkConfig.ListenerAddress)
	}
}

func TestGenerateQRCode(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test QR code generation (placeholder implementation)
	qrData, err := processor.GenerateQRCode(invitation)
	if err != nil {
		t.Fatalf("Failed to generate QR code: %v", err)
	}

	if len(qrData) == 0 {
		t.Error("Expected non-empty QR code data")
	}

	// Check that it contains expected placeholder text
	qrString := string(qrData)
	if !strings.Contains(qrString, "QR-CODE-PLACEHOLDER") {
		t.Error("Expected QR code placeholder text")
	}

	// Check that it contains the base64 encoded invitation
	if !strings.Contains(qrString, FormatPrefix) {
		t.Error("Expected QR code to contain encoded invitation")
	}
}

func TestDetectFormat(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test base64 format detection
	base64Encoded, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	format := processor.DetectFormat(base64Encoded)
	if format != FormatBase64 {
		t.Errorf("Expected format %s, got %s", FormatBase64, format)
	}

	// Test hex format detection
	hexEncoded, err := processor.EncodeToHex(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	format = processor.DetectFormat(hexEncoded)
	if format != FormatHex {
		t.Errorf("Expected format %s, got %s", FormatHex, format)
	}

	// Test JSON format detection
	jsonData, err := json.Marshal(invitation)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	format = processor.DetectFormat(string(jsonData))
	if format != FormatJSON {
		t.Errorf("Expected format %s, got %s", FormatJSON, format)
	}

	// Test unknown format detection
	format = processor.DetectFormat("invalid-data")
	if format != FormatUnknown {
		t.Errorf("Expected format %s, got %s", FormatUnknown, format)
	}

	// Test empty string
	format = processor.DetectFormat("")
	if format != FormatUnknown {
		t.Errorf("Expected format %s for empty string, got %s", FormatUnknown, format)
	}
}

func TestDecodeAuto(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test auto-decode with base64
	base64Encoded, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	decoded, err := processor.DecodeAuto(base64Encoded)
	if err != nil {
		t.Fatalf("Failed to auto-decode base64: %v", err)
	}

	if decoded.Version != invitation.Version {
		t.Errorf("Version mismatch in auto-decode: expected %d, got %d", invitation.Version, decoded.Version)
	}

	// Test auto-decode with hex
	hexEncoded, err := processor.EncodeToHex(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	decoded, err = processor.DecodeAuto(hexEncoded)
	if err != nil {
		t.Fatalf("Failed to auto-decode hex: %v", err)
	}

	if decoded.Version != invitation.Version {
		t.Errorf("Version mismatch in auto-decode: expected %d, got %d", invitation.Version, decoded.Version)
	}

	// Test auto-decode with JSON
	jsonData, err := json.Marshal(invitation)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	decoded, err = processor.DecodeAuto(string(jsonData))
	if err != nil {
		t.Fatalf("Failed to auto-decode JSON: %v", err)
	}

	if decoded.Version != invitation.Version {
		t.Errorf("Version mismatch in auto-decode: expected %d, got %d", invitation.Version, decoded.Version)
	}

	// Test auto-decode with invalid data
	_, err = processor.DecodeAuto("invalid-data")
	if err == nil {
		t.Error("Expected error for invalid data in auto-decode")
	}
}

func TestValidateFormat(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test valid base64 format
	base64Encoded, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	if err := processor.ValidateFormat(base64Encoded); err != nil {
		t.Errorf("Valid base64 format failed validation: %v", err)
	}

	// Test valid hex format
	hexEncoded, err := processor.EncodeToHex(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	if err := processor.ValidateFormat(hexEncoded); err != nil {
		t.Errorf("Valid hex format failed validation: %v", err)
	}

	// Test valid JSON format
	jsonData, err := json.Marshal(invitation)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	if err := processor.ValidateFormat(string(jsonData)); err != nil {
		t.Errorf("Valid JSON format failed validation: %v", err)
	}

	// Test invalid format
	if err := processor.ValidateFormat("invalid-data"); err == nil {
		t.Error("Expected validation error for invalid format")
	}

	// Test empty string
	if err := processor.ValidateFormat(""); err == nil {
		t.Error("Expected validation error for empty string")
	}
}

func TestEncodeToFormat(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test encoding to base64
	encoded, err := processor.EncodeToFormat(invitation, FormatBase64)
	if err != nil {
		t.Fatalf("Failed to encode to base64 format: %v", err)
	}

	if !strings.HasPrefix(encoded, FormatPrefix) {
		t.Error("Base64 encoded format should have prefix")
	}

	// Test encoding to hex
	encoded, err = processor.EncodeToFormat(invitation, FormatHex)
	if err != nil {
		t.Fatalf("Failed to encode to hex format: %v", err)
	}

	if !strings.HasPrefix(encoded, FormatPrefix+"hex:") {
		t.Error("Hex encoded format should have prefix and hex indicator")
	}

	// Test encoding to JSON
	encoded, err = processor.EncodeToFormat(invitation, FormatJSON)
	if err != nil {
		t.Fatalf("Failed to encode to JSON format: %v", err)
	}

	if !strings.HasPrefix(encoded, "{") {
		t.Error("JSON encoded format should start with {")
	}

	// Test unsupported format
	_, err = processor.EncodeToFormat(invitation, "unsupported")
	if err == nil {
		t.Error("Expected error for unsupported format")
	}

	// Test nil invitation
	_, err = processor.EncodeToFormat(nil, FormatBase64)
	if err == nil {
		t.Error("Expected error for nil invitation")
	}
}

func TestGetSupportedFormats(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	formats := processor.GetSupportedFormats()

	expectedFormats := []string{FormatBase64, FormatHex, FormatJSON}
	if len(formats) != len(expectedFormats) {
		t.Errorf("Expected %d supported formats, got %d", len(expectedFormats), len(formats))
	}

	for _, expected := range expectedFormats {
		found := false
		for _, format := range formats {
			if format == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected format %s not found in supported formats", expected)
		}
	}
}

func TestErrorHandling(t *testing.T) {
	processor := NewInvitationCodeProcessor()

	// Test encoding nil invitation
	_, err := processor.EncodeToBase64(nil)
	if err == nil {
		t.Error("Expected error when encoding nil invitation to base64")
	}

	_, err = processor.EncodeToHex(nil)
	if err == nil {
		t.Error("Expected error when encoding nil invitation to hex")
	}

	_, err = processor.GenerateQRCode(nil)
	if err == nil {
		t.Error("Expected error when generating QR code for nil invitation")
	}

	// Test decoding empty strings
	_, err = processor.DecodeFromBase64("")
	if err == nil {
		t.Error("Expected error when decoding empty base64 string")
	}

	_, err = processor.DecodeFromHex("")
	if err == nil {
		t.Error("Expected error when decoding empty hex string")
	}

	_, err = processor.DecodeAuto("")
	if err == nil {
		t.Error("Expected error when auto-decoding empty string")
	}

	// Test decoding invalid prefixes
	_, err = processor.DecodeFromBase64("invalid-prefix:data")
	if err == nil {
		t.Error("Expected error for invalid prefix in base64 decode")
	}

	_, err = processor.DecodeFromHex("invalid-prefix:hex:data")
	if err == nil {
		t.Error("Expected error for invalid prefix in hex decode")
	}

	// Test decoding invalid base64 data
	_, err = processor.DecodeFromBase64(FormatPrefix + "invalid-base64-data!")
	if err == nil {
		t.Error("Expected error for invalid base64 data")
	}

	// Test decoding invalid hex data
	_, err = processor.DecodeFromHex(FormatPrefix + "hex:invalid-hex-data!")
	if err == nil {
		t.Error("Expected error for invalid hex data")
	}
}

func TestRoundTripConsistency(t *testing.T) {
	processor := NewInvitationCodeProcessor()
	invitation := createTestInvitationCode(t)

	// Test base64 round-trip
	base64Encoded, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to base64: %v", err)
	}

	base64Decoded, err := processor.DecodeFromBase64(base64Encoded)
	if err != nil {
		t.Fatalf("Failed to decode from base64: %v", err)
	}

	// Test hex round-trip
	hexEncoded, err := processor.EncodeToHex(invitation)
	if err != nil {
		t.Fatalf("Failed to encode to hex: %v", err)
	}

	hexDecoded, err := processor.DecodeFromHex(hexEncoded)
	if err != nil {
		t.Fatalf("Failed to decode from hex: %v", err)
	}

	// Both decoded versions should be equivalent
	if base64Decoded.Version != hexDecoded.Version {
		t.Error("Version mismatch between base64 and hex round-trips")
	}

	if base64Decoded.ConnectionID != hexDecoded.ConnectionID {
		t.Error("Connection ID mismatch between base64 and hex round-trips")
	}

	if base64Decoded.SingleUse != hexDecoded.SingleUse {
		t.Error("SingleUse mismatch between base64 and hex round-trips")
	}
}