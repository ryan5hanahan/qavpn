package main

import (
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// TestPeerCertificateGeneration tests certificate generation
func TestPeerCertificateGeneration(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test self-signed certificate
	cert, err := GeneratePeerCertificate("test-peer", keyPair, nil, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cert.Identity != "test-peer" {
		t.Errorf("Expected identity 'test-peer', got '%s'", cert.Identity)
	}

	if cert.SignerID != "test-peer" {
		t.Errorf("Expected signer ID 'test-peer', got '%s'", cert.SignerID)
	}

	if len(cert.SerialNumber) != 16 {
		t.Errorf("Expected serial number length 16, got %d", len(cert.SerialNumber))
	}

	if len(cert.Signature) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(cert.Signature))
	}
}

// TestCertificateValidation tests certificate validation
func TestCertificateValidation(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Generate valid certificate
	cert, err := GeneratePeerCertificate("test-peer", keyPair, nil, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Test validation with empty trusted CAs (self-signed)
	trustedCAs := make(map[string]*PeerCertificate)
	revocationList := make(map[string]time.Time)

	err = ValidatePeerCertificate(cert, trustedCAs, revocationList)
	if err != nil {
		t.Errorf("Valid certificate failed validation: %v", err)
	}

	// Test expired certificate
	expiredCert, err := GeneratePeerCertificate("expired-peer", keyPair, nil, -time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate expired certificate: %v", err)
	}

	err = ValidatePeerCertificate(expiredCert, trustedCAs, revocationList)
	if err == nil {
		t.Error("Expired certificate should have failed validation")
	}

	// Test revoked certificate
	revocationList["test-peer"] = time.Now().Add(-time.Minute)
	err = ValidatePeerCertificate(cert, trustedCAs, revocationList)
	if err == nil {
		t.Error("Revoked certificate should have failed validation")
	}
}

// TestCertificateSerialization tests certificate serialization/deserialization
func TestCertificateSerialization(t *testing.T) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalCert, err := GeneratePeerCertificate("test-peer", keyPair, nil, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Serialize certificate
	serialized, err := serializeCertificate(originalCert)
	if err != nil {
		t.Fatalf("Failed to serialize certificate: %v", err)
	}

	// Deserialize certificate
	deserializedCert, err := deserializeCertificate(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize certificate: %v", err)
	}

	// Compare certificates
	if deserializedCert.Identity != originalCert.Identity {
		t.Errorf("Identity mismatch: expected '%s', got '%s'", originalCert.Identity, deserializedCert.Identity)
	}

	if deserializedCert.SignerID != originalCert.SignerID {
		t.Errorf("SignerID mismatch: expected '%s', got '%s'", originalCert.SignerID, deserializedCert.SignerID)
	}

	if len(deserializedCert.PublicKey) != len(originalCert.PublicKey) {
		t.Errorf("PublicKey length mismatch: expected %d, got %d", len(originalCert.PublicKey), len(deserializedCert.PublicKey))
	}

	if len(deserializedCert.Signature) != len(originalCert.Signature) {
		t.Errorf("Signature length mismatch: expected %d, got %d", len(originalCert.Signature), len(deserializedCert.Signature))
	}
}

// TestPSKAuthenticator tests PSK authentication functionality
func TestPSKAuthenticator(t *testing.T) {
	psk := NewPSKAuthenticator()

	// Test adding shared key
	sharedKey := make([]byte, 32)
	if _, err := rand.Read(sharedKey); err != nil {
		t.Fatalf("Failed to generate shared key: %v", err)
	}

	err := psk.AddSharedKey("peer1", sharedKey)
	if err != nil {
		t.Fatalf("Failed to add shared key: %v", err)
	}

	// Test key existence
	if !psk.HasSharedKey("peer1") {
		t.Error("Shared key should exist for peer1")
	}

	if psk.HasSharedKey("peer2") {
		t.Error("Shared key should not exist for peer2")
	}

	// Test invalid key length
	shortKey := make([]byte, 16)
	err = psk.AddSharedKey("peer2", shortKey)
	if err == nil {
		t.Error("Should reject keys shorter than 32 bytes")
	}

	// Test removing key
	psk.RemoveSharedKey("peer1")
	if psk.HasSharedKey("peer1") {
		t.Error("Shared key should be removed for peer1")
	}
}

// TestChallengeResponse tests challenge-response authentication
func TestChallengeResponse(t *testing.T) {
	// Generate test key pair
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKey := keyPair.SerializePublicKey()

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	// Generate response
	response, err := generateChallengeResponse(challenge, publicKey)
	if err != nil {
		t.Fatalf("Failed to generate challenge response: %v", err)
	}

	// Verify response
	err = verifyChallengeResponse(challenge, response, publicKey)
	if err != nil {
		t.Errorf("Valid challenge response failed verification: %v", err)
	}

	// Test with wrong public key
	wrongKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate wrong key pair: %v", err)
	}
	wrongPublicKey := wrongKeyPair.SerializePublicKey()

	err = verifyChallengeResponse(challenge, response, wrongPublicKey)
	if err == nil {
		t.Error("Challenge response should fail with wrong public key")
	}

	// Test with invalid response length
	invalidResponse := make([]byte, 30)
	err = verifyChallengeResponse(challenge, invalidResponse, publicKey)
	if err == nil {
		t.Error("Should reject invalid response length")
	}
}

// TestAuthenticationProof tests authentication proof generation and verification
func TestAuthenticationProof(t *testing.T) {
	// Generate test certificate
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	cert, err := GeneratePeerCertificate("test-peer", keyPair, nil, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	publicKey := keyPair.SerializePublicKey()

	// Generate authentication proof
	proof, err := generateAuthenticationProof(publicKey, cert)
	if err != nil {
		t.Fatalf("Failed to generate authentication proof: %v", err)
	}

	// Verify proof
	err = verifyAuthenticationProof(publicKey, proof, cert)
	if err != nil {
		t.Errorf("Valid authentication proof failed verification: %v", err)
	}

	// Test with wrong certificate
	wrongKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate wrong key pair: %v", err)
	}

	wrongCert, err := GeneratePeerCertificate("wrong-peer", wrongKeyPair, nil, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to generate wrong certificate: %v", err)
	}

	err = verifyAuthenticationProof(publicKey, proof, wrongCert)
	if err == nil {
		t.Error("Authentication proof should fail with wrong certificate")
	}
}

// TestAuthenticationContext tests authentication context functionality
func TestAuthenticationContext(t *testing.T) {
	authCtx := NewAuthenticationContext()

	if authCtx.AuthMethod != "certificate" {
		t.Errorf("Expected default auth method 'certificate', got '%s'", authCtx.AuthMethod)
	}

	if len(authCtx.TrustedCAs) != 0 {
		t.Errorf("Expected empty trusted CAs, got %d entries", len(authCtx.TrustedCAs))
	}

	if len(authCtx.RevocationList) != 0 {
		t.Errorf("Expected empty revocation list, got %d entries", len(authCtx.RevocationList))
	}

	// Test adding trusted CA
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	caCert, err := GeneratePeerCertificate("test-ca", keyPair, nil, time.Hour*24*365)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	authCtx.TrustedCAs["test-ca"] = caCert

	if len(authCtx.TrustedCAs) != 1 {
		t.Errorf("Expected 1 trusted CA, got %d", len(authCtx.TrustedCAs))
	}

	// Test adding to revocation list
	authCtx.RevocationList["revoked-peer"] = time.Now()

	if len(authCtx.RevocationList) != 1 {
		t.Errorf("Expected 1 revoked certificate, got %d", len(authCtx.RevocationList))
	}
}

// MockConnection implements net.Conn for testing
type MockConnection struct {
	readData  [][]byte
	writeData [][]byte
	readIdx   int
	writeIdx  int
	closed    bool
}

func NewMockConnection() *MockConnection {
	return &MockConnection{
		readData:  make([][]byte, 0),
		writeData: make([][]byte, 0),
	}
}

func (mc *MockConnection) Read(b []byte) (n int, err error) {
	if mc.closed {
		return 0, net.ErrClosed
	}
	if mc.readIdx >= len(mc.readData) {
		return 0, net.ErrClosed
	}
	
	data := mc.readData[mc.readIdx]
	mc.readIdx++
	
	copy(b, data)
	return len(data), nil
}

func (mc *MockConnection) Write(b []byte) (n int, err error) {
	if mc.closed {
		return 0, net.ErrClosed
	}
	
	data := make([]byte, len(b))
	copy(data, b)
	mc.writeData = append(mc.writeData, data)
	mc.writeIdx++
	
	return len(b), nil
}

func (mc *MockConnection) Close() error {
	mc.closed = true
	return nil
}

func (mc *MockConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (mc *MockConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
}

func (mc *MockConnection) SetDeadline(t time.Time) error {
	return nil
}

func (mc *MockConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (mc *MockConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (mc *MockConnection) AddReadData(data []byte) {
	mc.readData = append(mc.readData, data)
}

func (mc *MockConnection) GetWrittenData() [][]byte {
	return mc.writeData
}

// TestAuthMessageTransmission tests authentication message sending/receiving
func TestAuthMessageTransmission(t *testing.T) {
	conn := NewMockConnection()

	// Test data
	testData := []byte("test authentication message")

	// Send message
	err := sendAuthMessage(conn, testData)
	if err != nil {
		t.Fatalf("Failed to send auth message: %v", err)
	}

	// Verify written data
	writtenData := conn.GetWrittenData()
	if len(writtenData) != 2 { // Length prefix + data
		t.Fatalf("Expected 2 writes, got %d", len(writtenData))
	}

	// Check length prefix
	lengthPrefix := writtenData[0]
	if len(lengthPrefix) != 4 {
		t.Errorf("Expected length prefix of 4 bytes, got %d", len(lengthPrefix))
	}

	// Check data
	actualData := writtenData[1]
	if string(actualData) != string(testData) {
		t.Errorf("Expected data '%s', got '%s'", string(testData), string(actualData))
	}

	// Test receiving
	conn2 := NewMockConnection()
	conn2.AddReadData(lengthPrefix)
	conn2.AddReadData(testData)

	receivedData, err := receiveAuthMessage(conn2)
	if err != nil {
		t.Fatalf("Failed to receive auth message: %v", err)
	}

	if string(receivedData) != string(testData) {
		t.Errorf("Expected received data '%s', got '%s'", string(testData), string(receivedData))
	}
}

// TestVulnerableKeyExchangeBlocked tests that the vulnerable key exchange is blocked
func TestVulnerableKeyExchangeBlocked(t *testing.T) {
	conn := NewMockConnection()
	
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test that the vulnerable function is blocked
	_, err = performKeyExchange(conn, keyPair)
	if err == nil {
		t.Error("Vulnerable key exchange should be blocked")
	}

	expectedError := "SECURITY ERROR: unauthenticated key exchange is disabled"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestAuthenticatedKeyExchangeRequiresContext tests that authenticated key exchange requires context
func TestAuthenticatedKeyExchangeRequiresContext(t *testing.T) {
	conn := NewMockConnection()
	
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test with nil context
	_, err = performAuthenticatedKeyExchangeWithContext(conn, keyPair, nil)
	if err == nil {
		t.Error("Should require authentication context")
	}

	expectedError := "authentication context is required"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestPSKKeyExchangeRequiresPSK tests that PSK key exchange requires PSK authenticator
func TestPSKKeyExchangeRequiresPSK(t *testing.T) {
	conn := NewMockConnection()
	
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test with nil PSK authenticator
	_, err = performPSKKeyExchangeWithAuth(conn, keyPair, nil, "peer1")
	if err == nil {
		t.Error("Should require PSK authenticator")
	}

	expectedError := "PSK authenticator is required"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestSecurityValidation tests various security validation scenarios
func TestSecurityValidation(t *testing.T) {
	// Test nil certificate validation
	err := ValidatePeerCertificate(nil, nil, nil)
	if err == nil {
		t.Error("Should reject nil certificate")
	}

	// Test empty challenge response
	_, err = generateChallengeResponse([]byte{}, []byte("key"))
	if err == nil {
		t.Error("Should reject empty challenge")
	}

	// Test invalid proof length
	err = verifyAuthenticationProof([]byte("key"), []byte("short"), &PeerCertificate{Identity: "test"})
	if err == nil {
		t.Error("Should reject invalid proof length")
	}

	// Test certificate serialization with nil
	_, err = serializeCertificate(nil)
	if err == nil {
		t.Error("Should reject nil certificate for serialization")
	}

	// Test certificate deserialization with short data
	_, err = deserializeCertificate([]byte("short"))
	if err == nil {
		t.Error("Should reject short data for deserialization")
	}
}

// BenchmarkCertificateGeneration benchmarks certificate generation
func BenchmarkCertificateGeneration(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GeneratePeerCertificate("benchmark-peer", keyPair, nil, time.Hour*24)
		if err != nil {
			b.Fatalf("Failed to generate certificate: %v", err)
		}
	}
}

// BenchmarkCertificateValidation benchmarks certificate validation
func BenchmarkCertificateValidation(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	cert, err := GeneratePeerCertificate("benchmark-peer", keyPair, nil, time.Hour*24)
	if err != nil {
		b.Fatalf("Failed to generate certificate: %v", err)
	}

	trustedCAs := make(map[string]*PeerCertificate)
	revocationList := make(map[string]time.Time)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ValidatePeerCertificate(cert, trustedCAs, revocationList)
		if err != nil {
			b.Fatalf("Certificate validation failed: %v", err)
		}
	}
}

// BenchmarkChallengeResponse benchmarks challenge-response generation
func BenchmarkChallengeResponse(b *testing.B) {
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKey := keyPair.SerializePublicKey()
	challenge := make([]byte, 32)
	rand.Read(challenge)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateChallengeResponse(challenge, publicKey)
		if err != nil {
			b.Fatalf("Failed to generate challenge response: %v", err)
		}
	}
}
