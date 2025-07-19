package direct

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// TestCompleteDirectConnectionFlow tests the full end-to-end connection establishment
// and data transfer between two QAVPN instances using direct connection mode
func TestCompleteDirectConnectionFlow(t *testing.T) {
	// Setup two instances
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Step 1: Instance A generates invitation code
	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: "127.0.0.1:0", // Use any available port
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := instanceA.dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	// Step 2: Instance B validates invitation
	err = instanceB.dcm.ValidateInvitation(invitation)
	if err != nil {
		t.Fatalf("Failed to validate invitation: %v", err)
	}

	// Step 3: Start listener on Instance A
	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: "tcp",
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Step 4: Instance B connects to Instance A
	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect to peer: %v", err)
	}

	// Step 5: Wait for connection establishment
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 10*time.Second) {
		t.Fatal("Connection establishment timed out")
	}

	// Step 6: Verify both instances have active connections
	connectionsA := instanceA.dcm.GetActiveConnections()
	connectionsB := instanceB.dcm.GetActiveConnections()

	if len(connectionsA) != 1 {
		t.Errorf("Expected 1 active connection on instance A, got %d", len(connectionsA))
	}

	if len(connectionsB) != 1 {
		t.Errorf("Expected 1 active connection on instance B, got %d", len(connectionsB))
	}

	// Step 7: Test secure data transfer
	testData := []byte("Hello from integration test! This is secure direct connection data.")
	
	if !verifySecureDataTransfer(t, connectionsA[0], connectionsB[0], testData) {
		t.Fatal("Secure data transfer verification failed")
	}

	// Step 8: Verify connection health monitoring
	healthA := instanceA.healthMonitor.GetHealth(fmt.Sprintf("%x", invitation.ConnectionID))
	healthB := instanceB.healthMonitor.GetHealth(fmt.Sprintf("%x", invitation.ConnectionID))

	if healthA == nil || healthB == nil {
		t.Error("Connection health monitoring not working")
	}

	if healthA != nil && healthA.Status != "healthy" {
		t.Errorf("Instance A connection should be healthy, got: %s", healthA.Status)
	}

	// Step 9: Test graceful disconnection
	err = instanceB.dcm.(*DirectConnectionManagerImpl).Shutdown()
	if err != nil {
		t.Errorf("Failed to shutdown instance B: %v", err)
	}

	// Verify connection cleanup
	time.Sleep(100 * time.Millisecond)
	connectionsA = instanceA.dcm.GetActiveConnections()
	if len(connectionsA) != 0 {
		t.Errorf("Expected 0 active connections after shutdown, got %d", len(connectionsA))
	}
}

// TestMultipleSimultaneousConnections tests handling multiple direct connections
func TestMultipleSimultaneousConnections(t *testing.T) {
	// Setup one listener instance and multiple connector instances
	listener, connectors, cleanup := setupMultiInstanceTest(t, 3)
	defer cleanup()

	var wg sync.WaitGroup
	errors := make(chan error, len(connectors))

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     0, // Use any available port
		Protocol: "tcp",
	}

	err := listener.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Get the actual port assigned
	listeners := listener.dcm.(*DirectConnectionManagerImpl).GetActiveListeners()
	var actualPort int
	for key := range listeners {
		_, portStr, _ := net.SplitHostPort(key)
		fmt.Sscanf(portStr, "%d", &actualPort)
		break
	}

	// Connect all instances simultaneously
	for i, connector := range connectors {
		wg.Add(1)
		go func(idx int, conn *TestInstance) {
			defer wg.Done()

			// Generate invitation for this connection
			invitationConfig := &InvitationConfig{
				Protocol:        "tcp",
				ListenerAddress: fmt.Sprintf("127.0.0.1:%d", actualPort),
				ExpirationTime:  time.Now().Add(1 * time.Hour),
				SingleUse:       true,
			}

			invitation, err := listener.dcm.GenerateInvitation(invitationConfig)
			if err != nil {
				errors <- fmt.Errorf("connector %d: failed to generate invitation: %v", idx, err)
				return
			}

			// Connect
			err = conn.dcm.ConnectToPeer(invitation)
			if err != nil {
				errors <- fmt.Errorf("connector %d: failed to connect: %v", idx, err)
				return
			}
		}(i, connector)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Wait for all connections to establish
	time.Sleep(2 * time.Second)

	// Verify all connections are active
	listenerConnections := listener.dcm.GetActiveConnections()
	if len(listenerConnections) != len(connectors) {
		t.Errorf("Expected %d connections on listener, got %d", len(connectors), len(listenerConnections))
	}

	for i, connector := range connectors {
		connectorConnections := connector.dcm.GetActiveConnections()
		if len(connectorConnections) != 1 {
			t.Errorf("Connector %d: expected 1 connection, got %d", i, len(connectorConnections))
		}
	}

	// Test data transfer on all connections
	testData := []byte("Multi-connection test data")
	for i, listenerConn := range listenerConnections {
		connectorConn := connectors[i].dcm.GetActiveConnections()[0]
		if !verifySecureDataTransfer(t, listenerConn, connectorConn, testData) {
			t.Errorf("Data transfer failed on connection %d", i)
		}
	}
}

// TestTCPToUDPFallback tests protocol fallback functionality
func TestTCPToUDPFallback(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Configure protocol optimizer for aggressive fallback
	optimizer := NewProtocolOptimizer()
	fallbackManager := optimizer.fallback
	
	// Add custom fallback rule for testing
	testRule := &FallbackRule{
		Name:         "test_tcp_to_udp",
		FromProtocol: "tcp",
		ToProtocol:   "udp",
		Trigger: FallbackTrigger{
			Type:             "latency",
			LatencyThreshold: 100 * time.Millisecond, // Low threshold for testing
		},
		Priority: 1,
	}
	fallbackManager.fallbackRules = append(fallbackManager.fallbackRules, testRule)

	// Start with TCP connection
	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: "127.0.0.1:0",
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := instanceA.dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate TCP invitation: %v", err)
	}

	// Start TCP listener
	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: "tcp",
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}

	// Connect with TCP
	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect with TCP: %v", err)
	}

	// Wait for connection
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 5*time.Second) {
		t.Fatal("TCP connection establishment failed")
	}

	// Simulate high latency conditions to trigger fallback
	highLatencyConditions := &NetworkConditions{
		Latency:    200 * time.Millisecond, // Above threshold
		PacketLoss: 0.01,
		Throughput: 1000000,
		Jitter:     50 * time.Millisecond,
		Stability:  0.9,
	}

	// Check if fallback should be triggered
	rule, shouldFallback := fallbackManager.CheckFallbackConditions("tcp", highLatencyConditions)
	if !shouldFallback {
		t.Error("Fallback should be triggered for high latency")
	}

	if rule.ToProtocol != "udp" {
		t.Errorf("Expected fallback to UDP, got: %s", rule.ToProtocol)
	}

	// Execute fallback
	fallbackEvent := fallbackManager.ExecuteFallback(rule, highLatencyConditions)
	if !fallbackEvent.Success {
		t.Error("Fallback execution should succeed")
	}

	// Verify fallback was logged
	if fallbackEvent.FromProtocol != "tcp" || fallbackEvent.ToProtocol != "udp" {
		t.Errorf("Fallback event incorrect: %s -> %s", fallbackEvent.FromProtocol, fallbackEvent.ToProtocol)
	}
}

// TestOPSECIntegratedFlow tests complete OPSEC compliance during connection flow
func TestOPSECIntegratedFlow(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Enable all OPSEC features
	opsecConfig := &TrafficObfuscationConfig{
		EnablePadding:      true,
		PaddingMinSize:     32,
		PaddingMaxSize:     256,
		NoiseInjectionRate: 0.1,
		EnableSharding:     true,
		MaxShardSize:       1024,
		MinShardSize:       128,
	}

	opsecLayer := NewOPSECNetworkLayerWithConfig(opsecConfig)
	
	// Configure timing obfuscation
	opsecLayer.SetTimingConfiguration(
		200*time.Millisecond, // base connection delay
		5*time.Second,        // max connection delay
		1*time.Second,        // base retry delay
		30*time.Second,       // max retry delay
		0.3,                  // jitter factor
	)

	// Generate invitation with OPSEC considerations
	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: "127.0.0.1:0",
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := instanceA.dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate invitation: %v", err)
	}

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: "tcp",
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Measure connection establishment time (should include OPSEC delays)
	startTime := time.Now()
	
	// Apply connection delay
	connectionDelay := opsecLayer.CalculateConnectionDelay()
	time.Sleep(connectionDelay)

	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect with OPSEC: %v", err)
	}

	connectionTime := time.Since(startTime)
	
	// Verify OPSEC timing was applied (should be longer than base delay)
	if connectionTime < connectionDelay {
		t.Errorf("Connection time too short, OPSEC timing not applied: %v", connectionTime)
	}

	// Wait for connection establishment
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 10*time.Second) {
		t.Fatal("OPSEC connection establishment failed")
	}

	// Test obfuscated data transfer
	originalData := []byte("OPSEC test data that should be obfuscated during transmission")
	
	// Obfuscate data
	obfuscatedData, err := opsecLayer.ObfuscateTraffic(originalData)
	if err != nil {
		t.Fatalf("Failed to obfuscate traffic: %v", err)
	}

	// Verify obfuscation occurred (data should be different)
	if bytes.Equal(originalData, obfuscatedData) {
		t.Error("Data should be obfuscated (different from original)")
	}

	// Deobfuscate and verify integrity
	deobfuscatedData, err := opsecLayer.DeobfuscateTraffic(obfuscatedData)
	if err != nil {
		t.Fatalf("Failed to deobfuscate traffic: %v", err)
	}

	if !bytes.Equal(originalData, deobfuscatedData) {
		t.Error("Deobfuscated data should match original")
	}

	// Test secure keep-alive generation
	keepAlive, interval := opsecLayer.GenerateSecureKeepAlive()
	if len(keepAlive) == 0 {
		t.Error("Keep-alive packet should not be empty")
	}

	if !opsecLayer.IsKeepAlivePacket(keepAlive) {
		t.Error("Generated packet should be recognized as keep-alive")
	}

	if interval <= 0 {
		t.Error("Keep-alive interval should be positive")
	}

	// Verify secure logging (no sensitive data exposure)
	logger := NewOPSECLogger()
	logger.LogConnectionEvent(fmt.Sprintf("%x", invitation.ConnectionID), "established", "OPSEC connection successful", map[string]interface{}{
		"protocol": "tcp",
		"opsec_enabled": true,
	})

	// Get audit trail and verify no sensitive data
	auditTrail := logger.GetAuditTrail()
	if len(auditTrail) == 0 {
		t.Error("Audit trail should contain connection event")
	}

	// Verify connection health with OPSEC metrics
	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)
	instanceA.healthMonitor.UpdateHealth(connectionID, connectionTime, true)
	
	health := instanceA.healthMonitor.GetHealth(connectionID)
	if health == nil {
		t.Error("Health monitoring should be active")
	}

	if health.Status != "healthy" {
		t.Errorf("Connection should be healthy, got: %s", health.Status)
	}
}

// TestKeyRotationDuringDataTransfer tests key rotation while data is being transferred
func TestKeyRotationDuringDataTransfer(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish connection
	invitation, err := establishTestConnection(t, instanceA, instanceB)
	if err != nil {
		t.Fatalf("Failed to establish test connection: %v", err)
	}

	// Get active connections
	connectionsA := instanceA.dcm.GetActiveConnections()
	connectionsB := instanceB.dcm.GetActiveConnections()

	if len(connectionsA) == 0 || len(connectionsB) == 0 {
		t.Fatal("No active connections found")
	}

	// Start continuous data transfer in background
	transferDone := make(chan bool)
	transferErrors := make(chan error, 10)

	go func() {
		defer close(transferDone)
		
		for i := 0; i < 100; i++ {
			testData := []byte(fmt.Sprintf("Data packet %d during key rotation test", i))
			
			err := connectionsA[0].SendData(testData)
			if err != nil {
				transferErrors <- fmt.Errorf("send error at packet %d: %v", i, err)
				return
			}

			receivedData, err := connectionsB[0].ReceiveData()
			if err != nil {
				transferErrors <- fmt.Errorf("receive error at packet %d: %v", i, err)
				return
			}

			if !bytes.Equal(testData, receivedData) {
				transferErrors <- fmt.Errorf("data mismatch at packet %d", i)
				return
			}

			time.Sleep(10 * time.Millisecond) // Small delay between packets
		}
	}()

	// Trigger key rotation during data transfer
	time.Sleep(200 * time.Millisecond) // Let some data transfer first

	// Simulate key rotation (this would normally be triggered by the key exchange component)
	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)
	
	// Create new key exchange instances to simulate rotation
	keyExchangeA, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange A: %v", err)
	}
	defer keyExchangeA.SecureWipe()

	keyExchangeB, err := NewPostQuantumKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create key exchange B: %v", err)
	}
	defer keyExchangeB.SecureWipe()

	// Perform key rotation handshake
	rotationMessage, err := keyExchangeA.InitiateKeyRotation()
	if err != nil {
		t.Fatalf("Failed to initiate key rotation: %v", err)
	}

	rotationResponse, err := keyExchangeB.ProcessKeyExchangeMessage(rotationMessage)
	if err != nil {
		t.Fatalf("Failed to process rotation message: %v", err)
	}

	_, err = keyExchangeA.ProcessKeyExchangeMessage(rotationResponse)
	if err != nil {
		t.Fatalf("Failed to complete key rotation: %v", err)
	}

	// Wait for data transfer to complete
	select {
	case <-transferDone:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("Data transfer timed out during key rotation")
	}

	// Check for transfer errors
	close(transferErrors)
	for err := range transferErrors {
		t.Error(err)
	}

	// Verify connections are still healthy after key rotation
	healthA := instanceA.healthMonitor.GetHealth(connectionID)
	healthB := instanceB.healthMonitor.GetHealth(connectionID)

	if healthA == nil || healthA.Status != "healthy" {
		t.Error("Instance A connection should remain healthy after key rotation")
	}

	if healthB == nil || healthB.Status != "healthy" {
		t.Error("Instance B connection should remain healthy after key rotation")
	}
}

// TestSecureConfigWithAllComponents tests configuration integration
func TestSecureConfigWithAllComponents(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("integration-test-password-123")

	// Create secure config manager
	configManager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create secure config manager: %v", err)
	}

	// Create comprehensive connection profile
	profile := &ConnectionProfile{
		Name:        "integration-test-profile",
		Description: "Full integration test connection profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:8080",
			BackupAddresses: []string{"127.0.0.1:8081", "127.0.0.1:8082"},
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: make([]byte, 32),
			Salt:          make([]byte, 16),
			Nonce:         make([]byte, 12),
		},
		OPSECSettings: &OPSECSettings{
			EnableTrafficObfuscation: true,
			EnableTimingObfuscation:  true,
			ConnectionDelayMin:       100 * time.Millisecond,
			ConnectionDelayMax:       2 * time.Second,
			RetryDelayBase:          1 * time.Second,
			RetryDelayMax:           30 * time.Second,
		},
		CreatedAt: time.Now(),
		UseCount:  0,
	}

	// Fill crypto material with random data
	rand.Read(profile.CryptoMaterial.EncryptedData)
	rand.Read(profile.CryptoMaterial.Salt)
	rand.Read(profile.CryptoMaterial.Nonce)

	// Save profile
	err = configManager.SaveProfile(profile)
	if err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Load profile and verify all components
	loadedProfile, err := configManager.LoadProfile("integration-test-profile")
	if err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	// Verify all profile components
	if loadedProfile.Name != profile.Name {
		t.Errorf("Profile name mismatch: expected %s, got %s", profile.Name, loadedProfile.Name)
	}

	if loadedProfile.NetworkConfig.Protocol != profile.NetworkConfig.Protocol {
		t.Errorf("Protocol mismatch: expected %s, got %s", profile.NetworkConfig.Protocol, loadedProfile.NetworkConfig.Protocol)
	}

	if len(loadedProfile.NetworkConfig.BackupAddresses) != len(profile.NetworkConfig.BackupAddresses) {
		t.Errorf("Backup addresses count mismatch")
	}

	if !bytes.Equal(loadedProfile.CryptoMaterial.EncryptedData, profile.CryptoMaterial.EncryptedData) {
		t.Error("Crypto material mismatch")
	}

	if loadedProfile.OPSECSettings.EnableTrafficObfuscation != profile.OPSECSettings.EnableTrafficObfuscation {
		t.Error("OPSEC settings mismatch")
	}

	// Test connection establishment using saved profile
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Use profile configuration for connection
	invitationConfig := &InvitationConfig{
		Protocol:        loadedProfile.NetworkConfig.Protocol,
		ListenerAddress: "127.0.0.1:0", // Use any available port for testing
		BackupAddresses: loadedProfile.NetworkConfig.BackupAddresses,
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := instanceA.dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate invitation from profile: %v", err)
	}

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: loadedProfile.NetworkConfig.Protocol,
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener from profile: %v", err)
	}

	// Connect using profile configuration
	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect using profile: %v", err)
	}

	// Verify connection establishment
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 10*time.Second) {
		t.Fatal("Connection establishment failed with saved profile")
	}

	// Update profile usage statistics
	loadedProfile.UseCount++
	loadedProfile.LastUsed = time.Now()

	err = configManager.SaveProfile(loadedProfile)
	if err != nil {
		t.Fatalf("Failed to update profile usage: %v", err)
	}

	// Verify statistics update
	updatedProfile, err := configManager.LoadProfile("integration-test-profile")
	if err != nil {
		t.Fatalf("Failed to load updated profile: %v", err)
	}

	if updatedProfile.UseCount != 2 { // Should be 2 (1 from load + 1 from update)
		t.Errorf("Expected use count 2, got %d", updatedProfile.UseCount)
	}

	// Test profile backup and restore
	backupPassword := []byte("backup-password-456")
	backup, err := configManager.CreateBackup(backupPassword, true)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Create new config manager for restore test
	tempDir2 := t.TempDir()
	configManager2, err := NewSecureConfigManager(password, tempDir2)
	if err != nil {
		t.Fatalf("Failed to create second config manager: %v", err)
	}

	// Restore from backup
	err = configManager2.RestoreFromBackup(backup, backupPassword, false)
	if err != nil {
		t.Fatalf("Failed to restore from backup: %v", err)
	}

	// Verify restored profile
	restoredProfile, err := configManager2.LoadProfile("integration-test-profile")
	if err != nil {
		t.Fatalf("Failed to load restored profile: %v", err)
	}

	if restoredProfile.Name != profile.Name {
		t.Error("Restored profile name mismatch")
	}

	if !bytes.Equal(restoredProfile.CryptoMaterial.EncryptedData, profile.CryptoMaterial.EncryptedData) {
		t.Error("Restored crypto material mismatch")
	}
}

// TestNetworkFailureRecovery tests recovery from various network failures
func TestNetworkFailureRecovery(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish initial connection
	invitation, err := establishTestConnection(t, instanceA, instanceB)
	if err != nil {
		t.Fatalf("Failed to establish initial connection: %v", err)
	}

	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)

	// Test 1: Simulate temporary network interruption
	t.Run("TemporaryNetworkInterruption", func(t *testing.T) {
		// Get initial connection health
		initialHealth := instanceA.healthMonitor.GetHealth(connectionID)
		if initialHealth == nil {
			t.Fatal("Initial health should not be nil")
		}

		// Simulate network failure by updating health with failures
		for i := 0; i < 3; i++ {
			instanceA.healthMonitor.UpdateHealth(connectionID, 5*time.Second, false)
		}

		// Check that connection is marked as degraded
		degradedHealth := instanceA.healthMonitor.GetHealth(connectionID)
		if degradedHealth.Status != "degraded" {
			t.Errorf("Connection should be degraded after failures, got: %s", degradedHealth.Status)
		}

		// Simulate recovery
		for i := 0; i < 5; i++ {
			instanceA.healthMonitor.UpdateHealth(connectionID, 100*time.Millisecond, true)
		}

		// Check that connection recovers
		recoveredHealth := instanceA.healthMonitor.GetHealth(connectionID)
		if recoveredHealth.Status != "healthy" {
			t.Errorf("Connection should recover to healthy, got: %s", recoveredHealth.Status)
		}
	})

	// Test 2: Test retry logic with OPSEC compliance
	t.Run("RetryLogicWithOPSEC", func(t *testing.T) {
		retryManager := NewRetryManager()
		remoteAddr := "127.0.0.1:8080"

		// Simulate multiple connection failures
		networkErr := NewNetworkError(ErrCodeConnectionTimeout, "Connection timeout", "test", true)

		for attempt := 1; attempt <= 3; attempt++ {
			decision, err := retryManager.ShouldRetryConnection(connectionID, attempt, networkErr, remoteAddr)
			if err != nil {
				t.Fatalf("Retry decision failed: %v", err)
			}

			if !decision.ShouldRetry && attempt < 3 {
				t.Errorf("Should retry on attempt %d", attempt)
			}

			if decision.Delay <= 0 {
				t.Errorf("Retry delay should be positive on attempt %d", attempt)
			}

			// Verify exponential backoff
			if attempt > 1 {
				prevDecision, _ := retryManager.ShouldRetryConnection(connectionID, attempt-1, networkErr, remoteAddr)
				if decision.Delay <= prevDecision.Delay {
					t.Errorf("Retry delay should increase with attempts")
				}
			}

			// Verify OPSEC compliance (risk level assessment)
			expectedRisk := "low"
			if attempt >= 3 {
				expectedRisk = "medium"
			}
			if attempt >= 5 {
				expectedRisk = "high"
			}

			if decision.RiskLevel != expectedRisk {
				t.Errorf("Expected risk level %s on attempt %d, got %s", expectedRisk, attempt, decision.RiskLevel)
			}
		}
	})

	// Test 3: Test graceful degradation
	t.Run("GracefulDegradation", func(t *testing.T) {
		// Simulate high error rate
		for i := 0; i < 10; i++ {
			instanceA.healthMonitor.UpdateHealth(connectionID, 2*time.Second, false)
		}

		health := instanceA.healthMonitor.GetHealth(connectionID)
		if health == nil {
			t.Fatal("Health should not be nil")
		}

		// Connection should be marked as unhealthy due to high error rate
		if health.Status == "healthy" {
			t.Error("Connection should not be healthy with high error rate")
		}

		// Verify error rate calculation
		if health.ErrorCount == 0 {
			t.Error("Error count should be greater than 0")
		}

		// Test recovery after errors stop
		for i := 0; i < 15; i++ {
			instanceA.healthMonitor.UpdateHealth(connectionID, 50*time.Millisecond, true)
		}

		recoveredHealth := instanceA.healthMonitor.GetHealth(connectionID)
		if recoveredHealth.Status != "healthy" {
			t.Errorf("Connection should recover to healthy, got: %s", recoveredHealth.Status)
		}
	})
}

// TestHighThroughputDataTransfer tests performance under high data load
func TestHighThroughputDataTransfer(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish connection
	invitation, err := establishTestConnection(t, instanceA, instanceB)
	if err != nil {
		t.Fatalf("Failed to establish test connection: %v", err)
	}

	// Get active connections
	connectionsA := instanceA.dcm.GetActiveConnections()
	connectionsB := instanceB.dcm.GetActiveConnections()

	if len(connectionsA) == 0 || len(connectionsB) == 0 {
		t.Fatal("No active connections found")
	}

	// Test high throughput data transfer
	dataSize := 1024 * 1024 // 1MB
	testData := make([]byte, dataSize)
	rand.Read(testData)

	startTime := time.Now()

	// Send large data
	err = connectionsA[0].SendData(testData)
	if err != nil {
		t.Fatalf("Failed to send large data: %v", err)
	}

	// Receive large data
	receivedData, err := connectionsB[0].ReceiveData()
	if err != nil {
		t.Fatalf("Failed to receive large data: %v", err)
	}

	transferTime := time.Since(startTime)

	// Verify data integrity
	if !bytes.Equal(testData, receivedData) {
		t.Error("Large data transfer integrity check failed")
	}

	// Calculate throughput
	throughputMbps := float64(dataSize*8) / (transferTime.Seconds() * 1000000)
	t.Logf("Throughput: %.2f Mbps for %d bytes in %v", throughputMbps, dataSize, transferTime)

	// Verify reasonable performance (should be at least 1 Mbps for local connection)
	if throughputMbps < 1.0 {
		t.Errorf("Throughput too low: %.2f Mbps", throughputMbps)
	}

	// Test connection health monitoring under load
	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)
	health := instanceA.healthMonitor.GetHealth(connectionID)

	if health == nil {
		t.Error("Health monitoring should be active during high throughput")
	}

	if health.Status != "healthy" {
		t.Errorf("Connection should remain healthy during high throughput, got: %s", health.Status)
	}

	// Verify metrics collection
	if connectionsA[0].GetMetrics() == nil {
		t.Error("Connection metrics should be available")
	}

	metrics := connectionsA[0].GetMetrics()
	if metrics.BytesSent == 0 {
		t.Error("Bytes sent metric should be greater than 0")
	}

	if metrics.PacketsSent == 0 {
		t.Error("Packets sent metric should be greater than 0")
	}
}

// TestSOCKSProxyIntegration tests integration with SOCKS proxy functionality
func TestSOCKSProxyIntegration(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish direct connection
	invitation, err := establishTestConnection(t, instanceA, instanceB)
	if err != nil {
		t.Fatalf("Failed to establish test connection: %v", err)
	}

	// Get active connections
	connectionsA := instanceA.dcm.GetActiveConnections()
	connectionsB := instanceB.dcm.GetActiveConnections()

	if len(connectionsA) == 0 || len(connectionsB) == 0 {
		t.Fatal("No active connections found")
	}

	// Test tunnel multiplexing (simulating SOCKS proxy channels)
	directTunnelA, ok := connectionsA[0].(*DirectTunnel)
	if !ok {
		t.Fatal("Connection should be DirectTunnel type")
	}

	// Create multiple channels to simulate different SOCKS connections
	channels := make([]MultiplexChannel, 3)
	for i := 0; i < 3; i++ {
		channel, err := directTunnelA.CreateMultiplexChannel()
		if err != nil {
			t.Fatalf("Failed to create multiplex channel %d: %v", i, err)
		}
		channels[i] = channel
	}

	// Test data transfer on each channel
	for i, channel := range channels {
		testData := []byte(fmt.Sprintf("SOCKS proxy test data for channel %d", i))
		
		err := channel.SendData(testData)
		if err != nil {
			t.Errorf("Failed to send data on channel %d: %v", i, err)
		}

		// Verify channel is active
		if !channel.IsActive() {
			t.Errorf("Channel %d should be active", i)
		}

		// Get channel statistics
		stats := channel.GetStats()
		if stats == nil {
			t.Errorf("Channel %d should have statistics", i)
		}

		if stats.ChannelID != channel.GetChannelID() {
			t.Errorf("Channel %d statistics ID mismatch", i)
		}
	}

	// List all channels
	allChannels := directTunnelA.ListMultiplexChannels()
	if len(allChannels) != 3 {
		t.Errorf("Expected 3 channels, got %d", len(allChannels))
	}

	// Test channel cleanup
	for i, channel := range channels {
		err := channel.Close()
		if err != nil {
			t.Errorf("Failed to close channel %d: %v", i, err)
		}

		if channel.IsActive() {
			t.Errorf("Channel %d should be inactive after close", i)
		}
	}

	// Verify channels are cleaned up
	remainingChannels := directTunnelA.ListMultiplexChannels()
	if len(remainingChannels) != 0 {
		t.Errorf("Expected 0 channels after cleanup, got %d", len(remainingChannels))
	}
}

// TestConfigurationPersistenceAcrossRestart tests configuration persistence
func TestConfigurationPersistenceAcrossRestart(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("persistence-test-password")

	// Phase 1: Create and save configuration
	configManager1, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create first config manager: %v", err)
	}

	// Create multiple profiles
	profiles := []*ConnectionProfile{
		{
			Name:        "persistent-profile-1",
			Description: "First persistent profile",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "127.0.0.1:8080",
			},
			UseCount:  5,
			CreatedAt: time.Now().Add(-24 * time.Hour),
			LastUsed:  time.Now().Add(-1 * time.Hour),
		},
		{
			Name:        "persistent-profile-2",
			Description: "Second persistent profile",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "127.0.0.1:8081",
			},
			UseCount:  10,
			CreatedAt: time.Now().Add(-48 * time.Hour),
			LastUsed:  time.Now().Add(-30 * time.Minute),
		},
	}

	for _, profile := range profiles {
		err := configManager1.SaveProfile(profile)
		if err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Get statistics before "restart"
	statsBefore, err := configManager1.GetProfileStatistics()
	if err != nil {
		t.Fatalf("Failed to get statistics before restart: %v", err)
	}

	// Phase 2: Simulate application restart by creating new config manager
	configManager2, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create second config manager: %v", err)
	}

	// Verify all profiles are still available
	profileList := configManager2.ListProfiles()
	if len(profileList) != len(profiles) {
		t.Errorf("Expected %d profiles after restart, got %d", len(profiles), len(profileList))
	}

	// Verify each profile can be loaded and has correct data
	for _, originalProfile := range profiles {
		loadedProfile, err := configManager2.LoadProfile(originalProfile.Name)
		if err != nil {
			t.Errorf("Failed to load profile %s after restart: %v", originalProfile.Name, err)
			continue
		}

		if loadedProfile.Description != originalProfile.Description {
			t.Errorf("Profile %s description mismatch after restart", originalProfile.Name)
		}

		if loadedProfile.NetworkConfig.Protocol != originalProfile.NetworkConfig.Protocol {
			t.Errorf("Profile %s protocol mismatch after restart", originalProfile.Name)
		}

		// Use count should be incremented due to loading
		if loadedProfile.UseCount != originalProfile.UseCount+1 {
			t.Errorf("Profile %s use count mismatch after restart: expected %d, got %d", 
				originalProfile.Name, originalProfile.UseCount+1, loadedProfile.UseCount)
		}
	}

	// Verify statistics are consistent
	statsAfter, err := configManager2.GetProfileStatistics()
	if err != nil {
		t.Fatalf("Failed to get statistics after restart: %v", err)
	}

	if statsAfter.TotalProfiles != statsBefore.TotalProfiles {
		t.Errorf("Total profiles mismatch after restart: expected %d, got %d", 
			statsBefore.TotalProfiles, statsAfter.TotalProfiles)
	}

	// Test integrity verification after restart
	err = configManager2.VerifyIntegrity()
	if err != nil {
		t.Errorf("Integrity verification failed after restart: %v", err)
	}

	// Test that new connections can be established using persisted profiles
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Use first persisted profile for connection
	persistedProfile, err := configManager2.LoadProfile("persistent-profile-1")
	if err != nil {
		t.Fatalf("Failed to load persisted profile for connection test: %v", err)
	}

	// Establish connection using persisted configuration
	invitationConfig := &InvitationConfig{
		Protocol:        persistedProfile.NetworkConfig.Protocol,
		ListenerAddress: "127.0.0.1:0", // Use any available port
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := instanceA.dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		t.Fatalf("Failed to generate invitation with persisted config: %v", err)
	}

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: persistedProfile.NetworkConfig.Protocol,
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener with persisted config: %v", err)
	}

	// Connect
	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect with persisted config: %v", err)
	}

	// Verify connection establishment
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 10*time.Second) {
		t.Fatal("Connection establishment failed with persisted configuration")
	}

	// Update profile usage after successful connection
	persistedProfile.UseCount++
	persistedProfile.LastUsed = time.Now()

	err = configManager2.SaveProfile(persistedProfile)
	if err != nil {
		t.Errorf("Failed to update profile after connection: %v", err)
	}
}

// Helper Functions

// TestInstance represents a test instance with all components
type TestInstance struct {
	dcm            DirectConnectionManager
	healthMonitor  *ConnectionHealthMonitor
	configManager  SecureConfigManager
	opsecLayer     *OPSECNetworkLayer
	cleanup        func()
}

// setupTwoInstanceTest creates two test instances for integration testing
func setupTwoInstanceTest(t *testing.T) (*TestInstance, *TestInstance, func()) {
	// Create temporary directories for each instance
	tempDirA := t.TempDir()
	tempDirB := t.TempDir()

	// Create instance A
	instanceA := createTestInstance(t, tempDirA, "instance-A")
	instanceB := createTestInstance(t, tempDirB, "instance-B")

	cleanup := func() {
		if instanceA.cleanup != nil {
			instanceA.cleanup()
		}
		if instanceB.cleanup != nil {
			instanceB.cleanup()
		}
	}

	return instanceA, instanceB, cleanup
}

// setupMultiInstanceTest creates one listener and multiple connector instances
func setupMultiInstanceTest(t *testing.T, numConnectors int) (*TestInstance, []*TestInstance, func()) {
	// Create listener instance
	listenerDir := t.TempDir()
	listener := createTestInstance(t, listenerDir, "listener")

	// Create connector instances
	connectors := make([]*TestInstance, numConnectors)
	for i := 0; i < numConnectors; i++ {
		connectorDir := t.TempDir()
		connectors[i] = createTestInstance(t, connectorDir, fmt.Sprintf("connector-%d", i))
	}

	cleanup := func() {
		if listener.cleanup != nil {
			listener.cleanup()
		}
		for _, connector := range connectors {
			if connector.cleanup != nil {
				connector.cleanup()
			}
		}
	}

	return listener, connectors, cleanup
}

// createTestInstance creates a single test instance with all components
func createTestInstance(t *testing.T, tempDir, instanceName string) *TestInstance {
	// Create DirectConnectionManager
	config := &DirectConfig{
		ListenerPort:      0, // Use any available port
		Protocol:          "tcp",
		MaxConnections:    10,
		KeepAliveInterval: 30 * time.Second,
		ConnectionTimeout: 60 * time.Second,
		EnableOPSEC:       true,
	}

	dcm := NewDirectConnectionManager(config)

	// Create health monitor
	healthMonitor := NewConnectionHealthMonitor()

	// Create secure config manager
	password := []byte(fmt.Sprintf("%s-password-123", instanceName))
	configManager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager for %s: %v", instanceName, err)
	}

	// Create OPSEC layer
	opsecConfig := &TrafficObfuscationConfig{
		EnablePadding:      true,
		PaddingMinSize:     16,
		PaddingMaxSize:     128,
		NoiseInjectionRate: 0.05,
		EnableSharding:     true,
		MaxShardSize:       1024,
		MinShardSize:       64,
	}
	opsecLayer := NewOPSECNetworkLayerWithConfig(opsecConfig)

	cleanup := func() {
		if dcm != nil {
			dcm.(*DirectConnectionManagerImpl).Shutdown()
		}
	}

	return &TestInstance{
		dcm:           dcm,
		healthMonitor: healthMonitor,
		configManager: configManager,
		opsecLayer:    opsecLayer,
		cleanup:       cleanup,
	}
}

// establishTestConnection establishes a connection between two instances
func establishTestConnection(t *testing.T, instanceA, instanceB *TestInstance) (*InvitationCode, error) {
	// Generate invitation
	invitationConfig := &InvitationConfig{
		Protocol:        "tcp",
		ListenerAddress: "127.0.0.1:0",
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	}

	invitation, err := instanceA.dcm.GenerateInvitation(invitationConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invitation: %v", err)
	}

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: "tcp",
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to start listener: %v", err)
	}

	// Connect
	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer: %v", err)
	}

	// Wait for connection establishment
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 10*time.Second) {
		return nil, fmt.Errorf("connection establishment timed out")
	}

	return invitation, nil
}

// waitForConnectionEstablishment waits for connections to be established
func waitForConnectionEstablishment(t *testing.T, dcmA, dcmB DirectConnectionManager, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		connectionsA := dcmA.GetActiveConnections()
		connectionsB := dcmB.GetActiveConnections()
		
		if len(connectionsA) > 0 && len(connectionsB) > 0 {
			return true
		}
		
		time.Sleep(100 * time.Millisecond)
	}
	
	return false
}

// verifySecureDataTransfer verifies data can be transferred securely between connections
func verifySecureDataTransfer(t *testing.T, connA, connB DirectConnection, testData []byte) bool {
	// Send data from A to B
	err := connA.SendData(testData)
	if err != nil {
		t.Errorf("Failed to send data from A to B: %v", err)
		return false
	}

	// Receive data on B
	receivedData, err := connB.ReceiveData()
	if err != nil {
		t.Errorf("Failed to receive data on B: %v", err)
		return false
	}

	// Verify data integrity
	if !bytes.Equal(testData, receivedData) {
		t.Error("Data integrity check failed")
		return false
	}

	// Send data from B to A (bidirectional test)
	reverseData := []byte("Reverse direction test data")
	err = connB.SendData(reverseData)
	if err != nil {
		t.Errorf("Failed to send reverse data from B to A: %v", err)
		return false
	}

	// Receive reverse data on A
	receivedReverseData, err := connA.ReceiveData()
	if err != nil {
		t.Errorf("Failed to receive reverse data on A: %v", err)
		return false
	}

	// Verify reverse data integrity
	if !bytes.Equal(reverseData, receivedReverseData) {
		t.Error("Reverse data integrity check failed")
		return false
	}

	return true
}

// extractPortFromAddress extracts port number from address string
func extractPortFromAddress(address string) int {
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// Benchmark tests for performance validation

func BenchmarkCompleteConnectionFlow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		instanceA, instanceB, cleanup := setupTwoInstanceTest(&testing.T{})
		
		// Measure connection establishment time
		start := time.Now()
		
		invitation, err := establishTestConnection(&testing.T{}, instanceA, instanceB)
		if err != nil {
			b.Fatalf("Failed to establish connection: %v", err)
		}
		
		connectionTime := time.Since(start)
		b.ReportMetric(float64(connectionTime.Nanoseconds()), "ns/connection")
		
		// Test data transfer performance
		connections := instanceA.dcm.GetActiveConnections()
		if len(connections) > 0 {
			testData := make([]byte, 1024) // 1KB test data
			rand.Read(testData)
			
			start = time.Now()
			err = connections[0].SendData(testData)
			if err == nil {
				_, err = instanceB.dcm.GetActiveConnections()[0].ReceiveData()
			}
			transferTime := time.Since(start)
			
			if err == nil {
				b.ReportMetric(float64(len(testData))/transferTime.Seconds(), "bytes/sec")
			}
		}
		
		cleanup()
	}
}

func BenchmarkMultipleConnections(b *testing.B) {
	numConnections := []int{1, 5, 10, 20}
	
	for _, n := range numConnections {
		b.Run(fmt.Sprintf("connections-%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				listener, connectors, cleanup := setupMultiInstanceTest(&testing.T{}, n)
				
				start := time.Now()
				
				// Establish all connections
				var wg sync.WaitGroup
				for _, connector := range connectors {
					wg.Add(1)
					go func(conn *TestInstance) {
						defer wg.Done()
						establishTestConnection(&testing.T{}, listener, conn)
					}(connector)
				}
				wg.Wait()
				
				establishmentTime := time.Since(start)
				b.ReportMetric(float64(establishmentTime.Nanoseconds())/float64(n), "ns/connection")
				
				cleanup()
			}
		})
	}
}
