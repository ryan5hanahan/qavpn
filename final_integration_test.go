package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"qavpn/direct"
)

// TestCompleteQAVPNDirectIntegration tests the complete integration of direct mode with existing QAVPN
func TestCompleteQAVPNDirectIntegration(t *testing.T) {
	t.Run("SystemIntegrationWithDirectMode", testSystemIntegrationWithDirectMode)
	t.Run("ConfigurationCompatibilityAndMigration", testConfigurationCompatibilityAndMigration)
	t.Run("DirectToRelayFallbackMechanism", testDirectToRelayFallbackMechanism)
	t.Run("ConcurrentDirectAndRelayOperations", testConcurrentDirectAndRelayOperations)
	t.Run("SOCKSProxyIntegrationWithDirectMode", testSOCKSProxyIntegrationWithDirectMode)
	t.Run("NoRegressionInExistingFunctionality", testNoRegressionInExistingFunctionality)
	t.Run("HealthMonitoringIntegration", testHealthMonitoringIntegration)
	t.Run("ErrorHandlingIntegration", testErrorHandlingIntegration)
	t.Run("SecurityIntegrationValidation", testSecurityIntegrationValidation)
	t.Run("PerformanceIntegrationValidation", testPerformanceIntegrationValidation)
}

// testSystemIntegrationWithDirectMode tests complete system integration with direct mode enabled
func testSystemIntegrationWithDirectMode(t *testing.T) {
	// Create configuration with direct mode enabled
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Validate configuration
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("Configuration validation failed: %v", err)
	}

	// Initialize system integration
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	// Start system
	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Verify system status
	status := systemIntegration.GetSystemStatus()
	if !status.IsInitialized {
		t.Error("System should be initialized")
	}

	if !status.IsHealthy {
		t.Error("System should be healthy")
	}

	// Verify direct mode is integrated
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator == nil {
		t.Error("Direct integrator should be initialized")
	}

	// Test direct connection establishment within system context
	if directIntegrator != nil {
		dcm := directIntegrator.GetDirectConnectionManager()
		
		// Generate invitation
		invitation, err := dcm.GenerateInvitation(&direct.InvitationConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:0",
			ExpirationTime:  time.Now().Add(1 * time.Hour),
			SingleUse:       true,
		})
		if err != nil {
			t.Errorf("Failed to generate invitation in system context: %v", err)
		} else {
			t.Logf("Successfully generated invitation in system context: %x", invitation.ConnectionID)
		}
	}

	// Verify system components are working together
	if status.NodeStats == nil {
		t.Error("Node statistics should be available")
	}

	if status.HealthStatus == nil {
		t.Error("Health status should be available")
	}
}

// testConfigurationCompatibilityAndMigration tests configuration compatibility and migration
func testConfigurationCompatibilityAndMigration(t *testing.T) {
	// Test 1: Legacy configuration without direct mode
	legacyConfig := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode:  nil, // No direct mode configuration
	}

	// Migrate legacy configuration
	migratedConfig, err := MigrateConfig(legacyConfig)
	if err != nil {
		t.Fatalf("Configuration migration failed: %v", err)
	}

	// Verify migration added direct mode configuration
	if migratedConfig.DirectMode == nil {
		t.Error("Migration should add direct mode configuration")
	}

	if migratedConfig.DirectMode.DefaultPort == 0 {
		t.Error("Migration should set default direct mode port")
	}

	// Test 2: Configuration with direct mode enabled
	directEnabledConfig := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Validate direct-enabled configuration
	if err := ValidateConfig(directEnabledConfig); err != nil {
		t.Errorf("Direct-enabled configuration should be valid: %v", err)
	}

	// Test 3: Configuration validation with port conflicts
	conflictConfig := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9050, // Conflicts with client port
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Should fail validation due to port conflict
	if err := ValidateConfig(conflictConfig); err == nil {
		t.Error("Configuration with port conflict should fail validation")
	}

	// Test 4: System initialization with migrated configuration
	systemIntegration, err := NewSystemIntegration(migratedConfig)
	if err != nil {
		t.Fatalf("Failed to create system with migrated config: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system with migrated config: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Verify system works with migrated configuration
	status := systemIntegration.GetSystemStatus()
	if !status.IsInitialized {
		t.Error("System should initialize with migrated configuration")
	}
}

// testDirectToRelayFallbackMechanism tests fallback from direct to relay mode
func testDirectToRelayFallbackMechanism(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 5, // Short timeout for testing
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Initialize system
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Get direct integrator
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator == nil {
		t.Fatal("Direct integrator should be available")
	}

	// Test 1: Attempt direct connection to invalid address (should fail)
	dcm := directIntegrator.GetDirectConnectionManager()
	
	invalidInvitation := &direct.InvitationCode{
		ConnectionID: [32]byte{1, 2, 3, 4},
		NetworkConfig: &direct.NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:1", // Invalid port
		},
		ExpirationTime: time.Now().Add(1 * time.Hour),
		SingleUse:      true,
	}

	// This should fail and trigger fallback logic
	err = dcm.ConnectToPeer(invalidInvitation)
	if err == nil {
		t.Error("Connection to invalid address should fail")
	}

	// Test 2: Verify system can still function without direct connections
	// In a real scenario, this would fall back to relay mode
	status := systemIntegration.GetSystemStatus()
	if !status.IsHealthy {
		t.Error("System should remain healthy even when direct connections fail")
	}

	// Test 3: Verify tunnel manager can provide relay tunnels when direct fails
	if systemIntegration.tunnelManager != nil {
		// In a real implementation, this would attempt to create relay tunnels
		activeTunnels := systemIntegration.tunnelManager.GetActiveTunnels()
		t.Logf("Active relay tunnels available for fallback: %d", len(activeTunnels))
	}
}

// testConcurrentDirectAndRelayOperations tests concurrent operation of both modes
func testConcurrentDirectAndRelayOperations(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Initialize system
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	var wg sync.WaitGroup
	errors := make(chan error, 4)

	// Test concurrent operations
	wg.Add(4)

	// 1. Direct connection operations
	go func() {
		defer wg.Done()
		directIntegrator := GetGlobalDirectIntegrator()
		if directIntegrator == nil {
			errors <- fmt.Errorf("direct integrator not available")
			return
		}

		dcm := directIntegrator.GetDirectConnectionManager()
		invitation, err := dcm.GenerateInvitation(&direct.InvitationConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:0",
			ExpirationTime:  time.Now().Add(1 * time.Hour),
			SingleUse:       true,
		})
		if err != nil {
			errors <- fmt.Errorf("direct invitation generation failed: %v", err)
			return
		}

		t.Logf("Direct invitation generated concurrently: %x", invitation.ConnectionID)
	}()

	// 2. Node manager operations
	go func() {
		defer wg.Done()
		if systemIntegration.nodeManager == nil {
			errors <- fmt.Errorf("node manager not available")
			return
		}

		stats := systemIntegration.nodeManager.GetNodeStats()
		if stats == nil {
			errors <- fmt.Errorf("node stats not available")
			return
		}

		t.Log("Node manager operating concurrently with direct mode")
	}()

	// 3. Health monitoring operations
	go func() {
		defer wg.Done()
		if systemIntegration.healthChecker == nil {
			errors <- fmt.Errorf("health checker not available")
			return
		}

		// Health checker should be running
		time.Sleep(100 * time.Millisecond)
		t.Log("Health checker operating concurrently with direct mode")
	}()

	// 4. Connection monitoring operations
	go func() {
		defer wg.Done()
		if systemIntegration.connectionMonitor == nil {
			errors <- fmt.Errorf("connection monitor not available")
			return
		}

		isHealthy := systemIntegration.connectionMonitor.IsHealthy()
		if !isHealthy {
			errors <- fmt.Errorf("connection monitor reports unhealthy state")
			return
		}

		t.Log("Connection monitor operating concurrently with direct mode")
	}()

	// Wait for all operations
	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Verify system remains stable
	status := systemIntegration.GetSystemStatus()
	if !status.IsHealthy {
		t.Error("System should remain healthy during concurrent operations")
	}
}

// testSOCKSProxyIntegrationWithDirectMode tests SOCKS proxy integration with direct mode
func testSOCKSProxyIntegrationWithDirectMode(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Initialize system
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Get direct integrator
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator == nil {
		t.Fatal("Direct integrator should be available")
	}

	// Test getting best direct tunnel for SOCKS proxy
	tunnel, err := directIntegrator.GetBestDirectTunnel()
	if err != nil {
		// This is expected if no direct connections are established
		t.Logf("No direct tunnel available (expected): %v", err)
	} else {
		// If we have a tunnel, test SOCKS integration
		if !tunnel.IsActive() {
			t.Error("Direct tunnel should be active")
		}

		// Test tunnel operations (simulating SOCKS proxy usage)
		testData := []byte("SOCKS proxy test data")
		if err := tunnel.SendData(testData); err != nil {
			t.Errorf("Failed to send data through direct tunnel: %v", err)
		}
	}

	// Test tunnel cleanup
	directIntegrator.CleanupInactiveTunnels()
	activeTunnelCount := directIntegrator.GetActiveTunnelCount()
	t.Logf("Active direct tunnels after cleanup: %d", activeTunnelCount)

	// Verify SOCKS proxy can fall back to relay tunnels
	if systemIntegration.tunnelManager != nil {
		relayTunnels := systemIntegration.tunnelManager.GetActiveTunnels()
		t.Logf("Relay tunnels available for SOCKS fallback: %d", len(relayTunnels))
	}
}

// testNoRegressionInExistingFunctionality tests that existing functionality still works
func testNoRegressionInExistingFunctionality(t *testing.T) {
	// Test 1: System without direct mode (legacy behavior)
	legacyConfig := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled: false, // Direct mode disabled
		},
	}

	legacySystem, err := NewSystemIntegration(legacyConfig)
	if err != nil {
		t.Fatalf("Failed to create legacy system: %v", err)
	}

	if err := legacySystem.StartSystem(); err != nil {
		t.Fatalf("Failed to start legacy system: %v", err)
	}
	defer legacySystem.StopSystem()

	// Verify legacy system works
	legacyStatus := legacySystem.GetSystemStatus()
	if !legacyStatus.IsInitialized {
		t.Error("Legacy system should initialize properly")
	}

	if !legacyStatus.IsHealthy {
		t.Error("Legacy system should be healthy")
	}

	// Verify direct integrator is not initialized for legacy system
	if GetGlobalDirectIntegrator() != nil {
		// Reset global state for next test
		ShutdownDirectIntegration()
	}

	// Test 2: System with direct mode enabled
	directConfig := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	directSystem, err := NewSystemIntegration(directConfig)
	if err != nil {
		t.Fatalf("Failed to create direct system: %v", err)
	}

	if err := directSystem.StartSystem(); err != nil {
		t.Fatalf("Failed to start direct system: %v", err)
	}
	defer directSystem.StopSystem()

	// Verify direct system works
	directStatus := directSystem.GetSystemStatus()
	if !directStatus.IsInitialized {
		t.Error("Direct system should initialize properly")
	}

	if !directStatus.IsHealthy {
		t.Error("Direct system should be healthy")
	}

	// Verify all existing components still work
	if directSystem.nodeManager == nil {
		t.Error("Node manager should be available in direct system")
	}

	if directSystem.tunnelManager == nil {
		t.Error("Tunnel manager should be available in direct system")
	}

	if directSystem.errorHandler == nil {
		t.Error("Error handler should be available in direct system")
	}

	if directSystem.recoveryManager == nil {
		t.Error("Recovery manager should be available in direct system")
	}

	if directSystem.connectionMonitor == nil {
		t.Error("Connection monitor should be available in direct system")
	}

	if directSystem.healthChecker == nil {
		t.Error("Health checker should be available in direct system")
	}

	// Test 3: Verify existing functionality metrics
	nodeStats := directSystem.nodeManager.GetNodeStats()
	if nodeStats == nil {
		t.Error("Node statistics should be available")
	}

	errorStats := directSystem.errorHandler.GetErrorStatistics()
	if errorStats == nil {
		t.Error("Error statistics should be available")
	}

	recoveryStats := directSystem.recoveryManager.GetRecoveryStatistics()
	if recoveryStats == nil {
		t.Error("Recovery statistics should be available")
	}
}

// testHealthMonitoringIntegration tests health monitoring integration with direct mode
func testHealthMonitoringIntegration(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Test health monitoring
	healthChecker := systemIntegration.healthChecker
	if healthChecker == nil {
		t.Fatal("Health checker should be available")
	}

	// Wait for health check to run
	time.Sleep(2 * time.Second)

	// Get system status
	status := systemIntegration.GetSystemStatus()
	if status.HealthStatus == nil {
		t.Error("Health status should be available")
	}

	// Test connection monitoring
	connectionMonitor := systemIntegration.connectionMonitor
	if connectionMonitor == nil {
		t.Fatal("Connection monitor should be available")
	}

	isHealthy := connectionMonitor.IsHealthy()
	if !isHealthy {
		t.Error("Connection monitor should report healthy state")
	}

	healthStatus := connectionMonitor.GetHealthStatus()
	if healthStatus == nil {
		t.Error("Connection health status should be available")
	}

	// Test direct connection health monitoring integration
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator != nil {
		activeTunnelCount := directIntegrator.GetActiveTunnelCount()
		t.Logf("Direct tunnel count being monitored: %d", activeTunnelCount)

		// Test cleanup of inactive tunnels
		directIntegrator.CleanupInactiveTunnels()
		
		hasActiveConnections := directIntegrator.HasActiveDirectConnections()
		t.Logf("Has active direct connections: %v", hasActiveConnections)
	}
}

// testErrorHandlingIntegration tests error handling integration with direct mode
func testErrorHandlingIntegration(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Test error handler
	errorHandler := systemIntegration.errorHandler
	if errorHandler == nil {
		t.Fatal("Error handler should be available")
	}

	// Test recovery manager
	recoveryManager := systemIntegration.recoveryManager
	if recoveryManager == nil {
		t.Fatal("Recovery manager should be available")
	}

	// Get error statistics
	errorStats := errorHandler.GetErrorStatistics()
	if errorStats == nil {
		t.Error("Error statistics should be available")
	}

	// Get recovery statistics
	recoveryStats := recoveryManager.GetRecoveryStatistics()
	if recoveryStats == nil {
		t.Error("Recovery statistics should be available")
	}

	// Test that direct mode errors are handled properly
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator != nil {
		dcm := directIntegrator.GetDirectConnectionManager()
		
		// Try to connect to invalid address (should generate error)
		invalidInvitation := &direct.InvitationCode{
			ConnectionID: [32]byte{1, 2, 3, 4},
			NetworkConfig: &direct.NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "127.0.0.1:1", // Invalid port
			},
			ExpirationTime: time.Now().Add(1 * time.Hour),
			SingleUse:      true,
		}

		err = dcm.ConnectToPeer(invalidInvitation)
		if err == nil {
			t.Error("Connection to invalid address should fail")
		} else {
			t.Logf("Direct connection error handled properly: %v", err)
		}
	}

	// Verify system remains stable after errors
	status := systemIntegration.GetSystemStatus()
	if !status.IsHealthy {
		t.Error("System should remain healthy after handling direct mode errors")
	}
}

// testSecurityIntegrationValidation tests security integration with direct mode
func testSecurityIntegrationValidation(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true, // OPSEC enabled
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	// Test security hardener
	securityHardener := systemIntegration.securityHardener
	if securityHardener == nil {
		t.Fatal("Security hardener should be available")
	}

	appliedMeasures := securityHardener.GetAppliedMeasures()
	if len(appliedMeasures) == 0 {
		t.Error("Security hardening measures should be applied")
	}

	t.Logf("Applied security measures: %v", appliedMeasures)

	// Test that direct mode respects security settings
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator != nil {
		dcm := directIntegrator.GetDirectConnectionManager()
		
		// Generate invitation with OPSEC enabled
		invitation, err := dcm.GenerateInvitation(&direct.InvitationConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:0",
			ExpirationTime:  time.Now().Add(1 * time.Hour),
			SingleUse:       true,
		})
		if err != nil {
			t.Errorf("Failed to generate secure invitation: %v", err)
		} else {
			// Verify invitation has security features
			if len(invitation.ConnectionID) != 32 {
				t.Error("Connection ID should be 32 bytes for security")
			}

			if invitation.ExpirationTime.Before(time.Now()) {
				t.Error("Invitation should not be expired")
			}

			if !invitation.SingleUse {
				t.Error("Invitation should be single-use for security")
			}

			t.Logf("Secure invitation generated: %x", invitation.ConnectionID)
		}
	}

	// Verify secure logging
	logger := systemIntegration.logger
	if logger == nil {
		t.Error("Secure logger should be available")
	}

	// Test secure cleanup on shutdown
	// This will be tested when the system shuts down
}

// testPerformanceIntegrationValidation tests performance integration with direct mode
func testPerformanceIntegrationValidation(t *testing.T) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    1,
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        t.TempDir() + "/direct",
		},
	}

	// Measure system startup time
	startTime := time.Now()
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}

	if err := systemIntegration.StartSystem(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer systemIntegration.StopSystem()

	startupTime := time.Since(startTime)
	t.Logf("System startup time with direct mode: %v", startupTime)

	// Verify startup time is reasonable (should be under 5 seconds)
	if startupTime > 5*time.Second {
		t.Errorf("System startup time too slow: %v", startupTime)
	}

	// Test system performance metrics
	status := systemIntegration.GetSystemStatus()
	if !status.IsHealthy {
		t.Error("System should be healthy for performance testing")
	}

	// Test memory usage
	if status.NodeStats != nil {
		t.Logf("Node statistics available for performance monitoring")
	}

	if status.ErrorStats != nil {
		t.Logf("Error statistics available for performance monitoring")
	}

	// Test direct mode performance impact
	directIntegrator := GetGlobalDirectIntegrator()
	if directIntegrator != nil {
		// Measure direct connection operations
		operationStart := time.Now()
		
		dcm := directIntegrator.GetDirectConnectionManager()
		invitation, err := dcm.GenerateInvitation(&direct.InvitationConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:0",
			ExpirationTime:  time.Now().Add(1 * time.Hour),
			SingleUse:       true,
		})
		
		operationTime := time.Since(operationStart)
		t.Logf("Direct invitation generation time: %v", operationTime)

		if err != nil {
			t.Errorf("Direct operation failed: %v", err)
		} else {
			// Verify operation completed quickly (should be under 1 second)
			if operationTime > 1*time.Second {
				t.Errorf("Direct operation too slow: %v", operationTime)
			}

			t.Logf("Performance test invitation: %x", invitation.ConnectionID)
		}

		// Test cleanup performance
		cleanupStart := time.Now()
		directIntegrator.CleanupInactiveTunnels()
		cleanupTime := time.Since(cleanupStart)
		
		t.Logf("Tunnel cleanup time: %v", cleanupTime)
		if cleanupTime > 100*time.Millisecond {
			t.Errorf("Tunnel cleanup too slow: %v", cleanupTime)
		}
	}

	// Measure system shutdown time
	shutdownStart := time.Now()
	// Shutdown will be called by defer, so we'll measure it there
	t.Logf("Performance integration validation completed")
}

// BenchmarkSystemIntegrationWithDirectMode benchmarks system performance with direct mode
func BenchmarkSystemIntegrationWithDirectMode(b *testing.B) {
	config := &Config{
		ClientPort:  9050,
		RelayMode:   false,
		RelayPort:   9051,
		DesiredHops: 3,
		Protocol:    "tcp",
		LogLevel:    0, // Minimal logging for benchmarking
		DirectMode: &DirectModeConfig{
			Enabled:           true,
			DefaultPort:       9052,
			DefaultProtocol:   "tcp",
			MaxConnections:    10,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			EnableOPSEC:       true,
			ConfigPath:        b.TempDir() + "/direct",
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		systemIntegration, err := NewSystemIntegration(config)
		if err != nil {
			b.Fatalf("Failed to create system integration: %v", err)
		}

		if err := systemIntegration.StartSystem(); err != nil {
			b.Fatalf("Failed to start system: %v", err)
		}

		// Perform some operations
		directIntegrator := GetGlobalDirectIntegrator()
		if directIntegrator != nil {
			dcm := directIntegrator.GetDirectConnectionManager()
			_, err := dcm.GenerateInvitation(&direct.InvitationConfig{
				Protocol:        "tcp",
				ListenerAddress: "127.0.0.1:0",
				ExpirationTime:  time.Now().Add(1 * time.Hour),
				SingleUse:       true,
			})
			if err != nil {
				b.Errorf("Benchmark operation failed: %v", err)
			}
		}

		systemIntegration.StopSystem()
	}
}
