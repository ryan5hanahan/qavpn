package main

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestFinalSystemIntegration tests the complete integrated system
func TestFinalSystemIntegration(t *testing.T) {
	t.Run("System_Initialization", testSystemInitialization)
	t.Run("Component_Integration", testComponentIntegration)
	t.Run("Security_Hardening", testSecurityHardening)
	t.Run("Error_Handling_Integration", testErrorHandlingIntegration)
	t.Run("Health_Monitoring", testHealthMonitoring)
	t.Run("Graceful_Shutdown", testGracefulShutdown)
}

// testSystemInitialization tests system initialization
func testSystemInitialization(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	// Test client initialization
	t.Run("Client_Initialization", func(t *testing.T) {
		config.RelayMode = false
		systemIntegration, err := NewSystemIntegration(config)
		if err != nil {
			t.Fatalf("Failed to create client system integration: %v", err)
		}
		
		if !systemIntegration.isInitialized {
			t.Error("System not marked as initialized")
		}
		
		// Test system status
		status := systemIntegration.GetSystemStatus()
		if status.Version == "" {
			t.Error("System status missing version")
		}
		if status.Mode != "client" {
			t.Errorf("Expected client mode, got %s", status.Mode)
		}
		
		// Cleanup
		systemIntegration.StopSystem()
	})
	
	// Test relay initialization
	t.Run("Relay_Initialization", func(t *testing.T) {
		config.RelayMode = true
		systemIntegration, err := NewSystemIntegration(config)
		if err != nil {
			t.Fatalf("Failed to create relay system integration: %v", err)
		}
		
		if !systemIntegration.isInitialized {
			t.Error("System not marked as initialized")
		}
		
		// Test system status
		status := systemIntegration.GetSystemStatus()
		if status.Mode != "relay" {
			t.Errorf("Expected relay mode, got %s", status.Mode)
		}
		
		// Cleanup
		systemIntegration.StopSystem()
	})
}

// testComponentIntegration tests integration between components
func testComponentIntegration(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	config.RelayMode = false
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	// Test that all components are properly initialized
	if systemIntegration.nodeManager == nil {
		t.Error("Node manager not initialized")
	}
	if systemIntegration.tunnelManager == nil {
		t.Error("Tunnel manager not initialized")
	}
	if systemIntegration.errorHandler == nil {
		t.Error("Error handler not initialized")
	}
	if systemIntegration.recoveryManager == nil {
		t.Error("Recovery manager not initialized")
	}
	if systemIntegration.logger == nil {
		t.Error("Logger not initialized")
	}
	if systemIntegration.connectionMonitor == nil {
		t.Error("Connection monitor not initialized")
	}
	if systemIntegration.healthChecker == nil {
		t.Error("Health checker not initialized")
	}
	if systemIntegration.securityHardener == nil {
		t.Error("Security hardener not initialized")
	}
	
	// Test component interactions
	status := systemIntegration.GetSystemStatus()
	if status.NodeStats == nil {
		t.Error("Node stats not available")
	}
	if status.ErrorStats == nil {
		t.Error("Error stats not available")
	}
	if status.RecoveryStats == nil {
		t.Error("Recovery stats not available")
	}
}

// testSecurityHardening tests security hardening measures
func testSecurityHardening(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	// Test security hardener
	hardener := systemIntegration.securityHardener
	if hardener == nil {
		t.Fatal("Security hardener not initialized")
	}
	
	// Apply security hardening
	err = hardener.ApplySecurityHardening()
	if err != nil {
		t.Errorf("Failed to apply security hardening: %v", err)
	}
	
	// Check applied measures
	measures := hardener.GetAppliedMeasures()
	if len(measures) == 0 {
		t.Error("No security measures applied")
	}
	
	// Test secure cleanup
	hardener.ApplySecureCleanup()
	
	// Measures should be cleared after cleanup
	measuresAfterCleanup := hardener.GetAppliedMeasures()
	if len(measuresAfterCleanup) != 0 {
		t.Error("Security measures not cleared after cleanup")
	}
}

// testErrorHandlingIntegration tests integrated error handling
func testErrorHandlingIntegration(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	errorHandler := systemIntegration.errorHandler
	if errorHandler == nil {
		t.Fatal("Error handler not initialized")
	}
	
	// Test error handling
	testError := &SecurityError{
		Type:        ErrorTypeNetwork,
		Message:     "test network error",
		Timestamp:   time.Now(),
		Context:     "integration_test",
		Recoverable: true,
		SensitiveData: false,
	}
	
	err = errorHandler.HandleError(testError, "test_context")
	if err == nil {
		t.Error("Expected error to be returned from handler")
	}
	
	// Check error statistics
	stats := errorHandler.GetErrorStatistics()
	if networkErrors, ok := stats["network_errors"].(int); !ok || networkErrors == 0 {
		t.Error("Network error not recorded in statistics")
	}
	
	// Test recovery manager integration
	recoveryManager := systemIntegration.recoveryManager
	if recoveryManager == nil {
		t.Fatal("Recovery manager not initialized")
	}
	
	recoveryStats := recoveryManager.GetRecoveryStatistics()
	if recoveryStats == nil {
		t.Error("Recovery statistics not available")
	}
}

// testHealthMonitoring tests health monitoring integration
func testHealthMonitoring(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	// Start the system to activate monitoring
	err = systemIntegration.StartSystem()
	if err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	
	// Give monitoring time to initialize
	time.Sleep(100 * time.Millisecond)
	
	// Test connection monitor
	connectionMonitor := systemIntegration.connectionMonitor
	if connectionMonitor == nil {
		t.Fatal("Connection monitor not initialized")
	}
	
	// Test health checker
	healthChecker := systemIntegration.healthChecker
	if healthChecker == nil {
		t.Fatal("Health checker not initialized")
	}
	
	// Test system status
	status := systemIntegration.GetSystemStatus()
	if status.HealthStatus == nil {
		t.Error("Health status not available")
	}
	
	// The system should be healthy initially
	if !status.IsHealthy {
		t.Error("System should be healthy after startup")
	}
}

// testGracefulShutdown tests graceful system shutdown
func testGracefulShutdown(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	
	// Start the system
	err = systemIntegration.StartSystem()
	if err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	
	// Give system time to start
	time.Sleep(100 * time.Millisecond)
	
	// Test graceful shutdown
	err = systemIntegration.StopSystem()
	if err != nil {
		t.Errorf("Failed to stop system gracefully: %v", err)
	}
	
	// System should be properly cleaned up
	// This is verified by the absence of panics or errors during shutdown
}

// TestSystemPerformanceIntegration tests performance of integrated system
func TestSystemPerformanceIntegration(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	// Measure initialization time
	start := time.Now()
	systemIntegration, err := NewSystemIntegration(config)
	initTime := time.Since(start)
	
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	t.Logf("System initialization took: %v", initTime)
	
	// Initialization should be reasonably fast
	if initTime > 5*time.Second {
		t.Errorf("System initialization too slow: %v", initTime)
	}
	
	// Measure startup time
	start = time.Now()
	err = systemIntegration.StartSystem()
	startupTime := time.Since(start)
	
	if err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	
	t.Logf("System startup took: %v", startupTime)
	
	// Startup should be reasonably fast
	if startupTime > 10*time.Second {
		t.Errorf("System startup too slow: %v", startupTime)
	}
	
	// Test memory usage
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	
	// Get system status multiple times to test performance
	for i := 0; i < 100; i++ {
		status := systemIntegration.GetSystemStatus()
		if status == nil {
			t.Error("System status returned nil")
		}
	}
	
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	
	var memUsed uint64
	if memAfter.Alloc > memBefore.Alloc {
		memUsed = memAfter.Alloc - memBefore.Alloc
	} else {
		memUsed = 0 // Memory was reclaimed during operations
	}
	t.Logf("Memory used for 100 status calls: %d bytes", memUsed)
	
	// Memory usage should be reasonable (allow up to 10MB for test environment)
	if memUsed > 10*1024*1024 { // 10MB
		t.Errorf("Memory usage too high: %d bytes", memUsed)
	}
}

// TestConcurrentSystemOperations tests concurrent operations on integrated system
func TestConcurrentSystemOperations(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	err = systemIntegration.StartSystem()
	if err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	
	// Test concurrent status requests
	const numGoroutines = 10
	const operationsPerGoroutine = 50
	
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	
	start := time.Now()
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				status := systemIntegration.GetSystemStatus()
				if status == nil {
					errors <- fmt.Errorf("system status returned nil")
					return
				}
				
				// Small delay to simulate real usage
				time.Sleep(time.Millisecond)
			}
		}()
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// Check for errors
	select {
	case err := <-errors:
		t.Fatalf("Concurrent operations failed: %v", err)
	default:
	}
	
	totalOperations := numGoroutines * operationsPerGoroutine
	avgTime := duration / time.Duration(totalOperations)
	
	t.Logf("Concurrent operations: %d operations in %v (avg: %v per operation)", 
		totalOperations, duration, avgTime)
	
	// Operations should complete in reasonable time
	if avgTime > 10*time.Millisecond {
		t.Errorf("Concurrent operations too slow: %v per operation", avgTime)
	}
}

// TestSystemRecoveryIntegration tests system recovery capabilities
func TestSystemRecoveryIntegration(t *testing.T) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for testing
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		t.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	err = systemIntegration.StartSystem()
	if err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	
	// Simulate various error conditions
	errorHandler := systemIntegration.errorHandler
	
	// Test network error recovery
	networkError := &SecurityError{
		Type:        ErrorTypeNetwork,
		Message:     "simulated network failure",
		Timestamp:   time.Now(),
		Context:     "recovery_test",
		Recoverable: true,
		SensitiveData: false,
	}
	
	err = errorHandler.HandleError(networkError, "recovery_test")
	if err == nil {
		t.Error("Expected error to be returned for handling")
	}
	
	// Test route error recovery
	routeError := &SecurityError{
		Type:        ErrorTypeRoute,
		Message:     "simulated route failure",
		Timestamp:   time.Now(),
		Context:     "recovery_test",
		Recoverable: true,
		SensitiveData: false,
	}
	
	err = errorHandler.HandleError(routeError, "recovery_test")
	if err == nil {
		t.Error("Expected error to be returned for handling")
	}
	
	// Check that error statistics are updated
	stats := errorHandler.GetErrorStatistics()
	if networkErrors, ok := stats["network_errors"].(int); !ok || networkErrors == 0 {
		t.Error("Network errors not recorded")
	}
	if routeErrors, ok := stats["route_errors"].(int); !ok || routeErrors == 0 {
		t.Error("Route errors not recorded")
	}
	
	// System should still be functional after errors
	status := systemIntegration.GetSystemStatus()
	if status == nil {
		t.Error("System status not available after errors")
	}
}

// BenchmarkSystemIntegration benchmarks the integrated system performance
func BenchmarkSystemIntegration(b *testing.B) {
	config := NewDefaultConfig()
	config.LogLevel = 0 // Quiet for benchmarking
	
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		b.Fatalf("Failed to create system integration: %v", err)
	}
	defer systemIntegration.StopSystem()
	
	err = systemIntegration.StartSystem()
	if err != nil {
		b.Fatalf("Failed to start system: %v", err)
	}
	
	b.ResetTimer()
	
	b.Run("GetSystemStatus", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			status := systemIntegration.GetSystemStatus()
			if status == nil {
				b.Fatal("System status returned nil")
			}
		}
	})
	
	b.Run("ErrorHandling", func(b *testing.B) {
		testError := &SecurityError{
			Type:        ErrorTypeNetwork,
			Message:     "benchmark test error",
			Timestamp:   time.Now(),
			Context:     "benchmark",
			Recoverable: true,
			SensitiveData: false,
		}
		
		for i := 0; i < b.N; i++ {
			systemIntegration.errorHandler.HandleError(testError, "benchmark")
		}
	})
}