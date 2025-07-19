package direct

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestLongRunningConnectionStability tests connection stability over extended periods
func TestLongRunningConnectionStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish connection
	invitation, err := establishTestConnection(t, instanceA, instanceB)
	if err != nil {
		t.Fatalf("Failed to establish test connection: %v", err)
	}

	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)
	
	// Test duration (reduced for CI/testing)
	testDuration := 5 * time.Minute
	if testing.Short() {
		testDuration = 30 * time.Second
	}

	t.Logf("Starting long-running stability test for %v", testDuration)

	// Monitor connection health over time
	healthChecks := make(chan *ConnectionHealth, 100)
	stopHealthMonitoring := make(chan bool, 1)

	// Start health monitoring goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				health := instanceA.healthMonitor.GetHealth(connectionID)
				if health != nil {
					healthChecks <- health
				}
			case <-stopHealthMonitoring:
				return
			}
		}
	}()

	// Simulate periodic data transfer
	dataTransferErrors := make(chan error, 10)
	stopDataTransfer := make(chan bool, 1)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		connections := instanceA.dcm.GetActiveConnections()
		if len(connections) == 0 {
			dataTransferErrors <- fmt.Errorf("no active connections for data transfer")
			return
		}

		conn := connections[0]
		transferCount := 0

		for {
			select {
			case <-ticker.C:
				transferCount++
				testData := []byte(fmt.Sprintf("Long-running test data transfer #%d", transferCount))
				
				err := conn.SendData(testData)
				if err != nil {
					dataTransferErrors <- fmt.Errorf("data transfer %d failed: %v", transferCount, err)
				}

				// Update health with successful transfer
				instanceA.healthMonitor.UpdateHealth(connectionID, 50*time.Millisecond, err == nil)

			case <-stopDataTransfer:
				return
			}
		}
	}()

	// Run test for specified duration
	time.Sleep(testDuration)

	// Stop monitoring
	stopHealthMonitoring <- true
	stopDataTransfer <- true
	close(healthChecks)
	close(dataTransferErrors)

	// Analyze results
	var healthCheckCount int
	var unhealthyCount int
	var lastHealth *ConnectionHealth

	for health := range healthChecks {
		healthCheckCount++
		lastHealth = health
		if health.Status != "healthy" {
			unhealthyCount++
		}
	}

	// Check for data transfer errors
	var transferErrorCount int
	for err := range dataTransferErrors {
		transferErrorCount++
		t.Logf("Data transfer error: %v", err)
	}

	// Verify stability metrics
	t.Logf("Long-running test results:")
	t.Logf("- Health checks performed: %d", healthCheckCount)
	t.Logf("- Unhealthy periods: %d", unhealthyCount)
	t.Logf("- Data transfer errors: %d", transferErrorCount)

	if lastHealth != nil {
		t.Logf("- Final health score: %.2f", lastHealth.HealthScore)
		t.Logf("- Final status: %s", lastHealth.Status)
	}

	// Verify connection remained stable
	if healthCheckCount == 0 {
		t.Error("No health checks were performed")
	}

	if lastHealth == nil {
		t.Error("No final health status available")
	} else if lastHealth.Status != "healthy" {
		t.Errorf("Connection should be healthy after long-running test, got: %s", lastHealth.Status)
	}

	// Allow some transfer errors but not too many
	maxAllowedErrors := healthCheckCount / 10 // 10% error rate
	if transferErrorCount > maxAllowedErrors {
		t.Errorf("Too many data transfer errors: %d > %d", transferErrorCount, maxAllowedErrors)
	}
}

// TestMemoryLeakDetection tests for memory leaks during extended operation
func TestMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	// Force garbage collection before starting
	runtime.GC()
	runtime.GC()

	var initialMemStats runtime.MemStats
	runtime.ReadMemStats(&initialMemStats)

	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish and close connections repeatedly
	numIterations := 50
	if testing.Short() {
		numIterations = 10
	}

	t.Logf("Testing memory leaks over %d connection cycles", numIterations)

	for i := 0; i < numIterations; i++ {
		// Establish connection
		invitation, err := instanceA.dcm.GenerateInvitation(&InvitationConfig{
			Protocol:        "tcp",
			ListenerAddress: "127.0.0.1:0",
			ExpirationTime:  time.Now().Add(1 * time.Hour),
			SingleUse:       true,
		})
		if err != nil {
			t.Fatalf("Iteration %d: Failed to generate invitation: %v", i, err)
		}

		listenerConfig := &ListenerConfig{
			Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
			Protocol: "tcp",
		}

		err = instanceA.dcm.StartListener(listenerConfig)
		if err != nil {
			t.Fatalf("Iteration %d: Failed to start listener: %v", i, err)
		}

		err = instanceB.dcm.ConnectToPeer(invitation)
		if err != nil {
			t.Fatalf("Iteration %d: Failed to connect: %v", i, err)
		}

		// Wait for connection establishment
		if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 5*time.Second) {
			t.Fatalf("Iteration %d: Connection establishment failed", i)
		}

		// Transfer some data
		connections := instanceA.dcm.GetActiveConnections()
		if len(connections) > 0 {
			testData := []byte(fmt.Sprintf("Memory leak test data iteration %d", i))
			connections[0].SendData(testData)
		}

		// Close connections
		for _, conn := range instanceA.dcm.GetActiveConnections() {
			conn.Close()
		}
		for _, conn := range instanceB.dcm.GetActiveConnections() {
			conn.Close()
		}

		// Force garbage collection every 10 iterations
		if i%10 == 0 {
			runtime.GC()
			runtime.GC()

			var currentMemStats runtime.MemStats
			runtime.ReadMemStats(&currentMemStats)

			memGrowthMB := float64(currentMemStats.Alloc-initialMemStats.Alloc) / 1024 / 1024
			t.Logf("Iteration %d: Memory growth: %.2f MB", i, memGrowthMB)

			// Check for excessive memory growth
			if memGrowthMB > 50 { // More than 50MB growth
				t.Errorf("Excessive memory growth detected: %.2f MB", memGrowthMB)
			}
		}
	}

	// Final memory check
	runtime.GC()
	runtime.GC()

	var finalMemStats runtime.MemStats
	runtime.ReadMemStats(&finalMemStats)

	finalMemGrowthMB := float64(finalMemStats.Alloc-initialMemStats.Alloc) / 1024 / 1024
	t.Logf("Final memory growth: %.2f MB", finalMemGrowthMB)

	// Verify no significant memory leak
	if finalMemGrowthMB > 20 { // More than 20MB final growth
		t.Errorf("Potential memory leak detected: %.2f MB growth", finalMemGrowthMB)
	}
}

// TestHighConcurrencyStability tests stability under high concurrent load
func TestHighConcurrencyStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high concurrency test in short mode")
	}

	// Create listener instance
	listener, connectors, cleanup := setupMultiInstanceTest(t, 20)
	defer cleanup()

	// Start listener
	listenerConfig := &ListenerConfig{
		Port:     0,
		Protocol: "tcp",
	}

	err := listener.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	// Get actual listener port
	listeners := listener.dcm.(*DirectConnectionManagerImpl).GetActiveListeners()
	var actualPort int
	for key := range listeners {
		_, portStr, _ := net.SplitHostPort(key)
		fmt.Sscanf(portStr, "%d", &actualPort)
		break
	}

	t.Logf("Testing high concurrency with %d concurrent connections", len(connectors))

	// Track connection results
	results := make(chan ConnectionResult, len(connectors))
	var wg sync.WaitGroup

	// Start all connections concurrently
	for i, connector := range connectors {
		wg.Add(1)
		go func(idx int, conn *TestInstance) {
			defer wg.Done()

			result := ConnectionResult{
				ConnectorID: idx,
				StartTime:   time.Now(),
			}

			// Generate invitation
			invitation, err := listener.dcm.GenerateInvitation(&InvitationConfig{
				Protocol:        "tcp",
				ListenerAddress: fmt.Sprintf("127.0.0.1:%d", actualPort),
				ExpirationTime:  time.Now().Add(1 * time.Hour),
				SingleUse:       true,
			})
			if err != nil {
				result.Error = fmt.Errorf("invitation generation failed: %v", err)
				results <- result
				return
			}

			// Connect
			err = conn.dcm.ConnectToPeer(invitation)
			result.ConnectionTime = time.Since(result.StartTime)
			
			if err != nil {
				result.Error = err
			} else {
				result.Success = true
				
				// Test data transfer
				connections := conn.dcm.GetActiveConnections()
				if len(connections) > 0 {
					testData := []byte(fmt.Sprintf("Concurrency test data from connector %d", idx))
					err = connections[0].SendData(testData)
					if err != nil {
						result.DataTransferError = err
					}
				}
			}

			results <- result
		}(i, connector)
	}

	// Wait for all connections to complete
	wg.Wait()
	close(results)

	// Analyze results
	var successCount int
	var errorCount int
	var totalConnectionTime time.Duration
	var maxConnectionTime time.Duration
	var dataTransferErrors int

	for result := range results {
		if result.Success {
			successCount++
			totalConnectionTime += result.ConnectionTime
			if result.ConnectionTime > maxConnectionTime {
				maxConnectionTime = result.ConnectionTime
			}
		} else {
			errorCount++
			t.Logf("Connection %d failed: %v", result.ConnectorID, result.Error)
		}

		if result.DataTransferError != nil {
			dataTransferErrors++
			t.Logf("Data transfer error for connection %d: %v", result.ConnectorID, result.DataTransferError)
		}
	}

	avgConnectionTime := time.Duration(0)
	if successCount > 0 {
		avgConnectionTime = totalConnectionTime / time.Duration(successCount)
	}

	t.Logf("High concurrency test results:")
	t.Logf("- Successful connections: %d/%d", successCount, len(connectors))
	t.Logf("- Failed connections: %d", errorCount)
	t.Logf("- Average connection time: %v", avgConnectionTime)
	t.Logf("- Maximum connection time: %v", maxConnectionTime)
	t.Logf("- Data transfer errors: %d", dataTransferErrors)

	// Verify acceptable success rate
	successRate := float64(successCount) / float64(len(connectors))
	if successRate < 0.8 { // At least 80% success rate
		t.Errorf("Success rate too low: %.2f%%", successRate*100)
	}

	// Verify reasonable connection times
	if avgConnectionTime > 5*time.Second {
		t.Errorf("Average connection time too high: %v", avgConnectionTime)
	}

	if maxConnectionTime > 30*time.Second {
		t.Errorf("Maximum connection time too high: %v", maxConnectionTime)
	}

	// Verify listener is still responsive
	listenerConnections := listener.dcm.GetActiveConnections()
	t.Logf("Active connections on listener: %d", len(listenerConnections))
}

// TestSystemRecoveryAfterRestart tests system recovery after restart
func TestSystemRecoveryAfterRestart(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("restart-test-password")

	// Phase 1: Create and configure system
	configManager1, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create first config manager: %v", err)
	}

	// Create and save connection profiles
	profiles := []*ConnectionProfile{
		{
			Name:        "restart-test-profile-1",
			Description: "Profile for restart testing",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "127.0.0.1:9090",
			},
			UseCount:  3,
			CreatedAt: time.Now().Add(-2 * time.Hour),
			LastUsed:  time.Now().Add(-30 * time.Minute),
		},
		{
			Name:        "restart-test-profile-2",
			Description: "Second profile for restart testing",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "127.0.0.1:9091",
			},
			UseCount:  1,
			CreatedAt: time.Now().Add(-1 * time.Hour),
			LastUsed:  time.Now().Add(-10 * time.Minute),
		},
	}

	for _, profile := range profiles {
		err := configManager1.SaveProfile(profile)
		if err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Get pre-restart statistics
	preRestartStats, err := configManager1.GetProfileStatistics()
	if err != nil {
		t.Fatalf("Failed to get pre-restart statistics: %v", err)
	}

	// Phase 2: Simulate system restart
	configManager1 = nil // Simulate shutdown
	runtime.GC()

	// Create new config manager (simulating restart)
	configManager2, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create config manager after restart: %v", err)
	}

	// Phase 3: Verify recovery
	// Check that all profiles are still available
	profileList := configManager2.ListProfiles()
	if len(profileList) != len(profiles) {
		t.Errorf("Profile count mismatch after restart: expected %d, got %d", len(profiles), len(profileList))
	}

	// Verify each profile can be loaded
	for _, originalProfile := range profiles {
		loadedProfile, err := configManager2.LoadProfile(originalProfile.Name)
		if err != nil {
			t.Errorf("Failed to load profile %s after restart: %v", originalProfile.Name, err)
			continue
		}

		// Verify profile data integrity
		if loadedProfile.Description != originalProfile.Description {
			t.Errorf("Profile %s description corrupted after restart", originalProfile.Name)
		}

		if loadedProfile.NetworkConfig.Protocol != originalProfile.NetworkConfig.Protocol {
			t.Errorf("Profile %s protocol corrupted after restart", originalProfile.Name)
		}

		// Use count should be incremented due to loading
		expectedUseCount := originalProfile.UseCount + 1
		if loadedProfile.UseCount != expectedUseCount {
			t.Errorf("Profile %s use count incorrect after restart: expected %d, got %d", 
				originalProfile.Name, expectedUseCount, loadedProfile.UseCount)
		}
	}

	// Verify statistics consistency
	postRestartStats, err := configManager2.GetProfileStatistics()
	if err != nil {
		t.Fatalf("Failed to get post-restart statistics: %v", err)
	}

	if postRestartStats.TotalProfiles != preRestartStats.TotalProfiles {
		t.Errorf("Total profiles mismatch after restart: expected %d, got %d", 
			preRestartStats.TotalProfiles, postRestartStats.TotalProfiles)
	}

	// Phase 4: Test functionality after restart
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Use recovered profile for new connection
	recoveredProfile, err := configManager2.LoadProfile("restart-test-profile-1")
	if err != nil {
		t.Fatalf("Failed to load recovered profile: %v", err)
	}

	// Test connection establishment with recovered configuration
	invitation, err := instanceA.dcm.GenerateInvitation(&InvitationConfig{
		Protocol:        recoveredProfile.NetworkConfig.Protocol,
		ListenerAddress: "127.0.0.1:0", // Use any available port
		ExpirationTime:  time.Now().Add(1 * time.Hour),
		SingleUse:       true,
	})
	if err != nil {
		t.Fatalf("Failed to generate invitation with recovered profile: %v", err)
	}

	listenerConfig := &ListenerConfig{
		Port:     extractPortFromAddress(invitation.NetworkConfig.ListenerAddress),
		Protocol: recoveredProfile.NetworkConfig.Protocol,
	}

	err = instanceA.dcm.StartListener(listenerConfig)
	if err != nil {
		t.Fatalf("Failed to start listener with recovered profile: %v", err)
	}

	err = instanceB.dcm.ConnectToPeer(invitation)
	if err != nil {
		t.Fatalf("Failed to connect with recovered profile: %v", err)
	}

	// Verify connection establishment
	if !waitForConnectionEstablishment(t, instanceA.dcm, instanceB.dcm, 10*time.Second) {
		t.Fatal("Connection establishment failed with recovered configuration")
	}

	t.Log("System recovery after restart completed successfully")
}

// TestPerformanceDegradationDetection tests detection of performance degradation
func TestPerformanceDegradationDetection(t *testing.T) {
	instanceA, instanceB, cleanup := setupTwoInstanceTest(t)
	defer cleanup()

	// Establish connection
	invitation, err := establishTestConnection(t, instanceA, instanceB)
	if err != nil {
		t.Fatalf("Failed to establish test connection: %v", err)
	}

	connectionID := fmt.Sprintf("%x", invitation.ConnectionID)
	connections := instanceA.dcm.GetActiveConnections()
	if len(connections) == 0 {
		t.Fatal("No active connections found")
	}

	conn := connections[0]

	// Baseline performance measurement
	baselineLatencies := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		testData := []byte(fmt.Sprintf("Baseline test data %d", i))
		
		start := time.Now()
		err := conn.SendData(testData)
		latency := time.Since(start)
		
		if err != nil {
			t.Fatalf("Baseline data transfer %d failed: %v", i, err)
		}

		baselineLatencies[i] = latency
		instanceA.healthMonitor.UpdateHealth(connectionID, latency, true)
		time.Sleep(100 * time.Millisecond)
	}

	// Calculate baseline average
	var baselineTotal time.Duration
	for _, latency := range baselineLatencies {
		baselineTotal += latency
	}
	baselineAvg := baselineTotal / time.Duration(len(baselineLatencies))

	t.Logf("Baseline average latency: %v", baselineAvg)

	// Simulate performance degradation
	degradedLatencies := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		testData := []byte(fmt.Sprintf("Degraded test data %d", i))
		
		// Simulate increased latency
		time.Sleep(200 * time.Millisecond) // Artificial delay
		
		start := time.Now()
		err := conn.SendData(testData)
		latency := time.Since(start) + 200*time.Millisecond // Add simulated network delay
		
		if err != nil {
			t.Fatalf("Degraded data transfer %d failed: %v", i, err)
		}

		degradedLatencies[i] = latency
		instanceA.healthMonitor.UpdateHealth(connectionID, latency, true)
		time.Sleep(100 * time.Millisecond)
	}

	// Calculate degraded average
	var degradedTotal time.Duration
	for _, latency := range degradedLatencies {
		degradedTotal += latency
	}
	degradedAvg := degradedTotal / time.Duration(len(degradedLatencies))

	t.Logf("Degraded average latency: %v", degradedAvg)

	// Verify performance degradation detection
	performanceRatio := float64(degradedAvg) / float64(baselineAvg)
	t.Logf("Performance degradation ratio: %.2f", performanceRatio)

	if performanceRatio < 2.0 {
		t.Error("Performance degradation should be detected (ratio should be > 2.0)")
	}

	// Check connection health reflects degradation
	health := instanceA.healthMonitor.GetHealth(connectionID)
	if health == nil {
		t.Fatal("Health monitoring should be active")
	}

	if health.AverageLatency < degradedAvg/2 {
		t.Error("Health monitor should reflect increased latency")
	}

	// Test recovery detection
	recoveryLatencies := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		testData := []byte(fmt.Sprintf("Recovery test data %d", i))
		
		start := time.Now()
		err := conn.SendData(testData)
		latency := time.Since(start)
		
		if err != nil {
			t.Fatalf("Recovery data transfer %d failed: %v", i, err)
		}

		recoveryLatencies[i] = latency
		instanceA.healthMonitor.UpdateHealth(connectionID, latency, true)
		time.Sleep(50 * time.Millisecond)
	}

	// Calculate recovery average
	var recoveryTotal time.Duration
	for _, latency := range recoveryLatencies {
		recoveryTotal += latency
	}
	recoveryAvg := recoveryTotal / time.Duration(len(recoveryLatencies))

	t.Logf("Recovery average latency: %v", recoveryAvg)

	// Verify performance recovery
	recoveryRatio := float64(recoveryAvg) / float64(baselineAvg)
	t.Logf("Recovery ratio: %.2f", recoveryRatio)

	if recoveryRatio > 1.5 {
		t.Error("Performance should recover to near baseline levels")
	}
}

// Helper types for production readiness testing

// ConnectionResult represents the result of a connection attempt
type ConnectionResult struct {
	ConnectorID       int
	Success           bool
	Error             error
	DataTransferError error
	StartTime         time.Time
	ConnectionTime    time.Duration
}
