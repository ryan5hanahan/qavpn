package main

import (
	"errors"
	"testing"
	"time"
)

// TestSecureErrorHandler tests the secure error handling functionality
func TestSecureErrorHandler(t *testing.T) {
	handler := NewSecureErrorHandler()

	// Test crypto error handling (should trigger emergency shutdown)
	cryptoErr := errors.New("crypto key generation failed")
	err := handler.HandleError(cryptoErr, "crypto_test")
	if err == nil {
		t.Error("Expected crypto error to be handled")
	}

	// Check if emergency shutdown was triggered
	select {
	case <-handler.GetShutdownChannel():
		// Expected behavior for crypto errors
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected emergency shutdown for crypto error")
	}
}

// TestSecurityErrorClassification tests error classification
func TestSecurityErrorClassification(t *testing.T) {
	handler := NewSecureErrorHandler()

	testCases := []struct {
		error    string
		context  string
		expected ErrorType
		sensitive bool
	}{
		{"crypto operation failed", "test", ErrorTypeCrypto, true},
		{"connection refused", "test", ErrorTypeNetwork, false},
		{"protocol version mismatch", "test", ErrorTypeProtocol, false},
		{"route not found", "test", ErrorTypeRoute, false},
		{"unknown error", "test", ErrorTypeSystem, true},
	}

	for _, tc := range testCases {
		err := errors.New(tc.error)
		secErr := handler.classifyError(err, tc.context)
		
		if secErr.Type != tc.expected {
			t.Errorf("Expected error type %d, got %d for error: %s", 
				tc.expected, secErr.Type, tc.error)
		}
		
		if secErr.SensitiveData != tc.sensitive {
			t.Errorf("Expected sensitive data flag %v, got %v for error: %s", 
				tc.sensitive, secErr.SensitiveData, tc.error)
		}
	}
}

// TestErrorRecovery tests error recovery mechanisms
func TestErrorRecovery(t *testing.T) {
	handler := NewSecureErrorHandler()

	// Test network error recovery
	networkErr := &SecurityError{
		Type:        ErrorTypeNetwork,
		Message:     "connection timeout",
		Context:     "test_connection",
		Recoverable: true,
		SensitiveData: false,
	}

	recoveredErr := handler.attemptRecovery(networkErr)
	if recoveredErr == nil {
		t.Error("Expected recovery to return sanitized error")
	}

	secErr, ok := recoveredErr.(*SecurityError)
	if !ok {
		t.Error("Expected SecurityError from recovery")
	}

	if secErr.Type != ErrorTypeNetwork {
		t.Error("Expected network error type to be preserved")
	}
}

// TestRecoveryAttemptLimits tests recovery attempt limiting
func TestRecoveryAttemptLimits(t *testing.T) {
	handler := NewSecureErrorHandler()

	networkErr := &SecurityError{
		Type:        ErrorTypeNetwork,
		Message:     "connection failed",
		Context:     "test_limit",
		Recoverable: true,
		SensitiveData: false,
	}

	// Attempt recovery multiple times
	for i := 0; i < handler.maxRecoveryAttempts+1; i++ {
		err := handler.attemptRecovery(networkErr)
		if i >= handler.maxRecoveryAttempts {
			if err == nil || err.Error() != "max recovery attempts exceeded for test_limit" {
				t.Error("Expected max recovery attempts error")
			}
		}
	}
}

// TestAutomaticRecoveryManager tests the automatic recovery functionality
func TestAutomaticRecoveryManager(t *testing.T) {
	// Create mock components
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	tunnelManager := NewTunnelManager()
	errorHandler := NewSecureErrorHandler()
	
	recoveryManager := NewAutomaticRecoveryManager(nodeManager, tunnelManager, errorHandler)

	// Create a mock failed route
	failedRoute := &Route{
		Hops: []*Node{
			{
				ID:       NodeID{1, 2, 3, 4},
				Address:  "127.0.0.1:9999", // Non-existent address
				Protocol: "tcp",
			},
		},
		Protocol:  "tcp",
		CreatedAt: time.Now(),
		Active:    false,
	}

	// Test recovery (should fail due to no available nodes)
	newRoute, newTunnel, recoveryErr := recoveryManager.RecoverFromFailure(
		failedRoute, errors.New("route failed"), "test_recovery")

	// Recovery should fail due to insufficient nodes
	if recoveryErr == nil {
		t.Error("Expected recovery to fail with insufficient nodes")
	}

	if newRoute != nil {
		t.Error("Expected no new route when recovery fails")
	}

	if newTunnel != nil {
		t.Error("Expected no new tunnel when recovery fails")
	}
}

// TestFailoverRouteCreation tests failover route creation
func TestFailoverRouteCreation(t *testing.T) {
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	tunnelManager := NewTunnelManager()
	errorHandler := NewSecureErrorHandler()
	recoveryManager := NewAutomaticRecoveryManager(nodeManager, tunnelManager, errorHandler)

	// Add some mock nodes to the node manager
	mockNodes := []*Node{
		{ID: NodeID{1}, Address: "127.0.0.1:9001", Protocol: "tcp"},
		{ID: NodeID{2}, Address: "127.0.0.1:9002", Protocol: "tcp"},
		{ID: NodeID{3}, Address: "127.0.0.1:9003", Protocol: "tcp"},
		{ID: NodeID{4}, Address: "127.0.0.1:9004", Protocol: "tcp"},
	}

	// Add nodes to known nodes (simulate discovery)
	nodeManager.mutex.Lock()
	for _, node := range mockNodes {
		node.LastSeen = time.Now()
		nodeManager.knownNodes[node.ID] = node
	}
	nodeManager.mutex.Unlock()

	// Create failed route using first two nodes
	failedRoute := &Route{
		Hops:     []*Node{mockNodes[0], mockNodes[1]},
		Protocol: "tcp",
		Active:   false,
	}

	// Test failover route creation
	newRoute, err := recoveryManager.createFailoverRoute(failedRoute)
	if err != nil {
		t.Fatalf("Failed to create failover route: %v", err)
	}

	if len(newRoute.Hops) < MinRelayHops {
		t.Errorf("Expected at least %d hops, got %d", MinRelayHops, len(newRoute.Hops))
	}

	// Verify new route doesn't use failed nodes
	failedNodeIDs := make(map[NodeID]bool)
	for _, hop := range failedRoute.Hops {
		failedNodeIDs[hop.ID] = true
	}

	for _, hop := range newRoute.Hops {
		if failedNodeIDs[hop.ID] {
			t.Error("New route should not use failed nodes")
		}
	}
}

// TestErrorStatistics tests error statistics collection
func TestErrorStatistics(t *testing.T) {
	handler := NewSecureErrorHandler()

	// Generate various types of errors
	errors := []error{
		errors.New("connection timeout"),
		errors.New("protocol version mismatch"),
		errors.New("route not found"),
		errors.New("system failure"),
	}

	for _, err := range errors {
		handler.HandleError(err, "test_stats")
	}

	stats := handler.GetErrorStatistics()
	
	// "connection timeout" should be classified as network error
	if stats["network_errors"].(int) != 1 {
		t.Errorf("Expected 1 network error in statistics, got %d", stats["network_errors"].(int))
	}
	
	// "protocol version mismatch" should be classified as protocol error
	if stats["protocol_errors"].(int) != 1 {
		t.Errorf("Expected 1 protocol error in statistics, got %d", stats["protocol_errors"].(int))
	}
	
	// "route not found" should be classified as route error
	if stats["route_errors"].(int) != 1 {
		t.Errorf("Expected 1 route error in statistics, got %d", stats["route_errors"].(int))
	}
	
	// "system failure" should be classified as system error
	if stats["system_errors"].(int) != 1 {
		t.Errorf("Expected 1 system error in statistics, got %d", stats["system_errors"].(int))
	}
}

// TestSensitiveDataSanitization tests that sensitive data is properly sanitized
func TestSensitiveDataSanitization(t *testing.T) {
	_ = NewSecureErrorHandler() // Not used in this test

	// Test sensitive error message sanitization
	sensitiveErr := &SecurityError{
		Type:        ErrorTypeCrypto,
		Message:     "key material exposed: 0x1234567890abcdef",
		Context:     "crypto_test",
		SensitiveData: true,
	}

	errorMsg := sensitiveErr.Error()
	if errorMsg == sensitiveErr.Message {
		t.Error("Sensitive error message should be sanitized")
	}

	// Should not contain the original sensitive message
	if errorMsg == "key material exposed: 0x1234567890abcdef" {
		t.Error("Sensitive data should not appear in error message")
	}
}

// TestRecoverySessionManagement tests recovery session management
func TestRecoverySessionManagement(t *testing.T) {
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	tunnelManager := NewTunnelManager()
	errorHandler := NewSecureErrorHandler()
	recoveryManager := NewAutomaticRecoveryManager(nodeManager, tunnelManager, errorHandler)

	// Test concurrent recovery limit
	failedRoute := &Route{
		Hops:     []*Node{{ID: NodeID{1}, Address: "127.0.0.1:9999", Protocol: "tcp"}},
		Protocol: "tcp",
		Active:   false,
	}

	// Start multiple recovery operations
	for i := 0; i < recoveryManager.maxConcurrentRecoveries+1; i++ {
		go func() {
			recoveryManager.RecoverFromFailure(failedRoute, errors.New("test"), "concurrent_test")
		}()
	}

	// Give some time for goroutines to start
	time.Sleep(100 * time.Millisecond)

	stats := recoveryManager.GetRecoveryStatistics()
	maxConcurrent := stats["max_concurrent_recoveries"].(int)
	
	if maxConcurrent != recoveryManager.maxConcurrentRecoveries {
		t.Errorf("Expected max concurrent recoveries %d, got %d", 
			recoveryManager.maxConcurrentRecoveries, maxConcurrent)
	}
}

// TestEmergencyShutdownConditions tests various emergency shutdown conditions
func TestEmergencyShutdownConditions(t *testing.T) {

	testCases := []struct {
		errorType    ErrorType
		count        int
		shouldShutdown bool
		description  string
	}{
		{ErrorTypeCrypto, 1, true, "Single crypto error should trigger shutdown"},
		{ErrorTypeSystem, 3, true, "Multiple system errors should trigger shutdown"},
		{ErrorTypeNetwork, 5, false, "Few network errors should not trigger shutdown"},
		{ErrorTypeNetwork, 15, true, "Many network errors should trigger shutdown"},
	}

	for _, tc := range testCases {
		handler := NewSecureErrorHandler() // Reset handler for each test
		
		for i := 0; i < tc.count; i++ {
			err := &SecurityError{
				Type:    tc.errorType,
				Message: "test error",
				Context: "shutdown_test",
			}
			
			shouldShutdown := handler.shouldEmergencyShutdown(err)
			if i == tc.count-1 { // Check on last iteration
				if shouldShutdown != tc.shouldShutdown {
					t.Errorf("%s: expected shutdown=%v, got %v", 
						tc.description, tc.shouldShutdown, shouldShutdown)
				}
			}
		}
	}
}

// TestSecureCleanup tests secure cleanup functionality
func TestSecureCleanup(t *testing.T) {
	handler := NewSecureErrorHandler()

	// Add some recovery attempts
	handler.mutex.Lock()
	handler.recoveryAttempts["test_context_1"] = 2
	handler.recoveryAttempts["test_context_2"] = 1
	handler.mutex.Unlock()

	// Perform secure cleanup
	nonRecoverableErr := &SecurityError{
		Type:        ErrorTypeCrypto,
		Message:     "crypto failure",
		Context:     "cleanup_test",
		Recoverable: false,
		SensitiveData: true,
	}

	handler.performSecureCleanup(nonRecoverableErr)

	// Verify recovery attempts were cleared
	handler.mutex.RLock()
	if len(handler.recoveryAttempts) != 0 {
		t.Error("Expected recovery attempts to be cleared during secure cleanup")
	}
	handler.mutex.RUnlock()
}

// BenchmarkErrorHandling benchmarks error handling performance
func BenchmarkErrorHandling(b *testing.B) {
	handler := NewSecureErrorHandler()
	testErr := errors.New("benchmark test error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.HandleError(testErr, "benchmark")
	}
}

// BenchmarkErrorClassification benchmarks error classification performance
func BenchmarkErrorClassification(b *testing.B) {
	handler := NewSecureErrorHandler()
	testErr := errors.New("network connection failed")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.classifyError(testErr, "benchmark")
	}
}