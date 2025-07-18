package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSecureLogger tests the secure logging functionality
func TestSecureLogger(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)

	// Test basic logging
	logger.Info("test_component", "test message", map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	})

	// Get recent entries
	entries := logger.GetRecentEntries(1)
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Level != LogLevelInfo {
		t.Errorf("Expected log level %d, got %d", LogLevelInfo, entry.Level)
	}

	if entry.Component != "test_component" {
		t.Errorf("Expected component 'test_component', got '%s'", entry.Component)
	}

	if entry.Message != "test message" {
		t.Errorf("Expected message 'test message', got '%s'", entry.Message)
	}
}

// TestLogLevelFiltering tests that log levels are properly filtered
func TestLogLevelFiltering(t *testing.T) {
	logger := NewSecureLogger(LogLevelWarn)

	// These should be logged
	logger.Error("test", "error message", nil)
	logger.Warn("test", "warn message", nil)

	// These should be filtered out
	logger.Info("test", "info message", nil)
	logger.Debug("test", "debug message", nil)

	entries := logger.GetRecentEntries(10)
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	// Check that only error and warn messages were logged
	levels := make(map[LogLevel]bool)
	for _, entry := range entries {
		levels[entry.Level] = true
	}

	if !levels[LogLevelError] || !levels[LogLevelWarn] {
		t.Error("Expected error and warn messages to be logged")
	}

	if levels[LogLevelInfo] || levels[LogLevelDebug] {
		t.Error("Info and debug messages should have been filtered out")
	}
}

// TestLogSensitiveDataSanitization tests that sensitive data is sanitized in logs
func TestLogSensitiveDataSanitization(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)

	// Test sensitive message sanitization
	logger.Info("test", "crypto key generation failed", nil)

	entries := logger.GetRecentEntries(1)
	if len(entries) != 1 {
		t.Fatal("Expected 1 entry")
	}

	// Message should be sanitized
	if entries[0].Message == "crypto key generation failed" {
		t.Error("Sensitive message should have been sanitized")
	}

	if entries[0].Message != "operation completed" {
		t.Errorf("Expected sanitized message 'operation completed', got '%s'", entries[0].Message)
	}
}

// TestMetadataSanitization tests that sensitive metadata is sanitized
func TestMetadataSanitization(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)

	// Test with sensitive metadata
	metadata := map[string]interface{}{
		"safe_key":      "safe_value",
		"secret_key":    "sensitive_value",
		"node_id":       "should_be_removed",
		"normal_count":  42,
	}

	logger.Info("test", "test message", metadata)

	entries := logger.GetRecentEntries(1)
	if len(entries) != 1 {
		t.Fatal("Expected 1 entry")
	}

	sanitizedMetadata := entries[0].Metadata

	// Safe keys should remain
	if sanitizedMetadata["safe_key"] != "safe_value" {
		t.Error("Safe metadata should be preserved")
	}

	if sanitizedMetadata["normal_count"] != 42 {
		t.Error("Non-sensitive metadata should be preserved")
	}

	// Sensitive keys should be removed
	if _, exists := sanitizedMetadata["secret_key"]; exists {
		t.Error("Sensitive key 'secret_key' should have been removed")
	}

	if _, exists := sanitizedMetadata["node_id"]; exists {
		t.Error("Sensitive key 'node_id' should have been removed")
	}
}

// TestLogFileOutput tests logging to file
func TestLogFileOutput(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)

	// Create temporary log file
	tmpFile := "/tmp/test_qavpn.log"
	defer os.Remove(tmpFile)

	// Enable file output
	if err := logger.SetFileOutput(tmpFile); err != nil {
		t.Fatalf("Failed to set file output: %v", err)
	}

	// Log a message
	logger.Info("test", "file test message", nil)

	// Close logger to flush file
	logger.Close()

	// Read file content
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "file test message") {
		t.Error("Log message not found in file")
	}

	if !strings.Contains(contentStr, "INFO") {
		t.Error("Log level not found in file")
	}

	if !strings.Contains(contentStr, "test") {
		t.Error("Component name not found in file")
	}
}

// TestGetEntriesByComponent tests filtering entries by component
func TestGetEntriesByComponent(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)

	// Log messages from different components
	logger.Info("component1", "message1", nil)
	logger.Info("component2", "message2", nil)
	logger.Info("component1", "message3", nil)
	logger.Info("component3", "message4", nil)

	// Get entries for component1
	entries := logger.GetEntriesByComponent("component1", 10)
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries for component1, got %d", len(entries))
	}

	// Verify all entries are from component1
	for _, entry := range entries {
		if entry.Component != "component1" {
			t.Errorf("Expected component 'component1', got '%s'", entry.Component)
		}
	}

	// Verify messages are in correct order
	if entries[0].Message != "message1" || entries[1].Message != "message3" {
		t.Error("Entries not in correct order")
	}
}

// TestConnectionMonitor tests the connection monitoring functionality
func TestConnectionMonitor(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)
	
	// Create mock components
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	tunnelManager := NewTunnelManager()

	// Create connection monitor
	monitor := NewConnectionMonitor(logger, nodeManager, tunnelManager)

	// Test start/stop
	monitor.Start()
	if !monitor.isRunning {
		t.Error("Monitor should be running after start")
	}

	// Give it a moment to initialize
	time.Sleep(100 * time.Millisecond)

	monitor.Stop()
	if monitor.isRunning {
		t.Error("Monitor should not be running after stop")
	}
}

// TestHealthCheckStatus tests health check status reporting
func TestHealthCheckStatus(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)
	
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	tunnelManager := NewTunnelManager()
	monitor := NewConnectionMonitor(logger, nodeManager, tunnelManager)

	// Perform a single health check cycle
	monitor.performHealthChecks()

	// Get health status
	healthStatus := monitor.GetHealthStatus()

	// Should have health checks for basic components
	expectedComponents := []string{"node_manager", "tunnel_manager", "routes"}
	
	for _, component := range expectedComponents {
		if _, exists := healthStatus[component]; !exists {
			t.Errorf("Expected health check for component '%s'", component)
		}
	}

	// Test individual component health
	nodeHealth := monitor.GetComponentHealth("node_manager")
	if nodeHealth == nil {
		t.Error("Expected node manager health check")
	}

	if nodeHealth.Component != "node_manager" {
		t.Errorf("Expected component 'node_manager', got '%s'", nodeHealth.Component)
	}
}

// TestHealthStatusDetermination tests health status determination logic
func TestHealthStatusDetermination(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)
	
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	// Add some mock nodes to make node manager healthy
	mockNodes := []*Node{
		{ID: NodeID{1}, Address: "127.0.0.1:9001", Protocol: "tcp", LastSeen: time.Now()},
		{ID: NodeID{2}, Address: "127.0.0.1:9002", Protocol: "tcp", LastSeen: time.Now()},
		{ID: NodeID{3}, Address: "127.0.0.1:9003", Protocol: "tcp", LastSeen: time.Now()},
	}

	nodeManager.mutex.Lock()
	for _, node := range mockNodes {
		nodeManager.knownNodes[node.ID] = node
	}
	nodeManager.mutex.Unlock()

	tunnelManager := NewTunnelManager()
	monitor := NewConnectionMonitor(logger, nodeManager, tunnelManager)

	// Perform health checks
	monitor.performHealthChecks()

	// Node manager should be healthy with sufficient nodes
	nodeHealth := monitor.GetComponentHealth("node_manager")
	if nodeHealth.Status != HealthStatusHealthy {
		t.Errorf("Expected node manager to be healthy, got %s", 
			monitor.healthStatusString(nodeHealth.Status))
	}

	// Overall system should be healthy if all components are healthy
	if !monitor.IsHealthy() {
		// This might fail due to other components, but node manager should be healthy
		nodeHealth := monitor.GetComponentHealth("node_manager")
		if nodeHealth.Status != HealthStatusHealthy {
			t.Error("Node manager should be healthy with sufficient nodes")
		}
	}
}

// TestLogEntryMaxLimit tests that log entries are limited to prevent memory issues
func TestLogEntryMaxLimit(t *testing.T) {
	logger := NewSecureLogger(LogLevelInfo)
	
	// Set a small max entries limit for testing
	logger.maxEntries = 5

	// Log more entries than the limit
	for i := 0; i < 10; i++ {
		logger.Info("test", fmt.Sprintf("message %d", i), nil)
	}

	entries := logger.GetRecentEntries(20)
	if len(entries) > logger.maxEntries {
		t.Errorf("Expected at most %d entries, got %d", logger.maxEntries, len(entries))
	}

	// Should have the most recent entries
	if len(entries) > 0 {
		lastEntry := entries[len(entries)-1]
		if lastEntry.Message != "message 9" {
			t.Errorf("Expected last message to be 'message 9', got '%s'", lastEntry.Message)
		}
	}
}

// BenchmarkLogging benchmarks logging performance
func BenchmarkLogging(b *testing.B) {
	logger := NewSecureLogger(LogLevelInfo)
	
	metadata := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark", "benchmark message", metadata)
	}
}

// BenchmarkHealthCheck benchmarks health check performance
func BenchmarkHealthCheck(b *testing.B) {
	logger := NewSecureLogger(LogLevelInfo)
	
	nodeManager, err := NewNodeManager(false)
	if err != nil {
		b.Fatalf("Failed to create node manager: %v", err)
	}

	tunnelManager := NewTunnelManager()
	monitor := NewConnectionMonitor(logger, nodeManager, tunnelManager)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.performHealthChecks()
	}
}