package direct

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// MockTunnelForHealth implements the Tunnel interface for health monitoring tests
type MockTunnelForHealth struct {
	isActive    bool
	sendError   error
	sendDelay   time.Duration
	callCount   int
}

func (mt *MockTunnelForHealth) SendData(data []byte) error {
	mt.callCount++
	if mt.sendDelay > 0 {
		time.Sleep(mt.sendDelay)
	}
	return mt.sendError
}

func (mt *MockTunnelForHealth) ReceiveData() ([]byte, error) {
	return []byte("mock_data"), nil
}

func (mt *MockTunnelForHealth) Close() error {
	mt.isActive = false
	return nil
}

func (mt *MockTunnelForHealth) IsActive() bool {
	return mt.isActive
}

func TestNewConnectionHealthMonitorService(t *testing.T) {
	checkInterval := 5 * time.Second
	service := NewConnectionHealthMonitorService(checkInterval)

	if service == nil {
		t.Fatal("Health monitor service should not be nil")
	}

	if service.checkInterval != checkInterval {
		t.Errorf("Expected check interval: %v, got: %v", checkInterval, service.checkInterval)
	}

	if !service.enabled {
		t.Error("Service should be enabled by default")
	}

	if service.alertThresholds == nil {
		t.Error("Alert thresholds should be initialized")
	}

	if service.recoveryManager == nil {
		t.Error("Recovery manager should be initialized")
	}

	if service.metrics == nil {
		t.Error("Metrics should be initialized")
	}
}

func TestAddRemoveConnection(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)
	mockTunnel := &MockTunnelForHealth{isActive: true}

	// Test adding connection
	err := service.AddConnection("test-conn-1", mockTunnel)
	if err != nil {
		t.Fatalf("Failed to add connection: %v", err)
	}

	// Verify connection was added
	metrics := service.GetMetrics()
	if metrics.TotalConnections != 1 {
		t.Errorf("Expected 1 connection, got: %d", metrics.TotalConnections)
	}

	// Test adding duplicate connection
	err = service.AddConnection("test-conn-1", mockTunnel)
	if err == nil {
		t.Error("Should not allow duplicate connection IDs")
	}

	// Test removing connection
	err = service.RemoveConnection("test-conn-1")
	if err != nil {
		t.Fatalf("Failed to remove connection: %v", err)
	}

	// Verify connection was removed
	metrics = service.GetMetrics()
	if metrics.TotalConnections != 0 {
		t.Errorf("Expected 0 connections, got: %d", metrics.TotalConnections)
	}

	// Test removing non-existent connection
	err = service.RemoveConnection("non-existent")
	if err == nil {
		t.Error("Should return error for non-existent connection")
	}
}

func TestHealthCheckSuccess(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)
	mockTunnel := &MockTunnelForHealth{
		isActive:  true,
		sendDelay: 10 * time.Millisecond, // Small delay to test latency measurement
	}

	// Add connection
	err := service.AddConnection("test-conn", mockTunnel)
	if err != nil {
		t.Fatalf("Failed to add connection: %v", err)
	}

	// Perform health check
	result, err := service.PerformHealthCheck("test-conn")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Verify results
	if result.Status != HealthStatusHealthy {
		t.Errorf("Expected healthy status, got: %v", result.Status)
	}

	if result.Latency <= 0 {
		t.Error("Latency should be positive")
	}

	if result.Error != nil {
		t.Errorf("Expected no error, got: %v", result.Error)
	}

	if result.RecoveryNeeded {
		t.Error("Recovery should not be needed for successful health check")
	}

	// Verify tunnel was called
	if mockTunnel.callCount != 1 {
		t.Errorf("Expected 1 call to tunnel, got: %d", mockTunnel.callCount)
	}
}

func TestHealthCheckFailure(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)
	mockTunnel := &MockTunnelForHealth{
		isActive:  true,
		sendError: errors.New("connection failed"),
	}

	// Add connection
	err := service.AddConnection("test-conn", mockTunnel)
	if err != nil {
		t.Fatalf("Failed to add connection: %v", err)
	}

	// Perform multiple health checks to trigger failure threshold
	for i := 0; i < 3; i++ {
		result, err := service.PerformHealthCheck("test-conn")
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}

		if result.Error == nil {
			t.Error("Expected error in health check result")
		}

		if i == 2 { // After 3 failures (threshold)
			if result.Status != HealthStatusFailed {
				t.Errorf("Expected failed status after %d failures, got: %v", i+1, result.Status)
			}

			if !result.RecoveryNeeded {
				t.Error("Recovery should be needed after multiple failures")
			}
		}
	}
}

func TestGetConnectionHealth(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)
	mockTunnel := &MockTunnelForHealth{isActive: true}

	// Add connection
	err := service.AddConnection("test-conn", mockTunnel)
	if err != nil {
		t.Fatalf("Failed to add connection: %v", err)
	}

	// Get connection health
	health, err := service.GetConnectionHealth("test-conn")
	if err != nil {
		t.Fatalf("Failed to get connection health: %v", err)
	}

	if health.ConnectionID != "test-conn" {
		t.Errorf("Expected connection ID 'test-conn', got: %s", health.ConnectionID)
	}

	if health.Status != HealthStatusHealthy {
		t.Errorf("Expected healthy status, got: %v", health.Status)
	}

	// Test non-existent connection
	_, err = service.GetConnectionHealth("non-existent")
	if err == nil {
		t.Error("Should return error for non-existent connection")
	}
}

func TestGetAllConnectionsHealth(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)

	// Add multiple connections
	for i := 0; i < 3; i++ {
		mockTunnel := &MockTunnelForHealth{isActive: true}
		connID := fmt.Sprintf("test-conn-%d", i)
		err := service.AddConnection(connID, mockTunnel)
		if err != nil {
			t.Fatalf("Failed to add connection %s: %v", connID, err)
		}
	}

	// Get all connections health
	allHealth, err := service.GetAllConnectionsHealth()
	if err != nil {
		t.Fatalf("Failed to get all connections health: %v", err)
	}

	if len(allHealth) != 3 {
		t.Errorf("Expected 3 connections, got: %d", len(allHealth))
	}

	// Verify each connection
	for i, health := range allHealth {
		expectedID := fmt.Sprintf("test-conn-%d", i)
		if health.ConnectionID != expectedID {
			t.Errorf("Expected connection ID %s, got: %s", expectedID, health.ConnectionID)
		}

		if health.Status != HealthStatusHealthy {
			t.Errorf("Expected healthy status for %s, got: %v", health.ConnectionID, health.Status)
		}
	}
}

func TestHealthMonitorMetrics(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)

	// Add connections with different health states
	healthyTunnel := &MockTunnelForHealth{isActive: true}
	failedTunnel := &MockTunnelForHealth{isActive: true, sendError: errors.New("failed")}

	service.AddConnection("healthy-conn", healthyTunnel)
	service.AddConnection("failed-conn", failedTunnel)

	// Perform health checks to generate different states
	service.PerformHealthCheck("healthy-conn")
	
	// Perform multiple failed checks to trigger failure state
	for i := 0; i < 3; i++ {
		service.PerformHealthCheck("failed-conn")
	}

	// Get metrics (metrics are updated in PerformHealthCheck)
	metrics := service.GetMetrics()

	if metrics.TotalConnections != 2 {
		t.Errorf("Expected 2 total connections, got: %d", metrics.TotalConnections)
	}

	if metrics.HealthyConnections != 1 {
		t.Errorf("Expected 1 healthy connection, got: %d", metrics.HealthyConnections)
	}

	if metrics.FailedConnections != 1 {
		t.Errorf("Expected 1 failed connection, got: %d", metrics.FailedConnections)
	}

	if metrics.TotalHealthChecks != 4 { // 1 + 3 checks
		t.Errorf("Expected 4 total health checks, got: %d", metrics.TotalHealthChecks)
	}

	if metrics.SuccessfulChecks != 1 {
		t.Errorf("Expected 1 successful check, got: %d", metrics.SuccessfulChecks)
	}

	if metrics.FailedChecks != 3 {
		t.Errorf("Expected 3 failed checks, got: %d", metrics.FailedChecks)
	}
}

func TestSetAlertThresholds(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)

	// Set custom thresholds
	customThresholds := &HealthAlertThresholds{
		MaxConsecutiveFailures: 5,
		MaxLatency:            10 * time.Second,
		MinSuccessRate:        0.9,
		MaxRecoveryAttempts:   10,
		RecoveryTimeout:       60 * time.Second,
	}

	service.SetAlertThresholds(customThresholds)

	// Verify thresholds were set
	if service.alertThresholds.MaxConsecutiveFailures != 5 {
		t.Errorf("Expected max consecutive failures: 5, got: %d", service.alertThresholds.MaxConsecutiveFailures)
	}

	if service.alertThresholds.MaxLatency != 10*time.Second {
		t.Errorf("Expected max latency: 10s, got: %v", service.alertThresholds.MaxLatency)
	}
}

func TestGenerateHealthReport(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)

	// Add connections
	healthyTunnel := &MockTunnelForHealth{isActive: true}
	failedTunnel := &MockTunnelForHealth{isActive: true, sendError: errors.New("failed")}

	service.AddConnection("healthy-conn", healthyTunnel)
	service.AddConnection("failed-conn", failedTunnel)

	// Perform health checks
	service.PerformHealthCheck("healthy-conn")
	for i := 0; i < 3; i++ {
		service.PerformHealthCheck("failed-conn")
	}

	// Generate health report
	report, err := service.GenerateHealthReport()
	if err != nil {
		t.Fatalf("Failed to generate health report: %v", err)
	}

	if report == nil {
		t.Fatal("Health report should not be nil")
	}

	if report.OverallMetrics == nil {
		t.Error("Overall metrics should not be nil")
	}

	if len(report.ConnectionDetails) != 2 {
		t.Errorf("Expected 2 connection details, got: %d", len(report.ConnectionDetails))
	}

	if len(report.AlertsTriggered) == 0 {
		t.Error("Should have alerts for failed connections")
	}

	if len(report.Recommendations) == 0 {
		t.Error("Should have recommendations for poor health")
	}
}

func TestConnectionQualityMetrics(t *testing.T) {
	service := NewConnectionHealthMonitorService(1 * time.Second)
	mockTunnel := &MockTunnelForHealth{
		isActive:  true,
		sendDelay: 50 * time.Millisecond, // Consistent delay for testing
	}

	// Add connection
	err := service.AddConnection("test-conn", mockTunnel)
	if err != nil {
		t.Fatalf("Failed to add connection: %v", err)
	}

	// Perform multiple health checks to build quality metrics
	for i := 0; i < 5; i++ {
		_, err := service.PerformHealthCheck("test-conn")
		if err != nil {
			t.Fatalf("Health check %d failed: %v", i, err)
		}
	}

	// Get connection health to check quality metrics
	health, err := service.GetConnectionHealth("test-conn")
	if err != nil {
		t.Fatalf("Failed to get connection health: %v", err)
	}

	if health.QualityMetrics == nil {
		t.Fatal("Quality metrics should not be nil")
	}

	if health.QualityMetrics.Latency <= 0 {
		t.Error("Latency should be positive")
	}

	if health.QualityMetrics.Stability != 1.0 {
		t.Errorf("Expected stability 1.0 (100%% success), got: %f", health.QualityMetrics.Stability)
	}

	if health.QualityMetrics.LastMeasurement.IsZero() {
		t.Error("Last measurement timestamp should not be zero")
	}
}

func TestRecoveryHandlers(t *testing.T) {
	// Test reconnect recovery handler
	mockTunnel := &MockTunnelForHealth{isActive: true}
	conn := &MonitoredConnection{
		connectionID: "test-conn",
		tunnel:      mockTunnel,
	}

	err := reconnectRecoveryHandler(conn)
	if err != nil {
		t.Errorf("Reconnect recovery should succeed for active tunnel: %v", err)
	}

	// Test with inactive tunnel
	mockTunnel.isActive = false
	err = reconnectRecoveryHandler(conn)
	if err == nil {
		t.Error("Reconnect recovery should fail for inactive tunnel")
	}

	// Test reset connection recovery handler
	mockTunnel.isActive = true
	err = resetConnectionRecoveryHandler(conn)
	if err != nil {
		t.Errorf("Reset connection recovery should succeed: %v", err)
	}

	// Test with send error
	mockTunnel.sendError = errors.New("send failed")
	err = resetConnectionRecoveryHandler(conn)
	if err == nil {
		t.Error("Reset connection recovery should fail when send fails")
	}
}

func BenchmarkHealthCheck(b *testing.B) {
	service := NewConnectionHealthMonitorService(1 * time.Second)
	mockTunnel := &MockTunnelForHealth{isActive: true}

	service.AddConnection("bench-conn", mockTunnel)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := service.PerformHealthCheck("bench-conn")
		if err != nil {
			b.Fatalf("Health check failed: %v", err)
		}
	}
}

func BenchmarkMultipleHealthChecks(b *testing.B) {
	service := NewConnectionHealthMonitorService(1 * time.Second)

	// Add multiple connections
	for i := 0; i < 10; i++ {
		mockTunnel := &MockTunnelForHealth{isActive: true}
		connID := fmt.Sprintf("bench-conn-%d", i)
		service.AddConnection(connID, mockTunnel)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := service.GetAllConnectionsHealth()
		if err != nil {
			b.Fatalf("Get all connections health failed: %v", err)
		}
	}
}