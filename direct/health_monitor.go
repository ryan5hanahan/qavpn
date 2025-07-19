package direct

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ConnectionHealthMonitorService manages health monitoring for direct connections
type ConnectionHealthMonitorService struct {
	connections       map[string]*MonitoredConnection
	checkInterval     time.Duration
	enabled           bool
	alertThresholds   *HealthAlertThresholds
	recoveryManager   *ConnectionRecoveryManager
	metrics          *HealthMonitorMetrics
	stopChan         chan struct{}
	mutex            sync.RWMutex
}

// MonitoredConnection represents a connection being monitored for health
type MonitoredConnection struct {
	connectionID      string
	tunnel           Tunnel
	healthStatus     ConnectionHealthStatus
	lastHealthCheck  time.Time
	consecutiveFailures int
	totalChecks      uint64
	successfulChecks uint64
	failedChecks     uint64
	averageLatency   time.Duration
	lastLatency      time.Duration
	qualityMetrics   *ConnectionQualityMetrics
	recoveryAttempts uint64
	lastRecoveryTime time.Time
	mutex            sync.RWMutex
}

// HealthAlertThresholds defines thresholds for health alerts
type HealthAlertThresholds struct {
	MaxConsecutiveFailures int           `json:"max_consecutive_failures"`
	MaxLatency            time.Duration `json:"max_latency"`
	MinSuccessRate        float64       `json:"min_success_rate"`
	MaxRecoveryAttempts   int           `json:"max_recovery_attempts"`
	RecoveryTimeout       time.Duration `json:"recovery_timeout"`
}

// ConnectionQualityMetrics tracks detailed connection quality metrics
type ConnectionQualityMetrics struct {
	Latency           time.Duration `json:"latency"`
	Jitter            time.Duration `json:"jitter"`
	PacketLoss        float64       `json:"packet_loss"`
	Throughput        float64       `json:"throughput_bps"`
	Stability         float64       `json:"stability_score"`
	LastMeasurement   time.Time     `json:"last_measurement"`
	mutex             sync.RWMutex
}

// ConnectionRecoveryManager handles automatic connection recovery
type ConnectionRecoveryManager struct {
	maxRetries        int
	baseDelay         time.Duration
	maxDelay          time.Duration
	backoffMultiplier float64
	jitterEnabled     bool
	recoveryStrategies []RecoveryStrategy
	mutex             sync.RWMutex
}

// RecoveryStrategy defines a strategy for connection recovery
type RecoveryStrategy struct {
	Name        string
	Priority    int
	MaxAttempts int
	Timeout     time.Duration
	Handler     RecoveryHandler
}

// RecoveryHandler is a function that attempts to recover a connection
type RecoveryHandler func(connection *MonitoredConnection) error

// HealthMonitorMetrics tracks overall health monitoring metrics
type HealthMonitorMetrics struct {
	TotalConnections     int       `json:"total_connections"`
	HealthyConnections   int       `json:"healthy_connections"`
	DegradedConnections  int       `json:"degraded_connections"`
	UnhealthyConnections int       `json:"unhealthy_connections"`
	FailedConnections    int       `json:"failed_connections"`
	TotalHealthChecks    uint64    `json:"total_health_checks"`
	SuccessfulChecks     uint64    `json:"successful_checks"`
	FailedChecks         uint64    `json:"failed_checks"`
	RecoveryAttempts     uint64    `json:"recovery_attempts"`
	SuccessfulRecoveries uint64    `json:"successful_recoveries"`
	LastUpdate           time.Time `json:"last_update"`
	mutex                sync.RWMutex
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	ConnectionID    string                    `json:"connection_id"`
	Status          ConnectionHealthStatus    `json:"status"`
	Latency         time.Duration            `json:"latency"`
	Error           error                    `json:"error,omitempty"`
	QualityMetrics  *ConnectionQualityMetrics `json:"quality_metrics"`
	Timestamp       time.Time                `json:"timestamp"`
	RecoveryNeeded  bool                     `json:"recovery_needed"`
}

// RecoveryResult represents the result of a recovery attempt
type RecoveryResult struct {
	ConnectionID     string    `json:"connection_id"`
	Strategy         string    `json:"strategy"`
	Success          bool      `json:"success"`
	Error            error     `json:"error,omitempty"`
	AttemptNumber    int       `json:"attempt_number"`
	Duration         time.Duration `json:"duration"`
	Timestamp        time.Time `json:"timestamp"`
}

// NewConnectionHealthMonitorService creates a new health monitoring service
func NewConnectionHealthMonitorService(checkInterval time.Duration) *ConnectionHealthMonitorService {
	return &ConnectionHealthMonitorService{
		connections:   make(map[string]*MonitoredConnection),
		checkInterval: checkInterval,
		enabled:       true,
		alertThresholds: &HealthAlertThresholds{
			MaxConsecutiveFailures: 3,
			MaxLatency:            5 * time.Second,
			MinSuccessRate:        0.8,
			MaxRecoveryAttempts:   5,
			RecoveryTimeout:       30 * time.Second,
		},
		recoveryManager: &ConnectionRecoveryManager{
			maxRetries:        5,
			baseDelay:         1 * time.Second,
			maxDelay:          30 * time.Second,
			backoffMultiplier: 2.0,
			jitterEnabled:     true,
			recoveryStrategies: []RecoveryStrategy{
				{
					Name:        "reconnect",
					Priority:    1,
					MaxAttempts: 3,
					Timeout:     10 * time.Second,
					Handler:     reconnectRecoveryHandler,
				},
				{
					Name:        "reset_connection",
					Priority:    2,
					MaxAttempts: 2,
					Timeout:     15 * time.Second,
					Handler:     resetConnectionRecoveryHandler,
				},
			},
		},
		metrics:  &HealthMonitorMetrics{},
		stopChan: make(chan struct{}),
	}
}

// Start begins the health monitoring service
func (hms *ConnectionHealthMonitorService) Start() error {
	hms.mutex.Lock()
	defer hms.mutex.Unlock()

	if !hms.enabled {
		return errors.New("health monitoring service is disabled")
	}

	go hms.monitoringLoop()
	return nil
}

// Stop stops the health monitoring service
func (hms *ConnectionHealthMonitorService) Stop() error {
	hms.mutex.Lock()
	defer hms.mutex.Unlock()

	close(hms.stopChan)
	hms.enabled = false
	return nil
}

// AddConnection adds a connection to be monitored
func (hms *ConnectionHealthMonitorService) AddConnection(connectionID string, tunnel Tunnel) error {
	hms.mutex.Lock()
	defer hms.mutex.Unlock()

	if _, exists := hms.connections[connectionID]; exists {
		return fmt.Errorf("connection %s is already being monitored", connectionID)
	}

	monitoredConn := &MonitoredConnection{
		connectionID:    connectionID,
		tunnel:         tunnel,
		healthStatus:   HealthStatusHealthy,
		lastHealthCheck: time.Now(),
		qualityMetrics: &ConnectionQualityMetrics{
			LastMeasurement: time.Now(),
		},
	}

	hms.connections[connectionID] = monitoredConn
	hms.updateMetrics()

	return nil
}

// RemoveConnection removes a connection from monitoring
func (hms *ConnectionHealthMonitorService) RemoveConnection(connectionID string) error {
	hms.mutex.Lock()
	defer hms.mutex.Unlock()

	if _, exists := hms.connections[connectionID]; !exists {
		return fmt.Errorf("connection %s is not being monitored", connectionID)
	}

	delete(hms.connections, connectionID)
	hms.updateMetrics()

	return nil
}

// GetConnectionHealth returns the health status of a specific connection
func (hms *ConnectionHealthMonitorService) GetConnectionHealth(connectionID string) (*HealthCheckResult, error) {
	hms.mutex.RLock()
	defer hms.mutex.RUnlock()

	conn, exists := hms.connections[connectionID]
	if !exists {
		return nil, fmt.Errorf("connection %s is not being monitored", connectionID)
	}

	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	return &HealthCheckResult{
		ConnectionID:   connectionID,
		Status:         conn.healthStatus,
		Latency:        conn.lastLatency,
		QualityMetrics: conn.qualityMetrics,
		Timestamp:      conn.lastHealthCheck,
		RecoveryNeeded: conn.consecutiveFailures >= hms.alertThresholds.MaxConsecutiveFailures,
	}, nil
}

// GetAllConnectionsHealth returns health status for all monitored connections
func (hms *ConnectionHealthMonitorService) GetAllConnectionsHealth() ([]*HealthCheckResult, error) {
	hms.mutex.RLock()
	defer hms.mutex.RUnlock()

	results := make([]*HealthCheckResult, 0, len(hms.connections))

	for connectionID, conn := range hms.connections {
		conn.mutex.RLock()
		result := &HealthCheckResult{
			ConnectionID:   connectionID,
			Status:         conn.healthStatus,
			Latency:        conn.lastLatency,
			QualityMetrics: conn.qualityMetrics,
			Timestamp:      conn.lastHealthCheck,
			RecoveryNeeded: conn.consecutiveFailures >= hms.alertThresholds.MaxConsecutiveFailures,
		}
		conn.mutex.RUnlock()

		results = append(results, result)
	}

	return results, nil
}

// PerformHealthCheck performs a health check on a specific connection
func (hms *ConnectionHealthMonitorService) PerformHealthCheck(connectionID string) (*HealthCheckResult, error) {
	hms.mutex.RLock()
	conn, exists := hms.connections[connectionID]
	hms.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection %s is not being monitored", connectionID)
	}

	result, err := hms.performHealthCheckOnConnection(conn)
	if err == nil {
		hms.updateMetrics()
	}
	return result, err
}

// GetMetrics returns overall health monitoring metrics
func (hms *ConnectionHealthMonitorService) GetMetrics() *HealthMonitorMetrics {
	hms.metrics.mutex.RLock()
	defer hms.metrics.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &HealthMonitorMetrics{
		TotalConnections:     hms.metrics.TotalConnections,
		HealthyConnections:   hms.metrics.HealthyConnections,
		DegradedConnections:  hms.metrics.DegradedConnections,
		UnhealthyConnections: hms.metrics.UnhealthyConnections,
		FailedConnections:    hms.metrics.FailedConnections,
		TotalHealthChecks:    hms.metrics.TotalHealthChecks,
		SuccessfulChecks:     hms.metrics.SuccessfulChecks,
		FailedChecks:         hms.metrics.FailedChecks,
		RecoveryAttempts:     hms.metrics.RecoveryAttempts,
		SuccessfulRecoveries: hms.metrics.SuccessfulRecoveries,
		LastUpdate:           hms.metrics.LastUpdate,
	}
}

// SetAlertThresholds updates the alert thresholds
func (hms *ConnectionHealthMonitorService) SetAlertThresholds(thresholds *HealthAlertThresholds) {
	hms.mutex.Lock()
	defer hms.mutex.Unlock()

	hms.alertThresholds = thresholds
}

// monitoringLoop is the main monitoring loop
func (hms *ConnectionHealthMonitorService) monitoringLoop() {
	ticker := time.NewTicker(hms.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hms.performAllHealthChecks()
		case <-hms.stopChan:
			return
		}
	}
}

// performAllHealthChecks performs health checks on all monitored connections
func (hms *ConnectionHealthMonitorService) performAllHealthChecks() {
	hms.mutex.RLock()
	connections := make([]*MonitoredConnection, 0, len(hms.connections))
	for _, conn := range hms.connections {
		connections = append(connections, conn)
	}
	hms.mutex.RUnlock()

	for _, conn := range connections {
		result, err := hms.performHealthCheckOnConnection(conn)
		if err != nil {
			continue
		}

		// Check if recovery is needed
		if result.RecoveryNeeded {
			go hms.attemptRecovery(conn)
		}
	}

	hms.updateMetrics()
}

// performHealthCheckOnConnection performs a health check on a single connection
func (hms *ConnectionHealthMonitorService) performHealthCheckOnConnection(conn *MonitoredConnection) (*HealthCheckResult, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	startTime := time.Now()
	
	// Perform the actual health check by testing the tunnel
	healthCheckData := []byte("health_check")
	err := conn.tunnel.SendData(healthCheckData)
	
	latency := time.Since(startTime)
	conn.lastHealthCheck = time.Now()
	conn.totalChecks++

	result := &HealthCheckResult{
		ConnectionID: conn.connectionID,
		Latency:      latency,
		Timestamp:    conn.lastHealthCheck,
	}

	if err != nil {
		// Health check failed
		conn.consecutiveFailures++
		conn.failedChecks++
		conn.lastLatency = latency
		
		// Update health status based on consecutive failures
		if conn.consecutiveFailures >= hms.alertThresholds.MaxConsecutiveFailures {
			conn.healthStatus = HealthStatusFailed
		} else if conn.consecutiveFailures >= hms.alertThresholds.MaxConsecutiveFailures/2 {
			conn.healthStatus = HealthStatusDegraded
		} else {
			conn.healthStatus = HealthStatusUnhealthy
		}

		result.Status = conn.healthStatus
		result.Error = err
		result.RecoveryNeeded = conn.consecutiveFailures >= hms.alertThresholds.MaxConsecutiveFailures
	} else {
		// Health check succeeded
		conn.consecutiveFailures = 0
		conn.successfulChecks++
		conn.lastLatency = latency
		conn.healthStatus = HealthStatusHealthy

		// Update quality metrics
		hms.updateQualityMetrics(conn, latency)

		result.Status = conn.healthStatus
		result.QualityMetrics = conn.qualityMetrics
		result.RecoveryNeeded = false
	}

	return result, nil
}

// updateQualityMetrics updates connection quality metrics
func (hms *ConnectionHealthMonitorService) updateQualityMetrics(conn *MonitoredConnection, latency time.Duration) {
	conn.qualityMetrics.mutex.Lock()
	defer conn.qualityMetrics.mutex.Unlock()

	// Update latency
	conn.qualityMetrics.Latency = latency

	// Calculate jitter (variation in latency)
	if conn.averageLatency > 0 {
		jitter := latency - conn.averageLatency
		if jitter < 0 {
			jitter = -jitter
		}
		conn.qualityMetrics.Jitter = jitter
	}

	// Update average latency
	if conn.totalChecks > 0 {
		conn.averageLatency = time.Duration(
			(int64(conn.averageLatency)*int64(conn.totalChecks-1) + int64(latency)) / int64(conn.totalChecks))
	}

	// Calculate success rate and stability
	if conn.totalChecks > 0 {
		successRate := float64(conn.successfulChecks) / float64(conn.totalChecks)
		conn.qualityMetrics.Stability = successRate
	}

	conn.qualityMetrics.LastMeasurement = time.Now()
}

// attemptRecovery attempts to recover a failed connection
func (hms *ConnectionHealthMonitorService) attemptRecovery(conn *MonitoredConnection) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.recoveryAttempts >= uint64(hms.alertThresholds.MaxRecoveryAttempts) {
		return // Max recovery attempts reached
	}

	conn.recoveryAttempts++
	conn.lastRecoveryTime = time.Now()

	hms.metrics.mutex.Lock()
	hms.metrics.RecoveryAttempts++
	hms.metrics.mutex.Unlock()

	// Try each recovery strategy in order of priority
	for _, strategy := range hms.recoveryManager.recoveryStrategies {
		if int(conn.recoveryAttempts) > strategy.MaxAttempts {
			continue
		}

		startTime := time.Now()
		err := strategy.Handler(conn)
		duration := time.Since(startTime)

		result := &RecoveryResult{
			ConnectionID:  conn.connectionID,
			Strategy:      strategy.Name,
			Success:       err == nil,
			Error:         err,
			AttemptNumber: int(conn.recoveryAttempts),
			Duration:      duration,
			Timestamp:     time.Now(),
		}

		if result.Success {
			// Recovery successful
			conn.consecutiveFailures = 0
			conn.healthStatus = HealthStatusHealthy
			
			hms.metrics.mutex.Lock()
			hms.metrics.SuccessfulRecoveries++
			hms.metrics.mutex.Unlock()
			
			return
		}
	}
}

// updateMetrics updates the overall health monitoring metrics
func (hms *ConnectionHealthMonitorService) updateMetrics() {
	hms.metrics.mutex.Lock()
	defer hms.metrics.mutex.Unlock()

	hms.metrics.TotalConnections = len(hms.connections)
	hms.metrics.HealthyConnections = 0
	hms.metrics.DegradedConnections = 0
	hms.metrics.UnhealthyConnections = 0
	hms.metrics.FailedConnections = 0

	var totalChecks, successfulChecks, failedChecks uint64

	for _, conn := range hms.connections {
		conn.mutex.RLock()
		switch conn.healthStatus {
		case HealthStatusHealthy:
			hms.metrics.HealthyConnections++
		case HealthStatusDegraded:
			hms.metrics.DegradedConnections++
		case HealthStatusUnhealthy:
			hms.metrics.UnhealthyConnections++
		case HealthStatusFailed:
			hms.metrics.FailedConnections++
		}

		totalChecks += conn.totalChecks
		successfulChecks += conn.successfulChecks
		failedChecks += conn.failedChecks
		conn.mutex.RUnlock()
	}

	hms.metrics.TotalHealthChecks = totalChecks
	hms.metrics.SuccessfulChecks = successfulChecks
	hms.metrics.FailedChecks = failedChecks
	hms.metrics.LastUpdate = time.Now()
}

// Recovery handler implementations

// reconnectRecoveryHandler attempts to reconnect a failed connection
func reconnectRecoveryHandler(conn *MonitoredConnection) error {
	// This would implement actual reconnection logic
	// For now, just check if the tunnel is still active
	if !conn.tunnel.IsActive() {
		return errors.New("tunnel is not active, reconnection needed")
	}
	return nil
}

// resetConnectionRecoveryHandler attempts to reset a connection
func resetConnectionRecoveryHandler(conn *MonitoredConnection) error {
	// This would implement connection reset logic
	// For now, just perform a basic health check
	testData := []byte("reset_test")
	return conn.tunnel.SendData(testData)
}

// ConnectionHealthReport provides a comprehensive health report
type ConnectionHealthReport struct {
	Timestamp           time.Time                `json:"timestamp"`
	OverallMetrics      *HealthMonitorMetrics    `json:"overall_metrics"`
	ConnectionDetails   []*HealthCheckResult     `json:"connection_details"`
	AlertsTriggered     []string                 `json:"alerts_triggered"`
	RecoveryActions     []*RecoveryResult        `json:"recovery_actions"`
	Recommendations     []string                 `json:"recommendations"`
}

// GenerateHealthReport generates a comprehensive health report
func (hms *ConnectionHealthMonitorService) GenerateHealthReport() (*ConnectionHealthReport, error) {
	connections, err := hms.GetAllConnectionsHealth()
	if err != nil {
		return nil, fmt.Errorf("failed to get connection health: %w", err)
	}

	metrics := hms.GetMetrics()
	
	report := &ConnectionHealthReport{
		Timestamp:         time.Now(),
		OverallMetrics:    metrics,
		ConnectionDetails: connections,
		AlertsTriggered:   []string{},
		RecoveryActions:   []*RecoveryResult{},
		Recommendations:   []string{},
	}

	// Generate alerts and recommendations
	hms.generateAlertsAndRecommendations(report)

	return report, nil
}

// generateAlertsAndRecommendations generates alerts and recommendations for the health report
func (hms *ConnectionHealthMonitorService) generateAlertsAndRecommendations(report *ConnectionHealthReport) {
	// Check for alerts
	if report.OverallMetrics.FailedConnections > 0 {
		report.AlertsTriggered = append(report.AlertsTriggered, 
			fmt.Sprintf("%d connections have failed", report.OverallMetrics.FailedConnections))
	}

	if report.OverallMetrics.DegradedConnections > 0 {
		report.AlertsTriggered = append(report.AlertsTriggered, 
			fmt.Sprintf("%d connections are degraded", report.OverallMetrics.DegradedConnections))
	}

	// Generate recommendations
	if report.OverallMetrics.TotalConnections > 0 {
		successRate := float64(report.OverallMetrics.SuccessfulChecks) / float64(report.OverallMetrics.TotalHealthChecks)
		if successRate < 0.9 {
			report.Recommendations = append(report.Recommendations, 
				"Consider investigating network connectivity issues")
		}
	}

	if report.OverallMetrics.RecoveryAttempts > report.OverallMetrics.SuccessfulRecoveries*2 {
		report.Recommendations = append(report.Recommendations, 
			"High recovery failure rate detected, consider reviewing recovery strategies")
	}
}