package direct

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// OPSECSettings represents OPSEC configuration for connection profiles
type OPSECSettings struct {
	EnableTrafficObfuscation bool          `json:"enable_traffic_obfuscation"`
	EnableTimingObfuscation  bool          `json:"enable_timing_obfuscation"`
	ConnectionDelayMin       time.Duration `json:"connection_delay_min"`
	ConnectionDelayMax       time.Duration `json:"connection_delay_max"`
	RetryDelayBase          time.Duration `json:"retry_delay_base"`
	RetryDelayMax           time.Duration `json:"retry_delay_max"`
}


// RetryDecision represents a decision about whether to retry a connection
type RetryDecision struct {
	ShouldRetry     bool          `json:"should_retry"`
	Delay           time.Duration `json:"delay"`
	Reason          string        `json:"reason"`
	RiskLevel       string        `json:"risk_level"`
	Recommendations []string      `json:"recommendations,omitempty"`
}

// ConnectionHealth represents the health status of a connection
type ConnectionHealth struct {
	ConnectionID  string        `json:"connection_id"`
	Status        string        `json:"status"` // "healthy", "degraded", "unhealthy"
	SuccessCount  uint64        `json:"success_count"`
	ErrorCount    uint64        `json:"error_count"`
	HealthScore   float64       `json:"health_score"`
	LastCheck     time.Time     `json:"last_check"`
	AverageLatency time.Duration `json:"average_latency"`
}


// AuditEvent represents a security audit event
type AuditEvent struct {
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	RiskLevel   string                 `json:"risk_level"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HealthSummary represents overall health summary
type HealthSummary struct {
	TotalConnections     int `json:"total_connections"`
	HealthyConnections   int `json:"healthy_connections"`
	DegradedConnections  int `json:"degraded_connections"`
	UnhealthyConnections int `json:"unhealthy_connections"`
}


// ErrorSummary represents a summary of errors
type ErrorSummary struct {
	TotalErrors    int            `json:"total_errors"`
	ErrorsByType   map[string]int `json:"errors_by_type"`
	RecentErrors   []string       `json:"recent_errors"`
	LastErrorTime  time.Time      `json:"last_error_time"`
}

// RetryManager interface for managing connection retries
type RetryManager interface {
	ShouldRetryConnection(connectionID string, attemptCount int, lastError error, remoteAddr string) (*RetryDecision, error)
	CleanupRetryHistory(maxAge time.Duration)
	GetRetryStatistics() *RetryStatistics
}

// RetryStatistics represents retry statistics
type RetryStatistics struct {
	ActiveConnections              int     `json:"active_connections"`
	TotalAttempts                 int     `json:"total_attempts"`
	AverageAttemptsPerConnection  float64 `json:"average_attempts_per_connection"`
	SuccessfulConnections         int     `json:"successful_connections"`
	FailedConnections            int     `json:"failed_connections"`
}

// ConnectionHealthMonitor interface for monitoring connection health
type ConnectionHealthMonitor interface {
	UpdateHealth(connectionID string, latency time.Duration, success bool)
	GetHealth(connectionID string) *ConnectionHealth
	GetHealthSummary() *HealthSummary
}

// OPSECLogger interface for secure logging
type OPSECLogger interface {
	LogConnectionEvent(connectionID, eventType, message string, metadata map[string]interface{})
	LogRetryEvent(connectionID string, attemptCount int, decision *RetryDecision, err error)
	LogSecurityEvent(eventType, description, riskLevel string, metadata map[string]interface{})
	GetAuditTrail() []*AuditEvent
	UpdateConnectionHealth(connectionID string, latency time.Duration, success bool)
	GetConnectionHealth(connectionID string) *ConnectionHealth
	GetHealthSummary() *HealthSummary
}

// Helper functions for integration tests

// NewConnectionHealthMonitor creates a new connection health monitor
func NewConnectionHealthMonitor() ConnectionHealthMonitor {
	return &connectionHealthMonitor{
		healthData: make(map[string]*ConnectionHealth),
		alertThresholds: &healthAlertThresholds{
			MaxErrorRate:     0.1,  // 10% error rate
			MinHealthScore:   0.7,  // 70% health score
			MaxLatency:       5 * time.Second,
		},
	}
}

type connectionHealthMonitor struct {
	healthData      map[string]*ConnectionHealth
	alertThresholds *healthAlertThresholds
	mutex           sync.RWMutex
}

type healthAlertThresholds struct {
	MaxErrorRate   float64
	MinHealthScore float64
	MaxLatency     time.Duration
}

func (c *connectionHealthMonitor) UpdateHealth(connectionID string, latency time.Duration, success bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	health, exists := c.healthData[connectionID]
	if !exists {
		health = &ConnectionHealth{
			ConnectionID: connectionID,
			Status:       "healthy",
			LastCheck:    time.Now(),
		}
		c.healthData[connectionID] = health
	}

	if success {
		health.SuccessCount++
	} else {
		health.ErrorCount++
	}

	// Update average latency
	if health.AverageLatency == 0 {
		health.AverageLatency = latency
	} else {
		health.AverageLatency = (health.AverageLatency + latency) / 2
	}

	// Calculate health score
	totalRequests := health.SuccessCount + health.ErrorCount
	if totalRequests > 0 {
		health.HealthScore = float64(health.SuccessCount) / float64(totalRequests)
	}

	// Update status based on health score and error rate
	errorRate := float64(health.ErrorCount) / float64(totalRequests)
	if errorRate > c.alertThresholds.MaxErrorRate || health.HealthScore < c.alertThresholds.MinHealthScore {
		health.Status = "degraded"
	} else {
		health.Status = "healthy"
	}

	health.LastCheck = time.Now()
}

func (c *connectionHealthMonitor) GetHealth(connectionID string) *ConnectionHealth {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	health, exists := c.healthData[connectionID]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modification
	return &ConnectionHealth{
		ConnectionID:   health.ConnectionID,
		Status:         health.Status,
		SuccessCount:   health.SuccessCount,
		ErrorCount:     health.ErrorCount,
		HealthScore:    health.HealthScore,
		LastCheck:      health.LastCheck,
		AverageLatency: health.AverageLatency,
	}
}

func (c *connectionHealthMonitor) GetHealthSummary() *HealthSummary {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	summary := &HealthSummary{}
	for _, health := range c.healthData {
		summary.TotalConnections++
		switch health.Status {
		case "healthy":
			summary.HealthyConnections++
		case "degraded":
			summary.DegradedConnections++
		default:
			summary.UnhealthyConnections++
		}
	}

	return summary
}
