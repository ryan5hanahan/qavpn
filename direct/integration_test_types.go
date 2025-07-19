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

// DirectConnection interface for integration testing
type DirectConnection interface {
	SendData(data []byte) error
	ReceiveData() ([]byte, error)
	Close() error
	IsActive() bool
	GetMetrics() *ConnectionMetrics
}

// ConnectionMetrics represents connection performance metrics
type ConnectionMetrics struct {
	BytesSent       uint64        `json:"bytes_sent"`
	BytesReceived   uint64        `json:"bytes_received"`
	PacketsSent     uint64        `json:"packets_sent"`
	PacketsReceived uint64        `json:"packets_received"`
	ConnectionTime  time.Duration `json:"connection_time"`
	LastActivity    time.Time     `json:"last_activity"`
	ErrorCount      uint64        `json:"error_count"`
	Throughput      float64       `json:"throughput_bps"`
}

// MultiplexChannel interface for tunnel multiplexing
type MultiplexChannel interface {
	SendData(data []byte) error
	ReceiveData() ([]byte, error)
	Close() error
	IsActive() bool
	GetChannelID() uint32
	GetStats() *ChannelStats
}

// ChannelStats represents statistics for a multiplex channel
type ChannelStats struct {
	ChannelID    uint32    `json:"channel_id"`
	IsActive     bool      `json:"is_active"`
	BytesSent    uint64    `json:"bytes_sent"`
	BytesReceived uint64   `json:"bytes_received"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
}

// DirectTunnel interface extension for integration testing
type DirectTunnel interface {
	DirectConnection
	CreateMultiplexChannel() (MultiplexChannel, error)
	GetMultiplexChannel(channelID uint32) (MultiplexChannel, error)
	ListMultiplexChannels() []MultiplexChannel
	GetConnectionID() [16]byte
	GetRole() ConnectionRole
}

// NetworkConditions represents network condition parameters for testing
type NetworkConditions struct {
	Latency    time.Duration `json:"latency"`
	PacketLoss float64       `json:"packet_loss"`
	Throughput float64       `json:"throughput_bps"`
	Jitter     time.Duration `json:"jitter"`
	Stability  float64       `json:"stability"`
}

// FallbackRule represents a protocol fallback rule
type FallbackRule struct {
	Name         string          `json:"name"`
	FromProtocol string          `json:"from_protocol"`
	ToProtocol   string          `json:"to_protocol"`
	Trigger      FallbackTrigger `json:"trigger"`
	Priority     int             `json:"priority"`
}

// FallbackTrigger represents conditions that trigger protocol fallback
type FallbackTrigger struct {
	Type             string        `json:"type"`
	LatencyThreshold time.Duration `json:"latency_threshold,omitempty"`
	PacketLossRate   float64       `json:"packet_loss_rate,omitempty"`
	ErrorRate        float64       `json:"error_rate,omitempty"`
}

// FallbackEvent represents a protocol fallback event
type FallbackEvent struct {
	FromProtocol string           `json:"from_protocol"`
	ToProtocol   string           `json:"to_protocol"`
	Reason       string           `json:"reason"`
	Success      bool             `json:"success"`
	Timestamp    time.Time        `json:"timestamp"`
	Conditions   *NetworkConditions `json:"conditions,omitempty"`
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

// ProfileStatistics represents statistics about connection profiles
type ProfileStatistics struct {
	TotalProfiles        int                    `json:"total_profiles"`
	ProfilesByProtocol   map[string]int         `json:"profiles_by_protocol"`
	UsageStats          []ProfileUsageStats    `json:"usage_stats"`
	MostUsedProfile     string                 `json:"most_used_profile"`
	RecentlyUsedProfiles []string              `json:"recently_used_profiles"`
}

// ProfileUsageStats represents usage statistics for a profile
type ProfileUsageStats struct {
	ProfileName string    `json:"profile_name"`
	UseCount    int       `json:"use_count"`
	LastUsed    time.Time `json:"last_used"`
}

// BackupData represents encrypted backup data
type BackupData struct {
	Version       int       `json:"version"`
	ProfileCount  int       `json:"profile_count"`
	EncryptedData []byte    `json:"encrypted_data"`
	Salt          []byte    `json:"salt"`
	CreatedAt     time.Time `json:"created_at"`
	Statistics    *ProfileStatistics `json:"statistics,omitempty"`
}

// SearchCriteria represents search criteria for profiles
type SearchCriteria struct {
	Name        string `json:"name,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	MinUseCount int    `json:"min_use_count,omitempty"`
}

// ProfileMetadataUpdate represents updates to profile metadata
type ProfileMetadataUpdate struct {
	Description *string `json:"description,omitempty"`
}

// IntegrityCheckResult represents the result of an integrity check
type IntegrityCheckResult struct {
	Passed          bool     `json:"passed"`
	ProfilesChecked int      `json:"profiles_checked"`
	ErrorsFound     []string `json:"errors_found"`
	CheckedAt       time.Time `json:"checked_at"`
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

// DiagnosticInfo represents diagnostic information for a connection
type DiagnosticInfo struct {
	ConnectionID       string              `json:"connection_id"`
	NetworkMetrics     *NetworkMetrics     `json:"network_metrics"`
	PerformanceMetrics *PerformanceMetrics `json:"performance_metrics"`
	ErrorSummary       *ErrorSummary       `json:"error_summary"`
	CollectedAt        time.Time           `json:"collected_at"`
}

// NetworkMetrics represents network-level metrics
type NetworkMetrics struct {
	BytesSent       uint64        `json:"bytes_sent"`
	BytesReceived   uint64        `json:"bytes_received"`
	PacketsSent     uint64        `json:"packets_sent"`
	PacketsReceived uint64        `json:"packets_received"`
	AverageLatency  time.Duration `json:"average_latency"`
	PacketLossRate  float64       `json:"packet_loss_rate"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	ConnectionTime    time.Duration `json:"connection_time"`
	Throughput        float64       `json:"throughput_bps"`
	CPUUsage          float64       `json:"cpu_usage_percent"`
	MemoryUsage       uint64        `json:"memory_usage_bytes"`
	ActiveConnections int           `json:"active_connections"`
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

// DiagnosticCollector interface for collecting diagnostic information
type DiagnosticCollector interface {
	CollectDiagnostics(connectionID string, networkMetrics *NetworkMetrics, perfMetrics *PerformanceMetrics, errors []error)
	GetDiagnostics(connectionID string) *DiagnosticInfo
}

// OPSECLogger interface for secure logging
type OPSECLogger interface {
	LogConnectionEvent(connectionID, eventType, message string, metadata map[string]interface{})
	LogRetryEvent(connectionID string, attemptCount int, decision *RetryDecision, err error)
	LogSecurityEvent(eventType, description, riskLevel string, metadata map[string]interface{})
	GetAuditTrail() []*AuditEvent
	UpdateConnectionHealth(connectionID string, latency time.Duration, success bool)
	GetConnectionHealth(connectionID string) *ConnectionHealth
	CollectDiagnostics(connectionID string, networkMetrics *NetworkMetrics, perfMetrics *PerformanceMetrics, errors []error)
	GetDiagnostics(connectionID string) *DiagnosticInfo
	GetHealthSummary() *HealthSummary
}

// ProtocolOptimizer interface for protocol optimization
type ProtocolOptimizer interface {
	SelectOptimalProtocol(conditions *NetworkConditions) (*ProtocolSelection, error)
}

// ProtocolSelection represents a protocol selection result
type ProtocolSelection struct {
	Protocol string  `json:"protocol"`
	Score    float64 `json:"score"`
	Reason   string  `json:"reason"`
}

// ProtocolFallbackManager interface for managing protocol fallbacks
type ProtocolFallbackManager interface {
	CheckFallbackConditions(currentProtocol string, conditions *NetworkConditions) (*FallbackRule, bool)
	ExecuteFallback(rule *FallbackRule, conditions *NetworkConditions) *FallbackEvent
}

// Mock implementations for testing

// NewMockDirectConnection creates a mock DirectConnection for testing
func NewMockDirectConnection() DirectConnection {
	return &mockDirectConnection{
		active:  true,
		metrics: &ConnectionMetrics{},
	}
}

type mockDirectConnection struct {
	active  bool
	metrics *ConnectionMetrics
	data    []byte
}

func (m *mockDirectConnection) SendData(data []byte) error {
	if !m.active {
		return fmt.Errorf("connection not active")
	}
	m.data = make([]byte, len(data))
	copy(m.data, data)
	m.metrics.BytesSent += uint64(len(data))
	m.metrics.PacketsSent++
	return nil
}

func (m *mockDirectConnection) ReceiveData() ([]byte, error) {
	if !m.active {
		return nil, fmt.Errorf("connection not active")
	}
	if len(m.data) == 0 {
		return nil, fmt.Errorf("no data available")
	}
	data := make([]byte, len(m.data))
	copy(data, m.data)
	m.metrics.BytesReceived += uint64(len(data))
	m.metrics.PacketsReceived++
	return data, nil
}

func (m *mockDirectConnection) Close() error {
	m.active = false
	return nil
}

func (m *mockDirectConnection) IsActive() bool {
	return m.active
}

func (m *mockDirectConnection) GetMetrics() *ConnectionMetrics {
	return m.metrics
}

// Helper functions for integration tests

// NewConnectionHealthMonitor creates a new connection health monitor
func NewConnectionHealthMonitor() *ConnectionHealthMonitor {
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

// NewDiagnosticCollector creates a new diagnostic collector
func NewDiagnosticCollector() DiagnosticCollector {
	return &diagnosticCollector{
		diagnostics: make(map[string]*DiagnosticInfo),
	}
}

type diagnosticCollector struct {
	diagnostics map[string]*DiagnosticInfo
	mutex       sync.RWMutex
}

func (d *diagnosticCollector) CollectDiagnostics(connectionID string, networkMetrics *NetworkMetrics, perfMetrics *PerformanceMetrics, errors []error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	diagnostic := &DiagnosticInfo{
		ConnectionID:       connectionID,
		NetworkMetrics:     networkMetrics,
		PerformanceMetrics: perfMetrics,
		ErrorSummary:       d.createErrorSummary(errors),
		CollectedAt:        time.Now(),
	}

	d.diagnostics[connectionID] = diagnostic
}

func (d *diagnosticCollector) GetDiagnostics(connectionID string) *DiagnosticInfo {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	return d.diagnostics[connectionID]
}

func (d *diagnosticCollector) createErrorSummary(errors []error) *ErrorSummary {
	summary := &ErrorSummary{
		ErrorsByType: make(map[string]int),
		RecentErrors: make([]string, 0),
	}

	for _, err := range errors {
		if err == nil {
			continue
		}

		summary.TotalErrors++
		summary.RecentErrors = append(summary.RecentErrors, err.Error())
		summary.LastErrorTime = time.Now()

		// Classify error type
		errorType := d.classifyError(err)
		summary.ErrorsByType[errorType]++
	}

	return summary
}

func (d *diagnosticCollector) classifyError(err error) string {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	case strings.Contains(errStr, "connection"):
		return "connection"
	case strings.Contains(errStr, "network"):
		return "network"
	case strings.Contains(errStr, "crypto"):
		return "cryptographic"
	default:
		return "other"
	}
}
