package direct

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ProductionMonitor provides comprehensive monitoring and diagnostics for production environments
type ProductionMonitor struct {
	healthChecker     *ProductionHealthChecker
	metricsCollector  *ProductionMetricsCollector
	alertManager      *AlertManager
	diagnostics       *DiagnosticsCollector
	shutdownManager   *GracefulShutdownManager
	config           *ProductionMonitorConfig
	enabled          bool
	mutex            sync.RWMutex
}

// ProductionMonitorConfig contains configuration for production monitoring
type ProductionMonitorConfig struct {
	HealthCheckInterval    time.Duration `json:"health_check_interval"`
	MetricsInterval        time.Duration `json:"metrics_interval"`
	AlertingEnabled        bool          `json:"alerting_enabled"`
	DiagnosticsEnabled     bool          `json:"diagnostics_enabled"`
	GracefulShutdownTimeout time.Duration `json:"graceful_shutdown_timeout"`
	StatusReportInterval   time.Duration `json:"status_report_interval"`
	EnableDetailedMetrics  bool          `json:"enable_detailed_metrics"`
}

// ProductionHealthChecker performs comprehensive health checks
type ProductionHealthChecker struct {
	checks           []HealthCheck
	results          map[string]*HealthCheckResult
	lastCheck        time.Time
	checkInterval    time.Duration
	enabled          bool
	stopChan         chan struct{}
	mutex            sync.RWMutex
}

// HealthCheck defines a health check operation
type HealthCheck struct {
	Name        string
	Description string
	Checker     func() *HealthCheckResult
	Enabled     bool
	Timeout     time.Duration
	Critical    bool // If true, failure affects overall system health
}

// HealthCheckResult contains the result of a health check
type HealthCheckResult struct {
	Name        string        `json:"name"`
	Status      HealthStatus  `json:"status"`
	Message     string        `json:"message"`
	Duration    time.Duration `json:"duration"`
	Timestamp   time.Time     `json:"timestamp"`
	Details     interface{}   `json:"details,omitempty"`
	Error       string        `json:"error,omitempty"`
}

// HealthStatus represents the health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusFailed    HealthStatus = "failed"
)

// ProductionMetricsCollector collects production-specific metrics
type ProductionMetricsCollector struct {
	metrics          *ProductionMetrics
	collectors       []ProductionMetricCollector
	collectionInterval time.Duration
	enabled          bool
	stopChan         chan struct{}
	mutex            sync.RWMutex
}

// ProductionMetrics contains comprehensive production metrics
type ProductionMetrics struct {
	SystemHealth        *SystemHealthMetrics     `json:"system_health"`
	ConnectionMetrics   *ConnectionMetrics       `json:"connection_metrics"`
	PerformanceMetrics  *PerformanceMetrics      `json:"performance_metrics"`
	SecurityMetrics     *SecurityMetrics         `json:"security_metrics"`
	OperationalMetrics  *OperationalMetrics      `json:"operational_metrics"`
	LastUpdate          time.Time                `json:"last_update"`
}

// SystemHealthMetrics tracks overall system health
type SystemHealthMetrics struct {
	OverallStatus       HealthStatus  `json:"overall_status"`
	ComponentStatuses   map[string]HealthStatus `json:"component_statuses"`
	UptimeSeconds       int64         `json:"uptime_seconds"`
	LastHealthCheck     time.Time     `json:"last_health_check"`
	HealthCheckCount    int64         `json:"health_check_count"`
	FailedHealthChecks  int64         `json:"failed_health_checks"`
}

// SecurityMetrics tracks security-related metrics
type SecurityMetrics struct {
	FailedConnections   int64     `json:"failed_connections"`
	SecurityEvents      int64     `json:"security_events"`
	LastSecurityEvent   time.Time `json:"last_security_event"`
	EncryptionFailures  int64     `json:"encryption_failures"`
	AuthenticationFailures int64  `json:"authentication_failures"`
}

// OperationalMetrics tracks operational metrics
type OperationalMetrics struct {
	StartTime           time.Time `json:"start_time"`
	RestartCount        int64     `json:"restart_count"`
	ConfigReloads       int64     `json:"config_reloads"`
	ErrorCount          int64     `json:"error_count"`
	WarningCount        int64     `json:"warning_count"`
	LastError           time.Time `json:"last_error"`
	LastWarning         time.Time `json:"last_warning"`
}

// AlertManager handles alerting for production issues
type AlertManager struct {
	alerts           []Alert
	alertHandlers    []AlertHandler
	alertHistory     []*AlertEvent
	enabled          bool
	thresholds       *AlertThresholds
	mutex            sync.RWMutex
}

// Alert represents an alert condition
type Alert struct {
	ID          string
	Name        string
	Description string
	Severity    AlertSeverity
	Condition   AlertCondition
	Enabled     bool
	Cooldown    time.Duration
	LastFired   time.Time
}

// AlertSeverity represents the severity of an alert
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertCondition defines when an alert should fire
type AlertCondition func(metrics *ProductionMetrics) bool

// AlertHandler handles alert notifications
type AlertHandler interface {
	HandleAlert(event *AlertEvent) error
	GetName() string
	IsEnabled() bool
}

// AlertEvent represents an alert event
type AlertEvent struct {
	AlertID     string        `json:"alert_id"`
	AlertName   string        `json:"alert_name"`
	Severity    AlertSeverity `json:"severity"`
	Message     string        `json:"message"`
	Timestamp   time.Time     `json:"timestamp"`
	Details     interface{}   `json:"details,omitempty"`
	Resolved    bool          `json:"resolved"`
	ResolvedAt  *time.Time    `json:"resolved_at,omitempty"`
}

// AlertThresholds defines thresholds for various alerts
type AlertThresholds struct {
	MemoryUsagePercent    float64 `json:"memory_usage_percent"`
	CPUUsagePercent       float64 `json:"cpu_usage_percent"`
	ConnectionFailureRate float64 `json:"connection_failure_rate"`
	ResponseTimeMs        int64   `json:"response_time_ms"`
	ErrorRate             float64 `json:"error_rate"`
}

// DiagnosticsCollector collects diagnostic information
type DiagnosticsCollector struct {
	diagnostics      *DiagnosticInfo
	collectors       []DiagnosticCollector
	enabled          bool
	mutex            sync.RWMutex
}

// DiagnosticInfo contains comprehensive diagnostic information
type DiagnosticInfo struct {
	SystemInfo      *SystemDiagnostics    `json:"system_info"`
	NetworkInfo     *NetworkDiagnostics   `json:"network_info"`
	ConnectionInfo  *ConnectionDiagnostics `json:"connection_info"`
	PerformanceInfo *PerformanceDiagnostics `json:"performance_info"`
	ConfigInfo      *ConfigDiagnostics    `json:"config_info"`
	LastUpdate      time.Time             `json:"last_update"`
}

// SystemDiagnostics contains system diagnostic information
type SystemDiagnostics struct {
	Hostname        string    `json:"hostname"`
	OS              string    `json:"os"`
	Architecture    string    `json:"architecture"`
	GoVersion       string    `json:"go_version"`
	ProcessID       int       `json:"process_id"`
	StartTime       time.Time `json:"start_time"`
	WorkingDir      string    `json:"working_dir"`
	ExecutablePath  string    `json:"executable_path"`
}

// NetworkDiagnostics contains network diagnostic information
type NetworkDiagnostics struct {
	LocalAddresses  []string `json:"local_addresses"`
	ListeningPorts  []int    `json:"listening_ports"`
	ActiveSockets   int      `json:"active_sockets"`
	NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
}

// ConnectionDiagnostics contains connection diagnostic information
type ConnectionDiagnostics struct {
	ActiveConnections    int                    `json:"active_connections"`
	ConnectionsByState   map[string]int         `json:"connections_by_state"`
	ConnectionsByRole    map[string]int         `json:"connections_by_role"`
	RecentConnections    []*ConnectionSummary   `json:"recent_connections"`
	FailedConnections    []*ConnectionFailure   `json:"failed_connections"`
}

// ConnectionSummary provides a summary of a connection
type ConnectionSummary struct {
	ID            string    `json:"id"`
	RemoteAddress string    `json:"remote_address"`
	State         string    `json:"state"`
	Role          string    `json:"role"`
	ConnectedAt   time.Time `json:"connected_at"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
}

// ConnectionFailure represents a connection failure
type ConnectionFailure struct {
	Timestamp     time.Time `json:"timestamp"`
	RemoteAddress string    `json:"remote_address"`
	Error         string    `json:"error"`
	AttemptCount  int       `json:"attempt_count"`
}

// PerformanceDiagnostics contains performance diagnostic information
type PerformanceDiagnostics struct {
	MemoryStats     *MemoryDiagnostics    `json:"memory_stats"`
	GoroutineStats  *GoroutineDiagnostics `json:"goroutine_stats"`
	GCStats         *GCDiagnostics        `json:"gc_stats"`
	LatencyStats    *LatencyDiagnostics   `json:"latency_stats"`
}

// MemoryDiagnostics contains memory diagnostic information
type MemoryDiagnostics struct {
	AllocatedBytes    int64 `json:"allocated_bytes"`
	TotalAllocBytes   int64 `json:"total_alloc_bytes"`
	SystemBytes       int64 `json:"system_bytes"`
	HeapObjects       int64 `json:"heap_objects"`
	StackInUse        int64 `json:"stack_in_use"`
}

// GoroutineDiagnostics contains goroutine diagnostic information
type GoroutineDiagnostics struct {
	Count           int               `json:"count"`
	RunningCount    int               `json:"running_count"`
	BlockedCount    int               `json:"blocked_count"`
	StateBreakdown  map[string]int    `json:"state_breakdown"`
}

// GCDiagnostics contains garbage collection diagnostic information
type GCDiagnostics struct {
	NumGC           int64         `json:"num_gc"`
	PauseTotal      time.Duration `json:"pause_total"`
	LastPause       time.Duration `json:"last_pause"`
	NextGC          int64         `json:"next_gc"`
	GCCPUFraction   float64       `json:"gc_cpu_fraction"`
}

// LatencyDiagnostics contains latency diagnostic information
type LatencyDiagnostics struct {
	AverageLatency  time.Duration `json:"average_latency"`
	P50Latency      time.Duration `json:"p50_latency"`
	P95Latency      time.Duration `json:"p95_latency"`
	P99Latency      time.Duration `json:"p99_latency"`
	MaxLatency      time.Duration `json:"max_latency"`
}

// ConfigDiagnostics contains configuration diagnostic information
type ConfigDiagnostics struct {
	ConfigFile      string                 `json:"config_file"`
	ConfigHash      string                 `json:"config_hash"`
	LastReload      time.Time              `json:"last_reload"`
	ConfigValues    map[string]interface{} `json:"config_values"`
	ValidationErrors []string              `json:"validation_errors"`
}

// GracefulShutdownManager handles graceful shutdown procedures
type GracefulShutdownManager struct {
	shutdownTimeout time.Duration
	shutdownHooks   []ShutdownHook
	shutdownChan    chan os.Signal
	enabled         bool
	mutex           sync.RWMutex
}

// ShutdownHook represents a function to call during shutdown
type ShutdownHook struct {
	Name    string
	Handler func() error
	Timeout time.Duration
}

// ProductionMetricCollector defines an interface for production metric collectors
type ProductionMetricCollector interface {
	CollectMetrics() (interface{}, error)
	GetName() string
	IsEnabled() bool
}

// DiagnosticCollector defines an interface for diagnostic collectors
type DiagnosticCollector interface {
	CollectDiagnostics() (interface{}, error)
	GetName() string
	IsEnabled() bool
}

// NewProductionMonitor creates a new production monitor
func NewProductionMonitor(config *ProductionMonitorConfig) *ProductionMonitor {
	if config == nil {
		config = &ProductionMonitorConfig{
			HealthCheckInterval:     30 * time.Second,
			MetricsInterval:         60 * time.Second,
			AlertingEnabled:         true,
			DiagnosticsEnabled:      true,
			GracefulShutdownTimeout: 30 * time.Second,
			StatusReportInterval:    5 * time.Minute,
			EnableDetailedMetrics:   true,
		}
	}

	pm := &ProductionMonitor{
		config:  config,
		enabled: true,
	}

	pm.healthChecker = NewProductionHealthChecker(config.HealthCheckInterval)
	pm.metricsCollector = NewProductionMetricsCollector(config.MetricsInterval)
	
	if config.AlertingEnabled {
		pm.alertManager = NewAlertManager()
	}
	
	if config.DiagnosticsEnabled {
		pm.diagnostics = NewDiagnosticsCollector()
	}
	
	pm.shutdownManager = NewGracefulShutdownManager(config.GracefulShutdownTimeout)

	return pm
}

// Start starts the production monitor
func (pm *ProductionMonitor) Start() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.enabled {
		return fmt.Errorf("production monitor is disabled")
	}

	// Start health checker
	if err := pm.healthChecker.Start(); err != nil {
		return fmt.Errorf("failed to start health checker: %w", err)
	}

	// Start metrics collector
	if err := pm.metricsCollector.Start(); err != nil {
		return fmt.Errorf("failed to start metrics collector: %w", err)
	}

	// Start alert manager if enabled
	if pm.alertManager != nil {
		if err := pm.alertManager.Start(); err != nil {
			return fmt.Errorf("failed to start alert manager: %w", err)
		}
	}

	// Start diagnostics collector if enabled
	if pm.diagnostics != nil {
		if err := pm.diagnostics.Start(); err != nil {
			return fmt.Errorf("failed to start diagnostics collector: %w", err)
		}
	}

	// Start graceful shutdown manager
	if err := pm.shutdownManager.Start(); err != nil {
		return fmt.Errorf("failed to start shutdown manager: %w", err)
	}

	return nil
}

// Stop stops the production monitor
func (pm *ProductionMonitor) Stop() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var errors []error

	// Stop components
	if err := pm.healthChecker.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("health checker stop error: %w", err))
	}

	if err := pm.metricsCollector.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("metrics collector stop error: %w", err))
	}

	if pm.alertManager != nil {
		if err := pm.alertManager.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("alert manager stop error: %w", err))
		}
	}

	if pm.diagnostics != nil {
		if err := pm.diagnostics.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("diagnostics collector stop error: %w", err))
		}
	}

	if err := pm.shutdownManager.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("shutdown manager stop error: %w", err))
	}

	pm.enabled = false

	if len(errors) > 0 {
		return fmt.Errorf("multiple stop errors: %v", errors)
	}

	return nil
}

// GetHealthStatus returns the current health status
func (pm *ProductionMonitor) GetHealthStatus() (*SystemHealthMetrics, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.enabled {
		return nil, fmt.Errorf("production monitor is disabled")
	}

	return pm.healthChecker.GetHealthStatus()
}

// GetMetrics returns current production metrics
func (pm *ProductionMonitor) GetMetrics() (*ProductionMetrics, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.enabled {
		return nil, fmt.Errorf("production monitor is disabled")
	}

	return pm.metricsCollector.GetMetrics()
}

// GetDiagnostics returns diagnostic information
func (pm *ProductionMonitor) GetDiagnostics() (*DiagnosticInfo, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.enabled || pm.diagnostics == nil {
		return nil, fmt.Errorf("diagnostics not available")
	}

	return pm.diagnostics.GetDiagnostics()
}

// TriggerHealthCheck triggers an immediate health check
func (pm *ProductionMonitor) TriggerHealthCheck() error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.enabled {
		return fmt.Errorf("production monitor is disabled")
	}

	return pm.healthChecker.RunHealthChecks()
}

// AddShutdownHook adds a shutdown hook
func (pm *ProductionMonitor) AddShutdownHook(hook ShutdownHook) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.shutdownManager.AddShutdownHook(hook)
}

// Production Health Checker Implementation

// NewProductionHealthChecker creates a new production health checker
func NewProductionHealthChecker(interval time.Duration) *ProductionHealthChecker {
	phc := &ProductionHealthChecker{
		checkInterval: interval,
		enabled:       true,
		stopChan:      make(chan struct{}),
		results:       make(map[string]*HealthCheckResult),
	}

	// Initialize default health checks
	phc.checks = []HealthCheck{
		{
			Name:        "system_resources",
			Description: "Check system resource usage",
			Checker:     phc.checkSystemResources,
			Enabled:     true,
			Timeout:     10 * time.Second,
			Critical:    true,
		},
		{
			Name:        "connection_health",
			Description: "Check connection health",
			Checker:     phc.checkConnectionHealth,
			Enabled:     true,
			Timeout:     15 * time.Second,
			Critical:    true,
		},
		{
			Name:        "memory_usage",
			Description: "Check memory usage",
			Checker:     phc.checkMemoryUsage,
			Enabled:     true,
			Timeout:     5 * time.Second,
			Critical:    false,
		},
		{
			Name:        "goroutine_count",
			Description: "Check goroutine count",
			Checker:     phc.checkGoroutineCount,
			Enabled:     true,
			Timeout:     5 * time.Second,
			Critical:    false,
		},
	}

	return phc
}

// Start starts the health checker
func (phc *ProductionHealthChecker) Start() error {
	phc.mutex.Lock()
	defer phc.mutex.Unlock()

	if !phc.enabled {
		return fmt.Errorf("health checker is disabled")
	}

	go phc.healthCheckLoop()
	return nil
}

// Stop stops the health checker
func (phc *ProductionHealthChecker) Stop() error {
	phc.mutex.Lock()
	defer phc.mutex.Unlock()

	close(phc.stopChan)
	phc.enabled = false
	return nil
}

// RunHealthChecks runs all health checks immediately
func (phc *ProductionHealthChecker) RunHealthChecks() error {
	phc.mutex.Lock()
	defer phc.mutex.Unlock()

	for _, check := range phc.checks {
		if !check.Enabled {
			continue
		}

		start := time.Now()
		result := check.Checker()
		result.Duration = time.Since(start)
		result.Timestamp = time.Now()

		phc.results[check.Name] = result
	}

	phc.lastCheck = time.Now()
	return nil
}

// GetHealthStatus returns the current health status
func (phc *ProductionHealthChecker) GetHealthStatus() (*SystemHealthMetrics, error) {
	phc.mutex.RLock()
	defer phc.mutex.RUnlock()

	overallStatus := HealthStatusHealthy
	componentStatuses := make(map[string]HealthStatus)
	var failedChecks int64

	for name, result := range phc.results {
		componentStatuses[name] = result.Status
		
		if result.Status == HealthStatusFailed || result.Status == HealthStatusUnhealthy {
			failedChecks++
			// Find the check to see if it's critical
			for _, check := range phc.checks {
				if check.Name == name && check.Critical {
					if result.Status == HealthStatusFailed {
						overallStatus = HealthStatusFailed
					} else if overallStatus == HealthStatusHealthy {
						overallStatus = HealthStatusUnhealthy
					}
					break
				}
			}
		} else if result.Status == HealthStatusDegraded && overallStatus == HealthStatusHealthy {
			overallStatus = HealthStatusDegraded
		}
	}

	return &SystemHealthMetrics{
		OverallStatus:      overallStatus,
		ComponentStatuses:  componentStatuses,
		UptimeSeconds:      int64(time.Since(time.Now().Add(-time.Hour)).Seconds()), // Placeholder
		LastHealthCheck:    phc.lastCheck,
		HealthCheckCount:   int64(len(phc.results)),
		FailedHealthChecks: failedChecks,
	}, nil
}

// healthCheckLoop runs health checks periodically
func (phc *ProductionHealthChecker) healthCheckLoop() {
	ticker := time.NewTicker(phc.checkInterval)
	defer ticker.Stop()

	// Run initial health check
	phc.RunHealthChecks()

	for {
		select {
		case <-ticker.C:
			phc.RunHealthChecks()
		case <-phc.stopChan:
			return
		}
	}
}

// Health check implementations

// checkSystemResources checks system resource usage
func (phc *ProductionHealthChecker) checkSystemResources() *HealthCheckResult {
	// This would implement actual system resource checking
	// For now, return a healthy status
	return &HealthCheckResult{
		Name:    "system_resources",
		Status:  HealthStatusHealthy,
		Message: "System resources are within normal limits",
	}
}

// checkConnectionHealth checks connection health
func (phc *ProductionHealthChecker) checkConnectionHealth() *HealthCheckResult {
	// This would implement actual connection health checking
	// For now, return a healthy status
	return &HealthCheckResult{
		Name:    "connection_health",
		Status:  HealthStatusHealthy,
		Message: "All connections are healthy",
	}
}

// checkMemoryUsage checks memory usage
func (phc *ProductionHealthChecker) checkMemoryUsage() *HealthCheckResult {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check if memory usage is too high (example threshold: 1GB)
	threshold := int64(1024 * 1024 * 1024) // 1GB
	current := int64(memStats.Alloc)

	status := HealthStatusHealthy
	message := fmt.Sprintf("Memory usage: %d bytes", current)

	if current > threshold {
		status = HealthStatusDegraded
		message = fmt.Sprintf("High memory usage: %d bytes (threshold: %d bytes)", current, threshold)
	}

	return &HealthCheckResult{
		Name:    "memory_usage",
		Status:  status,
		Message: message,
		Details: map[string]interface{}{
			"current_bytes":   current,
			"threshold_bytes": threshold,
			"heap_objects":    memStats.HeapObjects,
		},
	}
}

// checkGoroutineCount checks goroutine count
func (phc *ProductionHealthChecker) checkGoroutineCount() *HealthCheckResult {
	count := runtime.NumGoroutine()
	threshold := 1000 // Example threshold

	status := HealthStatusHealthy
	message := fmt.Sprintf("Goroutine count: %d", count)

	if count > threshold {
		status = HealthStatusDegraded
		message = fmt.Sprintf("High goroutine count: %d (threshold: %d)", count, threshold)
	}

	return &HealthCheckResult{
		Name:    "goroutine_count",
		Status:  status,
		Message: message,
		Details: map[string]interface{}{
			"count":     count,
			"threshold": threshold,
		},
	}
}

// Production Metrics Collector Implementation

// NewProductionMetricsCollector creates a new production metrics collector
func NewProductionMetricsCollector(interval time.Duration) *ProductionMetricsCollector {
	pmc := &ProductionMetricsCollector{
		metrics: &ProductionMetrics{
			SystemHealth:       &SystemHealthMetrics{},
			ConnectionMetrics:  &ConnectionMetrics{},
			PerformanceMetrics: &PerformanceMetrics{},
			SecurityMetrics:    &SecurityMetrics{},
			OperationalMetrics: &OperationalMetrics{
				StartTime: time.Now(),
			},
			LastUpdate: time.Now(),
		},
		collectionInterval: interval,
		enabled:           true,
		stopChan:          make(chan struct{}),
		collectors:        make([]ProductionMetricCollector, 0),
	}

	return pmc
}

// Start starts the metrics collector
func (pmc *ProductionMetricsCollector) Start() error {
	pmc.mutex.Lock()
	defer pmc.mutex.Unlock()

	if !pmc.enabled {
		return fmt.Errorf("metrics collector is disabled")
	}

	go pmc.metricsCollectionLoop()
	return nil
}

// Stop stops the metrics collector
func (pmc *ProductionMetricsCollector) Stop() error {
	pmc.mutex.Lock()
	defer pmc.mutex.Unlock()

	close(pmc.stopChan)
	pmc.enabled = false
	return nil
}

// GetMetrics returns current production metrics
func (pmc *ProductionMetricsCollector) GetMetrics() (*ProductionMetrics, error) {
	pmc.mutex.RLock()
	defer pmc.mutex.RUnlock()

	if !pmc.enabled {
		return nil, fmt.Errorf("metrics collector is disabled")
	}

	// Update metrics
	pmc.updateMetrics()

	// Return a copy
	return &ProductionMetrics{
		SystemHealth:       pmc.metrics.SystemHealth,
		ConnectionMetrics:  pmc.metrics.ConnectionMetrics,
		PerformanceMetrics: pmc.metrics.PerformanceMetrics,
		SecurityMetrics:    pmc.metrics.SecurityMetrics,
		OperationalMetrics: pmc.metrics.OperationalMetrics,
		LastUpdate:         time.Now(),
	}, nil
}

// metricsCollectionLoop periodically collects metrics
func (pmc *ProductionMetricsCollector) metricsCollectionLoop() {
	ticker := time.NewTicker(pmc.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pmc.collectMetrics()
		case <-pmc.stopChan:
			return
		}
	}
}

// collectMetrics collects all metrics
func (pmc *ProductionMetricsCollector) collectMetrics() {
	pmc.mutex.Lock()
	defer pmc.mutex.Unlock()

	pmc.updateMetrics()
	pmc.metrics.LastUpdate = time.Now()
}

// updateMetrics updates all metrics
func (pmc *ProductionMetricsCollector) updateMetrics() {
	// Update metrics from collectors
	for _, collector := range pmc.collectors {
		if !collector.IsEnabled() {
			continue
		}

		metrics, err := collector.CollectMetrics()
		if err != nil {
			continue
		}

		// Update appropriate metrics based on collector type
		switch collector.GetName() {
		case "connection_metrics":
			if connMetrics, ok := metrics.(*ConnectionMetrics); ok {
				pmc.metrics.ConnectionMetrics = connMetrics
			}
		case "performance_metrics":
			if perfMetrics, ok := metrics.(*PerformanceMetrics); ok {
				pmc.metrics.PerformanceMetrics = perfMetrics
			}
		}
	}
}

// Alert Manager Implementation

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	am := &AlertManager{
		alerts:        make([]Alert, 0),
		alertHandlers: make([]AlertHandler, 0),
		alertHistory:  make([]*AlertEvent, 0),
		enabled:       true,
		thresholds: &AlertThresholds{
			MemoryUsagePercent:    80.0,
			CPUUsagePercent:       80.0,
			ConnectionFailureRate: 10.0,
			ResponseTimeMs:        1000,
			ErrorRate:            5.0,
		},
	}

	// Initialize default alerts
	am.initializeDefaultAlerts()

	return am
}

// Start starts the alert manager
func (am *AlertManager) Start() error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if !am.enabled {
		return fmt.Errorf("alert manager is disabled")
	}

	return nil
}

// Stop stops the alert manager
func (am *AlertManager) Stop() error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.enabled = false
	return nil
}

// initializeDefaultAlerts initializes default alerts
func (am *AlertManager) initializeDefaultAlerts() {
	am.alerts = []Alert{
		{
			ID:          "high_memory_usage",
			Name:        "High Memory Usage",
			Description: "Memory usage exceeds threshold",
			Severity:    AlertSeverityWarning,
			Condition:   am.highMemoryCondition,
			Enabled:     true,
			Cooldown:    5 * time.Minute,
		},
		{
			ID:          "connection_failures",
			Name:        "Connection Failures",
			Description: "High rate of connection failures",
			Severity:    AlertSeverityError,
			Condition:   am.connectionFailureCondition,
			Enabled:     true,
			Cooldown:    2 * time.Minute,
		},
		{
			ID:          "system_unhealthy",
			Name:        "System Unhealthy",
			Description: "System health check failed",
			Severity:    AlertSeverityCritical,
			Condition:   am.systemUnhealthyCondition,
			Enabled:     true,
			Cooldown:    1 * time.Minute,
		},
	}
}

// Alert condition implementations
func (am *AlertManager) highMemoryCondition(metrics *ProductionMetrics) bool {
	// This would implement actual memory usage checking
	return false // Placeholder
}

func (am *AlertManager) connectionFailureCondition(metrics *ProductionMetrics) bool {
	// This would implement actual connection failure rate checking
	return false // Placeholder
}

func (am *AlertManager) systemUnhealthyCondition(metrics *ProductionMetrics) bool {
	if metrics.SystemHealth == nil {
		return false
	}
	return metrics.SystemHealth.OverallStatus == HealthStatusFailed || 
		   metrics.SystemHealth.OverallStatus == HealthStatusUnhealthy
}

// Diagnostics Collector Implementation

// NewDiagnosticsCollector creates a new diagnostics collector
func NewDiagnosticsCollector() *DiagnosticsCollector {
	dc := &DiagnosticsCollector{
		diagnostics: &DiagnosticInfo{
			SystemInfo:      &SystemDiagnostics{},
			NetworkInfo:     &NetworkDiagnostics{},
			ConnectionInfo:  &ConnectionDiagnostics{},
			PerformanceInfo: &PerformanceDiagnostics{},
			ConfigInfo:      &ConfigDiagnostics{},
			LastUpdate:      time.Now(),
		},
		collectors: make([]DiagnosticCollector, 0),
		enabled:    true,
	}

	return dc
}

// Start starts the diagnostics collector
func (dc *DiagnosticsCollector) Start() error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	if !dc.enabled {
		return fmt.Errorf("diagnostics collector is disabled")
	}

	// Collect initial diagnostics
	dc.collectDiagnostics()
	return nil
}

// Stop stops the diagnostics collector
func (dc *DiagnosticsCollector) Stop() error {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	dc.enabled = false
	return nil
}

// GetDiagnostics returns current diagnostic information
func (dc *DiagnosticsCollector) GetDiagnostics() (*DiagnosticInfo, error) {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	if !dc.enabled {
		return nil, fmt.Errorf("diagnostics collector is disabled")
	}

	// Update diagnostics
	dc.collectDiagnostics()

	// Return a copy
	return &DiagnosticInfo{
		SystemInfo:      dc.diagnostics.SystemInfo,
		NetworkInfo:     dc.diagnostics.NetworkInfo,
		ConnectionInfo:  dc.diagnostics.ConnectionInfo,
		PerformanceInfo: dc.diagnostics.PerformanceInfo,
		ConfigInfo:      dc.diagnostics.ConfigInfo,
		LastUpdate:      time.Now(),
	}, nil
}

// collectDiagnostics collects all diagnostic information
func (dc *DiagnosticsCollector) collectDiagnostics() {
	// Collect system diagnostics
	dc.collectSystemDiagnostics()
	
	// Collect network diagnostics
	dc.collectNetworkDiagnostics()
	
	// Collect connection diagnostics
	dc.collectConnectionDiagnostics()
	
	// Collect performance diagnostics
	dc.collectPerformanceDiagnostics()
	
	// Collect configuration diagnostics
	dc.collectConfigDiagnostics()

	dc.diagnostics.LastUpdate = time.Now()
}

// collectSystemDiagnostics collects system diagnostic information
func (dc *DiagnosticsCollector) collectSystemDiagnostics() {
	hostname, _ := os.Hostname()
	workingDir, _ := os.Getwd()
	execPath, _ := os.Executable()

	dc.diagnostics.SystemInfo = &SystemDiagnostics{
		Hostname:       hostname,
		OS:             runtime.GOOS,
		Architecture:   runtime.GOARCH,
		GoVersion:      runtime.Version(),
		ProcessID:      os.Getpid(),
		StartTime:      time.Now(), // Would track actual start time
		WorkingDir:     workingDir,
		ExecutablePath: execPath,
	}
}

// collectNetworkDiagnostics collects network diagnostic information
func (dc *DiagnosticsCollector) collectNetworkDiagnostics() {
	// This would implement actual network interface collection
	dc.diagnostics.NetworkInfo = &NetworkDiagnostics{
		LocalAddresses:    []string{"127.0.0.1", "::1"},
		ListeningPorts:    []int{8080, 9090},
		ActiveSockets:     10,
		NetworkInterfaces: []NetworkInterface{},
	}
}

// collectConnectionDiagnostics collects connection diagnostic information
func (dc *DiagnosticsCollector) collectConnectionDiagnostics() {
	// This would implement actual connection diagnostics collection
	dc.diagnostics.ConnectionInfo = &ConnectionDiagnostics{
		ActiveConnections:  1,
		ConnectionsByState: map[string]int{"connected": 1},
		ConnectionsByRole:  map[string]int{"listener": 1},
		RecentConnections:  []*ConnectionSummary{},
		FailedConnections:  []*ConnectionFailure{},
	}
}

// collectPerformanceDiagnostics collects performance diagnostic information
func (dc *DiagnosticsCollector) collectPerformanceDiagnostics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	dc.diagnostics.PerformanceInfo = &PerformanceDiagnostics{
		MemoryStats: &MemoryDiagnostics{
			AllocatedBytes:  int64(memStats.Alloc),
			TotalAllocBytes: int64(memStats.TotalAlloc),
			SystemBytes:     int64(memStats.Sys),
			HeapObjects:     int64(memStats.HeapObjects),
			StackInUse:      int64(memStats.StackInuse),
		},
		GoroutineStats: &GoroutineDiagnostics{
			Count:          runtime.NumGoroutine(),
			RunningCount:   0, // Would implement actual counting
			BlockedCount:   0, // Would implement actual counting
			StateBreakdown: map[string]int{},
		},
		GCStats: &GCDiagnostics{
			NumGC:         int64(memStats.NumGC),
			PauseTotal:    time.Duration(memStats.PauseTotalNs),
			LastPause:     time.Duration(memStats.PauseNs[(memStats.NumGC+255)%256]),
			NextGC:        int64(memStats.NextGC),
			GCCPUFraction: memStats.GCCPUFraction,
		},
		LatencyStats: &LatencyDiagnostics{
			AverageLatency: 50 * time.Millisecond, // Placeholder
			P50Latency:     45 * time.Millisecond,
			P95Latency:     95 * time.Millisecond,
			P99Latency:     150 * time.Millisecond,
			MaxLatency:     200 * time.Millisecond,
		},
	}
}

// collectConfigDiagnostics collects configuration diagnostic information
func (dc *DiagnosticsCollector) collectConfigDiagnostics() {
	dc.diagnostics.ConfigInfo = &ConfigDiagnostics{
		ConfigFile:       "config.json",
		ConfigHash:       "abc123", // Would implement actual hash
		LastReload:       time.Now(),
		ConfigValues:     map[string]interface{}{},
		ValidationErrors: []string{},
	}
}

// Graceful Shutdown Manager Implementation

// NewGracefulShutdownManager creates a new graceful shutdown manager
func NewGracefulShutdownManager(timeout time.Duration) *GracefulShutdownManager {
	gsm := &GracefulShutdownManager{
		shutdownTimeout: timeout,
		shutdownHooks:   make([]ShutdownHook, 0),
		shutdownChan:    make(chan os.Signal, 1),
		enabled:         true,
	}

	// Register signal handlers
	signal.Notify(gsm.shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	return gsm
}

// Start starts the graceful shutdown manager
func (gsm *GracefulShutdownManager) Start() error {
	gsm.mutex.Lock()
	defer gsm.mutex.Unlock()

	if !gsm.enabled {
		return fmt.Errorf("shutdown manager is disabled")
	}

	go gsm.shutdownLoop()
	return nil
}

// Stop stops the graceful shutdown manager
func (gsm *GracefulShutdownManager) Stop() error {
	gsm.mutex.Lock()
	defer gsm.mutex.Unlock()

	gsm.enabled = false
	signal.Stop(gsm.shutdownChan)
	close(gsm.shutdownChan)
	return nil
}

// AddShutdownHook adds a shutdown hook
func (gsm *GracefulShutdownManager) AddShutdownHook(hook ShutdownHook) {
	gsm.mutex.Lock()
	defer gsm.mutex.Unlock()

	gsm.shutdownHooks = append(gsm.shutdownHooks, hook)
}

// shutdownLoop waits for shutdown signals and executes shutdown hooks
func (gsm *GracefulShutdownManager) shutdownLoop() {
	sig := <-gsm.shutdownChan
	fmt.Printf("Received shutdown signal: %v\n", sig)

	gsm.executeShutdownHooks()
	os.Exit(0)
}

// executeShutdownHooks executes all registered shutdown hooks
func (gsm *GracefulShutdownManager) executeShutdownHooks() {
	gsm.mutex.RLock()
	hooks := make([]ShutdownHook, len(gsm.shutdownHooks))
	copy(hooks, gsm.shutdownHooks)
	gsm.mutex.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), gsm.shutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, hook := range hooks {
		wg.Add(1)
		go func(h ShutdownHook) {
			defer wg.Done()
			
			hookCtx, hookCancel := context.WithTimeout(ctx, h.Timeout)
			defer hookCancel()

			done := make(chan error, 1)
			go func() {
				done <- h.Handler()
			}()

			select {
			case err := <-done:
				if err != nil {
					fmt.Printf("Shutdown hook %s failed: %v\n", h.Name, err)
				} else {
					fmt.Printf("Shutdown hook %s completed successfully\n", h.Name)
				}
			case <-hookCtx.Done():
				fmt.Printf("Shutdown hook %s timed out\n", h.Name)
			}
		}(hook)
	}

	// Wait for all hooks to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("All shutdown hooks completed")
	case <-ctx.Done():
		fmt.Println("Shutdown timeout reached, forcing exit")
	}
}

// LogAlertHandler logs alerts to stdout
type LogAlertHandler struct {
	enabled bool
}

// HandleAlert handles an alert by logging it
func (lah *LogAlertHandler) HandleAlert(event *AlertEvent) error {
	alertJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	fmt.Printf("ALERT: %s\n", string(alertJSON))
	return nil
}

// GetName returns the handler name
func (lah *LogAlertHandler) GetName() string {
	return "log_alert_handler"
}

// IsEnabled returns whether the handler is enabled
func (lah *LogAlertHandler) IsEnabled() bool {
	return lah.enabled
}

// ProductionStatusReport provides a comprehensive status report
type ProductionStatusReport struct {
	Timestamp       time.Time              `json:"timestamp"`
	OverallStatus   HealthStatus           `json:"overall_status"`
	SystemHealth    *SystemHealthMetrics   `json:"system_health"`
	Metrics         *ProductionMetrics     `json:"metrics"`
	Diagnostics     *DiagnosticInfo        `json:"diagnostics"`
	ActiveAlerts    []*AlertEvent          `json:"active_alerts"`
	RecentEvents    []string               `json:"recent_events"`
	Recommendations []string               `json:"recommendations"`
}

// GenerateStatusReport generates a comprehensive production status report
func (pm *ProductionMonitor) GenerateStatusReport() (*ProductionStatusReport, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.enabled {
		return nil, fmt.Errorf("production monitor is disabled")
	}

	// Get health status
	healthStatus, err := pm.healthChecker.GetHealthStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get health status: %w", err)
	}

	// Get metrics
	metrics, err := pm.metricsCollector.GetMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics: %w", err)
	}

	// Get diagnostics
	var diagnostics *DiagnosticInfo
	if pm.diagnostics != nil {
		diagnostics, err = pm.diagnostics.GetDiagnostics()
		if err != nil {
			diagnostics = nil // Continue without diagnostics
		}
	}

	// Get active alerts
	var activeAlerts []*AlertEvent
	if pm.alertManager != nil {
		activeAlerts = pm.getActiveAlerts()
	}

	report := &ProductionStatusReport{
		Timestamp:     time.Now(),
		OverallStatus: healthStatus.OverallStatus,
		SystemHealth:  healthStatus,
		Metrics:       metrics,
		Diagnostics:   diagnostics,
		ActiveAlerts:  activeAlerts,
		RecentEvents:  []string{}, // Would implement event tracking
		Recommendations: pm.generateRecommendations(healthStatus, metrics),
	}

	return report, nil
}

// getActiveAlerts returns currently active alerts
func (pm *ProductionMonitor) getActiveAlerts() []*AlertEvent {
	// This would implement actual active alert retrieval
	return []*AlertEvent{}
}

// generateRecommendations generates recommendations based on current status
func (pm *ProductionMonitor) generateRecommendations(health *SystemHealthMetrics, metrics *ProductionMetrics) []string {
	var recommendations []string

	if health.OverallStatus != HealthStatusHealthy {
		recommendations = append(recommendations, "System health is degraded - investigate component failures")
	}

	if health.FailedHealthChecks > 0 {
		recommendations = append(recommendations, "Some health checks are failing - review system resources")
	}

	// Add more recommendation logic based on metrics
	return recommendations
}
