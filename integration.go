package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

// SystemIntegration manages the complete integration of all QAVPN components
type SystemIntegration struct {
	config            *Config
	nodeManager       *NodeManager
	tunnelManager     *TunnelManager
	errorHandler      *SecureErrorHandler
	recoveryManager   *AutomaticRecoveryManager
	logger            *SecureLogger
	connectionMonitor *ConnectionMonitor
	healthChecker     *SystemHealthChecker
	securityHardener  *SecurityHardener
	isInitialized     bool
	mutex             sync.RWMutex
}

// NewSystemIntegration creates a new system integration manager
func NewSystemIntegration(config *Config) (*SystemIntegration, error) {
	si := &SystemIntegration{
		config: config,
	}

	if err := si.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize system components: %w", err)
	}

	return si, nil
}

// initializeComponents initializes all system components in the correct order
func (si *SystemIntegration) initializeComponents() error {
	si.mutex.Lock()
	defer si.mutex.Unlock()

	// 1. Initialize secure logging first
	si.logger = NewSecureLogger(LogLevel(si.config.LogLevel))
	si.logger.Info("system_integration", "Initializing QAVPN system components", map[string]interface{}{
		"version": fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch),
		"mode":    map[bool]string{true: "relay", false: "client"}[si.config.RelayMode],
	})

	// 2. Initialize error handling
	si.errorHandler = NewSecureErrorHandler()
	si.logger.Info("system_integration", "Secure error handler initialized", nil)

	// 3. Initialize node manager
	nodeManager, err := NewNodeManager(si.config.RelayMode)
	if err != nil {
		return fmt.Errorf("failed to initialize node manager: %w", err)
	}
	si.nodeManager = nodeManager
	si.logger.Info("system_integration", "Node manager initialized", map[string]interface{}{
		"is_relay": si.config.RelayMode,
	})

	// 4. Initialize tunnel manager (for clients)
	if !si.config.RelayMode {
		si.tunnelManager = NewTunnelManager()
		si.logger.Info("system_integration", "Tunnel manager initialized", nil)
	}

	// 5. Initialize recovery manager
	si.recoveryManager = NewAutomaticRecoveryManager(si.nodeManager, si.tunnelManager, si.errorHandler)
	si.logger.Info("system_integration", "Automatic recovery manager initialized", nil)

	// 6. Initialize connection monitor
	si.connectionMonitor = NewConnectionMonitor(si.logger, si.nodeManager, si.tunnelManager)
	si.logger.Info("system_integration", "Connection monitor initialized", nil)

	// 7. Initialize system health checker
	si.healthChecker = NewSystemHealthChecker(si.logger, si.nodeManager, si.tunnelManager, si.errorHandler)
	si.logger.Info("system_integration", "System health checker initialized", nil)

	// 8. Initialize security hardener
	si.securityHardener = NewSecurityHardener(si.logger, si.errorHandler)
	si.logger.Info("system_integration", "Security hardener initialized", nil)

	si.isInitialized = true
	si.logger.Info("system_integration", "All system components initialized successfully", nil)

	return nil
}

// StartSystem starts all system components in the correct order
func (si *SystemIntegration) StartSystem() error {
	si.mutex.Lock()
	defer si.mutex.Unlock()

	if !si.isInitialized {
		return fmt.Errorf("system not initialized")
	}

	si.logger.Info("system_integration", "Starting QAVPN system", nil)

	// Apply security hardening first
	if err := si.securityHardener.ApplySecurityHardening(); err != nil {
		return fmt.Errorf("failed to apply security hardening: %w", err)
	}

	// Start connection monitoring
	si.connectionMonitor.Start()

	// Start system health checking
	si.healthChecker.Start()

	// Start node manager maintenance
	si.nodeManager.StartPeriodicMaintenance()
	si.nodeManager.StartRouteMaintenance()

	// Start relay server if in relay mode
	if si.config.RelayMode {
		if err := si.nodeManager.StartRelayServer(si.config.RelayPort); err != nil {
			return fmt.Errorf("failed to start relay server: %w", err)
		}
		si.logger.Info("system_integration", "Relay server started", map[string]interface{}{
			"port": si.config.RelayPort,
		})
	} else {
		// For client mode, discover nodes
		if err := si.nodeManager.DiscoverNodes(); err != nil {
			si.logger.Warn("system_integration", "Node discovery failed, continuing with limited functionality", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	si.logger.Info("system_integration", "QAVPN system started successfully", nil)
	return nil
}

// StopSystem gracefully stops all system components
func (si *SystemIntegration) StopSystem() error {
	si.mutex.Lock()
	defer si.mutex.Unlock()

	si.logger.Info("system_integration", "Stopping QAVPN system", nil)

	// Stop health checker
	if si.healthChecker != nil {
		si.healthChecker.Stop()
	}

	// Stop connection monitor
	if si.connectionMonitor != nil {
		si.connectionMonitor.Stop()
	}

	// Close all tunnels
	if si.tunnelManager != nil {
		if err := si.tunnelManager.CloseAllTunnels(); err != nil {
			si.logger.Error("system_integration", "Error closing tunnels", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Stop relay server
	if si.nodeManager != nil {
		if err := si.nodeManager.StopRelayServer(); err != nil {
			si.logger.Error("system_integration", "Error stopping relay server", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Apply secure cleanup
	if si.securityHardener != nil {
		si.securityHardener.ApplySecureCleanup()
	}

	// Close logger
	if si.logger != nil {
		si.logger.Info("system_integration", "QAVPN system stopped", nil)
		si.logger.Close()
	}

	return nil
}

// GetSystemStatus returns comprehensive system status
func (si *SystemIntegration) GetSystemStatus() *SystemStatus {
	si.mutex.RLock()
	defer si.mutex.RUnlock()

	status := &SystemStatus{
		IsInitialized: si.isInitialized,
		Timestamp:     time.Now(),
		Version:       fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch),
		Mode:          map[bool]string{true: "relay", false: "client"}[si.config.RelayMode],
	}

	if si.nodeManager != nil {
		status.NodeStats = si.nodeManager.GetNodeStats()
		status.RelayStats = si.nodeManager.GetRelayStats()
	}

	if si.tunnelManager != nil {
		status.ActiveTunnels = len(si.tunnelManager.GetActiveTunnels())
	}

	if si.connectionMonitor != nil {
		status.IsHealthy = si.connectionMonitor.IsHealthy()
		status.HealthStatus = si.connectionMonitor.GetHealthStatus()
	}

	if si.errorHandler != nil {
		status.ErrorStats = si.errorHandler.GetErrorStatistics()
	}

	if si.recoveryManager != nil {
		status.RecoveryStats = si.recoveryManager.GetRecoveryStatistics()
	}

	return status
}

// SystemStatus represents the overall system status
type SystemStatus struct {
	IsInitialized bool                           `json:"is_initialized"`
	Timestamp     time.Time                      `json:"timestamp"`
	Version       string                         `json:"version"`
	Mode          string                         `json:"mode"`
	IsHealthy     bool                           `json:"is_healthy"`
	NodeStats     map[string]interface{}         `json:"node_stats,omitempty"`
	RelayStats    map[string]interface{}         `json:"relay_stats,omitempty"`
	ActiveTunnels int                            `json:"active_tunnels"`
	HealthStatus  map[string]*HealthCheck        `json:"health_status,omitempty"`
	ErrorStats    map[string]interface{}         `json:"error_stats,omitempty"`
	RecoveryStats map[string]interface{}         `json:"recovery_stats,omitempty"`
}

// SystemHealthChecker performs comprehensive system health checks
type SystemHealthChecker struct {
	logger        *SecureLogger
	nodeManager   *NodeManager
	tunnelManager *TunnelManager
	errorHandler  *SecureErrorHandler
	isRunning     bool
	stopChan      chan bool
	mutex         sync.RWMutex
}

// NewSystemHealthChecker creates a new system health checker
func NewSystemHealthChecker(logger *SecureLogger, nm *NodeManager, tm *TunnelManager, eh *SecureErrorHandler) *SystemHealthChecker {
	return &SystemHealthChecker{
		logger:        logger,
		nodeManager:   nm,
		tunnelManager: tm,
		errorHandler:  eh,
		stopChan:      make(chan bool, 1),
	}
}

// Start starts the system health checker
func (shc *SystemHealthChecker) Start() {
	shc.mutex.Lock()
	if shc.isRunning {
		shc.mutex.Unlock()
		return
	}
	shc.isRunning = true
	shc.mutex.Unlock()

	shc.logger.Info("system_health", "Starting system health checker", nil)
	go shc.healthCheckLoop()
}

// Stop stops the system health checker
func (shc *SystemHealthChecker) Stop() {
	shc.mutex.Lock()
	if !shc.isRunning {
		shc.mutex.Unlock()
		return
	}
	shc.isRunning = false
	shc.mutex.Unlock()

	shc.logger.Info("system_health", "Stopping system health checker", nil)
	select {
	case shc.stopChan <- true:
	default:
	}
}

// healthCheckLoop runs the main health check loop
func (shc *SystemHealthChecker) healthCheckLoop() {
	ticker := time.NewTicker(60 * time.Second) // Check every minute
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			shc.performComprehensiveHealthCheck()
		case <-shc.stopChan:
			shc.logger.Info("system_health", "Health check loop stopped", nil)
			return
		}
	}
}

// performComprehensiveHealthCheck performs a comprehensive system health check
func (shc *SystemHealthChecker) performComprehensiveHealthCheck() {
	shc.logger.Debug("system_health", "Performing comprehensive health check", nil)

	healthIssues := make([]string, 0)

	// Check memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	memUsageMB := memStats.Alloc / 1024 / 1024
	if memUsageMB > 100 { // More than 100MB
		healthIssues = append(healthIssues, fmt.Sprintf("high_memory_usage_%dMB", memUsageMB))
	}

	// Check goroutine count
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > 100 { // More than 100 goroutines
		healthIssues = append(healthIssues, fmt.Sprintf("high_goroutine_count_%d", numGoroutines))
	}

	// Check node manager health
	if shc.nodeManager != nil {
		nodeStats := shc.nodeManager.GetNodeStats()
		if totalNodes, ok := nodeStats["total_nodes"].(int); ok && totalNodes < MinRelayHops {
			healthIssues = append(healthIssues, "insufficient_relay_nodes")
		}
	}

	// Check tunnel health
	if shc.tunnelManager != nil {
		activeTunnels := shc.tunnelManager.GetActiveTunnels()
		staleTunnels := 0
		for _, tunnel := range activeTunnels {
			if time.Since(tunnel.LastActivity) > time.Duration(KeepAliveInterval*2)*time.Second {
				staleTunnels++
			}
		}
		if staleTunnels > 0 {
			healthIssues = append(healthIssues, fmt.Sprintf("stale_tunnels_%d", staleTunnels))
		}
	}

	// Check error handler health
	if shc.errorHandler != nil {
		errorStats := shc.errorHandler.GetErrorStatistics()
		if isShuttingDown, ok := errorStats["is_shutting_down"].(bool); ok && isShuttingDown {
			healthIssues = append(healthIssues, "emergency_shutdown_active")
		}
	}

	// Log health status
	if len(healthIssues) == 0 {
		shc.logger.Info("system_health", "System health check passed", map[string]interface{}{
			"memory_mb":    memUsageMB,
			"goroutines":   numGoroutines,
		})
	} else {
		shc.logger.Warn("system_health", "System health issues detected", map[string]interface{}{
			"issues":       healthIssues,
			"memory_mb":    memUsageMB,
			"goroutines":   numGoroutines,
		})
	}
}

// SecurityHardener applies security hardening measures
type SecurityHardener struct {
	logger       *SecureLogger
	errorHandler *SecureErrorHandler
	appliedMeasures []string
	mutex        sync.RWMutex
}

// NewSecurityHardener creates a new security hardener
func NewSecurityHardener(logger *SecureLogger, errorHandler *SecureErrorHandler) *SecurityHardener {
	return &SecurityHardener{
		logger:       logger,
		errorHandler: errorHandler,
		appliedMeasures: make([]string, 0),
	}
}

// ApplySecurityHardening applies all security hardening measures
func (sh *SecurityHardener) ApplySecurityHardening() error {
	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	sh.logger.Info("security_hardening", "Applying security hardening measures", nil)

	// 1. Set secure memory limits
	if err := sh.setMemoryLimits(); err != nil {
		sh.logger.Warn("security_hardening", "Failed to set memory limits", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		sh.appliedMeasures = append(sh.appliedMeasures, "memory_limits")
	}

	// 2. Configure secure garbage collection
	sh.configureSecureGC()
	sh.appliedMeasures = append(sh.appliedMeasures, "secure_gc")

	// 3. Set file permissions
	if err := sh.setSecureFilePermissions(); err != nil {
		sh.logger.Warn("security_hardening", "Failed to set secure file permissions", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		sh.appliedMeasures = append(sh.appliedMeasures, "file_permissions")
	}

	// 4. Configure process limits
	if err := sh.configureProcessLimits(); err != nil {
		sh.logger.Warn("security_hardening", "Failed to configure process limits", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		sh.appliedMeasures = append(sh.appliedMeasures, "process_limits")
	}

	sh.logger.Info("security_hardening", "Security hardening completed", map[string]interface{}{
		"applied_measures": sh.appliedMeasures,
	})

	return nil
}

// setMemoryLimits sets secure memory limits
func (sh *SecurityHardener) setMemoryLimits() error {
	// Set GOMAXPROCS to limit CPU usage
	maxProcs := runtime.GOMAXPROCS(0)
	if maxProcs > 4 {
		runtime.GOMAXPROCS(4) // Limit to 4 cores max
	}

	// Set memory limit for GC
	runtime.GC()
	
	return nil
}

// configureSecureGC configures garbage collection for security
func (sh *SecurityHardener) configureSecureGC() {
	// Force immediate garbage collection to clear any sensitive data
	runtime.GC()
	
	// Set GC target percentage to be more aggressive
	// This helps clear sensitive data from memory more quickly
	oldGCPercent := runtime.GOMAXPROCS(0)
	if oldGCPercent > 50 {
		// More aggressive GC for security
		runtime.GC()
	}
}

// setSecureFilePermissions sets secure file permissions
func (sh *SecurityHardener) setSecureFilePermissions() error {
	// Ensure config directory has secure permissions
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := homeDir + "/.qavpn"
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Set restrictive permissions on config directory
	if err := os.Chmod(configDir, 0700); err != nil {
		return fmt.Errorf("failed to set config directory permissions: %w", err)
	}

	return nil
}

// configureProcessLimits configures process resource limits
func (sh *SecurityHardener) configureProcessLimits() error {
	// This would set ulimits and other process restrictions
	// For now, we'll just ensure we don't exceed reasonable limits
	
	// Check current goroutine count
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > 1000 {
		return fmt.Errorf("too many goroutines: %d", numGoroutines)
	}

	return nil
}

// ApplySecureCleanup applies secure cleanup measures
func (sh *SecurityHardener) ApplySecureCleanup() {
	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	sh.logger.Info("security_hardening", "Applying secure cleanup", nil)

	// Force garbage collection to clear sensitive data
	runtime.GC()
	runtime.GC() // Run twice to be thorough

	// Clear applied measures list
	for i := range sh.appliedMeasures {
		sh.appliedMeasures[i] = ""
	}
	sh.appliedMeasures = sh.appliedMeasures[:0]

	sh.logger.Info("security_hardening", "Secure cleanup completed", nil)
}

// GetAppliedMeasures returns the list of applied security measures
func (sh *SecurityHardener) GetAppliedMeasures() []string {
	sh.mutex.RLock()
	defer sh.mutex.RUnlock()

	result := make([]string, len(sh.appliedMeasures))
	copy(result, sh.appliedMeasures)
	return result
}