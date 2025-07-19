package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time
	Level     LogLevel
	Component string
	Message   string
	Metadata  map[string]interface{}
}

// SecureLogger provides privacy-preserving logging functionality
type SecureLogger struct {
	level       LogLevel
	entries     []LogEntry
	maxEntries  int
	mutex       sync.RWMutex
	outputFile  *os.File
	enableFile  bool
}

// NewSecureLogger creates a new secure logger
func NewSecureLogger(level LogLevel) *SecureLogger {
	return &SecureLogger{
		level:      level,
		entries:    make([]LogEntry, 0),
		maxEntries: 1000, // Keep last 1000 entries in memory
		enableFile: false,
	}
}

// SetFileOutput enables logging to a file
func (sl *SecureLogger) SetFileOutput(filename string) error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	// Close existing file if open
	if sl.outputFile != nil {
		sl.outputFile.Close()
	}

	// Open new log file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	sl.outputFile = file
	sl.enableFile = true
	return nil
}

// Log writes a log entry with the specified level
func (sl *SecureLogger) Log(level LogLevel, component, message string, metadata map[string]interface{}) {
	if level > sl.level {
		return // Skip if log level is too verbose
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Component: component,
		Message:   sanitizeLogMessage(message),
		Metadata:  sanitizeMetadata(metadata),
	}

	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	// Add to in-memory entries
	sl.entries = append(sl.entries, entry)
	
	// Maintain max entries limit
	if len(sl.entries) > sl.maxEntries {
		sl.entries = sl.entries[1:] // Remove oldest entry
	}

	// Write to console
	sl.writeToConsole(entry)

	// Write to file if enabled
	if sl.enableFile && sl.outputFile != nil {
		sl.writeToFile(entry)
	}
}

// Error logs an error message
func (sl *SecureLogger) Error(component, message string, metadata map[string]interface{}) {
	sl.Log(LogLevelError, component, message, metadata)
}

// Warn logs a warning message
func (sl *SecureLogger) Warn(component, message string, metadata map[string]interface{}) {
	sl.Log(LogLevelWarn, component, message, metadata)
}

// Info logs an info message
func (sl *SecureLogger) Info(component, message string, metadata map[string]interface{}) {
	sl.Log(LogLevelInfo, component, message, metadata)
}

// Debug logs a debug message
func (sl *SecureLogger) Debug(component, message string, metadata map[string]interface{}) {
	sl.Log(LogLevelDebug, component, message, metadata)
}

// writeToConsole writes log entry to console
func (sl *SecureLogger) writeToConsole(entry LogEntry) {
	levelStr := sl.levelString(entry.Level)
	timestamp := entry.Timestamp.Format("15:04:05")
	
	if len(entry.Metadata) > 0 {
		fmt.Printf("[%s] %s [%s] %s %v\n", 
			timestamp, levelStr, entry.Component, entry.Message, entry.Metadata)
	} else {
		fmt.Printf("[%s] %s [%s] %s\n", 
			timestamp, levelStr, entry.Component, entry.Message)
	}
}

// writeToFile writes log entry to file
func (sl *SecureLogger) writeToFile(entry LogEntry) {
	levelStr := sl.levelString(entry.Level)
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
	
	logLine := fmt.Sprintf("[%s] %s [%s] %s", 
		timestamp, levelStr, entry.Component, entry.Message)
	
	if len(entry.Metadata) > 0 {
		logLine += fmt.Sprintf(" %v", entry.Metadata)
	}
	logLine += "\n"
	
	sl.outputFile.WriteString(logLine)
	sl.outputFile.Sync() // Ensure data is written to disk
}

// levelString returns string representation of log level
func (sl *SecureLogger) levelString(level LogLevel) string {
	switch level {
	case LogLevelError:
		return "ERROR"
	case LogLevelWarn:
		return "WARN "
	case LogLevelInfo:
		return "INFO "
	case LogLevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// GetRecentEntries returns recent log entries
func (sl *SecureLogger) GetRecentEntries(count int) []LogEntry {
	sl.mutex.RLock()
	defer sl.mutex.RUnlock()

	if count <= 0 || count > len(sl.entries) {
		count = len(sl.entries)
	}

	// Return last 'count' entries
	start := len(sl.entries) - count
	result := make([]LogEntry, count)
	copy(result, sl.entries[start:])
	
	return result
}

// GetEntriesByComponent returns log entries for a specific component
func (sl *SecureLogger) GetEntriesByComponent(component string, count int) []LogEntry {
	sl.mutex.RLock()
	defer sl.mutex.RUnlock()

	var result []LogEntry
	
	// Search backwards through entries
	for i := len(sl.entries) - 1; i >= 0 && len(result) < count; i-- {
		if sl.entries[i].Component == component {
			result = append([]LogEntry{sl.entries[i]}, result...) // Prepend to maintain order
		}
	}
	
	return result
}

// Close closes the logger and any open files
func (sl *SecureLogger) Close() error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	if sl.outputFile != nil {
		err := sl.outputFile.Close()
		sl.outputFile = nil
		sl.enableFile = false
		return err
	}
	
	return nil
}

// sanitizeLogMessage removes sensitive information from log messages
func sanitizeLogMessage(message string) string {
	// List of sensitive patterns to remove or replace
	sensitivePatterns := []string{
		"key", "secret", "password", "token", "auth", "crypto",
		"private", "confidential", "sensitive",
	}

	// Simple sanitization - in production this would be more sophisticated
	for _, pattern := range sensitivePatterns {
		if containsString(message, pattern) {
			// Replace with generic message if sensitive content detected
			return "operation completed"
		}
	}
	
	return message
}

// sanitizeMetadata removes sensitive information from metadata
func sanitizeMetadata(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	
	for key, value := range metadata {
		// Skip sensitive keys
		if isSensitiveKey(key) {
			continue
		}
		
		// Sanitize string values
		if strValue, ok := value.(string); ok {
			sanitized[key] = sanitizeLogMessage(strValue)
		} else {
			sanitized[key] = value
		}
	}
	
	return sanitized
}

// isSensitiveKey checks if a metadata key contains sensitive information
func isSensitiveKey(key string) bool {
	// Exact matches for sensitive keys
	exactSensitiveKeys := []string{
		"key", "secret", "password", "token", "auth", "crypto",
		"private", "confidential", "sensitive", "address", "ip",
		"node_id", "route", "hop", "private_key", "public_key",
		"secret_key", "auth_token", "crypto_key",
	}
	
	// Check for exact matches first
	for _, sensitiveKey := range exactSensitiveKeys {
		if key == sensitiveKey {
			return true
		}
	}
	
	// Check for sensitive patterns (more restrictive)
	sensitivePatterns := []string{
		"private_key", "secret_key", "crypto_key", "auth_key",
		"key_material", "password_", "token_", "auth_token",
	}
	
	for _, pattern := range sensitivePatterns {
		if containsString(key, pattern) {
			return true
		}
	}
	
	return false
}

// ConnectionMonitor monitors connection health and status
type ConnectionMonitor struct {
	logger          *SecureLogger
	nodeManager     *NodeManager
	tunnelManager   *TunnelManager
	healthChecks    map[string]*HealthCheck
	mutex           sync.RWMutex
	checkInterval   time.Duration
	isRunning       bool
	stopChan        chan bool
}

// HealthCheck represents a health check result
type HealthCheck struct {
	Component   string
	Status      HealthStatus
	LastCheck   time.Time
	LastSuccess time.Time
	FailureCount int
	Details     map[string]interface{}
}

// HealthStatus represents the health status of a component
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusDegraded
	HealthStatusUnhealthy
)

// NewConnectionMonitor creates a new connection monitor
func NewConnectionMonitor(logger *SecureLogger, nm *NodeManager, tm *TunnelManager) *ConnectionMonitor {
	return &ConnectionMonitor{
		logger:        logger,
		nodeManager:   nm,
		tunnelManager: tm,
		healthChecks:  make(map[string]*HealthCheck),
		checkInterval: 30 * time.Second,
		stopChan:      make(chan bool, 1),
	}
}

// Start starts the connection monitoring
func (cm *ConnectionMonitor) Start() {
	cm.mutex.Lock()
	if cm.isRunning {
		cm.mutex.Unlock()
		return
	}
	cm.isRunning = true
	cm.mutex.Unlock()

	cm.logger.Info("connection_monitor", "Starting connection monitoring", map[string]interface{}{
		"check_interval": cm.checkInterval.String(),
	})

	go cm.monitoringLoop()
}

// Stop stops the connection monitoring
func (cm *ConnectionMonitor) Stop() {
	cm.mutex.Lock()
	if !cm.isRunning {
		cm.mutex.Unlock()
		return
	}
	cm.isRunning = false
	cm.mutex.Unlock()

	cm.logger.Info("connection_monitor", "Stopping connection monitoring", nil)
	
	select {
	case cm.stopChan <- true:
	default:
	}
}

// monitoringLoop runs the main monitoring loop
func (cm *ConnectionMonitor) monitoringLoop() {
	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cm.performHealthChecks()
		case <-cm.stopChan:
			cm.logger.Info("connection_monitor", "Monitoring loop stopped", nil)
			return
		}
	}
}

// performHealthChecks performs all health checks
func (cm *ConnectionMonitor) performHealthChecks() {
	cm.logger.Debug("connection_monitor", "Performing health checks", nil)

	// Check node manager health
	cm.checkNodeManagerHealth()

	// Check tunnel manager health
	cm.checkTunnelManagerHealth()

	// Check individual tunnel health
	cm.checkTunnelHealth()

	// Check route health
	cm.checkRouteHealth()

	// Log overall health summary
	cm.logHealthSummary()
}

// checkNodeManagerHealth checks the health of the node manager
func (cm *ConnectionMonitor) checkNodeManagerHealth() {
	component := "node_manager"
	
	healthCheck := &HealthCheck{
		Component: component,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get node statistics
	nodeStats := cm.nodeManager.GetNodeStats()
	totalNodes := nodeStats["total_nodes"].(int)
	
	healthCheck.Details["total_nodes"] = totalNodes
	healthCheck.Details["is_relay"] = nodeStats["is_relay"]

	// Determine health status
	if totalNodes >= MinRelayHops {
		healthCheck.Status = HealthStatusHealthy
		healthCheck.LastSuccess = time.Now()
		healthCheck.FailureCount = 0
	} else if totalNodes > 0 {
		healthCheck.Status = HealthStatusDegraded
		healthCheck.FailureCount++
	} else {
		healthCheck.Status = HealthStatusUnhealthy
		healthCheck.FailureCount++
	}

	cm.mutex.Lock()
	cm.healthChecks[component] = healthCheck
	cm.mutex.Unlock()

	// Log health status
	cm.logger.Debug("connection_monitor", "Node manager health check completed", map[string]interface{}{
		"status": cm.healthStatusString(healthCheck.Status),
		"total_nodes": totalNodes,
	})
}

// checkTunnelManagerHealth checks the health of the tunnel manager
func (cm *ConnectionMonitor) checkTunnelManagerHealth() {
	component := "tunnel_manager"
	
	healthCheck := &HealthCheck{
		Component: component,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Check if tunnel manager is available (nil check for relay nodes)
	if cm.tunnelManager == nil {
		// For relay nodes, tunnel manager is not applicable
		healthCheck.Status = HealthStatusHealthy // Not applicable, but system is healthy
		healthCheck.Details["active_tunnels"] = 0
		healthCheck.Details["tunnel_manager_available"] = false
		healthCheck.Details["note"] = "TunnelManager not applicable for relay nodes"
		healthCheck.LastSuccess = time.Now()
		healthCheck.FailureCount = 0
		
		cm.logger.Debug("connection_monitor", "Tunnel manager health check completed - not applicable for relay node", map[string]interface{}{
			"status": cm.healthStatusString(healthCheck.Status),
			"tunnel_manager_available": false,
		})
	} else {
		// Get tunnel statistics safely
		activeTunnels := cm.tunnelManager.GetActiveTunnels()
		healthCheck.Details["active_tunnels"] = len(activeTunnels)
		healthCheck.Details["tunnel_manager_available"] = true

		// Determine health status based on active tunnels
		if len(activeTunnels) > 0 {
			healthCheck.Status = HealthStatusHealthy
			healthCheck.LastSuccess = time.Now()
			healthCheck.FailureCount = 0
		} else {
			healthCheck.Status = HealthStatusDegraded
			healthCheck.FailureCount++
		}

		cm.logger.Debug("connection_monitor", "Tunnel manager health check completed", map[string]interface{}{
			"status": cm.healthStatusString(healthCheck.Status),
			"active_tunnels": len(activeTunnels),
		})
	}

	cm.mutex.Lock()
	cm.healthChecks[component] = healthCheck
	cm.mutex.Unlock()
}

// checkTunnelHealth checks the health of individual tunnels
func (cm *ConnectionMonitor) checkTunnelHealth() {
	// Skip tunnel health checks if tunnel manager is not available (relay nodes)
	if cm.tunnelManager == nil {
		cm.logger.Debug("connection_monitor", "Skipping individual tunnel health checks - TunnelManager not available", nil)
		return
	}

	activeTunnels := cm.tunnelManager.GetActiveTunnels()
	
	for _, tunnelStats := range activeTunnels {
		component := fmt.Sprintf("tunnel_%s", tunnelStats.RemoteAddr)
		
		healthCheck := &HealthCheck{
			Component: component,
			LastCheck: time.Now(),
			Details:   make(map[string]interface{}),
		}

		healthCheck.Details["remote_addr"] = tunnelStats.RemoteAddr
		healthCheck.Details["created_at"] = tunnelStats.CreatedAt
		healthCheck.Details["last_activity"] = tunnelStats.LastActivity

		// Check tunnel activity
		timeSinceActivity := time.Since(tunnelStats.LastActivity)
		healthCheck.Details["time_since_activity"] = timeSinceActivity.String()

		if timeSinceActivity < time.Duration(KeepAliveInterval)*time.Second {
			healthCheck.Status = HealthStatusHealthy
			healthCheck.LastSuccess = time.Now()
			healthCheck.FailureCount = 0
		} else if timeSinceActivity < time.Duration(KeepAliveInterval*2)*time.Second {
			healthCheck.Status = HealthStatusDegraded
			healthCheck.FailureCount++
		} else {
			healthCheck.Status = HealthStatusUnhealthy
			healthCheck.FailureCount++
		}

		cm.mutex.Lock()
		cm.healthChecks[component] = healthCheck
		cm.mutex.Unlock()

		if healthCheck.Status != HealthStatusHealthy {
			cm.logger.Warn("connection_monitor", "Tunnel health degraded", map[string]interface{}{
				"tunnel": tunnelStats.RemoteAddr,
				"status": cm.healthStatusString(healthCheck.Status),
				"time_since_activity": timeSinceActivity.String(),
			})
		}
	}

	// Also check direct connection health if direct integration is available
	cm.checkDirectConnectionHealth()
}

// checkDirectConnectionHealth checks the health of direct connections
func (cm *ConnectionMonitor) checkDirectConnectionHealth() {
	integrator := GetGlobalDirectIntegrator()
	if integrator == nil {
		return // Direct integration not available
	}

	// Clean up inactive tunnels first
	integrator.CleanupInactiveTunnels()

	// Check direct connection health
	activeTunnelCount := integrator.GetActiveTunnelCount()
	
	component := "direct_connections"
	healthCheck := &HealthCheck{
		Component: component,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	healthCheck.Details["active_direct_tunnels"] = activeTunnelCount
	healthCheck.Details["has_active_connections"] = integrator.HasActiveDirectConnections()

	if integrator.HasActiveDirectConnections() {
		healthCheck.Status = HealthStatusHealthy
		healthCheck.LastSuccess = time.Now()
		healthCheck.FailureCount = 0
		
		cm.logger.Debug("connection_monitor", "Direct connections healthy", map[string]interface{}{
			"active_tunnels": activeTunnelCount,
		})
	} else {
		healthCheck.Status = HealthStatusDegraded
		healthCheck.FailureCount++
		
		cm.logger.Debug("connection_monitor", "No active direct connections", nil)
	}

	cm.mutex.Lock()
	cm.healthChecks[component] = healthCheck
	cm.mutex.Unlock()
}

// checkRouteHealth checks the health of active routes
func (cm *ConnectionMonitor) checkRouteHealth() {
	component := "routes"
	
	healthCheck := &HealthCheck{
		Component: component,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get active routes
	activeRoutes := cm.nodeManager.GetActiveRoutes()
	healthCheck.Details["active_routes"] = len(activeRoutes)

	// Check route health
	healthyRoutes := 0
	for _, route := range activeRoutes {
		if route.Active && time.Since(route.CreatedAt) < 30*time.Minute {
			healthyRoutes++
		}
	}

	healthCheck.Details["healthy_routes"] = healthyRoutes

	// Determine overall route health
	if healthyRoutes > 0 {
		healthCheck.Status = HealthStatusHealthy
		healthCheck.LastSuccess = time.Now()
		healthCheck.FailureCount = 0
	} else if len(activeRoutes) > 0 {
		healthCheck.Status = HealthStatusDegraded
		healthCheck.FailureCount++
	} else {
		healthCheck.Status = HealthStatusUnhealthy
		healthCheck.FailureCount++
	}

	cm.mutex.Lock()
	cm.healthChecks[component] = healthCheck
	cm.mutex.Unlock()

	cm.logger.Debug("connection_monitor", "Route health check completed", map[string]interface{}{
		"status": cm.healthStatusString(healthCheck.Status),
		"active_routes": len(activeRoutes),
		"healthy_routes": healthyRoutes,
	})
}

// logHealthSummary logs a summary of all health checks
func (cm *ConnectionMonitor) logHealthSummary() {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	summary := make(map[string]interface{})
	overallHealthy := true

	for component, healthCheck := range cm.healthChecks {
		summary[component] = cm.healthStatusString(healthCheck.Status)
		if healthCheck.Status != HealthStatusHealthy {
			overallHealthy = false
		}
	}

	summary["overall_healthy"] = overallHealthy

	if overallHealthy {
		cm.logger.Info("connection_monitor", "System health check completed - all systems healthy", summary)
	} else {
		cm.logger.Warn("connection_monitor", "System health check completed - some issues detected", summary)
	}
}

// healthStatusString returns string representation of health status
func (cm *ConnectionMonitor) healthStatusString(status HealthStatus) string {
	switch status {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// GetHealthStatus returns the current health status of all components
func (cm *ConnectionMonitor) GetHealthStatus() map[string]*HealthCheck {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	result := make(map[string]*HealthCheck)
	for component, healthCheck := range cm.healthChecks {
		// Create a copy to avoid race conditions
		result[component] = &HealthCheck{
			Component:    healthCheck.Component,
			Status:       healthCheck.Status,
			LastCheck:    healthCheck.LastCheck,
			LastSuccess:  healthCheck.LastSuccess,
			FailureCount: healthCheck.FailureCount,
			Details:      make(map[string]interface{}),
		}
		
		// Copy details
		for k, v := range healthCheck.Details {
			result[component].Details[k] = v
		}
	}

	return result
}

// GetComponentHealth returns health status for a specific component
func (cm *ConnectionMonitor) GetComponentHealth(component string) *HealthCheck {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if healthCheck, exists := cm.healthChecks[component]; exists {
		// Return a copy
		return &HealthCheck{
			Component:    healthCheck.Component,
			Status:       healthCheck.Status,
			LastCheck:    healthCheck.LastCheck,
			LastSuccess:  healthCheck.LastSuccess,
			FailureCount: healthCheck.FailureCount,
			Details:      healthCheck.Details,
		}
	}

	return nil
}

// IsHealthy returns true if all components are healthy
func (cm *ConnectionMonitor) IsHealthy() bool {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for _, healthCheck := range cm.healthChecks {
		if healthCheck.Status != HealthStatusHealthy {
			return false
		}
	}

	return true
}
