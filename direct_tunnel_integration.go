package main

import (
	"fmt"
	"sync"
	"time"

	"qavpn/direct"
)

// DirectTunnelWrapper wraps a DirectConnection to implement the Tunnel interface
type DirectTunnelWrapper struct {
	directConn   *direct.DirectConnection
	connectionID string
	manager      direct.DirectConnectionManager
	isActive     bool
	mutex        sync.RWMutex
}

// NewDirectTunnelWrapper creates a new DirectTunnelWrapper
func NewDirectTunnelWrapper(directConn *direct.DirectConnection, manager direct.DirectConnectionManager) *DirectTunnelWrapper {
	return &DirectTunnelWrapper{
		directConn:   directConn,
		connectionID: fmt.Sprintf("%x", directConn.ConnectionID),
		manager:      manager,
		isActive:     true,
	}
}

// SendData sends data through the direct connection
func (dtw *DirectTunnelWrapper) SendData(data []byte) error {
	dtw.mutex.RLock()
	defer dtw.mutex.RUnlock()

	if !dtw.isActive {
		return fmt.Errorf("direct tunnel is not active")
	}

	return dtw.directConn.SendData(data)
}

// ReceiveData receives data from the direct connection
func (dtw *DirectTunnelWrapper) ReceiveData() ([]byte, error) {
	dtw.mutex.RLock()
	defer dtw.mutex.RUnlock()

	if !dtw.isActive {
		return nil, fmt.Errorf("direct tunnel is not active")
	}

	return dtw.directConn.ReceiveData()
}

// Close closes the direct tunnel
func (dtw *DirectTunnelWrapper) Close() error {
	dtw.mutex.Lock()
	defer dtw.mutex.Unlock()

	if !dtw.isActive {
		return nil
	}

	dtw.isActive = false
	
	// Disconnect the direct connection
	if err := dtw.directConn.Close(); err != nil {
		return fmt.Errorf("failed to close direct connection: %w", err)
	}

	// Disconnect from manager
	if err := dtw.manager.DisconnectPeer(dtw.connectionID); err != nil {
		// Log error but don't fail - connection might already be cleaned up
		fmt.Printf("Warning: failed to disconnect peer from manager: %v\n", err)
	}

	return nil
}

// IsActive returns whether the direct tunnel is active
func (dtw *DirectTunnelWrapper) IsActive() bool {
	dtw.mutex.RLock()
	defer dtw.mutex.RUnlock()

	if !dtw.isActive {
		return false
	}

	// Check if the underlying direct connection is healthy
	return dtw.directConn.IsHealthy()
}

// DirectConnectionIntegrator manages integration between direct connections and the main system
type DirectConnectionIntegrator struct {
	manager       direct.DirectConnectionManager
	systemConfig  *Config
	activeTunnels map[string]*DirectTunnelWrapper
	mutex         sync.RWMutex
}

// NewDirectConnectionIntegrator creates a new DirectConnectionIntegrator
func NewDirectConnectionIntegrator(config *Config) (*DirectConnectionIntegrator, error) {
	if config.DirectMode == nil || !config.DirectMode.Enabled {
		return nil, fmt.Errorf("direct mode is not enabled")
	}

	// Create direct config from main config
	directConfig := &direct.DirectConfig{
		DefaultProtocol:   config.DirectMode.DefaultProtocol,
		DefaultPort:       config.DirectMode.DefaultPort,
		ConnectionTimeout: time.Duration(config.DirectMode.ConnectionTimeout) * time.Second,
		KeepAliveInterval: time.Duration(config.DirectMode.KeepAliveInterval) * time.Second,
		MaxConnections:    config.DirectMode.MaxConnections,
		EnableOPSEC:       config.DirectMode.EnableOPSEC,
	}

	manager := direct.NewDirectConnectionManager(directConfig)

	return &DirectConnectionIntegrator{
		manager:       manager,
		systemConfig:  config,
		activeTunnels: make(map[string]*DirectTunnelWrapper),
	}, nil
}

// GetBestDirectTunnel returns the best available direct tunnel
func (dci *DirectConnectionIntegrator) GetBestDirectTunnel() (Tunnel, error) {
	dci.mutex.RLock()
	defer dci.mutex.RUnlock()

	// Get active direct connections from manager
	activeConnections := dci.manager.GetActiveConnections()
	if len(activeConnections) == 0 {
		return nil, fmt.Errorf("no active direct connections available")
	}

	// Find the healthiest connection
	var bestConnection *direct.DirectConnection
	for _, conn := range activeConnections {
		if conn.IsHealthy() {
			if bestConnection == nil || conn.IsActive() {
				bestConnection = conn
			}
		}
	}

	if bestConnection == nil {
		return nil, fmt.Errorf("no healthy direct connections available")
	}

	// Create or get existing tunnel wrapper
	connectionID := fmt.Sprintf("%x", bestConnection.ConnectionID)
	if existingTunnel, exists := dci.activeTunnels[connectionID]; exists && existingTunnel.IsActive() {
		return existingTunnel, nil
	}

	// Create new tunnel wrapper
	tunnelWrapper := NewDirectTunnelWrapper(bestConnection, dci.manager)
	dci.activeTunnels[connectionID] = tunnelWrapper

	return tunnelWrapper, nil
}

// HasActiveDirectConnections checks if there are any active direct connections
func (dci *DirectConnectionIntegrator) HasActiveDirectConnections() bool {
	activeConnections := dci.manager.GetActiveConnections()
	
	for _, conn := range activeConnections {
		if conn.IsHealthy() && conn.IsActive() {
			return true
		}
	}

	return false
}

// GetDirectConnectionManager returns the underlying direct connection manager
func (dci *DirectConnectionIntegrator) GetDirectConnectionManager() direct.DirectConnectionManager {
	return dci.manager
}

// CleanupInactiveTunnels removes inactive tunnel wrappers
func (dci *DirectConnectionIntegrator) CleanupInactiveTunnels() {
	dci.mutex.Lock()
	defer dci.mutex.Unlock()

	for connectionID, tunnel := range dci.activeTunnels {
		if !tunnel.IsActive() {
			delete(dci.activeTunnels, connectionID)
		}
	}
}

// GetActiveTunnelCount returns the number of active direct tunnels
func (dci *DirectConnectionIntegrator) GetActiveTunnelCount() int {
	dci.mutex.RLock()
	defer dci.mutex.RUnlock()

	activeCount := 0
	for _, tunnel := range dci.activeTunnels {
		if tunnel.IsActive() {
			activeCount++
		}
	}

	return activeCount
}

// Shutdown gracefully shuts down the direct connection integrator
func (dci *DirectConnectionIntegrator) Shutdown() error {
	dci.mutex.Lock()
	defer dci.mutex.Unlock()

	// Close all active tunnels
	for _, tunnel := range dci.activeTunnels {
		if err := tunnel.Close(); err != nil {
			fmt.Printf("Warning: failed to close direct tunnel: %v\n", err)
		}
	}

	// Clear the tunnels map
	dci.activeTunnels = make(map[string]*DirectTunnelWrapper)

	// Shutdown the direct connection manager
	if managerImpl, ok := dci.manager.(*direct.DirectConnectionManagerImpl); ok {
		return managerImpl.Shutdown()
	}

	return nil
}

// Global direct connection integrator instance
var globalDirectIntegrator *DirectConnectionIntegrator

// InitializeDirectIntegration initializes the global direct connection integration
func InitializeDirectIntegration(config *Config) error {
	if config.DirectMode == nil || !config.DirectMode.Enabled {
		return nil // Direct mode not enabled, skip initialization
	}

	integrator, err := NewDirectConnectionIntegrator(config)
	if err != nil {
		return fmt.Errorf("failed to create direct connection integrator: %w", err)
	}

	globalDirectIntegrator = integrator
	return nil
}

// GetGlobalDirectIntegrator returns the global direct connection integrator
func GetGlobalDirectIntegrator() *DirectConnectionIntegrator {
	return globalDirectIntegrator
}

// ShutdownDirectIntegration shuts down the global direct connection integration
func ShutdownDirectIntegration() error {
	if globalDirectIntegrator != nil {
		err := globalDirectIntegrator.Shutdown()
		globalDirectIntegrator = nil
		return err
	}
	return nil
}
