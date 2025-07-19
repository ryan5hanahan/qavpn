package direct

import (
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"sync"
	"time"
)

// DirectTCPTunnel extends the existing TCPTunnel with direct connection features
type DirectTCPTunnel struct {
	conn             net.Conn
	cryptoContext    *CryptoContext
	localAddr        net.Addr
	remoteAddr       net.Addr
	isActive         bool
	createdAt        time.Time
	lastActivity     time.Time
	connectionID     [16]byte
	role            ConnectionRole
	directFeatures  *DirectConnectionFeatures
	mutex           sync.RWMutex
}

// DirectUDPTunnel extends the existing UDPTunnel with direct connection features
type DirectUDPTunnel struct {
	conn             *net.UDPConn
	remoteAddr       *net.UDPAddr
	cryptoContext    *CryptoContext
	localAddr        net.Addr
	isActive         bool
	createdAt        time.Time
	lastActivity     time.Time
	sessionID        [16]byte
	connectionID     [16]byte
	role            ConnectionRole
	directFeatures  *DirectConnectionFeatures
	mutex           sync.RWMutex
}

// DirectConnectionFeatures contains direct connection specific features
type DirectConnectionFeatures struct {
	trafficObfuscation *TrafficObfuscator
	keepAliveManager   *KeepAliveManager
	healthMonitor      *TunnelHealthMonitor
	retryManager       *ConnectionRetryManager
	metrics           *EnhancedTunnelMetrics
	mutex             sync.RWMutex
}

// TrafficObfuscator handles traffic obfuscation for OPSEC
type TrafficObfuscator struct {
	enabled       bool
	noiseInterval time.Duration
	lastNoise     time.Time
	mutex         sync.RWMutex
}

// KeepAliveManager handles secure keep-alive mechanisms
type KeepAliveManager struct {
	interval      time.Duration
	lastKeepAlive time.Time
	enabled       bool
	randomJitter  bool
	mutex         sync.RWMutex
}

// TunnelHealthMonitor monitors connection health and quality
type TunnelHealthMonitor struct {
	enabled           bool
	checkInterval     time.Duration
	lastHealthCheck   time.Time
	consecutiveFailures int
	maxFailures       int
	healthStatus      ConnectionHealthStatus
	mutex             sync.RWMutex
}

// ConnectionRetryManager handles connection retry logic with exponential backoff
type ConnectionRetryManager struct {
	maxRetries      int
	baseDelay       time.Duration
	maxDelay        time.Duration
	currentAttempt  int
	lastRetryTime   time.Time
	backoffFactor   float64
	jitterEnabled   bool
	mutex           sync.RWMutex
}

// EnhancedTunnelMetrics provides detailed tunnel metrics
type EnhancedTunnelMetrics struct {
	BytesSent           uint64
	BytesReceived       uint64
	PacketsSent         uint64
	PacketsReceived     uint64
	KeepAlivesSent      uint64
	KeepAlivesReceived  uint64
	HealthChecksPassed  uint64
	HealthChecksFailed  uint64
	ReconnectionAttempts uint64
	LastLatency         time.Duration
	AverageLatency      time.Duration
	ThroughputBps       float64
	PacketLossRate      float64
	ConnectionUptime    time.Duration
	mutex               sync.RWMutex
}

// ConnectionHealthStatus represents the health status of a connection
type ConnectionHealthStatus int

const (
	HealthStatusUnknown ConnectionHealthStatus = iota
	HealthStatusHealthy
	HealthStatusDegraded
	HealthStatusUnhealthy
	HealthStatusFailed
)

// String returns the string representation of the health status
func (h ConnectionHealthStatus) String() string {
	switch h {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	case HealthStatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// NewDirectTCPTunnel creates a new DirectTCPTunnel with enhanced features
func NewDirectTCPTunnel(conn net.Conn, cryptoContext *CryptoContext, connectionID [16]byte, role ConnectionRole) *DirectTCPTunnel {
	tunnel := &DirectTCPTunnel{
		conn:          conn,
		cryptoContext: cryptoContext,
		localAddr:     conn.LocalAddr(),
		remoteAddr:    conn.RemoteAddr(),
		isActive:      true,
		createdAt:     time.Now(),
		lastActivity:  time.Now(),
		connectionID:  connectionID,
		role:         role,
	}

	// Initialize direct connection features
	tunnel.directFeatures = &DirectConnectionFeatures{
		trafficObfuscation: &TrafficObfuscator{
			enabled:       true,
			noiseInterval: 30 * time.Second,
		},
		keepAliveManager: &KeepAliveManager{
			interval:     60 * time.Second,
			enabled:      true,
			randomJitter: true,
		},
		healthMonitor: &TunnelHealthMonitor{
			enabled:       true,
			checkInterval: 30 * time.Second,
			maxFailures:   3,
			healthStatus:  HealthStatusHealthy,
		},
		retryManager: &ConnectionRetryManager{
			maxRetries:    5,
			baseDelay:     1 * time.Second,
			maxDelay:      30 * time.Second,
			backoffFactor: 2.0,
			jitterEnabled: true,
		},
		metrics: &EnhancedTunnelMetrics{},
	}

	return tunnel
}

// NewDirectUDPTunnel creates a new DirectUDPTunnel with enhanced features
func NewDirectUDPTunnel(conn *net.UDPConn, remoteAddr *net.UDPAddr, cryptoContext *CryptoContext, sessionID [16]byte, connectionID [16]byte, role ConnectionRole) *DirectUDPTunnel {
	tunnel := &DirectUDPTunnel{
		conn:          conn,
		remoteAddr:    remoteAddr,
		cryptoContext: cryptoContext,
		localAddr:     conn.LocalAddr(),
		isActive:      true,
		createdAt:     time.Now(),
		lastActivity:  time.Now(),
		sessionID:     sessionID,
		connectionID:  connectionID,
		role:         role,
	}

	// Initialize direct connection features (same as TCP)
	tunnel.directFeatures = &DirectConnectionFeatures{
		trafficObfuscation: &TrafficObfuscator{
			enabled:       true,
			noiseInterval: 30 * time.Second,
		},
		keepAliveManager: &KeepAliveManager{
			interval:     60 * time.Second,
			enabled:      true,
			randomJitter: true,
		},
		healthMonitor: &TunnelHealthMonitor{
			enabled:       true,
			checkInterval: 30 * time.Second,
			maxFailures:   3,
			healthStatus:  HealthStatusHealthy,
		},
		retryManager: &ConnectionRetryManager{
			maxRetries:    5,
			baseDelay:     1 * time.Second,
			maxDelay:      30 * time.Second,
			backoffFactor: 2.0,
			jitterEnabled: true,
		},
		metrics: &EnhancedTunnelMetrics{},
	}

	return tunnel
}

// DirectTCPTunnel implementation

// SendData sends encrypted data through the direct TCP tunnel
func (dt *DirectTCPTunnel) SendData(data []byte) error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if !dt.isActive {
		return errors.New("direct TCP tunnel is not active")
	}

	startTime := time.Now()

	// Apply traffic obfuscation if enabled
	processedData := data
	if dt.directFeatures.trafficObfuscation.enabled {
		var err error
		processedData, err = dt.obfuscateTraffic(data)
		if err != nil {
			return fmt.Errorf("failed to obfuscate traffic: %w", err)
		}
	}

	// Encrypt data using the shared secret
	encryptedPacket, err := dt.encryptPacket(processedData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Send encrypted packet
	if err := dt.sendEncryptedPacket(encryptedPacket); err != nil {
		dt.isActive = false // Mark tunnel as inactive on send failure
		return fmt.Errorf("failed to send encrypted packet: %w", err)
	}

	// Update metrics
	dt.updateSendMetrics(len(data), time.Since(startTime))
	dt.lastActivity = time.Now()

	return nil
}

// ReceiveData receives and decrypts data from the direct TCP tunnel
func (dt *DirectTCPTunnel) ReceiveData() ([]byte, error) {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if !dt.isActive {
		return nil, errors.New("direct TCP tunnel is not active")
	}

	startTime := time.Now()

	// Receive encrypted packet
	encryptedPacket, err := dt.receiveEncryptedPacket()
	if err != nil {
		dt.isActive = false // Mark tunnel as inactive on receive failure
		return nil, fmt.Errorf("failed to receive encrypted packet: %w", err)
	}

	// Decrypt data
	data, err := dt.decryptPacket(encryptedPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Remove traffic obfuscation if enabled
	processedData := data
	if dt.directFeatures.trafficObfuscation.enabled {
		processedData, err = dt.deobfuscateTraffic(data)
		if err != nil {
			return nil, fmt.Errorf("failed to deobfuscate traffic: %w", err)
		}
	}

	// Update metrics
	dt.updateReceiveMetrics(len(processedData), time.Since(startTime))
	dt.lastActivity = time.Now()

	return processedData, nil
}

// Close closes the direct TCP tunnel and cleans up resources
func (dt *DirectTCPTunnel) Close() error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if !dt.isActive {
		return nil // Already closed
	}

	dt.isActive = false

	// Clear sensitive data
	if dt.cryptoContext != nil && dt.cryptoContext.SharedSecret != nil {
		for i := range dt.cryptoContext.SharedSecret {
			dt.cryptoContext.SharedSecret[i] = 0
		}
	}

	return dt.conn.Close()
}

// IsActive returns whether the direct TCP tunnel is currently active
func (dt *DirectTCPTunnel) IsActive() bool {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	return dt.isActive
}

// EnableTrafficObfuscation enables traffic obfuscation for OPSEC
func (dt *DirectTCPTunnel) EnableTrafficObfuscation() error {
	dt.directFeatures.mutex.Lock()
	defer dt.directFeatures.mutex.Unlock()

	dt.directFeatures.trafficObfuscation.enabled = true
	return nil
}

// SetKeepAliveInterval sets the keep-alive interval
func (dt *DirectTCPTunnel) SetKeepAliveInterval(interval time.Duration) error {
	dt.directFeatures.mutex.Lock()
	defer dt.directFeatures.mutex.Unlock()

	dt.directFeatures.keepAliveManager.interval = interval
	return nil
}

// GetConnectionMetrics returns connection metrics
func (dt *DirectTCPTunnel) GetConnectionMetrics() *ConnectionMetrics {
	dt.directFeatures.metrics.mutex.RLock()
	defer dt.directFeatures.metrics.mutex.RUnlock()

	return &ConnectionMetrics{
		Latency:         dt.directFeatures.metrics.LastLatency,
		Throughput:      dt.directFeatures.metrics.ThroughputBps,
		PacketLoss:      dt.directFeatures.metrics.PacketLossRate,
		ConnectionTime:  time.Since(dt.createdAt),
		LastHealthCheck: dt.directFeatures.healthMonitor.lastHealthCheck,
	}
}

// PerformHealthCheck performs a health check on the connection
func (dt *DirectTCPTunnel) PerformHealthCheck() error {
	dt.directFeatures.healthMonitor.mutex.Lock()
	defer dt.directFeatures.healthMonitor.mutex.Unlock()

	if !dt.directFeatures.healthMonitor.enabled {
		return nil
	}

	// Generate small random health check data
	healthCheckData := make([]byte, 8)
	if _, err := rand.Read(healthCheckData); err != nil {
		return fmt.Errorf("failed to generate health check data: %w", err)
	}

	// Send health check through the tunnel
	startTime := time.Now()
	if err := dt.SendData(healthCheckData); err != nil {
		dt.directFeatures.healthMonitor.consecutiveFailures++
		dt.directFeatures.metrics.HealthChecksFailed++
		
		if dt.directFeatures.healthMonitor.consecutiveFailures >= dt.directFeatures.healthMonitor.maxFailures {
			dt.directFeatures.healthMonitor.healthStatus = HealthStatusFailed
		} else {
			dt.directFeatures.healthMonitor.healthStatus = HealthStatusDegraded
		}
		
		return fmt.Errorf("health check failed: %w", err)
	}

	// Update health status
	dt.directFeatures.healthMonitor.consecutiveFailures = 0
	dt.directFeatures.healthMonitor.healthStatus = HealthStatusHealthy
	dt.directFeatures.healthMonitor.lastHealthCheck = time.Now()
	dt.directFeatures.metrics.HealthChecksPassed++
	dt.directFeatures.metrics.LastLatency = time.Since(startTime)

	return nil
}

// SendKeepAlive sends a keep-alive packet
func (dt *DirectTCPTunnel) SendKeepAlive() error {
	dt.directFeatures.keepAliveManager.mutex.Lock()
	defer dt.directFeatures.keepAliveManager.mutex.Unlock()

	if !dt.directFeatures.keepAliveManager.enabled {
		return nil
	}

	// Generate keep-alive data with random jitter if enabled
	keepAliveData := make([]byte, 8)
	if _, err := rand.Read(keepAliveData); err != nil {
		return fmt.Errorf("failed to generate keep-alive data: %w", err)
	}

	// Add random delay for OPSEC if jitter is enabled
	if dt.directFeatures.keepAliveManager.randomJitter {
		jitter := time.Duration(mathrand.Intn(5000)) * time.Millisecond
		time.Sleep(jitter)
	}

	// Send keep-alive through the tunnel
	if err := dt.SendData(keepAliveData); err != nil {
		return fmt.Errorf("failed to send keep-alive: %w", err)
	}

	dt.directFeatures.keepAliveManager.lastKeepAlive = time.Now()
	dt.directFeatures.metrics.KeepAlivesSent++

	return nil
}

// DirectUDPTunnel implementation (similar to TCP but with UDP-specific features)

// SendData sends encrypted data through the direct UDP tunnel
func (du *DirectUDPTunnel) SendData(data []byte) error {
	du.mutex.Lock()
	defer du.mutex.Unlock()

	if !du.isActive {
		return errors.New("direct UDP tunnel is not active")
	}

	startTime := time.Now()

	// Apply traffic obfuscation if enabled
	processedData := data
	if du.directFeatures.trafficObfuscation.enabled {
		var err error
		processedData, err = du.obfuscateTraffic(data)
		if err != nil {
			return fmt.Errorf("failed to obfuscate traffic: %w", err)
		}
	}

	// Encrypt data using the shared secret
	encryptedPacket, err := du.encryptPacket(processedData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Send encrypted UDP packet
	if err := du.sendEncryptedUDPPacket(encryptedPacket); err != nil {
		du.isActive = false // Mark tunnel as inactive on send failure
		return fmt.Errorf("failed to send encrypted UDP packet: %w", err)
	}

	// Update metrics
	du.updateSendMetrics(len(data), time.Since(startTime))
	du.lastActivity = time.Now()

	return nil
}

// ReceiveData receives and decrypts data from the direct UDP tunnel
func (du *DirectUDPTunnel) ReceiveData() ([]byte, error) {
	du.mutex.Lock()
	defer du.mutex.Unlock()

	if !du.isActive {
		return nil, errors.New("direct UDP tunnel is not active")
	}

	startTime := time.Now()

	// Receive encrypted UDP packet
	encryptedPacket, err := du.receiveEncryptedUDPPacket()
	if err != nil {
		du.isActive = false // Mark tunnel as inactive on receive failure
		return nil, fmt.Errorf("failed to receive encrypted UDP packet: %w", err)
	}

	// Decrypt data
	data, err := du.decryptPacket(encryptedPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Remove traffic obfuscation if enabled
	processedData := data
	if du.directFeatures.trafficObfuscation.enabled {
		processedData, err = du.deobfuscateTraffic(data)
		if err != nil {
			return nil, fmt.Errorf("failed to deobfuscate traffic: %w", err)
		}
	}

	// Update metrics
	du.updateReceiveMetrics(len(processedData), time.Since(startTime))
	du.lastActivity = time.Now()

	return processedData, nil
}

// Close closes the direct UDP tunnel and cleans up resources
func (du *DirectUDPTunnel) Close() error {
	du.mutex.Lock()
	defer du.mutex.Unlock()

	if !du.isActive {
		return nil // Already closed
	}

	du.isActive = false

	// Clear sensitive data
	if du.cryptoContext != nil && du.cryptoContext.SharedSecret != nil {
		for i := range du.cryptoContext.SharedSecret {
			du.cryptoContext.SharedSecret[i] = 0
		}
	}

	// Clear session ID
	for i := range du.sessionID {
		du.sessionID[i] = 0
	}

	return du.conn.Close()
}

// IsActive returns whether the direct UDP tunnel is currently active
func (du *DirectUDPTunnel) IsActive() bool {
	du.mutex.RLock()
	defer du.mutex.RUnlock()
	return du.isActive
}

// Helper methods for traffic obfuscation

// obfuscateTraffic applies traffic obfuscation to data
func (dt *DirectTCPTunnel) obfuscateTraffic(data []byte) ([]byte, error) {
	// Simple XOR obfuscation with random key
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate obfuscation key: %w", err)
	}

	obfuscated := make([]byte, len(data)+16) // Include key at the beginning
	copy(obfuscated[:16], key)

	for i, b := range data {
		obfuscated[i+16] = b ^ key[i%16]
	}

	return obfuscated, nil
}

// deobfuscateTraffic removes traffic obfuscation from data
func (dt *DirectTCPTunnel) deobfuscateTraffic(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("obfuscated data too short")
	}

	key := data[:16]
	obfuscatedData := data[16:]
	deobfuscated := make([]byte, len(obfuscatedData))

	for i, b := range obfuscatedData {
		deobfuscated[i] = b ^ key[i%16]
	}

	return deobfuscated, nil
}

// UDP-specific obfuscation methods (similar to TCP)
func (du *DirectUDPTunnel) obfuscateTraffic(data []byte) ([]byte, error) {
	return du.obfuscateTrafficInternal(data)
}

func (du *DirectUDPTunnel) deobfuscateTraffic(data []byte) ([]byte, error) {
	return du.deobfuscateTrafficInternal(data)
}

func (du *DirectUDPTunnel) obfuscateTrafficInternal(data []byte) ([]byte, error) {
	// Simple XOR obfuscation with random key
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate obfuscation key: %w", err)
	}

	obfuscated := make([]byte, len(data)+16) // Include key at the beginning
	copy(obfuscated[:16], key)

	for i, b := range data {
		obfuscated[i+16] = b ^ key[i%16]
	}

	return obfuscated, nil
}

func (du *DirectUDPTunnel) deobfuscateTrafficInternal(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("obfuscated data too short")
	}

	key := data[:16]
	obfuscatedData := data[16:]
	deobfuscated := make([]byte, len(obfuscatedData))

	for i, b := range obfuscatedData {
		deobfuscated[i] = b ^ key[i%16]
	}

	return deobfuscated, nil
}

// Placeholder methods for encryption/decryption (to be implemented with actual crypto)
func (dt *DirectTCPTunnel) encryptPacket(data []byte) (*EncryptedPacket, error) {
	// This would use the actual encryption implementation from crypto.go
	// For now, return a placeholder
	return &EncryptedPacket{
		Ciphertext: data, // Placeholder - should be encrypted
		Tag:        make([]byte, 16),
		Nonce:      make([]byte, 12),
	}, nil
}

func (dt *DirectTCPTunnel) decryptPacket(packet *EncryptedPacket) ([]byte, error) {
	// This would use the actual decryption implementation from crypto.go
	// For now, return the ciphertext as-is (placeholder)
	return packet.Ciphertext, nil
}

func (du *DirectUDPTunnel) encryptPacket(data []byte) (*EncryptedPacket, error) {
	// This would use the actual encryption implementation from crypto.go
	// For now, return a placeholder
	return &EncryptedPacket{
		Ciphertext: data, // Placeholder - should be encrypted
		Tag:        make([]byte, 16),
		Nonce:      make([]byte, 12),
	}, nil
}

func (du *DirectUDPTunnel) decryptPacket(packet *EncryptedPacket) ([]byte, error) {
	// This would use the actual decryption implementation from crypto.go
	// For now, return the ciphertext as-is (placeholder)
	return packet.Ciphertext, nil
}

// Placeholder packet sending/receiving methods (to be implemented with actual network code)
func (dt *DirectTCPTunnel) sendEncryptedPacket(packet *EncryptedPacket) error {
	// This would implement the actual packet sending logic
	// Similar to the existing TCPTunnel.sendEncryptedPacket method
	return nil // Placeholder
}

func (dt *DirectTCPTunnel) receiveEncryptedPacket() (*EncryptedPacket, error) {
	// This would implement the actual packet receiving logic
	// Similar to the existing TCPTunnel.receiveEncryptedPacket method
	return &EncryptedPacket{}, nil // Placeholder
}

func (du *DirectUDPTunnel) sendEncryptedUDPPacket(packet *EncryptedPacket) error {
	// This would implement the actual UDP packet sending logic
	// Similar to the existing UDPTunnel.sendEncryptedUDPPacket method
	return nil // Placeholder
}

func (du *DirectUDPTunnel) receiveEncryptedUDPPacket() (*EncryptedPacket, error) {
	// This would implement the actual UDP packet receiving logic
	// Similar to the existing UDPTunnel.receiveEncryptedUDPPacket method
	return &EncryptedPacket{}, nil // Placeholder
}

// Metrics update methods
func (dt *DirectTCPTunnel) updateSendMetrics(bytes int, latency time.Duration) {
	dt.directFeatures.metrics.mutex.Lock()
	defer dt.directFeatures.metrics.mutex.Unlock()

	dt.directFeatures.metrics.BytesSent += uint64(bytes)
	dt.directFeatures.metrics.PacketsSent++
	dt.directFeatures.metrics.LastLatency = latency

	// Update average latency
	if dt.directFeatures.metrics.PacketsSent > 0 {
		dt.directFeatures.metrics.AverageLatency = time.Duration(
			(int64(dt.directFeatures.metrics.AverageLatency)*int64(dt.directFeatures.metrics.PacketsSent-1) + int64(latency)) /
				int64(dt.directFeatures.metrics.PacketsSent))
	}

	// Calculate throughput
	uptime := time.Since(dt.createdAt)
	if uptime > 0 {
		dt.directFeatures.metrics.ThroughputBps = float64(dt.directFeatures.metrics.BytesSent+dt.directFeatures.metrics.BytesReceived) / uptime.Seconds()
	}
}

func (dt *DirectTCPTunnel) updateReceiveMetrics(bytes int, latency time.Duration) {
	dt.directFeatures.metrics.mutex.Lock()
	defer dt.directFeatures.metrics.mutex.Unlock()

	dt.directFeatures.metrics.BytesReceived += uint64(bytes)
	dt.directFeatures.metrics.PacketsReceived++
	dt.directFeatures.metrics.LastLatency = latency

	// Update average latency
	totalPackets := dt.directFeatures.metrics.PacketsSent + dt.directFeatures.metrics.PacketsReceived
	if totalPackets > 0 {
		dt.directFeatures.metrics.AverageLatency = time.Duration(
			(int64(dt.directFeatures.metrics.AverageLatency)*int64(totalPackets-1) + int64(latency)) /
				int64(totalPackets))
	}

	// Calculate throughput
	uptime := time.Since(dt.createdAt)
	if uptime > 0 {
		dt.directFeatures.metrics.ThroughputBps = float64(dt.directFeatures.metrics.BytesSent+dt.directFeatures.metrics.BytesReceived) / uptime.Seconds()
	}
}

func (du *DirectUDPTunnel) updateSendMetrics(bytes int, latency time.Duration) {
	du.directFeatures.metrics.mutex.Lock()
	defer du.directFeatures.metrics.mutex.Unlock()

	du.directFeatures.metrics.BytesSent += uint64(bytes)
	du.directFeatures.metrics.PacketsSent++
	du.directFeatures.metrics.LastLatency = latency

	// Update average latency
	if du.directFeatures.metrics.PacketsSent > 0 {
		du.directFeatures.metrics.AverageLatency = time.Duration(
			(int64(du.directFeatures.metrics.AverageLatency)*int64(du.directFeatures.metrics.PacketsSent-1) + int64(latency)) /
				int64(du.directFeatures.metrics.PacketsSent))
	}

	// Calculate throughput
	uptime := time.Since(du.createdAt)
	if uptime > 0 {
		du.directFeatures.metrics.ThroughputBps = float64(du.directFeatures.metrics.BytesSent+du.directFeatures.metrics.BytesReceived) / uptime.Seconds()
	}
}

func (du *DirectUDPTunnel) updateReceiveMetrics(bytes int, latency time.Duration) {
	du.directFeatures.metrics.mutex.Lock()
	defer du.directFeatures.metrics.mutex.Unlock()

	du.directFeatures.metrics.BytesReceived += uint64(bytes)
	du.directFeatures.metrics.PacketsReceived++
	du.directFeatures.metrics.LastLatency = latency

	// Update average latency
	totalPackets := du.directFeatures.metrics.PacketsSent + du.directFeatures.metrics.PacketsReceived
	if totalPackets > 0 {
		du.directFeatures.metrics.AverageLatency = time.Duration(
			(int64(du.directFeatures.metrics.AverageLatency)*int64(totalPackets-1) + int64(latency)) /
				int64(totalPackets))
	}

	// Calculate throughput
	uptime := time.Since(du.createdAt)
	if uptime > 0 {
		du.directFeatures.metrics.ThroughputBps = float64(du.directFeatures.metrics.BytesSent+du.directFeatures.metrics.BytesReceived) / uptime.Seconds()
	}
}

// EncryptedPacket represents an encrypted packet (placeholder - should match existing implementation)
type EncryptedPacket struct {
	Ciphertext []byte
	Tag        []byte
	Nonce      []byte
}