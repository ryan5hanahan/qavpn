package direct

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ProtocolOptimizer handles protocol-specific optimizations for direct connections
type ProtocolOptimizer struct {
	tcpOptimizer *TCPOptimizer
	udpOptimizer *UDPOptimizer
	selector     *ProtocolSelector
	fallback     *ProtocolFallbackManager
	mutex        sync.RWMutex
}

// TCPOptimizer provides TCP-specific optimizations
type TCPOptimizer struct {
	keepAliveEnabled    bool
	keepAliveInterval   time.Duration
	keepAliveProbes     int
	noDelayEnabled      bool
	bufferSizes         *TCPBufferSizes
	congestionControl   string
	connectionPooling   *TCPConnectionPool
	mutex               sync.RWMutex
}

// UDPOptimizer provides UDP-specific optimizations including connection simulation
type UDPOptimizer struct {
	connectionSimulation *UDPConnectionSimulation
	packetReordering     *PacketReorderingHandler
	duplicateDetection   *DuplicatePacketDetector
	fragmentationHandler *UDPFragmentationHandler
	bufferSizes          *UDPBufferSizes
	reliabilityLayer     *UDPReliabilityLayer
	mutex                sync.RWMutex
}

// ProtocolSelector chooses the best protocol based on network conditions
type ProtocolSelector struct {
	networkAnalyzer    *NetworkConditionAnalyzer
	selectionCriteria  *ProtocolSelectionCriteria
	lastAnalysis       time.Time
	analysisInterval   time.Duration
	currentProtocol    string
	protocolHistory    []ProtocolSelection
	mutex              sync.RWMutex
}

// ProtocolFallbackManager handles automatic protocol fallback
type ProtocolFallbackManager struct {
	fallbackRules      []FallbackRule
	fallbackHistory    []FallbackEvent
	maxFallbackAttempts int
	fallbackCooldown   time.Duration
	lastFallback       time.Time
	mutex              sync.RWMutex
}

// TCP-specific types

// TCPBufferSizes contains optimized buffer sizes for TCP connections
type TCPBufferSizes struct {
	SendBuffer    int `json:"send_buffer"`
	ReceiveBuffer int `json:"receive_buffer"`
	WindowSize    int `json:"window_size"`
}

// TCPConnectionPool manages a pool of TCP connections for reuse
type TCPConnectionPool struct {
	connections map[string][]*PooledTCPConnection
	maxPoolSize int
	idleTimeout time.Duration
	mutex       sync.RWMutex
}

// PooledTCPConnection represents a pooled TCP connection
type PooledTCPConnection struct {
	conn        net.Conn
	lastUsed    time.Time
	useCount    int
	isAvailable bool
	mutex       sync.RWMutex
}

// UDP-specific types

// UDPConnectionSimulation simulates connection-like behavior over UDP
type UDPConnectionSimulation struct {
	sessions        map[string]*UDPSession
	sessionTimeout  time.Duration
	heartbeatInterval time.Duration
	sequenceNumbers map[string]uint32
	acknowledgments map[string]uint32
	mutex           sync.RWMutex
}

// UDPSession represents a simulated connection session over UDP
type UDPSession struct {
	sessionID       string
	remoteAddr      *net.UDPAddr
	lastActivity    time.Time
	sequenceNumber  uint32
	expectedSeq     uint32
	isActive        bool
	sendWindow      *SlidingWindow
	receiveWindow   *SlidingWindow
	mutex           sync.RWMutex
}

// SlidingWindow implements a sliding window for UDP reliability
type SlidingWindow struct {
	windowSize   int
	packets      map[uint32]*UDPPacketInfo
	baseSequence uint32
	nextSequence uint32
	mutex        sync.RWMutex
}

// UDPPacketInfo contains information about a UDP packet
type UDPPacketInfo struct {
	sequenceNumber uint32
	data           []byte
	timestamp      time.Time
	acknowledged   bool
	retryCount     int
}

// PacketReorderingHandler handles out-of-order UDP packets
type PacketReorderingHandler struct {
	reorderBuffer map[string]*ReorderBuffer
	maxBufferSize int
	timeout       time.Duration
	mutex         sync.RWMutex
}

// ReorderBuffer buffers out-of-order packets
type ReorderBuffer struct {
	packets       map[uint32][]byte
	expectedSeq   uint32
	maxBufferSize int
	lastActivity  time.Time
	mutex         sync.RWMutex
}

// DuplicatePacketDetector detects and filters duplicate UDP packets
type DuplicatePacketDetector struct {
	seenPackets   map[string]map[uint32]time.Time
	cleanupInterval time.Duration
	retentionTime time.Duration
	mutex         sync.RWMutex
}

// UDPFragmentationHandler handles large UDP packet fragmentation
type UDPFragmentationHandler struct {
	maxPacketSize   int
	fragmentBuffers map[string]*FragmentBuffer
	reassemblyTimeout time.Duration
	mutex           sync.RWMutex
}

// FragmentBuffer buffers packet fragments for reassembly
type FragmentBuffer struct {
	fragments    map[int][]byte
	totalFragments int
	receivedFragments int
	timestamp    time.Time
	mutex        sync.RWMutex
}

// UDPBufferSizes contains optimized buffer sizes for UDP connections
type UDPBufferSizes struct {
	SendBuffer    int `json:"send_buffer"`
	ReceiveBuffer int `json:"receive_buffer"`
	PacketSize    int `json:"packet_size"`
}

// UDPReliabilityLayer provides reliability features for UDP
type UDPReliabilityLayer struct {
	acknowledgmentTimeout time.Duration
	maxRetries           int
	retryBackoff         time.Duration
	pendingAcks          map[uint32]*PendingAcknowledgment
	mutex                sync.RWMutex
}

// PendingAcknowledgment tracks packets waiting for acknowledgment
type PendingAcknowledgment struct {
	sequenceNumber uint32
	data           []byte
	timestamp      time.Time
	retryCount     int
	acknowledged   bool
}

// Protocol selection types

// NetworkConditionAnalyzer analyzes network conditions for protocol selection
type NetworkConditionAnalyzer struct {
	latencyMeasurements []time.Duration
	packetLossMeasurements []float64
	throughputMeasurements []float64
	jitterMeasurements []time.Duration
	lastAnalysis       time.Time
	analysisWindow     time.Duration
	mutex              sync.RWMutex
}

// ProtocolSelectionCriteria defines criteria for protocol selection
type ProtocolSelectionCriteria struct {
	LatencyThreshold    time.Duration `json:"latency_threshold"`
	PacketLossThreshold float64       `json:"packet_loss_threshold"`
	ThroughputThreshold float64       `json:"throughput_threshold"`
	JitterThreshold     time.Duration `json:"jitter_threshold"`
	PreferTCP           bool          `json:"prefer_tcp"`
	PreferUDP           bool          `json:"prefer_udp"`
}

// ProtocolSelection represents a protocol selection decision
type ProtocolSelection struct {
	Protocol    string                 `json:"protocol"`
	Reason      string                 `json:"reason"`
	Confidence  float64                `json:"confidence"`
	Conditions  *NetworkConditions     `json:"conditions"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NetworkConditions represents current network conditions
type NetworkConditions struct {
	Latency     time.Duration `json:"latency"`
	PacketLoss  float64       `json:"packet_loss"`
	Throughput  float64       `json:"throughput"`
	Jitter      time.Duration `json:"jitter"`
	Stability   float64       `json:"stability"`
}

// Fallback types

// FallbackRule defines when and how to fallback between protocols
type FallbackRule struct {
	Name        string        `json:"name"`
	FromProtocol string       `json:"from_protocol"`
	ToProtocol   string       `json:"to_protocol"`
	Trigger      FallbackTrigger `json:"trigger"`
	Conditions   []FallbackCondition `json:"conditions"`
	Priority     int          `json:"priority"`
}

// FallbackTrigger defines what triggers a fallback
type FallbackTrigger struct {
	Type                string        `json:"type"`
	ConsecutiveFailures int           `json:"consecutive_failures,omitempty"`
	LatencyThreshold    time.Duration `json:"latency_threshold,omitempty"`
	PacketLossThreshold float64       `json:"packet_loss_threshold,omitempty"`
	TimeoutDuration     time.Duration `json:"timeout_duration,omitempty"`
}

// FallbackCondition defines conditions that must be met for fallback
type FallbackCondition struct {
	Type      string      `json:"type"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Threshold interface{} `json:"threshold"`
}

// FallbackEvent represents a fallback event
type FallbackEvent struct {
	FromProtocol string             `json:"from_protocol"`
	ToProtocol   string             `json:"to_protocol"`
	Reason       string             `json:"reason"`
	Conditions   *NetworkConditions `json:"conditions"`
	Success      bool               `json:"success"`
	Timestamp    time.Time          `json:"timestamp"`
}

// NewProtocolOptimizer creates a new protocol optimizer
func NewProtocolOptimizer() *ProtocolOptimizer {
	return &ProtocolOptimizer{
		tcpOptimizer: NewTCPOptimizer(),
		udpOptimizer: NewUDPOptimizer(),
		selector:     NewProtocolSelector(),
		fallback:     NewProtocolFallbackManager(),
	}
}

// NewTCPOptimizer creates a new TCP optimizer
func NewTCPOptimizer() *TCPOptimizer {
	return &TCPOptimizer{
		keepAliveEnabled:  true,
		keepAliveInterval: 60 * time.Second,
		keepAliveProbes:   3,
		noDelayEnabled:    true,
		bufferSizes: &TCPBufferSizes{
			SendBuffer:    64 * 1024,    // 64KB
			ReceiveBuffer: 64 * 1024,    // 64KB
			WindowSize:    128 * 1024,   // 128KB
		},
		congestionControl: "cubic",
		connectionPooling: &TCPConnectionPool{
			connections: make(map[string][]*PooledTCPConnection),
			maxPoolSize: 10,
			idleTimeout: 300 * time.Second,
		},
	}
}

// NewUDPOptimizer creates a new UDP optimizer
func NewUDPOptimizer() *UDPOptimizer {
	return &UDPOptimizer{
		connectionSimulation: &UDPConnectionSimulation{
			sessions:          make(map[string]*UDPSession),
			sessionTimeout:    300 * time.Second,
			heartbeatInterval: 30 * time.Second,
			sequenceNumbers:   make(map[string]uint32),
			acknowledgments:   make(map[string]uint32),
		},
		packetReordering: &PacketReorderingHandler{
			reorderBuffer: make(map[string]*ReorderBuffer),
			maxBufferSize: 100,
			timeout:       5 * time.Second,
		},
		duplicateDetection: &DuplicatePacketDetector{
			seenPackets:     make(map[string]map[uint32]time.Time),
			cleanupInterval: 60 * time.Second,
			retentionTime:   300 * time.Second,
		},
		fragmentationHandler: &UDPFragmentationHandler{
			maxPacketSize:     1400, // Safe MTU size
			fragmentBuffers:   make(map[string]*FragmentBuffer),
			reassemblyTimeout: 10 * time.Second,
		},
		bufferSizes: &UDPBufferSizes{
			SendBuffer:    128 * 1024, // 128KB
			ReceiveBuffer: 128 * 1024, // 128KB
			PacketSize:    1400,       // Safe packet size
		},
		reliabilityLayer: &UDPReliabilityLayer{
			acknowledgmentTimeout: 1 * time.Second,
			maxRetries:           3,
			retryBackoff:         500 * time.Millisecond,
			pendingAcks:          make(map[uint32]*PendingAcknowledgment),
		},
	}
}

// NewProtocolSelector creates a new protocol selector
func NewProtocolSelector() *ProtocolSelector {
	return &ProtocolSelector{
		networkAnalyzer: &NetworkConditionAnalyzer{
			latencyMeasurements:    make([]time.Duration, 0, 100),
			packetLossMeasurements: make([]float64, 0, 100),
			throughputMeasurements: make([]float64, 0, 100),
			jitterMeasurements:     make([]time.Duration, 0, 100),
			analysisWindow:         60 * time.Second,
		},
		selectionCriteria: &ProtocolSelectionCriteria{
			LatencyThreshold:    100 * time.Millisecond,
			PacketLossThreshold: 0.01, // 1%
			ThroughputThreshold: 1000000, // 1 Mbps
			JitterThreshold:     50 * time.Millisecond,
			PreferTCP:           false,
			PreferUDP:           false,
		},
		analysisInterval: 30 * time.Second,
		currentProtocol:  "tcp", // Default to TCP
		protocolHistory:  make([]ProtocolSelection, 0, 100),
	}
}

// NewProtocolFallbackManager creates a new protocol fallback manager
func NewProtocolFallbackManager() *ProtocolFallbackManager {
	return &ProtocolFallbackManager{
		fallbackRules: []FallbackRule{
			{
				Name:         "tcp_to_udp_high_latency",
				FromProtocol: "tcp",
				ToProtocol:   "udp",
				Trigger: FallbackTrigger{
					Type:             "latency",
					LatencyThreshold: 500 * time.Millisecond,
				},
				Priority: 1,
			},
			{
				Name:         "udp_to_tcp_packet_loss",
				FromProtocol: "udp",
				ToProtocol:   "tcp",
				Trigger: FallbackTrigger{
					Type:                "packet_loss",
					PacketLossThreshold: 0.05, // 5%
				},
				Priority: 2,
			},
			{
				Name:         "tcp_to_udp_timeout",
				FromProtocol: "tcp",
				ToProtocol:   "udp",
				Trigger: FallbackTrigger{
					Type:            "timeout",
					TimeoutDuration: 10 * time.Second,
				},
				Priority: 3,
			},
		},
		fallbackHistory:     make([]FallbackEvent, 0, 100),
		maxFallbackAttempts: 3,
		fallbackCooldown:    60 * time.Second,
	}
}

// TCP Optimization Methods

// OptimizeTCPConnection applies TCP-specific optimizations to a connection
func (to *TCPOptimizer) OptimizeTCPConnection(conn net.Conn) error {
	to.mutex.Lock()
	defer to.mutex.Unlock()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("connection is not a TCP connection")
	}

	// Enable TCP keep-alive
	if to.keepAliveEnabled {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return fmt.Errorf("failed to enable keep-alive: %w", err)
		}

		if err := tcpConn.SetKeepAlivePeriod(to.keepAliveInterval); err != nil {
			return fmt.Errorf("failed to set keep-alive period: %w", err)
		}
	}

	// Disable Nagle's algorithm for low latency
	if to.noDelayEnabled {
		if err := tcpConn.SetNoDelay(true); err != nil {
			return fmt.Errorf("failed to set no delay: %w", err)
		}
	}

	// Set buffer sizes
	if to.bufferSizes != nil {
		if err := tcpConn.SetReadBuffer(to.bufferSizes.ReceiveBuffer); err != nil {
			return fmt.Errorf("failed to set read buffer: %w", err)
		}

		if err := tcpConn.SetWriteBuffer(to.bufferSizes.SendBuffer); err != nil {
			return fmt.Errorf("failed to set write buffer: %w", err)
		}
	}

	return nil
}

// GetPooledConnection retrieves a connection from the pool or creates a new one
func (to *TCPOptimizer) GetPooledConnection(address string) (net.Conn, error) {
	to.connectionPooling.mutex.Lock()
	defer to.connectionPooling.mutex.Unlock()

	// Check for available pooled connections
	if connections, exists := to.connectionPooling.connections[address]; exists {
		for i, pooledConn := range connections {
			pooledConn.mutex.Lock()
			if pooledConn.isAvailable && time.Since(pooledConn.lastUsed) < to.connectionPooling.idleTimeout {
				pooledConn.isAvailable = false
				pooledConn.useCount++
				pooledConn.mutex.Unlock()
				
				// Remove from pool
				to.connectionPooling.connections[address] = append(connections[:i], connections[i+1:]...)
				
				return pooledConn.conn, nil
			}
			pooledConn.mutex.Unlock()
		}
	}

	// Create new connection
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection: %w", err)
	}

	// Apply optimizations
	if err := to.OptimizeTCPConnection(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to optimize connection: %w", err)
	}

	return conn, nil
}

// ReturnPooledConnection returns a connection to the pool
func (to *TCPOptimizer) ReturnPooledConnection(address string, conn net.Conn) error {
	to.connectionPooling.mutex.Lock()
	defer to.connectionPooling.mutex.Unlock()

	// Check pool size limit
	if connections, exists := to.connectionPooling.connections[address]; exists {
		if len(connections) >= to.connectionPooling.maxPoolSize {
			return conn.Close() // Pool is full, close connection
		}
	}

	// Add to pool
	pooledConn := &PooledTCPConnection{
		conn:        conn,
		lastUsed:    time.Now(),
		isAvailable: true,
	}

	if to.connectionPooling.connections[address] == nil {
		to.connectionPooling.connections[address] = make([]*PooledTCPConnection, 0)
	}

	to.connectionPooling.connections[address] = append(to.connectionPooling.connections[address], pooledConn)
	return nil
}

// UDP Optimization Methods

// CreateUDPSession creates a new UDP session for connection simulation
func (uo *UDPOptimizer) CreateUDPSession(sessionID string, remoteAddr *net.UDPAddr) *UDPSession {
	uo.connectionSimulation.mutex.Lock()
	defer uo.connectionSimulation.mutex.Unlock()

	session := &UDPSession{
		sessionID:      sessionID,
		remoteAddr:     remoteAddr,
		lastActivity:   time.Now(),
		sequenceNumber: 0,
		expectedSeq:    0,
		isActive:       true,
		sendWindow: &SlidingWindow{
			windowSize:   64,
			packets:      make(map[uint32]*UDPPacketInfo),
			baseSequence: 0,
			nextSequence: 0,
		},
		receiveWindow: &SlidingWindow{
			windowSize:   64,
			packets:      make(map[uint32]*UDPPacketInfo),
			baseSequence: 0,
			nextSequence: 0,
		},
	}

	uo.connectionSimulation.sessions[sessionID] = session
	return session
}

// SendReliableUDP sends UDP data with reliability features
func (uo *UDPOptimizer) SendReliableUDP(conn *net.UDPConn, sessionID string, data []byte) error {
	uo.connectionSimulation.mutex.Lock()
	session, exists := uo.connectionSimulation.sessions[sessionID]
	uo.connectionSimulation.mutex.Unlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Fragment large packets if necessary
	fragments, err := uo.fragmentPacket(data)
	if err != nil {
		return fmt.Errorf("failed to fragment packet: %w", err)
	}

	// Send each fragment with sequence number
	for _, fragment := range fragments {
		sequenceNumber := session.sequenceNumber
		session.sequenceNumber++

		// Create packet with sequence number
		packet := uo.createSequencedPacket(sequenceNumber, fragment)

		// Send packet
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send UDP packet: %w", err)
		}

		// Add to reliability layer for acknowledgment tracking
		uo.reliabilityLayer.mutex.Lock()
		uo.reliabilityLayer.pendingAcks[sequenceNumber] = &PendingAcknowledgment{
			sequenceNumber: sequenceNumber,
			data:           packet,
			timestamp:      time.Now(),
			retryCount:     0,
			acknowledged:   false,
		}
		uo.reliabilityLayer.mutex.Unlock()
	}

	session.lastActivity = time.Now()
	return nil
}

// ReceiveReliableUDP receives UDP data with reordering and duplicate detection
func (uo *UDPOptimizer) ReceiveReliableUDP(conn *net.UDPConn, sessionID string) ([]byte, error) {
	buffer := make([]byte, uo.bufferSizes.PacketSize)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read UDP packet: %w", err)
	}

	packet := buffer[:n]

	// Extract sequence number and data
	sequenceNumber, data, err := uo.parseSequencedPacket(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sequenced packet: %w", err)
	}

	// Check for duplicates
	if uo.isDuplicatePacket(sessionID, sequenceNumber) {
		return nil, nil // Ignore duplicate
	}

	// Handle packet reordering
	reorderedData, err := uo.handlePacketReordering(sessionID, sequenceNumber, data)
	if err != nil {
		return nil, fmt.Errorf("failed to handle packet reordering: %w", err)
	}

	// Send acknowledgment
	uo.sendAcknowledgment(conn, sequenceNumber)

	return reorderedData, nil
}

// Protocol Selection Methods

// SelectOptimalProtocol selects the best protocol based on current network conditions
func (ps *ProtocolSelector) SelectOptimalProtocol(conditions *NetworkConditions) (*ProtocolSelection, error) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	selection := &ProtocolSelection{
		Conditions: conditions,
		Timestamp:  time.Now(),
	}

	// Analyze conditions against criteria
	tcpScore := ps.calculateProtocolScore("tcp", conditions)
	udpScore := ps.calculateProtocolScore("udp", conditions)

	if tcpScore > udpScore {
		selection.Protocol = "tcp"
		selection.Confidence = tcpScore
		selection.Reason = ps.generateSelectionReason("tcp", conditions)
	} else {
		selection.Protocol = "udp"
		selection.Confidence = udpScore
		selection.Reason = ps.generateSelectionReason("udp", conditions)
	}

	// Update history
	ps.protocolHistory = append(ps.protocolHistory, *selection)
	if len(ps.protocolHistory) > 100 {
		ps.protocolHistory = ps.protocolHistory[1:]
	}

	ps.currentProtocol = selection.Protocol
	ps.lastAnalysis = time.Now()

	return selection, nil
}

// calculateProtocolScore calculates a score for a protocol based on network conditions
func (ps *ProtocolSelector) calculateProtocolScore(protocol string, conditions *NetworkConditions) float64 {
	score := 0.5 // Base score

	switch protocol {
	case "tcp":
		// TCP is better for reliable connections with moderate latency
		if conditions.PacketLoss < ps.selectionCriteria.PacketLossThreshold {
			score += 0.2
		}
		if conditions.Latency < ps.selectionCriteria.LatencyThreshold*2 {
			score += 0.15
		}
		if conditions.Stability > 0.9 {
			score += 0.15
		}

	case "udp":
		// UDP is better for low-latency, high-throughput scenarios
		if conditions.Latency < ps.selectionCriteria.LatencyThreshold {
			score += 0.2
		}
		if conditions.Throughput > ps.selectionCriteria.ThroughputThreshold {
			score += 0.15
		}
		if conditions.Jitter < ps.selectionCriteria.JitterThreshold {
			score += 0.15
		}
	}

	// Apply preferences (smaller bonus to stay within range)
	if ps.selectionCriteria.PreferTCP && protocol == "tcp" {
		score += 0.05
	}
	if ps.selectionCriteria.PreferUDP && protocol == "udp" {
		score += 0.05
	}

	// Ensure score stays within 0-1 range
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}

// generateSelectionReason generates a human-readable reason for protocol selection
func (ps *ProtocolSelector) generateSelectionReason(protocol string, conditions *NetworkConditions) string {
	switch protocol {
	case "tcp":
		if conditions.PacketLoss < ps.selectionCriteria.PacketLossThreshold {
			return "Low packet loss favors TCP reliability"
		}
		return "Network conditions suitable for TCP"
	case "udp":
		if conditions.Latency < ps.selectionCriteria.LatencyThreshold {
			return "Low latency favors UDP performance"
		}
		return "Network conditions suitable for UDP"
	default:
		return "Default protocol selection"
	}
}

// Protocol Fallback Methods

// CheckFallbackConditions checks if fallback conditions are met
func (pfm *ProtocolFallbackManager) CheckFallbackConditions(currentProtocol string, conditions *NetworkConditions) (*FallbackRule, bool) {
	pfm.mutex.RLock()
	defer pfm.mutex.RUnlock()

	// Check cooldown period
	if time.Since(pfm.lastFallback) < pfm.fallbackCooldown {
		return nil, false
	}

	// Check each fallback rule
	for _, rule := range pfm.fallbackRules {
		if rule.FromProtocol != currentProtocol {
			continue
		}

		if pfm.evaluateFallbackTrigger(rule.Trigger, conditions) {
			return &rule, true
		}
	}

	return nil, false
}

// evaluateFallbackTrigger evaluates if a fallback trigger condition is met
func (pfm *ProtocolFallbackManager) evaluateFallbackTrigger(trigger FallbackTrigger, conditions *NetworkConditions) bool {
	switch trigger.Type {
	case "latency":
		return conditions.Latency > trigger.LatencyThreshold
	case "packet_loss":
		return conditions.PacketLoss > trigger.PacketLossThreshold
	case "timeout":
		// This would be evaluated based on connection timeout events
		return false // Placeholder
	default:
		return false
	}
}

// ExecuteFallback executes a protocol fallback
func (pfm *ProtocolFallbackManager) ExecuteFallback(rule *FallbackRule, conditions *NetworkConditions) *FallbackEvent {
	pfm.mutex.Lock()
	defer pfm.mutex.Unlock()

	event := &FallbackEvent{
		FromProtocol: rule.FromProtocol,
		ToProtocol:   rule.ToProtocol,
		Reason:       fmt.Sprintf("Triggered by %s", rule.Trigger.Type),
		Conditions:   conditions,
		Success:      true, // Assume success for now
		Timestamp:    time.Now(),
	}

	pfm.fallbackHistory = append(pfm.fallbackHistory, *event)
	if len(pfm.fallbackHistory) > 100 {
		pfm.fallbackHistory = pfm.fallbackHistory[1:]
	}

	pfm.lastFallback = time.Now()

	return event
}

// Helper methods for UDP optimization

// fragmentPacket fragments a large packet into smaller chunks
func (uo *UDPOptimizer) fragmentPacket(data []byte) ([][]byte, error) {
	maxSize := uo.fragmentationHandler.maxPacketSize - 8 // Reserve space for headers

	if len(data) <= maxSize {
		return [][]byte{data}, nil
	}

	var fragments [][]byte
	for i := 0; i < len(data); i += maxSize {
		end := i + maxSize
		if end > len(data) {
			end = len(data)
		}
		fragments = append(fragments, data[i:end])
	}

	return fragments, nil
}

// createSequencedPacket creates a packet with sequence number
func (uo *UDPOptimizer) createSequencedPacket(sequenceNumber uint32, data []byte) []byte {
	packet := make([]byte, 4+len(data))
	
	// Add sequence number (4 bytes, big-endian)
	packet[0] = byte(sequenceNumber >> 24)
	packet[1] = byte(sequenceNumber >> 16)
	packet[2] = byte(sequenceNumber >> 8)
	packet[3] = byte(sequenceNumber)
	
	// Add data
	copy(packet[4:], data)
	
	return packet
}

// parseSequencedPacket parses a packet to extract sequence number and data
func (uo *UDPOptimizer) parseSequencedPacket(packet []byte) (uint32, []byte, error) {
	if len(packet) < 4 {
		return 0, nil, errors.New("packet too short")
	}

	sequenceNumber := uint32(packet[0])<<24 | uint32(packet[1])<<16 | uint32(packet[2])<<8 | uint32(packet[3])
	data := packet[4:]

	return sequenceNumber, data, nil
}

// isDuplicatePacket checks if a packet is a duplicate
func (uo *UDPOptimizer) isDuplicatePacket(sessionID string, sequenceNumber uint32) bool {
	uo.duplicateDetection.mutex.Lock()
	defer uo.duplicateDetection.mutex.Unlock()

	if sessionPackets, exists := uo.duplicateDetection.seenPackets[sessionID]; exists {
		if _, seen := sessionPackets[sequenceNumber]; seen {
			return true
		}
		sessionPackets[sequenceNumber] = time.Now()
	} else {
		uo.duplicateDetection.seenPackets[sessionID] = make(map[uint32]time.Time)
		uo.duplicateDetection.seenPackets[sessionID][sequenceNumber] = time.Now()
	}

	return false
}

// handlePacketReordering handles out-of-order packet delivery
func (uo *UDPOptimizer) handlePacketReordering(sessionID string, sequenceNumber uint32, data []byte) ([]byte, error) {
	uo.packetReordering.mutex.Lock()
	defer uo.packetReordering.mutex.Unlock()

	if _, exists := uo.packetReordering.reorderBuffer[sessionID]; !exists {
		uo.packetReordering.reorderBuffer[sessionID] = &ReorderBuffer{
			packets:       make(map[uint32][]byte),
			expectedSeq:   0,
			maxBufferSize: uo.packetReordering.maxBufferSize,
			lastActivity:  time.Now(),
		}
	}

	buffer := uo.packetReordering.reorderBuffer[sessionID]
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	if sequenceNumber == buffer.expectedSeq {
		// Packet is in order
		buffer.expectedSeq++
		buffer.lastActivity = time.Now()
		return data, nil
	} else if sequenceNumber > buffer.expectedSeq {
		// Packet is out of order, buffer it
		buffer.packets[sequenceNumber] = data
		buffer.lastActivity = time.Now()
		return nil, nil // No data to return yet
	} else {
		// Packet is older than expected, might be duplicate
		return nil, nil
	}
}

// sendAcknowledgment sends an acknowledgment for a received packet
func (uo *UDPOptimizer) sendAcknowledgment(conn *net.UDPConn, sequenceNumber uint32) error {
	ackPacket := make([]byte, 5)
	ackPacket[0] = 0xFF // ACK marker
	ackPacket[1] = byte(sequenceNumber >> 24)
	ackPacket[2] = byte(sequenceNumber >> 16)
	ackPacket[3] = byte(sequenceNumber >> 8)
	ackPacket[4] = byte(sequenceNumber)

	_, err := conn.Write(ackPacket)
	return err
}