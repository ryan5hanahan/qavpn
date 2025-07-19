package direct

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DirectTunnel wraps existing tunnel implementations for direct connection mode
type DirectTunnel struct {
	underlying    Tunnel
	connectionID  [16]byte
	role         ConnectionRole
	multiplexer  *TunnelMultiplexer
	isActive     bool
	createdAt    time.Time
	lastActivity time.Time
	metrics      *DirectTunnelMetrics
	mutex        sync.RWMutex
}

// DirectTunnelMetrics tracks performance metrics for direct tunnels
type DirectTunnelMetrics struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	ConnectionTime  time.Duration
	LastLatency     time.Duration
	ThroughputBps   float64
	PacketLossRate  float64
	mutex           sync.RWMutex
}

// TunnelMultiplexer handles multiple application streams over a single direct connection
type TunnelMultiplexer struct {
	channels      map[uint16]*MultiplexChannel
	nextChannelID uint16
	tunnel        *DirectTunnel
	mutex         sync.RWMutex
}

// MultiplexChannel represents a single application stream within a multiplexed tunnel
type MultiplexChannel struct {
	channelID    uint16
	isActive     bool
	sendBuffer   chan []byte
	receiveBuffer chan []byte
	createdAt    time.Time
	lastActivity time.Time
	mutex        sync.RWMutex
}

// MultiplexFrame represents a frame in the multiplexing protocol
type MultiplexFrame struct {
	ChannelID uint16
	FrameType uint8
	Length    uint32
	Data      []byte
}

// Frame types for multiplexing protocol
const (
	FrameTypeData    uint8 = 1
	FrameTypeOpen    uint8 = 2
	FrameTypeClose   uint8 = 3
	FrameTypeAck     uint8 = 4
	FrameTypeControl uint8 = 5
)

// NewDirectTunnel creates a new DirectTunnel wrapper around an existing tunnel
func NewDirectTunnel(underlying Tunnel, connectionID [16]byte, role ConnectionRole) *DirectTunnel {
	dt := &DirectTunnel{
		underlying:   underlying,
		connectionID: connectionID,
		role:        role,
		isActive:    true,
		createdAt:   time.Now(),
		lastActivity: time.Now(),
		metrics:     &DirectTunnelMetrics{},
	}

	// Initialize multiplexer
	dt.multiplexer = &TunnelMultiplexer{
		channels: make(map[uint16]*MultiplexChannel),
		tunnel:   dt,
	}

	return dt
}

// SendData sends data through the direct tunnel with multiplexing support
func (dt *DirectTunnel) SendData(data []byte) error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if !dt.isActive {
		return errors.New("direct tunnel is not active")
	}

	startTime := time.Now()

	// Send data through underlying tunnel
	if err := dt.underlying.SendData(data); err != nil {
		return fmt.Errorf("failed to send data through underlying tunnel: %w", err)
	}

	// Update metrics
	dt.updateSendMetrics(len(data), time.Since(startTime))
	dt.lastActivity = time.Now()

	return nil
}

// ReceiveData receives data from the direct tunnel with multiplexing support
func (dt *DirectTunnel) ReceiveData() ([]byte, error) {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if !dt.isActive {
		return nil, errors.New("direct tunnel is not active")
	}

	startTime := time.Now()

	// Receive data from underlying tunnel
	data, err := dt.underlying.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("failed to receive data from underlying tunnel: %w", err)
	}

	// Update metrics
	dt.updateReceiveMetrics(len(data), time.Since(startTime))
	dt.lastActivity = time.Now()

	return data, nil
}

// Close closes the direct tunnel and all multiplexed channels
func (dt *DirectTunnel) Close() error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if !dt.isActive {
		return nil // Already closed
	}

	dt.isActive = false

	// Close all multiplexed channels
	if dt.multiplexer != nil {
		dt.multiplexer.CloseAllChannels()
	}

	// Close underlying tunnel
	return dt.underlying.Close()
}

// IsActive returns whether the direct tunnel is currently active
func (dt *DirectTunnel) IsActive() bool {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	return dt.isActive && dt.underlying.IsActive()
}

// GetConnectionID returns the connection ID for this direct tunnel
func (dt *DirectTunnel) GetConnectionID() [16]byte {
	return dt.connectionID
}

// GetRole returns the connection role for this direct tunnel
func (dt *DirectTunnel) GetRole() ConnectionRole {
	return dt.role
}

// GetMetrics returns performance metrics for the direct tunnel
func (dt *DirectTunnel) GetMetrics() *DirectTunnelMetrics {
	dt.metrics.mutex.RLock()
	defer dt.metrics.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &DirectTunnelMetrics{
		BytesSent:       dt.metrics.BytesSent,
		BytesReceived:   dt.metrics.BytesReceived,
		PacketsSent:     dt.metrics.PacketsSent,
		PacketsReceived: dt.metrics.PacketsReceived,
		ConnectionTime:  time.Since(dt.createdAt),
		LastLatency:     dt.metrics.LastLatency,
		ThroughputBps:   dt.metrics.ThroughputBps,
		PacketLossRate:  dt.metrics.PacketLossRate,
	}
}

// CreateMultiplexChannel creates a new multiplexed channel for application traffic
func (dt *DirectTunnel) CreateMultiplexChannel() (*MultiplexChannel, error) {
	return dt.multiplexer.CreateChannel()
}

// GetMultiplexChannel retrieves an existing multiplexed channel by ID
func (dt *DirectTunnel) GetMultiplexChannel(channelID uint16) (*MultiplexChannel, error) {
	return dt.multiplexer.GetChannel(channelID)
}

// ListMultiplexChannels returns all active multiplexed channels
func (dt *DirectTunnel) ListMultiplexChannels() []*MultiplexChannel {
	return dt.multiplexer.ListChannels()
}

// updateSendMetrics updates metrics for sent data
func (dt *DirectTunnel) updateSendMetrics(bytes int, latency time.Duration) {
	dt.metrics.mutex.Lock()
	defer dt.metrics.mutex.Unlock()

	dt.metrics.BytesSent += uint64(bytes)
	dt.metrics.PacketsSent++
	dt.metrics.LastLatency = latency

	// Calculate throughput (bytes per second)
	if dt.metrics.ConnectionTime > 0 {
		dt.metrics.ThroughputBps = float64(dt.metrics.BytesSent) / dt.metrics.ConnectionTime.Seconds()
	}
}

// updateReceiveMetrics updates metrics for received data
func (dt *DirectTunnel) updateReceiveMetrics(bytes int, latency time.Duration) {
	dt.metrics.mutex.Lock()
	defer dt.metrics.mutex.Unlock()

	dt.metrics.BytesReceived += uint64(bytes)
	dt.metrics.PacketsReceived++
	dt.metrics.LastLatency = latency

	// Update throughput calculation
	totalBytes := dt.metrics.BytesSent + dt.metrics.BytesReceived
	if dt.metrics.ConnectionTime > 0 {
		dt.metrics.ThroughputBps = float64(totalBytes) / dt.metrics.ConnectionTime.Seconds()
	}
}

// TunnelMultiplexer implementation

// CreateChannel creates a new multiplexed channel
func (tm *TunnelMultiplexer) CreateChannel() (*MultiplexChannel, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Find next available channel ID
	channelID := tm.nextChannelID
	for {
		if _, exists := tm.channels[channelID]; !exists {
			break
		}
		channelID++
		if channelID == tm.nextChannelID {
			return nil, errors.New("no available channel IDs")
		}
	}

	// Create new channel
	channel := &MultiplexChannel{
		channelID:     channelID,
		isActive:      true,
		sendBuffer:    make(chan []byte, 100),
		receiveBuffer: make(chan []byte, 100),
		createdAt:     time.Now(),
		lastActivity:  time.Now(),
	}

	tm.channels[channelID] = channel
	tm.nextChannelID = channelID + 1

	// Send channel open frame
	if err := tm.sendControlFrame(channelID, FrameTypeOpen, nil); err != nil {
		delete(tm.channels, channelID)
		return nil, fmt.Errorf("failed to send channel open frame: %w", err)
	}

	return channel, nil
}

// GetChannel retrieves an existing channel by ID
func (tm *TunnelMultiplexer) GetChannel(channelID uint16) (*MultiplexChannel, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	channel, exists := tm.channels[channelID]
	if !exists {
		return nil, fmt.Errorf("channel %d not found", channelID)
	}

	return channel, nil
}

// ListChannels returns all active channels
func (tm *TunnelMultiplexer) ListChannels() []*MultiplexChannel {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	channels := make([]*MultiplexChannel, 0, len(tm.channels))
	for _, channel := range tm.channels {
		if channel.isActive {
			channels = append(channels, channel)
		}
	}

	return channels
}

// CloseAllChannels closes all multiplexed channels
func (tm *TunnelMultiplexer) CloseAllChannels() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	for channelID, channel := range tm.channels {
		channel.Close()
		// Send close frame
		tm.sendControlFrame(channelID, FrameTypeClose, nil)
	}

	// Clear channels map
	tm.channels = make(map[uint16]*MultiplexChannel)
}

// sendControlFrame sends a control frame for channel management
func (tm *TunnelMultiplexer) sendControlFrame(channelID uint16, frameType uint8, data []byte) error {
	frame := &MultiplexFrame{
		ChannelID: channelID,
		FrameType: frameType,
		Length:    uint32(len(data)),
		Data:      data,
	}

	frameData, err := tm.serializeFrame(frame)
	if err != nil {
		return fmt.Errorf("failed to serialize control frame: %w", err)
	}

	return tm.tunnel.SendData(frameData)
}

// serializeFrame converts a MultiplexFrame to bytes
func (tm *TunnelMultiplexer) serializeFrame(frame *MultiplexFrame) ([]byte, error) {
	// Frame format: [ChannelID:2][FrameType:1][Length:4][Data:Length]
	frameSize := 2 + 1 + 4 + len(frame.Data)
	frameData := make([]byte, frameSize)

	// Write channel ID (big-endian)
	binary.BigEndian.PutUint16(frameData[0:2], frame.ChannelID)

	// Write frame type
	frameData[2] = frame.FrameType

	// Write length (big-endian)
	binary.BigEndian.PutUint32(frameData[3:7], frame.Length)

	// Write data
	if len(frame.Data) > 0 {
		copy(frameData[7:], frame.Data)
	}

	return frameData, nil
}

// deserializeFrame converts bytes to a MultiplexFrame
func (tm *TunnelMultiplexer) deserializeFrame(data []byte) (*MultiplexFrame, error) {
	if len(data) < 7 {
		return nil, errors.New("frame data too short")
	}

	frame := &MultiplexFrame{
		ChannelID: binary.BigEndian.Uint16(data[0:2]),
		FrameType: data[2],
		Length:    binary.BigEndian.Uint32(data[3:7]),
	}

	// Validate length
	if frame.Length > uint32(len(data)-7) {
		return nil, fmt.Errorf("invalid frame length: %d > %d", frame.Length, len(data)-7)
	}

	// Extract data if present
	if frame.Length > 0 {
		frame.Data = make([]byte, frame.Length)
		copy(frame.Data, data[7:7+frame.Length])
	}

	return frame, nil
}

// MultiplexChannel implementation

// SendData sends data through the multiplexed channel
func (mc *MultiplexChannel) SendData(data []byte) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if !mc.isActive {
		return errors.New("multiplexed channel is not active")
	}

	select {
	case mc.sendBuffer <- data:
		mc.lastActivity = time.Now()
		return nil
	default:
		return errors.New("send buffer full")
	}
}

// ReceiveData receives data from the multiplexed channel
func (mc *MultiplexChannel) ReceiveData() ([]byte, error) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	if !mc.isActive {
		return nil, errors.New("multiplexed channel is not active")
	}

	select {
	case data := <-mc.receiveBuffer:
		mc.lastActivity = time.Now()
		return data, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("receive timeout")
	}
}

// Close closes the multiplexed channel
func (mc *MultiplexChannel) Close() error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if !mc.isActive {
		return nil // Already closed
	}

	mc.isActive = false

	// Close buffers
	close(mc.sendBuffer)
	close(mc.receiveBuffer)

	return nil
}

// IsActive returns whether the multiplexed channel is active
func (mc *MultiplexChannel) IsActive() bool {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	return mc.isActive
}

// GetChannelID returns the channel ID
func (mc *MultiplexChannel) GetChannelID() uint16 {
	return mc.channelID
}

// GetStats returns channel statistics
func (mc *MultiplexChannel) GetStats() *ChannelStats {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	return &ChannelStats{
		ChannelID:    mc.channelID,
		IsActive:     mc.isActive,
		CreatedAt:    mc.createdAt,
		LastActivity: mc.lastActivity,
		SendBufferSize:    len(mc.sendBuffer),
		ReceiveBufferSize: len(mc.receiveBuffer),
	}
}

// ChannelStats contains statistics for a multiplexed channel
type ChannelStats struct {
	ChannelID         uint16    `json:"channel_id"`
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivity      time.Time `json:"last_activity"`
	SendBufferSize    int       `json:"send_buffer_size"`
	ReceiveBufferSize int       `json:"receive_buffer_size"`
}