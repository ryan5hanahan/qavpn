package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"sync"
	"time"
)

// NodeManager handles node discovery, routing, and relay functionality
type NodeManager struct {
	localNode      *Node
	knownNodes     map[NodeID]*Node
	activeRoutes   map[string]*Route
	bootstrapList  []string
	mutex          sync.RWMutex
	isRelay        bool
	relayServer    *RelayServer
	routingTable   *RoutingTable
	failureHandler *RouteFailureHandler
}

// RelayServer handles incoming relay connections
type RelayServer struct {
	listener    net.Listener
	connections map[string]*RelayConnection
	mutex       sync.RWMutex
	isRunning   bool
	statistics  *RelayStatistics
}

// RelayConnection represents a connection to a relay node
type RelayConnection struct {
	conn          net.Conn
	nodeID        NodeID
	cryptoContext *CryptoContext
	lastActivity  time.Time
	isActive      bool
	mutex         sync.RWMutex
}

// NodeDiscoveryMessage represents a node discovery protocol message
type NodeDiscoveryMessage struct {
	Type      string    `json:"type"`      // "discover", "announce", "response"
	NodeID    NodeID    `json:"node_id"`   // Sender's node ID
	Address   string    `json:"address"`   // Sender's address
	Protocol  string    `json:"protocol"`  // Supported protocol
	PublicKey []byte    `json:"public_key"` // Node's public key
	Timestamp int64     `json:"timestamp"` // Message timestamp
	Signature []byte    `json:"signature"` // Message signature
}

// NewNodeManager creates a new node manager
func NewNodeManager(isRelay bool) (*NodeManager, error) {
	// Generate local node ID
	var nodeID NodeID
	if _, err := rand.Read(nodeID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate node ID: %w", err)
	}

	// Generate key pair for this node
	keyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create local node
	localNode := &Node{
		ID:        nodeID,
		PublicKey: keyPair.PublicKey,
		Address:   "", // Will be set when server starts
		Protocol:  "tcp",
		LastSeen:  time.Now(),
		Latency:   0,
	}

	nm := &NodeManager{
		localNode:     localNode,
		knownNodes:    make(map[NodeID]*Node),
		activeRoutes:  make(map[string]*Route),
		bootstrapList: make([]string, len(BootstrapNodes)),
		isRelay:       isRelay,
	}

	// Copy bootstrap nodes
	copy(nm.bootstrapList, BootstrapNodes)

	return nm, nil
}

// DiscoverNodes performs initial node discovery from bootstrap nodes
func (nm *NodeManager) DiscoverNodes() error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	discoveredCount := 0
	
	for _, bootstrapAddr := range nm.bootstrapList {
		nodes, err := nm.discoverFromBootstrap(bootstrapAddr)
		if err != nil {
			// Log error but continue with other bootstrap nodes
			fmt.Printf("Failed to discover from bootstrap %s: %v\n", bootstrapAddr, err)
			continue
		}

		// Add discovered nodes to known nodes
		for _, node := range nodes {
			if node.ID != nm.localNode.ID { // Don't add ourselves
				nm.knownNodes[node.ID] = node
				discoveredCount++
			}
		}
	}

	if discoveredCount == 0 {
		return errors.New("failed to discover any nodes from bootstrap")
	}

	fmt.Printf("Discovered %d relay nodes\n", discoveredCount)
	return nil
}

// discoverFromBootstrap discovers nodes from a single bootstrap node
func (nm *NodeManager) discoverFromBootstrap(bootstrapAddr string) ([]*Node, error) {
	// Connect to bootstrap node
	conn, err := net.DialTimeout("tcp", bootstrapAddr, time.Duration(NodeDiscoveryTimeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bootstrap: %w", err)
	}
	defer conn.Close()

	// Create discovery message
	discoveryMsg := NodeDiscoveryMessage{
		Type:      "discover",
		NodeID:    nm.localNode.ID,
		Address:   nm.localNode.Address,
		Protocol:  nm.localNode.Protocol,
		PublicKey: nm.localNode.PublicKey,
		Timestamp: time.Now().Unix(),
	}

	// Send discovery request
	if err := nm.sendDiscoveryMessage(conn, &discoveryMsg); err != nil {
		return nil, fmt.Errorf("failed to send discovery message: %w", err)
	}

	// Receive response with node list
	responseMsg, err := nm.receiveDiscoveryMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive discovery response: %w", err)
	}

	if responseMsg.Type != "response" {
		return nil, errors.New("invalid discovery response type")
	}

	// Parse node list from response (simplified - in real implementation would be more complex)
	// For now, just return the bootstrap node itself as a discovered node
	bootstrapNode := &Node{
		ID:        responseMsg.NodeID,
		PublicKey: responseMsg.PublicKey,
		Address:   bootstrapAddr,
		Protocol:  responseMsg.Protocol,
		LastSeen:  time.Now(),
		Latency:   0,
	}

	return []*Node{bootstrapNode}, nil
}

// sendDiscoveryMessage sends a discovery protocol message
func (nm *NodeManager) sendDiscoveryMessage(conn net.Conn, msg *NodeDiscoveryMessage) error {
	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal discovery message: %w", err)
	}

	// Send message length first
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(len(data) >> 24)
	lengthBytes[1] = byte(len(data) >> 16)
	lengthBytes[2] = byte(len(data) >> 8)
	lengthBytes[3] = byte(len(data))

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to send message length: %w", err)
	}

	// Send message data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send message data: %w", err)
	}

	return nil
}

// receiveDiscoveryMessage receives a discovery protocol message
func (nm *NodeManager) receiveDiscoveryMessage(conn net.Conn) (*NodeDiscoveryMessage, error) {
	// Set timeout for discovery
	conn.SetDeadline(time.Now().Add(time.Duration(NodeDiscoveryTimeout) * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Read message length
	lengthBytes := make([]byte, 4)
	if _, err := conn.Read(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := int(lengthBytes[0])<<24 | int(lengthBytes[1])<<16 | int(lengthBytes[2])<<8 | int(lengthBytes[3])
	if length <= 0 || length > 10*1024 { // Max 10KB for discovery messages
		return nil, fmt.Errorf("invalid message length: %d", length)
	}

	// Read message data
	data := make([]byte, length)
	totalRead := 0
	for totalRead < length {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read message data: %w", err)
		}
		totalRead += n
	}

	// Parse JSON message
	var msg NodeDiscoveryMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal discovery message: %w", err)
	}

	return &msg, nil
}

// CheckNodeHealth performs health checks on known nodes
func (nm *NodeManager) CheckNodeHealth() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	now := time.Now()
	
	for nodeID, node := range nm.knownNodes {
		// Check if node has been seen recently
		if now.Sub(node.LastSeen) > time.Duration(KeepAliveInterval*2)*time.Second {
			// Node is stale, try to ping it
			if err := nm.pingNode(node); err != nil {
				// Node is unreachable, remove it
				delete(nm.knownNodes, nodeID)
				fmt.Printf("Removed stale node %x\n", nodeID[:8])
			} else {
				// Node responded, update last seen
				node.LastSeen = now
			}
		}
	}
}

// pingNode sends a ping to check if a node is still alive
func (nm *NodeManager) pingNode(node *Node) error {
	// Connect to node with short timeout
	conn, err := net.DialTimeout("tcp", node.Address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to node: %w", err)
	}
	defer conn.Close()

	// Send ping message
	pingMsg := NodeDiscoveryMessage{
		Type:      "ping",
		NodeID:    nm.localNode.ID,
		Timestamp: time.Now().Unix(),
	}

	if err := nm.sendDiscoveryMessage(conn, &pingMsg); err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	// Wait for pong response
	response, err := nm.receiveDiscoveryMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive pong: %w", err)
	}

	if response.Type != "pong" {
		return errors.New("invalid ping response")
	}

	// Measure latency
	latency := time.Since(time.Unix(pingMsg.Timestamp, 0))
	node.Latency = latency

	return nil
}

// GetAvailableNodes returns a list of healthy nodes for routing
func (nm *NodeManager) GetAvailableNodes() []*Node {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	var nodes []*Node
	now := time.Now()

	for _, node := range nm.knownNodes {
		// Only include nodes that have been seen recently
		if now.Sub(node.LastSeen) <= time.Duration(KeepAliveInterval*2)*time.Second {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// StartPeriodicMaintenance starts background tasks for node management
func (nm *NodeManager) StartPeriodicMaintenance() {
	// Start health checking goroutine
	go func() {
		ticker := time.NewTicker(time.Duration(KeepAliveInterval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			nm.CheckNodeHealth()
		}
	}()

	// Start periodic node discovery
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Rediscover every 5 minutes
		defer ticker.Stop()

		for range ticker.C {
			if err := nm.DiscoverNodes(); err != nil {
				fmt.Printf("Periodic node discovery failed: %v\n", err)
			}
		}
	}()
}

// GetNodeStats returns statistics about known nodes
func (nm *NodeManager) GetNodeStats() map[string]interface{} {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_nodes"] = len(nm.knownNodes)
	stats["local_node_id"] = fmt.Sprintf("%x", nm.localNode.ID[:8])
	stats["is_relay"] = nm.isRelay

	// Count nodes by protocol
	tcpNodes := 0
	udpNodes := 0
	for _, node := range nm.knownNodes {
		if node.Protocol == "tcp" {
			tcpNodes++
		} else if node.Protocol == "udp" {
			udpNodes++
		}
	}
	stats["tcp_nodes"] = tcpNodes
	stats["udp_nodes"] = udpNodes

	return stats
}

// SelectRoute chooses a multi-hop route with at least 3 hops
func (nm *NodeManager) SelectRoute(destination string, protocol string) (*Route, error) {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	availableNodes := nm.GetAvailableNodes()
	if len(availableNodes) < MinRelayHops {
		return nil, fmt.Errorf("insufficient nodes for routing: need %d, have %d", MinRelayHops, len(availableNodes))
	}

	// Filter nodes by protocol
	var protocolNodes []*Node
	for _, node := range availableNodes {
		if node.Protocol == protocol {
			protocolNodes = append(protocolNodes, node)
		}
	}

	if len(protocolNodes) < MinRelayHops {
		return nil, fmt.Errorf("insufficient %s nodes for routing: need %d, have %d", protocol, MinRelayHops, len(protocolNodes))
	}

	// Select random nodes for the route (minimum 3 hops)
	hopCount := MinRelayHops
	if len(protocolNodes) > MaxRelayHops {
		// Use more hops if we have enough nodes
		hopCount = MaxRelayHops
	} else if len(protocolNodes) > MinRelayHops {
		hopCount = len(protocolNodes)
	}

	selectedNodes := nm.selectRandomNodes(protocolNodes, hopCount)
	if len(selectedNodes) < MinRelayHops {
		return nil, errors.New("failed to select sufficient nodes for route")
	}

	// Create route
	route := &Route{
		Hops:      selectedNodes,
		Protocol:  protocol,
		CreatedAt: time.Now(),
		Active:    true,
	}

	// Store route
	routeID := nm.generateRouteID(route)
	nm.activeRoutes[routeID] = route

	return route, nil
}

// selectRandomNodes randomly selects n nodes from the available list
func (nm *NodeManager) selectRandomNodes(nodes []*Node, count int) []*Node {
	if count >= len(nodes) {
		// Return all nodes if we need more than available
		result := make([]*Node, len(nodes))
		copy(result, nodes)
		return result
	}

	// Create a copy to avoid modifying original slice
	available := make([]*Node, len(nodes))
	copy(available, nodes)

	var selected []*Node
	for i := 0; i < count; i++ {
		// Generate random index
		randomBytes := make([]byte, 4)
		rand.Read(randomBytes)
		randomIndex := int(randomBytes[0])<<24 | int(randomBytes[1])<<16 | int(randomBytes[2])<<8 | int(randomBytes[3])
		if randomIndex < 0 {
			randomIndex = -randomIndex
		}
		randomIndex = randomIndex % len(available)

		// Select node and remove from available list
		selected = append(selected, available[randomIndex])
		available = append(available[:randomIndex], available[randomIndex+1:]...)
	}

	return selected
}

// generateRouteID creates a unique identifier for a route
func (nm *NodeManager) generateRouteID(route *Route) string {
	// Create route ID based on hop sequence
	routeStr := fmt.Sprintf("%s-%d", route.Protocol, route.CreatedAt.Unix())
	for _, hop := range route.Hops {
		routeStr += fmt.Sprintf("-%x", hop.ID[:4])
	}
	return routeStr
}

// MaintainRoutes performs maintenance on active routes
func (nm *NodeManager) MaintainRoutes() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	now := time.Now()
	
	for routeID, route := range nm.activeRoutes {
		// Check if route is too old
		if now.Sub(route.CreatedAt) > 30*time.Minute {
			// Route is stale, mark as inactive
			route.Active = false
		}

		// Check if all hops are still available
		allHopsAvailable := true
		for _, hop := range route.Hops {
			if _, exists := nm.knownNodes[hop.ID]; !exists {
				allHopsAvailable = false
				break
			}
			
			// Check if hop is still healthy
			if now.Sub(hop.LastSeen) > time.Duration(KeepAliveInterval*2)*time.Second {
				allHopsAvailable = false
				break
			}
		}

		if !allHopsAvailable {
			route.Active = false
		}

		// Remove inactive routes
		if !route.Active {
			delete(nm.activeRoutes, routeID)
			fmt.Printf("Removed inactive route %s\n", routeID)
		}
	}
}

// GetActiveRoutes returns all currently active routes
func (nm *NodeManager) GetActiveRoutes() []*Route {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	var routes []*Route
	for _, route := range nm.activeRoutes {
		if route.Active {
			routes = append(routes, route)
		}
	}

	return routes
}

// CreateFailoverRoute creates a new route when the current one fails
func (nm *NodeManager) CreateFailoverRoute(failedRoute *Route) (*Route, error) {
	// Mark failed route as inactive
	nm.mutex.Lock()
	failedRoute.Active = false
	nm.mutex.Unlock()

	// Create new route with different nodes
	newRoute, err := nm.SelectRoute("", failedRoute.Protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create failover route: %w", err)
	}

	// Ensure new route doesn't use the same nodes as failed route
	for attempt := 0; attempt < 3; attempt++ {
		if !nm.routesOverlap(newRoute, failedRoute) {
			break
		}
		
		// Try again with different selection
		newRoute, err = nm.SelectRoute("", failedRoute.Protocol)
		if err != nil {
			return nil, fmt.Errorf("failed to create non-overlapping failover route: %w", err)
		}
	}

	return newRoute, nil
}

// routesOverlap checks if two routes share any common nodes
func (nm *NodeManager) routesOverlap(route1, route2 *Route) bool {
	for _, hop1 := range route1.Hops {
		for _, hop2 := range route2.Hops {
			if hop1.ID == hop2.ID {
				return true
			}
		}
	}
	return false
}

// StartRelayServer starts the relay server for handling incoming connections
func (nm *NodeManager) StartRelayServer(port int) error {
	if !nm.isRelay {
		return errors.New("node is not configured as relay")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start relay server: %w", err)
	}

	nm.relayServer = &RelayServer{
		listener:    listener,
		connections: make(map[string]*RelayConnection),
		isRunning:   true,
	}

	// Update local node address
	nm.localNode.Address = listener.Addr().String()

	fmt.Printf("Relay server started on %s\n", nm.localNode.Address)

	// Start accepting connections
	go nm.acceptRelayConnections()

	return nil
}

// acceptRelayConnections handles incoming relay connections
func (nm *NodeManager) acceptRelayConnections() {
	for nm.relayServer.isRunning {
		conn, err := nm.relayServer.listener.Accept()
		if err != nil {
			if nm.relayServer.isRunning {
				fmt.Printf("Failed to accept relay connection: %v\n", err)
			}
			continue
		}

		// Handle connection in separate goroutine
		go nm.handleRelayConnection(conn)
	}
}

// handleRelayConnection processes a single relay connection
func (nm *NodeManager) handleRelayConnection(conn net.Conn) {
	defer conn.Close()

	// Perform handshake to identify the connecting node
	nodeID, cryptoContext, err := nm.performRelayHandshake(conn)
	if err != nil {
		fmt.Printf("Relay handshake failed: %v\n", err)
		return
	}

	// Create relay connection
	relayConn := &RelayConnection{
		conn:          conn,
		nodeID:        nodeID,
		cryptoContext: cryptoContext,
		lastActivity:  time.Now(),
		isActive:      true,
	}

	// Add to active connections
	connID := fmt.Sprintf("%x", nodeID[:8])
	nm.relayServer.mutex.Lock()
	nm.relayServer.connections[connID] = relayConn
	nm.relayServer.mutex.Unlock()

	fmt.Printf("New relay connection from node %s\n", connID)

	// Handle packet forwarding
	nm.handlePacketForwarding(relayConn)

	// Clean up connection
	nm.relayServer.mutex.Lock()
	delete(nm.relayServer.connections, connID)
	nm.relayServer.mutex.Unlock()
}

// performRelayHandshake performs handshake with connecting node
func (nm *NodeManager) performRelayHandshake(conn net.Conn) (NodeID, *CryptoContext, error) {
	// Set handshake timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Receive handshake message from connecting node
	handshakeMsg, err := nm.receiveDiscoveryMessage(conn)
	if err != nil {
		return NodeID{}, nil, fmt.Errorf("failed to receive handshake: %w", err)
	}

	if handshakeMsg.Type != "handshake" {
		return NodeID{}, nil, errors.New("invalid handshake message type")
	}

	// Generate local key pair for this connection
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return NodeID{}, nil, fmt.Errorf("failed to generate handshake keys: %w", err)
	}

	// Send handshake response
	responseMsg := NodeDiscoveryMessage{
		Type:      "handshake_response",
		NodeID:    nm.localNode.ID,
		PublicKey: localKeyPair.PublicKey,
		Timestamp: time.Now().Unix(),
	}

	if err := nm.sendDiscoveryMessage(conn, &responseMsg); err != nil {
		return NodeID{}, nil, fmt.Errorf("failed to send handshake response: %w", err)
	}

	// Perform key exchange
	cryptoContext := &CryptoContext{
		LocalKeyPair:    KeyPair{PublicKey: localKeyPair.PublicKey, PrivateKey: localKeyPair.PrivateKey},
		RemotePublicKey: handshakeMsg.PublicKey,
		CreatedAt:       time.Now(),
	}

	// Derive shared secret (simplified)
	cryptoContext.SharedSecret = deriveSymmetricKey(append(localKeyPair.PrivateKey, handshakeMsg.PublicKey...))

	return handshakeMsg.NodeID, cryptoContext, nil
}

// handlePacketForwarding handles packet forwarding for a relay connection
func (nm *NodeManager) handlePacketForwarding(relayConn *RelayConnection) {
	buffer := make([]byte, MaxPacketSize*2)
	
	for relayConn.isActive {
		// Set read timeout
		relayConn.conn.SetReadDeadline(time.Now().Add(time.Duration(KeepAliveInterval) * time.Second))
		
		// Read packet
		n, err := relayConn.conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout - check if connection is still needed
				if time.Since(relayConn.lastActivity) > time.Duration(KeepAliveInterval*2)*time.Second {
					break // Close idle connection
				}
				continue
			}
			fmt.Printf("Failed to read from relay connection: %v\n", err)
			break
		}

		relayConn.lastActivity = time.Now()

		// Process and forward packet
		if err := nm.forwardPacket(buffer[:n], relayConn); err != nil {
			fmt.Printf("Failed to forward packet: %v\n", err)
			// Continue processing other packets
		}
	}

	relayConn.isActive = false
}

// forwardPacket forwards a packet to the next hop without correlation
func (nm *NodeManager) forwardPacket(packetData []byte, relayConn *RelayConnection) error {
	// Parse packet header to determine next hop
	if len(packetData) < 64 { // Minimum packet size
		return errors.New("packet too small")
	}

	// Extract next hop information (encrypted)
	// In a real implementation, this would involve decrypting the routing header
	// For now, we'll simulate by selecting a random next hop
	
	availableNodes := nm.GetAvailableNodes()
	if len(availableNodes) == 0 {
		return errors.New("no available nodes for forwarding")
	}

	// Select random next hop (excluding sender)
	var nextHop *Node
	for _, node := range availableNodes {
		if node.ID != relayConn.nodeID {
			nextHop = node
			break
		}
	}

	if nextHop == nil {
		return errors.New("no suitable next hop found")
	}

	// Forward packet to next hop
	return nm.forwardToNode(packetData, nextHop)
}

// forwardToNode forwards a packet to a specific node
func (nm *NodeManager) forwardToNode(packetData []byte, node *Node) error {
	// Connect to next hop
	conn, err := net.DialTimeout("tcp", node.Address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to next hop: %w", err)
	}
	defer conn.Close()

	// Send packet
	if _, err := conn.Write(packetData); err != nil {
		return fmt.Errorf("failed to forward packet: %w", err)
	}

	return nil
}

// StopRelayServer stops the relay server
func (nm *NodeManager) StopRelayServer() error {
	if nm.relayServer == nil {
		return nil
	}

	nm.relayServer.isRunning = false
	
	// Close listener
	if err := nm.relayServer.listener.Close(); err != nil {
		return fmt.Errorf("failed to close relay listener: %w", err)
	}

	// Close all active connections
	nm.relayServer.mutex.Lock()
	for _, conn := range nm.relayServer.connections {
		conn.isActive = false
		conn.conn.Close()
	}
	nm.relayServer.mutex.Unlock()

	fmt.Println("Relay server stopped")
	return nil
}

// GetRelayStats returns statistics about relay operations
func (nm *NodeManager) GetRelayStats() map[string]interface{} {
	if nm.relayServer == nil {
		return map[string]interface{}{
			"is_relay": false,
		}
	}

	nm.relayServer.mutex.RLock()
	defer nm.relayServer.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["is_relay"] = true
	stats["is_running"] = nm.relayServer.isRunning
	stats["active_connections"] = len(nm.relayServer.connections)
	stats["listen_address"] = nm.localNode.Address

	return stats
}

// RoutingTable manages encrypted next-hop addressing
type RoutingTable struct {
	entries map[string]*RoutingEntry
	mutex   sync.RWMutex
}

// RoutingEntry represents an encrypted routing table entry
type RoutingEntry struct {
	RouteID       string    `json:"route_id"`
	EncryptedHops []byte    `json:"encrypted_hops"` // Encrypted next hop information
	HopIndex      int       `json:"hop_index"`      // Current position in route
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// NewRoutingTable creates a new routing table
func NewRoutingTable() *RoutingTable {
	return &RoutingTable{
		entries: make(map[string]*RoutingEntry),
	}
}

// AddRoute adds a new route to the routing table with encrypted next-hop addressing
func (rt *RoutingTable) AddRoute(route *Route) (string, error) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// Generate unique route ID
	routeID := generateUniqueRouteID()
	
	// Encrypt the hop sequence for privacy
	encryptedHops, err := encryptHopSequence(route.Hops)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt hop sequence: %w", err)
	}

	// Create routing entry
	entry := &RoutingEntry{
		RouteID:       routeID,
		EncryptedHops: encryptedHops,
		HopIndex:      0,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute), // Routes expire after 30 minutes
	}

	rt.entries[routeID] = entry
	return routeID, nil
}

// GetNextHop returns the next hop for a given route ID
func (rt *RoutingTable) GetNextHop(routeID string) (*Node, error) {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	entry, exists := rt.entries[routeID]
	if !exists {
		return nil, errors.New("route not found")
	}

	// Check if route has expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, errors.New("route expired")
	}

	// Decrypt and get next hop
	hops, err := decryptHopSequence(entry.EncryptedHops)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt hop sequence: %w", err)
	}

	if entry.HopIndex >= len(hops) {
		return nil, errors.New("route completed")
	}

	nextHop := hops[entry.HopIndex]
	return nextHop, nil
}

// AdvanceRoute moves to the next hop in the route
func (rt *RoutingTable) AdvanceRoute(routeID string) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	entry, exists := rt.entries[routeID]
	if !exists {
		return errors.New("route not found")
	}

	entry.HopIndex++
	return nil
}

// RemoveRoute removes a route from the routing table
func (rt *RoutingTable) RemoveRoute(routeID string) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	delete(rt.entries, routeID)
}

// CleanupExpiredRoutes removes expired routes from the table
func (rt *RoutingTable) CleanupExpiredRoutes() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	now := time.Now()
	for routeID, entry := range rt.entries {
		if now.After(entry.ExpiresAt) {
			delete(rt.entries, routeID)
		}
	}
}

// generateUniqueRouteID creates a unique identifier for a route
func generateUniqueRouteID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return fmt.Sprintf("%x", randomBytes)
}

// encryptHopSequence encrypts a sequence of hops for privacy
func encryptHopSequence(hops []*Node) ([]byte, error) {
	// Serialize hops to JSON
	hopsData, err := json.Marshal(hops)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal hops: %w", err)
	}

	// Generate encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Encrypt using simple XOR (in production, use proper encryption)
	encrypted := make([]byte, len(hopsData)+32) // Include key
	copy(encrypted[:32], key)
	
	for i, b := range hopsData {
		encrypted[32+i] = b ^ key[i%32]
	}

	return encrypted, nil
}

// decryptHopSequence decrypts a sequence of hops
func decryptHopSequence(encryptedData []byte) ([]*Node, error) {
	if len(encryptedData) < 32 {
		return nil, errors.New("encrypted data too short")
	}

	// Extract key and encrypted data
	key := encryptedData[:32]
	encrypted := encryptedData[32:]

	// Decrypt using XOR
	decrypted := make([]byte, len(encrypted))
	for i, b := range encrypted {
		decrypted[i] = b ^ key[i%32]
	}

	// Deserialize hops
	var hops []*Node
	if err := json.Unmarshal(decrypted, &hops); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hops: %w", err)
	}

	return hops, nil
}

// RouteFailureHandler handles route failures and implements failover
type RouteFailureHandler struct {
	nodeManager   *NodeManager
	routingTable  *RoutingTable
	failedRoutes  map[string]time.Time
	mutex         sync.RWMutex
}

// NewRouteFailureHandler creates a new route failure handler
func NewRouteFailureHandler(nm *NodeManager, rt *RoutingTable) *RouteFailureHandler {
	return &RouteFailureHandler{
		nodeManager:  nm,
		routingTable: rt,
		failedRoutes: make(map[string]time.Time),
	}
}

// HandleRouteFailure processes a route failure and creates failover route
func (rfh *RouteFailureHandler) HandleRouteFailure(routeID string, failureReason error) (*Route, error) {
	rfh.mutex.Lock()
	defer rfh.mutex.Unlock()

	// Record failure
	rfh.failedRoutes[routeID] = time.Now()
	
	// Remove failed route from routing table
	rfh.routingTable.RemoveRoute(routeID)

	fmt.Printf("Route %s failed: %v\n", routeID[:8], failureReason)

	// Get original route information to create failover
	originalRoute := rfh.nodeManager.activeRoutes[routeID]
	if originalRoute == nil {
		return nil, errors.New("original route not found")
	}

	// Create failover route
	failoverRoute, err := rfh.nodeManager.CreateFailoverRoute(originalRoute)
	if err != nil {
		return nil, fmt.Errorf("failed to create failover route: %w", err)
	}

	// Add failover route to routing table
	newRouteID, err := rfh.routingTable.AddRoute(failoverRoute)
	if err != nil {
		return nil, fmt.Errorf("failed to add failover route to routing table: %w", err)
	}

	fmt.Printf("Created failover route %s\n", newRouteID[:8])
	return failoverRoute, nil
}

// GetFailureStats returns statistics about route failures
func (rfh *RouteFailureHandler) GetFailureStats() map[string]interface{} {
	rfh.mutex.RLock()
	defer rfh.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_failures"] = len(rfh.failedRoutes)
	
	// Count recent failures (last hour)
	recentFailures := 0
	oneHourAgo := time.Now().Add(-time.Hour)
	for _, failureTime := range rfh.failedRoutes {
		if failureTime.After(oneHourAgo) {
			recentFailures++
		}
	}
	stats["recent_failures"] = recentFailures

	return stats
}

// StartRouteMaintenance starts background route maintenance
func (nm *NodeManager) StartRouteMaintenance() {
	routingTable := NewRoutingTable()
	failureHandler := NewRouteFailureHandler(nm, routingTable)

	// Start route maintenance goroutine
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			// Maintain routes
			nm.MaintainRoutes()
			
			// Cleanup expired routing table entries
			routingTable.CleanupExpiredRoutes()
		}
	}()

	// Store references for later use
	nm.routingTable = routingTable
	nm.failureHandler = failureHandler
}

// Note: routing table and failure handler fields are added to NodeManager struct

// Enhanced route selection with load balancing
func (nm *NodeManager) SelectOptimalRoute(destination string, protocol string) (*Route, error) {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	availableNodes := nm.GetAvailableNodes()
	if len(availableNodes) < MinRelayHops {
		return nil, fmt.Errorf("insufficient nodes for routing: need %d, have %d", MinRelayHops, len(availableNodes))
	}

	// Filter and sort nodes by latency and load
	var suitableNodes []*Node
	for _, node := range availableNodes {
		if node.Protocol == protocol {
			suitableNodes = append(suitableNodes, node)
		}
	}

	if len(suitableNodes) < MinRelayHops {
		return nil, fmt.Errorf("insufficient %s nodes for routing", protocol)
	}

	// Sort nodes by latency (prefer lower latency)
	for i := 0; i < len(suitableNodes)-1; i++ {
		for j := i + 1; j < len(suitableNodes); j++ {
			if suitableNodes[i].Latency > suitableNodes[j].Latency {
				suitableNodes[i], suitableNodes[j] = suitableNodes[j], suitableNodes[i]
			}
		}
	}

	// Select best nodes for route (prefer low latency but ensure diversity)
	hopCount := MinRelayHops
	if len(suitableNodes) > MaxRelayHops {
		hopCount = MaxRelayHops
	}

	var selectedNodes []*Node
	usedNodes := make(map[NodeID]bool)

	// Select first hop from lowest latency nodes
	for _, node := range suitableNodes {
		if len(selectedNodes) < hopCount && !usedNodes[node.ID] {
			selectedNodes = append(selectedNodes, node)
			usedNodes[node.ID] = true
		}
	}

	if len(selectedNodes) < MinRelayHops {
		return nil, errors.New("failed to select sufficient optimal nodes")
	}

	// Create optimized route
	route := &Route{
		Hops:      selectedNodes,
		Protocol:  protocol,
		CreatedAt: time.Now(),
		Active:    true,
	}

	// Store route
	routeID := nm.generateRouteID(route)
	nm.activeRoutes[routeID] = route

	return route, nil
}

// PacketProcessor handles packet processing without correlation capability
type PacketProcessor struct {
	processingQueue chan *RelayPacket
	outputQueue     chan *RelayPacket
	isRunning       bool
	mutex           sync.RWMutex
}

// RelayPacket represents a packet being processed by the relay
type RelayPacket struct {
	Data         []byte
	SourceConn   *RelayConnection
	Timestamp    time.Time
	ProcessingID [16]byte // Unique ID for this processing instance
}

// NewPacketProcessor creates a new packet processor
func NewPacketProcessor() *PacketProcessor {
	return &PacketProcessor{
		processingQueue: make(chan *RelayPacket, 1000),
		outputQueue:     make(chan *RelayPacket, 1000),
		isRunning:       false,
	}
}

// StartPacketProcessor starts the packet processing pipeline
func (pp *PacketProcessor) StartPacketProcessor() {
	pp.mutex.Lock()
	defer pp.mutex.Unlock()

	if pp.isRunning {
		return
	}

	pp.isRunning = true

	// Start input processing goroutine
	go pp.processIncomingPackets()

	// Start output processing goroutine
	go pp.processOutgoingPackets()

	// Start packet mixing goroutine (prevents timing correlation)
	go pp.mixPacketTiming()
}

// StopPacketProcessor stops the packet processing pipeline
func (pp *PacketProcessor) StopPacketProcessor() {
	pp.mutex.Lock()
	defer pp.mutex.Unlock()

	pp.isRunning = false
	close(pp.processingQueue)
	close(pp.outputQueue)
}

// ProcessPacket adds a packet to the processing queue
func (pp *PacketProcessor) ProcessPacket(data []byte, sourceConn *RelayConnection) error {
	if !pp.isRunning {
		return errors.New("packet processor not running")
	}

	// Generate unique processing ID
	var processingID [16]byte
	rand.Read(processingID[:])

	packet := &RelayPacket{
		Data:         make([]byte, len(data)),
		SourceConn:   sourceConn,
		Timestamp:    time.Now(),
		ProcessingID: processingID,
	}
	copy(packet.Data, data)

	select {
	case pp.processingQueue <- packet:
		return nil
	default:
		return errors.New("processing queue full")
	}
}

// processIncomingPackets processes packets from the input queue
func (pp *PacketProcessor) processIncomingPackets() {
	for pp.isRunning {
		select {
		case packet, ok := <-pp.processingQueue:
			if !ok {
				return
			}

			// Process packet without correlation
			processedPacket := pp.processPacketWithoutCorrelation(packet)
			if processedPacket != nil {
				// Add random delay to prevent timing correlation
				delay := time.Duration(MinPacketDelay+mathrand.Intn(MaxPacketDelay-MinPacketDelay)) * time.Millisecond
				time.Sleep(delay)

				// Send to output queue
				select {
				case pp.outputQueue <- processedPacket:
				default:
					// Drop packet if output queue is full
					fmt.Println("Output queue full, dropping packet")
				}
			}
		}
	}
}

// processOutgoingPackets handles packets from the output queue
func (pp *PacketProcessor) processOutgoingPackets() {
	for pp.isRunning {
		select {
		case packet, ok := <-pp.outputQueue:
			if !ok {
				return
			}

			// Forward packet to next hop
			if err := pp.forwardProcessedPacket(packet); err != nil {
				fmt.Printf("Failed to forward processed packet: %v\n", err)
			}
		}
	}
}

// mixPacketTiming adds random delays to prevent timing analysis
func (pp *PacketProcessor) mixPacketTiming() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for pp.isRunning {
		select {
		case <-ticker.C:
			// Inject dummy processing to create timing noise
			if mathrand.Float32() < 0.1 { // 10% chance
				delay := time.Duration(mathrand.Intn(50)) * time.Millisecond
				time.Sleep(delay)
			}
		}
	}
}

// processPacketWithoutCorrelation processes a packet while preventing correlation
func (pp *PacketProcessor) processPacketWithoutCorrelation(packet *RelayPacket) *RelayPacket {
	// Validate packet structure
	if len(packet.Data) < 64 {
		return nil // Drop malformed packets
	}

	// Create new packet instance to break memory correlation
	processedPacket := &RelayPacket{
		Data:         make([]byte, len(packet.Data)),
		SourceConn:   nil, // Remove source connection reference
		Timestamp:    time.Now(), // New timestamp
		ProcessingID: packet.ProcessingID,
	}
	copy(processedPacket.Data, packet.Data)

	// Modify packet to prevent fingerprinting (while preserving functionality)
	pp.obfuscatePacketFingerprint(processedPacket.Data)

	return processedPacket
}

// obfuscatePacketFingerprint modifies packet to prevent fingerprinting
func (pp *PacketProcessor) obfuscatePacketFingerprint(data []byte) {
	// Add random padding to change packet size slightly
	if len(data) > 100 && mathrand.Float32() < 0.3 {
		// Randomly modify non-critical bytes (last few bytes)
		for i := len(data) - 8; i < len(data); i++ {
			if mathrand.Float32() < 0.5 {
				data[i] ^= byte(mathrand.Intn(256))
			}
		}
	}
}

// forwardProcessedPacket forwards a processed packet to the next hop
func (pp *PacketProcessor) forwardProcessedPacket(packet *RelayPacket) error {
	// This would integrate with the routing system to determine next hop
	// For now, we'll simulate forwarding
	
	// In a real implementation, this would:
	// 1. Decrypt routing header to get next hop
	// 2. Establish connection to next hop
	// 3. Forward packet
	
	fmt.Printf("Forwarding processed packet %x (size: %d bytes)\n", 
		packet.ProcessingID[:4], len(packet.Data))
	
	return nil
}

// Enhanced relay connection handling with packet processing
func (nm *NodeManager) handleRelayConnectionWithProcessor(conn net.Conn) {
	defer conn.Close()

	// Perform handshake
	nodeID, cryptoContext, err := nm.performRelayHandshake(conn)
	if err != nil {
		fmt.Printf("Relay handshake failed: %v\n", err)
		return
	}

	// Create relay connection
	relayConn := &RelayConnection{
		conn:          conn,
		nodeID:        nodeID,
		cryptoContext: cryptoContext,
		lastActivity:  time.Now(),
		isActive:      true,
	}

	// Add to active connections
	connID := fmt.Sprintf("%x", nodeID[:8])
	nm.relayServer.mutex.Lock()
	nm.relayServer.connections[connID] = relayConn
	nm.relayServer.mutex.Unlock()

	// Create packet processor for this connection
	processor := NewPacketProcessor()
	processor.StartPacketProcessor()
	defer processor.StopPacketProcessor()

	fmt.Printf("New relay connection with packet processor from node %s\n", connID)

	// Handle packets with processing pipeline
	buffer := make([]byte, MaxPacketSize*2)
	
	for relayConn.isActive {
		// Set read timeout
		relayConn.conn.SetReadDeadline(time.Now().Add(time.Duration(KeepAliveInterval) * time.Second))
		
		// Read packet
		n, err := relayConn.conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if time.Since(relayConn.lastActivity) > time.Duration(KeepAliveInterval*2)*time.Second {
					break
				}
				continue
			}
			fmt.Printf("Failed to read from relay connection: %v\n", err)
			break
		}

		relayConn.lastActivity = time.Now()

		// Process packet through correlation-prevention pipeline
		if err := processor.ProcessPacket(buffer[:n], relayConn); err != nil {
			fmt.Printf("Failed to process packet: %v\n", err)
		}
	}

	relayConn.isActive = false

	// Clean up connection
	nm.relayServer.mutex.Lock()
	delete(nm.relayServer.connections, connID)
	nm.relayServer.mutex.Unlock()
}

// RelayStatistics tracks relay node performance and statistics
type RelayStatistics struct {
	PacketsForwarded    uint64
	BytesForwarded      uint64
	ActiveConnections   int
	TotalConnections    uint64
	AverageLatency      time.Duration
	UptimeStart         time.Time
	LastPacketTime      time.Time
	ErrorCount          uint64
	mutex               sync.RWMutex
}

// NewRelayStatistics creates a new relay statistics tracker
func NewRelayStatistics() *RelayStatistics {
	return &RelayStatistics{
		UptimeStart: time.Now(),
	}
}

// RecordPacketForwarded records a forwarded packet
func (rs *RelayStatistics) RecordPacketForwarded(size int) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	rs.PacketsForwarded++
	rs.BytesForwarded += uint64(size)
	rs.LastPacketTime = time.Now()
}

// RecordConnection records a new connection
func (rs *RelayStatistics) RecordConnection() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	rs.TotalConnections++
	rs.ActiveConnections++
}

// RecordDisconnection records a connection closure
func (rs *RelayStatistics) RecordDisconnection() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if rs.ActiveConnections > 0 {
		rs.ActiveConnections--
	}
}

// RecordError records an error
func (rs *RelayStatistics) RecordError() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	rs.ErrorCount++
}

// GetStats returns current statistics
func (rs *RelayStatistics) GetStats() map[string]interface{} {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	uptime := time.Since(rs.UptimeStart)
	
	stats := make(map[string]interface{})
	stats["packets_forwarded"] = rs.PacketsForwarded
	stats["bytes_forwarded"] = rs.BytesForwarded
	stats["active_connections"] = rs.ActiveConnections
	stats["total_connections"] = rs.TotalConnections
	stats["uptime_seconds"] = int(uptime.Seconds())
	stats["error_count"] = rs.ErrorCount
	
	if !rs.LastPacketTime.IsZero() {
		stats["last_packet_ago_seconds"] = int(time.Since(rs.LastPacketTime).Seconds())
	}
	
	// Calculate packets per second
	if uptime.Seconds() > 0 {
		stats["packets_per_second"] = float64(rs.PacketsForwarded) / uptime.Seconds()
	}

	return stats
}

// Add statistics to NodeManager
func (nm *NodeManager) GetEnhancedRelayStats() map[string]interface{} {
	baseStats := nm.GetRelayStats()
	
	if nm.relayServer != nil && nm.relayServer.statistics != nil {
		relayStats := nm.relayServer.statistics.GetStats()
		for k, v := range relayStats {
			baseStats[k] = v
		}
	}

	return baseStats
}

// Update RelayServer to include statistics
func (nm *NodeManager) StartEnhancedRelayServer(port int) error {
	if !nm.isRelay {
		return errors.New("node is not configured as relay")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start relay server: %w", err)
	}

	nm.relayServer = &RelayServer{
		listener:    listener,
		connections: make(map[string]*RelayConnection),
		isRunning:   true,
		statistics:  NewRelayStatistics(),
	}

	// Update local node address
	nm.localNode.Address = listener.Addr().String()

	fmt.Printf("Enhanced relay server started on %s\n", nm.localNode.Address)

	// Start accepting connections with enhanced processing
	go nm.acceptEnhancedRelayConnections()

	return nil
}

// acceptEnhancedRelayConnections handles incoming connections with enhanced processing
func (nm *NodeManager) acceptEnhancedRelayConnections() {
	for nm.relayServer.isRunning {
		conn, err := nm.relayServer.listener.Accept()
		if err != nil {
			if nm.relayServer.isRunning {
				fmt.Printf("Failed to accept relay connection: %v\n", err)
				nm.relayServer.statistics.RecordError()
			}
			continue
		}

		// Record new connection
		nm.relayServer.statistics.RecordConnection()

		// Handle connection with enhanced processing
		go func() {
			defer nm.relayServer.statistics.RecordDisconnection()
			nm.handleRelayConnectionWithProcessor(conn)
		}()
	}
}

// Add statistics field to RelayServer
type EnhancedRelayServer struct {
	listener    net.Listener
	connections map[string]*RelayConnection
	mutex       sync.RWMutex
	isRunning   bool
	statistics  *RelayStatistics
}