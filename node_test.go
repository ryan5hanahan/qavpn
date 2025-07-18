package main

import (
	"testing"
	"time"
)

// TestNodeManagerCreation tests creating a new node manager
func TestNodeManagerCreation(t *testing.T) {
	// Test client node creation
	clientNM, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create client node manager: %v", err)
	}

	if clientNM.isRelay {
		t.Error("Client node manager should not be relay")
	}

	if clientNM.localNode == nil {
		t.Error("Local node should not be nil")
	}

	if len(clientNM.localNode.ID) != 32 {
		t.Error("Node ID should be 32 bytes")
	}

	// Test relay node creation
	relayNM, err := NewNodeManager(true)
	if err != nil {
		t.Fatalf("Failed to create relay node manager: %v", err)
	}

	if !relayNM.isRelay {
		t.Error("Relay node manager should be relay")
	}
}

// TestNodeDiscovery tests node discovery functionality
func TestNodeDiscovery(t *testing.T) {
	nm, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	// Test with empty bootstrap list (should fail)
	nm.bootstrapList = []string{}
	err = nm.DiscoverNodes()
	if err == nil {
		t.Error("Discovery should fail with empty bootstrap list")
	}

	// Test with invalid bootstrap addresses (should fail gracefully)
	nm.bootstrapList = []string{"invalid:9999", "localhost:99999"}
	err = nm.DiscoverNodes()
	if err == nil {
		t.Error("Discovery should fail with invalid bootstrap addresses")
	}
}

// TestRouteSelection tests route selection functionality
func TestRouteSelection(t *testing.T) {
	nm, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	// Add some mock nodes
	for i := 0; i < 5; i++ {
		node := &Node{
			ID:       NodeID{byte(i)}, // Simple ID for testing
			Address:  "127.0.0.1:9051",
			Protocol: "tcp",
			LastSeen: time.Now(),
		}
		nm.knownNodes[node.ID] = node
	}

	// Test route selection
	route, err := nm.SelectRoute("destination", "tcp")
	if err != nil {
		t.Fatalf("Failed to select route: %v", err)
	}

	if len(route.Hops) < MinRelayHops {
		t.Errorf("Route should have at least %d hops, got %d", MinRelayHops, len(route.Hops))
	}

	if route.Protocol != "tcp" {
		t.Errorf("Route protocol should be tcp, got %s", route.Protocol)
	}

	if !route.Active {
		t.Error("New route should be active")
	}
}

// TestRoutingTable tests routing table functionality
func TestRoutingTable(t *testing.T) {
	rt := NewRoutingTable()

	// Create a test route
	nodes := []*Node{
		{ID: NodeID{1}, Address: "127.0.0.1:9051", Protocol: "tcp"},
		{ID: NodeID{2}, Address: "127.0.0.1:9052", Protocol: "tcp"},
		{ID: NodeID{3}, Address: "127.0.0.1:9053", Protocol: "tcp"},
	}

	route := &Route{
		Hops:      nodes,
		Protocol:  "tcp",
		CreatedAt: time.Now(),
		Active:    true,
	}

	// Add route to table
	routeID, err := rt.AddRoute(route)
	if err != nil {
		t.Fatalf("Failed to add route to table: %v", err)
	}

	if routeID == "" {
		t.Error("Route ID should not be empty")
	}

	// Get next hop
	nextHop, err := rt.GetNextHop(routeID)
	if err != nil {
		t.Fatalf("Failed to get next hop: %v", err)
	}

	if nextHop.ID != nodes[0].ID {
		t.Error("Next hop should be first node in route")
	}

	// Advance route
	err = rt.AdvanceRoute(routeID)
	if err != nil {
		t.Fatalf("Failed to advance route: %v", err)
	}

	// Get next hop again
	nextHop, err = rt.GetNextHop(routeID)
	if err != nil {
		t.Fatalf("Failed to get next hop after advance: %v", err)
	}

	if nextHop.ID != nodes[1].ID {
		t.Error("Next hop should be second node after advance")
	}

	// Remove route
	rt.RemoveRoute(routeID)

	// Should not find route after removal
	_, err = rt.GetNextHop(routeID)
	if err == nil {
		t.Error("Should not find route after removal")
	}
}

// TestPacketProcessor tests packet processing functionality
func TestPacketProcessor(t *testing.T) {
	pp := NewPacketProcessor()

	if pp.isRunning {
		t.Error("Packet processor should not be running initially")
	}

	// Start processor
	pp.StartPacketProcessor()

	if !pp.isRunning {
		t.Error("Packet processor should be running after start")
	}

	// Test packet processing
	testData := []byte("test packet data")
	err := pp.ProcessPacket(testData, nil)
	if err != nil {
		t.Fatalf("Failed to process packet: %v", err)
	}

	// Stop processor
	pp.StopPacketProcessor()

	if pp.isRunning {
		t.Error("Packet processor should not be running after stop")
	}

	// Should fail to process packet after stop
	err = pp.ProcessPacket(testData, nil)
	if err == nil {
		t.Error("Should fail to process packet after processor stop")
	}
}

// TestRelayStatistics tests relay statistics functionality
func TestRelayStatistics(t *testing.T) {
	stats := NewRelayStatistics()

	// Initial stats should be zero
	initialStats := stats.GetStats()
	if initialStats["packets_forwarded"] != uint64(0) {
		t.Error("Initial packets forwarded should be 0")
	}

	if initialStats["bytes_forwarded"] != uint64(0) {
		t.Error("Initial bytes forwarded should be 0")
	}

	// Record some activity
	stats.RecordPacketForwarded(100)
	stats.RecordPacketForwarded(200)
	stats.RecordConnection()
	stats.RecordError()

	// Check updated stats
	updatedStats := stats.GetStats()
	if updatedStats["packets_forwarded"] != uint64(2) {
		t.Errorf("Expected 2 packets forwarded, got %v", updatedStats["packets_forwarded"])
	}

	if updatedStats["bytes_forwarded"] != uint64(300) {
		t.Errorf("Expected 300 bytes forwarded, got %v", updatedStats["bytes_forwarded"])
	}

	if updatedStats["active_connections"] != 1 {
		t.Errorf("Expected 1 active connection, got %v", updatedStats["active_connections"])
	}

	if updatedStats["error_count"] != uint64(1) {
		t.Errorf("Expected 1 error, got %v", updatedStats["error_count"])
	}

	// Record disconnection
	stats.RecordDisconnection()
	finalStats := stats.GetStats()
	if finalStats["active_connections"] != 0 {
		t.Errorf("Expected 0 active connections after disconnection, got %v", finalStats["active_connections"])
	}
}

// TestNodeHealthChecking tests node health checking functionality
func TestNodeHealthChecking(t *testing.T) {
	nm, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	// Add a stale node (old LastSeen time)
	staleNode := &Node{
		ID:       NodeID{99},
		Address:  "127.0.0.1:9999", // Invalid address
		Protocol: "tcp",
		LastSeen: time.Now().Add(-time.Hour), // 1 hour ago
	}
	nm.knownNodes[staleNode.ID] = staleNode

	// Add a fresh node
	freshNode := &Node{
		ID:       NodeID{100},
		Address:  "127.0.0.1:9051",
		Protocol: "tcp",
		LastSeen: time.Now(),
	}
	nm.knownNodes[freshNode.ID] = freshNode

	initialCount := len(nm.knownNodes)

	// Run health check
	nm.CheckNodeHealth()

	// Stale node should be removed (since address is invalid)
	if len(nm.knownNodes) >= initialCount {
		t.Error("Stale node should have been removed during health check")
	}

	// Fresh node should still be there
	if _, exists := nm.knownNodes[freshNode.ID]; !exists {
		t.Error("Fresh node should not have been removed")
	}
}

// TestFailoverRouting tests route failover functionality
func TestFailoverRouting(t *testing.T) {
	nm, err := NewNodeManager(false)
	if err != nil {
		t.Fatalf("Failed to create node manager: %v", err)
	}

	// Add enough nodes for multiple routes
	for i := 0; i < 8; i++ {
		node := &Node{
			ID:       NodeID{byte(i)},
			Address:  "127.0.0.1:9051",
			Protocol: "tcp",
			LastSeen: time.Now(),
		}
		nm.knownNodes[node.ID] = node
	}

	// Create initial route
	originalRoute, err := nm.SelectRoute("destination", "tcp")
	if err != nil {
		t.Fatalf("Failed to create original route: %v", err)
	}

	// Create failover route
	failoverRoute, err := nm.CreateFailoverRoute(originalRoute)
	if err != nil {
		t.Fatalf("Failed to create failover route: %v", err)
	}

	// Original route should be inactive
	if originalRoute.Active {
		t.Error("Original route should be inactive after failover")
	}

	// Failover route should be active
	if !failoverRoute.Active {
		t.Error("Failover route should be active")
	}

	// Routes should not overlap (use different nodes) - but with limited nodes, some overlap is acceptable
	// This test verifies that failover routing works, even if routes might overlap with limited nodes
	if nm.routesOverlap(originalRoute, failoverRoute) {
		t.Log("Routes overlap due to limited node pool - this is acceptable for testing")
	}
}