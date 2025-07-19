package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Main application entry point
func main() {
	// Load configuration from file if it exists
	config, err := loadConfig()
	if err != nil {
		log.Printf("Warning: Could not load config file, using defaults: %v", err)
		config = NewDefaultConfig()
	}

	// Parse command line arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	
	// Handle help flags
	if command == "help" || command == "-h" || command == "--help" {
		printDetailedHelp()
		return
	}

	// Parse command-specific arguments
	switch command {
	case "start":
		config.RelayMode = false
		if err := parseStartArgs(config); err != nil {
			log.Fatalf("Error parsing start arguments: %v", err)
		}
		fmt.Printf("QAVPN v%d.%d.%d - Starting VPN client...\n", VersionMajor, VersionMinor, VersionPatch)
		if err := startIntegratedClient(config); err != nil {
			log.Fatalf("Failed to start client: %v", err)
		}
	case "relay":
		config.RelayMode = true
		if err := parseRelayArgs(config); err != nil {
			log.Fatalf("Error parsing relay arguments: %v", err)
		}
		fmt.Printf("QAVPN v%d.%d.%d - Starting relay node...\n", VersionMajor, VersionMinor, VersionPatch)
		if err := startIntegratedRelay(config); err != nil {
			log.Fatalf("Failed to start relay: %v", err)
		}
	case "direct":
		fmt.Printf("QAVPN v%d.%d.%d - Direct Connection Mode\n", VersionMajor, VersionMinor, VersionPatch)
		directCLI := NewDirectCLIWithConfig(config)
		if err := directCLI.HandleDirectCommand(os.Args[2:]); err != nil {
			log.Fatalf("Direct mode error: %v", err)
		}
	case "status":
		fmt.Printf("QAVPN v%d.%d.%d - Connection Status\n", VersionMajor, VersionMinor, VersionPatch)
		showIntegratedStatus()
	case "version":
		fmt.Printf("QAVPN v%d.%d.%d\n", VersionMajor, VersionMinor, VersionPatch)
	case "config":
		if err := createDefaultConfigFile(); err != nil {
			log.Fatalf("Failed to create config file: %v", err)
		}
		fmt.Println("Default configuration file created at ~/.qavpn/config")
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// printUsage displays basic command usage information
func printUsage() {
	fmt.Printf("Quantum Anonymous VPN v%d.%d.%d\n", VersionMajor, VersionMinor, VersionPatch)
	fmt.Println("Usage:")
	fmt.Printf("  %s start   - Start VPN client\n", os.Args[0])
	fmt.Printf("  %s relay   - Run as relay node\n", os.Args[0])
	fmt.Printf("  %s direct  - Direct connection mode\n", os.Args[0])
	fmt.Printf("  %s status  - Show connection status\n", os.Args[0])
	fmt.Printf("  %s config  - Create default configuration file\n", os.Args[0])
	fmt.Printf("  %s version - Show version information\n", os.Args[0])
	fmt.Printf("  %s help    - Show detailed help\n", os.Args[0])
}

// printDetailedHelp displays comprehensive help information
func printDetailedHelp() {
	fmt.Printf("Quantum Anonymous VPN v%d.%d.%d\n", VersionMajor, VersionMinor, VersionPatch)
	fmt.Println("A minimal, quantum-resistant VPN with multi-hop routing and traffic analysis resistance.")
	fmt.Println()
	fmt.Println("COMMANDS:")
	fmt.Println("  start    Start VPN client mode")
	fmt.Println("    -port <port>     Client listening port (default: 9050)")
	fmt.Println("    -hops <number>   Number of relay hops (3-5, default: 3)")
	fmt.Println("    -protocol <tcp|udp>  Transport protocol (default: tcp)")
	fmt.Println("    -verbose         Enable verbose logging")
	fmt.Println()
	fmt.Println("  relay    Start relay node mode")
	fmt.Println("    -port <port>     Relay listening port (default: 9051)")
	fmt.Println("    -protocol <tcp|udp>  Transport protocol (default: tcp)")
	fmt.Println("    -verbose         Enable verbose logging")
	fmt.Println()
	fmt.Println("  direct   Direct connection mode (peer-to-peer)")
	fmt.Println("    listen           Start listener for direct connections")
	fmt.Println("    connect <code>   Connect using invitation code")
	fmt.Println("    invite           Generate invitation code")
	fmt.Println("    status           Show direct connection status")
	fmt.Println("    Use 'qavpn direct help' for detailed direct mode help")
	fmt.Println()
	fmt.Println("  status   Show connection status and statistics")
	fmt.Println("  version  Show version information")
	fmt.Println("  help     Show this help message")
	fmt.Println()
	fmt.Println("CONFIGURATION:")
	fmt.Println("  Configuration file: ~/.qavpn/config")
	fmt.Println("  Command line arguments override config file settings")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Printf("  %s start -hops 4 -protocol udp\n", os.Args[0])
	fmt.Printf("  %s relay -port 9052\n", os.Args[0])
	fmt.Printf("  %s direct listen -port 9053\n", os.Args[0])
	fmt.Printf("  %s direct invite -address 192.168.1.100\n", os.Args[0])
}

// startClient initializes and starts the VPN client
func startClient(config *Config) error {
	fmt.Printf("Client listening on port %d\n", config.ClientPort)
	fmt.Printf("Using %d-hop routing with %s protocol\n", config.DesiredHops, config.Protocol)

	// Initialize post-quantum cryptography
	fmt.Println("Initializing post-quantum cryptography...")
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return fmt.Errorf("failed to initialize PQC: %w", err)
	}
	if config.LogLevel >= 2 {
		fmt.Printf("Generated PQC key pair (public key size: %d bytes)\n", len(localKeyPair.PublicKey))
	}

	// Initialize node manager for client mode
	fmt.Println("Initializing node manager...")
	nodeManager, err := NewNodeManager(false) // false = not a relay
	if err != nil {
		return fmt.Errorf("failed to initialize node manager: %w", err)
	}

	// Discover relay nodes from bootstrap
	fmt.Println("Discovering relay nodes...")
	if err := nodeManager.DiscoverNodes(); err != nil {
		return fmt.Errorf("failed to discover relay nodes: %w", err)
	}

	// Start periodic maintenance
	nodeManager.StartPeriodicMaintenance()
	nodeManager.StartRouteMaintenance()

	// Initialize tunnel manager
	tunnelManager := NewTunnelManager()

	// Establish multi-hop routes
	fmt.Printf("Establishing %d-hop route...\n", config.DesiredHops)
	route, err := nodeManager.SelectRoute("", config.Protocol)
	if err != nil {
		return fmt.Errorf("failed to select route: %w", err)
	}
	
	if config.LogLevel >= 2 {
		fmt.Printf("Selected route with %d hops using %s protocol\n", len(route.Hops), route.Protocol)
		for i, hop := range route.Hops {
			fmt.Printf("  Hop %d: %s (%x)\n", i+1, hop.Address, hop.ID[:4])
		}
	}

	// Initialize secure error handling
	errorHandler := NewSecureErrorHandler()
	recoveryManager := NewAutomaticRecoveryManager(nodeManager, tunnelManager, errorHandler)

	// Initialize secure logging
	logLevel := LogLevel(config.LogLevel)
	logger := NewSecureLogger(logLevel)
	
	// Initialize connection monitoring
	connectionMonitor := NewConnectionMonitor(logger, nodeManager, tunnelManager)

	// Create client state
	clientState := &ClientState{
		Config:            config,
		NodeManager:       nodeManager,
		TunnelManager:     tunnelManager,
		LocalKeyPair:      localKeyPair,
		ActiveRoute:       route,
		IsRunning:         true,
		StartTime:         time.Now(),
		ErrorHandler:      errorHandler,
		RecoveryManager:   recoveryManager,
		Logger:            logger,
		ConnectionMonitor: connectionMonitor,
	}

	fmt.Println("VPN client started successfully")
	fmt.Println("Press Ctrl+C to stop")

	// Start client services
	if err := startClientServices(clientState); err != nil {
		return fmt.Errorf("failed to start client services: %w", err)
	}

	// Main event loop with graceful shutdown
	return runClientEventLoop(clientState)
}

// startRelay initializes and starts a relay node
func startRelay(config *Config) error {
	fmt.Printf("Relay node listening on port %d\n", config.RelayPort)
	fmt.Printf("Protocol support: %s\n", config.Protocol)

	// Initialize post-quantum cryptography
	fmt.Println("Initializing post-quantum cryptography...")
	localKeyPair, err := GenerateKyberKeyPair()
	if err != nil {
		return fmt.Errorf("failed to initialize PQC: %w", err)
	}
	if config.LogLevel >= 2 {
		fmt.Printf("Generated PQC key pair (public key size: %d bytes)\n", len(localKeyPair.PublicKey))
	}

	// Initialize node manager for relay mode
	fmt.Println("Initializing relay node manager...")
	nodeManager, err := NewNodeManager(true) // true = is a relay
	if err != nil {
		return fmt.Errorf("failed to initialize node manager: %w", err)
	}

	// Start relay server
	fmt.Println("Starting relay server...")
	if err := nodeManager.StartRelayServer(config.RelayPort); err != nil {
		return fmt.Errorf("failed to start relay server: %w", err)
	}

	// Register with bootstrap nodes
	fmt.Println("Registering with bootstrap nodes...")
	if err := registerWithBootstrap(nodeManager, config); err != nil {
		fmt.Printf("Warning: Failed to register with bootstrap nodes: %v\n", err)
		// Continue anyway - relay can still function without bootstrap registration
	}

	// Start periodic maintenance
	nodeManager.StartPeriodicMaintenance()
	nodeManager.StartRouteMaintenance()

	// Initialize secure logging for relay
	logLevel := LogLevel(config.LogLevel)
	logger := NewSecureLogger(logLevel)
	
	// Initialize connection monitoring for relay
	connectionMonitor := NewConnectionMonitor(logger, nodeManager, nil) // No tunnel manager for relay

	// Create relay state
	relayState := &RelayState{
		Config:            config,
		NodeManager:       nodeManager,
		LocalKeyPair:      localKeyPair,
		IsRunning:         true,
		StartTime:         time.Now(),
		Statistics:        NewRelayStatistics(),
		Logger:            logger,
		ConnectionMonitor: connectionMonitor,
	}

	fmt.Println("Relay node started successfully")
	fmt.Printf("Relay address: %s\n", nodeManager.localNode.Address)
	fmt.Println("Press Ctrl+C to stop")

	// Start relay services
	if err := startRelayServices(relayState); err != nil {
		return fmt.Errorf("failed to start relay services: %w", err)
	}

	// Main event loop with graceful shutdown
	return runRelayEventLoop(relayState)
}

// showStatus displays current connection status
func showStatus() {
	fmt.Println("Status: Not connected")
	fmt.Println("Active routes: 0")
	fmt.Println("Relay nodes: 0")

	// TODO: Show actual connection status
	// TODO: Display active routes and relay nodes
	// TODO: Show traffic statistics
}
// loadConfig loads configuration from ~/.qavpn/config file
func loadConfig() (*Config, error) {
	config := NewDefaultConfig()
	
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return config, err
	}
	
	configPath := filepath.Join(homeDir, ".qavpn", "config")
	
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Validate default config before returning
		if err := ValidateConfig(config); err != nil {
			return nil, fmt.Errorf("default configuration is invalid: %w", err)
		}
		return config, nil
	}
	
	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}
	
	// Parse simple key=value format
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		switch key {
		case "client_port":
			if port, err := strconv.Atoi(value); err == nil {
				config.ClientPort = port
			}
		case "relay_port":
			if port, err := strconv.Atoi(value); err == nil {
				config.RelayPort = port
			}
		case "desired_hops":
			if hops, err := strconv.Atoi(value); err == nil && hops >= MinRelayHops && hops <= MaxRelayHops {
				config.DesiredHops = hops
			}
		case "protocol":
			if value == "tcp" || value == "udp" {
				config.Protocol = value
			}
		case "log_level":
			if level, err := strconv.Atoi(value); err == nil {
				config.LogLevel = level
			}
		// Direct mode configuration
		case "direct_mode_enabled":
			if enabled, err := strconv.ParseBool(value); err == nil {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.Enabled = enabled
			}
		case "direct_mode_port":
			if port, err := strconv.Atoi(value); err == nil {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.DefaultPort = port
			}
		case "direct_mode_protocol":
			if value == "tcp" || value == "udp" {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.DefaultProtocol = value
			}
		case "direct_mode_max_connections":
			if maxConn, err := strconv.Atoi(value); err == nil {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.MaxConnections = maxConn
			}
		case "direct_mode_connection_timeout":
			if timeout, err := strconv.Atoi(value); err == nil {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.ConnectionTimeout = timeout
			}
		case "direct_mode_keepalive_interval":
			if interval, err := strconv.Atoi(value); err == nil {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.KeepAliveInterval = interval
			}
		case "direct_mode_enable_opsec":
			if opsec, err := strconv.ParseBool(value); err == nil {
				if config.DirectMode == nil {
					config.DirectMode = &DirectModeConfig{}
				}
				config.DirectMode.EnableOPSEC = opsec
			}
		case "direct_mode_config_path":
			if config.DirectMode == nil {
				config.DirectMode = &DirectModeConfig{}
			}
			config.DirectMode.ConfigPath = value
		}
	}
	
	// Migrate configuration if needed
	migratedConfig, err := MigrateConfig(config)
	if err != nil {
		return nil, fmt.Errorf("configuration migration failed: %w", err)
	}
	
	// Validate the final configuration
	if err := ValidateConfig(migratedConfig); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	return migratedConfig, nil
}

// parseStartArgs parses command line arguments for start command
func parseStartArgs(config *Config) error {
	if len(os.Args) <= 2 {
		return nil // No additional arguments
	}
	
	// Create a new flag set for start command
	startFlags := flag.NewFlagSet("start", flag.ContinueOnError)
	startFlags.Usage = func() {
		fmt.Println("Usage: qavpn start [options]")
		fmt.Println("Options:")
		startFlags.PrintDefaults()
	}
	
	port := startFlags.Int("port", config.ClientPort, "Client listening port")
	hops := startFlags.Int("hops", config.DesiredHops, "Number of relay hops (3-5)")
	protocol := startFlags.String("protocol", config.Protocol, "Transport protocol (tcp or udp)")
	verbose := startFlags.Bool("verbose", false, "Enable verbose logging")
	
	// Parse arguments starting from index 2 (after "start")
	if err := startFlags.Parse(os.Args[2:]); err != nil {
		return err
	}
	
	// Validate and apply parsed values
	if *hops < MinRelayHops || *hops > MaxRelayHops {
		return fmt.Errorf("hops must be between %d and %d", MinRelayHops, MaxRelayHops)
	}
	
	if *protocol != "tcp" && *protocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp'")
	}
	
	config.ClientPort = *port
	config.DesiredHops = *hops
	config.Protocol = *protocol
	if *verbose {
		config.LogLevel = 2
	}
	
	return nil
}

// parseRelayArgs parses command line arguments for relay command
func parseRelayArgs(config *Config) error {
	if len(os.Args) <= 2 {
		return nil // No additional arguments
	}
	
	// Create a new flag set for relay command
	relayFlags := flag.NewFlagSet("relay", flag.ContinueOnError)
	relayFlags.Usage = func() {
		fmt.Println("Usage: qavpn relay [options]")
		fmt.Println("Options:")
		relayFlags.PrintDefaults()
	}
	
	port := relayFlags.Int("port", config.RelayPort, "Relay listening port")
	protocol := relayFlags.String("protocol", config.Protocol, "Transport protocol (tcp or udp)")
	verbose := relayFlags.Bool("verbose", false, "Enable verbose logging")
	
	// Parse arguments starting from index 2 (after "relay")
	if err := relayFlags.Parse(os.Args[2:]); err != nil {
		return err
	}
	
	// Validate and apply parsed values
	if *protocol != "tcp" && *protocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp'")
	}
	
	config.RelayPort = *port
	config.Protocol = *protocol
	if *verbose {
		config.LogLevel = 2
	}
	
	return nil
}

// createDefaultConfigFile creates a default configuration file
func createDefaultConfigFile() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	
	configDir := filepath.Join(homeDir, ".qavpn")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}
	
	configPath := filepath.Join(configDir, "config")
	
	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // File already exists
	}
	
	// Create default config content
	defaultConfig := `# QAVPN Configuration File
# Lines starting with # are comments

# Client configuration
client_port=9050
desired_hops=3
protocol=tcp

# Relay configuration  
relay_port=9051

# Direct mode configuration
direct_mode_enabled=false
direct_mode_port=9052
direct_mode_protocol=tcp
direct_mode_max_connections=10
direct_mode_connection_timeout=30
direct_mode_keepalive_interval=60
direct_mode_enable_opsec=true
direct_mode_config_path=~/.qavpn/direct

# Logging (0=quiet, 1=normal, 2=verbose)
log_level=1
`
	
	return os.WriteFile(configPath, []byte(defaultConfig), 0644)
}

// ClientState holds the state of the VPN client
type ClientState struct {
	Config            *Config
	NodeManager       *NodeManager
	TunnelManager     *TunnelManager
	LocalKeyPair      *KyberKeyPair
	ActiveRoute       *Route
	IsRunning         bool
	StartTime         time.Time
	Statistics        *ClientStatistics
	ErrorHandler      *SecureErrorHandler
	RecoveryManager   *AutomaticRecoveryManager
	Logger            *SecureLogger
	ConnectionMonitor *ConnectionMonitor
	mutex             sync.RWMutex
}

// ClientStatistics tracks client performance metrics
type ClientStatistics struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	ConnectionTime  time.Duration
	RouteChanges    uint64
	LastActivity    time.Time
}

// startClientServices starts background services for the client
func startClientServices(state *ClientState) error {
	// Initialize statistics
	state.Statistics = &ClientStatistics{
		LastActivity: time.Now(),
	}

	// Log service startup
	state.Logger.Info("client_services", "Starting client services", map[string]interface{}{
		"client_port": state.Config.ClientPort,
		"protocol": state.Config.Protocol,
		"desired_hops": state.Config.DesiredHops,
	})

	// Start connection monitoring
	state.ConnectionMonitor.Start()

	// Start traffic interception and routing
	if err := startTrafficInterception(state); err != nil {
		state.Logger.Error("client_services", "Failed to start traffic interception", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to start traffic interception: %w", err)
	}

	// Start status monitoring
	go startStatusMonitoring(state)

	// Start connection monitoring with error handling
	go startConnectionMonitoring(state)

	state.Logger.Info("client_services", "All client services started successfully", nil)
	return nil
}

// startTrafficInterception sets up traffic interception and routing through VPN tunnels
func startTrafficInterception(state *ClientState) error {
	// Create a local proxy server to intercept traffic
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", state.Config.ClientPort))
	if err != nil {
		return fmt.Errorf("failed to create proxy listener: %w", err)
	}

	if state.Config.LogLevel >= 2 {
		fmt.Printf("Traffic interception started on port %d\n", state.Config.ClientPort)
	}

	// Start accepting connections in background
	go func() {
		defer listener.Close()
		
		for state.IsRunning {
			conn, err := listener.Accept()
			if err != nil {
				if state.IsRunning {
					fmt.Printf("Failed to accept connection: %v\n", err)
				}
				continue
			}

			// Handle each connection in a separate goroutine
			go handleClientConnection(state, conn)
		}
	}()

	return nil
}

// handleClientConnection processes a single client connection through the VPN
func handleClientConnection(state *ClientState, clientConn net.Conn) {
	defer clientConn.Close()

	if state.Config.LogLevel >= 2 {
		fmt.Printf("New client connection from %s\n", clientConn.RemoteAddr())
	}

	// Use unified traffic routing to select best tunnel
	tunnel, tunnelType, err := establishUnifiedTunnel(state, clientConn)
	if err != nil {
		fmt.Printf("Failed to establish tunnel: %v\n", err)
		return
	}
	defer tunnel.Close()

	if state.Config.LogLevel >= 2 {
		fmt.Printf("Using %s tunnel for connection from %s\n", tunnelType, clientConn.RemoteAddr())
	}

	// Start bidirectional data forwarding
	done := make(chan bool, 2)

	// Forward data from client to tunnel
	go func() {
		defer func() { done <- true }()
		buffer := make([]byte, 4096)
		
		for {
			n, err := clientConn.Read(buffer)
			if err != nil {
				return
			}

			// Add noise packets periodically (only for relay mode)
			if tunnelType == "relay" && shouldInjectNoise() {
				if err := injectNoisePacket(tunnel); err != nil {
					fmt.Printf("Failed to inject noise: %v\n", err)
				}
			}

			// Send data through tunnel
			if err := tunnel.SendData(buffer[:n]); err != nil {
				fmt.Printf("Failed to send data through tunnel: %v\n", err)
				return
			}

			// Update statistics
			state.mutex.Lock()
			state.Statistics.BytesSent += uint64(n)
			state.Statistics.PacketsSent++
			state.Statistics.LastActivity = time.Now()
			state.mutex.Unlock()
		}
	}()

	// Forward data from tunnel to client
	go func() {
		defer func() { done <- true }()
		
		for {
			data, err := tunnel.ReceiveData()
			if err != nil {
				return
			}

			// Filter out noise packets (only relevant for relay mode)
			if tunnelType == "relay" && IsNoisePacket(data) {
				continue // Skip noise packets
			}

			if _, err := clientConn.Write(data); err != nil {
				return
			}

			// Update statistics
			state.mutex.Lock()
			state.Statistics.BytesReceived += uint64(len(data))
			state.Statistics.PacketsReceived++
			state.Statistics.LastActivity = time.Now()
			state.mutex.Unlock()
		}
	}()

	// Wait for either direction to complete
	<-done
}

// establishUnifiedTunnel creates the best available tunnel (direct or relay)
func establishUnifiedTunnel(state *ClientState, clientConn net.Conn) (Tunnel, string, error) {
	// Check if direct mode is enabled and we have active direct connections
	if state.Config.DirectMode != nil && state.Config.DirectMode.Enabled {
		if directTunnel, err := tryEstablishDirectTunnel(state, clientConn); err == nil {
			return directTunnel, "direct", nil
		} else if state.Config.LogLevel >= 2 {
			fmt.Printf("Direct tunnel not available, falling back to relay: %v\n", err)
		}
	}

	// Fall back to relay mode
	relayTunnel, err := establishTunnelThroughRoute(state, state.ActiveRoute)
	if err != nil {
		return nil, "", fmt.Errorf("failed to establish relay tunnel: %w", err)
	}

	return relayTunnel, "relay", nil
}

// tryEstablishDirectTunnel attempts to create a direct tunnel
func tryEstablishDirectTunnel(state *ClientState, clientConn net.Conn) (Tunnel, error) {
	// Get the global direct connection integrator
	integrator := GetGlobalDirectIntegrator()
	if integrator == nil {
		return nil, fmt.Errorf("direct connection integrator not initialized")
	}

	// Check if we have active direct connections
	if !integrator.HasActiveDirectConnections() {
		return nil, fmt.Errorf("no active direct connections available")
	}

	// Get the best available direct tunnel
	directTunnel, err := integrator.GetBestDirectTunnel()
	if err != nil {
		return nil, fmt.Errorf("failed to get direct tunnel: %w", err)
	}

	return directTunnel, nil
}

// establishTunnelThroughRoute creates a tunnel through the specified route
func establishTunnelThroughRoute(state *ClientState, route *Route) (Tunnel, error) {
	if len(route.Hops) == 0 {
		return nil, errors.New("route has no hops")
	}

	// Connect to the first hop in the route
	firstHop := route.Hops[0]
	
	var tunnel Tunnel
	var err error

	if route.Protocol == "tcp" {
		tunnel, err = state.TunnelManager.CreateTCPTunnel(firstHop.Address, 
			time.Duration(ConnectionTimeout)*time.Second)
	} else {
		tunnel, err = state.TunnelManager.CreateUDPTunnel(firstHop.Address, 
			time.Duration(ConnectionTimeout)*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel to first hop: %w", err)
	}

	// TODO: In a full implementation, we would establish the complete multi-hop route
	// For now, we'll use the direct tunnel to the first hop as a simplified version

	return tunnel, nil
}

// Tunnel interface for both TCP and UDP tunnels
type Tunnel interface {
	SendData(data []byte) error
	ReceiveData() ([]byte, error)
	Close() error
	IsActive() bool
}

// Ensure TCPTunnel implements Tunnel interface
var _ Tunnel = (*TCPTunnel)(nil)

// Ensure UDPTunnel implements Tunnel interface  
var _ Tunnel = (*UDPTunnel)(nil)

// shouldInjectNoise determines if a noise packet should be injected
func shouldInjectNoise() bool {
	// Simple probability-based noise injection
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomValue := float64(randomBytes[0]) / 255.0
	return randomValue < NoisePacketRatio
}

// injectNoisePacket sends a noise packet through the tunnel
func injectNoisePacket(tunnel Tunnel) error {
	noisePacket, err := GenerateNoisePacket()
	if err != nil {
		return fmt.Errorf("failed to generate noise packet: %w", err)
	}

	return tunnel.SendData(noisePacket.Data)
}

// startStatusMonitoring starts background status monitoring and reporting
func startStatusMonitoring(state *ClientState) {
	ticker := time.NewTicker(30 * time.Second) // Report status every 30 seconds
	defer ticker.Stop()

	for state.IsRunning {
		select {
		case <-ticker.C:
			reportClientStatus(state)
		}
	}
}

// reportClientStatus reports current client status
func reportClientStatus(state *ClientState) {
	state.mutex.RLock()
	stats := *state.Statistics
	state.mutex.RUnlock()

	uptime := time.Since(state.StartTime)
	
	// Log status using secure logger
	state.Logger.Info("client_status", "Client status report", map[string]interface{}{
		"uptime_seconds": int(uptime.Seconds()),
		"bytes_sent": stats.BytesSent,
		"packets_sent": stats.PacketsSent,
		"bytes_received": stats.BytesReceived,
		"packets_received": stats.PacketsReceived,
		"route_changes": stats.RouteChanges,
	})

	// Also log connection monitor health if available
	if state.ConnectionMonitor != nil && state.ConnectionMonitor.IsHealthy() {
		state.Logger.Info("client_status", "All systems healthy", nil)
	} else if state.ConnectionMonitor != nil {
		healthStatus := state.ConnectionMonitor.GetHealthStatus()
		unhealthyComponents := make([]string, 0)
		for component, health := range healthStatus {
			if health.Status != HealthStatusHealthy {
				unhealthyComponents = append(unhealthyComponents, component)
			}
		}
		state.Logger.Warn("client_status", "Some components unhealthy", map[string]interface{}{
			"unhealthy_components": unhealthyComponents,
		})
	}
}

// startConnectionMonitoring monitors connection health and handles failures
func startConnectionMonitoring(state *ClientState) {
	ticker := time.NewTicker(time.Duration(KeepAliveInterval) * time.Second)
	defer ticker.Stop()

	for state.IsRunning {
		select {
		case <-ticker.C:
			// Check if current route is still healthy
			if !isRouteHealthy(state.ActiveRoute, state.NodeManager) {
				routeError := &SecurityError{
					Type:        ErrorTypeRoute,
					Message:     "route became unhealthy",
					Timestamp:   time.Now(),
					Context:     "connection_monitoring",
					Recoverable: true,
					SensitiveData: false,
				}

				// Handle the route failure with secure error handling
				if err := state.ErrorHandler.HandleError(routeError, "route_health_check"); err != nil {
					fmt.Printf("Route health check failed: %v\n", err)
					
					// Attempt automatic recovery
					newRoute, newTunnel, recoveryErr := state.RecoveryManager.RecoverFromFailure(
						state.ActiveRoute, routeError, "route_health_failure")
					
					if recoveryErr != nil {
						fmt.Printf("Automatic recovery failed: %v\n", recoveryErr)
						continue
					}

					// Update active route with recovered route
					state.mutex.Lock()
					state.ActiveRoute = newRoute
					state.Statistics.RouteChanges++
					state.mutex.Unlock()

					if state.Config.LogLevel >= 1 {
						fmt.Printf("Automatically recovered with new %d-hop route\n", len(newRoute.Hops))
					}

					// Close the new tunnel since we're just doing route selection here
					if newTunnel != nil {
						newTunnel.Close()
					}
				}
			}

			// Perform tunnel maintenance with error handling
			if err := performSecureTunnelMaintenance(state); err != nil {
				state.ErrorHandler.HandleError(err, "tunnel_maintenance")
			}

		case <-state.ErrorHandler.GetShutdownChannel():
			// Emergency shutdown requested
			fmt.Println("Emergency shutdown requested by error handler")
			state.mutex.Lock()
			state.IsRunning = false
			state.mutex.Unlock()
			return
		}
	}
}

// isRouteHealthy checks if a route is still healthy
func isRouteHealthy(route *Route, nodeManager *NodeManager) bool {
	if !route.Active {
		return false
	}

	// Check if all hops are still available
	availableNodes := nodeManager.GetAvailableNodes()
	nodeMap := make(map[NodeID]bool)
	for _, node := range availableNodes {
		nodeMap[node.ID] = true
	}

	for _, hop := range route.Hops {
		if !nodeMap[hop.ID] {
			return false
		}
	}

	return true
}

// runClientEventLoop runs the main client event loop with graceful shutdown
func runClientEventLoop(state *ClientState) error {
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down VPN client...")

	// Stop client
	state.mutex.Lock()
	state.IsRunning = false
	state.mutex.Unlock()

	// Close all tunnels
	if err := state.TunnelManager.CloseAllTunnels(); err != nil {
		fmt.Printf("Error closing tunnels: %v\n", err)
	}

	// Stop relay server if running
	if err := state.NodeManager.StopRelayServer(); err != nil {
		fmt.Printf("Error stopping relay server: %v\n", err)
	}

	// Print final statistics
	printFinalStatistics(state)

	fmt.Println("VPN client stopped")
	return nil
}

// printFinalStatistics prints final client statistics
func printFinalStatistics(state *ClientState) {
	state.mutex.RLock()
	stats := *state.Statistics
	state.mutex.RUnlock()

	uptime := time.Since(state.StartTime)
	fmt.Printf("\nFinal Statistics:\n")
	fmt.Printf("  Uptime: %v\n", uptime.Round(time.Second))
	fmt.Printf("  Data sent: %d bytes (%d packets)\n", stats.BytesSent, stats.PacketsSent)
	fmt.Printf("  Data received: %d bytes (%d packets)\n", stats.BytesReceived, stats.PacketsReceived)
	fmt.Printf("  Route changes: %d\n", stats.RouteChanges)
	
	if stats.BytesSent > 0 || stats.BytesReceived > 0 {
		totalBytes := stats.BytesSent + stats.BytesReceived
		avgThroughput := float64(totalBytes) / uptime.Seconds()
		fmt.Printf("  Average throughput: %.2f bytes/sec\n", avgThroughput)
	}
}

// RelayState holds the state of the relay node
type RelayState struct {
	Config            *Config
	NodeManager       *NodeManager
	LocalKeyPair      *KyberKeyPair
	IsRunning         bool
	StartTime         time.Time
	Statistics        *RelayStatistics
	Logger            *SecureLogger
	ConnectionMonitor *ConnectionMonitor
	mutex             sync.RWMutex
}

// Note: RelayStatistics is defined in node.go

// registerWithBootstrap registers this relay node with bootstrap nodes
func registerWithBootstrap(nodeManager *NodeManager, config *Config) error {
	registrationCount := 0
	
	for _, bootstrapAddr := range BootstrapNodes {
		if err := registerWithSingleBootstrap(nodeManager, bootstrapAddr, config); err != nil {
			fmt.Printf("Failed to register with bootstrap %s: %v\n", bootstrapAddr, err)
			continue
		}
		registrationCount++
	}

	if registrationCount == 0 {
		return errors.New("failed to register with any bootstrap nodes")
	}

	fmt.Printf("Successfully registered with %d bootstrap nodes\n", registrationCount)
	return nil
}

// registerWithSingleBootstrap registers with a single bootstrap node
func registerWithSingleBootstrap(nodeManager *NodeManager, bootstrapAddr string, config *Config) error {
	// Connect to bootstrap node
	conn, err := net.DialTimeout("tcp", bootstrapAddr, time.Duration(NodeDiscoveryTimeout)*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to bootstrap: %w", err)
	}
	defer conn.Close()

	// Create registration message
	registrationMsg := NodeDiscoveryMessage{
		Type:      "register",
		NodeID:    nodeManager.localNode.ID,
		Address:   nodeManager.localNode.Address,
		Protocol:  nodeManager.localNode.Protocol,
		PublicKey: nodeManager.localNode.PublicKey,
		Timestamp: time.Now().Unix(),
	}

	// Send registration request
	if err := nodeManager.sendDiscoveryMessage(conn, &registrationMsg); err != nil {
		return fmt.Errorf("failed to send registration message: %w", err)
	}

	// Receive acknowledgment
	responseMsg, err := nodeManager.receiveDiscoveryMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive registration response: %w", err)
	}

	if responseMsg.Type != "registered" {
		return fmt.Errorf("registration failed: %s", responseMsg.Type)
	}

	return nil
}

// startRelayServices starts background services for the relay node
func startRelayServices(state *RelayState) error {
	// Statistics are already initialized in NewRelayStatistics()

	// Start relay health monitoring
	go startRelayHealthMonitoring(state)

	// Start relay statistics reporting
	go startRelayStatisticsReporting(state)

	// Start periodic cleanup
	go startRelayCleanup(state)

	return nil
}

// startRelayHealthMonitoring monitors relay node health
func startRelayHealthMonitoring(state *RelayState) {
	ticker := time.NewTicker(time.Duration(KeepAliveInterval) * time.Second)
	defer ticker.Stop()

	for state.IsRunning {
		select {
		case <-ticker.C:
			// Check relay server health
			relayStats := state.NodeManager.GetRelayStats()
			
			if state.Config.LogLevel >= 2 {
				fmt.Printf("Relay health check: %d active connections\n", 
					relayStats["active_connections"])
			}

			// Update statistics
			state.mutex.Lock()
			if activeConns, ok := relayStats["active_connections"].(int); ok {
				state.Statistics.ActiveConnections = activeConns
			}
			state.mutex.Unlock()

			// Perform node health checks
			state.NodeManager.CheckNodeHealth()
		}
	}
}

// startRelayStatisticsReporting reports relay statistics periodically
func startRelayStatisticsReporting(state *RelayState) {
	ticker := time.NewTicker(5 * time.Minute) // Report every 5 minutes
	defer ticker.Stop()

	for state.IsRunning {
		select {
		case <-ticker.C:
			if state.Config.LogLevel >= 1 {
				reportRelayStatistics(state)
			}
		}
	}
}

// reportRelayStatistics reports current relay statistics
func reportRelayStatistics(state *RelayState) {
	state.mutex.RLock()
	stats := *state.Statistics
	state.mutex.RUnlock()

	uptime := time.Since(state.StartTime)
	fmt.Printf("Relay Stats: Uptime: %v | Forwarded: %d packets (%d bytes) | Active: %d connections | Total: %d connections\n",
		uptime.Round(time.Second), stats.PacketsForwarded, stats.BytesForwarded,
		stats.ActiveConnections, stats.TotalConnections)
	
	if stats.ErrorCount > 0 {
		fmt.Printf("  Forwarding errors: %d\n", stats.ErrorCount)
	}
}

// startRelayCleanup performs periodic cleanup of relay resources
func startRelayCleanup(state *RelayState) {
	ticker := time.NewTicker(10 * time.Minute) // Cleanup every 10 minutes
	defer ticker.Stop()

	for state.IsRunning {
		select {
		case <-ticker.C:
			// Perform route maintenance
			state.NodeManager.MaintainRoutes()

			// Clean up stale connections
			performRelayCleanup(state)
		}
	}
}

// performRelayCleanup cleans up stale relay resources
func performRelayCleanup(state *RelayState) {
	if state.Config.LogLevel >= 2 {
		fmt.Println("Performing relay cleanup...")
	}

	// Get current relay stats before cleanup
	beforeStats := state.NodeManager.GetRelayStats()
	
	// The actual cleanup is handled by the NodeManager's maintenance routines
	// This function serves as a coordination point for cleanup activities
	
	// Update cleanup statistics
	state.mutex.Lock()
	if activeConns, ok := beforeStats["active_connections"].(int); ok {
		state.Statistics.ActiveConnections = activeConns
	}
	state.mutex.Unlock()
}

// runRelayEventLoop runs the main relay event loop with graceful shutdown
func runRelayEventLoop(state *RelayState) error {
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down relay node...")

	// Stop relay
	state.mutex.Lock()
	state.IsRunning = false
	state.mutex.Unlock()

	// Stop relay server
	if err := state.NodeManager.StopRelayServer(); err != nil {
		fmt.Printf("Error stopping relay server: %v\n", err)
	}

	// Print final statistics
	printFinalRelayStatistics(state)

	fmt.Println("Relay node stopped")
	return nil
}

// printFinalRelayStatistics prints final relay statistics
func printFinalRelayStatistics(state *RelayState) {
	state.mutex.RLock()
	stats := *state.Statistics
	state.mutex.RUnlock()

	uptime := time.Since(state.StartTime)
	fmt.Printf("\nFinal Relay Statistics:\n")
	fmt.Printf("  Uptime: %v\n", uptime.Round(time.Second))
	fmt.Printf("  Packets forwarded: %d (%d bytes)\n", stats.PacketsForwarded, stats.BytesForwarded)
	fmt.Printf("  Total connections handled: %d\n", stats.TotalConnections)
	fmt.Printf("  Forwarding errors: %d\n", stats.ErrorCount)
	
	if stats.PacketsForwarded > 0 {
		avgPacketSize := float64(stats.BytesForwarded) / float64(stats.PacketsForwarded)
		packetsPerSecond := float64(stats.PacketsForwarded) / uptime.Seconds()
		fmt.Printf("  Average packet size: %.2f bytes\n", avgPacketSize)
		fmt.Printf("  Average forwarding rate: %.2f packets/sec\n", packetsPerSecond)
	}
	
	if uptime.Hours() > 0 {
		connectionsPerHour := float64(stats.TotalConnections) / uptime.Hours()
		fmt.Printf("  Average connections per hour: %.2f\n", connectionsPerHour)
	}
}
// performSecureTunnelMaintenance performs tunnel maintenance with secure error handling
func performSecureTunnelMaintenance(state *ClientState) error {
	// Perform regular tunnel maintenance
	state.TunnelManager.MaintainTunnels()
	
	// Check for any tunnel errors and handle them securely
	activeTunnels := state.TunnelManager.GetActiveTunnels()
	
	for _, tunnelStats := range activeTunnels {
		// Check if tunnel has been inactive for too long
		if time.Since(tunnelStats.LastActivity) > time.Duration(KeepAliveInterval*3)*time.Second {
			// Create a connection error for inactive tunnel
			connError := &SecurityError{
				Type:        ErrorTypeConnection,
				Message:     "tunnel inactive for extended period",
				Timestamp:   time.Now(),
				Context:     fmt.Sprintf("tunnel_%s", tunnelStats.RemoteAddr),
				Recoverable: true,
				SensitiveData: false,
			}
			
			// Handle the error through secure error handler
			if err := state.ErrorHandler.HandleError(connError, "tunnel_maintenance"); err != nil {
				return fmt.Errorf("tunnel maintenance error: %w", err)
			}
		}
	}
	
	return nil
}

// startIntegratedClient starts the VPN client using the integrated system
func startIntegratedClient(config *Config) error {
	// Create system integration
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		return fmt.Errorf("failed to create system integration: %w", err)
	}

	// Start the integrated system
	if err := systemIntegration.StartSystem(); err != nil {
		return fmt.Errorf("failed to start integrated system: %w", err)
	}

	fmt.Println("Integrated VPN client started successfully")
	fmt.Println("Press Ctrl+C to stop")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down integrated VPN client...")

	// Stop the integrated system
	if err := systemIntegration.StopSystem(); err != nil {
		fmt.Printf("Error during shutdown: %v\n", err)
	}

	fmt.Println("Integrated VPN client stopped")
	return nil
}

// startIntegratedRelay starts the relay node using the integrated system
func startIntegratedRelay(config *Config) error {
	// Create system integration
	systemIntegration, err := NewSystemIntegration(config)
	if err != nil {
		return fmt.Errorf("failed to create system integration: %w", err)
	}

	// Start the integrated system
	if err := systemIntegration.StartSystem(); err != nil {
		return fmt.Errorf("failed to start integrated system: %w", err)
	}

	fmt.Println("Integrated relay node started successfully")
	fmt.Printf("System status: %+v\n", systemIntegration.GetSystemStatus())
	fmt.Println("Press Ctrl+C to stop")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down integrated relay node...")

	// Stop the integrated system
	if err := systemIntegration.StopSystem(); err != nil {
		fmt.Printf("Error during shutdown: %v\n", err)
	}

	fmt.Println("Integrated relay node stopped")
	return nil
}

// showIntegratedStatus displays comprehensive system status
func showIntegratedStatus() {
	fmt.Println("QAVPN System Status")
	fmt.Println("==================")
	
	// Try to connect to a running instance to get status
	// For now, show basic information
	fmt.Println("Status: No running instance detected")
	fmt.Println("To start QAVPN:")
	fmt.Println("  Client mode: qavpn start")
	fmt.Println("  Relay mode:  qavpn relay")
	fmt.Println()
	fmt.Println("Configuration:")
	
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("  Error loading config: %v\n", err)
		return
	}
	
	fmt.Printf("  Client port: %d\n", config.ClientPort)
	fmt.Printf("  Relay port: %d\n", config.RelayPort)
	fmt.Printf("  Protocol: %s\n", config.Protocol)
	fmt.Printf("  Desired hops: %d\n", config.DesiredHops)
	fmt.Printf("  Log level: %d\n", config.LogLevel)
}
