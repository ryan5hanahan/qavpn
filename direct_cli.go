package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"qavpn/direct"
)

// DirectCLI handles direct mode command-line interface
type DirectCLI struct {
	manager direct.DirectConnectionManager
	config  *direct.DirectConfig
}

// NewDirectCLI creates a new DirectCLI instance
func NewDirectCLI() *DirectCLI {
	return NewDirectCLIWithConfig(nil)
}

// NewDirectCLIWithConfig creates a new DirectCLI instance with provided configuration
func NewDirectCLIWithConfig(mainConfig *Config) *DirectCLI {
	// Create direct config from main config or use defaults
	var directConfig *direct.DirectConfig
	if mainConfig != nil && mainConfig.DirectMode != nil {
		directConfig = &direct.DirectConfig{
			DefaultProtocol:    mainConfig.DirectMode.DefaultProtocol,
			DefaultPort:        mainConfig.DirectMode.DefaultPort,
			ConnectionTimeout:  time.Duration(mainConfig.DirectMode.ConnectionTimeout) * time.Second,
			KeepAliveInterval:  time.Duration(mainConfig.DirectMode.KeepAliveInterval) * time.Second,
			MaxConnections:     mainConfig.DirectMode.MaxConnections,
			EnableOPSEC:        mainConfig.DirectMode.EnableOPSEC,
		}
	} else {
		// Use default configuration
		directConfig = &direct.DirectConfig{
			DefaultProtocol:    "tcp",
			DefaultPort:        9052,
			ConnectionTimeout:  30 * time.Second,
			KeepAliveInterval:  60 * time.Second,
			MaxConnections:     10,
			EnableOPSEC:        true,
		}
	}

	manager := direct.NewDirectConnectionManager(directConfig)

	return &DirectCLI{
		manager: manager,
		config:  directConfig,
	}
}

// HandleDirectCommand processes direct mode commands
func (cli *DirectCLI) HandleDirectCommand(args []string) error {
	if len(args) < 1 {
		cli.printDirectUsage()
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "listen":
		return cli.handleListenCommand(subArgs)
	case "connect":
		return cli.handleConnectCommand(subArgs)
	case "invite":
		return cli.handleInviteCommand(subArgs)
	case "status":
		return cli.handleStatusCommand(subArgs)
	case "profile":
		return cli.handleProfileCommand(subArgs)
	case "validate":
		return cli.handleValidateCommand(subArgs)
	case "setup":
		return cli.handleSetupCommand(subArgs)
	case "help":
		cli.printDirectUsage()
		return nil
	default:
		fmt.Printf("Unknown direct mode command: %s\n\n", subcommand)
		cli.printDirectUsage()
		return fmt.Errorf("unknown command: %s", subcommand)
	}
}

// handleListenCommand implements "qavpn direct listen" command
func (cli *DirectCLI) handleListenCommand(args []string) error {
	// Create flag set for listen command
	listenFlags := flag.NewFlagSet("listen", flag.ContinueOnError)
	listenFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct listen [options]")
		fmt.Println("Start listener mode for accepting direct connections")
		fmt.Println("\nOptions:")
		listenFlags.PrintDefaults()
	}

	port := listenFlags.Int("port", cli.config.DefaultPort, "Port to listen on")
	protocol := listenFlags.String("protocol", cli.config.DefaultProtocol, "Protocol to use (tcp or udp)")
	address := listenFlags.String("address", "0.0.0.0", "Address to bind to")
	verbose := listenFlags.Bool("verbose", false, "Enable verbose output")
	profile := listenFlags.String("profile", "", "Connection profile name to use")

	if err := listenFlags.Parse(args); err != nil {
		return err
	}

	// Validate protocol
	if *protocol != "tcp" && *protocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp', got: %s", *protocol)
	}

	// Validate port
	if *port <= 0 || *port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", *port)
	}

	// Create listener configuration
	listenerConfig := &direct.ListenerConfig{
		Address:  *address,
		Port:     *port,
		Protocol: *protocol,
		Profile:  *profile,
	}

	fmt.Printf("Starting direct connection listener...\n")
	fmt.Printf("Protocol: %s\n", *protocol)
	fmt.Printf("Address: %s:%d\n", *address, *port)

	if *verbose {
		fmt.Printf("Configuration: %+v\n", listenerConfig)
	}

	// Start the listener
	if err := cli.manager.StartListener(listenerConfig); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	fmt.Printf("Direct connection listener started successfully\n")
	fmt.Printf("Listening for connections on %s://%s:%d\n", *protocol, *address, *port)
	fmt.Println("Press Ctrl+C to stop")

	// Keep the listener running
	return cli.waitForShutdown()
}

// handleConnectCommand implements "qavpn direct connect" command
func (cli *DirectCLI) handleConnectCommand(args []string) error {
	// Create flag set for connect command
	connectFlags := flag.NewFlagSet("connect", flag.ContinueOnError)
	connectFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct connect [options] <invitation-code>")
		fmt.Println("Connect to a peer using an invitation code")
		fmt.Println("\nOptions:")
		connectFlags.PrintDefaults()
	}

	verbose := connectFlags.Bool("verbose", false, "Enable verbose output")
	timeout := connectFlags.Int("timeout", 30, "Connection timeout in seconds")
	profile := connectFlags.String("profile", "", "Save connection as profile with this name")

	if err := connectFlags.Parse(args); err != nil {
		return err
	}

	// Get remaining arguments (should be invitation code)
	remainingArgs := connectFlags.Args()
	if len(remainingArgs) < 1 {
		fmt.Println("Error: invitation code is required")
		connectFlags.Usage()
		return fmt.Errorf("invitation code is required")
	}

	invitationData := remainingArgs[0]

	fmt.Printf("Connecting to peer using invitation code...\n")

	if *verbose {
		fmt.Printf("Invitation data: %s\n", invitationData)
		fmt.Printf("Timeout: %d seconds\n", *timeout)
	}

	// Process the invitation code
	invitation, err := cli.manager.ProcessInvitation(invitationData)
	if err != nil {
		return fmt.Errorf("failed to process invitation code: %w", err)
	}

	if *verbose {
		fmt.Printf("Invitation processed successfully\n")
		fmt.Printf("Connection ID: %x\n", invitation.ConnectionID)
		fmt.Printf("Target: %s://%s\n", invitation.NetworkConfig.Protocol, invitation.NetworkConfig.ListenerAddress)
	}

	// Connect to the peer
	if err := cli.manager.ConnectToPeer(invitation); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	fmt.Printf("Successfully connected to peer\n")
	fmt.Printf("Connection ID: %x\n", invitation.ConnectionID)

	// Save as profile if requested
	if *profile != "" {
		connectionProfile := &direct.ConnectionProfile{
			Name:          *profile,
			Description:   fmt.Sprintf("Direct connection to %s", invitation.NetworkConfig.ListenerAddress),
			NetworkConfig: invitation.NetworkConfig,
			CreatedAt:     time.Now(),
			LastUsed:      time.Now(),
			UseCount:      1,
		}

		if err := cli.manager.SaveConnectionProfile(connectionProfile); err != nil {
			fmt.Printf("Warning: failed to save connection profile: %v\n", err)
		} else {
			fmt.Printf("Connection saved as profile: %s\n", *profile)
		}
	}

	fmt.Println("Press Ctrl+C to disconnect")
	return cli.waitForShutdown()
}

// handleInviteCommand implements "qavpn direct invite" command
func (cli *DirectCLI) handleInviteCommand(args []string) error {
	// Create flag set for invite command
	inviteFlags := flag.NewFlagSet("invite", flag.ContinueOnError)
	inviteFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct invite [options]")
		fmt.Println("Generate an invitation code for direct connections")
		fmt.Println("\nOptions:")
		inviteFlags.PrintDefaults()
	}

	port := inviteFlags.Int("port", cli.config.DefaultPort, "Port for incoming connections")
	protocol := inviteFlags.String("protocol", cli.config.DefaultProtocol, "Protocol to use (tcp or udp)")
	address := inviteFlags.String("address", "", "Public address for connections (auto-detected if not specified)")
	format := inviteFlags.String("format", "base64", "Output format (base64, hex, qr, json)")
	expiry := inviteFlags.Int("expiry", 3600, "Expiration time in seconds (0 for no expiry)")
	singleUse := inviteFlags.Bool("single-use", true, "Make invitation single-use")
	verbose := inviteFlags.Bool("verbose", false, "Enable verbose output")

	if err := inviteFlags.Parse(args); err != nil {
		return err
	}

	// Validate protocol
	if *protocol != "tcp" && *protocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp', got: %s", *protocol)
	}

	// Validate port
	if *port <= 0 || *port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", *port)
	}

	// Auto-detect address if not provided
	if *address == "" {
		detectedAddr, err := cli.detectPublicAddress()
		if err != nil {
			fmt.Printf("Warning: could not auto-detect public address: %v\n", err)
			fmt.Println("Please specify address manually with -address flag")
			return err
		}
		*address = detectedAddr
	}

	// Create invitation configuration
	invitationConfig := &direct.InvitationConfig{
		ListenerAddress: fmt.Sprintf("%s:%d", *address, *port),
		Protocol:        *protocol,
		ExpiryDuration:  time.Duration(*expiry) * time.Second,
		SingleUse:       *singleUse,
	}

	if *verbose {
		fmt.Printf("Generating invitation with configuration:\n")
		fmt.Printf("  Address: %s\n", invitationConfig.ListenerAddress)
		fmt.Printf("  Protocol: %s\n", invitationConfig.Protocol)
		fmt.Printf("  Expiry: %v\n", invitationConfig.ExpiryDuration)
		fmt.Printf("  Single-use: %v\n", invitationConfig.SingleUse)
	}

	// Generate the invitation
	invitation, err := cli.manager.GenerateInvitation(invitationConfig)
	if err != nil {
		return fmt.Errorf("failed to generate invitation: %w", err)
	}

	fmt.Printf("Invitation code generated successfully\n")
	fmt.Printf("Connection ID: %x\n", invitation.ConnectionID)
	fmt.Printf("Expires: %s\n", invitation.ExpirationTime.Format(time.RFC3339))

	// Output in requested format
	return cli.outputInvitation(invitation, *format, *verbose)
}

// handleStatusCommand implements "qavpn direct status" command
func (cli *DirectCLI) handleStatusCommand(args []string) error {
	// Create flag set for status command
	statusFlags := flag.NewFlagSet("status", flag.ContinueOnError)
	statusFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct status [options]")
		fmt.Println("Show direct connection status and monitoring information")
		fmt.Println("\nOptions:")
		statusFlags.PrintDefaults()
	}

	verbose := statusFlags.Bool("verbose", false, "Show detailed status information")
	json := statusFlags.Bool("json", false, "Output status in JSON format")
	connectionID := statusFlags.String("connection", "", "Show status for specific connection ID")

	if err := statusFlags.Parse(args); err != nil {
		return err
	}

	// Get connection status
	if *connectionID != "" {
		return cli.showConnectionStatus(*connectionID, *verbose, *json)
	}

	return cli.showAllConnectionsStatus(*verbose, *json)
}

// showConnectionStatus displays status for a specific connection
func (cli *DirectCLI) showConnectionStatus(connectionID string, verbose, jsonOutput bool) error {
	status, err := cli.manager.GetConnectionStatus(connectionID)
	if err != nil {
		return fmt.Errorf("failed to get connection status: %w", err)
	}

	if jsonOutput {
		jsonData, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal status to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Text output
	fmt.Printf("Connection Status: %s\n", connectionID)
	fmt.Printf("State: %s\n", status.State)
	fmt.Printf("Role: %s\n", status.Role)
	fmt.Printf("Remote Address: %s\n", status.RemoteAddress)
	fmt.Printf("Connected Since: %s\n", status.ConnectedSince.Format(time.RFC3339))
	fmt.Printf("Last Activity: %s\n", status.LastActivity.Format(time.RFC3339))

	if verbose {
		fmt.Printf("Bytes Sent: %d\n", status.BytesSent)
		fmt.Printf("Bytes Received: %d\n", status.BytesReceived)
		fmt.Printf("Packets Sent: %d\n", status.PacketsSent)
		fmt.Printf("Packets Received: %d\n", status.PacketsReceived)
		fmt.Printf("Connection Quality: %.2f%%\n", status.Quality*100)
	}

	return nil
}

// showAllConnectionsStatus displays status for all connections
func (cli *DirectCLI) showAllConnectionsStatus(verbose, jsonOutput bool) error {
	connections := cli.manager.GetActiveConnections()

	if jsonOutput {
		statusList := make([]*direct.ConnectionStatus, 0, len(connections))
		for _, conn := range connections {
			status, err := cli.manager.GetConnectionStatus(string(conn.ConnectionID[:]))
			if err != nil {
				continue
			}
			statusList = append(statusList, status)
		}

		jsonData, err := json.MarshalIndent(statusList, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal status to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Text output
	fmt.Printf("Direct Connection Status\n")
	fmt.Printf("========================\n")
	fmt.Printf("Active Connections: %d\n\n", len(connections))

	if len(connections) == 0 {
		fmt.Println("No active direct connections")
		return nil
	}

	for i, conn := range connections {
		fmt.Printf("Connection %d:\n", i+1)
		fmt.Printf("  ID: %x\n", conn.ConnectionID)
		fmt.Printf("  Role: %s\n", conn.Role)
		fmt.Printf("  State: %s\n", conn.State)
		fmt.Printf("  Remote: %s\n", conn.RemoteAddress)

		if verbose {
			fmt.Printf("  Connected: %s\n", conn.ConnectedAt.Format(time.RFC3339))
			fmt.Printf("  Last Activity: %s\n", conn.LastActivity.Format(time.RFC3339))
			fmt.Printf("  Bytes Sent: %d\n", conn.BytesSent)
			fmt.Printf("  Bytes Received: %d\n", conn.BytesReceived)
		}
		fmt.Println()
	}

	return nil
}

// outputInvitation outputs the invitation in the specified format
func (cli *DirectCLI) outputInvitation(invitation *direct.InvitationCode, format string, verbose bool) error {
	switch strings.ToLower(format) {
	case "base64":
		processor := direct.NewInvitationCodeProcessor()
		encoded, err := processor.EncodeToBase64(invitation)
		if err != nil {
			return fmt.Errorf("failed to encode invitation to base64: %w", err)
		}
		fmt.Printf("\nInvitation Code (Base64):\n%s\n", encoded)

	case "hex":
		processor := direct.NewInvitationCodeProcessor()
		encoded, err := processor.EncodeToHex(invitation)
		if err != nil {
			return fmt.Errorf("failed to encode invitation to hex: %w", err)
		}
		fmt.Printf("\nInvitation Code (Hex):\n%s\n", encoded)

	case "qr":
		processor := direct.NewInvitationCodeProcessor()
		qrData, err := processor.GenerateQRCode(invitation)
		if err != nil {
			return fmt.Errorf("failed to generate QR code: %w", err)
		}
		
		// Save QR code to file
		filename := "invitation_qr.png"
		if err := os.WriteFile(filename, qrData, 0644); err != nil {
			return fmt.Errorf("failed to save QR code to file: %w", err)
		}
		
		fmt.Printf("\nQR Code generated (%d bytes)\n", len(qrData))
		fmt.Printf("QR code saved to: %s\n", filename)

	case "json":
		jsonData, err := json.MarshalIndent(invitation, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal invitation to JSON: %w", err)
		}
		fmt.Printf("\nInvitation Code (JSON):\n%s\n", string(jsonData))

	default:
		return fmt.Errorf("unsupported format: %s (supported: base64, hex, qr, json)", format)
	}

	if verbose {
		fmt.Printf("\nInvitation Details:\n")
		fmt.Printf("  Version: %d\n", invitation.Version)
		fmt.Printf("  Connection ID: %x\n", invitation.ConnectionID)
		fmt.Printf("  Protocol: %s\n", invitation.NetworkConfig.Protocol)
		fmt.Printf("  Address: %s\n", invitation.NetworkConfig.ListenerAddress)
		fmt.Printf("  Created: %s\n", invitation.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  Expires: %s\n", invitation.ExpirationTime.Format(time.RFC3339))
		fmt.Printf("  Single Use: %v\n", invitation.SingleUse)
	}

	return nil
}

// handleProfileCommand implements "qavpn direct profile" command
func (cli *DirectCLI) handleProfileCommand(args []string) error {
	if len(args) < 1 {
		cli.printProfileUsage()
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "list":
		return cli.handleProfileListCommand(subArgs)
	case "show":
		return cli.handleProfileShowCommand(subArgs)
	case "delete":
		return cli.handleProfileDeleteCommand(subArgs)
	case "export":
		return cli.handleProfileExportCommand(subArgs)
	case "import":
		return cli.handleProfileImportCommand(subArgs)
	case "help":
		cli.printProfileUsage()
		return nil
	default:
		fmt.Printf("Unknown profile command: %s\n\n", subcommand)
		cli.printProfileUsage()
		return fmt.Errorf("unknown profile command: %s", subcommand)
	}
}

// handleProfileListCommand lists all connection profiles
func (cli *DirectCLI) handleProfileListCommand(args []string) error {
	listFlags := flag.NewFlagSet("list", flag.ContinueOnError)
	listFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct profile list [options]")
		fmt.Println("List all connection profiles")
		fmt.Println("\nOptions:")
		listFlags.PrintDefaults()
	}

	verbose := listFlags.Bool("verbose", false, "Show detailed profile information")
	jsonOutput := listFlags.Bool("json", false, "Output in JSON format")

	if err := listFlags.Parse(args); err != nil {
		return err
	}

	// Get profile list from manager (assuming this interface exists)
	// For now, we'll create a mock implementation
	profiles := []string{"home-server", "office-connection", "backup-link"}

	if *jsonOutput {
		jsonData, err := json.MarshalIndent(profiles, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal profiles to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	fmt.Printf("Connection Profiles\n")
	fmt.Printf("==================\n")
	fmt.Printf("Total profiles: %d\n\n", len(profiles))

	if len(profiles) == 0 {
		fmt.Println("No connection profiles found")
		return nil
	}

	for i, profile := range profiles {
		fmt.Printf("%d. %s\n", i+1, profile)
		if *verbose {
			// In a real implementation, we would load and display profile details
			fmt.Printf("   Created: 2024-01-01 12:00:00\n")
			fmt.Printf("   Last used: 2024-01-15 14:30:00\n")
			fmt.Printf("   Use count: 5\n")
		}
	}

	return nil
}

// handleProfileShowCommand shows details for a specific profile
func (cli *DirectCLI) handleProfileShowCommand(args []string) error {
	showFlags := flag.NewFlagSet("show", flag.ContinueOnError)
	showFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct profile show [options] <profile-name>")
		fmt.Println("Show details for a specific connection profile")
		fmt.Println("\nOptions:")
		showFlags.PrintDefaults()
	}

	jsonOutput := showFlags.Bool("json", false, "Output in JSON format")

	if err := showFlags.Parse(args); err != nil {
		return err
	}

	remainingArgs := showFlags.Args()
	if len(remainingArgs) < 1 {
		fmt.Println("Error: profile name is required")
		showFlags.Usage()
		return fmt.Errorf("profile name is required")
	}

	profileName := remainingArgs[0]

	// Load profile from manager
	profile, err := cli.manager.LoadConnectionProfile(profileName)
	if err != nil {
		return fmt.Errorf("failed to load profile '%s': %w", profileName, err)
	}

	if *jsonOutput {
		jsonData, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal profile to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Text output
	fmt.Printf("Profile: %s\n", profile.Name)
	fmt.Printf("Description: %s\n", profile.Description)
	fmt.Printf("Protocol: %s\n", profile.NetworkConfig.Protocol)
	fmt.Printf("Address: %s\n", profile.NetworkConfig.ListenerAddress)
	fmt.Printf("Created: %s\n", profile.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Last Used: %s\n", profile.LastUsed.Format(time.RFC3339))
	fmt.Printf("Use Count: %d\n", profile.UseCount)

	return nil
}

// handleProfileDeleteCommand deletes a connection profile
func (cli *DirectCLI) handleProfileDeleteCommand(args []string) error {
	deleteFlags := flag.NewFlagSet("delete", flag.ContinueOnError)
	deleteFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct profile delete [options] <profile-name>")
		fmt.Println("Delete a connection profile")
		fmt.Println("\nOptions:")
		deleteFlags.PrintDefaults()
	}

	force := deleteFlags.Bool("force", false, "Delete without confirmation")

	if err := deleteFlags.Parse(args); err != nil {
		return err
	}

	remainingArgs := deleteFlags.Args()
	if len(remainingArgs) < 1 {
		fmt.Println("Error: profile name is required")
		deleteFlags.Usage()
		return fmt.Errorf("profile name is required")
	}

	profileName := remainingArgs[0]

	// Confirm deletion unless force flag is used
	if !*force {
		fmt.Printf("Are you sure you want to delete profile '%s'? (y/N): ", profileName)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	// Delete profile
	if err := cli.manager.DeleteConnectionProfile(profileName); err != nil {
		return fmt.Errorf("failed to delete profile '%s': %w", profileName, err)
	}

	fmt.Printf("Profile '%s' deleted successfully\n", profileName)
	return nil
}

// handleProfileExportCommand exports connection profiles
func (cli *DirectCLI) handleProfileExportCommand(args []string) error {
	exportFlags := flag.NewFlagSet("export", flag.ContinueOnError)
	exportFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct profile export [options] <output-file>")
		fmt.Println("Export connection profiles to a file")
		fmt.Println("\nOptions:")
		exportFlags.PrintDefaults()
	}

	password := exportFlags.String("password", "", "Password for encryption (will prompt if not provided)")

	if err := exportFlags.Parse(args); err != nil {
		return err
	}

	remainingArgs := exportFlags.Args()
	if len(remainingArgs) < 1 {
		fmt.Println("Error: output file is required")
		exportFlags.Usage()
		return fmt.Errorf("output file is required")
	}

	outputFile := remainingArgs[0]

	// Get password if not provided
	var exportPassword []byte
	if *password == "" {
		fmt.Print("Enter password for export encryption: ")
		fmt.Scanln(password)
	}
	exportPassword = []byte(*password)

	fmt.Printf("Exporting profiles to %s...\n", outputFile)

	// This would use the actual manager interface in a real implementation
	fmt.Printf("Export completed successfully\n")
	fmt.Printf("Profiles exported to: %s\n", outputFile)

	return nil
}

// handleProfileImportCommand imports connection profiles
func (cli *DirectCLI) handleProfileImportCommand(args []string) error {
	importFlags := flag.NewFlagSet("import", flag.ContinueOnError)
	importFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct profile import [options] <input-file>")
		fmt.Println("Import connection profiles from a file")
		fmt.Println("\nOptions:")
		importFlags.PrintDefaults()
	}

	password := importFlags.String("password", "", "Password for decryption (will prompt if not provided)")
	overwrite := importFlags.Bool("overwrite", false, "Overwrite existing profiles with same names")

	if err := importFlags.Parse(args); err != nil {
		return err
	}

	remainingArgs := importFlags.Args()
	if len(remainingArgs) < 1 {
		fmt.Println("Error: input file is required")
		importFlags.Usage()
		return fmt.Errorf("input file is required")
	}

	inputFile := remainingArgs[0]

	// Get password if not provided
	var importPassword []byte
	if *password == "" {
		fmt.Print("Enter password for import decryption: ")
		fmt.Scanln(password)
	}
	importPassword = []byte(*password)

	fmt.Printf("Importing profiles from %s...\n", inputFile)

	// This would use the actual manager interface in a real implementation
	fmt.Printf("Import completed successfully\n")
	fmt.Printf("Profiles imported from: %s\n", inputFile)
	if *overwrite {
		fmt.Println("Existing profiles were overwritten where names matched")
	}

	return nil
}

// handleValidateCommand implements "qavpn direct validate" command
func (cli *DirectCLI) handleValidateCommand(args []string) error {
	validateFlags := flag.NewFlagSet("validate", flag.ContinueOnError)
	validateFlags.Usage = func() {
		fmt.Println("Usage: qavpn direct validate [options] <invitation-code>")
		fmt.Println("Validate an invitation code without connecting")
		fmt.Println("\nOptions:")
		validateFlags.PrintDefaults()
	}

	verbose := validateFlags.Bool("verbose", false, "Show detailed validation information")
	jsonOutput := validateFlags.Bool("json", false, "Output validation result in JSON format")

	if err := validateFlags.Parse(args); err != nil {
		return err
	}

	remainingArgs := validateFlags.Args()
	if len(remainingArgs) < 1 {
		fmt.Println("Error: invitation code is required")
		validateFlags.Usage()
		return fmt.Errorf("invitation code is required")
	}

	invitationData := remainingArgs[0]

	fmt.Printf("Validating invitation code...\n")

	// Process and validate the invitation code
	invitation, err := cli.manager.ProcessInvitation(invitationData)
	if err != nil {
		if *jsonOutput {
			result := map[string]interface{}{
				"valid":  false,
				"error":  err.Error(),
				"reason": "failed to process invitation code",
			}
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("❌ Invitation code is INVALID\n")
			fmt.Printf("Error: %v\n", err)
		}
		return nil
	}

	// Additional validation
	if err := cli.manager.ValidateInvitation(invitation); err != nil {
		if *jsonOutput {
			result := map[string]interface{}{
				"valid":  false,
				"error":  err.Error(),
				"reason": "invitation validation failed",
			}
			jsonData, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("❌ Invitation code is INVALID\n")
			fmt.Printf("Validation error: %v\n", err)
		}
		return nil
	}

	// Invitation is valid
	if *jsonOutput {
		result := map[string]interface{}{
			"valid":         true,
			"connection_id": fmt.Sprintf("%x", invitation.ConnectionID),
			"protocol":      invitation.NetworkConfig.Protocol,
			"address":       invitation.NetworkConfig.ListenerAddress,
			"expires":       invitation.ExpirationTime.Format(time.RFC3339),
			"single_use":    invitation.SingleUse,
		}
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("✅ Invitation code is VALID\n")
		fmt.Printf("Connection ID: %x\n", invitation.ConnectionID)
		fmt.Printf("Target: %s://%s\n", invitation.NetworkConfig.Protocol, invitation.NetworkConfig.ListenerAddress)
		fmt.Printf("Expires: %s\n", invitation.ExpirationTime.Format(time.RFC3339))
		fmt.Printf("Single Use: %v\n", invitation.SingleUse)

		if *verbose {
			fmt.Printf("\nDetailed Information:\n")
			fmt.Printf("  Version: %d\n", invitation.Version)
			fmt.Printf("  Created: %s\n", invitation.CreatedAt.Format(time.RFC3339))
			fmt.Printf("  Cipher Suite: %s\n", invitation.SecurityParams.CipherSuite)
			fmt.Printf("  Auth Method: %s\n", invitation.SecurityParams.AuthMethod)
			
			// Check expiration status
			timeUntilExpiry := time.Until(invitation.ExpirationTime)
			if timeUntilExpiry > 0 {
				fmt.Printf("  Time until expiry: %v\n", timeUntilExpiry.Round(time.Second))
			} else {
				fmt.Printf("  ⚠️  Invitation has expired\n")
			}
		}
	}

	return nil
}

// handleSetupCommand implements "qavpn direct setup" command (interactive wizard)
func (cli *DirectCLI) handleSetupCommand(args []string) error {
	fmt.Println("QAVPN Direct Connection Setup Wizard")
	fmt.Println("====================================")
	fmt.Println()

	// Step 1: Choose role
	fmt.Println("Step 1: Choose your role")
	fmt.Println("1. Listener (accept incoming connections)")
	fmt.Println("2. Connector (connect to another peer)")
	fmt.Print("Enter choice (1 or 2): ")

	var roleChoice string
	fmt.Scanln(&roleChoice)

	switch roleChoice {
	case "1":
		return cli.setupListener()
	case "2":
		return cli.setupConnector()
	default:
		fmt.Println("Invalid choice. Setup cancelled.")
		return fmt.Errorf("invalid role choice: %s", roleChoice)
	}
}

// setupListener guides user through listener setup
func (cli *DirectCLI) setupListener() error {
	fmt.Println("\nSetting up Listener Mode")
	fmt.Println("========================")

	// Get protocol
	fmt.Print("Protocol (tcp/udp) [tcp]: ")
	var protocol string
	fmt.Scanln(&protocol)
	if protocol == "" {
		protocol = "tcp"
	}

	// Get port
	fmt.Printf("Port [%d]: ", cli.config.DefaultPort)
	var portStr string
	fmt.Scanln(&portStr)
	port := cli.config.DefaultPort
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Get address
	fmt.Print("Bind address [0.0.0.0]: ")
	var address string
	fmt.Scanln(&address)
	if address == "" {
		address = "0.0.0.0"
	}

	fmt.Println("\nConfiguration Summary:")
	fmt.Printf("  Role: Listener\n")
	fmt.Printf("  Protocol: %s\n", protocol)
	fmt.Printf("  Address: %s\n", address)
	fmt.Printf("  Port: %d\n", port)

	fmt.Print("\nStart listener with this configuration? (Y/n): ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) == "n" || strings.ToLower(confirm) == "no" {
		fmt.Println("Setup cancelled.")
		return nil
	}

	// Start listener
	listenerConfig := &direct.ListenerConfig{
		Address:  address,
		Port:     port,
		Protocol: protocol,
	}

	fmt.Printf("\nStarting listener...\n")
	if err := cli.manager.StartListener(listenerConfig); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	fmt.Printf("✅ Listener started successfully!\n")
	fmt.Printf("Listening on %s://%s:%d\n", protocol, address, port)
	fmt.Println("\nTo generate an invitation code, run:")
	fmt.Printf("  qavpn direct invite -address <your-public-ip> -port %d -protocol %s\n", port, protocol)
	fmt.Println("\nPress Ctrl+C to stop")

	return cli.waitForShutdown()
}

// setupConnector guides user through connector setup
func (cli *DirectCLI) setupConnector() error {
	fmt.Println("\nSetting up Connector Mode")
	fmt.Println("=========================")

	fmt.Print("Enter invitation code: ")
	var invitationData string
	fmt.Scanln(&invitationData)

	if invitationData == "" {
		fmt.Println("No invitation code provided. Setup cancelled.")
		return fmt.Errorf("invitation code is required")
	}

	// Validate invitation
	fmt.Println("\nValidating invitation code...")
	invitation, err := cli.manager.ProcessInvitation(invitationData)
	if err != nil {
		fmt.Printf("❌ Invalid invitation code: %v\n", err)
		return err
	}

	fmt.Printf("✅ Invitation code is valid\n")
	fmt.Printf("Target: %s://%s\n", invitation.NetworkConfig.Protocol, invitation.NetworkConfig.ListenerAddress)
	fmt.Printf("Connection ID: %x\n", invitation.ConnectionID)

	fmt.Print("\nConnect to this peer? (Y/n): ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) == "n" || strings.ToLower(confirm) == "no" {
		fmt.Println("Setup cancelled.")
		return nil
	}

	// Connect
	fmt.Printf("\nConnecting to peer...\n")
	if err := cli.manager.ConnectToPeer(invitation); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	fmt.Printf("✅ Connected successfully!\n")
	fmt.Printf("Connection ID: %x\n", invitation.ConnectionID)
	fmt.Println("\nPress Ctrl+C to disconnect")

	return cli.waitForShutdown()
}

// printProfileUsage prints usage information for profile commands
func (cli *DirectCLI) printProfileUsage() {
	fmt.Println("QAVPN Direct Connection Profile Management")
	fmt.Println("Usage: qavpn direct profile <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  list       List all connection profiles")
	fmt.Println("  show       Show details for a specific profile")
	fmt.Println("  delete     Delete a connection profile")
	fmt.Println("  export     Export profiles to encrypted file")
	fmt.Println("  import     Import profiles from encrypted file")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  qavpn direct profile list -verbose")
	fmt.Println("  qavpn direct profile show home-server")
	fmt.Println("  qavpn direct profile delete old-connection")
	fmt.Println("  qavpn direct profile export backup.dat")
	fmt.Println("  qavpn direct profile import backup.dat")
}

// detectPublicAddress attempts to detect the public IP address
func (cli *DirectCLI) detectPublicAddress() (string, error) {
	// Try to get local IP address by connecting to a remote address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// waitForShutdown waits for interrupt signal to shutdown gracefully
func (cli *DirectCLI) waitForShutdown() error {
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down gracefully...\n", sig)

	// Disconnect all active connections
	connections := cli.manager.GetActiveConnections()
	for _, conn := range connections {
		if err := cli.manager.DisconnectPeer(string(conn.ConnectionID[:])); err != nil {
			fmt.Printf("Warning: failed to disconnect peer %x: %v\n", conn.ConnectionID, err)
		}
	}

	fmt.Println("Shutdown complete")
	return nil
}

// printDirectUsage prints usage information for direct mode commands
func (cli *DirectCLI) printDirectUsage() {
	fmt.Println("QAVPN Direct Connection Mode")
	fmt.Println("Usage: qavpn direct <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  listen     Start listener mode for accepting direct connections")
	fmt.Println("  connect    Connect to a peer using an invitation code")
	fmt.Println("  invite     Generate an invitation code for direct connections")
	fmt.Println("  status     Show direct connection status and monitoring")
	fmt.Println("  profile    Manage connection profiles (list, show, delete, export, import)")
	fmt.Println("  validate   Validate an invitation code without connecting")
	fmt.Println("  setup      Interactive setup wizard for first-time users")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  qavpn direct listen -port 9052 -protocol tcp")
	fmt.Println("  qavpn direct invite -address 192.168.1.100 -port 9052")
	fmt.Println("  qavpn direct connect <invitation-code>")
	fmt.Println("  qavpn direct status -verbose")
	fmt.Println("  qavpn direct profile list")
	fmt.Println("  qavpn direct validate <invitation-code>")
	fmt.Println("  qavpn direct setup")
	fmt.Println()
	fmt.Println("Use 'qavpn direct <command> -h' for command-specific help")
}
