package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand"
	"sync"
	"time"
)

// ErrorType represents different categories of errors in the system
type ErrorType int

const (
	ErrorTypeCrypto ErrorType = iota
	ErrorTypeNetwork
	ErrorTypeProtocol
	ErrorTypeRoute
	ErrorTypeConnection
	ErrorTypeSystem
)

// SecurityError represents a security-sensitive error that requires secure handling
type SecurityError struct {
	Type        ErrorType
	Message     string
	Timestamp   time.Time
	Context     string
	Recoverable bool
	SensitiveData bool // Indicates if error might contain sensitive information
}

// Error implements the error interface
func (se *SecurityError) Error() string {
	if se.SensitiveData {
		// Return generic message for security-sensitive errors
		return fmt.Sprintf("security error occurred at %s", se.Timestamp.Format("15:04:05"))
	}
	return fmt.Sprintf("[%s] %s", se.Context, se.Message)
}

// IsRecoverable returns whether this error can be recovered from
func (se *SecurityError) IsRecoverable() bool {
	return se.Recoverable
}

// SecureErrorHandler manages error handling with security-first approach
type SecureErrorHandler struct {
	errorCounts    map[ErrorType]int
	lastErrors     map[ErrorType]time.Time
	recoveryAttempts map[string]int
	maxRecoveryAttempts int
	mutex          sync.RWMutex
	shutdownChan   chan bool
	isShuttingDown bool
}

// NewSecureErrorHandler creates a new secure error handler
func NewSecureErrorHandler() *SecureErrorHandler {
	return &SecureErrorHandler{
		errorCounts:         make(map[ErrorType]int),
		lastErrors:          make(map[ErrorType]time.Time),
		recoveryAttempts:    make(map[string]int),
		maxRecoveryAttempts: 3,
		shutdownChan:        make(chan bool, 1),
	}
}

// HandleError processes an error with security-first approach
func (seh *SecureErrorHandler) HandleError(err error, context string) error {
	if err == nil {
		return nil
	}

	// Convert to SecurityError if not already
	var secErr *SecurityError
	if se, ok := err.(*SecurityError); ok {
		secErr = se
	} else {
		secErr = seh.classifyError(err, context)
	}

	// Update error statistics
	seh.mutex.Lock()
	seh.errorCounts[secErr.Type]++
	seh.lastErrors[secErr.Type] = time.Now()
	seh.mutex.Unlock()

	// Handle based on error type and severity
	return seh.processSecurityError(secErr)
}

// classifyError converts a regular error into a SecurityError
func (seh *SecureErrorHandler) classifyError(err error, context string) *SecurityError {
	errMsg := err.Error()
	
	// Classify error type based on error message patterns
	var errorType ErrorType
	var recoverable bool
	var sensitiveData bool

	switch {
	case containsAny(errMsg, []string{"crypto", "encrypt", "decrypt", "key", "cipher"}):
		errorType = ErrorTypeCrypto
		recoverable = false // Crypto errors are generally not recoverable
		sensitiveData = true // May contain key material or crypto state
	case containsAny(errMsg, []string{"connection", "dial", "listen", "accept", "read", "write"}):
		errorType = ErrorTypeNetwork
		recoverable = true // Network errors can often be recovered
		sensitiveData = false
	case containsAny(errMsg, []string{"protocol", "handshake", "version", "message"}):
		errorType = ErrorTypeProtocol
		recoverable = true // Protocol errors may be recoverable
		sensitiveData = false
	case containsAny(errMsg, []string{"route", "hop", "node", "relay"}):
		errorType = ErrorTypeRoute
		recoverable = true // Route errors are recoverable by selecting new routes
		sensitiveData = false
	default:
		errorType = ErrorTypeSystem
		recoverable = false // Unknown errors are treated as non-recoverable
		sensitiveData = true // Assume sensitive until proven otherwise
	}

	return &SecurityError{
		Type:        errorType,
		Message:     sanitizeErrorMessage(errMsg, sensitiveData),
		Timestamp:   time.Now(),
		Context:     context,
		Recoverable: recoverable,
		SensitiveData: sensitiveData,
	}
}

// processSecurityError handles a security error based on its type and severity
func (seh *SecureErrorHandler) processSecurityError(secErr *SecurityError) error {
	// Check if we should initiate emergency shutdown
	if seh.shouldEmergencyShutdown(secErr) {
		return seh.initiateEmergencyShutdown(secErr)
	}

	// Attempt recovery if error is recoverable
	if secErr.Recoverable {
		return seh.attemptRecovery(secErr)
	}

	// For non-recoverable errors, perform secure cleanup
	seh.performSecureCleanup(secErr)
	return secErr
}

// shouldEmergencyShutdown determines if an emergency shutdown is required
func (seh *SecureErrorHandler) shouldEmergencyShutdown(secErr *SecurityError) bool {
	seh.mutex.RLock()
	defer seh.mutex.RUnlock()

	// Emergency shutdown conditions
	switch secErr.Type {
	case ErrorTypeCrypto:
		// Any crypto error triggers emergency shutdown to prevent data leakage
		return true
	case ErrorTypeSystem:
		// Multiple system errors in short time period
		if seh.errorCounts[ErrorTypeSystem] >= 3 {
			return true
		}
	case ErrorTypeNetwork:
		// Too many network errors might indicate attack
		if seh.errorCounts[ErrorTypeNetwork] >= 10 {
			lastError := seh.lastErrors[ErrorTypeNetwork]
			if time.Since(lastError) < 5*time.Minute {
				return true
			}
		}
	}

	return false
}

// initiateEmergencyShutdown performs emergency shutdown with secure cleanup
func (seh *SecureErrorHandler) initiateEmergencyShutdown(secErr *SecurityError) error {
	seh.mutex.Lock()
	if seh.isShuttingDown {
		seh.mutex.Unlock()
		return errors.New("emergency shutdown already in progress")
	}
	seh.isShuttingDown = true
	seh.mutex.Unlock()

	// Clear all sensitive data immediately
	seh.clearSensitiveData()

	// Signal shutdown to all components
	select {
	case seh.shutdownChan <- true:
	default:
		// Channel already has shutdown signal
	}

	return fmt.Errorf("emergency shutdown initiated due to security error: %s", secErr.Context)
}

// attemptRecovery tries to recover from a recoverable error
func (seh *SecureErrorHandler) attemptRecovery(secErr *SecurityError) error {
	recoveryKey := fmt.Sprintf("%s-%d", secErr.Context, secErr.Type)
	
	seh.mutex.Lock()
	attempts := seh.recoveryAttempts[recoveryKey]
	if attempts >= seh.maxRecoveryAttempts {
		seh.mutex.Unlock()
		return fmt.Errorf("max recovery attempts exceeded for %s", secErr.Context)
	}
	seh.recoveryAttempts[recoveryKey]++
	seh.mutex.Unlock()

	// Perform recovery based on error type
	switch secErr.Type {
	case ErrorTypeNetwork:
		return seh.recoverNetworkError(secErr)
	case ErrorTypeRoute:
		return seh.recoverRouteError(secErr)
	case ErrorTypeConnection:
		return seh.recoverConnectionError(secErr)
	case ErrorTypeProtocol:
		return seh.recoverProtocolError(secErr)
	default:
		return secErr
	}
}

// recoverNetworkError attempts to recover from network errors
func (seh *SecureErrorHandler) recoverNetworkError(secErr *SecurityError) error {
	// Add random delay to prevent timing attacks
	delay := time.Duration(100+mathrand.Intn(400)) * time.Millisecond
	time.Sleep(delay)

	// Network errors are typically handled by higher-level retry logic
	// Here we just sanitize and return the error for upstream handling
	return &SecurityError{
		Type:        secErr.Type,
		Message:     "network connectivity issue",
		Timestamp:   time.Now(),
		Context:     secErr.Context,
		Recoverable: true,
		SensitiveData: false,
	}
}

// recoverRouteError attempts to recover from routing errors
func (seh *SecureErrorHandler) recoverRouteError(secErr *SecurityError) error {
	// Route errors require new route selection
	// This is handled by the NodeManager, so we return a sanitized error
	return &SecurityError{
		Type:        secErr.Type,
		Message:     "route unavailable, new route required",
		Timestamp:   time.Now(),
		Context:     secErr.Context,
		Recoverable: true,
		SensitiveData: false,
	}
}

// recoverConnectionError attempts to recover from connection errors
func (seh *SecureErrorHandler) recoverConnectionError(secErr *SecurityError) error {
	// Connection errors require reconnection with new crypto context
	return &SecurityError{
		Type:        secErr.Type,
		Message:     "connection lost, reconnection required",
		Timestamp:   time.Now(),
		Context:     secErr.Context,
		Recoverable: true,
		SensitiveData: false,
	}
}

// recoverProtocolError attempts to recover from protocol errors
func (seh *SecureErrorHandler) recoverProtocolError(secErr *SecurityError) error {
	// Protocol errors may require renegotiation
	return &SecurityError{
		Type:        secErr.Type,
		Message:     "protocol error, renegotiation required",
		Timestamp:   time.Now(),
		Context:     secErr.Context,
		Recoverable: true,
		SensitiveData: false,
	}
}

// performSecureCleanup performs secure cleanup for non-recoverable errors
func (seh *SecureErrorHandler) performSecureCleanup(secErr *SecurityError) {
	// Clear any sensitive data that might be related to this error
	seh.clearSensitiveData()

	// Log error in a secure manner (without sensitive data)
	seh.secureLog(secErr)
}

// clearSensitiveData securely clears all sensitive data from memory
func (seh *SecureErrorHandler) clearSensitiveData() {
	// This would be called by components to clear their sensitive data
	// For now, we'll just ensure our own data structures are clean
	seh.mutex.Lock()
	defer seh.mutex.Unlock()

	// Clear recovery attempts to prevent information leakage
	for key := range seh.recoveryAttempts {
		delete(seh.recoveryAttempts, key)
	}
}

// secureLog logs errors without exposing sensitive information
func (seh *SecureErrorHandler) secureLog(secErr *SecurityError) {
	// Only log non-sensitive information
	if !secErr.SensitiveData {
		fmt.Printf("Error [%s]: %s at %s\n", 
			seh.errorTypeString(secErr.Type), 
			secErr.Message, 
			secErr.Timestamp.Format("15:04:05"))
	} else {
		fmt.Printf("Security error occurred at %s\n", secErr.Timestamp.Format("15:04:05"))
	}
}

// errorTypeString returns a string representation of error type
func (seh *SecureErrorHandler) errorTypeString(errorType ErrorType) string {
	switch errorType {
	case ErrorTypeCrypto:
		return "CRYPTO"
	case ErrorTypeNetwork:
		return "NETWORK"
	case ErrorTypeProtocol:
		return "PROTOCOL"
	case ErrorTypeRoute:
		return "ROUTE"
	case ErrorTypeConnection:
		return "CONNECTION"
	case ErrorTypeSystem:
		return "SYSTEM"
	default:
		return "UNKNOWN"
	}
}

// GetShutdownChannel returns the shutdown channel for emergency shutdowns
func (seh *SecureErrorHandler) GetShutdownChannel() <-chan bool {
	return seh.shutdownChan
}

// GetErrorStatistics returns error statistics without sensitive information
func (seh *SecureErrorHandler) GetErrorStatistics() map[string]interface{} {
	seh.mutex.RLock()
	defer seh.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["crypto_errors"] = seh.errorCounts[ErrorTypeCrypto]
	stats["network_errors"] = seh.errorCounts[ErrorTypeNetwork]
	stats["protocol_errors"] = seh.errorCounts[ErrorTypeProtocol]
	stats["route_errors"] = seh.errorCounts[ErrorTypeRoute]
	stats["connection_errors"] = seh.errorCounts[ErrorTypeConnection]
	stats["system_errors"] = seh.errorCounts[ErrorTypeSystem]
	stats["is_shutting_down"] = seh.isShuttingDown

	return stats
}

// ResetRecoveryAttempts resets recovery attempts for a specific context
func (seh *SecureErrorHandler) ResetRecoveryAttempts(context string) {
	seh.mutex.Lock()
	defer seh.mutex.Unlock()

	// Remove all recovery attempts for this context
	for key := range seh.recoveryAttempts {
		if containsString(key, context) {
			delete(seh.recoveryAttempts, key)
		}
	}
}

// AutomaticRecoveryManager handles automatic reconnection with new routes
type AutomaticRecoveryManager struct {
	nodeManager    *NodeManager
	tunnelManager  *TunnelManager
	errorHandler   *SecureErrorHandler
	activeRecoveries map[string]*RecoverySession
	mutex          sync.RWMutex
	maxConcurrentRecoveries int
}

// RecoverySession tracks an ongoing recovery operation
type RecoverySession struct {
	ID            string
	StartTime     time.Time
	ErrorType     ErrorType
	Context       string
	Attempts      int
	MaxAttempts   int
	LastAttempt   time.Time
	Success       bool
	NewRoute      *Route
	NewTunnel     Tunnel
}

// NewAutomaticRecoveryManager creates a new recovery manager
func NewAutomaticRecoveryManager(nm *NodeManager, tm *TunnelManager, eh *SecureErrorHandler) *AutomaticRecoveryManager {
	return &AutomaticRecoveryManager{
		nodeManager:             nm,
		tunnelManager:           tm,
		errorHandler:            eh,
		activeRecoveries:        make(map[string]*RecoverySession),
		maxConcurrentRecoveries: 3,
	}
}

// RecoverFromFailure attempts automatic recovery from a failure
func (arm *AutomaticRecoveryManager) RecoverFromFailure(failedRoute *Route, failureError error, context string) (*Route, Tunnel, error) {
	// Check if we can start a new recovery session
	arm.mutex.Lock()
	if len(arm.activeRecoveries) >= arm.maxConcurrentRecoveries {
		arm.mutex.Unlock()
		return nil, nil, errors.New("too many concurrent recovery operations")
	}

	// Create recovery session
	sessionID := generateRecoverySessionID()
	session := &RecoverySession{
		ID:          sessionID,
		StartTime:   time.Now(),
		ErrorType:   ErrorTypeRoute,
		Context:     context,
		Attempts:    0,
		MaxAttempts: 3,
		Success:     false,
	}
	arm.activeRecoveries[sessionID] = session
	arm.mutex.Unlock()

	// Perform recovery
	newRoute, newTunnel, err := arm.performRecovery(session, failedRoute)
	
	// Update session and cleanup
	arm.mutex.Lock()
	session.Success = (err == nil)
	session.NewRoute = newRoute
	session.NewTunnel = newTunnel
	delete(arm.activeRecoveries, sessionID)
	arm.mutex.Unlock()

	return newRoute, newTunnel, err
}

// performRecovery performs the actual recovery operation
func (arm *AutomaticRecoveryManager) performRecovery(session *RecoverySession, failedRoute *Route) (*Route, Tunnel, error) {
	for session.Attempts < session.MaxAttempts {
		session.Attempts++
		session.LastAttempt = time.Now()

		// Add exponential backoff delay
		if session.Attempts > 1 {
			delay := time.Duration(session.Attempts*session.Attempts) * time.Second
			time.Sleep(delay)
		}

		// Create new route avoiding failed nodes
		newRoute, err := arm.createFailoverRoute(failedRoute)
		if err != nil {
			continue // Try again
		}

		// Establish tunnel through new route
		newTunnel, err := arm.establishSecureTunnel(newRoute)
		if err != nil {
			continue // Try again
		}

		// Success
		return newRoute, newTunnel, nil
	}

	return nil, nil, fmt.Errorf("recovery failed after %d attempts", session.MaxAttempts)
}

// createFailoverRoute creates a new route avoiding failed nodes
func (arm *AutomaticRecoveryManager) createFailoverRoute(failedRoute *Route) (*Route, error) {
	// Get list of failed node IDs to avoid
	failedNodeIDs := make(map[NodeID]bool)
	for _, hop := range failedRoute.Hops {
		failedNodeIDs[hop.ID] = true
	}

	// Get available nodes
	availableNodes := arm.nodeManager.GetAvailableNodes()
	
	// Filter out failed nodes
	var suitableNodes []*Node
	for _, node := range availableNodes {
		if !failedNodeIDs[node.ID] && node.Protocol == failedRoute.Protocol {
			suitableNodes = append(suitableNodes, node)
		}
	}

	if len(suitableNodes) < MinRelayHops {
		return nil, fmt.Errorf("insufficient nodes for failover route: need %d, have %d", 
			MinRelayHops, len(suitableNodes))
	}

	// Select nodes for new route
	hopCount := MinRelayHops
	if len(suitableNodes) > MaxRelayHops {
		hopCount = MaxRelayHops
	} else if len(suitableNodes) > MinRelayHops {
		hopCount = len(suitableNodes)
	}

	selectedNodes := arm.selectRandomNodes(suitableNodes, hopCount)
	
	// Create new route
	newRoute := &Route{
		Hops:      selectedNodes,
		Protocol:  failedRoute.Protocol,
		CreatedAt: time.Now(),
		Active:    true,
	}

	return newRoute, nil
}

// establishSecureTunnel establishes a secure tunnel through the new route
func (arm *AutomaticRecoveryManager) establishSecureTunnel(route *Route) (Tunnel, error) {
	if len(route.Hops) == 0 {
		return nil, errors.New("route has no hops")
	}

	firstHop := route.Hops[0]
	timeout := time.Duration(ConnectionTimeout) * time.Second

	var tunnel Tunnel
	var err error

	if route.Protocol == "tcp" {
		tunnel, err = arm.tunnelManager.CreateTCPTunnel(firstHop.Address, timeout)
	} else {
		tunnel, err = arm.tunnelManager.CreateUDPTunnel(firstHop.Address, timeout)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to establish tunnel: %w", err)
	}

	return tunnel, nil
}

// selectRandomNodes randomly selects nodes for the new route
func (arm *AutomaticRecoveryManager) selectRandomNodes(nodes []*Node, count int) []*Node {
	if count >= len(nodes) {
		result := make([]*Node, len(nodes))
		copy(result, nodes)
		return result
	}

	available := make([]*Node, len(nodes))
	copy(available, nodes)

	var selected []*Node
	for i := 0; i < count; i++ {
		randomBytes := make([]byte, 4)
		rand.Read(randomBytes)
		randomIndex := int(randomBytes[0])<<24 | int(randomBytes[1])<<16 | int(randomBytes[2])<<8 | int(randomBytes[3])
		if randomIndex < 0 {
			randomIndex = -randomIndex
		}
		randomIndex = randomIndex % len(available)

		selected = append(selected, available[randomIndex])
		available = append(available[:randomIndex], available[randomIndex+1:]...)
	}

	return selected
}

// GetRecoveryStatistics returns statistics about recovery operations
func (arm *AutomaticRecoveryManager) GetRecoveryStatistics() map[string]interface{} {
	arm.mutex.RLock()
	defer arm.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["active_recoveries"] = len(arm.activeRecoveries)
	stats["max_concurrent_recoveries"] = arm.maxConcurrentRecoveries

	return stats
}

// Utility functions

// containsAny checks if a string contains any of the given substrings
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsString(s, substr) {
			return true
		}
	}
	return false
}

// containsString checks if a string contains a substring (case-insensitive)
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     findSubstring(s, substr)))
}

// findSubstring performs case-insensitive substring search
func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1 := s[i+j]
			c2 := substr[j]
			// Simple case-insensitive comparison
			if c1 >= 'A' && c1 <= 'Z' {
				c1 = c1 + 32 // Convert to lowercase
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 = c2 + 32 // Convert to lowercase
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// sanitizeErrorMessage removes sensitive information from error messages
func sanitizeErrorMessage(msg string, isSensitive bool) string {
	if !isSensitive {
		return msg
	}

	// For sensitive errors, return generic message
	return "operation failed"
}

// generateRecoverySessionID generates a unique ID for recovery sessions
func generateRecoverySessionID() string {
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("recovery-%x", randomBytes)
}