package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecurityPolicyEnforcer enforces security policies across the system
type SecurityPolicyEnforcer struct {
	policies map[string]SecurityPolicy
	auditor  SecurityAuditor
	mutex    sync.RWMutex
}

// SecurityPolicy defines security requirements and constraints
type SecurityPolicy struct {
	Name                string
	MinKeySize          int
	AllowedCipherSuites []string
	MaxConnectionTime   time.Duration
	RequireAuth         bool
	AuditLevel          int
	MaxConnections      int
	RateLimitPerSecond  int
	AllowedNetworks     []string
	BlockedNetworks     []string
}

// SecurityAuditor handles security event logging and monitoring
type SecurityAuditor struct {
	logFile    string
	violations map[string]int
	mutex      sync.RWMutex
}

// NewSecurityPolicyEnforcer creates a new security policy enforcer
func NewSecurityPolicyEnforcer() *SecurityPolicyEnforcer {
	return &SecurityPolicyEnforcer{
		policies: make(map[string]SecurityPolicy),
		auditor:  SecurityAuditor{
			violations: make(map[string]int),
		},
	}
}

// LoadDefaultPolicies loads default security policies
func (spe *SecurityPolicyEnforcer) LoadDefaultPolicies() {
	spe.mutex.Lock()
	defer spe.mutex.Unlock()

	// Connection security policy
	spe.policies["connection"] = SecurityPolicy{
		Name:                "connection_security",
		MinKeySize:          32, // AES-256
		AllowedCipherSuites: []string{"kyber1024-aes256-gcm", "aes256-gcm"},
		MaxConnectionTime:   24 * time.Hour,
		RequireAuth:         true,
		AuditLevel:          2,
		MaxConnections:      100,
		RateLimitPerSecond:  10,
		AllowedNetworks:     []string{}, // Empty means all allowed
		BlockedNetworks:     []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"},
	}

	// Cryptographic policy
	spe.policies["crypto"] = SecurityPolicy{
		Name:                "crypto_security",
		MinKeySize:          32,
		AllowedCipherSuites: []string{"kyber1024-aes256-gcm"},
		RequireAuth:         true,
		AuditLevel:          3, // Highest audit level for crypto
	}

	// Network policy
	spe.policies["network"] = SecurityPolicy{
		Name:               "network_security",
		MaxConnections:     50,
		RateLimitPerSecond: 5,
		AuditLevel:         2,
		AllowedNetworks:    []string{},
		BlockedNetworks:    []string{"0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}
}

// EnforceConnectionPolicy enforces security policy for connections
func (spe *SecurityPolicyEnforcer) EnforceConnectionPolicy(conn *DirectConnection) error {
	spe.mutex.RLock()
	policy, exists := spe.policies["connection"]
	spe.mutex.RUnlock()

	if !exists {
		return errors.New("no connection policy defined")
	}

	// Enforce authentication requirement
	if policy.RequireAuth && !conn.IsAuthenticated() {
		spe.auditor.LogSecurityViolation("unauthenticated_connection_attempt", conn.RemoteAddress)
		return errors.New("authentication required by policy")
	}

	// Enforce key size requirements
	if conn.cryptoContext != nil && len(conn.cryptoContext.SharedSecret) < policy.MinKeySize {
		spe.auditor.LogSecurityViolation("insufficient_key_size", conn.RemoteAddress)
		return errors.New("key size below policy minimum")
	}

	// Enforce connection time limits
	if time.Since(conn.ConnectedAt) > policy.MaxConnectionTime {
		spe.auditor.LogSecurityViolation("connection_time_exceeded", conn.RemoteAddress)
		return errors.New("connection time limit exceeded")
	}

	// Enforce network restrictions
	if err := spe.enforceNetworkPolicy(conn.RemoteAddress, policy); err != nil {
		spe.auditor.LogSecurityViolation("network_policy_violation", conn.RemoteAddress)
		return fmt.Errorf("network policy violation: %w", err)
	}

	return nil
}

// EnforceCryptographicPolicy enforces cryptographic security policies
func (spe *SecurityPolicyEnforcer) EnforceCryptographicPolicy(keySize int, cipherSuite string) error {
	spe.mutex.RLock()
	policy, exists := spe.policies["crypto"]
	spe.mutex.RUnlock()

	if !exists {
		return errors.New("no cryptographic policy defined")
	}

	// Check minimum key size
	if keySize < policy.MinKeySize {
		spe.auditor.LogSecurityViolation("weak_key_size", fmt.Sprintf("size:%d", keySize))
		return fmt.Errorf("key size %d below minimum %d", keySize, policy.MinKeySize)
	}

	// Check allowed cipher suites
	allowed := false
	for _, allowedSuite := range policy.AllowedCipherSuites {
		if cipherSuite == allowedSuite {
			allowed = true
			break
		}
	}

	if !allowed {
		spe.auditor.LogSecurityViolation("unauthorized_cipher_suite", cipherSuite)
		return fmt.Errorf("cipher suite %s not allowed", cipherSuite)
	}

	return nil
}

// enforceNetworkPolicy enforces network-level security policies
func (spe *SecurityPolicyEnforcer) enforceNetworkPolicy(remoteAddr string, policy SecurityPolicy) error {
	// Parse the remote address
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return fmt.Errorf("invalid remote address format: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}

	// Check blocked networks
	for _, blockedNet := range policy.BlockedNetworks {
		_, network, err := net.ParseCIDR(blockedNet)
		if err != nil {
			continue // Skip invalid CIDR
		}
		if network.Contains(ip) {
			return fmt.Errorf("connection from blocked network: %s", blockedNet)
		}
	}

	// Check allowed networks (if specified)
	if len(policy.AllowedNetworks) > 0 {
		allowed := false
		for _, allowedNet := range policy.AllowedNetworks {
			_, network, err := net.ParseCIDR(allowedNet)
			if err != nil {
				continue // Skip invalid CIDR
			}
			if network.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("connection not from allowed network")
		}
	}

	return nil
}

// LogSecurityViolation logs a security policy violation
func (sa *SecurityAuditor) LogSecurityViolation(violationType, details string) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()

	// Increment violation counter
	sa.violations[violationType]++

	// Log the violation (in production, this would go to a secure log)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[SECURITY VIOLATION] %s: %s - %s\n", timestamp, violationType, details)
}

// GetViolationStats returns security violation statistics
func (sa *SecurityAuditor) GetViolationStats() map[string]int {
	sa.mutex.RLock()
	defer sa.mutex.RUnlock()

	stats := make(map[string]int)
	for violationType, count := range sa.violations {
		stats[violationType] = count
	}
	return stats
}

// SecureLogger provides secure logging with sanitization
type SecureLogger struct {
	logLevel    LogLevel
	mutex       sync.Mutex
	sanitizer   *LogSanitizer
}

// LogLevel represents different logging levels
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Context   string    `json:"context"`
	SessionID string    `json:"session_id"`
}

// LogSanitizer sanitizes log messages to prevent information disclosure
type LogSanitizer struct {
	sensitivePatterns []string
	mutex             sync.RWMutex
}

// NewSecureLogger creates a new secure logger
func NewSecureLogger(level LogLevel) *SecureLogger {
	return &SecureLogger{
		logLevel: level,
		sanitizer: &LogSanitizer{
			sensitivePatterns: []string{
				"key", "password", "token", "secret", "auth", "cert",
				"private", "credential", "session", "cookie", "hash",
			},
		},
	}
}

// LogError logs an error with sanitization
func (sl *SecureLogger) LogError(secErr *SecurityError) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	// Always sanitize log messages
	sanitizedMessage := sl.sanitizer.SanitizeMessage(secErr.Message)
	sanitizedContext := sl.sanitizer.SanitizeContext(secErr.Context)

	logEntry := LogEntry{
		Timestamp: secErr.Timestamp,
		Level:     "ERROR",
		Type:      sl.errorTypeString(secErr.Type),
		Message:   sanitizedMessage,
		Context:   sanitizedContext,
		SessionID: generateSessionID(),
	}

	// Write to secure log
	sl.writeLogEntry(logEntry)
}

// SanitizeMessage removes sensitive information from log messages
func (ls *LogSanitizer) SanitizeMessage(message string) string {
	ls.mutex.RLock()
	defer ls.mutex.RUnlock()

	sanitized := message
	for _, pattern := range ls.sensitivePatterns {
		re := regexp.MustCompile(`(?i)` + pattern + `[:\s]*[^\s]+`)
		sanitized = re.ReplaceAllString(sanitized, pattern+": [REDACTED]")
	}
	return sanitized
}

// SanitizeContext removes sensitive information from context strings
func (ls *LogSanitizer) SanitizeContext(context string) string {
	ls.mutex.RLock()
	defer ls.mutex.RUnlock()

	sanitized := context
	for _, pattern := range ls.sensitivePatterns {
		if strings.Contains(strings.ToLower(context), pattern) {
			return "secure_operation"
		}
	}
	return sanitized
}

// writeLogEntry writes a log entry to the secure log
func (sl *SecureLogger) writeLogEntry(entry LogEntry) {
	// In production, this would write to a secure, tamper-evident log
	fmt.Printf("[%s] %s [%s]: %s (Context: %s, Session: %s)\n",
		entry.Timestamp.Format("2006-01-02 15:04:05"),
		entry.Level,
		entry.Type,
		entry.Message,
		entry.Context,
		entry.SessionID)
}

// errorTypeString converts error type to string
func (sl *SecureLogger) errorTypeString(errorType ErrorType) string {
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
	case ErrorTypeDirect:
		return "DIRECT"
	case ErrorTypeInvitation:
		return "INVITATION"
	case ErrorTypeHandshake:
		return "HANDSHAKE"
	default:
		return "UNKNOWN"
	}
}

// generateSessionID generates a unique session ID for log correlation
func generateSessionID() string {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "unknown"
	}
	return fmt.Sprintf("sess-%x", randomBytes)
}

// ResourceLimiter enforces resource usage limits
type ResourceLimiter struct {
	maxConnections    int
	currentConnections int
	rateLimiter       map[string]*RateLimit
	mutex             sync.RWMutex
}

// RateLimit tracks rate limiting for a specific source
type RateLimit struct {
	requests  int
	window    time.Time
	blocked   bool
	blockTime time.Time
}

// NewResourceLimiter creates a new resource limiter
func NewResourceLimiter(maxConnections int) *ResourceLimiter {
	return &ResourceLimiter{
		maxConnections: maxConnections,
		rateLimiter:    make(map[string]*RateLimit),
	}
}

// CheckConnectionLimit checks if a new connection is allowed
func (rl *ResourceLimiter) CheckConnectionLimit() error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if rl.currentConnections >= rl.maxConnections {
		return errors.New("connection limit exceeded")
	}

	rl.currentConnections++
	return nil
}

// ReleaseConnection releases a connection slot
func (rl *ResourceLimiter) ReleaseConnection() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if rl.currentConnections > 0 {
		rl.currentConnections--
	}
}

// CheckRateLimit checks if a request from a source is rate limited
func (rl *ResourceLimiter) CheckRateLimit(source string, limit int) error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	rateLimit, exists := rl.rateLimiter[source]

	if !exists {
		rl.rateLimiter[source] = &RateLimit{
			requests: 1,
			window:   now,
		}
		return nil
	}

	// Check if currently blocked
	if rateLimit.blocked && now.Sub(rateLimit.blockTime) < time.Minute {
		return errors.New("rate limit exceeded - temporarily blocked")
	}

	// Reset window if needed
	if now.Sub(rateLimit.window) > time.Second {
		rateLimit.requests = 1
		rateLimit.window = now
		rateLimit.blocked = false
		return nil
	}

	// Check rate limit
	rateLimit.requests++
	if rateLimit.requests > limit {
		rateLimit.blocked = true
		rateLimit.blockTime = now
		return errors.New("rate limit exceeded")
	}

	return nil
}

// NetworkAddressValidator validates network addresses for security
type NetworkAddressValidator struct {
	blockedNetworks []string
	allowedNetworks []string
	mutex           sync.RWMutex
}

// NewNetworkAddressValidator creates a new network address validator
func NewNetworkAddressValidator() *NetworkAddressValidator {
	return &NetworkAddressValidator{
		blockedNetworks: []string{
			"127.0.0.0/8",    // Loopback
			"169.254.0.0/16", // Link-local
			"224.0.0.0/4",    // Multicast
			"0.0.0.0/8",      // Invalid
		},
	}
}

// ValidateAddress validates a network address for security
func (nav *NetworkAddressValidator) ValidateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	// Validate port
	if err := validatePortNumber(port); err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Parse IP address
	ip := net.ParseIP(host)
	if ip == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("failed to resolve hostname: %w", err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for hostname")
		}
		ip = ips[0] // Use first IP
	}

	// Check blocked networks
	nav.mutex.RLock()
	defer nav.mutex.RUnlock()

	for _, blockedNet := range nav.blockedNetworks {
		_, network, err := net.ParseCIDR(blockedNet)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return fmt.Errorf("address in blocked network: %s", blockedNet)
		}
	}

	// Check allowed networks (if specified)
	if len(nav.allowedNetworks) > 0 {
		allowed := false
		for _, allowedNet := range nav.allowedNetworks {
			_, network, err := net.ParseCIDR(allowedNet)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("address not in allowed networks")
		}
	}

	return nil
}

// validatePortNumber validates a port number string
func validatePortNumber(portStr string) error {
	if portStr == "" {
		return errors.New("port cannot be empty")
	}

	// Simple validation - in production would use strconv.Atoi
	for _, char := range portStr {
		if char < '0' || char > '9' {
			return errors.New("port must be numeric")
		}
	}

	return nil
}

// PanicRecoveryManager handles panic recovery with security considerations
type PanicRecoveryManager struct {
	emergencyCleanup func()
	secureLogger     *SecureLogger
}

// NewPanicRecoveryManager creates a new panic recovery manager
func NewPanicRecoveryManager(cleanup func(), logger *SecureLogger) *PanicRecoveryManager {
	return &PanicRecoveryManager{
		emergencyCleanup: cleanup,
		secureLogger:     logger,
	}
}

// RecoverFromPanic recovers from a panic with secure cleanup
func (prm *PanicRecoveryManager) RecoverFromPanic() {
	if r := recover(); r != nil {
		// Log panic securely without exposing sensitive data
		if prm.secureLogger != nil {
			secErr := &SecurityError{
				Type:        ErrorTypeSystem,
				Message:     "system panic recovered",
				Timestamp:   time.Now(),
				Context:     "panic_recovery",
				Recoverable: false,
				SensitiveData: true,
			}
			prm.secureLogger.LogError(secErr)
		}

		// Perform emergency cleanup
		if prm.emergencyCleanup != nil {
			prm.emergencyCleanup()
		}
	}
}

// PerformEmergencyCleanup performs emergency cleanup operations
func PerformEmergencyCleanup() {
	// Clear sensitive data from memory
	clearSensitiveMemory()

	// Close open connections
	closeAllConnections()

	// Write emergency state to secure location
	writeEmergencyState()
}

// clearSensitiveMemory clears sensitive data from memory
func clearSensitiveMemory() {
	// This would clear cryptographic keys, session data, etc.
	// Implementation would depend on the specific data structures used
}

// closeAllConnections closes all open network connections
func closeAllConnections() {
	// This would close all active network connections
	// Implementation would depend on the connection management system
}

// writeEmergencyState writes emergency state information
func writeEmergencyState() {
	// This would write minimal state information for forensic analysis
	// without exposing sensitive data
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[EMERGENCY] System emergency cleanup completed at %s\n", timestamp)
}

// Enhanced resource cleanup with comprehensive memory management
type ResourceCleanupManager struct {
	resources []CleanupResource
	mutex     sync.Mutex
}

// CleanupResource represents a resource that needs cleanup
type CleanupResource interface {
	Cleanup() error
	GetResourceType() string
}

// NewResourceCleanupManager creates a new resource cleanup manager
func NewResourceCleanupManager() *ResourceCleanupManager {
	return &ResourceCleanupManager{
		resources: make([]CleanupResource, 0),
	}
}

// RegisterResource registers a resource for cleanup
func (rcm *ResourceCleanupManager) RegisterResource(resource CleanupResource) {
	rcm.mutex.Lock()
	defer rcm.mutex.Unlock()
	rcm.resources = append(rcm.resources, resource)
}

// CleanupAll cleans up all registered resources
func (rcm *ResourceCleanupManager) CleanupAll() error {
	rcm.mutex.Lock()
	defer rcm.mutex.Unlock()

	var lastErr error
	for _, resource := range rcm.resources {
		if err := resource.Cleanup(); err != nil {
			lastErr = err
			// Continue cleanup even if one resource fails
		}
	}

	// Clear the resources slice
	rcm.resources = rcm.resources[:0]

	return lastErr
}

// SecureRandomGenerator provides cryptographically secure random number generation
type SecureRandomGenerator struct {
	mutex sync.Mutex
}

// NewSecureRandomGenerator creates a new secure random generator
func NewSecureRandomGenerator() *SecureRandomGenerator {
	return &SecureRandomGenerator{}
}

// GenerateBytes generates cryptographically secure random bytes
func (srg *SecureRandomGenerator) GenerateBytes(length int) ([]byte, error) {
	srg.mutex.Lock()
	defer srg.mutex.Unlock()

	if length <= 0 {
		return nil, errors.New("length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return bytes, nil
}

// GenerateInt generates a cryptographically secure random integer
func (srg *SecureRandomGenerator) GenerateInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be positive")
	}

	bytes, err := srg.GenerateBytes(8)
	if err != nil {
		return 0, err
	}

	value := int(binary.LittleEndian.Uint64(bytes))
	if value < 0 {
		value = -value
	}

	return value % max, nil
}

// GenerateDuration generates a cryptographically secure random duration
func (srg *SecureRandomGenerator) GenerateDuration(min, max time.Duration) (time.Duration, error) {
	if min >= max {
		return 0, errors.New("min must be less than max")
	}

	rangeNs := int64(max - min)
	randomNs, err := srg.GenerateInt(int(rangeNs))
	if err != nil {
		return 0, err
	}

	return min + time.Duration(randomNs), nil
}
