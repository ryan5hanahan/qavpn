package direct

import (
	"fmt"
	"time"
)

// ErrorType categorizes different types of direct mode errors
type ErrorType int

const (
	ErrorTypeConfiguration ErrorType = iota
	ErrorTypeNetwork
	ErrorTypeCryptographic
	ErrorTypeOPSEC
	ErrorTypeInternal
	ErrorTypeInvitation
	ErrorTypeConnection
	ErrorTypeStorage
)

// String returns the string representation of the error type
func (e ErrorType) String() string {
	switch e {
	case ErrorTypeConfiguration:
		return "configuration"
	case ErrorTypeNetwork:
		return "network"
	case ErrorTypeCryptographic:
		return "cryptographic"
	case ErrorTypeOPSEC:
		return "opsec"
	case ErrorTypeInternal:
		return "internal"
	case ErrorTypeInvitation:
		return "invitation"
	case ErrorTypeConnection:
		return "connection"
	case ErrorTypeStorage:
		return "storage"
	default:
		return "unknown"
	}
}

// DirectModeError represents errors specific to direct connection mode
type DirectModeError struct {
	Type        ErrorType              `json:"type"`
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Context     string                 `json:"context"`
	Recoverable bool                   `json:"recoverable"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Error implements the error interface
func (e *DirectModeError) Error() string {
	return fmt.Sprintf("[%s:%s] %s", e.Type.String(), e.Code, e.Message)
}

// IsRecoverable returns whether the error is recoverable
func (e *DirectModeError) IsRecoverable() bool {
	return e.Recoverable
}

// GetContext returns the error context
func (e *DirectModeError) GetContext() string {
	return e.Context
}

// GetMetadata returns the error metadata
func (e *DirectModeError) GetMetadata() map[string]interface{} {
	return e.Metadata
}

// Predefined error codes for direct mode
const (
	// Configuration errors
	ErrCodeInvalidConfig         = "INVALID_CONFIG"
	ErrCodeMissingConfig         = "MISSING_CONFIG"
	ErrCodeIncompatibleConfig    = "INCOMPATIBLE_CONFIG"

	// Network errors
	ErrCodeConnectionTimeout     = "CONNECTION_TIMEOUT"
	ErrCodeAddressUnreachable    = "ADDRESS_UNREACHABLE"
	ErrCodePortBindFailure       = "PORT_BIND_FAILURE"
	ErrCodeNetworkUnavailable    = "NETWORK_UNAVAILABLE"

	// Cryptographic errors
	ErrCodeKeyExchangeFailure    = "KEY_EXCHANGE_FAILURE"
	ErrCodeSignatureVerification = "SIGNATURE_VERIFICATION"
	ErrCodeEncryptionFailure     = "ENCRYPTION_FAILURE"
	ErrCodeDecryptionFailure     = "DECRYPTION_FAILURE"

	// OPSEC errors
	ErrCodeSuspiciousPattern     = "SUSPICIOUS_PATTERN"
	ErrCodeTimingAnalysisRisk    = "TIMING_ANALYSIS_RISK"
	ErrCodeMetadataLeakage       = "METADATA_LEAKAGE"

	// Invitation errors
	ErrCodeInvalidInvitation     = "INVALID_INVITATION"
	ErrCodeExpiredInvitation     = "EXPIRED_INVITATION"
	ErrCodeUsedInvitation        = "USED_INVITATION"
	ErrCodeMalformedInvitation   = "MALFORMED_INVITATION"

	// Connection errors
	ErrCodeConnectionFailed      = "CONNECTION_FAILED"
	ErrCodeConnectionLost        = "CONNECTION_LOST"
	ErrCodeRoleConflict          = "ROLE_CONFLICT"
	ErrCodeHandshakeFailure      = "HANDSHAKE_FAILURE"

	// Storage errors
	ErrCodeStorageFailure        = "STORAGE_FAILURE"
	ErrCodeIntegrityViolation    = "INTEGRITY_VIOLATION"
	ErrCodeIntegrityFailure      = "INTEGRITY_FAILURE"
	ErrCodeEncryptionKeyMissing  = "ENCRYPTION_KEY_MISSING"
)

// NewDirectModeError creates a new DirectModeError
func NewDirectModeError(errorType ErrorType, code, message, context string, recoverable bool) *DirectModeError {
	return &DirectModeError{
		Type:        errorType,
		Code:        code,
		Message:     message,
		Context:     context,
		Recoverable: recoverable,
		Timestamp:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}
}

// WithMetadata adds metadata to the error
func (e *DirectModeError) WithMetadata(key string, value interface{}) *DirectModeError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// Common error constructors for convenience

// NewConfigurationError creates a configuration-related error
func NewConfigurationError(code, message, context string) *DirectModeError {
	return NewDirectModeError(ErrorTypeConfiguration, code, message, context, true)
}

// NewNetworkError creates a network-related error
func NewNetworkError(code, message, context string, recoverable bool) *DirectModeError {
	return NewDirectModeError(ErrorTypeNetwork, code, message, context, recoverable)
}

// NewCryptographicError creates a cryptographic-related error
func NewCryptographicError(code, message, context string) *DirectModeError {
	return NewDirectModeError(ErrorTypeCryptographic, code, message, context, false)
}

// NewOPSECError creates an OPSEC-related error
func NewOPSECError(code, message, context string) *DirectModeError {
	return NewDirectModeError(ErrorTypeOPSEC, code, message, context, true)
}

// NewInvitationError creates an invitation-related error
func NewInvitationError(code, message, context string) *DirectModeError {
	return NewDirectModeError(ErrorTypeInvitation, code, message, context, true)
}

// NewConnectionError creates a connection-related error
func NewConnectionError(code, message, context string, recoverable bool) *DirectModeError {
	return NewDirectModeError(ErrorTypeConnection, code, message, context, recoverable)
}

// NewStorageError creates a storage-related error
func NewStorageError(code, message, context string, recoverable bool) *DirectModeError {
	return NewDirectModeError(ErrorTypeStorage, code, message, context, recoverable)
}

// Error type checking helper functions

// IsConfigurationError checks if an error is a configuration error
func IsConfigurationError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeConfiguration
	}
	return false
}

// IsNetworkError checks if an error is a network error
func IsNetworkError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeNetwork
	}
	return false
}

// IsCryptographicError checks if an error is a cryptographic error
func IsCryptographicError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeCryptographic
	}
	return false
}

// IsOPSECError checks if an error is an OPSEC error
func IsOPSECError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeOPSEC
	}
	return false
}

// IsInvitationError checks if an error is an invitation error
func IsInvitationError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeInvitation
	}
	return false
}

// IsConnectionError checks if an error is a connection error
func IsConnectionError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeConnection
	}
	return false
}

// IsStorageError checks if an error is a storage error
func IsStorageError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeStorage
	}
	return false
}

// IsInternalError checks if an error is an internal error
func IsInternalError(err error) bool {
	if directErr, ok := err.(*DirectModeError); ok {
		return directErr.Type == ErrorTypeInternal
	}
	return false
}