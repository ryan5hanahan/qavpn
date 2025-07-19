package direct

import (
	"time"
)

// DirectConnectionManager orchestrates direct connection establishment and management
type DirectConnectionManager interface {
	// Connection lifecycle
	StartListener(config *ListenerConfig) error
	StartEnhancedListener(config *ListenerConfig) error
	ConnectToPeer(invitation *InvitationCode) error
	ConnectToPeerEnhanced(invitation *InvitationCode) error
	DisconnectPeer(connectionID string) error

	// Invitation management
	GenerateInvitation(config *InvitationConfig) (*InvitationCode, error)
	ProcessInvitation(invitationData string) (*InvitationCode, error)
	ValidateInvitation(invitation *InvitationCode) error

	// Connection management
	GetActiveConnections() []*DirectConnection
	GetConnectionStatus(connectionID string) (*ConnectionStatus, error)

	// Role management and conflict resolution
	DetectAndResolveRoleConflicts() ([]*RoleConflictResolution, error)
	GetRoleConflictGuidanceForConnection(connectionID string) (*RoleConflictResolution, error)
	ResolveRoleConflictForConnection(connectionID string, preferredRole ConnectionRole) error

	// Configuration
	SaveConnectionProfile(profile *ConnectionProfile) error
	LoadConnectionProfile(name string) (*ConnectionProfile, error)
	DeleteConnectionProfile(name string) error
}

// DirectConnectionHandler manages individual direct connections
type DirectConnectionHandler interface {
	// Connection management
	Establish() error
	Disconnect() error
	IsHealthy() bool

	// Data transmission (implements existing Tunnel interface)
	SendData(data []byte) error
	ReceiveData() ([]byte, error)
	Close() error
	IsActive() bool

	// Handshake and role management
	InitiateHandshake() error
	ProcessHandshakeMessage(messageData []byte) (*HandshakeMessage, error)
	IsHandshakeComplete() bool
	GetHandshakeState() *HandshakeState
	GetRoleConflictGuidance() *RoleConflictResolution

	// OPSEC features
	EnableTrafficObfuscation() error
	SetKeepAliveInterval(interval time.Duration) error
	GetConnectionMetrics() *ConnectionMetrics
}

// SecureConfigManager handles secure storage and management of direct connection configurations
type SecureConfigManager interface {
	// Basic profile management
	SaveProfile(profile *ConnectionProfile) error
	LoadProfile(name string) (*ConnectionProfile, error)
	DeleteProfile(name string) error
	ListProfiles() []string

	// Enhanced profile management
	ListProfilesWithMetadata() ([]*ProfileMetadata, error)
	SearchProfiles(criteria *SearchCriteria) ([]*ConnectionProfile, error)
	GetProfileStatistics() (*ProfileStatistics, error)
	UpdateProfileMetadata(name string, metadata *ProfileMetadataUpdate) error
	GetMostUsedProfiles(limit int) ([]*ConnectionProfile, error)
	GetRecentlyUsedProfiles(limit int) ([]*ConnectionProfile, error)
	CleanupUnusedProfiles(unusedDuration time.Duration) ([]string, error)

	// Security operations
	ChangeEncryptionKey(oldKey, newKey []byte) error
	VerifyIntegrity() error
	SecureWipe() error
	SecureDeleteProfile(name string) error

	// Backup/restore
	ExportProfiles(password []byte) ([]byte, error)
	ImportProfiles(data []byte, password []byte) error
	CreateBackup(password []byte, includeMetadata bool) (*BackupData, error)
	RestoreFromBackup(backupData *BackupData, password []byte, overwriteExisting bool) error
	VerifyBackupIntegrity(backupData *BackupData, password []byte) error

	// Integrity checking
	PerformIntegrityCheck() (*IntegrityCheckResult, error)
}

// OPSECNetworkLayer implements network behavior that minimizes fingerprinting
type OPSECNetworkLayer interface {
	// Connection timing
	CalculateConnectionDelay() time.Duration
	CalculateRetryDelay(attempt int) time.Duration
	AddRandomJitter(baseDelay time.Duration) time.Duration

	// Retry management
	ShouldRetry(attempt int, lastError error) bool
	GetNextRetryTime(attempt int) time.Time
	ResetRetryState()

	// Traffic obfuscation
	ObfuscateTraffic(data []byte) ([]byte, error)
	DeobfuscateTraffic(data []byte) ([]byte, error)
}

// InvitationCodeProcessor handles invitation code encoding, decoding, and validation
type InvitationCodeProcessor interface {
	// Encoding/Decoding
	EncodeToBase64(invitation *InvitationCode) (string, error)
	DecodeFromBase64(data string) (*InvitationCode, error)
	EncodeToHex(invitation *InvitationCode) (string, error)
	DecodeFromHex(data string) (*InvitationCode, error)
	GenerateQRCode(invitation *InvitationCode) ([]byte, error)

	// Format detection and auto-decoding
	DetectFormat(data string) string
	DecodeAuto(data string) (*InvitationCode, error)
	EncodeToFormat(invitation *InvitationCode, format string) (string, error)
	GetSupportedFormats() []string

	// Validation
	ValidateFormat(invitationData string) error
	ValidateSignature(invitation *InvitationCode) error
	ValidateExpiration(invitation *InvitationCode) error
	ValidateIntegrity(invitation *InvitationCode) error
}

// ConfigStorage provides the backend storage interface for configuration data
type ConfigStorage interface {
	// Basic storage operations
	Store(key string, data []byte) error
	Retrieve(key string) ([]byte, error)
	Delete(key string) error
	List() ([]string, error)

	// Security operations
	SecureDelete(key string) error
	VerifyIntegrity(key string, expectedHash []byte) error
}