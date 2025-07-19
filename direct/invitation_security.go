package direct

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// InvitationSecurityManager handles anti-replay protection and security features for invitation codes
type InvitationSecurityManager struct {
	usedInvitations map[string]*UsedInvitationRecord
	mutex           sync.RWMutex
	cleanupInterval time.Duration
	maxAge          time.Duration
	stopCleanup     chan struct{}
}

// UsedInvitationRecord tracks when an invitation code was used
type UsedInvitationRecord struct {
	InvitationHash string
	UsedAt         time.Time
	ConnectionID   [16]byte
	RemoteAddr     string // Optional: track where it was used from
}

// Anti-replay protection errors
var (
	ErrInvitationAlreadyUsed = errors.New("invitation code has already been used")
	ErrInvitationExpired     = errors.New("invitation code has expired")
	ErrInvalidInvitation     = errors.New("invitation code is invalid")
)

// NewInvitationSecurityManager creates a new invitation security manager
func NewInvitationSecurityManager(cleanupInterval, maxAge time.Duration) *InvitationSecurityManager {
	manager := &InvitationSecurityManager{
		usedInvitations: make(map[string]*UsedInvitationRecord),
		cleanupInterval: cleanupInterval,
		maxAge:          maxAge,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go manager.cleanupLoop()

	return manager
}

// ValidateAndMarkUsed validates an invitation code and marks it as used if valid
func (ism *InvitationSecurityManager) ValidateAndMarkUsed(invitation *InvitationCode, remoteAddr string) error {
	if invitation == nil {
		return ErrInvalidInvitation
	}

	// First, validate the invitation code itself
	if err := invitation.Validate(); err != nil {
		return fmt.Errorf("invitation validation failed: %w", err)
	}

	// Generate a unique hash for this invitation
	invitationHash, err := ism.generateInvitationHash(invitation)
	if err != nil {
		return fmt.Errorf("failed to generate invitation hash: %w", err)
	}

	ism.mutex.Lock()
	defer ism.mutex.Unlock()

	// Check if this invitation has already been used
	if record, exists := ism.usedInvitations[invitationHash]; exists {
		return fmt.Errorf("%w: used at %v from %s", ErrInvitationAlreadyUsed, record.UsedAt, record.RemoteAddr)
	}

	// For single-use invitations, mark as used immediately
	if invitation.SingleUse {
		ism.usedInvitations[invitationHash] = &UsedInvitationRecord{
			InvitationHash: invitationHash,
			UsedAt:         time.Now(),
			ConnectionID:   invitation.ConnectionID,
			RemoteAddr:     remoteAddr,
		}
	}

	return nil
}

// IsInvitationUsed checks if an invitation code has been used
func (ism *InvitationSecurityManager) IsInvitationUsed(invitation *InvitationCode) (bool, error) {
	if invitation == nil {
		return false, ErrInvalidInvitation
	}

	invitationHash, err := ism.generateInvitationHash(invitation)
	if err != nil {
		return false, fmt.Errorf("failed to generate invitation hash: %w", err)
	}

	ism.mutex.RLock()
	defer ism.mutex.RUnlock()

	_, exists := ism.usedInvitations[invitationHash]
	return exists, nil
}

// GetUsageRecord returns the usage record for an invitation code
func (ism *InvitationSecurityManager) GetUsageRecord(invitation *InvitationCode) (*UsedInvitationRecord, error) {
	if invitation == nil {
		return nil, ErrInvalidInvitation
	}

	invitationHash, err := ism.generateInvitationHash(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invitation hash: %w", err)
	}

	ism.mutex.RLock()
	defer ism.mutex.RUnlock()

	record, exists := ism.usedInvitations[invitationHash]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modification
	return &UsedInvitationRecord{
		InvitationHash: record.InvitationHash,
		UsedAt:         record.UsedAt,
		ConnectionID:   record.ConnectionID,
		RemoteAddr:     record.RemoteAddr,
	}, nil
}

// RevokeInvitation manually revokes an invitation code (marks it as used)
func (ism *InvitationSecurityManager) RevokeInvitation(invitation *InvitationCode, reason string) error {
	if invitation == nil {
		return ErrInvalidInvitation
	}

	invitationHash, err := ism.generateInvitationHash(invitation)
	if err != nil {
		return fmt.Errorf("failed to generate invitation hash: %w", err)
	}

	ism.mutex.Lock()
	defer ism.mutex.Unlock()

	ism.usedInvitations[invitationHash] = &UsedInvitationRecord{
		InvitationHash: invitationHash,
		UsedAt:         time.Now(),
		ConnectionID:   invitation.ConnectionID,
		RemoteAddr:     fmt.Sprintf("REVOKED: %s", reason),
	}

	return nil
}

// GetUsageStatistics returns statistics about invitation usage
func (ism *InvitationSecurityManager) GetUsageStatistics() map[string]interface{} {
	ism.mutex.RLock()
	defer ism.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_used_invitations"] = len(ism.usedInvitations)

	// Count by time periods
	now := time.Now()
	lastHour := 0
	lastDay := 0
	lastWeek := 0

	for _, record := range ism.usedInvitations {
		age := now.Sub(record.UsedAt)
		if age <= time.Hour {
			lastHour++
		}
		if age <= 24*time.Hour {
			lastDay++
		}
		if age <= 7*24*time.Hour {
			lastWeek++
		}
	}

	stats["used_last_hour"] = lastHour
	stats["used_last_day"] = lastDay
	stats["used_last_week"] = lastWeek

	return stats
}

// Cleanup removes old invitation records
func (ism *InvitationSecurityManager) Cleanup() int {
	ism.mutex.Lock()
	defer ism.mutex.Unlock()

	now := time.Now()
	removed := 0

	for hash, record := range ism.usedInvitations {
		if now.Sub(record.UsedAt) > ism.maxAge {
			delete(ism.usedInvitations, hash)
			removed++
		}
	}

	return removed
}

// Stop stops the cleanup goroutine
func (ism *InvitationSecurityManager) Stop() {
	close(ism.stopCleanup)
}

// generateInvitationHash creates a unique hash for an invitation code
func (ism *InvitationSecurityManager) generateInvitationHash(invitation *InvitationCode) (string, error) {
	// Create a hash based on the invitation's unique characteristics
	h := sha256.New()

	// Include version
	h.Write([]byte{invitation.Version})

	// Include connection ID
	h.Write(invitation.ConnectionID[:])

	// Include public key
	h.Write(invitation.PublicKey)

	// Include network config
	if invitation.NetworkConfig != nil {
		h.Write([]byte(invitation.NetworkConfig.Protocol))
		h.Write([]byte(invitation.NetworkConfig.ListenerAddress))
		for _, addr := range invitation.NetworkConfig.BackupAddresses {
			h.Write([]byte(addr))
		}
	}

	// Include security params
	if invitation.SecurityParams != nil {
		h.Write(invitation.SecurityParams.KeyDerivationSalt)
		h.Write([]byte(invitation.SecurityParams.CipherSuite))
		h.Write([]byte(invitation.SecurityParams.AuthMethod))
	}

	// Include creation time (to make each invitation unique even with same params)
	createdAtBytes := make([]byte, 8)
	createdAtNanos := invitation.CreatedAt.UnixNano()
	for i := 0; i < 8; i++ {
		createdAtBytes[i] = byte(createdAtNanos >> (56 - i*8))
	}
	h.Write(createdAtBytes)

	// Include single use flag
	if invitation.SingleUse {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	hash := h.Sum(nil)
	return hex.EncodeToString(hash), nil
}

// cleanupLoop runs periodic cleanup of old invitation records
func (ism *InvitationSecurityManager) cleanupLoop() {
	ticker := time.NewTicker(ism.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ism.Cleanup()
		case <-ism.stopCleanup:
			return
		}
	}
}

// SecureInvitationValidator combines validation and anti-replay protection
type SecureInvitationValidator struct {
	processor       InvitationCodeProcessor
	securityManager *InvitationSecurityManager
	signerPublicKey []byte // Ed25519 public key for signature validation
}

// NewSecureInvitationValidator creates a new secure invitation validator
func NewSecureInvitationValidator(signerPublicKey []byte) *SecureInvitationValidator {
	return &SecureInvitationValidator{
		processor:       NewInvitationCodeProcessor(),
		securityManager: NewInvitationSecurityManager(1*time.Hour, 24*time.Hour), // Cleanup every hour, keep records for 24 hours
		signerPublicKey: signerPublicKey,
	}
}

// ValidateAndProcessInvitation performs comprehensive validation and anti-replay protection
func (siv *SecureInvitationValidator) ValidateAndProcessInvitation(invitationData string, remoteAddr string) (*InvitationCode, error) {
	// First, decode the invitation
	invitation, err := siv.processor.DecodeAuto(invitationData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode invitation: %w", err)
	}

	// Validate the invitation structure
	if err := invitation.Validate(); err != nil {
		return nil, fmt.Errorf("invitation validation failed: %w", err)
	}

	// Validate the signature if we have a signer public key
	if len(siv.signerPublicKey) > 0 {
		if err := invitation.ValidateSignature(siv.signerPublicKey); err != nil {
			return nil, fmt.Errorf("signature validation failed: %w", err)
		}
	}

	// Check for replay attacks and mark as used
	if err := siv.securityManager.ValidateAndMarkUsed(invitation, remoteAddr); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	return invitation, nil
}

// IsInvitationUsed checks if an invitation has been used
func (siv *SecureInvitationValidator) IsInvitationUsed(invitation *InvitationCode) (bool, error) {
	return siv.securityManager.IsInvitationUsed(invitation)
}

// GetUsageStatistics returns usage statistics
func (siv *SecureInvitationValidator) GetUsageStatistics() map[string]interface{} {
	return siv.securityManager.GetUsageStatistics()
}

// Stop stops the validator
func (siv *SecureInvitationValidator) Stop() {
	siv.securityManager.Stop()
}