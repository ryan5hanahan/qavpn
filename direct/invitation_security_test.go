package direct

import (
	"errors"
	"testing"
	"time"
)

func TestNewInvitationSecurityManager(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	if manager == nil {
		t.Error("Expected non-nil security manager")
	}

	// Clean up
	manager.Stop()
}

func TestValidateAndMarkUsed(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)
	remoteAddr := "192.168.1.100:12345"

	// First use should succeed
	err := manager.ValidateAndMarkUsed(invitation, remoteAddr)
	if err != nil {
		t.Fatalf("First use should succeed: %v", err)
	}

	// Second use should fail for single-use invitation
	err = manager.ValidateAndMarkUsed(invitation, remoteAddr)
	if err == nil {
		t.Error("Expected error for second use of single-use invitation")
	}

	// Check that the error is wrapped ErrInvitationAlreadyUsed
	if !errors.Is(err, ErrInvitationAlreadyUsed) {
		t.Errorf("Expected ErrInvitationAlreadyUsed, got: %v", err)
	}
}

func TestValidateAndMarkUsedNonSingleUse(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)
	invitation.SingleUse = false // Allow multiple uses
	remoteAddr := "192.168.1.100:12345"

	// Multiple uses should succeed for non-single-use invitation
	err := manager.ValidateAndMarkUsed(invitation, remoteAddr)
	if err != nil {
		t.Fatalf("First use should succeed: %v", err)
	}

	err = manager.ValidateAndMarkUsed(invitation, remoteAddr)
	if err != nil {
		t.Fatalf("Second use should succeed for non-single-use invitation: %v", err)
	}
}

func TestIsInvitationUsed(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)
	remoteAddr := "192.168.1.100:12345"

	// Initially should not be used
	used, err := manager.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if used {
		t.Error("Invitation should not be marked as used initially")
	}

	// Mark as used
	err = manager.ValidateAndMarkUsed(invitation, remoteAddr)
	if err != nil {
		t.Fatalf("Failed to mark invitation as used: %v", err)
	}

	// Now should be used
	used, err = manager.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if !used {
		t.Error("Invitation should be marked as used")
	}
}

func TestGetUsageRecord(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)
	remoteAddr := "192.168.1.100:12345"

	// Initially should have no usage record
	record, err := manager.GetUsageRecord(invitation)
	if err != nil {
		t.Fatalf("Failed to get usage record: %v", err)
	}
	if record != nil {
		t.Error("Should have no usage record initially")
	}

	// Mark as used
	beforeUse := time.Now()
	err = manager.ValidateAndMarkUsed(invitation, remoteAddr)
	if err != nil {
		t.Fatalf("Failed to mark invitation as used: %v", err)
	}
	afterUse := time.Now()

	// Now should have usage record
	record, err = manager.GetUsageRecord(invitation)
	if err != nil {
		t.Fatalf("Failed to get usage record: %v", err)
	}
	if record == nil {
		t.Error("Should have usage record after use")
	}

	// Verify record details
	if record.ConnectionID != invitation.ConnectionID {
		t.Error("Usage record should have correct connection ID")
	}

	if record.RemoteAddr != remoteAddr {
		t.Errorf("Expected remote addr %s, got %s", remoteAddr, record.RemoteAddr)
	}

	if record.UsedAt.Before(beforeUse) || record.UsedAt.After(afterUse) {
		t.Error("Usage time should be within expected range")
	}
}

func TestRevokeInvitation(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)
	reason := "Security concern"

	// Initially should not be used
	used, err := manager.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if used {
		t.Error("Invitation should not be marked as used initially")
	}

	// Revoke the invitation
	err = manager.RevokeInvitation(invitation, reason)
	if err != nil {
		t.Fatalf("Failed to revoke invitation: %v", err)
	}

	// Now should be marked as used
	used, err = manager.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if !used {
		t.Error("Invitation should be marked as used after revocation")
	}

	// Check usage record
	record, err := manager.GetUsageRecord(invitation)
	if err != nil {
		t.Fatalf("Failed to get usage record: %v", err)
	}
	if record == nil {
		t.Error("Should have usage record after revocation")
	}

	expectedRemoteAddr := "REVOKED: " + reason
	if record.RemoteAddr != expectedRemoteAddr {
		t.Errorf("Expected remote addr %s, got %s", expectedRemoteAddr, record.RemoteAddr)
	}

	// Attempting to use revoked invitation should fail
	err = manager.ValidateAndMarkUsed(invitation, "192.168.1.100:12345")
	if err == nil {
		t.Error("Expected error when using revoked invitation")
	}
}

func TestGetUsageStatistics(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	// Initially should have zero statistics
	stats := manager.GetUsageStatistics()
	if stats["total_used_invitations"] != 0 {
		t.Error("Expected zero total used invitations initially")
	}

	// Use some invitations
	for i := 0; i < 3; i++ {
		invitation := createTestInvitationCode(t)
		err := manager.ValidateAndMarkUsed(invitation, "192.168.1.100:12345")
		if err != nil {
			t.Fatalf("Failed to use invitation %d: %v", i, err)
		}
	}

	// Check updated statistics
	stats = manager.GetUsageStatistics()
	if stats["total_used_invitations"] != 3 {
		t.Errorf("Expected 3 total used invitations, got %v", stats["total_used_invitations"])
	}

	if stats["used_last_hour"] != 3 {
		t.Errorf("Expected 3 invitations used in last hour, got %v", stats["used_last_hour"])
	}

	if stats["used_last_day"] != 3 {
		t.Errorf("Expected 3 invitations used in last day, got %v", stats["used_last_day"])
	}
}

func TestCleanup(t *testing.T) {
	// Use short max age for testing
	manager := NewInvitationSecurityManager(1*time.Minute, 100*time.Millisecond)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)
	err := manager.ValidateAndMarkUsed(invitation, "192.168.1.100:12345")
	if err != nil {
		t.Fatalf("Failed to use invitation: %v", err)
	}

	// Should be present initially
	used, err := manager.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if !used {
		t.Error("Invitation should be marked as used")
	}

	// Wait for record to age
	time.Sleep(150 * time.Millisecond)

	// Manual cleanup
	removed := manager.Cleanup()
	if removed != 1 {
		t.Errorf("Expected 1 record to be removed, got %d", removed)
	}

	// Should no longer be present
	used, err = manager.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if used {
		t.Error("Invitation should not be marked as used after cleanup")
	}
}

func TestSecureInvitationValidator(t *testing.T) {
	// Create a signer for testing
	signer, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	validator := NewSecureInvitationValidator(signer.PublicKey)
	defer validator.Stop()

	// Create and sign an invitation
	invitation := createTestInvitationCode(t)
	err = invitation.Sign(signer)
	if err != nil {
		t.Fatalf("Failed to sign invitation: %v", err)
	}

	// Encode the invitation
	processor := NewInvitationCodeProcessor()
	invitationData, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode invitation: %v", err)
	}

	remoteAddr := "192.168.1.100:12345"

	// First validation should succeed
	validatedInvitation, err := validator.ValidateAndProcessInvitation(invitationData, remoteAddr)
	if err != nil {
		t.Fatalf("First validation should succeed: %v", err)
	}

	if validatedInvitation.ConnectionID != invitation.ConnectionID {
		t.Error("Validated invitation should match original")
	}

	// Second validation should fail due to replay protection
	_, err = validator.ValidateAndProcessInvitation(invitationData, remoteAddr)
	if err == nil {
		t.Error("Expected error for second validation (replay attack)")
	}

	// Check that it's marked as used
	used, err := validator.IsInvitationUsed(invitation)
	if err != nil {
		t.Fatalf("Failed to check if invitation is used: %v", err)
	}
	if !used {
		t.Error("Invitation should be marked as used")
	}
}

func TestSecureInvitationValidatorInvalidSignature(t *testing.T) {
	// Create two different signers
	signer1, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer1: %v", err)
	}

	signer2, err := NewInvitationCodeSigner()
	if err != nil {
		t.Fatalf("Failed to create signer2: %v", err)
	}

	// Create validator with signer1's public key
	validator := NewSecureInvitationValidator(signer1.PublicKey)
	defer validator.Stop()

	// Create and sign invitation with signer2
	invitation := createTestInvitationCode(t)
	err = invitation.Sign(signer2)
	if err != nil {
		t.Fatalf("Failed to sign invitation: %v", err)
	}

	// Encode the invitation
	processor := NewInvitationCodeProcessor()
	invitationData, err := processor.EncodeToBase64(invitation)
	if err != nil {
		t.Fatalf("Failed to encode invitation: %v", err)
	}

	// Validation should fail due to signature mismatch
	_, err = validator.ValidateAndProcessInvitation(invitationData, "192.168.1.100:12345")
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestErrorHandlingSecurityManager(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	// Test with nil invitation
	err := manager.ValidateAndMarkUsed(nil, "192.168.1.100:12345")
	if err == nil {
		t.Error("Expected error for nil invitation")
	}

	used, err := manager.IsInvitationUsed(nil)
	if err == nil {
		t.Error("Expected error for nil invitation in IsInvitationUsed")
	}
	if used {
		t.Error("Nil invitation should not be marked as used")
	}

	record, err := manager.GetUsageRecord(nil)
	if err == nil {
		t.Error("Expected error for nil invitation in GetUsageRecord")
	}
	if record != nil {
		t.Error("Should not get usage record for nil invitation")
	}

	err = manager.RevokeInvitation(nil, "test")
	if err == nil {
		t.Error("Expected error for nil invitation in RevokeInvitation")
	}
}

func TestInvitationHashConsistency(t *testing.T) {
	manager := NewInvitationSecurityManager(1*time.Minute, 1*time.Hour)
	defer manager.Stop()

	invitation := createTestInvitationCode(t)

	// Generate hash multiple times - should be consistent
	hash1, err := manager.generateInvitationHash(invitation)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	hash2, err := manager.generateInvitationHash(invitation)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if hash1 != hash2 {
		t.Error("Hash should be consistent for same invitation")
	}

	// Different invitations should have different hashes
	invitation2 := createTestInvitationCode(t)
	hash3, err := manager.generateInvitationHash(invitation2)
	if err != nil {
		t.Fatalf("Failed to generate hash for second invitation: %v", err)
	}

	if hash1 == hash3 {
		t.Error("Different invitations should have different hashes")
	}
}