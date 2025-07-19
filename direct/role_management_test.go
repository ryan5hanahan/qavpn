package direct

import (
	"testing"
	"time"
)

func TestConnectionRoleCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		role1      ConnectionRole
		role2      ConnectionRole
		compatible bool
		conflict   bool
	}{
		{
			name:       "Listener and Connector are compatible",
			role1:      RoleListener,
			role2:      RoleConnector,
			compatible: true,
			conflict:   false,
		},
		{
			name:       "Connector and Listener are compatible",
			role1:      RoleConnector,
			role2:      RoleListener,
			compatible: true,
			conflict:   false,
		},
		{
			name:       "Two Listeners have conflict",
			role1:      RoleListener,
			role2:      RoleListener,
			compatible: false,
			conflict:   true,
		},
		{
			name:       "Two Connectors have conflict",
			role1:      RoleConnector,
			role2:      RoleConnector,
			compatible: false,
			conflict:   true,
		},
		{
			name:       "Negotiating roles don't conflict",
			role1:      RoleNegotiating,
			role2:      RoleNegotiating,
			compatible: false,
			conflict:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role1.IsCompatible(tt.role2); got != tt.compatible {
				t.Errorf("IsCompatible() = %v, want %v", got, tt.compatible)
			}

			if got := tt.role1.HasConflict(tt.role2); got != tt.conflict {
				t.Errorf("HasConflict() = %v, want %v", got, tt.conflict)
			}
		})
	}
}

func TestDetectRoleConflict(t *testing.T) {
	tests := []struct {
		name           string
		localRole      ConnectionRole
		remoteRole     ConnectionRole
		expectConflict bool
		conflictType   RoleConflictType
		autoResolvable bool
	}{
		{
			name:           "No conflict - Listener and Connector",
			localRole:      RoleListener,
			remoteRole:     RoleConnector,
			expectConflict: false,
		},
		{
			name:           "Conflict - Both Listeners",
			localRole:      RoleListener,
			remoteRole:     RoleListener,
			expectConflict: true,
			conflictType:   ConflictBothListeners,
			autoResolvable: true,
		},
		{
			name:           "Conflict - Both Connectors",
			localRole:      RoleConnector,
			remoteRole:     RoleConnector,
			expectConflict: true,
			conflictType:   ConflictBothConnectors,
			autoResolvable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflict := DetectRoleConflict(tt.localRole, tt.remoteRole)

			if tt.expectConflict {
				if conflict == nil {
					t.Fatal("Expected conflict but got none")
				}

				if conflict.ConflictType != tt.conflictType {
					t.Errorf("ConflictType = %v, want %v", conflict.ConflictType, tt.conflictType)
				}

				if conflict.AutoResolvable != tt.autoResolvable {
					t.Errorf("AutoResolvable = %v, want %v", conflict.AutoResolvable, tt.autoResolvable)
				}

				if conflict.LocalRole != tt.localRole {
					t.Errorf("LocalRole = %v, want %v", conflict.LocalRole, tt.localRole)
				}

				if conflict.RemoteRole != tt.remoteRole {
					t.Errorf("RemoteRole = %v, want %v", conflict.RemoteRole, tt.remoteRole)
				}
			} else {
				if conflict != nil {
					t.Errorf("Expected no conflict but got: %+v", conflict)
				}
			}
		})
	}
}

func TestResolveRoleConflict(t *testing.T) {
	tests := []struct {
		name           string
		localRole      ConnectionRole
		localPriority  uint32
		remoteRole     ConnectionRole
		remotePriority uint32
		expectedRole   ConnectionRole
		expectError    bool
	}{
		{
			name:           "Both Listeners - Higher priority becomes Connector",
			localRole:      RoleListener,
			localPriority:  1000,
			remoteRole:     RoleListener,
			remotePriority: 500,
			expectedRole:   RoleConnector,
			expectError:    false,
		},
		{
			name:           "Both Listeners - Lower priority stays Listener",
			localRole:      RoleListener,
			localPriority:  500,
			remoteRole:     RoleListener,
			remotePriority: 1000,
			expectedRole:   RoleListener,
			expectError:    false,
		},
		{
			name:           "Both Connectors - Higher priority becomes Listener",
			localRole:      RoleConnector,
			localPriority:  1000,
			remoteRole:     RoleConnector,
			remotePriority: 500,
			expectedRole:   RoleListener,
			expectError:    false,
		},
		{
			name:           "Both Connectors - Lower priority stays Connector",
			localRole:      RoleConnector,
			localPriority:  500,
			remoteRole:     RoleConnector,
			remotePriority: 1000,
			expectedRole:   RoleConnector,
			expectError:    false,
		},
		{
			name:           "Equal priorities - Both Listeners default to Connector",
			localRole:      RoleListener,
			localPriority:  500,
			remoteRole:     RoleListener,
			remotePriority: 500,
			expectedRole:   RoleConnector,
			expectError:    false,
		},
		{
			name:           "Equal priorities - Both Connectors default to Listener",
			localRole:      RoleConnector,
			localPriority:  500,
			remoteRole:     RoleConnector,
			remotePriority: 500,
			expectedRole:   RoleListener,
			expectError:    false,
		},
		{
			name:           "No conflict - Compatible roles",
			localRole:      RoleListener,
			localPriority:  500,
			remoteRole:     RoleConnector,
			remotePriority: 500,
			expectedRole:   RoleListener,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvedRole, err := ResolveRoleConflict(
				tt.localRole,
				tt.localPriority,
				tt.remoteRole,
				tt.remotePriority,
			)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}

				if resolvedRole != tt.expectedRole {
					t.Errorf("ResolvedRole = %v, want %v", resolvedRole, tt.expectedRole)
				}
			}
		})
	}
}

func TestGenerateRolePriority(t *testing.T) {
	// Test that priority generation works and produces different values
	priorities := make(map[uint32]bool)
	
	for i := 0; i < 100; i++ {
		priority := GenerateRolePriority()
		if priority == 0 {
			t.Error("Generated priority should not be zero")
		}
		priorities[priority] = true
	}

	// We should have generated multiple different priorities
	if len(priorities) < 50 {
		t.Errorf("Expected at least 50 different priorities, got %d", len(priorities))
	}
}

func TestCreateHandshakeMessage(t *testing.T) {
	connectionID, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	tests := []struct {
		name     string
		msgType  HandshakeMessageType
		role     ConnectionRole
		priority uint32
	}{
		{
			name:     "Init message for Listener",
			msgType:  HandshakeInit,
			role:     RoleListener,
			priority: 1000,
		},
		{
			name:     "Response message for Connector",
			msgType:  HandshakeResponse,
			role:     RoleConnector,
			priority: 2000,
		},
		{
			name:     "Role negotiation message",
			msgType:  HandshakeRoleNegotiation,
			role:     RoleNegotiating,
			priority: 1500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := CreateHandshakeMessage(tt.msgType, connectionID, tt.role, tt.priority)
			if err != nil {
				t.Fatalf("CreateHandshakeMessage() error = %v", err)
			}

			if message.Type != tt.msgType {
				t.Errorf("Type = %v, want %v", message.Type, tt.msgType)
			}

			if message.ConnectionID != connectionID {
				t.Errorf("ConnectionID mismatch")
			}

			if message.ProposedRole != tt.role {
				t.Errorf("ProposedRole = %v, want %v", message.ProposedRole, tt.role)
			}

			if message.Priority != tt.priority {
				t.Errorf("Priority = %v, want %v", message.Priority, tt.priority)
			}

			if len(message.Capabilities) == 0 {
				t.Error("Capabilities should not be empty")
			}

			if message.Timestamp.IsZero() {
				t.Error("Timestamp should be set")
			}

			// Check that nonce is not zero
			var zeroNonce [16]byte
			if message.Nonce == zeroNonce {
				t.Error("Nonce should not be zero")
			}
		})
	}
}

func TestValidateHandshakeMessage(t *testing.T) {
	connectionID, err := GenerateConnectionID()
	if err != nil {
		t.Fatalf("Failed to generate connection ID: %v", err)
	}

	validMessage, err := CreateHandshakeMessage(HandshakeInit, connectionID, RoleListener, 1000)
	if err != nil {
		t.Fatalf("Failed to create valid message: %v", err)
	}

	tests := []struct {
		name        string
		message     *HandshakeMessage
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid message",
			message:     validMessage,
			expectError: false,
		},
		{
			name:        "Nil message",
			message:     nil,
			expectError: true,
			errorMsg:    "handshake message is nil",
		},
		{
			name: "Invalid connection ID",
			message: &HandshakeMessage{
				Type:         HandshakeInit,
				ConnectionID: [16]byte{}, // Zero connection ID
				ProposedRole: RoleListener,
				Priority:     1000,
				Timestamp:    time.Now(),
				Nonce:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			expectError: true,
			errorMsg:    "invalid connection ID",
		},
		{
			name: "Future timestamp",
			message: &HandshakeMessage{
				Type:         HandshakeInit,
				ConnectionID: connectionID,
				ProposedRole: RoleListener,
				Priority:     1000,
				Timestamp:    time.Now().Add(10 * time.Minute), // Too far in future
				Nonce:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			expectError: true,
			errorMsg:    "handshake message timestamp is too far in the future",
		},
		{
			name: "Old timestamp",
			message: &HandshakeMessage{
				Type:         HandshakeInit,
				ConnectionID: connectionID,
				ProposedRole: RoleListener,
				Priority:     1000,
				Timestamp:    time.Now().Add(-15 * time.Minute), // Too old
				Nonce:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			expectError: true,
			errorMsg:    "handshake message timestamp is too old",
		},
		{
			name: "Invalid nonce",
			message: &HandshakeMessage{
				Type:         HandshakeInit,
				ConnectionID: connectionID,
				ProposedRole: RoleListener,
				Priority:     1000,
				Timestamp:    time.Now(),
				Nonce:        [16]byte{}, // Zero nonce
			},
			expectError: true,
			errorMsg:    "invalid nonce",
		},
		{
			name: "Invalid role",
			message: &HandshakeMessage{
				Type:         HandshakeInit,
				ConnectionID: connectionID,
				ProposedRole: ConnectionRole(99), // Invalid role
				Priority:     1000,
				Timestamp:    time.Now(),
				Nonce:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			expectError: true,
			errorMsg:    "invalid proposed role: 99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHandshakeMessage(tt.message)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Error message = %v, want %v", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestHandshakeMessageTypeString(t *testing.T) {
	tests := []struct {
		msgType  HandshakeMessageType
		expected string
	}{
		{HandshakeInit, "init"},
		{HandshakeResponse, "response"},
		{HandshakeConfirm, "confirm"},
		{HandshakeReject, "reject"},
		{HandshakeRoleNegotiation, "role_negotiation"},
		{HandshakeMessageType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.msgType.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRoleConflictTypeString(t *testing.T) {
	tests := []struct {
		conflictType RoleConflictType
		expected     string
	}{
		{ConflictBothListeners, "both_listeners"},
		{ConflictBothConnectors, "both_connectors"},
		{ConflictIncompatibleCapabilities, "incompatible_capabilities"},
		{ConflictNetworkConfiguration, "network_configuration"},
		{RoleConflictType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.conflictType.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHandshakePhaseString(t *testing.T) {
	tests := []struct {
		phase    HandshakePhase
		expected string
	}{
		{PhaseInit, "init"},
		{PhaseRoleNegotiation, "role_negotiation"},
		{PhaseKeyExchange, "key_exchange"},
		{PhaseConfirmation, "confirmation"},
		{PhaseComplete, "complete"},
		{PhaseError, "error"},
		{HandshakePhase(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.phase.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}