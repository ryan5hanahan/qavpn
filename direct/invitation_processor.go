package direct

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// DefaultInvitationCodeProcessor implements the InvitationCodeProcessor interface
type DefaultInvitationCodeProcessor struct {
	// Future: could add configuration options here
}

// NewInvitationCodeProcessor creates a new invitation code processor
func NewInvitationCodeProcessor() InvitationCodeProcessor {
	return &DefaultInvitationCodeProcessor{}
}

// Format constants for invitation codes
const (
	FormatPrefix    = "QAVPN-DIRECT-v1:"
	FormatBase64    = "base64"
	FormatHex       = "hex"
	FormatJSON      = "json"
	FormatQR        = "qr"
	FormatUnknown   = "unknown"
)

// Encoding format detection errors
var (
	ErrUnknownFormat     = errors.New("unknown invitation code format")
	ErrInvalidPrefix     = errors.New("invalid invitation code prefix")
	ErrInvalidEncoding   = errors.New("invalid encoding format")
	ErrQRNotImplemented  = errors.New("QR code generation not implemented yet")
)

// EncodeToBase64 encodes an invitation code to base64 format
func (p *DefaultInvitationCodeProcessor) EncodeToBase64(invitation *InvitationCode) (string, error) {
	if invitation == nil {
		return "", errors.New("invitation code is nil")
	}

	// Serialize to JSON first
	jsonData, err := json.Marshal(invitation)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation to JSON: %w", err)
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	// Add format prefix
	return FormatPrefix + encoded, nil
}

// DecodeFromBase64 decodes an invitation code from base64 format
func (p *DefaultInvitationCodeProcessor) DecodeFromBase64(data string) (*InvitationCode, error) {
	if data == "" {
		return nil, errors.New("invitation data is empty")
	}

	// Check and remove prefix
	if !strings.HasPrefix(data, FormatPrefix) {
		return nil, ErrInvalidPrefix
	}

	encodedData := data[len(FormatPrefix):]
	if encodedData == "" {
		return nil, errors.New("no data after prefix")
	}

	// Decode from base64
	jsonData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %w", err)
	}

	// Unmarshal from JSON
	var invitation InvitationCode
	if err := json.Unmarshal(jsonData, &invitation); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON data: %w", err)
	}

	return &invitation, nil
}

// EncodeToHex encodes an invitation code to hex format for manual entry
func (p *DefaultInvitationCodeProcessor) EncodeToHex(invitation *InvitationCode) (string, error) {
	if invitation == nil {
		return "", errors.New("invitation code is nil")
	}

	// Serialize to JSON first
	jsonData, err := json.Marshal(invitation)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation to JSON: %w", err)
	}

	// Encode to hex
	encoded := hex.EncodeToString(jsonData)

	// Add format prefix and hex indicator
	return FormatPrefix + "hex:" + encoded, nil
}

// DecodeFromHex decodes an invitation code from hex format
func (p *DefaultInvitationCodeProcessor) DecodeFromHex(data string) (*InvitationCode, error) {
	if data == "" {
		return nil, errors.New("invitation data is empty")
	}

	// Check and remove prefix
	if !strings.HasPrefix(data, FormatPrefix) {
		return nil, ErrInvalidPrefix
	}

	remaining := data[len(FormatPrefix):]
	
	// Check for hex indicator
	if !strings.HasPrefix(remaining, "hex:") {
		return nil, fmt.Errorf("expected hex format indicator, got: %s", remaining[:min(10, len(remaining))])
	}

	encodedData := remaining[4:] // Remove "hex:"
	if encodedData == "" {
		return nil, errors.New("no data after hex indicator")
	}

	// Decode from hex
	jsonData, err := hex.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex data: %w", err)
	}

	// Unmarshal from JSON
	var invitation InvitationCode
	if err := json.Unmarshal(jsonData, &invitation); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON data: %w", err)
	}

	return &invitation, nil
}

// GenerateQRCode generates a QR code for the invitation code
// Note: This is a placeholder implementation. In a real implementation,
// you would use a QR code library like github.com/skip2/go-qrcode
func (p *DefaultInvitationCodeProcessor) GenerateQRCode(invitation *InvitationCode) ([]byte, error) {
	if invitation == nil {
		return nil, errors.New("invitation code is nil")
	}

	// For now, return an error indicating QR code generation is not implemented
	// In a real implementation, this would:
	// 1. Encode the invitation to base64
	// 2. Generate a QR code containing the base64 data
	// 3. Return the QR code as PNG bytes
	
	// Get the base64 encoded data that would go in the QR code
	base64Data, err := p.EncodeToBase64(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to encode invitation for QR code: %w", err)
	}

	// Placeholder: return a simple representation
	// In real implementation: return qrcode.Encode(base64Data, qrcode.Medium, 256)
	qrData := fmt.Sprintf("QR-CODE-PLACEHOLDER: %s", base64Data)
	return []byte(qrData), nil
}

// DetectFormat attempts to detect the format of invitation code data
func (p *DefaultInvitationCodeProcessor) DetectFormat(data string) string {
	if data == "" {
		return FormatUnknown
	}

	// Check for our format prefix
	if !strings.HasPrefix(data, FormatPrefix) {
		// Check if it looks like raw JSON
		if strings.HasPrefix(strings.TrimSpace(data), "{") {
			return FormatJSON
		}
		return FormatUnknown
	}

	remaining := data[len(FormatPrefix):]
	
	// Check for hex format
	if strings.HasPrefix(remaining, "hex:") {
		return FormatHex
	}

	// Check if it looks like base64 (no special indicators)
	// Base64 characters are A-Z, a-z, 0-9, +, /, =
	isBase64 := true
	for _, char := range remaining {
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '+' || char == '/' || char == '=') {
			isBase64 = false
			break
		}
	}

	if isBase64 {
		return FormatBase64
	}

	return FormatUnknown
}

// DecodeAuto automatically detects the format and decodes the invitation code
func (p *DefaultInvitationCodeProcessor) DecodeAuto(data string) (*InvitationCode, error) {
	if data == "" {
		return nil, errors.New("invitation data is empty")
	}

	format := p.DetectFormat(data)
	
	switch format {
	case FormatBase64:
		return p.DecodeFromBase64(data)
	case FormatHex:
		return p.DecodeFromHex(data)
	case FormatJSON:
		// Handle raw JSON format
		var invitation InvitationCode
		if err := json.Unmarshal([]byte(data), &invitation); err != nil {
			return nil, fmt.Errorf("failed to unmarshal raw JSON: %w", err)
		}
		return &invitation, nil
	default:
		return nil, fmt.Errorf("%w: detected format %s", ErrUnknownFormat, format)
	}
}

// ValidateFormat validates that the invitation data has a valid format
func (p *DefaultInvitationCodeProcessor) ValidateFormat(invitationData string) error {
	if invitationData == "" {
		return errors.New("invitation data is empty")
	}

	format := p.DetectFormat(invitationData)
	if format == FormatUnknown {
		return ErrUnknownFormat
	}

	// Try to decode to ensure the format is actually valid
	_, err := p.DecodeAuto(invitationData)
	if err != nil {
		return fmt.Errorf("format validation failed: %w", err)
	}

	return nil
}

// EncodeToFormat encodes an invitation code to the specified format
func (p *DefaultInvitationCodeProcessor) EncodeToFormat(invitation *InvitationCode, format string) (string, error) {
	if invitation == nil {
		return "", errors.New("invitation code is nil")
	}

	switch format {
	case FormatBase64:
		return p.EncodeToBase64(invitation)
	case FormatHex:
		return p.EncodeToHex(invitation)
	case FormatJSON:
		jsonData, err := json.Marshal(invitation)
		if err != nil {
			return "", fmt.Errorf("failed to marshal to JSON: %w", err)
		}
		return string(jsonData), nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// GetSupportedFormats returns a list of supported encoding formats
func (p *DefaultInvitationCodeProcessor) GetSupportedFormats() []string {
	return []string{FormatBase64, FormatHex, FormatJSON}
}

// Helper function for min (Go 1.21 doesn't have built-in min for int)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ValidateSignature validates the signature of an invitation code
func (p *DefaultInvitationCodeProcessor) ValidateSignature(invitation *InvitationCode) error {
	if invitation == nil {
		return errors.New("invitation code is nil")
	}

	// This method requires a public key to validate against
	// For now, we'll return an error indicating that the signer public key is needed
	// In a real implementation, this would be called with a specific signer's public key
	return errors.New("ValidateSignature requires a signer public key - use invitation.ValidateSignature(signerPublicKey) instead")
}

// ValidateExpiration validates that the invitation code has not expired
func (p *DefaultInvitationCodeProcessor) ValidateExpiration(invitation *InvitationCode) error {
	if invitation == nil {
		return errors.New("invitation code is nil")
	}

	return invitation.validateExpiration()
}

// ValidateIntegrity validates the overall integrity of the invitation code
func (p *DefaultInvitationCodeProcessor) ValidateIntegrity(invitation *InvitationCode) error {
	if invitation == nil {
		return errors.New("invitation code is nil")
	}

	// Perform comprehensive validation
	return invitation.Validate()
}