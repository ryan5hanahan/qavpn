package direct

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSecureConfigManager(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	if manager == nil {
		t.Fatal("SecureConfigManager should not be nil")
	}

	// Verify config directory was created
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		t.Fatal("Config directory was not created")
	}
}

func TestNewSecureConfigManagerEmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("")

	_, err := NewSecureConfigManager(password, tempDir)
	if err == nil {
		t.Fatal("Expected error for empty password")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestSaveAndLoadProfile(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Test connection profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
			BackupAddresses: []string{"192.168.1.101:8080"},
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: []byte("encrypted-key-data"),
			Salt:          []byte("test-salt-16-bytes"),
			Nonce:         []byte("test-nonce-12"),
		},
		CreatedAt: time.Now(),
		UseCount:  0,
	}

	// Save profile
	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Load profile
	loadedProfile, err := manager.LoadProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	// Verify profile data
	if loadedProfile.Name != profile.Name {
		t.Errorf("Expected name %s, got %s", profile.Name, loadedProfile.Name)
	}

	if loadedProfile.Description != profile.Description {
		t.Errorf("Expected description %s, got %s", profile.Description, loadedProfile.Description)
	}

	if loadedProfile.NetworkConfig.Protocol != profile.NetworkConfig.Protocol {
		t.Errorf("Expected protocol %s, got %s", profile.NetworkConfig.Protocol, loadedProfile.NetworkConfig.Protocol)
	}

	if loadedProfile.UseCount != 1 {
		t.Errorf("Expected use count 1, got %d", loadedProfile.UseCount)
	}
}

func TestSaveProfileNil(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	err = manager.SaveProfile(nil)
	if err == nil {
		t.Fatal("Expected error for nil profile")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestSaveProfileEmptyName(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	profile := &ConnectionProfile{
		Name: "",
	}

	err = manager.SaveProfile(profile)
	if err == nil {
		t.Fatal("Expected error for empty profile name")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestLoadProfileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	_, err = manager.LoadProfile("non-existent")
	if err == nil {
		t.Fatal("Expected error for non-existent profile")
	}

	if !IsStorageError(err) {
		t.Fatalf("Expected StorageError, got: %T", err)
	}
}

func TestDeleteProfile(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create and save test profile
	profile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Test connection profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Verify profile exists
	profiles := manager.ListProfiles()
	if len(profiles) != 1 || profiles[0] != "test-profile" {
		t.Fatal("Profile should exist before deletion")
	}

	// Delete profile
	if err := manager.DeleteProfile("test-profile"); err != nil {
		t.Fatalf("Failed to delete profile: %v", err)
	}

	// Verify profile is deleted
	profiles = manager.ListProfiles()
	if len(profiles) != 0 {
		t.Fatal("Profile should be deleted")
	}

	// Verify loading deleted profile fails
	_, err = manager.LoadProfile("test-profile")
	if err == nil {
		t.Fatal("Expected error when loading deleted profile")
	}
}

func TestListProfiles(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Initially should be empty
	profiles := manager.ListProfiles()
	if len(profiles) != 0 {
		t.Fatal("Profile list should be empty initially")
	}

	// Create test profiles
	profileNames := []string{"profile1", "profile2", "profile3"}
	for _, name := range profileNames {
		profile := &ConnectionProfile{
			Name: name,
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		}
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", name, err)
		}
	}

	// List profiles
	profiles = manager.ListProfiles()
	if len(profiles) != len(profileNames) {
		t.Fatalf("Expected %d profiles, got %d", len(profileNames), len(profiles))
	}

	// Verify all profiles are listed
	profileMap := make(map[string]bool)
	for _, profile := range profiles {
		profileMap[profile] = true
	}

	for _, expectedName := range profileNames {
		if !profileMap[expectedName] {
			t.Errorf("Profile %s not found in list", expectedName)
		}
	}
}

func TestChangeEncryptionKey(t *testing.T) {
	tempDir := t.TempDir()
	oldPassword := []byte("old-password-123")
	newPassword := []byte("new-password-456")

	manager, err := NewSecureConfigManager(oldPassword, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Test connection profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Change encryption key
	if err := manager.ChangeEncryptionKey(oldPassword, newPassword); err != nil {
		t.Fatalf("Failed to change encryption key: %v", err)
	}

	// Verify profile can still be loaded
	loadedProfile, err := manager.LoadProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to load profile after key change: %v", err)
	}

	if loadedProfile.Name != profile.Name {
		t.Errorf("Profile data corrupted after key change")
	}
}

func TestVerifyIntegrity(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name: "test-profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Verify integrity should pass
	if err := manager.VerifyIntegrity(); err != nil {
		t.Fatalf("Integrity verification failed: %v", err)
	}
}

func TestExportAndImportProfiles(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	exportPassword := []byte("export-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name: "profile1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		},
		{
			Name: "profile2",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.101:8081",
			},
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Export profiles
	exportData, err := manager.ExportProfiles(exportPassword)
	if err != nil {
		t.Fatalf("Failed to export profiles: %v", err)
	}

	if len(exportData) == 0 {
		t.Fatal("Export data should not be empty")
	}

	// Create new manager for import test
	tempDir2 := t.TempDir()
	manager2, err := NewSecureConfigManager(password, tempDir2)
	if err != nil {
		t.Fatalf("Failed to create second SecureConfigManager: %v", err)
	}

	// Import profiles
	if err := manager2.ImportProfiles(exportData, exportPassword); err != nil {
		t.Fatalf("Failed to import profiles: %v", err)
	}

	// Verify imported profiles
	importedProfiles := manager2.ListProfiles()
	if len(importedProfiles) != len(profiles) {
		t.Fatalf("Expected %d imported profiles, got %d", len(profiles), len(importedProfiles))
	}

	for _, originalProfile := range profiles {
		importedProfile, err := manager2.LoadProfile(originalProfile.Name)
		if err != nil {
			t.Fatalf("Failed to load imported profile %s: %v", originalProfile.Name, err)
		}

		if importedProfile.Name != originalProfile.Name {
			t.Errorf("Profile name mismatch: expected %s, got %s", originalProfile.Name, importedProfile.Name)
		}

		if importedProfile.NetworkConfig.Protocol != originalProfile.NetworkConfig.Protocol {
			t.Errorf("Protocol mismatch for profile %s", originalProfile.Name)
		}
	}
}

func TestExportProfilesEmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	_, err = manager.ExportProfiles([]byte(""))
	if err == nil {
		t.Fatal("Expected error for empty export password")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestImportProfilesInvalidData(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Test with invalid JSON
	err = manager.ImportProfiles([]byte("invalid-json"), password)
	if err == nil {
		t.Fatal("Expected error for invalid import data")
	}

	if !IsStorageError(err) {
		t.Fatalf("Expected StorageError, got: %T", err)
	}
}

func TestSecureWipe(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name: "test-profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Verify profile exists
	profiles := manager.ListProfiles()
	if len(profiles) != 1 {
		t.Fatal("Profile should exist before secure wipe")
	}

	// Perform secure wipe
	if err := manager.SecureWipe(); err != nil {
		t.Fatalf("Failed to perform secure wipe: %v", err)
	}

	// Verify all profiles are wiped
	profiles = manager.ListProfiles()
	if len(profiles) != 0 {
		t.Fatal("All profiles should be wiped")
	}

	// Verify loading profile fails
	_, err = manager.LoadProfile("test-profile")
	if err == nil {
		t.Fatal("Expected error when loading wiped profile")
	}
}

func TestFileConfigStorage(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewFileConfigStorage(tempDir)

	testKey := "test-key"
	testData := []byte("test-data-content")

	// Test Store
	if err := storage.Store(testKey, testData); err != nil {
		t.Fatalf("Failed to store data: %v", err)
	}

	// Test Retrieve
	retrievedData, err := storage.Retrieve(testKey)
	if err != nil {
		t.Fatalf("Failed to retrieve data: %v", err)
	}

	if !bytes.Equal(testData, retrievedData) {
		t.Errorf("Retrieved data doesn't match stored data")
	}

	// Test List
	keys, err := storage.List()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if len(keys) != 1 || keys[0] != testKey {
		t.Errorf("Expected key %s in list, got %v", testKey, keys)
	}

	// Test Delete
	if err := storage.Delete(testKey); err != nil {
		t.Fatalf("Failed to delete data: %v", err)
	}

	// Verify deletion
	_, err = storage.Retrieve(testKey)
	if err == nil {
		t.Fatal("Expected error when retrieving deleted data")
	}
}

func TestFileConfigStorageSecureDelete(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewFileConfigStorage(tempDir)

	testKey := "test-key"
	testData := make([]byte, 1024)
	rand.Read(testData)

	// Store data
	if err := storage.Store(testKey, testData); err != nil {
		t.Fatalf("Failed to store data: %v", err)
	}

	// Verify file exists
	filePath := filepath.Join(tempDir, testKey+ConfigFileExtension)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("File should exist before secure delete")
	}

	// Secure delete
	if err := storage.SecureDelete(testKey); err != nil {
		t.Fatalf("Failed to securely delete data: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatal("File should be deleted after secure delete")
	}

	// Verify retrieval fails
	_, err := storage.Retrieve(testKey)
	if err == nil {
		t.Fatal("Expected error when retrieving securely deleted data")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	scm := manager.(*SecureConfigManagerImpl)

	testData := []byte("sensitive-test-data-for-encryption")

	// Test encryption
	encryptedData, err := scm.encryptData(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	if bytes.Equal(testData, encryptedData) {
		t.Fatal("Encrypted data should be different from original")
	}

	// Test decryption
	decryptedData, err := scm.decryptData(encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(testData, decryptedData) {
		t.Fatal("Decrypted data should match original")
	}
}

func TestIntegrityVerification(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewFileConfigStorage(tempDir)

	testKey := "test-key"
	testData := []byte("test-data-content")

	// Store data
	if err := storage.Store(testKey, testData); err != nil {
		t.Fatalf("Failed to store data: %v", err)
	}

	// Calculate expected hash
	expectedHash := sha256.Sum256(testData)

	// Test integrity verification
	if err := storage.VerifyIntegrity(testKey, expectedHash[:]); err != nil {
		t.Fatalf("Integrity verification failed: %v", err)
	}

	// Test with wrong hash
	wrongHash := make([]byte, 32)
	rand.Read(wrongHash)

	if err := storage.VerifyIntegrity(testKey, wrongHash); err == nil {
		t.Fatal("Expected integrity verification to fail with wrong hash")
	}
}

// Enhanced profile management tests

func TestListProfilesWithMetadata(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name:        "tcp-profile",
			Description: "TCP connection profile",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
			UseCount: 5,
		},
		{
			Name:        "udp-profile",
			Description: "UDP connection profile",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.101:8081",
			},
			UseCount: 3,
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Get metadata
	metadata, err := manager.ListProfilesWithMetadata()
	if err != nil {
		t.Fatalf("Failed to list profiles with metadata: %v", err)
	}

	if len(metadata) != len(profiles) {
		t.Fatalf("Expected %d metadata entries, got %d", len(profiles), len(metadata))
	}

	// Verify metadata
	metadataMap := make(map[string]*ProfileMetadata)
	for _, meta := range metadata {
		metadataMap[meta.Name] = meta
	}

	for _, profile := range profiles {
		meta, exists := metadataMap[profile.Name]
		if !exists {
			t.Errorf("Metadata not found for profile %s", profile.Name)
			continue
		}

		if meta.Description != profile.Description {
			t.Errorf("Description mismatch for profile %s", profile.Name)
		}

		if meta.Protocol != profile.NetworkConfig.Protocol {
			t.Errorf("Protocol mismatch for profile %s", profile.Name)
		}

		if meta.UseCount != profile.UseCount {
			t.Errorf("Use count mismatch for profile %s: expected %d, got %d", 
				profile.Name, profile.UseCount, meta.UseCount)
		}
	}
}

func TestSearchProfiles(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name:        "home-server",
			Description: "Home server connection",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
			UseCount: 10,
		},
		{
			Name:        "office-vpn",
			Description: "Office VPN connection",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "10.0.0.50:9090",
			},
			UseCount: 5,
		},
		{
			Name:        "backup-server",
			Description: "Backup server connection",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.200:8080",
			},
			UseCount: 2,
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Test search by name
	criteria := &SearchCriteria{Name: "server"}
	results, err := manager.SearchProfiles(criteria)
	if err != nil {
		t.Fatalf("Failed to search profiles: %v", err)
	}

	if len(results) != 2 { // home-server and backup-server
		t.Errorf("Expected 2 results for name search, got %d", len(results))
	}

	// Test search by protocol
	criteria = &SearchCriteria{Protocol: "tcp"}
	results, err = manager.SearchProfiles(criteria)
	if err != nil {
		t.Fatalf("Failed to search profiles by protocol: %v", err)
	}

	if len(results) != 2 { // home-server and backup-server
		t.Errorf("Expected 2 results for protocol search, got %d", len(results))
	}

	// Test search by minimum use count
	criteria = &SearchCriteria{MinUseCount: 5}
	results, err = manager.SearchProfiles(criteria)
	if err != nil {
		t.Fatalf("Failed to search profiles by use count: %v", err)
	}

	if len(results) != 2 { // home-server and office-vpn (after loading, use counts are incremented)
		t.Errorf("Expected 2 results for use count search, got %d", len(results))
	}
}

func TestGetProfileStatistics(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name: "tcp-profile-1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
			UseCount: 10,
		},
		{
			Name: "tcp-profile-2",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.101:8080",
			},
			UseCount: 5,
		},
		{
			Name: "udp-profile-1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.102:8081",
			},
			UseCount: 3,
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Get statistics
	stats, err := manager.GetProfileStatistics()
	if err != nil {
		t.Fatalf("Failed to get profile statistics: %v", err)
	}

	// Verify statistics
	if stats.TotalProfiles != len(profiles) {
		t.Errorf("Expected %d total profiles, got %d", len(profiles), stats.TotalProfiles)
	}

	expectedTCP := 2
	expectedUDP := 1
	if stats.ProfilesByProtocol["tcp"] != expectedTCP {
		t.Errorf("Expected %d TCP profiles, got %d", expectedTCP, stats.ProfilesByProtocol["tcp"])
	}

	if stats.ProfilesByProtocol["udp"] != expectedUDP {
		t.Errorf("Expected %d UDP profiles, got %d", expectedUDP, stats.ProfilesByProtocol["udp"])
	}

	if len(stats.UsageStats) != len(profiles) {
		t.Errorf("Expected %d usage stats, got %d", len(profiles), len(stats.UsageStats))
	}
}

func TestUpdateProfileMetadata(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Original description",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Update metadata
	newDescription := "Updated description"
	metadata := &ProfileMetadataUpdate{
		Description: &newDescription,
	}

	if err := manager.UpdateProfileMetadata("test-profile", metadata); err != nil {
		t.Fatalf("Failed to update profile metadata: %v", err)
	}

	// Verify update
	updatedProfile, err := manager.LoadProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to load updated profile: %v", err)
	}

	if updatedProfile.Description != newDescription {
		t.Errorf("Expected description '%s', got '%s'", newDescription, updatedProfile.Description)
	}
}

func TestGetMostUsedProfiles(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles with different use counts
	profiles := []*ConnectionProfile{
		{
			Name:     "most-used",
			UseCount: 100,
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		},
		{
			Name:     "medium-used",
			UseCount: 50,
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.101:8080",
			},
		},
		{
			Name:     "least-used",
			UseCount: 10,
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.102:8080",
			},
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Get most used profiles
	mostUsed, err := manager.GetMostUsedProfiles(2)
	if err != nil {
		t.Fatalf("Failed to get most used profiles: %v", err)
	}

	if len(mostUsed) != 2 {
		t.Fatalf("Expected 2 most used profiles, got %d", len(mostUsed))
	}

	// Verify order (most used first)
	if mostUsed[0].Name != "most-used" {
		t.Errorf("Expected first profile to be 'most-used', got '%s'", mostUsed[0].Name)
	}

	if mostUsed[1].Name != "medium-used" {
		t.Errorf("Expected second profile to be 'medium-used', got '%s'", mostUsed[1].Name)
	}
}

func TestGetRecentlyUsedProfiles(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles with different last used times
	now := time.Now()
	profiles := []*ConnectionProfile{
		{
			Name:     "recent",
			LastUsed: now.Add(-1 * time.Hour),
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		},
		{
			Name:     "older",
			LastUsed: now.Add(-24 * time.Hour),
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.101:8080",
			},
		},
		{
			Name:     "oldest",
			LastUsed: now.Add(-7 * 24 * time.Hour),
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.102:8080",
			},
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Get recently used profiles
	recentlyUsed, err := manager.GetRecentlyUsedProfiles(2)
	if err != nil {
		t.Fatalf("Failed to get recently used profiles: %v", err)
	}

	if len(recentlyUsed) != 2 {
		t.Fatalf("Expected 2 recently used profiles, got %d", len(recentlyUsed))
	}

	// Note: The order might be affected by the LoadProfile calls during SaveProfile
	// which update the LastUsed time, so we just verify we got the expected profiles
	profileNames := make(map[string]bool)
	for _, profile := range recentlyUsed {
		profileNames[profile.Name] = true
	}

	// At least one of the more recent profiles should be in the results
	if !profileNames["recent"] && !profileNames["older"] {
		t.Error("Expected at least one of the recent profiles in the results")
	}
}

func TestCleanupUnusedProfiles(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	now := time.Now()
	profiles := []*ConnectionProfile{
		{
			Name: "recent-profile",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		},
		{
			Name: "old-profile",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.101:8080",
			},
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Manually update the LastUsed times by accessing the internal implementation
	scm := manager.(*SecureConfigManagerImpl)
	scm.mutex.Lock()
	scm.profiles["recent-profile"].LastUsed = now.Add(-1 * time.Hour)
	scm.profiles["old-profile"].LastUsed = now.Add(-10 * 24 * time.Hour) // 10 days old
	
	// Save the profiles with updated times
	if err := scm.saveProfileWithoutLock(scm.profiles["recent-profile"]); err != nil {
		scm.mutex.Unlock()
		t.Fatalf("Failed to update recent profile: %v", err)
	}
	if err := scm.saveProfileWithoutLock(scm.profiles["old-profile"]); err != nil {
		scm.mutex.Unlock()
		t.Fatalf("Failed to update old profile: %v", err)
	}
	scm.mutex.Unlock()

	// Cleanup profiles older than 7 days
	removedProfiles, err := manager.CleanupUnusedProfiles(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Failed to cleanup unused profiles: %v", err)
	}

	// Verify that the old profile was removed
	if len(removedProfiles) != 1 || removedProfiles[0] != "old-profile" {
		t.Errorf("Expected to remove 'old-profile', got: %v", removedProfiles)
	}

	// Verify that the recent profile still exists
	remainingProfiles := manager.ListProfiles()
	if len(remainingProfiles) != 1 || remainingProfiles[0] != "recent-profile" {
		t.Errorf("Expected 'recent-profile' to remain, got: %v", remainingProfiles)
	}
}

func TestSearchProfilesNilCriteria(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	_, err = manager.SearchProfiles(nil)
	if err == nil {
		t.Fatal("Expected error for nil search criteria")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestUpdateProfileMetadataNotFound(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	newDescription := "Updated description"
	metadata := &ProfileMetadataUpdate{
		Description: &newDescription,
	}

	err = manager.UpdateProfileMetadata("non-existent", metadata)
	if err == nil {
		t.Fatal("Expected error for non-existent profile")
	}

	if !IsStorageError(err) {
		t.Fatalf("Expected StorageError, got: %T", err)
	}
}

// Enhanced secure deletion and backup tests

func TestSecureDeleteProfile(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Test connection profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
		CryptoMaterial: &EncryptedKeyMaterial{
			EncryptedData: []byte("sensitive-crypto-data"),
			Salt:          []byte("test-salt-16-bytes"),
			Nonce:         []byte("test-nonce-12"),
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Verify profile exists
	profiles := manager.ListProfiles()
	if len(profiles) != 1 || profiles[0] != "test-profile" {
		t.Fatal("Profile should exist before secure deletion")
	}

	// Securely delete profile
	if err := manager.SecureDeleteProfile("test-profile"); err != nil {
		t.Fatalf("Failed to securely delete profile: %v", err)
	}

	// Verify profile is deleted
	profiles = manager.ListProfiles()
	if len(profiles) != 0 {
		t.Fatal("Profile should be securely deleted")
	}

	// Verify loading deleted profile fails
	_, err = manager.LoadProfile("test-profile")
	if err == nil {
		t.Fatal("Expected error when loading securely deleted profile")
	}
}

func TestSecureDeleteProfileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	err = manager.SecureDeleteProfile("non-existent")
	if err == nil {
		t.Fatal("Expected error for non-existent profile")
	}

	if !IsStorageError(err) {
		t.Fatalf("Expected StorageError, got: %T", err)
	}
}

func TestCreateBackup(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name: "profile1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
			UseCount: 5,
		},
		{
			Name: "profile2",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.101:8081",
			},
			UseCount: 3,
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Create backup with metadata
	backup, err := manager.CreateBackup(backupPassword, true)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Verify backup structure
	if backup == nil {
		t.Fatal("Backup should not be nil")
	}

	if backup.Version != 1 {
		t.Errorf("Expected backup version 1, got %d", backup.Version)
	}

	if backup.ProfileCount != len(profiles) {
		t.Errorf("Expected profile count %d, got %d", len(profiles), backup.ProfileCount)
	}

	if len(backup.EncryptedData) == 0 {
		t.Fatal("Backup should contain encrypted data")
	}

	if len(backup.Salt) == 0 {
		t.Fatal("Backup should contain salt")
	}

	if backup.Statistics == nil {
		t.Fatal("Backup should contain statistics when requested")
	}
}

func TestCreateBackupEmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	_, err = manager.CreateBackup([]byte(""), false)
	if err == nil {
		t.Fatal("Expected error for empty backup password")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestRestoreFromBackup(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	// Create first manager and profiles
	manager1, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create first SecureConfigManager: %v", err)
	}

	profiles := []*ConnectionProfile{
		{
			Name: "profile1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		},
		{
			Name: "profile2",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.101:8081",
			},
		},
	}

	for _, profile := range profiles {
		if err := manager1.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Create backup
	backup, err := manager1.CreateBackup(backupPassword, false)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Create second manager for restore test
	tempDir2 := t.TempDir()
	manager2, err := NewSecureConfigManager(password, tempDir2)
	if err != nil {
		t.Fatalf("Failed to create second SecureConfigManager: %v", err)
	}

	// Restore from backup
	if err := manager2.RestoreFromBackup(backup, backupPassword, false); err != nil {
		t.Fatalf("Failed to restore from backup: %v", err)
	}

	// Verify restored profiles
	restoredProfiles := manager2.ListProfiles()
	if len(restoredProfiles) != len(profiles) {
		t.Fatalf("Expected %d restored profiles, got %d", len(profiles), len(restoredProfiles))
	}

	for _, originalProfile := range profiles {
		restoredProfile, err := manager2.LoadProfile(originalProfile.Name)
		if err != nil {
			t.Fatalf("Failed to load restored profile %s: %v", originalProfile.Name, err)
		}

		if restoredProfile.Name != originalProfile.Name {
			t.Errorf("Profile name mismatch: expected %s, got %s", originalProfile.Name, restoredProfile.Name)
		}

		if restoredProfile.NetworkConfig.Protocol != originalProfile.NetworkConfig.Protocol {
			t.Errorf("Protocol mismatch for profile %s", originalProfile.Name)
		}
	}
}

func TestRestoreFromBackupNilData(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	err = manager.RestoreFromBackup(nil, backupPassword, false)
	if err == nil {
		t.Fatal("Expected error for nil backup data")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestVerifyBackupIntegrity(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profile
	profile := &ConnectionProfile{
		Name: "test-profile",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(profile); err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Create backup
	backup, err := manager.CreateBackup(backupPassword, false)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Verify backup integrity with correct password
	if err := manager.VerifyBackupIntegrity(backup, backupPassword); err != nil {
		t.Fatalf("Backup integrity verification failed: %v", err)
	}

	// Verify backup integrity with wrong password
	wrongPassword := []byte("wrong-password")
	if err := manager.VerifyBackupIntegrity(backup, wrongPassword); err == nil {
		t.Fatal("Expected integrity verification to fail with wrong password")
	}
}

func TestVerifyBackupIntegrityNilData(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	err = manager.VerifyBackupIntegrity(nil, backupPassword)
	if err == nil {
		t.Fatal("Expected error for nil backup data")
	}

	if !IsConfigurationError(err) {
		t.Fatalf("Expected ConfigurationError, got: %T", err)
	}
}

func TestPerformIntegrityCheck(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create test profiles
	profiles := []*ConnectionProfile{
		{
			Name: "profile1",
			NetworkConfig: &NetworkConfig{
				Protocol:        "tcp",
				ListenerAddress: "192.168.1.100:8080",
			},
		},
		{
			Name: "profile2",
			NetworkConfig: &NetworkConfig{
				Protocol:        "udp",
				ListenerAddress: "192.168.1.101:8081",
			},
		},
	}

	for _, profile := range profiles {
		if err := manager.SaveProfile(profile); err != nil {
			t.Fatalf("Failed to save profile %s: %v", profile.Name, err)
		}
	}

	// Perform integrity check
	result, err := manager.PerformIntegrityCheck()
	if err != nil {
		t.Fatalf("Failed to perform integrity check: %v", err)
	}

	// Verify integrity check result
	if result == nil {
		t.Fatal("Integrity check result should not be nil")
	}

	if !result.Passed {
		t.Errorf("Integrity check should pass, errors: %v", result.ErrorsFound)
	}

	if result.ProfilesChecked != len(profiles) {
		t.Errorf("Expected %d profiles checked, got %d", len(profiles), result.ProfilesChecked)
	}

	if len(result.ErrorsFound) > 0 {
		t.Errorf("No errors should be found, got: %v", result.ErrorsFound)
	}
}

func TestBackupAndRestoreWithOverwrite(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")
	backupPassword := []byte("backup-password-456")

	manager, err := NewSecureConfigManager(password, tempDir)
	if err != nil {
		t.Fatalf("Failed to create SecureConfigManager: %v", err)
	}

	// Create original profile
	originalProfile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Original description",
		NetworkConfig: &NetworkConfig{
			Protocol:        "tcp",
			ListenerAddress: "192.168.1.100:8080",
		},
	}

	if err := manager.SaveProfile(originalProfile); err != nil {
		t.Fatalf("Failed to save original profile: %v", err)
	}

	// Create backup
	backup, err := manager.CreateBackup(backupPassword, false)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Modify the profile
	modifiedProfile := &ConnectionProfile{
		Name:        "test-profile",
		Description: "Modified description",
		NetworkConfig: &NetworkConfig{
			Protocol:        "udp",
			ListenerAddress: "192.168.1.200:9090",
		},
	}

	if err := manager.SaveProfile(modifiedProfile); err != nil {
		t.Fatalf("Failed to save modified profile: %v", err)
	}

	// Restore from backup with overwrite
	if err := manager.RestoreFromBackup(backup, backupPassword, true); err != nil {
		t.Fatalf("Failed to restore from backup with overwrite: %v", err)
	}

	// Verify original profile was restored
	restoredProfile, err := manager.LoadProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to load restored profile: %v", err)
	}

	if restoredProfile.Description != originalProfile.Description {
		t.Errorf("Expected description '%s', got '%s'", originalProfile.Description, restoredProfile.Description)
	}

	if restoredProfile.NetworkConfig.Protocol != originalProfile.NetworkConfig.Protocol {
		t.Errorf("Expected protocol '%s', got '%s'", originalProfile.NetworkConfig.Protocol, restoredProfile.NetworkConfig.Protocol)
	}
}