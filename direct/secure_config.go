package direct

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Cryptographic constants
	AESKeySize        = 32  // AES-256
	HMACKeySize       = 32  // HMAC-SHA256
	NonceSize         = 12  // GCM nonce size
	SaltSize          = 32  // PBKDF2 salt size
	PBKDF2Iterations  = 100000 // High iteration count for security
	
	// File constants
	ConfigFileExtension = ".qavpn"
	BackupFileExtension = ".qavpn.bak"
	IntegrityFileExtension = ".integrity"
)

// SecureConfigManagerImpl implements the SecureConfigManager interface
type SecureConfigManagerImpl struct {
	encryptionKey    []byte
	hmacKey          []byte
	storageBackend   ConfigStorage
	profiles         map[string]*ConnectionProfile
	configDir        string
	mutex            sync.RWMutex
}

// EncryptedProfileData represents encrypted profile data for storage
type EncryptedProfileData struct {
	EncryptedData []byte    `json:"encrypted_data"`
	Nonce         []byte    `json:"nonce"`
	Salt          []byte    `json:"salt"`
	HMAC          []byte    `json:"hmac"`
	CreatedAt     time.Time `json:"created_at"`
	Version       uint8     `json:"version"`
}

// ConfigMetadata holds metadata about stored configurations
type ConfigMetadata struct {
	ProfileCount    int       `json:"profile_count"`
	LastModified    time.Time `json:"last_modified"`
	IntegrityHash   []byte    `json:"integrity_hash"`
	Version         uint8     `json:"version"`
}

// NewSecureConfigManager creates a new SecureConfigManager instance
func NewSecureConfigManager(password []byte, configDir string) (SecureConfigManager, error) {
	if len(password) == 0 {
		return nil, NewConfigurationError(ErrCodeInvalidConfig, 
			"password cannot be empty", 
			"new_secure_config_manager")
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to create config directory: %v", err), 
			"new_secure_config_manager", true)
	}

	// Generate master salt for key derivation
	masterSalt := make([]byte, SaltSize)
	if _, err := rand.Read(masterSalt); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate master salt", 
			"new_secure_config_manager")
	}

	// Derive encryption and HMAC keys from password
	encryptionKey := pbkdf2.Key(password, masterSalt, PBKDF2Iterations, AESKeySize, sha256.New)
	hmacKey := pbkdf2.Key(password, append(masterSalt, []byte("hmac")...), PBKDF2Iterations, HMACKeySize, sha256.New)

	// Create file-based storage backend
	storage := NewFileConfigStorage(configDir)

	manager := &SecureConfigManagerImpl{
		encryptionKey:  encryptionKey,
		hmacKey:        hmacKey,
		storageBackend: storage,
		profiles:       make(map[string]*ConnectionProfile),
		configDir:      configDir,
		mutex:          sync.RWMutex{},
	}

	// Load existing profiles
	if err := manager.loadAllProfiles(); err != nil {
		return nil, fmt.Errorf("failed to load existing profiles: %w", err)
	}

	return manager, nil
}

// SaveProfile saves a connection profile with encryption
func (scm *SecureConfigManagerImpl) SaveProfile(profile *ConnectionProfile) error {
	if profile == nil {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"profile cannot be nil", 
			"save_profile")
	}

	if profile.Name == "" {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"profile name cannot be empty", 
			"save_profile")
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Update profile metadata
	now := time.Now()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	profile.LastUsed = now

	// Serialize profile to JSON
	profileData, err := json.Marshal(profile)
	if err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to serialize profile: %v", err), 
			"save_profile", true)
	}

	// Encrypt profile data
	encryptedData, err := scm.encryptData(profileData)
	if err != nil {
		return fmt.Errorf("failed to encrypt profile data: %w", err)
	}

	// Store encrypted data
	profileKey := scm.getProfileKey(profile.Name)
	if err := scm.storageBackend.Store(profileKey, encryptedData); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to store profile: %v", err), 
			"save_profile", true)
	}

	// Update in-memory cache
	scm.profiles[profile.Name] = profile

	// Update integrity metadata
	if err := scm.updateIntegrityMetadata(); err != nil {
		return fmt.Errorf("failed to update integrity metadata: %w", err)
	}

	return nil
}

// LoadProfile loads a connection profile by name
func (scm *SecureConfigManagerImpl) LoadProfile(name string) (*ConnectionProfile, error) {
	if name == "" {
		return nil, NewConfigurationError(ErrCodeInvalidConfig, 
			"profile name cannot be empty", 
			"load_profile")
	}

	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Check in-memory cache first
	if profile, exists := scm.profiles[name]; exists {
		// Update last used time
		profile.LastUsed = time.Now()
		profile.UseCount++
		return profile, nil
	}

	// Load from storage
	profileKey := scm.getProfileKey(name)
	encryptedData, err := scm.storageBackend.Retrieve(profileKey)
	if err != nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to retrieve profile: %v", err), 
			"load_profile", false)
	}

	// Decrypt profile data
	profileData, err := scm.decryptData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt profile data: %w", err)
	}

	// Deserialize profile
	var profile ConnectionProfile
	if err := json.Unmarshal(profileData, &profile); err != nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to deserialize profile: %v", err), 
			"load_profile", false)
	}

	// Update usage statistics
	profile.LastUsed = time.Now()
	profile.UseCount++

	// Update in-memory cache
	scm.profiles[name] = &profile

	return &profile, nil
}

// DeleteProfile deletes a connection profile by name
func (scm *SecureConfigManagerImpl) DeleteProfile(name string) error {
	if name == "" {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"profile name cannot be empty", 
			"delete_profile")
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Remove from storage with secure deletion
	profileKey := scm.getProfileKey(name)
	if err := scm.storageBackend.SecureDelete(profileKey); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to securely delete profile: %v", err), 
			"delete_profile", true)
	}

	// Remove from in-memory cache
	delete(scm.profiles, name)

	// Update integrity metadata
	if err := scm.updateIntegrityMetadata(); err != nil {
		return fmt.Errorf("failed to update integrity metadata: %w", err)
	}

	return nil
}

// ListProfiles returns a list of all profile names
func (scm *SecureConfigManagerImpl) ListProfiles() []string {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	profiles := make([]string, 0, len(scm.profiles))
	for name := range scm.profiles {
		profiles = append(profiles, name)
	}

	return profiles
}

// ChangeEncryptionKey changes the encryption key and re-encrypts all data
func (scm *SecureConfigManagerImpl) ChangeEncryptionKey(oldKey, newKey []byte) error {
	if len(oldKey) == 0 || len(newKey) == 0 {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"keys cannot be empty", 
			"change_encryption_key")
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Generate new salt for key derivation
	newSalt := make([]byte, SaltSize)
	if _, err := rand.Read(newSalt); err != nil {
		return NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate new salt", 
			"change_encryption_key")
	}

	// Derive new encryption and HMAC keys
	newEncryptionKey := pbkdf2.Key(newKey, newSalt, PBKDF2Iterations, AESKeySize, sha256.New)
	newHMACKey := pbkdf2.Key(newKey, append(newSalt, []byte("hmac")...), PBKDF2Iterations, HMACKeySize, sha256.New)

	// Re-encrypt all profiles with new key
	oldEncryptionKey := scm.encryptionKey
	oldHMACKey := scm.hmacKey

	// Temporarily set new keys
	scm.encryptionKey = newEncryptionKey
	scm.hmacKey = newHMACKey

	// Re-save all profiles with new encryption
	for _, profile := range scm.profiles {
		if err := scm.saveProfileWithoutLock(profile); err != nil {
			// Restore old keys on failure
			scm.encryptionKey = oldEncryptionKey
			scm.hmacKey = oldHMACKey
			return fmt.Errorf("failed to re-encrypt profile %s: %w", profile.Name, err)
		}
	}

	// Securely wipe old keys from memory
	scm.secureWipeBytes(oldEncryptionKey)
	scm.secureWipeBytes(oldHMACKey)

	return nil
}

// VerifyIntegrity verifies the integrity of all stored configurations
func (scm *SecureConfigManagerImpl) VerifyIntegrity() error {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Load integrity metadata
	metadata, err := scm.loadIntegrityMetadata()
	if err != nil {
		return fmt.Errorf("failed to load integrity metadata: %w", err)
	}

	// Calculate current integrity hash
	currentHash, err := scm.calculateIntegrityHash()
	if err != nil {
		return fmt.Errorf("failed to calculate integrity hash: %w", err)
	}

	// Compare hashes
	if !hmac.Equal(metadata.IntegrityHash, currentHash) {
		return NewStorageError(ErrCodeIntegrityFailure, 
			"integrity verification failed", 
			"verify_integrity", false)
	}

	return nil
}

// SecureWipe securely wipes all sensitive data from memory and storage
func (scm *SecureConfigManagerImpl) SecureWipe() error {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Wipe encryption keys from memory
	scm.secureWipeBytes(scm.encryptionKey)
	scm.secureWipeBytes(scm.hmacKey)

	// Clear profiles from memory
	for name, profile := range scm.profiles {
		scm.secureWipeProfile(profile)
		delete(scm.profiles, name)
	}

	// Securely delete all stored files
	profileList, err := scm.storageBackend.List()
	if err != nil {
		return fmt.Errorf("failed to list profiles for secure wipe: %w", err)
	}

	for _, profileKey := range profileList {
		if err := scm.storageBackend.SecureDelete(profileKey); err != nil {
			return fmt.Errorf("failed to securely delete profile %s: %w", profileKey, err)
		}
	}

	return nil
}

// ExportProfiles exports all profiles to an encrypted backup format
func (scm *SecureConfigManagerImpl) ExportProfiles(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, NewConfigurationError(ErrCodeInvalidConfig, 
			"export password cannot be empty", 
			"export_profiles")
	}

	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Create export data structure
	exportData := struct {
		Profiles  map[string]*ConnectionProfile `json:"profiles"`
		Metadata  *ConfigMetadata               `json:"metadata"`
		ExportedAt time.Time                    `json:"exported_at"`
		Version   uint8                         `json:"version"`
	}{
		Profiles:   scm.profiles,
		Metadata:   &ConfigMetadata{
			ProfileCount: len(scm.profiles),
			LastModified: time.Now(),
			Version:      1,
		},
		ExportedAt: time.Now(),
		Version:    1,
	}

	// Serialize export data
	exportJSON, err := json.Marshal(exportData)
	if err != nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to serialize export data: %v", err), 
			"export_profiles", true)
	}

	// Generate export salt
	exportSalt := make([]byte, SaltSize)
	if _, err := rand.Read(exportSalt); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate export salt", 
			"export_profiles")
	}

	// Derive export encryption key
	exportKey := pbkdf2.Key(password, exportSalt, PBKDF2Iterations, AESKeySize, sha256.New)

	// Encrypt export data
	encryptedExport, err := scm.encryptDataWithKey(exportJSON, exportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt export data: %w", err)
	}

	// Create final export structure
	finalExport := struct {
		EncryptedData []byte    `json:"encrypted_data"`
		Salt          []byte    `json:"salt"`
		ExportedAt    time.Time `json:"exported_at"`
		Version       uint8     `json:"version"`
	}{
		EncryptedData: encryptedExport,
		Salt:          exportSalt,
		ExportedAt:    time.Now(),
		Version:       1,
	}

	return json.Marshal(finalExport)
}

// ImportProfiles imports profiles from an encrypted backup
func (scm *SecureConfigManagerImpl) ImportProfiles(data []byte, password []byte) error {
	if len(data) == 0 {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"import data cannot be empty", 
			"import_profiles")
	}

	if len(password) == 0 {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"import password cannot be empty", 
			"import_profiles")
	}

	// Parse import structure
	var importStruct struct {
		EncryptedData []byte    `json:"encrypted_data"`
		Salt          []byte    `json:"salt"`
		ExportedAt    time.Time `json:"exported_at"`
		Version       uint8     `json:"version"`
	}

	if err := json.Unmarshal(data, &importStruct); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to parse import data: %v", err), 
			"import_profiles", false)
	}

	// Derive import decryption key
	importKey := pbkdf2.Key(password, importStruct.Salt, PBKDF2Iterations, AESKeySize, sha256.New)

	// Decrypt import data
	decryptedData, err := scm.decryptDataWithKey(importStruct.EncryptedData, importKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt import data: %w", err)
	}

	// Parse decrypted export data
	var exportData struct {
		Profiles  map[string]*ConnectionProfile `json:"profiles"`
		Metadata  *ConfigMetadata               `json:"metadata"`
		ExportedAt time.Time                    `json:"exported_at"`
		Version   uint8                         `json:"version"`
	}

	if err := json.Unmarshal(decryptedData, &exportData); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to parse decrypted import data: %v", err), 
			"import_profiles", false)
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Import profiles
	for name, profile := range exportData.Profiles {
		if err := scm.saveProfileWithoutLock(profile); err != nil {
			return fmt.Errorf("failed to import profile %s: %w", name, err)
		}
		scm.profiles[name] = profile
	}

	// Update integrity metadata
	if err := scm.updateIntegrityMetadata(); err != nil {
		return fmt.Errorf("failed to update integrity metadata after import: %w", err)
	}

	return nil
}

// Helper methods

// encryptData encrypts data using AES-256-GCM with HMAC integrity protection
func (scm *SecureConfigManagerImpl) encryptData(data []byte) ([]byte, error) {
	return scm.encryptDataWithKey(data, scm.encryptionKey)
}

// encryptDataWithKey encrypts data using the specified key
func (scm *SecureConfigManagerImpl) encryptDataWithKey(data []byte, key []byte) ([]byte, error) {
	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate nonce", 
			"encrypt_data")
	}

	// Generate salt for this encryption
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate salt", 
			"encrypt_data")
	}

	// Derive HMAC key from the encryption key for this specific encryption
	hmacKey := pbkdf2.Key(key, append(salt, []byte("hmac")...), PBKDF2Iterations, HMACKeySize, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			fmt.Sprintf("failed to create AES cipher: %v", err), 
			"encrypt_data")
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			fmt.Sprintf("failed to create GCM mode: %v", err), 
			"encrypt_data")
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Calculate HMAC for integrity protection
	hmacHash := hmac.New(sha256.New, hmacKey)
	hmacHash.Write(ciphertext)
	hmacHash.Write(nonce)
	hmacHash.Write(salt)
	hmacValue := hmacHash.Sum(nil)

	// Create encrypted data structure
	encryptedData := &EncryptedProfileData{
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Salt:          salt,
		HMAC:          hmacValue,
		CreatedAt:     time.Now(),
		Version:       1,
	}

	return json.Marshal(encryptedData)
}

// decryptData decrypts data using AES-256-GCM with HMAC integrity verification
func (scm *SecureConfigManagerImpl) decryptData(encryptedBytes []byte) ([]byte, error) {
	return scm.decryptDataWithKey(encryptedBytes, scm.encryptionKey)
}

// decryptDataWithKey decrypts data using the specified key
func (scm *SecureConfigManagerImpl) decryptDataWithKey(encryptedBytes []byte, key []byte) ([]byte, error) {
	// Parse encrypted data structure
	var encryptedData EncryptedProfileData
	if err := json.Unmarshal(encryptedBytes, &encryptedData); err != nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to parse encrypted data: %v", err), 
			"decrypt_data", false)
	}

	// Derive HMAC key from the encryption key using the same salt as encryption
	hmacKey := pbkdf2.Key(key, append(encryptedData.Salt, []byte("hmac")...), PBKDF2Iterations, HMACKeySize, sha256.New)

	// Verify HMAC integrity
	hmacHash := hmac.New(sha256.New, hmacKey)
	hmacHash.Write(encryptedData.EncryptedData)
	hmacHash.Write(encryptedData.Nonce)
	hmacHash.Write(encryptedData.Salt)
	expectedHMAC := hmacHash.Sum(nil)

	if !hmac.Equal(encryptedData.HMAC, expectedHMAC) {
		return nil, NewCryptographicError(ErrCodeDecryptionFailure, 
			"HMAC integrity verification failed", 
			"decrypt_data")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewCryptographicError(ErrCodeDecryptionFailure, 
			fmt.Sprintf("failed to create AES cipher: %v", err), 
			"decrypt_data")
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewCryptographicError(ErrCodeDecryptionFailure, 
			fmt.Sprintf("failed to create GCM mode: %v", err), 
			"decrypt_data")
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, encryptedData.Nonce, encryptedData.EncryptedData, nil)
	if err != nil {
		return nil, NewCryptographicError(ErrCodeDecryptionFailure, 
			fmt.Sprintf("failed to decrypt data: %v", err), 
			"decrypt_data")
	}

	return plaintext, nil
}

// getProfileKey generates a storage key for a profile
func (scm *SecureConfigManagerImpl) getProfileKey(profileName string) string {
	return fmt.Sprintf("profile_%s", profileName)
}

// loadAllProfiles loads all profiles from storage into memory
func (scm *SecureConfigManagerImpl) loadAllProfiles() error {
	profileKeys, err := scm.storageBackend.List()
	if err != nil {
		return fmt.Errorf("failed to list profiles: %w", err)
	}

	for _, key := range profileKeys {
		// Skip non-profile keys
		if len(key) < 8 || key[:8] != "profile_" {
			continue
		}

		profileName := key[8:] // Remove "profile_" prefix
		_, err := scm.LoadProfile(profileName)
		if err != nil {
			// Log error but continue loading other profiles
			continue
		}
	}

	return nil
}

// saveProfileWithoutLock saves a profile without acquiring the mutex (internal use)
func (scm *SecureConfigManagerImpl) saveProfileWithoutLock(profile *ConnectionProfile) error {
	// Serialize profile to JSON
	profileData, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to serialize profile: %w", err)
	}

	// Encrypt profile data
	encryptedData, err := scm.encryptData(profileData)
	if err != nil {
		return fmt.Errorf("failed to encrypt profile data: %w", err)
	}

	// Store encrypted data
	profileKey := scm.getProfileKey(profile.Name)
	return scm.storageBackend.Store(profileKey, encryptedData)
}

// updateIntegrityMetadata updates the integrity metadata
func (scm *SecureConfigManagerImpl) updateIntegrityMetadata() error {
	integrityHash, err := scm.calculateIntegrityHash()
	if err != nil {
		return fmt.Errorf("failed to calculate integrity hash: %w", err)
	}

	metadata := &ConfigMetadata{
		ProfileCount:  len(scm.profiles),
		LastModified:  time.Now(),
		IntegrityHash: integrityHash,
		Version:       1,
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	return scm.storageBackend.Store("integrity_metadata", metadataJSON)
}

// loadIntegrityMetadata loads the integrity metadata
func (scm *SecureConfigManagerImpl) loadIntegrityMetadata() (*ConfigMetadata, error) {
	metadataBytes, err := scm.storageBackend.Retrieve("integrity_metadata")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve integrity metadata: %w", err)
	}

	var metadata ConfigMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse integrity metadata: %w", err)
	}

	return &metadata, nil
}

// calculateIntegrityHash calculates a hash of all profile data for integrity verification
func (scm *SecureConfigManagerImpl) calculateIntegrityHash() ([]byte, error) {
	h := hmac.New(sha256.New, scm.hmacKey)

	// Hash all profile names and their data in sorted order
	profileNames := make([]string, 0, len(scm.profiles))
	for name := range scm.profiles {
		profileNames = append(profileNames, name)
	}

	// Sort for consistent hash calculation
	for i := 0; i < len(profileNames); i++ {
		for j := i + 1; j < len(profileNames); j++ {
			if profileNames[i] > profileNames[j] {
				profileNames[i], profileNames[j] = profileNames[j], profileNames[i]
			}
		}
	}

	for _, name := range profileNames {
		profile := scm.profiles[name]
		profileData, err := json.Marshal(profile)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize profile %s for integrity hash: %w", name, err)
		}
		h.Write([]byte(name))
		h.Write(profileData)
	}

	return h.Sum(nil), nil
}

// secureWipeBytes securely wipes a byte slice from memory
func (scm *SecureConfigManagerImpl) secureWipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// secureWipeProfile securely wipes sensitive data from a profile
func (scm *SecureConfigManagerImpl) secureWipeProfile(profile *ConnectionProfile) {
	if profile.CryptoMaterial != nil {
		scm.secureWipeBytes(profile.CryptoMaterial.EncryptedData)
		scm.secureWipeBytes(profile.CryptoMaterial.Salt)
		scm.secureWipeBytes(profile.CryptoMaterial.Nonce)
	}
}

// FileConfigStorage implements the ConfigStorage interface using the filesystem
type FileConfigStorage struct {
	baseDir string
	mutex   sync.RWMutex
}

// NewFileConfigStorage creates a new file-based configuration storage
func NewFileConfigStorage(baseDir string) ConfigStorage {
	return &FileConfigStorage{
		baseDir: baseDir,
		mutex:   sync.RWMutex{},
	}
}

// Store stores data to a file
func (fcs *FileConfigStorage) Store(key string, data []byte) error {
	fcs.mutex.Lock()
	defer fcs.mutex.Unlock()

	filePath := filepath.Join(fcs.baseDir, key+ConfigFileExtension)
	
	// Create backup if file exists
	if _, err := os.Stat(filePath); err == nil {
		backupPath := filePath + BackupFileExtension
		if err := os.Rename(filePath, backupPath); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
	}

	// Write data to file with secure permissions
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Calculate and store integrity hash
	hash := sha256.Sum256(data)
	integrityPath := filePath + IntegrityFileExtension
	if err := os.WriteFile(integrityPath, hash[:], 0600); err != nil {
		return fmt.Errorf("failed to write integrity file: %w", err)
	}

	// Remove backup on successful write
	backupPath := filePath + BackupFileExtension
	if _, err := os.Stat(backupPath); err == nil {
		os.Remove(backupPath)
	}

	return nil
}

// Retrieve retrieves data from a file
func (fcs *FileConfigStorage) Retrieve(key string) ([]byte, error) {
	fcs.mutex.RLock()
	defer fcs.mutex.RUnlock()

	filePath := filepath.Join(fcs.baseDir, key+ConfigFileExtension)
	
	// Read file data
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Verify integrity if integrity file exists
	integrityPath := filePath + IntegrityFileExtension
	if expectedHashBytes, err := os.ReadFile(integrityPath); err == nil {
		actualHash := sha256.Sum256(data)
		if len(expectedHashBytes) == 32 && !hmac.Equal(expectedHashBytes, actualHash[:]) {
			return nil, fmt.Errorf("integrity verification failed for key %s", key)
		}
	}

	return data, nil
}

// Delete deletes a file
func (fcs *FileConfigStorage) Delete(key string) error {
	fcs.mutex.Lock()
	defer fcs.mutex.Unlock()

	filePath := filepath.Join(fcs.baseDir, key+ConfigFileExtension)
	integrityPath := filePath + IntegrityFileExtension
	
	// Remove main file
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Remove integrity file
	if err := os.Remove(integrityPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete integrity file: %w", err)
	}

	return nil
}

// SecureDelete securely deletes a file by overwriting it multiple times
func (fcs *FileConfigStorage) SecureDelete(key string) error {
	fcs.mutex.Lock()
	defer fcs.mutex.Unlock()

	filePath := filepath.Join(fcs.baseDir, key+ConfigFileExtension)
	integrityPath := filePath + IntegrityFileExtension
	
	// Securely overwrite main file
	if err := fcs.secureOverwriteFile(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to securely delete file: %w", err)
	}

	// Securely overwrite integrity file
	if err := fcs.secureOverwriteFile(integrityPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to securely delete integrity file: %w", err)
	}

	return nil
}

// List lists all stored keys
func (fcs *FileConfigStorage) List() ([]string, error) {
	fcs.mutex.RLock()
	defer fcs.mutex.RUnlock()

	entries, err := os.ReadDir(fcs.baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var keys []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if len(name) > len(ConfigFileExtension) && 
		   name[len(name)-len(ConfigFileExtension):] == ConfigFileExtension {
			// Remove extension to get key
			key := name[:len(name)-len(ConfigFileExtension)]
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// VerifyIntegrity verifies the integrity of a stored file
func (fcs *FileConfigStorage) VerifyIntegrity(key string, expectedHash []byte) error {
	fcs.mutex.RLock()
	defer fcs.mutex.RUnlock()

	filePath := filepath.Join(fcs.baseDir, key+ConfigFileExtension)
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file for integrity check: %w", err)
	}

	actualHash := sha256.Sum256(data)
	if !hmac.Equal(expectedHash, actualHash[:]) {
		return fmt.Errorf("integrity verification failed for key %s", key)
	}

	return nil
}

// secureOverwriteFile securely overwrites a file multiple times before deletion
func (fcs *FileConfigStorage) secureOverwriteFile(filePath string) error {
	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	fileSize := info.Size()
	if fileSize == 0 {
		return os.Remove(filePath)
	}

	// Open file for writing
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	// Overwrite with random data 3 times
	for i := 0; i < 3; i++ {
		// Seek to beginning
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}

		// Generate random data
		randomData := make([]byte, fileSize)
		if _, err := rand.Read(randomData); err != nil {
			return err
		}

		// Write random data
		if _, err := file.Write(randomData); err != nil {
			return err
		}

		// Sync to disk
		if err := file.Sync(); err != nil {
			return err
		}
	}

	// Close file before deletion
	file.Close()

	// Finally delete the file
	return os.Remove(filePath)
}

// Enhanced profile management methods

// ListProfilesWithMetadata returns profiles with their metadata
func (scm *SecureConfigManagerImpl) ListProfilesWithMetadata() ([]*ProfileMetadata, error) {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	metadata := make([]*ProfileMetadata, 0, len(scm.profiles))
	for _, profile := range scm.profiles {
		meta := &ProfileMetadata{
			Name:        profile.Name,
			Description: profile.Description,
			Protocol:    profile.NetworkConfig.Protocol,
			Address:     profile.NetworkConfig.ListenerAddress,
			CreatedAt:   profile.CreatedAt,
			LastUsed:    profile.LastUsed,
			UseCount:    profile.UseCount,
		}
		metadata = append(metadata, meta)
	}

	return metadata, nil
}

// SearchProfiles searches for profiles matching the given criteria
func (scm *SecureConfigManagerImpl) SearchProfiles(criteria *SearchCriteria) ([]*ConnectionProfile, error) {
	if criteria == nil {
		return nil, NewConfigurationError(ErrCodeInvalidConfig, 
			"search criteria cannot be nil", 
			"search_profiles")
	}

	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	var results []*ConnectionProfile
	for _, profile := range scm.profiles {
		if scm.matchesSearchCriteria(profile, criteria) {
			results = append(results, profile)
		}
	}

	return results, nil
}

// GetProfileStatistics returns usage statistics for all profiles
func (scm *SecureConfigManagerImpl) GetProfileStatistics() (*ProfileStatistics, error) {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	stats := &ProfileStatistics{
		TotalProfiles:    len(scm.profiles),
		ProfilesByProtocol: make(map[string]int),
		UsageStats:       make([]*ProfileUsageStats, 0, len(scm.profiles)),
	}

	var totalUseCount int
	var lastUsedTime time.Time

	for _, profile := range scm.profiles {
		// Count by protocol
		stats.ProfilesByProtocol[profile.NetworkConfig.Protocol]++

		// Track usage
		totalUseCount += profile.UseCount
		if profile.LastUsed.After(lastUsedTime) {
			lastUsedTime = profile.LastUsed
		}

		// Individual profile stats
		usageStats := &ProfileUsageStats{
			ProfileName: profile.Name,
			UseCount:    profile.UseCount,
			LastUsed:    profile.LastUsed,
			CreatedAt:   profile.CreatedAt,
		}
		stats.UsageStats = append(stats.UsageStats, usageStats)
	}

	stats.TotalUseCount = totalUseCount
	stats.LastActivity = lastUsedTime

	return stats, nil
}

// UpdateProfileMetadata updates non-sensitive metadata for a profile
func (scm *SecureConfigManagerImpl) UpdateProfileMetadata(name string, metadata *ProfileMetadataUpdate) error {
	if name == "" {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"profile name cannot be empty", 
			"update_profile_metadata")
	}

	if metadata == nil {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"metadata cannot be nil", 
			"update_profile_metadata")
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	profile, exists := scm.profiles[name]
	if !exists {
		return NewStorageError(ErrCodeStorageFailure, 
			"profile not found", 
			"update_profile_metadata", false)
	}

	// Update metadata fields
	if metadata.Description != nil {
		profile.Description = *metadata.Description
	}

	// Save updated profile
	if err := scm.saveProfileWithoutLock(profile); err != nil {
		return fmt.Errorf("failed to save updated profile: %w", err)
	}

	return nil
}

// GetMostUsedProfiles returns the most frequently used profiles
func (scm *SecureConfigManagerImpl) GetMostUsedProfiles(limit int) ([]*ConnectionProfile, error) {
	if limit <= 0 {
		limit = 10 // Default limit
	}

	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Create a slice of profiles for sorting
	profiles := make([]*ConnectionProfile, 0, len(scm.profiles))
	for _, profile := range scm.profiles {
		profiles = append(profiles, profile)
	}

	// Sort by use count (descending)
	for i := 0; i < len(profiles); i++ {
		for j := i + 1; j < len(profiles); j++ {
			if profiles[i].UseCount < profiles[j].UseCount {
				profiles[i], profiles[j] = profiles[j], profiles[i]
			}
		}
	}

	// Return top profiles up to limit
	if len(profiles) > limit {
		profiles = profiles[:limit]
	}

	return profiles, nil
}

// GetRecentlyUsedProfiles returns recently used profiles
func (scm *SecureConfigManagerImpl) GetRecentlyUsedProfiles(limit int) ([]*ConnectionProfile, error) {
	if limit <= 0 {
		limit = 10 // Default limit
	}

	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Create a slice of profiles for sorting
	profiles := make([]*ConnectionProfile, 0, len(scm.profiles))
	for _, profile := range scm.profiles {
		profiles = append(profiles, profile)
	}

	// Sort by last used time (descending)
	for i := 0; i < len(profiles); i++ {
		for j := i + 1; j < len(profiles); j++ {
			if profiles[i].LastUsed.Before(profiles[j].LastUsed) {
				profiles[i], profiles[j] = profiles[j], profiles[i]
			}
		}
	}

	// Return recent profiles up to limit
	if len(profiles) > limit {
		profiles = profiles[:limit]
	}

	return profiles, nil
}

// CleanupUnusedProfiles removes profiles that haven't been used for a specified duration
func (scm *SecureConfigManagerImpl) CleanupUnusedProfiles(unusedDuration time.Duration) ([]string, error) {
	if unusedDuration <= 0 {
		return nil, NewConfigurationError(ErrCodeInvalidConfig, 
			"unused duration must be positive", 
			"cleanup_unused_profiles")
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	cutoffTime := time.Now().Add(-unusedDuration)
	var removedProfiles []string

	for name, profile := range scm.profiles {
		if profile.LastUsed.Before(cutoffTime) {
			// Securely delete the profile
			profileKey := scm.getProfileKey(name)
			if err := scm.storageBackend.SecureDelete(profileKey); err != nil {
				continue // Skip this profile if deletion fails
			}

			// Remove from memory
			scm.secureWipeProfile(profile)
			delete(scm.profiles, name)
			removedProfiles = append(removedProfiles, name)
		}
	}

	// Update integrity metadata if profiles were removed
	if len(removedProfiles) > 0 {
		if err := scm.updateIntegrityMetadata(); err != nil {
			return removedProfiles, fmt.Errorf("failed to update integrity metadata after cleanup: %w", err)
		}
	}

	return removedProfiles, nil
}

// Helper methods

// matchesSearchCriteria checks if a profile matches the search criteria
func (scm *SecureConfigManagerImpl) matchesSearchCriteria(profile *ConnectionProfile, criteria *SearchCriteria) bool {
	// Name search
	if criteria.Name != "" {
		if !scm.containsIgnoreCase(profile.Name, criteria.Name) {
			return false
		}
	}

	// Description search
	if criteria.Description != "" {
		if !scm.containsIgnoreCase(profile.Description, criteria.Description) {
			return false
		}
	}

	// Protocol filter
	if criteria.Protocol != "" {
		if profile.NetworkConfig.Protocol != criteria.Protocol {
			return false
		}
	}

	// Address search
	if criteria.Address != "" {
		if !scm.containsIgnoreCase(profile.NetworkConfig.ListenerAddress, criteria.Address) {
			return false
		}
	}

	// Date range filter
	if !criteria.CreatedAfter.IsZero() {
		if profile.CreatedAt.Before(criteria.CreatedAfter) {
			return false
		}
	}

	if !criteria.CreatedBefore.IsZero() {
		if profile.CreatedAt.After(criteria.CreatedBefore) {
			return false
		}
	}

	// Usage filter
	if criteria.MinUseCount > 0 {
		if profile.UseCount < criteria.MinUseCount {
			return false
		}
	}

	return true
}

// containsIgnoreCase performs case-insensitive substring search
func (scm *SecureConfigManagerImpl) containsIgnoreCase(text, substr string) bool {
	if substr == "" {
		return true
	}

	// Simple case-insensitive search
	textLower := scm.toLowerCase(text)
	substrLower := scm.toLowerCase(substr)

	return scm.contains(textLower, substrLower)
}

// toLowerCase converts a string to lowercase
func (scm *SecureConfigManagerImpl) toLowerCase(s string) string {
	result := make([]byte, len(s))
	for i, b := range []byte(s) {
		if b >= 'A' && b <= 'Z' {
			result[i] = b + 32
		} else {
			result[i] = b
		}
	}
	return string(result)
}

// contains checks if a string contains a substring
func (scm *SecureConfigManagerImpl) contains(text, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(text) {
		return false
	}

	for i := 0; i <= len(text)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if text[i+j] != substr[j] {
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

// Additional secure deletion and backup methods

// SecureDeleteProfile securely deletes a single profile with cryptographic wiping
func (scm *SecureConfigManagerImpl) SecureDeleteProfile(name string) error {
	if name == "" {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"profile name cannot be empty", 
			"secure_delete_profile")
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Check if profile exists
	profile, exists := scm.profiles[name]
	if !exists {
		return NewStorageError(ErrCodeStorageFailure, 
			"profile not found", 
			"secure_delete_profile", false)
	}

	// Securely wipe profile from memory first
	scm.secureWipeProfile(profile)

	// Remove from storage with secure deletion
	profileKey := scm.getProfileKey(name)
	if err := scm.storageBackend.SecureDelete(profileKey); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to securely delete profile: %v", err), 
			"secure_delete_profile", true)
	}

	// Remove from in-memory cache
	delete(scm.profiles, name)

	// Update integrity metadata
	if err := scm.updateIntegrityMetadata(); err != nil {
		return fmt.Errorf("failed to update integrity metadata after secure deletion: %w", err)
	}

	return nil
}

// CreateBackup creates an encrypted backup of all profiles with additional metadata
func (scm *SecureConfigManagerImpl) CreateBackup(password []byte, includeMetadata bool) (*BackupData, error) {
	if len(password) == 0 {
		return nil, NewConfigurationError(ErrCodeInvalidConfig, 
			"backup password cannot be empty", 
			"create_backup")
	}

	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Create backup structure
	backup := &BackupData{
		Version:    1,
		CreatedAt:  time.Now(),
		ProfileCount: len(scm.profiles),
		Profiles:   make(map[string]*ConnectionProfile),
	}

	// Copy profiles
	for name, profile := range scm.profiles {
		backup.Profiles[name] = profile
	}

	// Add metadata if requested
	if includeMetadata {
		stats, err := scm.getProfileStatisticsWithoutLock()
		if err != nil {
			return nil, fmt.Errorf("failed to get profile statistics for backup: %w", err)
		}
		backup.Statistics = stats
	}

	// Serialize backup data
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return nil, NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to serialize backup data: %v", err), 
			"create_backup", true)
	}

	// Generate backup salt
	backupSalt := make([]byte, SaltSize)
	if _, err := rand.Read(backupSalt); err != nil {
		return nil, NewCryptographicError(ErrCodeEncryptionFailure, 
			"failed to generate backup salt", 
			"create_backup")
	}

	// Derive backup encryption key
	backupKey := pbkdf2.Key(password, backupSalt, PBKDF2Iterations, AESKeySize, sha256.New)

	// Encrypt backup data
	encryptedBackup, err := scm.encryptDataWithKey(backupJSON, backupKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt backup data: %w", err)
	}

	// Create final backup structure
	backup.EncryptedData = encryptedBackup
	backup.Salt = backupSalt

	return backup, nil
}

// RestoreFromBackup restores profiles from an encrypted backup
func (scm *SecureConfigManagerImpl) RestoreFromBackup(backupData *BackupData, password []byte, overwriteExisting bool) error {
	if backupData == nil {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"backup data cannot be nil", 
			"restore_from_backup")
	}

	if len(password) == 0 {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"backup password cannot be empty", 
			"restore_from_backup")
	}

	// Derive backup decryption key
	backupKey := pbkdf2.Key(password, backupData.Salt, PBKDF2Iterations, AESKeySize, sha256.New)

	// Decrypt backup data
	decryptedData, err := scm.decryptDataWithKey(backupData.EncryptedData, backupKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt backup data: %w", err)
	}

	// Parse decrypted backup data
	var backup BackupData
	if err := json.Unmarshal(decryptedData, &backup); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			fmt.Sprintf("failed to parse decrypted backup data: %v", err), 
			"restore_from_backup", false)
	}

	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Restore profiles
	restoredCount := 0
	for name, profile := range backup.Profiles {
		// Check if profile already exists
		if _, exists := scm.profiles[name]; exists && !overwriteExisting {
			continue // Skip existing profiles if not overwriting
		}

		// Save restored profile
		if err := scm.saveProfileWithoutLock(profile); err != nil {
			continue // Skip profiles that fail to save
		}

		scm.profiles[name] = profile
		restoredCount++
	}

	// Update integrity metadata
	if err := scm.updateIntegrityMetadata(); err != nil {
		return fmt.Errorf("failed to update integrity metadata after restore: %w", err)
	}

	return nil
}

// VerifyBackupIntegrity verifies the integrity of a backup without restoring it
func (scm *SecureConfigManagerImpl) VerifyBackupIntegrity(backupData *BackupData, password []byte) error {
	if backupData == nil {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"backup data cannot be nil", 
			"verify_backup_integrity")
	}

	if len(password) == 0 {
		return NewConfigurationError(ErrCodeInvalidConfig, 
			"backup password cannot be empty", 
			"verify_backup_integrity")
	}

	// Derive backup decryption key
	backupKey := pbkdf2.Key(password, backupData.Salt, PBKDF2Iterations, AESKeySize, sha256.New)

	// Try to decrypt backup data
	decryptedData, err := scm.decryptDataWithKey(backupData.EncryptedData, backupKey)
	if err != nil {
		return NewCryptographicError(ErrCodeDecryptionFailure, 
			"backup integrity verification failed", 
			"verify_backup_integrity")
	}

	// Try to parse decrypted backup data
	var backup BackupData
	if err := json.Unmarshal(decryptedData, &backup); err != nil {
		return NewStorageError(ErrCodeStorageFailure, 
			"backup data structure is corrupted", 
			"verify_backup_integrity", false)
	}

	// Verify profile count matches
	if len(backup.Profiles) != backup.ProfileCount {
		return NewStorageError(ErrCodeIntegrityFailure, 
			"backup profile count mismatch", 
			"verify_backup_integrity", false)
	}

	// Verify each profile structure
	for name, profile := range backup.Profiles {
		if profile.Name != name {
			return NewStorageError(ErrCodeIntegrityFailure, 
				fmt.Sprintf("profile name mismatch for %s", name), 
				"verify_backup_integrity", false)
		}

		if profile.NetworkConfig == nil {
			return NewStorageError(ErrCodeIntegrityFailure, 
				fmt.Sprintf("missing network config for profile %s", name), 
				"verify_backup_integrity", false)
		}
	}

	return nil
}

// PerformIntegrityCheck performs a comprehensive integrity check on startup
func (scm *SecureConfigManagerImpl) PerformIntegrityCheck() (*IntegrityCheckResult, error) {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	result := &IntegrityCheckResult{
		CheckTime:     time.Now(),
		ProfilesChecked: 0,
		ErrorsFound:   make([]string, 0),
		WarningsFound: make([]string, 0),
	}

	// Check metadata integrity
	if err := scm.VerifyIntegrity(); err != nil {
		result.ErrorsFound = append(result.ErrorsFound, fmt.Sprintf("Metadata integrity check failed: %v", err))
	}

	// Check each profile
	for name, profile := range scm.profiles {
		result.ProfilesChecked++

		// Verify profile structure
		if profile.Name != name {
			result.ErrorsFound = append(result.ErrorsFound, fmt.Sprintf("Profile name mismatch: %s", name))
		}

		if profile.NetworkConfig == nil {
			result.ErrorsFound = append(result.ErrorsFound, fmt.Sprintf("Missing network config for profile: %s", name))
		}

		if profile.CreatedAt.IsZero() {
			result.WarningsFound = append(result.WarningsFound, fmt.Sprintf("Missing creation time for profile: %s", name))
		}

		// Verify storage integrity
		profileKey := scm.getProfileKey(name)
		if _, err := scm.storageBackend.Retrieve(profileKey); err != nil {
			result.ErrorsFound = append(result.ErrorsFound, fmt.Sprintf("Storage integrity check failed for profile %s: %v", name, err))
		}
	}

	result.Passed = len(result.ErrorsFound) == 0

	return result, nil
}

// Helper method for getting statistics without lock (internal use)
func (scm *SecureConfigManagerImpl) getProfileStatisticsWithoutLock() (*ProfileStatistics, error) {
	stats := &ProfileStatistics{
		TotalProfiles:    len(scm.profiles),
		ProfilesByProtocol: make(map[string]int),
		UsageStats:       make([]*ProfileUsageStats, 0, len(scm.profiles)),
	}

	var totalUseCount int
	var lastUsedTime time.Time

	for _, profile := range scm.profiles {
		// Count by protocol
		stats.ProfilesByProtocol[profile.NetworkConfig.Protocol]++

		// Track usage
		totalUseCount += profile.UseCount
		if profile.LastUsed.After(lastUsedTime) {
			lastUsedTime = profile.LastUsed
		}

		// Individual profile stats
		usageStats := &ProfileUsageStats{
			ProfileName: profile.Name,
			UseCount:    profile.UseCount,
			LastUsed:    profile.LastUsed,
			CreatedAt:   profile.CreatedAt,
		}
		stats.UsageStats = append(stats.UsageStats, usageStats)
	}

	stats.TotalUseCount = totalUseCount
	stats.LastActivity = lastUsedTime

	return stats, nil
}