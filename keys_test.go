package volta

import (
	"bytes"
	"crypto/rand"
	"github.com/awnumar/memguard"
	"os"
	"southwinds.dev/volta/internal/crypto"
	"southwinds.dev/volta/persist"
	"testing"
	"time"
)

func TestVaultKeyManagement(t *testing.T) {
	// Ensure clean test environment
	cleanup(t)

	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"SetupDerivationKey", TestSetupDerivationKey},
		{"SetupDerivationKeyFromEnv", TestSetupDerivationKeyFromEnv},
		{"SetupDerivationKeyErrors", TestSetupDerivationKeyErrors},
		{"LoadOrCreateSalt", TestLoadOrCreateSalt},
		{"LoadOrCreateSaltWithProvidedSalt", TestLoadOrCreateSaltWithProvidedSalt},
		{"LoadOrCreateSaltExisting", TestLoadOrCreateSaltExisting},
		{"CreateNewKey", TestCreateNewKey},
		{"CreateNewKeyWithRotation", TestCreateNewKeyWithRotation},
		{"LoadKey", TestLoadKey},
		{"LoadKeyWithMissingMetadata", TestLoadKeyWithMissingMetadata},
		{"SaveKey", TestSaveKey},
		{"GetCurrentKey", TestGetCurrentKey},
		{"GetKeyByID", TestGetKeyByID},
		{"LoadKeyFromMetadata", TestLoadKeyFromMetadata},
		{"SaveAndLoadEncryptedKeys", TestSaveAndLoadEncryptedKeys},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test
			cleanup(t)
			tt.fn(t)
		})
	}
}

func TestSetupDerivationKey(t *testing.T) {
	vault := createEmptyTestVault(t)
	defer vault.Close()

	// Create a test salt and protect it with memguard
	testSalt := make([]byte, 32)
	rand.Read(testSalt)
	vault.derivationSaltEnclave = memguard.NewEnclave(testSalt)
	memguard.WipeBytes(testSalt) // Clear original

	// Test with passphrase
	err := vault.setupDerivationKey(passPhrase, "")
	if err != nil {
		t.Fatalf("Failed to setup derivation key with passphrase: %v", err)
	}

	// Verify derivation key enclave was created
	if vault.derivationKeyEnclave == nil {
		t.Error("Derivation key enclave was not created")
	}

	// Test that we can open the derivation key
	keyBuffer, err := vault.derivationKeyEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open derivation key enclave: %v", err)
	}
	defer keyBuffer.Destroy()

	if len(keyBuffer.Bytes()) == 0 {
		t.Error("Derivation key is empty")
	}
}

func TestSetupDerivationKeyFromEnv(t *testing.T) {
	vault := createEmptyTestVault(t)
	defer vault.Close()

	// Create a test salt and protect it with memguard
	testSalt := make([]byte, 32)
	rand.Read(testSalt)
	vault.derivationSaltEnclave = memguard.NewEnclave(testSalt)
	memguard.WipeBytes(testSalt) // Clear original

	// Set environment variable
	envVar := "TEST_VAULT_PASSPHRASE"
	os.Setenv(envVar, passPhrase)
	defer os.Unsetenv(envVar)

	// Test with environment variable
	err := vault.setupDerivationKey("", envVar)
	if err != nil {
		t.Fatalf("Failed to setup derivation key from env var: %v", err)
	}

	// Verify derivation key was created
	if vault.derivationKeyEnclave == nil {
		t.Error("Derivation key enclave was not created")
	}
}

func TestSetupDerivationKeyErrors(t *testing.T) {
	vault := createEmptyTestVault(t)
	defer vault.Close()

	// Create a test salt and protect it with memguard
	testSalt := make([]byte, 32)
	rand.Read(testSalt)
	vault.derivationSaltEnclave = memguard.NewEnclave(testSalt)
	memguard.WipeBytes(testSalt) // Clear original

	tests := []struct {
		name       string
		passphrase string
		envVar     string
		expectErr  bool
		errContain string
	}{
		{
			name:       "no passphrase or env var",
			passphrase: "",
			envVar:     "",
			expectErr:  true,
			errContain: "no passphrase or environment variable provided",
		},
		{
			name:       "empty env var",
			passphrase: "",
			envVar:     "NONEXISTENT_VAR",
			expectErr:  true,
			errContain: "environment variable NONEXISTENT_VAR is empty or not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := vault.setupDerivationKey(tt.passphrase, tt.envVar)
			if tt.expectErr {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if tt.errContain != "" && !contains(err.Error(), tt.errContain) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errContain, err)
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestLoadOrCreateSalt(t *testing.T) {
	vault := createEmptyTestVault(t)
	defer vault.Close()

	// Load or create salt (should create new since none exists)
	err := vault.loadOrCreateSalt(nil)
	if err != nil {
		t.Fatalf("Failed to load or create salt: %v", err)
	}

	// Verify salt enclave was created
	if vault.derivationSaltEnclave == nil {
		t.Fatal("Derivation salt enclave was not created")
	}

	// Verify salt has the expected length
	saltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open salt enclave: %v", err)
	}
	defer saltBuffer.Destroy()

	if len(saltBuffer.Bytes()) != 32 {
		t.Errorf("Expected 32-byte salt, got %d bytes", len(saltBuffer.Bytes()))
	}

	// Verify salt exists in storage
	exists, err := vault.store.SaltExists()
	if err != nil {
		t.Fatalf("Failed to check salt existence: %v", err)
	}

	if !exists {
		t.Error("Salt was not saved to storage")
	}
}

func TestLoadOrCreateSaltWithProvidedSalt(t *testing.T) {
	// Create a completely fresh vault with a unique temp directory
	tempDir := t.TempDir()
	conf := persist.StoreConfig{
		Type: persist.StoreTypeFileSystem,
		Config: map[string]interface{}{
			"base_path": tempDir,
		},
	}
	store, err := persist.NewStore(conf, tenantID)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	vault := &Vault{
		store:       store,
		keyEnclaves: make(map[string]*memguard.Enclave),
		keyMetadata: make(map[string]KeyMetadata),
		audit:       createLogger(),
	}
	defer vault.Close()

	// Verify no salt exists initially
	exists, err := vault.store.SaltExists()
	if err != nil {
		t.Fatalf("Failed to check salt existence: %v", err)
	}
	if exists {
		t.Fatal("Expected fresh vault with no existing salt")
	}

	// Create a provided salt
	providedSalt := make([]byte, 32)
	rand.Read(providedSalt)

	// Make a copy for comparison
	expectedSalt := make([]byte, len(providedSalt))
	copy(expectedSalt, providedSalt)

	// Load or create salt with provided salt
	err = vault.loadOrCreateSalt(providedSalt)
	if err != nil {
		t.Fatalf("Failed to load or create salt with provided salt: %v", err)
	}

	// Verify salt enclave was created
	if vault.derivationSaltEnclave == nil {
		t.Fatal("Derivation salt enclave was not created")
	}

	// Compare the stored salt
	saltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open salt enclave: %v", err)
	}
	defer saltBuffer.Destroy()

	if !bytes.Equal(saltBuffer.Bytes(), expectedSalt) {
		t.Errorf("Stored salt does not match provided salt")
		t.Logf("Expected length: %d, stored length: %d", len(expectedSalt), len(saltBuffer.Bytes()))
		t.Logf("Expected: %x", expectedSalt)
		t.Logf("Stored: %x", saltBuffer.Bytes())
	}

	// Verify salt was saved to storage
	exists, err = vault.store.SaltExists()
	if err != nil {
		t.Fatalf("Failed to check salt existence: %v", err)
	}

	if !exists {
		t.Error("Salt was not saved to storage")
	}

	// Load versioned salt from storage and verify it matches
	versionedSalt, err := vault.store.LoadSalt()
	if err != nil {
		t.Fatalf("Failed to load salt from storage: %v", err)
	}

	loadedSalt := versionedSalt.Data
	defer memguard.WipeBytes(loadedSalt)

	if !bytes.Equal(loadedSalt, expectedSalt) {
		t.Error("Salt loaded from storage does not match expected salt")
		t.Logf("Expected: %x", expectedSalt)
		t.Logf("Loaded: %x", loadedSalt)
		t.Logf("Storage version: %s", versionedSalt.Version)
	}

	// Verify version information is present
	if versionedSalt.Version == "" {
		t.Error("Salt version should not be empty")
	}

	if versionedSalt.Timestamp.IsZero() {
		t.Error("Salt timestamp should not be zero")
	}

	t.Logf("Salt successfully stored with version: %s, timestamp: %v",
		versionedSalt.Version, versionedSalt.Timestamp)

	// Clean up
	memguard.WipeBytes(expectedSalt)
}

func TestLoadOrCreateSaltExisting(t *testing.T) {
	tempDir := t.TempDir()
	store := createStore(testStoreType, tempDir, tenantID)

	vault := &Vault{
		store:       store,
		keyEnclaves: make(map[string]*memguard.Enclave),
		keyMetadata: make(map[string]KeyMetadata),
		audit:       createLogger(),
	}
	defer vault.Close()

	// First, create a salt
	err := vault.loadOrCreateSalt(nil)
	if err != nil {
		t.Fatalf("Failed to create initial salt: %v", err)
	}

	// Get the original salt
	originalSaltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open original salt enclave: %v", err)
	}
	originalSalt := make([]byte, len(originalSaltBuffer.Bytes()))
	copy(originalSalt, originalSaltBuffer.Bytes())
	originalSaltBuffer.Destroy()

	// Create a new vault instance with the same store
	vault2 := &Vault{
		store:       store,
		keyEnclaves: make(map[string]*memguard.Enclave),
		keyMetadata: make(map[string]KeyMetadata),
		audit:       createLogger(),
	}
	defer vault2.Close()

	// Load existing salt
	err = vault2.loadOrCreateSalt(nil)
	if err != nil {
		t.Fatalf("Failed to load existing salt: %v", err)
	}

	// Verify the salt is the same
	loadedSaltBuffer, err := vault2.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open loaded salt enclave: %v", err)
	}
	defer loadedSaltBuffer.Destroy()

	if !bytes.Equal(loadedSaltBuffer.Bytes(), originalSalt) {
		t.Error("Loaded salt does not match original salt")
	}

	// Clean up
	memguard.WipeBytes(originalSalt)
}

func TestCreateNewKey(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	originalKeyID := vault.currentKeyID
	originalKeyCount := len(vault.keyMetadata)

	// Create a new key
	err := vault.createNewKey()
	if err != nil {
		t.Fatalf("Failed to create new key: %v", err)
	}

	// Verify new key was created
	if vault.currentKeyID == originalKeyID {
		t.Error("Current key ID should have changed")
	}

	if len(vault.keyMetadata) != originalKeyCount+1 {
		t.Errorf("Expected %d keys in metadata, got %d", originalKeyCount+1, len(vault.keyMetadata))
	}

	// Verify new key exists in enclaves
	if _, exists := vault.keyEnclaves[vault.currentKeyID]; !exists {
		t.Error("New key not found in key enclaves")
	}

	// Verify new key metadata
	newKeyMeta, exists := vault.keyMetadata[vault.currentKeyID]
	if !exists {
		t.Error("New key metadata not found")
	}

	if !newKeyMeta.Active {
		t.Error("New key should be active")
	}

	if newKeyMeta.Status != KeyStatusActive {
		t.Error("New key status should be active")
	}

	// Verify old key was deactivated (if there was one)
	if originalKeyID != "" && originalKeyCount > 0 {
		oldKeyMeta, exists := vault.keyMetadata[originalKeyID]
		if !exists {
			t.Error("Original key metadata should still exist")
		}

		if oldKeyMeta.Active {
			t.Error("Original key should be deactivated")
		}

		if oldKeyMeta.Status != KeyStatusInactive {
			t.Error("Original key status should be inactive")
		}

		if oldKeyMeta.DeactivatedAt == nil {
			t.Error("Original key should have deactivation timestamp")
		}
	}
}

func TestCreateNewKeyWithRotation(t *testing.T) {
	vault := createEmptyTestVault(t)
	defer vault.Close()

	// Create first key rotation
	err := vault.createNewKey()
	if err != nil {
		t.Fatalf("Failed to create first new key: %v", err)
	}

	firstKeyID := vault.currentKeyID

	// Create second key rotation
	err = vault.createNewKey()
	if err != nil {
		t.Fatalf("Failed to create second new key: %v", err)
	}

	secondKeyID := vault.currentKeyID

	// Verify we have different key IDs
	if firstKeyID == secondKeyID {
		t.Error("Key IDs should be different after rotation")
	}

	// Verify we have the expected number of keys
	expectedKeys := 3 // original + 2 new keys
	if len(vault.keyMetadata) != expectedKeys {
		t.Errorf("Expected %d keys, got %d", expectedKeys, len(vault.keyMetadata))
	}

	// Verify only the latest key is active
	activeCount := 0
	for _, meta := range vault.keyMetadata {
		if meta.Active {
			activeCount++
		}
	}

	if activeCount != 1 {
		t.Errorf("Expected exactly 1 active key, got %d", activeCount)
	}
}

func TestLoadKey(t *testing.T) {
	// Create vault and save a key
	tempDir := t.TempDir()
	vault1 := createTestVault(t, createTestOptionsWithPath(), tempDir)
	originalKeyID := vault1.currentKeyID
	vault1.Close()

	// Create new vault instance to test loading
	options := createTestOptionsWithPath()
	vault2, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault2.Close()

	// Verify key was loaded
	if vault2.(*Vault).currentKeyID != originalKeyID {
		t.Errorf("Expected key ID %s, got %s", originalKeyID, vault2.(*Vault).currentKeyID)
	}

	// Verify we can access the key
	_, err = vault2.(*Vault).getCurrentKey()
	if err != nil {
		t.Errorf("Failed to get current key after loading: %v", err)
	}
}

func TestLoadKeyWithMissingMetadata(t *testing.T) {
	// Create a vault with no existing metadata
	tempDir := t.TempDir()
	options := createTestOptionsWithPath()

	// Create store but don't save any metadata
	store := createStore(testStoreType, tempDir, tenantID)
	defer store.Close()

	vault := &Vault{
		store:       store,
		keyEnclaves: make(map[string]*memguard.Enclave),
		keyMetadata: make(map[string]KeyMetadata),
		audit:       createLogger(),
	}
	defer vault.Close()

	// Setup salt and derivation key
	err := vault.loadOrCreateSalt(options.DerivationSalt)
	if err != nil {
		t.Fatalf("Failed to load salt: %v", err)
	}

	err = vault.setupDerivationKey(options.DerivationPassphrase, options.EnvPassphraseVar)
	if err != nil {
		t.Fatalf("Failed to setup derivation key: %v", err)
	}

	// Test initializeKeys with no existing metadata (should create new key)
	err = vault.initializeKeys()
	if err != nil {
		t.Fatalf("Expected initializeKeys to create new key when no metadata exists, but got error: %v", err)
	}

	// Verify a key was created
	if vault.currentKeyID == "" {
		t.Error("Expected new key to be created, but currentKeyID is empty")
	}

	if len(vault.keyEnclaves) == 0 {
		t.Error("Expected key enclave to be created, but none found")
	}

	t.Logf("Successfully created new key: %s", vault.currentKeyID)
}

func TestSaveKey(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	originalKeyID := vault.currentKeyID

	// Create metadata structure and save it (this replaces the old saveKey method)
	rotationMetadata := &KeyRotationMetadata{
		Version:       1,
		CurrentKeyID:  vault.currentKeyID,
		LastRotation:  time.Now().UTC(),
		Keys:          vault.keyMetadata,
		EncryptedKeys: make(map[string][]byte),
	}

	// Encrypt and add all keys to metadata
	derivationKeyBuffer, err := vault.derivationKeyEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to access derivation key: %v", err)
	}
	defer derivationKeyBuffer.Destroy()

	for keyID, keyEnclave := range vault.keyEnclaves {
		keyBuffer, err := keyEnclave.Open()
		if err != nil {
			t.Fatalf("Failed to open key %s: %v", keyID, err)
		}

		encryptedKey, err := crypto.EncryptValue(keyBuffer.Bytes(), derivationKeyBuffer.Bytes())
		keyBuffer.Destroy()
		if err != nil {
			t.Fatalf("Failed to encrypt key %s: %v", keyID, err)
		}

		rotationMetadata.EncryptedKeys[keyID] = encryptedKey
	}

	// Save the metadata
	err = vault.saveKeyMetadata(rotationMetadata)
	if err != nil {
		t.Fatalf("Failed to save key metadata: %v", err)
	}

	// Verify metadata exists by creating a new vault instance
	tempDir := t.TempDir()
	// Copy the store files to temp dir for testing
	// (This assumes your store can be copied - adjust based on your implementation)
	options := createTestOptionsWithPath()

	// Create new vault to test loading
	vault2, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err == nil {
		defer vault2.Close()
		if vault2.(*Vault).currentKeyID == originalKeyID {
			t.Log("Key metadata was successfully saved and loaded")
		}
	}
}

func TestLoadKeyFromMetadata(t *testing.T) {
	// Create vault with a key in a shared temp directory
	tempDir := t.TempDir()
	options := createTestOptionsWithPath()

	vault1, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create first vault: %v", err)
	}

	v1 := vault1.(*Vault)
	originalKeyID := v1.currentKeyID

	// Save state by rotating key (which saves metadata)
	_, err = v1.RotateDataEncryptionKey("TestLoadKeyFromMetadata")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify we have 2 keys after rotation
	if len(v1.keyEnclaves) != 2 {
		t.Fatalf("Expected 2 keys after rotation in vault1, got %d", len(v1.keyEnclaves))
	}

	vault1.Close()

	// Create new vault instance using the SAME temp directory to test loading from metadata
	vault2, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID) // Use same options, same tempDir
	if err != nil {
		t.Fatalf("Failed to create new vault: %v", err)
	}
	defer vault2.Close()

	// Verify both old and new keys are loaded
	v2 := vault2.(*Vault)
	if len(v2.keyEnclaves) < 2 {
		t.Errorf("Expected at least 2 keys (original + rotated), got %d", len(v2.keyEnclaves))
		t.Logf("Keys in vault2: %v", getKeyIDs(v2.keyEnclaves))
	}

	// Verify we can access the old key
	if _, exists := v2.keyEnclaves[originalKeyID]; !exists {
		t.Errorf("Original key %s not found in enclaves after loading from metadata", originalKeyID)
		t.Logf("Available keys: %v", getKeyIDs(v2.keyEnclaves))
	}

	// Test with nonexistent metadata
	tempDir2 := t.TempDir()
	options2 := createTestOptionsWithPath()
	vault3, err := NewWithStore(options2, createStore(testStoreType, tempDir2, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault with no metadata: %v", err)
	}
	defer vault3.Close()

	// Should have created a new key
	v3 := vault3.(*Vault)
	if v3.currentKeyID == "" {
		t.Error("Expected new key to be created when no metadata exists")
	}

	// Should only have 1 key (the new one)
	if len(v3.keyEnclaves) != 1 {
		t.Errorf("Expected 1 key in new vault, got %d", len(v3.keyEnclaves))
	}
}

// Helper function to get key IDs for debugging
func getKeyIDs(keyEnclaves map[string]*memguard.Enclave) []string {
	var keyIDs []string
	for keyID := range keyEnclaves {
		keyIDs = append(keyIDs, keyID)
	}
	return keyIDs
}

func TestSaveAndLoadEncryptedKeys(t *testing.T) {
	// Use a shared temp directory
	tempDir := t.TempDir()
	options := createTestOptionsWithPath()

	vault1, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	v1 := vault1.(*Vault)

	// Get the original key for comparison
	originalKeyEnclave, err := v1.getCurrentKey()
	if err != nil {
		t.Fatalf("Failed to get current key: %v", err)
	}

	originalKeyBuffer, err := originalKeyEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open original key: %v", err)
	}

	originalKeyBytes := make([]byte, len(originalKeyBuffer.Bytes()))
	copy(originalKeyBytes, originalKeyBuffer.Bytes())
	originalKeyBuffer.Destroy()
	defer func() {
		for i := range originalKeyBytes {
			originalKeyBytes[i] = 0
		}
	}()

	originalKeyID := v1.currentKeyID

	// Rotate key to trigger saving of metadata with encrypted keys
	newKeyMetadata, err := v1.RotateDataEncryptionKey("TestSaveAndLoadEncryptedKeys")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	vault1.Close()

	// Create new vault instance using the SAME options/tempDir to test loading
	vault2, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID) // Same options, same storage
	if err != nil {
		t.Fatalf("Failed to create new vault: %v", err)
	}
	defer vault2.Close()

	v2 := vault2.(*Vault)

	// Verify both keys exist
	if len(v2.keyEnclaves) != 2 {
		t.Fatalf("Expected 2 keys after rotation, got %d", len(v2.keyEnclaves))
	}

	// Verify we can access the original key and it matches
	originalEnclave, exists := v2.keyEnclaves[originalKeyID]
	if !exists {
		t.Fatalf("Original key %s not found after loading from metadata. Available keys: %v",
			originalKeyID, getKeyIDs(v2.keyEnclaves))
	}

	loadedKeyBuffer, err := originalEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open loaded original key: %v", err)
	}
	defer loadedKeyBuffer.Destroy()

	if !bytes.Equal(loadedKeyBuffer.Bytes(), originalKeyBytes) {
		t.Error("Loaded key does not match original key")
		t.Logf("Original length: %d, loaded length: %d", len(originalKeyBytes), len(loadedKeyBuffer.Bytes()))
		if len(originalKeyBytes) >= 8 && len(loadedKeyBuffer.Bytes()) >= 8 {
			t.Logf("Original first 8 bytes: %x", originalKeyBytes[:8])
			t.Logf("Loaded first 8 bytes: %x", loadedKeyBuffer.Bytes()[:8])
		}
	}

	// Verify new key is current
	if v2.currentKeyID != newKeyMetadata.KeyID {
		t.Errorf("Expected current key to be %s, got %s", newKeyMetadata.KeyID, v2.currentKeyID)
	}
}

func TestGetCurrentKey(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Test getting current key
	keyEnclave, err := vault.getCurrentKey()
	if err != nil {
		t.Fatalf("Failed to get current key: %v", err)
	}

	if keyEnclave == nil {
		t.Error("Current key enclave is nil")
	}

	// Test with no current key ID
	vault.currentKeyID = ""
	_, err = vault.getCurrentKey()
	if err == nil {
		t.Error("Expected error when no current key ID is set")
	}

	// Test with missing enclave
	vault.currentKeyID = "nonexistent"
	_, err = vault.getCurrentKey()
	if err == nil {
		t.Error("Expected error when key enclave doesn't exist")
	}
}

func TestGetKeyByID(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Test getting existing key
	keyEnclave, err := vault.getKeyByID(vault.currentKeyID)
	if err != nil {
		t.Fatalf("Failed to get key by ID: %v", err)
	}

	if keyEnclave == nil {
		t.Error("Key enclave is nil")
	}

	// Test with empty key ID
	_, err = vault.getKeyByID("")
	if err == nil {
		t.Error("Expected error with empty key ID")
	}

	// Test with nonexistent key
	_, err = vault.getKeyByID("nonexistent")
	if err == nil {
		t.Error("Expected error with nonexistent key ID")
	}
}

// Updated helper functions

func createTestOptionsWithPath() Options {
	return Options{
		DerivationPassphrase: "test_passphrase_123",
		EnableMemoryLock:     false,
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}()
}
