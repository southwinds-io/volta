package volta

import (
	"crypto/rand"
	"encoding/json"
	"github.com/awnumar/memguard"
	"testing"
	"time"
)

func TestDestroyKey(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"DestroyInactiveKey", TestDestroyInactiveKey},
		{"DestroyActiveKeyFailure", TestDestroyActiveKeyFailure},
		{"DestroyCurrentKeyFailure", TestDestroyCurrentKeyFailure},
		{"DestroyKeyWithSecretsFailure", TestDestroyKeyWithSecretsFailure},
		{"DestroyNonExistentKeyFailure", TestDestroyNonExistentKeyFailure},
		{"DestroyKeyEmptyIDFailure", TestDestroyKeyEmptyIDFailure},
		{"DestroyKeyClosedVaultFailure", TestDestroyKeyClosedVaultFailure},
		{"DestroyKeyMetadataPersistence", TestDestroyKeyMetadataPersistence},
		{"DestroyKeyMemoryCleanup", TestDestroyKeyMemoryCleanup},
	}

	// Clean up before AND after tests
	cleanup(t)
	defer cleanup(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestDestroyInactiveKey(t *testing.T) {
	vault := createTestVaultWithMultipleKeys(t)

	// Ensure proper cleanup with error handling
	defer func() {
		if vault != nil && !vault.closed {
			vault.Close()
		}
	}()

	// Get initial key count
	initialKeyCount := len(vault.keyMetadata)
	if initialKeyCount < 2 {
		t.Fatal("Test requires at least 2 keys")
	}

	// Find an inactive key to destroy
	var inactiveKeyID string
	for keyID, metadata := range vault.keyMetadata {
		if keyID != vault.currentKeyID && metadata.Status == KeyStatusInactive {
			inactiveKeyID = keyID
			break
		}
	}

	if inactiveKeyID == "" {
		t.Fatal("No inactive key found for testing")
	}

	// Destroy the inactive key
	err := vault.DestroyKey(inactiveKeyID)
	if err != nil {
		t.Fatalf("Failed to destroy inactive key: %v", err)
	}

	// Verify key is removed from memory
	if _, exists := vault.keyEnclaves[inactiveKeyID]; exists {
		t.Error("Key enclave still exists in memory after destruction")
	}

	// Verify key is removed from metadata
	if _, exists := vault.keyMetadata[inactiveKeyID]; exists {
		t.Error("Key metadata still exists after destruction")
	}

	// Verify metadata count decreased
	if len(vault.keyMetadata) != initialKeyCount-1 {
		t.Errorf("Expected %d keys after destruction, got %d",
			initialKeyCount-1, len(vault.keyMetadata))
	}

	// Verify current key is unchanged
	if vault.currentKeyID != "test-current-key" {
		t.Error("Current key ID should not change when destroying inactive key")
	}
}

func TestDestroyCurrentKeyFailure(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)
	defer vault.Close()

	currentKeyID := vault.currentKeyID
	if currentKeyID == "" {
		t.Fatal("No current key set")
	}

	// Attempt to destroy current key should fail
	err := vault.DestroyKey(currentKeyID)
	if err == nil {
		t.Error("Expected error when destroying current key")
	}

	expectedMsg := "cannot destroy active key"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
	}

	// Verify key is still present
	if _, exists := vault.keyEnclaves[currentKeyID]; !exists {
		t.Error("Current key was removed from memory")
	}

	if _, exists := vault.keyMetadata[currentKeyID]; !exists {
		t.Error("Current key metadata was removed")
	}
}

func TestDestroyActiveKeyFailure(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)
	defer vault.Close()

	// Find an active key that's not current
	var activeKeyID string
	for keyID, metadata := range vault.keyMetadata {
		if keyID != vault.currentKeyID && metadata.Active && metadata.Status == KeyStatusActive {
			activeKeyID = keyID
			break
		}
	}

	if activeKeyID == "" {
		// Create an active key for testing
		activeKeyID = createActiveTestKey(t, vault)
	}

	// Attempt to destroy active key should fail
	err := vault.DestroyKey(activeKeyID)
	if err == nil {
		t.Error("Expected error when destroying active key")
	}

	expectedMsg := "can only destroy inactive keys"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
	}
}

func TestDestroyKeyWithSecretsFailure(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	options := createTestOptions()
	// Create a vault with a single key first
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	// Store a secret with the current key
	secretData := []byte("test secret data")
	secretID := "test-secret"

	currentKeyID := vault.currentKeyID
	_, err := vault.StoreSecret(secretID, secretData, nil, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Now rotate the key (this makes the old key inactive but keeps the secret)
	_, err = vault.RotateDataEncryptionKey("TestDestroyKeyWithSecretsFailure")
	if err != nil {
		t.Fatalf("Failed to rotate keys: %v", err)
	}

	// The old key should now be inactive but still referenced by the secret
	// Attempt to destroy the old key should fail
	err = vault.DestroyKey(currentKeyID)
	if err == nil {
		t.Error("Expected error when destroying key with secrets")
	}

	expectedMsg := "key is still in use"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
	}

	// Should list the secret using the key
	if !contains(err.Error(), secretID) {
		t.Errorf("Expected error to mention secret ID '%s'", secretID)
	}
}

func TestDestroyNonExistentKeyFailure(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)
	defer vault.Close()

	nonExistentKeyID := "non-existent-key-id"

	err := vault.DestroyKey(nonExistentKeyID)
	if err == nil {
		t.Error("Expected error when destroying non-existent key")
	}

	expectedMsg := "key " + nonExistentKeyID + " not found"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, err.Error())
	}
}

func TestDestroyKeyEmptyIDFailure(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)
	defer vault.Close()

	err := vault.DestroyKey("")
	if err == nil {
		t.Error("Expected error when destroying key with empty ID")
	}

	expectedMsg := "key ID cannot be empty"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, err.Error())
	}
}

func TestDestroyKeyClosedVaultFailure(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)

	// Close the vault
	vault.Close()

	err := vault.DestroyKey("any-key-id")
	if err == nil {
		t.Error("Expected error when destroying key in closed vault")
	}

	expectedMsg := "vault is closed"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, err.Error())
	}
}

func TestDestroyKeyMetadataPersistence(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)
	defer vault.Close()

	// Find an inactive key
	var inactiveKeyID string
	for keyID, metadata := range vault.keyMetadata {
		if keyID != vault.currentKeyID && metadata.Status == KeyStatusInactive {
			inactiveKeyID = keyID
			break
		}
	}

	if inactiveKeyID == "" {
		inactiveKeyID = createInactiveTestKey(t, vault)
	}

	// Get the store to verify persistence
	store := vault.store

	// Destroy the key
	err := vault.DestroyKey(inactiveKeyID)
	if err != nil {
		t.Fatalf("Failed to destroy key: %v", err)
	}

	// Verify metadata was persisted correctly
	exists, err := store.MetadataExists()
	if err != nil {
		t.Fatalf("Failed to check metadata existence: %v", err)
	}

	if !exists {
		t.Error("Metadata should exist after key destruction")
	}

	// Load and verify metadata no longer contains destroyed key
	encryptedMetadata, err := store.LoadMetadata()
	if err != nil {
		t.Fatalf("Failed to load metadata: %v", err)
	}

	decryptedMetadata, err := vault.decryptWithKeyEnclave(encryptedMetadata.Data, vault.derivationKeyEnclave)
	if err != nil {
		t.Fatalf("Failed to decrypt metadata: %v", err)
	}

	var rotationMetadata KeyRotationMetadata
	err = json.Unmarshal(decryptedMetadata, &rotationMetadata)
	if err != nil {
		t.Fatalf("Failed to parse metadata: %v", err)
	}

	// Verify destroyed key is not in persisted metadata
	if _, exists = rotationMetadata.Keys[inactiveKeyID]; exists {
		t.Error("Destroyed key still exists in persisted metadata")
	}

	if _, exists = rotationMetadata.EncryptedKeys[inactiveKeyID]; exists {
		t.Error("Destroyed key still exists in persisted encrypted keys")
	}
}

func TestDestroyKeyMemoryCleanup(t *testing.T) {
	// Clean up any previous test artifacts
	cleanup(t)

	vault := createTestVaultWithMultipleKeys(t)
	defer vault.Close()

	inactiveKeyID := createInactiveTestKey(t, vault)

	// Verify key exists in memory before destruction
	enclave, exists := vault.keyEnclaves[inactiveKeyID]
	if !exists {
		t.Fatal("Test key not found in enclaves")
	}

	// Destroy the key
	err := vault.DestroyKey(inactiveKeyID)
	if err != nil {
		t.Fatalf("Failed to destroy key: %v", err)
	}

	// Verify memory cleanup
	if _, exists := vault.keyEnclaves[inactiveKeyID]; exists {
		t.Error("Key enclave still exists in memory after destruction")
	}

	// Note: We can't easily test that enclave.Destroy() was called
	// since memguard doesn't expose the internal state
	// But we can verify the enclave is gone from our map
	if enclave == nil {
		t.Error("Original enclave reference should not be nil for this test")
	}
}

// Helper functions for key destruction tests

func createInactiveTestKey(t *testing.T, vault *Vault) string {
	// Generate a test key
	testKey := make([]byte, 32)
	_, err := rand.Read(testKey)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	keyID := generateKeyID()
	enclave := memguard.NewEnclave(testKey)

	// Add to vault
	vault.keyEnclaves[keyID] = enclave
	vault.keyMetadata[keyID] = KeyMetadata{
		KeyID:         keyID,
		Status:        KeyStatusInactive,
		Active:        false,
		CreatedAt:     time.Now(),
		DeactivatedAt: timePtr(time.Now()),
		Version:       1,
	}

	return keyID
}

func createActiveTestKey(t *testing.T, vault *Vault) string {
	// Generate a test key
	testKey := make([]byte, 32)
	_, err := rand.Read(testKey)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	keyID := generateKeyID()
	enclave := memguard.NewEnclave(testKey)

	// Add to vault as active (but not current)
	vault.keyEnclaves[keyID] = enclave
	vault.keyMetadata[keyID] = KeyMetadata{
		KeyID:     keyID,
		Status:    KeyStatusActive,
		Active:    true,
		CreatedAt: time.Now(),
		Version:   1,
	}

	return keyID
}

func timePtr(t time.Time) *time.Time {
	return &t
}
