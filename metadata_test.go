package volta

import (
	"encoding/json"
	"southwinds.dev/volta/internal/crypto"
	"testing"
	"time"
)

func TestVaultMetadata(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"ListKeyMetadataUninitialized", TestListKeyMetadataUninitialized},
		{"ListKeyMetadataEmpty", TestListKeyMetadataEmpty},
		{"ListKeyMetadataWithKeys", TestListKeyMetadataWithKeys},
		{"GetActiveKeyMetadataUninitialized", TestGetActiveKeyMetadataUninitialized},
		{"GetActiveKeyMetadataNoActiveKey", TestGetActiveKeyMetadataNoActiveKey},
		{"GetActiveKeyMetadataSuccess", TestGetActiveKeyMetadataSuccess},
		{"GetActiveKeyMetadataMissingMetadata", TestGetActiveKeyMetadataMissingMetadata},
		{"LoadKeyMetadataNewVault", TestLoadKeyMetadataNewVault},
		{"LoadKeyMetadataExisting", TestLoadKeyMetadataExisting},
		{"LoadKeyMetadataCorrupted", TestLoadKeyMetadataCorrupted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestListKeyMetadataUninitialized(t *testing.T) {
	vault := createUninitializedVault(t) // Use uninitialized vault
	defer vault.Close()

	_, err := vault.ListKeyMetadata()
	if err == nil {
		t.Error("Expected error for uninitialized vault")
	}
	t.Logf("Got expected error: %v", err)
}

func TestListKeyMetadataEmpty(t *testing.T) {
	vault := createTestVaultWithKeys(t)

	// Clear metadata but keep keys to simulate empty metadata state
	vault.keyMetadata = make(map[string]KeyMetadata)

	metadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(metadata) != 0 {
		t.Errorf("Expected empty metadata slice, got length: %d", len(metadata))
	}
}

func TestListKeyMetadataWithKeys(t *testing.T) {
	vault := createTestVaultWithKeys(t)

	// Add test metadata
	keyID1 := "key1"
	keyID2 := "key2"
	vault.currentKeyID = keyID1

	now := time.Now()
	deactivatedAt := now.Add(-time.Minute)

	vault.keyMetadata = map[string]KeyMetadata{
		keyID1: {
			KeyID:     keyID1,
			CreatedAt: now,
			Status:    KeyStatusInactive, // Will be updated by ListKeyMetadata
			Active:    false,             // Will be updated by ListKeyMetadata
		},
		keyID2: {
			KeyID:         keyID2,
			CreatedAt:     now.Add(-time.Hour * 2),
			DeactivatedAt: &deactivatedAt,
			Status:        KeyStatusInactive,
			Active:        false,
		},
	}

	metadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(metadata) != 2 {
		t.Errorf("Expected 2 metadata entries, got: %d", len(metadata))
	}

	// Find active key in results
	var activeKey, inactiveKey *KeyMetadata
	for i := range metadata {
		if metadata[i].KeyID == keyID1 {
			activeKey = &metadata[i]
		} else if metadata[i].KeyID == keyID2 {
			inactiveKey = &metadata[i]
		}
	}

	if activeKey == nil {
		t.Fatal("Active key not found in metadata")
	}
	if !activeKey.Active {
		t.Error("Expected active key to be marked as active")
	}
	if activeKey.Status != KeyStatusActive {
		t.Errorf("Expected active key status to be %v, got: %v", KeyStatusActive, activeKey.Status)
	}

	if inactiveKey == nil {
		t.Fatal("Inactive key not found in metadata")
	}
	if inactiveKey.Active {
		t.Error("Expected inactive key to be marked as inactive")
	}
	if inactiveKey.Status != KeyStatusInactive {
		t.Errorf("Expected inactive key status to be %v, got: %v", KeyStatusInactive, inactiveKey.Status)
	}
}

func TestGetActiveKeyMetadataUninitialized(t *testing.T) {
	vault := createUninitializedVault(t) // Use your existing helper

	metadata, err := vault.GetActiveKeyMetadata()
	if err == nil {
		t.Fatal("Expected error for uninitialized vault")
	}
	if err.Error() != "vault is not initialized" {
		t.Errorf("Expected 'vault is not initialized' error, got: %v", err)
	}
	if metadata.KeyID != "" {
		t.Error("Expected empty metadata for uninitialized vault")
	}
}

func TestGetActiveKeyMetadataNoActiveKey(t *testing.T) {
	vault := createTestVaultWithKeys(t)

	vault.currentKeyID = "" // No active key

	metadata, err := vault.GetActiveKeyMetadata()
	if err == nil {
		t.Fatal("Expected error for no active key")
	}
	if err.Error() != "no active key found" {
		t.Errorf("Expected 'no active key found' error, got: %v", err)
	}
	if metadata.KeyID != "" {
		t.Error("Expected empty metadata when no active key")
	}
}

func TestGetActiveKeyMetadataSuccess(t *testing.T) {
	vault := createTestVaultWithKeys(t)

	keyID := "active-key"
	vault.currentKeyID = keyID

	now := time.Now()
	deactivatedAt := now.Add(-time.Minute)

	vault.keyMetadata = map[string]KeyMetadata{
		keyID: {
			KeyID:         keyID,
			CreatedAt:     now,
			DeactivatedAt: &deactivatedAt,    // Should be cleared by GetActiveKeyMetadata
			Status:        KeyStatusInactive, // Should be updated
			Active:        false,             // Should be updated
		},
	}

	metadata, err := vault.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if metadata.KeyID != keyID {
		t.Errorf("Expected KeyID %s, got: %s", keyID, metadata.KeyID)
	}
	if !metadata.Active {
		t.Error("Expected active metadata to be marked as active")
	}
	if metadata.Status != KeyStatusActive {
		t.Errorf("Expected status %v, got: %v", KeyStatusActive, metadata.Status)
	}
	if metadata.DeactivatedAt != nil {
		t.Error("Expected DeactivatedAt to be nil for active key")
	}
}

func TestGetActiveKeyMetadataMissingMetadata(t *testing.T) {
	vault := createTestVaultWithKeys(t)

	vault.currentKeyID = "non-existent-key"
	vault.keyMetadata = make(map[string]KeyMetadata)

	metadata, err := vault.GetActiveKeyMetadata()
	if err == nil {
		t.Fatal("Expected error for missing metadata")
	}
	if err.Error() != "active key metadata not found" {
		t.Errorf("Expected 'active key metadata not found' error, got: %v", err)
	}
	if metadata.KeyID != "" {
		t.Error("Expected empty metadata when metadata not found")
	}
}

func TestLoadKeyMetadataNewVault(t *testing.T) {
	// Create a completely new vault with fresh storage
	vault := createTestVaultWithDerivation(t)
	defer vault.Close()

	// Load metadata from the new vault (should return default empty metadata)
	loadedMetadata, err := vault.loadKeyMetadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify default metadata values for a new vault
	if loadedMetadata.Version != 1 {
		t.Errorf("Expected version 1, got: %d", loadedMetadata.Version)
	}

	if loadedMetadata.CurrentKeyID != "" {
		t.Errorf("Expected empty CurrentKeyID, got: %s", loadedMetadata.CurrentKeyID)
	}

	if len(loadedMetadata.Keys) != 0 {
		t.Errorf("Expected empty Keys map, got length: %d", len(loadedMetadata.Keys))
	}

	// Verify the Keys map is properly initialized
	if loadedMetadata.Keys == nil {
		t.Error("Keys map should be initialized, not nil")
	}

	// Verify LastRotation is zero time for new vault
	if !loadedMetadata.LastRotation.IsZero() {
		t.Errorf("Expected zero LastRotation, got: %v", loadedMetadata.LastRotation)
	}
}

func TestLoadKeyMetadataExisting(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	defer vault.Close()

	// Create test metadata
	keyID := "test-key"
	now := time.Now()
	testMetadata := &KeyRotationMetadata{
		Version:      2,
		CurrentKeyID: keyID,
		LastRotation: now,
		Keys: map[string]KeyMetadata{
			keyID: {
				KeyID:     keyID,
				CreatedAt: now,
				Status:    KeyStatusActive,
				Active:    true,
			},
		},
	}

	// Save metadata using the vault's own method to ensure consistency
	err := vault.saveKeyMetadata(testMetadata)
	if err != nil {
		t.Fatalf("Failed to save test metadata: %v", err)
	}

	// Load metadata using the same vault instance
	loadedMetadata, err := vault.loadKeyMetadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify the loaded metadata
	if loadedMetadata.Version != 2 {
		t.Errorf("Expected version 2, got: %d", loadedMetadata.Version)
	}
	if loadedMetadata.CurrentKeyID != keyID {
		t.Errorf("Expected CurrentKeyID %s, got: %s", keyID, loadedMetadata.CurrentKeyID)
	}
	if len(loadedMetadata.Keys) != 1 {
		t.Errorf("Expected 1 key, got: %d", len(loadedMetadata.Keys))
	}

	key, exists := loadedMetadata.Keys[keyID]
	if !exists {
		t.Fatal("Expected key not found in loaded metadata")
	}
	if key.KeyID != keyID {
		t.Errorf("Expected KeyID %s, got: %s", keyID, key.KeyID)
	}
	if key.Status != KeyStatusActive {
		t.Errorf("Expected Status %v, got: %v", KeyStatusActive, key.Status)
	}
	if !key.Active {
		t.Error("Expected key to be active")
	}
}

func TestLoadKeyMetadataCorrupted(t *testing.T) {
	vault := createTestVaultWithDerivation(t)

	// First, create and save some valid metadata to ensure the file exists
	validMetadata := &KeyRotationMetadata{
		Version: 1,
		Keys:    make(map[string]KeyMetadata),
	}

	// Encrypt and save valid metadata first
	derivationKeyBuffer, err := vault.derivationKeyEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to access derivation key: %v", err)
	}

	metadataBytes, err := json.Marshal(validMetadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	encryptedMetadata, err := crypto.EncryptValue(metadataBytes, derivationKeyBuffer.Bytes())
	derivationKeyBuffer.Destroy()
	if err != nil {
		t.Fatalf("Failed to encrypt metadata: %v", err)
	}

	err = vault.saveMetadataWithRetry(encryptedMetadata)
	if err != nil {
		t.Fatalf("Failed to save valid metadata: %v", err)
	}

	// Verify we can load the valid metadata
	_, err = vault.loadKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to load valid metadata we just created: %v", err)
	}

	// NOW corrupt the metadata
	corruptedData := []byte("this-is-definitely-not-valid-encrypted-data")
	err = vault.saveMetadataWithRetry(corruptedData)
	if err != nil {
		t.Fatalf("Failed to write corrupted data: %v", err)
	}

	// This should fail during decryptValue()
	_, err = vault.loadKeyMetadata()
	if err == nil {
		t.Fatal("Expected error for corrupted metadata")
	}

	t.Logf("Got expected error: %v", err)
}
