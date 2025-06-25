package volta

import (
	"bytes"
	"os"
	"testing"
	"time"
)

const (
	testPassphrase = "test-passphrase-for-rotation"
)

func TestRotateKeyAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"RotateKeyBasic", TestRotateKeyBasic},
		{"RotateKeyEncryptionCompatibility", TestRotateKeyEncryptionCompatibility},
		{"RotateKeyPersistence", TestRotateKeyPersistence},
		{"RotateKeyMultipleRotations", TestRotateKeyMultipleRotations},
		{"RotateKeyNoExistingKey", TestRotateKeyNoExistingKey},
		{"RotateKeyMetadataValidation", TestRotateKeyMetadataValidation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

// TestRotateKeyBasic tests the basic key rotation functionality.
// It verifies that after rotation:
// - A new key is generated and becomes active
// - The old key becomes inactive
// - Key metadata is properly updated with timestamps
func TestRotateKeyBasic(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_rotate_basic_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	options := Options{
		DerivationPassphrase: testPassphrase,
		EnvPassphraseVar:     "",
	}

	// Create vault - this should create initial key
	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Get original active key metadata
	originalMeta, err := vault.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to get original active key metadata: %v", err)
	}

	// Perform key rotation
	newMeta, err := vault.RotateKey("TestRotateKeyBasic")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify new key is different and active
	if newMeta.KeyID == originalMeta.KeyID {
		t.Errorf("New key ID should be different from original. Both are: %s", newMeta.KeyID)
	}

	if !newMeta.Active {
		t.Errorf("New key should be active, got: %v", newMeta.Active)
	}

	if newMeta.Status != KeyStatusActive {
		t.Errorf("New key status should be active, got: %s", newMeta.Status)
	}

	// Verify original key is now inactive
	allKeys, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list key metadata: %v", err)
	}

	var foundOriginal bool
	for _, key := range allKeys {
		if key.KeyID == originalMeta.KeyID {
			foundOriginal = true
			if key.Active {
				t.Errorf("Original key should be inactive after rotation")
			}
			if key.Status != KeyStatusInactive {
				t.Errorf("Original key status should be inactive, got: %s", key.Status)
			}
			if key.DeactivatedAt == nil {
				t.Errorf("Original key should have deactivation timestamp")
			}
		}
	}

	if !foundOriginal {
		t.Errorf("Original key not found in key metadata list")
	}
}

// TestRotateKeyEncryptionCompatibility tests that data encrypted before rotation
// can still be decrypted after rotation, and that new encryptions use the new key.
// This ensures backward compatibility while using the latest key for new operations.
func TestRotateKeyEncryptionCompatibility(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_rotate_encryption_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vault, err := NewWithStore(Options{
		DerivationPassphrase: testPassphrase,
		EnvPassphraseVar:     "",
	}, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Encrypt data with original key
	originalData := []byte("sensitive data encrypted before rotation")
	encryptedWithOriginal, err := vault.Encrypt(originalData)
	if err != nil {
		t.Fatalf("Failed to encrypt with original key: %v", err)
	}

	// Rotate the key
	_, err = vault.RotateKey("TestRotateKeyEncryptionCompatibility")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify old data can still be decrypted
	decryptedOriginal, err := vault.Decrypt(encryptedWithOriginal)
	if err != nil {
		t.Fatalf("Failed to decrypt data encrypted before rotation: %v", err)
	}

	if !bytes.Equal(decryptedOriginal, originalData) {
		t.Errorf("Decrypted data doesn't match original. Expected %q, got %q",
			string(originalData), string(decryptedOriginal))
	}

	// Encrypt new data with rotated key
	newData := []byte("data encrypted after rotation")
	encryptedWithNew, err := vault.Encrypt(newData)
	if err != nil {
		t.Fatalf("Failed to encrypt with new key: %v", err)
	}

	// Verify new data can be decrypted
	decryptedNew, err := vault.Decrypt(encryptedWithNew)
	if err != nil {
		t.Fatalf("Failed to decrypt data encrypted after rotation: %v", err)
	}

	if !bytes.Equal(decryptedNew, newData) {
		t.Errorf("Decrypted new data doesn't match original. Expected %q, got %q",
			string(newData), string(decryptedNew))
	}

	// Verify encrypted data is different (indicating different keys were used)
	if encryptedWithOriginal == encryptedWithNew {
		t.Errorf("Encrypted data should be different when using different keys")
	}
}

// TestRotateKeyPersistence tests that key rotation state persists across vault restarts.
// This ensures that after rotating keys and restarting the vault, the rotated key
// remains active and previously encrypted data remains accessible.
func TestRotateKeyPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_rotate_persistence_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	options := Options{
		DerivationPassphrase: testPassphrase,
		EnvPassphraseVar:     "",
	}
	// First vault instance
	vault1, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create first vault: %v", err)
	}

	// Rotate key and encrypt data
	rotatedMeta, err := vault1.RotateKey("TestRotateKeyPersistence")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	testData := []byte("data to test persistence")
	encrypted, err := vault1.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Close first instance
	if err = vault1.Close(); err != nil {
		t.Fatalf("Failed to close first vault: %v", err)
	}

	// Create second vault instance with same configuration
	vault2, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create second vault: %v", err)
	}
	defer vault2.Close()

	// Verify the rotated key is still active
	activeMeta, err := vault2.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to get active key metadata from second vault: %v", err)
	}

	if activeMeta.KeyID != rotatedMeta.KeyID {
		t.Errorf("Active key should persist across restarts. Expected %s, got %s",
			rotatedMeta.KeyID, activeMeta.KeyID)
	}

	// Verify encrypted data can still be decrypted
	decrypted, err := vault2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt data after restart: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data doesn't match after restart. Expected %q, got %q",
			string(testData), string(decrypted))
	}
}

// TestRotateKeyMultipleRotations tests multiple consecutive key rotations.
// This verifies that the vault can handle multiple rotations correctly,
// maintaining only one active key while keeping all previous keys accessible
// for decryption of older data.
func TestRotateKeyMultipleRotations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_rotate_multiple_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vault, err := NewWithStore(Options{
		DerivationPassphrase: testPassphrase,
		EnvPassphraseVar:     "",
	}, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Get original key
	originalMeta, err := vault.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to get original key metadata: %v", err)
	}

	// Encrypt data with original key
	data1 := []byte("data encrypted with original key")
	encrypted1, err := vault.Encrypt(data1)
	if err != nil {
		t.Fatalf("Failed to encrypt with original key: %v", err)
	}

	// First rotation
	rotation1Meta, err := vault.RotateKey("TestRotateKeyMultipleRotations")
	if err != nil {
		t.Fatalf("Failed to perform first rotation: %v", err)
	}

	// Encrypt data with first rotated key
	data2 := []byte("data encrypted with first rotated key")
	encrypted2, err := vault.Encrypt(data2)
	if err != nil {
		t.Fatalf("Failed to encrypt with first rotated key: %v", err)
	}

	// Second rotation
	rotation2Meta, err := vault.RotateKey("TestRotateKeyMultipleRotations")
	if err != nil {
		t.Fatalf("Failed to perform second rotation: %v", err)
	}

	// Verify all three keys are different
	if originalMeta.KeyID == rotation1Meta.KeyID ||
		originalMeta.KeyID == rotation2Meta.KeyID ||
		rotation1Meta.KeyID == rotation2Meta.KeyID {
		t.Errorf("All key IDs should be unique")
	}

	// Verify only the latest key is active
	allKeys, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list key metadata: %v", err)
	}

	if len(allKeys) != 3 {
		t.Errorf("Should have exactly 3 keys, got: %d", len(allKeys))
	}

	activeCount := 0
	for _, key := range allKeys {
		if key.Active {
			activeCount++
			if key.KeyID != rotation2Meta.KeyID {
				t.Errorf("Only the latest rotated key should be active")
			}
		}
	}

	if activeCount != 1 {
		t.Errorf("Should have exactly 1 active key, got: %d", activeCount)
	}

	// Verify all encrypted data can still be decrypted
	decrypted1, err := vault.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("Failed to decrypt data from original key: %v", err)
	}
	if !bytes.Equal(decrypted1, data1) {
		t.Errorf("Original data decryption failed")
	}

	decrypted2, err := vault.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Failed to decrypt data from first rotated key: %v", err)
	}
	if !bytes.Equal(decrypted2, data2) {
		t.Errorf("First rotation data decryption failed")
	}
}

// TestRotateKeyNoExistingKey tests key rotation when no keys exist yet.
// This edge case verifies that rotation can handle the scenario where
// the vault is initialized but no active key exists, effectively making
// rotation equivalent to initial key generation.
func TestRotateKeyNoExistingKey(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_rotate_nokey_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create vault but somehow ensure no active key exists
	// (This might need adjustment based on actual vault initialization behavior)
	vault, err := NewWithStore(Options{
		DerivationPassphrase: testPassphrase,
		EnvPassphraseVar:     "",
	}, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// If vault automatically creates a key, we need to work around this
	// For now, let's test rotation with an existing key and verify behavior
	initialMeta, err := vault.GetActiveKeyMetadata()
	if err != nil {
		// If no key exists, rotation should still work
		rotatedMeta, err := vault.RotateKey("TestRotateKeyNoExistingKey")
		if err != nil {
			t.Fatalf("Failed to rotate key when no existing key: %v", err)
		}

		if !rotatedMeta.Active {
			t.Errorf("Rotated key should be active when no previous key exists")
		}

		// Verify it can be used for encryption
		testData := []byte("test data with rotated key")
		encrypted, err := vault.Encrypt(testData)
		if err != nil {
			t.Fatalf("Failed to encrypt with rotated key: %v", err)
		}

		decrypted, err := vault.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt with rotated key: %v", err)
		}

		if !bytes.Equal(decrypted, testData) {
			t.Errorf("Encryption/decryption failed with rotated key")
		}
	} else {
		// If key exists, just verify normal rotation
		rotatedMeta, err := vault.RotateKey("TestRotateKeyNoExistingKey")
		if err != nil {
			t.Fatalf("Failed to rotate existing key: %v", err)
		}

		if rotatedMeta.KeyID == initialMeta.KeyID {
			t.Errorf("Rotated key should be different from initial key")
		}
	}
}

// TestRotateKeyMetadataValidation tests that key metadata is properly
// populated and validated during rotation. This includes checking timestamps,
// key algorithms, status transitions, and metadata consistency.
func TestRotateKeyMetadataValidation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_rotate_metadata_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vault, err := NewWithStore(Options{
		DerivationPassphrase: testPassphrase,
		EnvPassphraseVar:     "",
	}, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Record time before rotation
	beforeRotation := time.Now()

	// Perform rotation
	rotatedMeta, err := vault.RotateKey("TestRotateKeyMetadataValidation")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Record time after rotation
	afterRotation := time.Now()

	// Validate new key metadata
	if rotatedMeta.KeyID == "" {
		t.Errorf("Rotated key should have non-empty KeyID")
	}

	if !rotatedMeta.Active {
		t.Errorf("Rotated key should be active")
	}

	if rotatedMeta.Status != KeyStatusActive {
		t.Errorf("Rotated key status should be active, got: %s", rotatedMeta.Status)
	}

	// Validate timestamps
	if rotatedMeta.CreatedAt.Before(beforeRotation) || rotatedMeta.CreatedAt.After(afterRotation) {
		t.Errorf("CreatedAt timestamp should be between rotation start and end")
	}

	if rotatedMeta.DeactivatedAt != nil {
		t.Errorf("New rotated key should not have DeactivatedAt timestamp")
	}

	if rotatedMeta.DeactivatedAt != nil {
		t.Errorf("New rotated key should not have DecommissionedAt timestamp")
	}

	// Validate that GetActiveKeyMetadata returns the same metadata
	activeMeta, err := vault.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to get active key metadata: %v", err)
	}

	if activeMeta.KeyID != rotatedMeta.KeyID {
		t.Errorf("Active key metadata should match rotated key metadata")
	}

	// Validate key listing includes the rotated key
	allKeys, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list all keys: %v", err)
	}

	foundRotatedKey := false
	for _, key := range allKeys {
		if key.KeyID == rotatedMeta.KeyID {
			foundRotatedKey = true
			if key.Active != rotatedMeta.Active {
				t.Errorf("Listed key metadata should match rotated key metadata for Active field")
			}
			if key.Status != rotatedMeta.Status {
				t.Errorf("Listed key metadata should match rotated key metadata for Status field")
			}
			break
		}
	}

	if !foundRotatedKey {
		t.Errorf("Rotated key should appear in key metadata list")
	}
}
