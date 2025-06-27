package volta

import (
	"bytes"
	"fmt"
	"github.com/awnumar/memguard"
	"southwinds.dev/volta/audit"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"testing"
)

func TestVaultKEKRotation(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"KEKRotationBasic", TestKEKRotationBasic},
		{"KEKRotationWithSecrets", TestKEKRotationWithSecrets},
		{"KEKRotationValidation", TestKEKRotationValidation},
		{"KEKRotationMultipleKeys", TestKEKRotationMultipleKeys},
		{"KEKRotationErrorHandling", TestKEKRotationErrorHandling},
		{"KEKRotationAuditLogging", TestKEKRotationAuditLogging},
	}

	// Ensure clean test environment
	defer cleanup(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestKEKRotationBasic(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Store original salt for comparison (must open enclave to access data)
	originalSaltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open original salt enclave: %v", err)
	}
	originalSalt := make([]byte, len(originalSaltBuffer.Bytes()))
	copy(originalSalt, originalSaltBuffer.Bytes())
	originalSaltBuffer.Destroy()
	defer memguard.WipeBytes(originalSalt) // Clean up at end of test

	// Get original metadata count
	originalKeyCount := len(vault.keyMetadata)
	if originalKeyCount == 0 {
		t.Fatal("Vault should have at least one key")
	}

	// Perform passphrase rotation
	newKEK := "new-secure-passphrase-for-rotation-test"
	reason := "test rotation"

	err = vault.RotateKeyEncryptionKey(newKEK, reason)
	if err != nil {
		t.Fatalf("Failed to rotate passphrase: %v", err)
	}

	// Verify salt changed (must open new salt enclave to compare)
	newSaltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open new salt enclave: %v", err)
	}
	defer newSaltBuffer.Destroy()

	if bytes.Equal(newSaltBuffer.Bytes(), originalSalt) {
		t.Error("Salt should have changed after passphrase rotation")
	}

	// Verify key count remains the same
	if len(vault.keyMetadata) != originalKeyCount {
		t.Errorf("Key count changed: expected %d, got %d", originalKeyCount, len(vault.keyMetadata))
	}

	// Verify vault still functions (can encrypt/decrypt)
	testData := []byte("test data after rotation")
	encrypted, err := vault.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt after passphrase rotation: %v", err)
	}

	decrypted, err := vault.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt after passphrase rotation: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Error("Data mismatch after passphrase rotation")
	}

	// Clean up test data
	memguard.WipeBytes(testData)
	memguard.WipeBytes(decrypted)
}

func TestKEKRotationWithSecrets(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	defer vault.Close()

	// Store multiple secrets before rotation to test different scenarios
	testSecrets := map[string][]byte{
		"secret-1": []byte("sensitive information 1"),
		"secret-2": []byte("sensitive information 2"),
		"secret-3": []byte("sensitive information 3"),
	}

	storedMetadata := make(map[string]*SecretMetadata)

	// Store all test secrets
	for secretID, data := range testSecrets {
		metadata, err := vault.StoreSecret(secretID, data, []string{"pre-rotation"}, ContentTypeText)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secretID, err)
		}
		storedMetadata[secretID] = metadata

		// Verify each secret uses active key initially
		result, err := vault.GetSecret(secretID)
		if err != nil {
			t.Fatalf("Failed to retrieve secret %s before rotation: %v", secretID, err)
		}
		if !result.UsedActiveKey {
			t.Errorf("Expected secret %s to use active key before rotation", secretID)
		}
	}

	// Perform passphrase rotation
	newKEK := "rotated-passphrase-with-secrets"
	err := vault.RotateKeyEncryptionKey(newKEK, "testing with secrets")
	if err != nil {
		t.Fatalf("Failed to rotate passphrase: %v", err)
	}

	// Verify all existing secrets are still accessible after rotation
	for secretID, originalData := range testSecrets {
		result, err := vault.GetSecret(secretID)
		if err != nil {
			t.Fatalf("Failed to retrieve secret %s after rotation: %v", secretID, err)
		}

		// Check data integrity
		if string(result.Data) != string(originalData) {
			t.Errorf("Secret %s data corrupted after passphrase rotation", secretID)
		}

		// Check metadata integrity
		originalMetadata := storedMetadata[secretID]
		if result.Metadata.SecretID != originalMetadata.SecretID {
			t.Errorf("Secret %s metadata corrupted after passphrase rotation", secretID)
		}

		// Log key usage information
		if result.UsedActiveKey {
			t.Logf("Secret %s was re-encrypted with new key during rotation", secretID)
		} else {
			t.Logf("Secret %s still uses old key after rotation", secretID)
		}
	}

	// Store new secrets after rotation
	postRotationSecrets := map[string][]byte{
		"post-secret-1": []byte("new secret after rotation 1"),
		"post-secret-2": []byte("new secret after rotation 2"),
	}

	for secretID, data := range postRotationSecrets {
		metadata, err := vault.StoreSecret(secretID, data, []string{"post-rotation"}, ContentTypeText)
		if err != nil {
			t.Fatalf("Failed to store new secret %s after rotation: %v", secretID, err)
		}

		// Verify new secret is accessible and uses active key
		result, err := vault.GetSecret(secretID)
		if err != nil {
			t.Fatalf("Failed to retrieve new secret %s: %v", secretID, err)
		}

		if string(result.Data) != string(data) {
			t.Errorf("New secret %s data corrupted", secretID)
		}

		if result.Metadata.SecretID != metadata.SecretID {
			t.Errorf("New secret %s metadata corrupted", secretID)
		}

		// New secrets should always use the active key
		if !result.UsedActiveKey {
			t.Errorf("Expected new secret %s to use active key", secretID)
		}
	}

	// Test key usage statistics
	activeKeyCount := 0
	oldKeyCount := 0

	allSecretIDs := make([]string, 0, len(testSecrets)+len(postRotationSecrets))
	for secretID := range testSecrets {
		allSecretIDs = append(allSecretIDs, secretID)
	}
	for secretID := range postRotationSecrets {
		allSecretIDs = append(allSecretIDs, secretID)
	}

	for _, secretID := range allSecretIDs {
		result, err := vault.GetSecret(secretID)
		if err != nil {
			t.Fatalf("Failed to retrieve secret %s for statistics: %v", secretID, err)
		}

		if result.UsedActiveKey {
			activeKeyCount++
		} else {
			oldKeyCount++
		}
	}

	t.Logf("Key usage statistics: %d secrets use active key, %d use old keys",
		activeKeyCount, oldKeyCount)

	// At minimum, all post-rotation secrets should use active key
	if activeKeyCount < len(postRotationSecrets) {
		t.Error("Not all post-rotation secrets use the active key")
	}
}

func TestKEKRotationValidation(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Test empty passphrase
	err := vault.RotateKeyEncryptionKey("", "test")
	if err == nil || !strings.Contains(err.Error(), "passphrase cannot be empty") {
		t.Error("Should reject empty passphrase")
	}

	// Test with closed vault
	closedVault := createEmptyTestVault(t)
	closedVault.Close()

	err = closedVault.RotateKeyEncryptionKey("new-pass", "test")
	if err == nil || !strings.Contains(err.Error(), "vault is closed") {
		t.Error("Should reject rotation on closed vault")
	}

	// Test default reason when empty
	originalAudit := vault.audit
	auditLog := &mockAuditLogger{events: make([]mockAuditEvent, 0)}
	vault.audit = auditLog

	err = vault.RotateKeyEncryptionKey("valid-passphrase", "")
	if err != nil {
		t.Fatalf("Rotation should succeed with empty reason: %v", err)
	}

	// Verify default reason was used in audit log
	found := false
	for _, event := range auditLog.events {
		if event.action == "emergency_passphrase_rotation" {
			if reason, ok := event.metadata["reason"].(string); ok && reason == "manual rotation" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Default reason 'manual rotation' should be used when reason is empty")
	}

	vault.audit = originalAudit
}

func TestKEKRotationMultipleKeys(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Create multiple keys through rotation
	// Rotate to create second key
	_, err := vault.RotateDataEncryptionKey("TestKEKRotationMultipleKeys")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Rotate again to create third key
	_, err = vault.RotateDataEncryptionKey("TestKEKRotationMultipleKeys")
	if err != nil {
		t.Fatalf("Failed to rotate key again: %v", err)
	}

	if len(vault.keyMetadata) < 3 {
		t.Fatalf("Expected at least 3 keys, got %d", len(vault.keyMetadata))
	}

	// Encrypt data with the current key
	testData := []byte("data with current key")
	encrypted, err := vault.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Perform passphrase rotation
	newKEK := "multi-key-rotation-test"
	err = vault.RotateKeyEncryptionKey(newKEK, "testing multiple keys")
	if err != nil {
		t.Fatalf("Failed to rotate passphrase with multiple keys: %v", err)
	}

	// Verify existing encrypted data can still be decrypted
	decrypted, err := vault.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt data after passphrase rotation: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Error("Data mismatch after passphrase rotation")
	}

	// Verify new encryption still works
	newData := []byte("data after passphrase rotation")
	encryptedNew, err := vault.Encrypt(newData)
	if err != nil {
		t.Fatalf("Failed to encrypt after passphrase rotation: %v", err)
	}

	decryptedNew, err := vault.Decrypt(encryptedNew)
	if err != nil {
		t.Fatalf("Failed to decrypt new data: %v", err)
	}

	if string(decryptedNew) != string(newData) {
		t.Error("New data mismatch after passphrase rotation")
	}
}

func TestKEKRotationErrorHandling(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Create a store that will fail on salt save to test rollback
	originalStore := vault.store
	failingStore := &mockFailingStore{
		Store:      originalStore,
		failOnSalt: true,
	}
	vault.store = failingStore

	// Attempt rotation - should fail and rollback
	// Get original salt from enclave for comparison
	originalSaltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open original salt enclave: %v", err)
	}
	originalSalt := make([]byte, len(originalSaltBuffer.Bytes()))
	copy(originalSalt, originalSaltBuffer.Bytes())
	originalSaltBuffer.Destroy()
	defer memguard.WipeBytes(originalSalt)

	// Also capture original salt version for verification
	originalVersionedSalt, err := originalStore.LoadSalt()
	if err != nil {
		t.Fatalf("Failed to load original salt version: %v", err)
	}
	originalSaltVersion := originalVersionedSalt.Version

	err = vault.RotateKeyEncryptionKey("new-passphrase", "test failure")
	if err == nil {
		t.Fatal("Rotation should have failed due to store failure")
	}

	// Verify error mentions versioned save failure
	if !strings.Contains(err.Error(), "mock store failure on salt save") {
		t.Errorf("Error should mention salt save failure, got: %v", err)
	}

	// Verify rollback occurred - salt should be unchanged
	currentSaltBuffer, err := vault.derivationSaltEnclave.Open()
	if err != nil {
		t.Fatalf("Failed to open current salt enclave after failed rotation: %v", err)
	}
	defer currentSaltBuffer.Destroy()

	if !bytes.Equal(currentSaltBuffer.Bytes(), originalSalt) {
		t.Error("Salt should be rolled back after failed rotation")
	}

	// Verify stored salt version is unchanged
	currentVersionedSalt, err := originalStore.LoadSalt()
	if err != nil {
		t.Fatalf("Failed to load current salt version: %v", err)
	}

	if currentVersionedSalt.Version != originalSaltVersion {
		t.Errorf("Salt version should be unchanged after failed rotation. Expected: %s, Got: %s",
			originalSaltVersion, currentVersionedSalt.Version)
	}

	t.Logf("Rollback successful - salt version maintained: %s", currentVersionedSalt.Version)

	// Verify vault still works after failed rotation
	testData := []byte("test after failed rotation")
	encrypted, err := vault.Encrypt(testData)
	if err != nil {
		t.Fatalf("Vault should still work after failed rotation: %v", err)
	}

	decrypted, err := vault.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt after failed rotation: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Error("Data should be intact after failed rotation")
	}

	// Test successful rotation after fixing the store
	vault.store = originalStore

	err = vault.RotateKeyEncryptionKey("new-passphrase-success", "test success after failure")
	if err != nil {
		t.Fatalf("Rotation should succeed with working store: %v", err)
	}

	// Verify version was incremented after successful rotation
	newVersionedSalt, err := originalStore.LoadSalt()
	if err != nil {
		t.Fatalf("Failed to load new salt version: %v", err)
	}

	if newVersionedSalt.Version == originalSaltVersion {
		t.Error("Salt version should be incremented after successful rotation")
	}

	t.Logf("Successful rotation - salt version updated from %s to %s",
		originalSaltVersion, newVersionedSalt.Version)

	// Clean up test data
	memguard.WipeBytes(testData)
	memguard.WipeBytes(decrypted)
}

func TestKEKRotationAuditLogging(t *testing.T) {
	vault := createTestVault(t, createTestOptions(), tempDir)
	defer vault.Close()

	// Setup mock audit logger
	auditLog := &mockAuditLogger{events: make([]mockAuditEvent, 0)}
	vault.audit = auditLog

	keyCount := len(vault.keyEnclaves)
	currentKeyID := vault.currentKeyID
	reason := "audit logging test"

	// Perform rotation
	err := vault.RotateKeyEncryptionKey("audit-test-passphrase", reason)
	if err != nil {
		t.Fatalf("Failed to rotate passphrase: %v", err)
	}

	// Verify audit log contains rotation event
	found := false
	for _, event := range auditLog.events {
		if event.action == "emergency_passphrase_rotation" && event.success {
			// Verify audit event contains expected metadata
			if r, ok := event.metadata["reason"].(string); !ok || r != reason {
				t.Errorf("Expected reason '%s', got '%v'", reason, event.metadata["reason"])
			}

			if count, ok := event.metadata["keys_re_encrypted"].(int); !ok || count != keyCount {
				t.Errorf("Expected keys_re_encrypted %d, got %v", keyCount, event.metadata["keys_re_encrypted"])
			}

			if keyID, ok := event.metadata["current_key_id"].(string); !ok || keyID != currentKeyID {
				t.Errorf("Expected current_key_id '%s', got '%v'", currentKeyID, event.metadata["current_key_id"])
			}

			found = true
			break
		}
	}

	if !found {
		t.Error("Audit log should contain successful passphrase rotation event")
	}
}

// Mock audit logger for testing
type mockAuditLogger struct {
	events []mockAuditEvent
	mu     sync.Mutex
}

type mockAuditEvent struct {
	action   string
	success  bool
	metadata map[string]interface{}
}

func (m *mockAuditLogger) Log(action string, success bool, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, mockAuditEvent{
		action:   action,
		success:  success,
		metadata: metadata,
	})
	return nil
}

func (m *mockAuditLogger) LogSecretAccess(operation, secretID string, success bool, errorMessage string) error {
	return m.Log("secret_access", success, map[string]interface{}{
		"operation": operation,
		"secret_id": secretID,
		"error":     errorMessage,
	})
}

func (m *mockAuditLogger) LogKeyOperation(operation, keyID string, success bool, errorMessage string) error {
	return m.Log("key_operation", success, map[string]interface{}{
		"operation": operation,
		"key_id":    keyID,
		"error":     errorMessage,
	})
}

func (m *mockAuditLogger) Query(options audit.QueryOptions) (audit.QueryResult, error) {
	return audit.QueryResult{}, nil
}

func (m *mockAuditLogger) Close() error {
	return nil
}

// Mock failing store for error handling tests
type mockFailingStore struct {
	persist.Store
	failOnSalt     bool
	failOnMetadata bool
}

func (m *mockFailingStore) SaveSalt(salt []byte, expectedVersion string) (string, error) {
	if m.failOnSalt {
		return "", fmt.Errorf("mock store failure on salt save")
	}
	return m.Store.SaveSalt(salt, expectedVersion)
}

func (m *mockFailingStore) SaveMetadata(encryptedMetadata []byte, expectedVersion string) (string, error) {
	if m.failOnMetadata {
		return "", fmt.Errorf("mock store failure on metadata save")
	}
	return m.Store.SaveMetadata(encryptedMetadata, expectedVersion)
}
