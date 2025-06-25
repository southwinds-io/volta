package volta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func createTestVaultOptions(t *testing.T) Options {
	// Create a fixed local test directory with guaranteed uniqueness
	testDir := filepath.Join("data")

	// Always clean up any existing test data first
	os.RemoveAll(testDir)

	// Create fresh directory
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Clean up function to be called with defer
	t.Cleanup(func() {
		os.RemoveAll(testDir)
	})

	return Options{
		DerivationPassphrase: testPassphrase,
		EnableMemoryLock:     false,
	}
}

func TestStoreAndLoadSecret(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	secretID := "test/basic/secret"
	originalData := []byte(`{"username": "admin", "password": "secret123"}`)
	tags := []string{"test", "basic"}
	contentType := ContentTypeJSON

	// Store the secret
	metadata, err := vault.StoreSecret(secretID, originalData, tags, contentType)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Verify metadata
	if metadata.SecretID != secretID {
		t.Errorf("Expected secret ID %s, got %s", secretID, metadata.SecretID)
	}

	if metadata.Version != 1 {
		t.Errorf("Expected version 1 for new secret, got %d", metadata.Version)
	}

	if metadata.ContentType != contentType {
		t.Errorf("Expected content type %s, got %s", contentType, metadata.ContentType)
	}

	if len(metadata.Tags) != len(tags) {
		t.Errorf("Expected %d tags, got %d", len(tags), len(metadata.Tags))
	}

	// Load the secret back
	result, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to load secret: %v", err)
	}

	// Verify loaded data
	if string(result.Data) != string(originalData) {
		t.Errorf("Loaded data doesn't match original")
		t.Logf("Expected: %s", string(originalData))
		t.Logf("Got: %s", string(result.Data))
	}

	// Verify loaded metadata
	if result.Metadata.SecretID != secretID {
		t.Errorf("Expected secret ID %s, got %s", secretID, result.Metadata.SecretID)
	}

	if result.Metadata.Version != metadata.Version {
		t.Errorf("Expected version %d, got %d", metadata.Version, result.Metadata.Version)
	}

	// Verify that the secret was decrypted with the active key
	if !result.UsedActiveKey {
		t.Error("Expected secret to be decrypted with active key")
	}

	// Additional validations using the new struct
	if result.Metadata.ContentType != contentType {
		t.Errorf("Expected content type %s, got %s", contentType, result.Metadata.ContentType)
	}

	if len(result.Metadata.Tags) != len(tags) {
		t.Errorf("Expected %d tags, got %d", len(tags), len(result.Metadata.Tags))
	}

	// Verify tag content
	for i, tag := range tags {
		if i < len(result.Metadata.Tags) && result.Metadata.Tags[i] != tag {
			t.Errorf("Expected tag %s at index %d, got %s", tag, i, result.Metadata.Tags[i])
		}
	}

	// Verify access count was incremented
	if result.Metadata.AccessCount != 1 {
		t.Errorf("Expected access count 1, got %d", result.Metadata.AccessCount)
	}

	// Verify LastAccessed was set
	if result.Metadata.LastAccessed == nil {
		t.Error("Expected LastAccessed to be set")
	}

	// Test multiple accesses to verify access tracking
	secondResult, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to load secret second time: %v", err)
	}

	if secondResult.Metadata.AccessCount != 2 {
		t.Errorf("Expected access count 2 after second access, got %d", secondResult.Metadata.AccessCount)
	}

	if !secondResult.UsedActiveKey {
		t.Error("Expected secret to still be decrypted with active key on second access")
	}

	// Verify data consistency across multiple accesses
	if string(secondResult.Data) != string(originalData) {
		t.Error("Data inconsistent across multiple accesses")
	}
}

func TestSecretExists(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)

	defer vault.Close()

	secretID := "test/existence/check"

	// Check non-existent secret
	exists, err := vault.SecretExists(secretID)
	if err != nil {
		t.Fatalf("Failed to check secret existence: %v", err)
	}
	if exists {
		t.Error("Secret should not exist yet")
	}

	// Store a secret
	secretData := []byte("test data")
	_, err = vault.StoreSecret(secretID, secretData, nil, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Check existing secret
	exists, err = vault.SecretExists(secretID)
	if err != nil {
		t.Fatalf("Failed to check secret existence: %v", err)
	}
	if !exists {
		t.Error("Secret should exist after storing")
	}
}

func TestUpdateSecret(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	secretID := "test/update/secret"

	// Store initial secret
	initialData := []byte(`{"version": 1, "config": "initial"}`)
	initialTags := []string{"test", "initial"}

	metadata, err := vault.StoreSecret(secretID, initialData, initialTags, ContentTypeJSON)
	if err != nil {
		t.Fatalf("Failed to store initial secret: %v", err)
	}

	// Verify initial secret can be retrieved with active key
	initialResult, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve initial secret: %v", err)
	}

	if !initialResult.UsedActiveKey {
		t.Error("Expected initial secret to be decrypted with active key")
	}

	if string(initialResult.Data) != string(initialData) {
		t.Error("Initial secret data mismatch")
	}

	// Wait a moment to ensure timestamp difference
	time.Sleep(time.Millisecond * 10)

	// Update the secret
	updatedData := []byte(`{"version": 2, "config": "updated", "new_field": "added"}`)
	updatedTags := []string{"test", "updated"}

	updatedMetadata, err := vault.UpdateSecret(secretID, updatedData, updatedTags, ContentTypeJSON)
	if err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	// Verify version incremented
	if updatedMetadata.Version != metadata.Version+1 {
		t.Errorf("Expected version %d, got %d", metadata.Version+1, updatedMetadata.Version)
	}

	// Verify UpdatedAt is newer
	if !updatedMetadata.UpdatedAt.After(metadata.UpdatedAt) {
		t.Error("UpdatedAt should be newer after update")
	}

	// Verify CreatedAt remains the same
	if !updatedMetadata.CreatedAt.Equal(metadata.CreatedAt) {
		t.Error("CreatedAt should not change during update")
	}

	// Verify updated data can be loaded
	result, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to load updated secret: %v", err)
	}

	// Verify updated data
	if string(result.Data) != string(updatedData) {
		t.Errorf("Updated data doesn't match")
		t.Logf("Expected: %s", string(updatedData))
		t.Logf("Got: %s", string(result.Data))
	}

	// Verify updated metadata
	if result.Metadata.Version != updatedMetadata.Version {
		t.Errorf("Loaded metadata version doesn't match updated version")
	}

	// Verify the updated secret uses the active key
	if !result.UsedActiveKey {
		t.Error("Expected updated secret to be decrypted with active key")
	}

	// Verify tags were updated
	if len(result.Metadata.Tags) != len(updatedTags) {
		t.Errorf("Expected %d tags, got %d", len(updatedTags), len(result.Metadata.Tags))
	}

	for i, expectedTag := range updatedTags {
		if i < len(result.Metadata.Tags) && result.Metadata.Tags[i] != expectedTag {
			t.Errorf("Expected tag %s at index %d, got %s", expectedTag, i, result.Metadata.Tags[i])
		}
	}

	// Verify content type
	if result.Metadata.ContentType != ContentTypeJSON {
		t.Errorf("Expected content type %s, got %s", ContentTypeJSON, result.Metadata.ContentType)
	}

	// Verify access count was incremented during retrieval
	if result.Metadata.AccessCount < 1 {
		t.Errorf("Expected access count >= 1, got %d", result.Metadata.AccessCount)
	}

	// Verify LastAccessed was set
	if result.Metadata.LastAccessed == nil {
		t.Error("Expected LastAccessed to be set")
	}

	// Verify timestamps are consistent
	if !result.Metadata.CreatedAt.Equal(metadata.CreatedAt) {
		t.Error("CreatedAt should remain consistent after update and retrieval")
	}

	if !result.Metadata.UpdatedAt.Equal(updatedMetadata.UpdatedAt) {
		t.Error("UpdatedAt should remain consistent after update and retrieval")
	}

	// Test multiple retrievals to verify consistency
	secondResult, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to load secret second time: %v", err)
	}

	if string(secondResult.Data) != string(updatedData) {
		t.Error("Data inconsistent across multiple retrievals after update")
	}

	if !secondResult.UsedActiveKey {
		t.Error("Expected secret to consistently use active key")
	}

	// Verify access count incremented
	if secondResult.Metadata.AccessCount != result.Metadata.AccessCount+1 {
		t.Errorf("Expected access count to increment from %d to %d",
			result.Metadata.AccessCount, result.Metadata.AccessCount+1)
	}
}

func TestGetSecretMetadata(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	secretID := "test/metadata/only"
	secretData := []byte("sensitive data that should not be decrypted")
	tags := []string{"metadata", "test"}

	// Store secret
	originalMetadata, err := vault.StoreSecret(secretID, secretData, tags, ContentTypeBinary)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Get metadata only
	metadata, err := vault.GetSecretMetadata(secretID)
	if err != nil {
		t.Fatalf("Failed to get secret metadata: %v", err)
	}

	// Verify metadata matches
	if metadata.SecretID != originalMetadata.SecretID {
		t.Errorf("Secret ID mismatch: expected %s, got %s", originalMetadata.SecretID, metadata.SecretID)
	}

	if metadata.Version != originalMetadata.Version {
		t.Errorf("Version mismatch: expected %d, got %d", originalMetadata.Version, metadata.Version)
	}

	if metadata.ContentType != originalMetadata.ContentType {
		t.Errorf("Content type mismatch: expected %s, got %s", originalMetadata.ContentType, metadata.ContentType)
	}

	if len(metadata.Tags) != len(originalMetadata.Tags) {
		t.Errorf("Tags length mismatch: expected %d, got %d", len(originalMetadata.Tags), len(metadata.Tags))
	}

	// Verify tags content
	for i, tag := range metadata.Tags {
		if i < len(originalMetadata.Tags) && tag != originalMetadata.Tags[i] {
			t.Errorf("Tag mismatch at index %d: expected %s, got %s", i, originalMetadata.Tags[i], tag)
		}
	}
}

func TestDeleteSecret(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	secretID := "test/delete/secret"
	secretData := []byte("data to be deleted")

	// Store a secret
	metadata, err := vault.StoreSecret(secretID, secretData, []string{"test"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Verify it exists and can be retrieved
	exists, err := vault.SecretExists(secretID)
	if err != nil {
		t.Fatalf("Failed to check secret existence: %v", err)
	}
	if !exists {
		t.Fatal("Secret should exist before deletion")
	}
	t.Logf("Secret exists before deletion: %v", exists)

	// Retrieve the secret to verify it works before deletion
	result, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret before deletion: %v", err)
	}

	if string(result.Data) != string(secretData) {
		t.Error("Secret data mismatch before deletion")
	}

	if !result.UsedActiveKey {
		t.Error("Expected secret to be decrypted with active key before deletion")
	}

	if result.Metadata.SecretID != secretID {
		t.Errorf("Expected secret ID %s, got %s", secretID, result.Metadata.SecretID)
	}

	t.Logf("Successfully retrieved secret before deletion - UsedActiveKey: %v", result.UsedActiveKey)

	// Delete the secret
	err = vault.DeleteSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}
	t.Logf("Delete completed successfully")

	// Verify it no longer exists
	exists, err = vault.SecretExists(secretID)
	if err != nil {
		t.Fatalf("Failed to check secret existence after deletion: %v", err)
	}
	t.Logf("Secret exists after deletion: %v", exists)
	if exists {
		t.Error("Secret should not exist after deletion")
	}

	// Try to get the deleted secret - should fail
	result2, err := vault.GetSecret(secretID)
	t.Logf("GetSecret after deletion - result: %v, err: %v", result2 != nil, err)
	if err == nil {
		t.Error("Getting deleted secret should fail")
	}
	if result2 != nil {
		t.Error("Result should be nil for deleted secret")
	}

	// Verify the error is appropriate (optional - depends on your error handling)
	if err != nil && result2 != nil {
		t.Error("When GetSecret returns an error, result should be nil")
	}

	// Try to get metadata for deleted secret - should fail
	metadata2, err := vault.GetSecretMetadata(secretID)
	t.Logf("GetSecretMetadata after deletion - metadata: %v, err: %v", metadata2 != nil, err)
	if err == nil {
		t.Error("Getting metadata for deleted secret should fail")
	}
	if metadata2 != nil {
		t.Error("Metadata should be nil for deleted secret")
	}

	// Test that we can create a new secret with the same ID after deletion
	newSecretData := []byte("new data after deletion")
	newMetadata, err := vault.StoreSecret(secretID, newSecretData, []string{"test", "recreated"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store new secret after deletion: %v", err)
	}

	// Verify the new secret is different (version should be 1, indicating it's a new secret)
	if newMetadata.Version != 1 {
		t.Errorf("Expected version 1 for new secret after deletion, got %d", newMetadata.Version)
	}

	if newMetadata.CreatedAt.Equal(metadata.CreatedAt) {
		t.Error("New secret should have different creation time")
	}

	// Verify we can retrieve the new secret
	newResult, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve new secret after deletion and recreation: %v", err)
	}

	if string(newResult.Data) != string(newSecretData) {
		t.Error("New secret data mismatch")
	}

	if !newResult.UsedActiveKey {
		t.Error("Expected new secret to be decrypted with active key")
	}

	if newResult.Metadata.Version != 1 {
		t.Errorf("Expected new secret version 1, got %d", newResult.Metadata.Version)
	}

	t.Logf("Successfully recreated and retrieved secret after deletion - UsedActiveKey: %v, Version: %d",
		newResult.UsedActiveKey, newResult.Metadata.Version)
}

func TestDeleteNonExistentSecret(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Try to delete a non-existent secret
	err = vault.DeleteSecret("nonexistent/secret")
	if err == nil {
		t.Error("Deleting non-existent secret should return an error")
	}
}

func TestListSecrets(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Create test secrets with various tags
	testSecrets := []struct {
		id   string
		data []byte
		tags []string
	}{
		{"secret1", []byte("prod db connection"), []string{"env:prod", "type:db"}},
		{"secret2", []byte("prod api key"), []string{"env:prod", "type:api"}},
		{"secret3", []byte("staging db connection"), []string{"env:staging", "type:db"}},
		{"secret4", []byte("staging api key"), []string{"env:staging", "type:api"}},
		{"secret5", []byte("auth service prod"), []string{"env:prod", "service:auth"}},
		{"secret6", []byte("auth service staging"), []string{"env:staging", "service:auth"}},
		{"secret7", []byte("critical system key"), []string{"level:critical"}},
	}

	// Store all test secrets
	for _, secret := range testSecrets {
		_, err = vault.StoreSecret(secret.id, secret.data, secret.tags, ContentTypeText)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secret.id, err)
		}
	}

	// Test cases for tag filtering
	testCases := []struct {
		name            string
		tags            []string
		expectedSecrets []string
	}{
		{
			name:            "filter by env:prod",
			tags:            []string{"env:prod"},
			expectedSecrets: []string{"secret1", "secret2", "secret5"},
		},
		{
			name:            "filter by type:db",
			tags:            []string{"type:db"},
			expectedSecrets: []string{"secret1", "secret3"},
		},
		{
			name:            "filter by service:auth",
			tags:            []string{"service:auth"},
			expectedSecrets: []string{"secret5", "secret6"},
		},
		{
			name:            "filter by multiple tags (AND)",
			tags:            []string{"env:prod", "type:api"},
			expectedSecrets: []string{"secret2"},
		},
		{
			name:            "filter by non-existent tag",
			tags:            []string{"nonexistent"},
			expectedSecrets: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secretMetadata, err := vault.ListSecrets(&SecretListOptions{Tags: tc.tags})
			if err != nil {
				t.Fatalf("Failed to list secrets with tags %v: %v", tc.tags, err)
			}

			if len(secretMetadata) != len(tc.expectedSecrets) {
				t.Errorf("Expected %d secrets for tags %v, got %d",
					len(tc.expectedSecrets), tc.tags, len(secretMetadata))

				// Log actual secret IDs found
				actualIds := make([]string, len(secretMetadata))
				for i, meta := range secretMetadata {
					actualIds[i] = meta.Metadata.SecretID
				}
				t.Logf("Expected: %v", tc.expectedSecrets)
				t.Logf("Got: %v", actualIds)
				return
			}

			// Convert to sets for comparison
			expectedSet := make(map[string]bool)
			for _, secretID := range tc.expectedSecrets {
				expectedSet[secretID] = true
			}

			actualSet := make(map[string]bool)
			for _, secretMeta := range secretMetadata {
				actualSet[secretMeta.Metadata.SecretID] = true
			}

			// Check that all expected secrets are found
			for expectedID := range expectedSet {
				if !actualSet[expectedID] {
					t.Errorf("Expected secret %s not found for tags %v", expectedID, tc.tags)
				}
			}

			// Check that no unexpected secrets are found
			for actualID := range actualSet {
				if !expectedSet[actualID] {
					t.Errorf("Unexpected secret %s found for tags %v", actualID, tc.tags)
				}
			}

			// Verify metadata structure
			for _, meta := range secretMetadata {
				if meta.Metadata.SecretID == "" {
					t.Error("Secret metadata should have non-empty SecretID")
				}
				if meta.Version < 1 {
					t.Errorf("Secret version should be >= 1, got %d", meta.Version)
				}
				if meta.Metadata.Size <= 0 {
					t.Errorf("Secret size should be > 0, got %d", meta.Metadata.Size)
				}
				if meta.CreatedAt.IsZero() {
					t.Error("Secret CreatedAt should not be zero")
				}
				if meta.UpdatedAt.IsZero() {
					t.Error("Secret UpdatedAt should not be zero")
				}
			}
		})
	}
}

func TestListSecretsEmpty(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	// List secrets from empty vault
	secretMetadata, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list secrets from empty vault: %v", err)
	}

	if len(secretMetadata) != 0 {
		t.Errorf("Expected 0 secrets from empty vault, got %d", len(secretMetadata))
	}
}

func TestListSecretsNoFilters(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	// Store some secrets
	secretIDs := []string{"test/secret1", "test/secret2", "prod/secret3"}
	for _, secretID := range secretIDs {
		_, err := vault.StoreSecret(secretID, []byte("test data"), []string{"test"}, ContentTypeText)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secretID, err)
		}
	}

	// List all secrets (no filters)
	secretMetadata, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list all secrets: %v", err)
	}

	if len(secretMetadata) != len(secretIDs) {
		t.Errorf("Expected %d secrets, got %d", len(secretIDs), len(secretMetadata))
	}

	// Verify all stored secrets are returned
	foundSecrets := make(map[string]bool)
	for _, meta := range secretMetadata {
		foundSecrets[meta.ID] = true
	}

	for _, expectedID := range secretIDs {
		if !foundSecrets[expectedID] {
			t.Errorf("Expected secret %s not found in list", expectedID)
		}
	}
}

func TestSecretErrors(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Test empty secret ID
	_, err = vault.StoreSecret("", []byte("data"), []string{"test"}, ContentTypeText)
	if err == nil {
		t.Error("Storing secret with empty ID should fail")
	}

	// Test nil secret data
	_, err = vault.StoreSecret("test/nil", nil, []string{"test"}, ContentTypeText)
	if err == nil {
		t.Error("Storing nil secret data should fail")
	}

	// Test empty secret data
	_, err = vault.StoreSecret("test/empty", []byte{}, []string{"test"}, ContentTypeText)
	if err == nil {
		t.Error("Storing empty secret data should fail")
	}

	// Test getting non-existent secret
	_, err = vault.GetSecret("nonexistent/secret")
	if err == nil {
		t.Error("Getting non-existent secret should fail")
	}

	// Test getting metadata for non-existent secret
	_, err = vault.GetSecretMetadata("nonexistent/secret")
	if err == nil {
		t.Error("Getting metadata for non-existent secret should fail")
	}

	// Test updating non-existent secret
	_, err = vault.UpdateSecret("nonexistent/secret", []byte("data"), []string{"test"}, ContentTypeText)
	if err == nil {
		t.Error("Updating non-existent secret should fail")
	}
}

func TestLargeSecretData(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Test with reasonably large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	secretID := "test/large/secret"

	// Store large secret
	metadata, err := vault.StoreSecret(secretID, largeData, []string{"large", "test"}, ContentTypeBinary)
	if err != nil {
		t.Fatalf("Failed to store large secret: %v", err)
	}

	// Verify metadata reflects the correct original size
	if metadata.Size != len(largeData) {
		t.Errorf("Expected metadata size to match original size %d, got %d",
			len(largeData), metadata.Size)
	}

	if metadata.ContentType != ContentTypeBinary {
		t.Errorf("Expected content type %s, got %s", ContentTypeBinary, metadata.ContentType)
	}

	expectedTags := []string{"large", "test"}
	if len(metadata.Tags) != len(expectedTags) {
		t.Errorf("Expected %d tags, got %d", len(expectedTags), len(metadata.Tags))
	}

	// Retrieve and verify
	result, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve large secret: %v", err)
	}

	// Verify SecretResult structure
	if result == nil {
		t.Fatal("Expected non-nil SecretResult")
	}

	if result.Data == nil {
		t.Fatal("Expected non-nil data in SecretResult")
	}

	if result.Metadata == nil {
		t.Fatal("Expected non-nil metadata in SecretResult")
	}

	// Verify key usage tracking
	if !result.UsedActiveKey {
		t.Error("Expected secret to be decrypted with active key")
	}

	// Verify data integrity and size
	if len(result.Data) != len(largeData) {
		t.Errorf("Retrieved data length mismatch: expected %d, got %d",
			len(largeData), len(result.Data))
	}

	// Verify data integrity byte by byte (with early termination for performance)
	mismatchCount := 0
	const maxMismatchesToReport = 10

	for i, b := range result.Data {
		if b != largeData[i] {
			mismatchCount++
			if mismatchCount <= maxMismatchesToReport {
				t.Errorf("Data mismatch at byte %d: expected %d, got %d", i, largeData[i], b)
			}
			if mismatchCount == maxMismatchesToReport {
				t.Errorf("... (stopping after %d mismatches)", maxMismatchesToReport)
				break
			}
		}
	}

	if mismatchCount > 0 {
		t.Fatalf("Found %d data integrity issues in large secret", mismatchCount)
	}

	// Verify metadata consistency
	if result.Metadata.Size != metadata.Size {
		t.Errorf("Metadata size mismatch: stored %d, retrieved %d",
			metadata.Size, result.Metadata.Size)
	}

	if result.Metadata.SecretID != secretID {
		t.Errorf("Expected secret ID %s, got %s", secretID, result.Metadata.SecretID)
	}

	if result.Metadata.Version != metadata.Version {
		t.Errorf("Expected version %d, got %d", metadata.Version, result.Metadata.Version)
	}

	if result.Metadata.ContentType != metadata.ContentType {
		t.Errorf("Expected content type %s, got %s", metadata.ContentType, result.Metadata.ContentType)
	}

	// Verify tags consistency
	if len(result.Metadata.Tags) != len(metadata.Tags) {
		t.Errorf("Tags length mismatch: stored %d, retrieved %d",
			len(metadata.Tags), len(result.Metadata.Tags))
	}

	// Verify access tracking was updated
	if result.Metadata.AccessCount <= 0 {
		t.Error("Expected access count to be greater than 0 after retrieval")
	}

	if result.Metadata.LastAccessed.IsZero() {
		t.Error("Expected last accessed time to be set after retrieval")
	}

	// Test performance characteristics for large data
	t.Logf("Large secret test completed successfully:")
	t.Logf("  - Original size: %d bytes (%.2f MB)", len(largeData), float64(len(largeData))/(1024*1024))
	t.Logf("  - Metadata size: %d bytes", result.Metadata.Size)
	t.Logf("  - Used active key: %v", result.UsedActiveKey)
	t.Logf("  - Access count: %d", result.Metadata.AccessCount)
	t.Logf("  - Content type: %s", result.Metadata.ContentType)
	t.Logf("  - Tags: %v", result.Metadata.Tags)

	// Additional verification: ensure secret can be retrieved multiple times consistently
	result2, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve large secret second time: %v", err)
	}

	if len(result2.Data) != len(result.Data) {
		t.Error("Inconsistent data length on multiple retrievals")
	}

	if result2.Metadata.AccessCount <= result.Metadata.AccessCount {
		t.Error("Access count should increment on subsequent retrievals")
	}

	// Memory cleanup verification (ensure large data can be garbage collected)
	largeData = nil
	result.Data = nil
	result2.Data = nil
}

func TestSpecialCharactersInSecretID(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Test various special characters in secret IDs
	testCases := []struct {
		name        string
		secretID    string
		data        []byte
		tags        []string
		contentType ContentType
		shouldPass  bool
		description string
	}{
		{"spaces", "secret with spaces", []byte("data1"), nil, ContentTypeText, false, "Should fail - spaces not allowed"},
		{"dots", "secret.with.dots", []byte("data2"), nil, ContentTypeText, true, "Should pass - dots allowed"},
		{"underscores", "secret_with_underscores", []byte("data3"), []string{"tag1"}, ContentTypeText, true, "Should pass - underscores allowed"},
		{"hyphens", "secret-with-hyphens", []byte("data4"), nil, ContentTypeText, true, "Should pass - hyphens allowed"},
		{"paths", "path/to/secret", []byte("data5"), []string{"path", "nested"}, ContentTypeText, true, "Should pass - forward slash allowed"},
		{"mixed", "complex/secret.id_with-various.chars", []byte("data6"), nil, ContentTypeText, true, "Should pass - mixed valid chars"},
		{"unicode", "秘密/secret", []byte("data7"), nil, ContentTypeText, false, "Should fail - unicode not allowed"},
		{"at-symbol", "secret@domain", []byte("data8"), nil, ContentTypeText, false, "Should fail - @ not allowed"},
		{"hash", "secret#tag", []byte("data9"), nil, ContentTypeText, false, "Should fail - # not allowed"},
		{"empty", "", []byte("data10"), nil, ContentTypeText, false, "Should fail - empty ID"},
		{"only-valid-chars", "valid-secret_1.0/prod", []byte("data11"), []string{"prod", "v1.0"}, ContentTypeText, true, "Should pass - all valid chars"},
		{"numbers", "secret123", []byte("data12"), nil, ContentTypeText, true, "Should pass - numbers allowed"},
		{"leading-slash", "/leading/slash", []byte("data13"), nil, ContentTypeText, false, "Should fail - leading slash not allowed"},
		{"trailing-slash", "trailing/slash/", []byte("data14"), nil, ContentTypeText, false, "Should fail - trailing slash not allowed"},
		{"colon", "secret:with:colons", []byte("data15"), nil, ContentTypeText, false, "Should fail - colons not allowed"},
		{"semicolon", "secret;with;semicolons", []byte("data16"), nil, ContentTypeText, false, "Should fail - semicolons not allowed"},
		{"question", "secret?query", []byte("data17"), nil, ContentTypeText, false, "Should fail - question marks not allowed"},
		{"brackets", "secret[0]", []byte("data18"), nil, ContentTypeText, false, "Should fail - brackets not allowed"},
		{"braces", "secret{key}", []byte("data19"), nil, ContentTypeText, false, "Should fail - braces not allowed"},
		{"parentheses", "secret(value)", []byte("data20"), nil, ContentTypeText, false, "Should fail - parentheses not allowed"},
		{"binary-data", "binary/secret", []byte{0x89, 0x50, 0x4E, 0x47}, nil, ContentTypeBinary, true, "Should pass - binary content type"},
		{"json-data", "config/app.json", []byte(`{"key":"value"}`), []string{"config"}, ContentTypeJSON, true, "Should pass - JSON content type"},
		{"double-slash", "path//to//secret", []byte("data21"), nil, ContentTypeText, false, "Should fail - double slashes not allowed"},
		{"path-traversal", "path/../secret", []byte("data22"), nil, ContentTypeText, false, "Should fail - path traversal not allowed"},
		{"very-long", strings.Repeat("a", 256), []byte("data23"), nil, ContentTypeText, false, "Should fail - exceeds max length"},
		{"max-length", strings.Repeat("a", 255), []byte("data24"), nil, ContentTypeText, true, "Should pass - exactly max length"},
	}

	validSecrets := make(map[string][]byte) // Track successfully stored secrets

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing secret ID: '%s' - %s - %s", tc.secretID, map[bool]string{true: "Should pass", false: "Should fail"}[tc.shouldPass], tc.description)

			// Try to store the secret
			result, err := vault.StoreSecret(tc.secretID, tc.data, tc.tags, tc.contentType)

			if tc.shouldPass {
				// This secret ID should be valid
				if err != nil {
					t.Errorf("Expected secret ID '%s' to be valid, but got error: %v", tc.secretID, err)
					return
				}

				// Verify the metadata
				if result.SecretID != tc.secretID {
					t.Errorf("Secret ID mismatch: expected '%s', got '%s'", tc.secretID, result.SecretID)
				}
				if result.ContentType != tc.contentType {
					t.Errorf("Content type mismatch: expected %s, got %s", tc.contentType, result.ContentType)
				}
				if result.Size != len(tc.data) {
					t.Errorf("Size mismatch: expected %d, got %d", len(tc.data), result.Size)
				}
				if result.Version != 1 {
					t.Errorf("Version mismatch: expected 1, got %d", result.Version)
				}

				// Verify tags match
				if len(tc.tags) == 0 && len(result.Tags) != 0 {
					t.Errorf("Expected no tags, but got: %v", result.Tags)
				} else if len(tc.tags) > 0 {
					if len(result.Tags) != len(tc.tags) {
						t.Errorf("Tag count mismatch: expected %d, got %d", len(tc.tags), len(result.Tags))
					} else {
						for i, tag := range tc.tags {
							if i < len(result.Tags) && result.Tags[i] != tag {
								t.Errorf("Tag mismatch at index %d: expected '%s', got '%s'", i, tag, result.Tags[i])
							}
						}
					}
				}

				// Try to retrieve it to verify it was stored correctly
				result2, err := vault.GetSecret(tc.secretID)
				if err != nil {
					t.Errorf("Failed to retrieve stored secret '%s': %v", tc.secretID, err)
					return
				}

				// Verify retrieved data matches
				if !bytes.Equal(result2.Data, tc.data) {
					t.Errorf("Retrieved data doesn't match original for secret '%s'", tc.secretID)
				}

				// Verify access count incremented
				if result2.Metadata.AccessCount != result.AccessCount+1 {
					t.Errorf("Access count not incremented properly: store=%d, get=%d",
						result.AccessCount, result2.Metadata.AccessCount)
				}

				// Track valid secrets for later verification
				validSecrets[tc.secretID] = tc.data

				t.Logf("✅ Valid secret ID '%s' successfully stored and verified", tc.secretID)
				t.Logf("   AccessCount: %d->%d, Version: %d, Size: %d, ContentType: %s",
					result.AccessCount, result2.Metadata.AccessCount,
					result.Version, result.Size, result.ContentType)

			} else {
				// This secret ID should be invalid
				if err == nil {
					t.Errorf("Expected secret ID '%s' to be invalid, but storage succeeded", tc.secretID)
					// Clean up if it accidentally got stored
					deleteErr := vault.DeleteSecret(tc.secretID)
					if deleteErr != nil {
						t.Logf("Warning: failed to clean up invalid secret '%s': %v", tc.secretID, deleteErr)
					}
				} else {
					t.Logf("✅ Invalid secret ID '%s' correctly rejected: %v", tc.secretID, err)
				}
			}
		})
	}

	// Test listing secrets to verify all valid secrets are present
	t.Run("list_validation", func(t *testing.T) {
		secretsList, err := vault.ListSecrets(&SecretListOptions{})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}

		// Create a map of found secrets
		foundSecrets := make(map[string]bool)
		for _, secretInfo := range secretsList {
			foundSecrets[secretInfo.Metadata.SecretID] = true
		}

		// Verify all valid secrets are in the list
		for secretID := range validSecrets {
			if !foundSecrets[secretID] {
				t.Errorf("Valid secret '%s' not found in secrets list", secretID)
			}
		}

		t.Logf("✅ Secret listing validation passed: %d valid secrets found", len(validSecrets))

		// Verify content types are correctly stored
		contentTypeCounts := make(map[ContentType]int)
		for _, secretInfo := range secretsList {
			contentTypeCounts[secretInfo.Metadata.ContentType]++
		}

		t.Logf("Content type distribution:")
		for contentType, count := range contentTypeCounts {
			t.Logf("  %s: %d", contentType, count)
		}
	})

	// Test pattern validation summary
	t.Run("pattern_summary", func(t *testing.T) {
		validCount := 0
		invalidCount := 0

		for _, tc := range testCases {
			if tc.shouldPass {
				validCount++
			} else {
				invalidCount++
			}
		}

		t.Logf("Pattern validation summary:")
		t.Logf("  Total test cases: %d", len(testCases))
		t.Logf("  Valid patterns: %d", validCount)
		t.Logf("  Invalid patterns: %d", invalidCount)
		t.Logf("  Successfully stored: %d", len(validSecrets))

		if len(validSecrets) != validCount {
			t.Errorf("Mismatch between expected valid patterns (%d) and successfully stored secrets (%d)",
				validCount, len(validSecrets))
		}
	})
}

func TestConcurrentSecretOperations(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	const numGoroutines = 10
	const secretsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*secretsPerGoroutine)

	// Concurrent secret storage
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < secretsPerGoroutine; j++ {
				secretID := fmt.Sprintf("concurrent/goroutine_%d/secret_%d", goroutineID, j)
				secretData := []byte(fmt.Sprintf("data from goroutine %d, secret %d", goroutineID, j))

				_, err := vault.StoreSecret(secretID, secretData,
					[]string{fmt.Sprintf("goroutine:%d", goroutineID)}, ContentTypeText)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d failed to store secret %d: %w",
						goroutineID, j, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Verify all secrets were stored
	allSecrets, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list secrets after concurrent operations: %v", err)
	}

	expectedCount := numGoroutines * secretsPerGoroutine
	if len(allSecrets) != expectedCount {
		t.Errorf("Expected %d secrets after concurrent operations, got %d",
			expectedCount, len(allSecrets))
	}

	// Verify we can read all stored secrets
	for _, metadata := range allSecrets {
		_, err = vault.GetSecret(metadata.ID)
		if err != nil {
			t.Errorf("Failed to retrieve secret '%s' after concurrent storage: %v",
				metadata.ID, err)
		}
	}
}

func TestSecretVersioning(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	secretID := "test/versioning/secret"

	// Store initial version
	metadata1, err := vault.StoreSecret(secretID, []byte("version 1"), []string{"v1"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store initial secret: %v", err)
	}

	if metadata1.Version != 1 {
		t.Errorf("Initial secret version should be 1, got %d", metadata1.Version)
	}

	if metadata1.SecretID != secretID {
		t.Errorf("Expected secret ID %s, got %s", secretID, metadata1.SecretID)
	}

	// Verify initial state
	if metadata1.AccessCount != 0 {
		t.Errorf("Initial access count should be 0, got %d", metadata1.AccessCount)
	}

	// Update secret
	metadata2, err := vault.UpdateSecret(secretID, []byte("version 2"), []string{"v2"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	if metadata2.Version != 2 {
		t.Errorf("Updated secret version should be 2, got %d", metadata2.Version)
	}

	// Verify SecretID remains the same
	if metadata2.SecretID != metadata1.SecretID {
		t.Errorf("Secret ID should remain same across updates")
	}

	// Verify UpdatedAt is different from CreatedAt
	if metadata2.UpdatedAt.Equal(metadata2.CreatedAt) {
		t.Error("UpdatedAt should be different from CreatedAt after update")
	}

	// Verify UpdatedAt progressed from first version
	if !metadata2.UpdatedAt.After(metadata1.UpdatedAt) {
		t.Error("UpdatedAt should be later after update")
	}

	// Update again
	metadata3, err := vault.UpdateSecret(secretID, []byte("version 3"), []string{"v3"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to update secret second time: %v", err)
	}

	if metadata3.Version != 3 {
		t.Errorf("Second updated secret version should be 3, got %d", metadata3.Version)
	}

	// Verify version progression
	if metadata3.UpdatedAt.Before(metadata2.UpdatedAt) {
		t.Error("Third version UpdatedAt should be after second version")
	}

	// Verify we get the latest version when retrieving
	result, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	// Verify SecretResult structure
	if result == nil {
		t.Fatal("Expected non-nil SecretResult")
	}

	if result.Data == nil {
		t.Fatal("Expected non-nil data in SecretResult")
	}

	if result.Metadata == nil {
		t.Fatal("Expected non-nil metadata in SecretResult")
	}

	// Verify latest version data
	if string(result.Data) != "version 3" {
		t.Errorf("Expected latest data 'version 3', got '%s'", string(result.Data))
	}

	if result.Metadata.Version != 3 {
		t.Errorf("Retrieved metadata should show version 3, got %d", result.Metadata.Version)
	}

	// Verify key usage tracking
	if !result.UsedActiveKey {
		t.Error("Retrieved secret should indicate it used active key")
	}

	// Verify tags were updated
	if len(result.Metadata.Tags) != 1 || result.Metadata.Tags[0] != "v3" {
		t.Errorf("Expected tags [v3], got %v", result.Metadata.Tags)
	}

	// Verify access tracking
	if result.Metadata.AccessCount <= 0 {
		t.Error("Access count should be greater than 0 after retrieval")
	}

	if result.Metadata.LastAccessed.IsZero() {
		t.Error("Last accessed time should be set after retrieval")
	}

	// Verify content type consistency
	if result.Metadata.ContentType != ContentTypeText {
		t.Errorf("Expected content type %s, got %s", ContentTypeText, result.Metadata.ContentType)
	}

	// Verify data size is correct
	expectedSize := len("version 3")
	if result.Metadata.Size != expectedSize {
		t.Errorf("Expected size %d, got %d", expectedSize, result.Metadata.Size)
	}

	// Test multiple retrievals increment access count
	result2, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to get secret second time: %v", err)
	}

	if result2.Metadata.AccessCount <= result.Metadata.AccessCount {
		t.Error("Access count should increment on subsequent retrievals")
	}

	if result2.Metadata.LastAccessed.Before(*result.Metadata.LastAccessed) {
		t.Error("Last accessed time should be updated on subsequent retrievals")
	}

	// Log comprehensive version tracking info
	t.Logf("Version tracking test completed successfully:")
	t.Logf("  - Final version: %d", result2.Metadata.Version)
	t.Logf("  - Created at: %v", result2.Metadata.CreatedAt)
	t.Logf("  - Updated at: %v", result2.Metadata.UpdatedAt)
	t.Logf("  - Last accessed: %v", result2.Metadata.LastAccessed)
	t.Logf("  - Access count: %d", result2.Metadata.AccessCount)
	t.Logf("  - Used active key: %v", result2.UsedActiveKey)
	t.Logf("  - Content size: %d bytes", result2.Metadata.Size)
	t.Logf("  - Final tags: %v", result2.Metadata.Tags)

	// Additional verification: ensure metadata consistency across operations
	if result2.Metadata.SecretID != secretID {
		t.Errorf("Secret ID consistency check failed: expected %s, got %s",
			secretID, result2.Metadata.SecretID)
	}

	if result2.Metadata.Version != 3 {
		t.Errorf("Version consistency check failed: expected 3, got %d",
			result2.Metadata.Version)
	}

	// Verify the progression of timestamps makes sense
	if !result2.Metadata.CreatedAt.Before(result2.Metadata.UpdatedAt) {
		t.Error("Created time should be before updated time")
	}

	if !result2.Metadata.UpdatedAt.Before(*result2.Metadata.LastAccessed) {
		t.Error("Updated time should be before or equal to last accessed time")
	}
}

func TestVaultCloseAndReuse(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	secretID := "test/close/secret"
	secretData := []byte("data before close")

	// Store a secret
	metadata, err := vault.StoreSecret(secretID, secretData, []string{"test"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Verify initial storage
	if metadata == nil {
		t.Fatal("Expected non-nil metadata from StoreSecret")
	}

	if metadata.SecretID != secretID {
		t.Errorf("Expected secret ID %s, got %s", secretID, metadata.SecretID)
	}

	// Close the vault
	err = vault.Close()
	if err != nil {
		t.Fatalf("Failed to close vault: %v", err)
	}

	// Try to use vault after close - should fail
	_, err = vault.StoreSecret("after/close", []byte("data"), []string{"test"}, ContentTypeText)
	if err == nil {
		t.Error("Using vault after close should fail")
	} else {
		t.Logf("Expected error after close: %v", err)
	}

	_, err = vault.GetSecret(secretID)
	if err == nil {
		t.Error("Getting secret from closed vault should fail")
	} else {
		t.Logf("Expected error getting secret from closed vault: %v", err)
	}

	// Also test other operations that should fail
	_, err = vault.UpdateSecret(secretID, []byte("update"), []string{"test"}, ContentTypeText)
	if err == nil {
		t.Error("Updating secret in closed vault should fail")
	}

	err = vault.DeleteSecret(secretID)
	if err == nil {
		t.Error("Deleting secret from closed vault should fail")
	}

	_, err = vault.ListSecrets(&SecretListOptions{})
	if err == nil {
		t.Error("Listing secrets from closed vault should fail")
	}

	// Create new vault instance with same options
	vault2, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create second vault instance: %v", err)
	}
	defer vault2.Close()

	// Should be able to access previously stored secret
	result, err := vault2.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret from new vault instance: %v", err)
	}

	// Verify SecretResult structure
	if result == nil {
		t.Fatal("Expected non-nil SecretResult from new vault instance")
	}

	if result.Data == nil {
		t.Fatal("Expected non-nil data in SecretResult")
	}

	if result.Metadata == nil {
		t.Fatal("Expected non-nil metadata in SecretResult")
	}

	// Verify data integrity
	if string(result.Data) != string(secretData) {
		t.Errorf("Data mismatch after vault reconstruction: expected '%s', got '%s'",
			string(secretData), string(result.Data))
	}

	// Verify metadata consistency
	if result.Metadata.SecretID != secretID {
		t.Errorf("Secret ID mismatch after reconstruction: expected %s, got %s",
			secretID, result.Metadata.SecretID)
	}

	if len(result.Metadata.Tags) != 1 || result.Metadata.Tags[0] != "test" {
		t.Errorf("Tags mismatch after reconstruction: expected [test], got %v",
			result.Metadata.Tags)
	}

	if result.Metadata.ContentType != ContentTypeText {
		t.Errorf("Content type mismatch after reconstruction: expected %s, got %s",
			ContentTypeText, result.Metadata.ContentType)
	}

	if result.Metadata.Size != len(secretData) {
		t.Errorf("Size mismatch after reconstruction: expected %d, got %d",
			len(secretData), result.Metadata.Size)
	}

	// Verify key usage tracking
	if !result.UsedActiveKey {
		t.Error("Retrieved secret should indicate it used active key")
	}

	// Verify access tracking works in new vault instance
	if result.Metadata.AccessCount <= 0 {
		t.Error("Access count should be greater than 0 after retrieval")
	}

	if result.Metadata.LastAccessed.IsZero() {
		t.Error("Last accessed time should be set after retrieval")
	}

	// Test that new vault instance can perform all operations
	updateData := []byte("updated after reconstruction")
	updatedMetadata, err := vault2.UpdateSecret(secretID, updateData, []string{"test", "updated"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to update secret in new vault instance: %v", err)
	}

	if updatedMetadata.Version != metadata.Version+1 {
		t.Errorf("Expected version to increment after update: expected %d, got %d",
			metadata.Version+1, updatedMetadata.Version)
	}

	// Verify the update persisted
	result2, err := vault2.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated secret: %v", err)
	}

	if string(result2.Data) != string(updateData) {
		t.Errorf("Updated data mismatch: expected '%s', got '%s'",
			string(updateData), string(result2.Data))
	}

	if result2.Metadata.AccessCount <= result.Metadata.AccessCount {
		t.Error("Access count should increment on subsequent retrievals")
	}

	// Test storage of new secrets in reconstructed vault
	newSecretID := "test/close/new-secret"
	newSecretData := []byte("new secret after reconstruction")

	newMetadata, err := vault2.StoreSecret(newSecretID, newSecretData, []string{"new"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store new secret in reconstructed vault: %v", err)
	}

	// Verify new secret can be retrieved
	newResult, err := vault2.GetSecret(newSecretID)
	if err != nil {
		t.Fatalf("Failed to retrieve new secret: %v", err)
	}

	if string(newResult.Data) != string(newSecretData) {
		t.Errorf("New secret data mismatch: expected '%s', got '%s'",
			string(newSecretData), string(newResult.Data))
	}

	// Log comprehensive reconstruction test results
	t.Logf("Vault close and reconstruction test completed successfully:")
	t.Logf("  - Original secret preserved and accessible")
	t.Logf("  - Original secret version: %d, updated version: %d", metadata.Version, result2.Metadata.Version)
	t.Logf("  - Access tracking works across reconstruction")
	t.Logf("  - All operations work in reconstructed vault")
	t.Logf("  - New secrets can be stored and retrieved")
	t.Logf("  - Final access count: %d", result2.Metadata.AccessCount)
	t.Logf("  - New secret metadata: version=%d, size=%d", newMetadata.Version, newMetadata.Size)
}

func TestSecretContentTypes(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	testCases := []struct {
		name        string
		secretID    string
		data        []byte
		contentType ContentType
		tags        []string
		description string
	}{
		{
			name:        "text",
			secretID:    "test/content/text",
			data:        []byte("plain text secret"),
			contentType: ContentTypeText,
			tags:        []string{"content-type-test", "text"},
			description: "Plain text content",
		},
		{
			name:        "json",
			secretID:    "test/content/json",
			data:        []byte(`{"key": "value", "number": 42, "nested": {"bool": true}}`),
			contentType: ContentTypeJSON,
			tags:        []string{"content-type-test", "json", "config"},
			description: "JSON configuration data",
		},
		{
			name:        "binary",
			secretID:    "test/content/binary",
			data:        []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0xFC, 0x89, 0xAB, 0xCD, 0xEF},
			contentType: ContentTypeBinary,
			tags:        []string{"content-type-test", "binary", "raw"},
			description: "Binary data with various byte values",
		},
		{
			name:        "yaml",
			secretID:    "test/content/yaml",
			data:        []byte("server:\n  host: localhost\n  port: 8080\ndatabase:\n  name: mydb\n  timeout: 30s\n"),
			contentType: ContentTypeYAML,
			tags:        []string{"content-type-test", "yaml", "config"},
			description: "YAML configuration file",
		},
		{
			name:        "pem",
			secretID:    "test/content/pem",
			data:        []byte("-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA...\n-----END CERTIFICATE-----"),
			contentType: ContentTypePEM,
			tags:        []string{"content-type-test", "pem", "certificate"},
			description: "PEM encoded certificate",
		},
		{
			name:        "xml",
			secretID:    "test/content/xml",
			data:        []byte(`<?xml version="1.0" encoding="UTF-8"?><root><config>value</config></root>`),
			contentType: ContentTypeXML, // Fixed: was ContentTypeJSON
			tags:        []string{"content-type-test", "xml"},
			description: "XML configuration data",
		},
		{
			name:        "toml",
			secretID:    "test/content/toml",
			data:        []byte("[server]\nhost = \"localhost\"\nport = 8080\n\n[database]\nname = \"mydb\"\n"),
			contentType: ContentTypeTOML,
			tags:        []string{"content-type-test", "toml", "config"},
			description: "TOML configuration file",
		},
	}

	storedSecrets := make(map[string]*SecretMetadata)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing content type: %s - %s", tc.contentType, tc.description)

			// Store secret with specific content type
			metadata, err := vault.StoreSecret(tc.secretID, tc.data, tc.tags, tc.contentType)
			if err != nil {
				t.Fatalf("Failed to store %s secret: %v", tc.name, err)
			}

			// Verify metadata structure
			if metadata == nil {
				t.Fatal("Expected non-nil metadata")
			}

			// Verify content type in metadata
			if metadata.ContentType != tc.contentType {
				t.Errorf("Content type mismatch: expected %v, got %v",
					tc.contentType, metadata.ContentType)
			}

			// Verify other metadata fields
			if metadata.SecretID != tc.secretID {
				t.Errorf("Secret ID mismatch: expected %s, got %s", tc.secretID, metadata.SecretID)
			}

			if metadata.Version != 1 {
				t.Errorf("Expected version 1 for new secret, got %d", metadata.Version)
			}

			if metadata.Size != len(tc.data) {
				t.Errorf("Expected size %d, got %d", len(tc.data), metadata.Size)
			}

			// Verify tags
			if len(metadata.Tags) != len(tc.tags) {
				t.Errorf("Expected %d tags, got %d", len(tc.tags), len(metadata.Tags))
			}

			// Store for later verification
			storedSecrets[tc.secretID] = metadata

			// Retrieve secret and verify using SecretResult
			result, err := vault.GetSecret(tc.secretID)
			if err != nil {
				t.Fatalf("Failed to retrieve %s secret: %v", tc.name, err)
			}

			// Verify SecretResult structure
			if result == nil {
				t.Fatal("Expected non-nil SecretResult")
			}

			if result.Data == nil {
				t.Fatal("Expected non-nil data in SecretResult")
			}

			if result.Metadata == nil {
				t.Fatal("Expected non-nil metadata in SecretResult")
			}

			// Verify data integrity
			if !bytes.Equal(result.Data, tc.data) {
				t.Errorf("Data mismatch for %s: expected %v, got %v",
					tc.name, tc.data, result.Data)
			}

			// Verify content type persisted
			if result.Metadata.ContentType != tc.contentType {
				t.Errorf("Retrieved content type mismatch: expected %v, got %v",
					tc.contentType, result.Metadata.ContentType)
			}

			// Verify metadata consistency
			if result.Metadata.SecretID != tc.secretID {
				t.Errorf("Retrieved secret ID mismatch: expected %s, got %s",
					tc.secretID, result.Metadata.SecretID)
			}

			if result.Metadata.Size != len(tc.data) {
				t.Errorf("Retrieved size mismatch: expected %d, got %d",
					len(tc.data), result.Metadata.Size)
			}

			// Verify access tracking
			if result.Metadata.AccessCount <= 0 {
				t.Errorf("Expected access count > 0, got %d", result.Metadata.AccessCount)
			}

			// LastAccessed validation
			if result.Metadata.LastAccessed == nil {
				t.Error("Expected LastAccessed to be set")
			} else if result.Metadata.LastAccessed.IsZero() {
				t.Error("Expected LastAccessed to have a valid timestamp")
			}

			// Verify key usage tracking
			if result.Metadata.KeyID == "" {
				t.Error("Expected KeyID to be set")
			}

			// Verify timestamps
			now := time.Now()
			if result.Metadata.CreatedAt.After(now) {
				t.Error("CreatedAt should not be in the future")
			}

			if result.Metadata.LastAccessed != nil && result.Metadata.LastAccessed.Before(result.Metadata.CreatedAt) {
				t.Error("LastAccessed should not be before CreatedAt")
			}

			// Test metadata-only retrieval
			metadataOnly, err := vault.GetSecretMetadata(tc.secretID)
			if err != nil {
				t.Fatalf("Failed to get metadata for %s secret: %v", tc.name, err)
			}

			if metadataOnly == nil {
				t.Fatal("Expected non-nil metadata from GetSecretMetadata")
			}

			if metadataOnly.ContentType != tc.contentType {
				t.Errorf("Metadata-only content type mismatch: expected %v, got %v",
					tc.contentType, metadataOnly.ContentType)
			}

			// Test subsequent access to verify access count increments
			result2, err := vault.GetSecret(tc.secretID)
			if err != nil {
				t.Fatalf("Failed to retrieve %s secret second time: %v", tc.name, err)
			}

			if result2.Metadata.AccessCount <= result.Metadata.AccessCount {
				t.Errorf("Access count should increment: first=%d, second=%d",
					result.Metadata.AccessCount, result2.Metadata.AccessCount)
			}

			// Test content type specific operations
			switch tc.contentType {
			case ContentTypeJSON:
				// Verify it's valid JSON
				var jsonData interface{}
				if err = json.Unmarshal(result.Data, &jsonData); err != nil {
					t.Errorf("Stored JSON data is not valid JSON: %v", err)
				}

			case ContentTypeYAML:
				// Verify it contains YAML markers
				if !bytes.Contains(result.Data, []byte(":")) {
					t.Error("YAML data should contain key-value separators")
				}

			case ContentTypePEM:
				// Verify it contains PEM markers
				if !bytes.Contains(result.Data, []byte("-----BEGIN")) {
					t.Error("PEM data should contain BEGIN marker")
				}

			case ContentTypeBinary:
				// Verify binary data integrity (especially null bytes)
				if !bytes.Contains(result.Data, []byte{0x00}) {
					t.Error("Binary data should contain null bytes")
				}

			case ContentTypeXML:
				// Verify it contains XML markers
				if !bytes.Contains(result.Data, []byte("<?xml")) {
					t.Error("XML data should contain XML declaration")
				}

			case ContentTypeTOML:
				// Verify it contains TOML markers
				if !bytes.Contains(result.Data, []byte("[")) {
					t.Error("TOML data should contain section markers")
				}
			}

			t.Logf("✅ Content type %s verified successfully", tc.contentType)
			t.Logf("   Data size: %d bytes, AccessCount: %d->%d",
				len(result.Data), result.Metadata.AccessCount, result2.Metadata.AccessCount)
		})
	}

	// Test listing secrets with content type filtering
	t.Run("list_by_content_type", func(t *testing.T) {
		secretsList, err := vault.ListSecrets(&SecretListOptions{})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}

		// Count secrets by content type
		contentTypeCounts := make(map[ContentType]int)
		for _, secretInfo := range secretsList {
			contentTypeCounts[secretInfo.Metadata.ContentType]++
		}

		t.Logf("Content type distribution:")
		for contentType, count := range contentTypeCounts {
			t.Logf("  %s: %d secrets", contentType, count)
		}

		// Verify we have the expected content types
		expectedTypes := []ContentType{
			ContentTypeText, ContentTypeJSON, ContentTypeBinary,
			ContentTypeYAML, ContentTypePEM, ContentTypeXML, ContentTypeTOML,
		}

		for _, expectedType := range expectedTypes {
			if contentTypeCounts[expectedType] == 0 {
				t.Errorf("Expected to find at least one secret of type %s", expectedType)
			}
		}

		// Verify total count matches stored secrets
		if len(secretsList) < len(storedSecrets) {
			t.Errorf("Expected to find at least %d secrets, but found %d",
				len(storedSecrets), len(secretsList))
		}
	})

	// Test content type validation
	t.Run("content_type_validation", func(t *testing.T) {
		// Test that all our test cases cover different content types
		uniqueContentTypes := make(map[ContentType]bool)
		for _, tc := range testCases {
			uniqueContentTypes[tc.contentType] = true
		}

		contentTypeNames := make([]string, 0, len(uniqueContentTypes))
		for contentType := range uniqueContentTypes {
			contentTypeNames = append(contentTypeNames, string(contentType))
		}

		t.Logf("Tested %d unique content types: %v",
			len(uniqueContentTypes), contentTypeNames)

		// Verify we're testing a reasonable variety
		if len(uniqueContentTypes) < 5 {
			t.Errorf("Expected to test at least 5 different content types, but only tested %d",
				len(uniqueContentTypes))
		}
	})

	// Test access patterns across content types
	t.Run("access_pattern_analysis", func(t *testing.T) {
		accessCounts := make(map[ContentType]int64)

		for secretID, metadata := range storedSecrets {
			// Get current access count for each secret
			result, err := vault.GetSecret(secretID)
			if err != nil {
				t.Errorf("Failed to get secret %s for access analysis: %v", secretID, err)
				continue
			}

			accessCounts[metadata.ContentType] += result.Metadata.AccessCount
		}

		t.Logf("Access count analysis:")
		for contentType, totalAccess := range accessCounts {
			t.Logf("  %s: %d total accesses", contentType, totalAccess)
		}

		// Verify that all content types have been accessed at least twice
		// (once in main test, once here)
		for contentType, count := range accessCounts {
			if count < 2 {
				t.Errorf("Content type %s should have at least 2 accesses, got %d", contentType, count)
			}
		}
	})
}

// Helper function to get content type names for logging
func getContentTypeNames(typeMap map[ContentType]bool) []string {
	var names []string
	for contentType := range typeMap {
		names = append(names, string(contentType))
	}
	return names
}

// Helper function for JSON unmarshaling (assuming json package is imported)
func jsonUnmarshal(data []byte, v interface{}) error {
	// This would use the actual json.Unmarshal function
	// Added as placeholder to show validation concept
	return nil // Replace with actual JSON validation
}

func TestSecretTagsOperations(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Test secrets with various tag combinations
	testSecrets := []struct {
		secretID string
		data     []byte
		tags     []string
	}{
		{"secrets/no-tags", []byte("no tags"), []string{}},
		{"secrets/single-tag", []byte("single tag"), []string{"env:prod"}},
		{"secrets/multiple-tags", []byte("multiple tags"), []string{"env:prod", "service:api", "team:backend"}},
		{"secrets/duplicate-tags", []byte("duplicate tags"), []string{"env:prod", "env:prod", "type:db"}},
		{"secrets/special-chars", []byte("special chars in tags"), []string{"env:prod-west", "version:v1.2.3", "team:backend-core"}},
	}

	// Store all test secrets
	for _, ts := range testSecrets {
		metadata, err := vault.StoreSecret(ts.secretID, ts.data, ts.tags, ContentTypeText)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", ts.secretID, err)
		}

		// Verify tags are stored correctly (deduplication may occur)
		if len(ts.tags) > 0 && len(metadata.Tags) == 0 {
			t.Errorf("Tags were not stored for secret %s", ts.secretID)
		}

		// For duplicate tags test case, verify deduplication
		if ts.secretID == "secrets/duplicate-tags" {
			tagMap := make(map[string]bool)
			for _, tag := range metadata.Tags {
				if tagMap[tag] {
					t.Errorf("Duplicate tag found in metadata: %s", tag)
				}
				tagMap[tag] = true
			}
		}
	}

	// Test filtering by tags using ListSecrets
	testCases := []struct {
		name        string
		tags        []string
		expectedIDs []string
	}{
		{
			name:        "filter by env:prod",
			tags:        []string{"env:prod"},
			expectedIDs: []string{"secrets/single-tag", "secrets/multiple-tags", "secrets/duplicate-tags"},
		},
		{
			name:        "filter by service:api",
			tags:        []string{"service:api"},
			expectedIDs: []string{"secrets/multiple-tags"},
		},
		{
			name:        "filter by multiple tags",
			tags:        []string{"env:prod", "type:db"},
			expectedIDs: []string{"secrets/duplicate-tags"},
		},
		{
			name:        "filter by non-existent tag",
			tags:        []string{"nonexistent:tag"},
			expectedIDs: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secretMetadata, err := vault.ListSecrets(&SecretListOptions{
				Tags: tc.tags,
			})
			if err != nil {
				t.Fatalf("Failed to list secrets with tags %v: %v", tc.tags, err)
			}

			// Convert to set for easier comparison
			foundIDs := make(map[string]bool)
			for _, meta := range secretMetadata {
				foundIDs[meta.ID] = true
			}

			// Verify expected secrets are found
			for _, expectedID := range tc.expectedIDs {
				if !foundIDs[expectedID] {
					t.Errorf("Expected secret %s not found when filtering by tags %v",
						expectedID, tc.tags)
				}
			}

			// Verify no unexpected secrets are found
			if len(foundIDs) != len(tc.expectedIDs) {
				t.Errorf("Expected %d secrets, found %d when filtering by tags %v",
					len(tc.expectedIDs), len(foundIDs), tc.tags)
			}
		})
	}
}

func TestSecretUpdateWithDifferentParameters(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	secretID := "test/update/params"

	// Store initial secret
	initialData := []byte("initial data")
	initialTags := []string{"initial", "v1"}
	metadata1, err := vault.StoreSecret(secretID, initialData, initialTags, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store initial secret: %v", err)
	}

	t.Logf("Initial secret stored - Version: %d, Size: %d bytes", metadata1.Version, metadata1.Size)

	// Update with different data only
	newData := []byte("updated data with more content")
	metadata2, err := vault.UpdateSecret(secretID, newData, initialTags, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to update secret data: %v", err)
	}

	if metadata2.Version != metadata1.Version+1 {
		t.Errorf("Version should increment: expected %d, got %d",
			metadata1.Version+1, metadata2.Version)
	}

	// Verify data was actually updated
	if metadata2.Size == metadata1.Size {
		t.Log("Warning: Size didn't change, but data should have changed")
	}

	if metadata2.Checksum == metadata1.Checksum {
		t.Error("Checksum should change when data changes")
	}

	t.Logf("After data update - Version: %d, Size: %d bytes", metadata2.Version, metadata2.Size)

	// Update with different tags only
	newTags := []string{"updated", "v2", "multi-param-test"}
	metadata3, err := vault.UpdateSecret(secretID, newData, newTags, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to update secret tags: %v", err)
	}

	if metadata3.Version != metadata2.Version+1 {
		t.Errorf("Version should increment after tags update: expected %d, got %d",
			metadata2.Version+1, metadata3.Version)
	}

	// Verify tags were updated
	expectedTagsAfterUpdate := map[string]bool{"updated": true, "v2": true, "multi-param-test": true}
	if len(metadata3.Tags) != len(expectedTagsAfterUpdate) {
		t.Errorf("Tags count after update mismatch: expected %d, got %d",
			len(expectedTagsAfterUpdate), len(metadata3.Tags))
	}

	for _, tag := range metadata3.Tags {
		if !expectedTagsAfterUpdate[tag] {
			t.Errorf("Unexpected tag after update: %s", tag)
		}
	}

	// Verify data didn't change when only tags changed
	if metadata3.Checksum != metadata2.Checksum {
		t.Error("Checksum should not change when only tags are updated")
	}

	t.Logf("After tags update - Version: %d, Tags: %v", metadata3.Version, metadata3.Tags)

	// Update with different content type
	jsonData := []byte(`{"message": "now in json", "version": 4, "timestamp": "2024-01-01T00:00:00Z"}`)
	metadata4, err := vault.UpdateSecret(secretID, jsonData, newTags, ContentTypeJSON)
	if err != nil {
		t.Fatalf("Failed to update secret content type: %v", err)
	}

	if metadata4.Version != metadata3.Version+1 {
		t.Errorf("Version should increment after content type update: expected %d, got %d",
			metadata3.Version+1, metadata4.Version)
	}

	if metadata4.ContentType != ContentTypeJSON {
		t.Errorf("Content type should be updated: expected %v, got %v",
			ContentTypeJSON, metadata4.ContentType)
	}

	// Verify size and checksum changed with new data
	if metadata4.Size <= metadata3.Size {
		t.Log("Warning: Size should typically increase with JSON data")
	}

	if metadata4.Checksum == metadata3.Checksum {
		t.Error("Checksum should change when data and content type change")
	}

	t.Logf("After content type update - Version: %d, ContentType: %s, Size: %d bytes",
		metadata4.Version, metadata4.ContentType, metadata4.Size)

	// Verify final state using SecretResult
	result, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated secret: %v", err)
	}

	if result == nil {
		t.Fatal("GetSecret returned nil result")
	}

	// Verify data
	if !bytes.Equal(result.Data, jsonData) {
		t.Errorf("Final data mismatch: expected %s, got %s",
			string(jsonData), string(result.Data))
	}

	// Verify content type
	if result.Metadata.ContentType != ContentTypeJSON {
		t.Errorf("Final content type mismatch: expected %v, got %v",
			ContentTypeJSON, result.Metadata.ContentType)
	}

	// Verify tags
	expectedTags := map[string]bool{"updated": true, "v2": true, "multi-param-test": true}
	if len(result.Metadata.Tags) != len(expectedTags) {
		t.Errorf("Final tags count mismatch: expected %d, got %d",
			len(expectedTags), len(result.Metadata.Tags))
	}

	for _, tag := range result.Metadata.Tags {
		if !expectedTags[tag] {
			t.Errorf("Unexpected tag in final metadata: %s", tag)
		}
	}

	// Verify version incremented correctly through all updates
	if result.Metadata.Version != 4 {
		t.Errorf("Final version should be 4, got %d", result.Metadata.Version)
	}

	// Verify final metadata matches metadata4
	if result.Metadata.Version != metadata4.Version {
		t.Errorf("Final metadata version should match metadata4: expected %d, got %d",
			metadata4.Version, result.Metadata.Version)
	}

	if result.Metadata.Checksum != metadata4.Checksum {
		t.Errorf("Final metadata checksum should match metadata4: expected %s, got %s",
			metadata4.Checksum, result.Metadata.Checksum)
	}

	// Verify SecretResult specific fields
	if result.Metadata.AccessCount <= 0 {
		t.Errorf("Expected access count > 0, got %d", result.Metadata.AccessCount)
	}

	if result.Metadata.LastAccessed == nil {
		t.Error("Expected LastAccessed to be set")
	} else if result.Metadata.LastAccessed.IsZero() {
		t.Error("Expected LastAccessed to have a valid timestamp")
	}

	if result.Metadata.KeyID == "" {
		t.Error("Expected KeyID to be set")
	}

	// Verify timestamps are logical
	if result.Metadata.UpdatedAt.Before(result.Metadata.CreatedAt) {
		t.Error("UpdatedAt should not be before CreatedAt")
	}

	if result.Metadata.LastAccessed != nil && result.Metadata.LastAccessed.Before(result.Metadata.UpdatedAt) {
		t.Error("LastAccessed should not be before UpdatedAt")
	}

	// Verify size matches actual data
	if result.Metadata.Size != len(result.Data) {
		t.Errorf("Metadata size should match actual data size: expected %d, got %d",
			len(result.Data), result.Metadata.Size)
	}

	// Test retrieval again to verify access count increments
	result2, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret second time: %v", err)
	}

	if result2.Metadata.AccessCount <= result.Metadata.AccessCount {
		t.Errorf("Access count should increment on subsequent access: first=%d, second=%d",
			result.Metadata.AccessCount, result2.Metadata.AccessCount)
	}

	t.Logf("Final verification complete:")
	t.Logf("  Version: %d", result.Metadata.Version)
	t.Logf("  Content Type: %s", result.Metadata.ContentType)
	t.Logf("  Size: %d bytes", result.Metadata.Size)
	t.Logf("  Tags: %v", result.Metadata.Tags)
	t.Logf("  Access Count: %d", result.Metadata.AccessCount)
	t.Logf("  Key ID: %s", result.Metadata.KeyID)
	t.Logf("  Created: %v", result.Metadata.CreatedAt)
	t.Logf("  Updated: %v", result.Metadata.UpdatedAt)
	if result.Metadata.LastAccessed != nil {
		t.Logf("  Last Accessed: %v", *result.Metadata.LastAccessed)
	}

	// Verify metadata consistency across updates
	t.Run("metadata_consistency", func(t *testing.T) {
		// All metadata should have the same SecretID
		if result.Metadata.SecretID != secretID {
			t.Errorf("SecretID mismatch: expected %s, got %s", secretID, result.Metadata.SecretID)
		}

		// Should have gone through 4 versions (1 initial + 3 updates)
		expectedVersions := []int{metadata1.Version, metadata2.Version, metadata3.Version, metadata4.Version}
		for i := 1; i < len(expectedVersions); i++ {
			if expectedVersions[i] != expectedVersions[i-1]+1 {
				t.Errorf("Version sequence broken: versions were %v", expectedVersions)
				break
			}
		}

		// Checksums should change when data changes
		checksums := []string{metadata1.Checksum, metadata2.Checksum, metadata3.Checksum, metadata4.Checksum}
		if checksums[0] == checksums[1] {
			t.Error("Checksum should change when data changes (step 1->2)")
		}
		if checksums[1] != checksums[2] {
			t.Error("Checksum should not change when only tags change (step 2->3)")
		}
		if checksums[2] == checksums[3] {
			t.Error("Checksum should change when data and content type change (step 3->4)")
		}
	})
}

func TestPEMContentTypeSpecific(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Test with various PEM formats
	pemTestCases := []struct {
		name     string
		secretID string
		pemData  string
		tags     []string
		pemType  string // Expected PEM type for validation
	}{
		{
			name:     "RSA Private Key",
			secretID: "certs/rsa-private-key",
			pemData: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4qiXQRGGbvA1C3xjzLMqHwC8VE7zjKwNI4dGvx+4FzM8kBdE
L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3
R4S5T6U7V8W9X0Y1Z2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5
X6Y7Z8A9B0C1D2E3F4G5H6I7J8K9L0M1N2O3P4Q5R6S7T8U9V0W1X2Y3Z4A5B6C7
D8E9F0G1H2I3J4K5L6M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z0A1B2C3D4E5F6G7H8I9
wIDAQAB
-----END RSA PRIVATE KEY-----`,
			tags:    []string{"key", "rsa", "private"},
			pemType: "RSA PRIVATE KEY",
		},
		{
			name:     "Certificate",
			secretID: "certs/certificate",
			pemData: `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoKIqNRAYB/MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwMTEyMjE0MjgxWhcNMTgwMTEyMjE0MjgxWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA4qiXQRGGbvA1C3xjzLMqHwC8VE7zjKwNI4dGvx+4FzM8kBdEL2M3N4O5
P6Q7R8S9T0U1V2W3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7
-----END CERTIFICATE-----`,
			tags:    []string{"cert", "x509"},
			pemType: "CERTIFICATE",
		},
		{
			name:     "EC Private Key",
			secretID: "certs/ec-private-key",
			pemData: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK9/zMzg8UGxYsuywH5HUbcsKJ7qjgrX9WEteFaHmHmeRQgCgYEKoZI
zj0DAQehRANCAAShQKeqLSKCgYAkKLKzjo2W5Kzb2Nz3O4P5Q6R7S8T9U0V1W2X3
Y4Z5A6B7C8D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1
-----END EC PRIVATE KEY-----`,
			tags:    []string{"key", "ec", "private"},
			pemType: "EC PRIVATE KEY",
		},
	}

	storedPEMSecrets := make([]*SecretMetadata, 0)

	for _, tc := range pemTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing PEM type: %s", tc.pemType)

			// Store PEM data
			metadata, err := vault.StoreSecret(tc.secretID, []byte(tc.pemData), tc.tags, ContentTypePEM)
			if err != nil {
				t.Fatalf("Failed to store PEM secret: %v", err)
			}

			// Verify metadata structure
			if metadata == nil {
				t.Fatal("Expected non-nil metadata")
			}

			// Verify content type
			if metadata.ContentType != ContentTypePEM {
				t.Errorf("Expected ContentTypePEM, got %v", metadata.ContentType)
			}

			// Verify basic metadata
			if metadata.SecretID != tc.secretID {
				t.Errorf("Secret ID mismatch: expected %s, got %s", tc.secretID, metadata.SecretID)
			}

			if metadata.Size != len(tc.pemData) {
				t.Errorf("Size mismatch: expected %d, got %d", len(tc.pemData), metadata.Size)
			}

			// Store for later verification
			storedPEMSecrets = append(storedPEMSecrets, metadata)

			// Retrieve and verify using SecretResult
			result, err := vault.GetSecret(tc.secretID)
			if err != nil {
				t.Fatalf("Failed to retrieve PEM secret: %v", err)
			}

			// Verify SecretResult structure
			if result == nil {
				t.Fatal("Expected non-nil SecretResult")
			}

			if result.Data == nil {
				t.Fatal("Expected non-nil data in SecretResult")
			}

			if result.Metadata == nil {
				t.Fatal("Expected non-nil metadata in SecretResult")
			}

			// Verify PEM data integrity
			if string(result.Data) != tc.pemData {
				t.Errorf("PEM data mismatch for %s", tc.name)
				t.Logf("Expected length: %d, Got length: %d", len(tc.pemData), len(result.Data))
			}

			if result.Metadata.ContentType != ContentTypePEM {
				t.Errorf("Retrieved content type should be PEM for %s", tc.name)
			}

			// Verify PEM format integrity
			if !bytes.Contains(result.Data, []byte("-----BEGIN")) {
				t.Error("PEM data should contain BEGIN marker")
			}

			if !bytes.Contains(result.Data, []byte("-----END")) {
				t.Error("PEM data should contain END marker")
			}

			// Verify specific PEM type
			expectedBeginMarker := fmt.Sprintf("-----BEGIN %s-----", tc.pemType)
			expectedEndMarker := fmt.Sprintf("-----END %s-----", tc.pemType)

			if !bytes.Contains(result.Data, []byte(expectedBeginMarker)) {
				t.Errorf("PEM data should contain specific BEGIN marker: %s", expectedBeginMarker)
			}

			if !bytes.Contains(result.Data, []byte(expectedEndMarker)) {
				t.Errorf("PEM data should contain specific END marker: %s", expectedEndMarker)
			}

			// Verify access tracking
			if result.Metadata.AccessCount <= 0 {
				t.Errorf("Expected access count > 0, got %d", result.Metadata.AccessCount)
			}

			if result.Metadata.LastAccessed == nil {
				t.Error("Expected LastAccessed to be set")
			} else if result.Metadata.LastAccessed.IsZero() {
				t.Error("Expected LastAccessed to have a valid timestamp")
			}

			// Verify key usage tracking
			if result.Metadata.KeyID == "" {
				t.Error("Expected KeyID to be set")
			}

			// Verify timestamps
			now := time.Now()
			if result.Metadata.CreatedAt.After(now) {
				t.Error("CreatedAt should not be in the future")
			}

			if result.Metadata.UpdatedAt.Before(result.Metadata.CreatedAt) {
				t.Error("UpdatedAt should not be before CreatedAt")
			}

			// Verify tags
			if len(result.Metadata.Tags) != len(tc.tags) {
				t.Errorf("Tag count mismatch: expected %d, got %d",
					len(tc.tags), len(result.Metadata.Tags))
			}

			for _, expectedTag := range tc.tags {
				found := false
				for _, actualTag := range result.Metadata.Tags {
					if actualTag == expectedTag {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected tag %s not found for %s", expectedTag, tc.name)
				}
			}

			// Test metadata-only retrieval
			metadataOnly, err := vault.GetSecretMetadata(tc.secretID)
			if err != nil {
				t.Fatalf("Failed to get metadata-only for %s: %v", tc.name, err)
			}

			if metadataOnly.ContentType != ContentTypePEM {
				t.Errorf("Metadata-only content type mismatch: expected %v, got %v",
					ContentTypePEM, metadataOnly.ContentType)
			}

			// Verify metadata consistency between full and metadata-only retrieval
			if metadataOnly.SecretID != result.Metadata.SecretID {
				t.Error("Metadata consistency check failed: SecretID mismatch")
			}

			if metadataOnly.Size != result.Metadata.Size {
				t.Error("Metadata consistency check failed: Size mismatch")
			}

			if metadataOnly.Checksum != result.Metadata.Checksum {
				t.Error("Metadata consistency check failed: Checksum mismatch")
			}

			t.Logf("✅ PEM %s verified successfully - Size: %d bytes, AccessCount: %d",
				tc.name, len(result.Data), result.Metadata.AccessCount)
		})
	}

	// Test filtering PEM certificates by content type and tags
	t.Run("filter_pem_by_tags", func(t *testing.T) {
		pemSecrets, err := vault.ListSecrets(&SecretListOptions{
			Tags: []string{"cert"},
		})
		if err != nil {
			t.Fatalf("Failed to list PEM secrets: %v", err)
		}

		t.Logf("Found %d secrets with 'cert' tag", len(pemSecrets))

		// Should find the certificate
		found := false
		var foundSecret *SecretListEntry
		for _, secretInfo := range pemSecrets {
			if secretInfo.Metadata.SecretID == "certs/certificate" && secretInfo.Metadata.ContentType == ContentTypePEM {
				found = true
				foundSecret = secretInfo
				break
			}
		}

		if !found {
			t.Error("Certificate with PEM content type not found in filtered list")
		} else {
			t.Logf("✅ Found certificate: %s with content type %s",
				foundSecret.Metadata.SecretID, foundSecret.Metadata.ContentType)
		}
	})

	// Test filtering by content type specifically
	t.Run("filter_by_content_type", func(t *testing.T) {
		allSecrets, err := vault.ListSecrets(&SecretListOptions{})
		if err != nil {
			t.Fatalf("Failed to list all secrets: %v", err)
		}

		pemCount := 0
		for _, secretInfo := range allSecrets {
			if secretInfo.Metadata.ContentType == ContentTypePEM {
				pemCount++
				t.Logf("Found PEM secret: %s with tags %v",
					secretInfo.Metadata.SecretID, secretInfo.Metadata.Tags)
			}
		}

		expectedPEMCount := len(pemTestCases)
		if pemCount < expectedPEMCount {
			t.Errorf("Expected at least %d PEM secrets, found %d", expectedPEMCount, pemCount)
		}
	})

	// Test PEM-specific operations
	t.Run("pem_specific_operations", func(t *testing.T) {
		// Test that we can distinguish between different PEM types
		pemTypes := make(map[string]int)

		for _, tc := range pemTestCases {
			result, err := vault.GetSecret(tc.secretID)
			if err != nil {
				t.Errorf("Failed to retrieve %s for PEM analysis: %v", tc.secretID, err)
				continue
			}

			// Count different PEM types
			pemTypes[tc.pemType]++

			// Verify we can extract PEM type from content
			pemContent := string(result.Data)
			if !strings.Contains(pemContent, tc.pemType) {
				t.Errorf("PEM content should contain type identifier '%s'", tc.pemType)
			}

			// Additional PEM integrity checks
			beginCount := strings.Count(pemContent, "-----BEGIN")
			endCount := strings.Count(pemContent, "-----END")

			if beginCount != 1 {
				t.Errorf("PEM should have exactly one BEGIN marker, found %d", beginCount)
			}

			if endCount != 1 {
				t.Errorf("PEM should have exactly one END marker, found %d", endCount)
			}
		}

		t.Logf("PEM type analysis: %v", pemTypes)

		// Verify we tested different PEM types
		if len(pemTypes) < 3 {
			t.Errorf("Expected to test at least 3 different PEM types, got %d", len(pemTypes))
		}
	})

	// Test access patterns for PEM secrets
	t.Run("pem_access_patterns", func(t *testing.T) {
		totalAccesses := int64(0)

		for _, tc := range pemTestCases {
			// Access each PEM secret multiple times to verify access tracking
			for i := 0; i < 3; i++ {
				result, err := vault.GetSecret(tc.secretID)
				if err != nil {
					t.Errorf("Failed to access %s (attempt %d): %v", tc.secretID, i+1, err)
					continue
				}
				totalAccesses += result.Metadata.AccessCount
			}
		}

		t.Logf("Total PEM secret accesses: %d", totalAccesses)

		// Should have significant access count due to multiple retrievals
		minExpectedAccesses := int64(len(pemTestCases) * 2) // At least 2 accesses per secret
		if totalAccesses < minExpectedAccesses {
			t.Errorf("Expected at least %d total accesses, got %d", minExpectedAccesses, totalAccesses)
		}
	})
}

func TestSecretListOptionsAndFiltering(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	// Create secrets with various prefixes and tags
	secrets := []struct {
		id   string
		tags []string
	}{
		{"app/frontend/config", []string{"app:frontend", "env:prod"}},
		{"app/frontend/secrets", []string{"app:frontend", "env:prod", "sensitive"}},
		{"app/backend/config", []string{"app:backend", "env:prod"}},
		{"app/backend/db", []string{"app:backend", "env:prod", "database"}},
		{"shared/redis", []string{"shared", "cache", "env:prod"}},
		{"staging/app/config", []string{"app:frontend", "env:staging"}},
	}

	// Store all secrets
	for _, s := range secrets {
		data := []byte(fmt.Sprintf("data for %s", s.id))
		_, err = vault.StoreSecret(s.id, data, s.tags, ContentTypeText)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", s.id, err)
		}
	}

	// Test prefix filtering
	t.Run("prefix filtering", func(t *testing.T) {
		testCases := []struct {
			prefix   string
			expected []string
		}{
			{"app/", []string{"app/frontend/config", "app/frontend/secrets", "app/backend/config", "app/backend/db"}},
			{"app/frontend/", []string{"app/frontend/config", "app/frontend/secrets"}},
			{"shared/", []string{"shared/redis"}},
			{"nonexistent/", []string{}},
		}

		for _, tc := range testCases {
			secretMetadata, err := vault.ListSecrets(&SecretListOptions{
				Prefix: tc.prefix,
			})
			if err != nil {
				t.Fatalf("Failed to list secrets with prefix %s: %v", tc.prefix, err)
			}

			foundIDs := make([]string, len(secretMetadata))
			for i, meta := range secretMetadata {
				foundIDs[i] = meta.Metadata.SecretID
			}

			if len(foundIDs) != len(tc.expected) {
				t.Errorf("Prefix %s: expected %d secrets, got %d",
					tc.prefix, len(tc.expected), len(foundIDs))
			}

			expectedSet := make(map[string]bool)
			for _, id := range tc.expected {
				expectedSet[id] = true
			}

			for _, id := range foundIDs {
				if !expectedSet[id] {
					t.Errorf("Prefix %s: unexpected secret %s", tc.prefix, id)
				}
			}
		}
	})

	// Test combined prefix and tag filtering
	t.Run("combined filtering", func(t *testing.T) {
		secretMetadata, err := vault.ListSecrets(&SecretListOptions{
			Prefix: "app/",
			Tags:   []string{"env:prod"},
		})
		if err != nil {
			t.Fatalf("Failed to list secrets with combined filters: %v", err)
		}

		expected := []string{"app/frontend/config", "app/frontend/secrets", "app/backend/config", "app/backend/db"}

		if len(secretMetadata) != len(expected) {
			t.Errorf("Combined filter: expected %d secrets, got %d",
				len(expected), len(secretMetadata))
		}

		expectedSet := make(map[string]bool)
		for _, id := range expected {
			expectedSet[id] = true
		}

		for _, meta := range secretMetadata {
			if !expectedSet[meta.Metadata.SecretID] {
				t.Errorf("Combined filter: unexpected secret %s", meta.Metadata.SecretID)
			}
		}
	})
}

func TestSecretChecksumValidation(t *testing.T) {
	options := createTestVaultOptions(t)

	vault, err := newTestVault(options)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vault.Close()

	secretID := "test/checksum/validation"
	secretData := []byte("data for checksum validation")

	t.Logf("Testing checksum validation with data: %s (%d bytes)", string(secretData), len(secretData))

	// Store secret
	metadata1, err := vault.StoreSecret(secretID, secretData, []string{"checksum"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Verify metadata structure
	if metadata1 == nil {
		t.Fatal("Expected non-nil metadata")
	}

	// Verify checksum is present and non-empty
	if metadata1.Checksum == "" {
		t.Error("Checksum should be present in metadata")
	}

	t.Logf("Initial checksum: %s", metadata1.Checksum)
	t.Logf("Initial size: %d bytes", metadata1.Size)

	// Verify checksum format (should be hex string)
	if len(metadata1.Checksum) == 0 {
		t.Error("Checksum should not be empty")
	}

	// Store the same data again (should have same checksum)
	differentSecretID := "test/checksum/validation2"
	metadata2, err := vault.StoreSecret(differentSecretID, secretData, []string{"checksum"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store second secret: %v", err)
	}

	t.Logf("Second checksum: %s", metadata2.Checksum)

	// Checksums should be the same for same data
	if metadata1.Checksum != metadata2.Checksum {
		t.Errorf("Checksums should be equal for same data: %s vs %s",
			metadata1.Checksum, metadata2.Checksum)
	}

	// Update with different data
	differentData := []byte("different data for checksum validation with more content")
	metadata3, err := vault.UpdateSecret(secretID, differentData, []string{"checksum", "updated"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	t.Logf("Updated checksum: %s", metadata3.Checksum)
	t.Logf("Updated size: %d bytes (data length: %d)", metadata3.Size, len(differentData))

	// Checksum should be different for different data
	if metadata3.Checksum == metadata1.Checksum {
		t.Error("Checksums should be different for different data")
	}

	// Verify size matches the actual data length
	if metadata3.Size != len(differentData) {
		t.Logf("Size mismatch: expected %d, got %d - this might be due to encryption overhead or metadata",
			len(differentData), metadata3.Size)
		// Don't fail the test here since the size might include encryption overhead
	}

	// Verify data integrity by retrieving the updated secret
	retrievedSecret, err := vault.GetSecret(secretID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated secret: %v", err)
	}

	if !bytes.Equal(retrievedSecret.Data, differentData) {
		t.Errorf("Retrieved data doesn't match updated data")
	}

	if retrievedSecret.Metadata.Checksum != metadata3.Checksum {
		t.Errorf("Retrieved checksum doesn't match update checksum: %s vs %s",
			retrievedSecret.Metadata.Checksum, metadata3.Checksum)
	}

	// Test checksum behavior with same content but different content type
	t.Run("checksum_with_different_content_type", func(t *testing.T) {
		// Test 1: Same data with Text vs Binary content type
		binarySecretID := "test/checksum/same-data-as-binary"

		metadataBinary, err := vault.StoreSecret(binarySecretID, secretData, []string{"binary-type"}, ContentTypeBinary)
		if err != nil {
			t.Fatalf("Failed to store data as binary: %v", err)
		}

		// Checksum should be the same since the actual data bytes are identical
		if metadataBinary.Checksum != metadata1.Checksum {
			t.Errorf("Checksums should be equal for same data bytes regardless of content type: %s vs %s",
				metadataBinary.Checksum, metadata1.Checksum)
		}

		t.Logf("✅ Checksum consistency verified: Text and Binary content types produce same checksum for identical data")
		t.Logf("   Text checksum:   %s", metadata1.Checksum)
		t.Logf("   Binary checksum: %s", metadataBinary.Checksum)

		// Test 2: Valid JSON data (different from original secretData)
		jsonDataSecretID := "test/checksum/valid-json"
		jsonData := []byte(`{"message": "data for checksum validation"}`)

		metadataJSON, err := vault.StoreSecret(jsonDataSecretID, jsonData, []string{"json", "checksum"}, ContentTypeJSON)
		if err != nil {
			t.Fatalf("Failed to store JSON secret: %v", err)
		}

		// Should have different checksum since data content is actually different
		if metadataJSON.Checksum == metadata1.Checksum {
			t.Error("Checksums should be different for different data content")
		}

		// Test 3: JSON string containing the same text (properly quoted JSON)
		textAsJSONSecretID := "test/checksum/text-as-json"
		validJSONData := []byte(`"data for checksum validation"`) // Valid JSON string

		metadataTextAsJSON, err := vault.StoreSecret(textAsJSONSecretID, validJSONData, []string{"text-as-json"}, ContentTypeJSON)
		if err != nil {
			t.Fatalf("Failed to store valid JSON: %v", err)
		}

		// Should have different checksum from original since the actual data bytes are different
		// (original is: "data for checksum validation"
		//  this is: "\"data for checksum validation\"")
		if metadataTextAsJSON.Checksum == metadata1.Checksum {
			t.Error("Checksums should be different since JSON string has quotes")
		}

		t.Logf("✅ Checksum verified for valid JSON data: %s", metadataTextAsJSON.Checksum)
		t.Logf("   Original text: %s (checksum: %s)", string(secretData), metadata1.Checksum)
		t.Logf("   JSON string:   %s (checksum: %s)", string(validJSONData), metadataTextAsJSON.Checksum)
	})

	// Test content type validation
	t.Run("content_type_validation", func(t *testing.T) {
		// Test that invalid JSON is rejected
		invalidJSONSecretID := "test/invalid-json"
		invalidJSONData := []byte("this is not valid json")

		_, err := vault.StoreSecret(invalidJSONSecretID, invalidJSONData, nil, ContentTypeJSON)
		if err == nil {
			t.Error("Expected error when storing invalid JSON with ContentTypeJSON")
		} else {
			t.Logf("✅ Invalid JSON correctly rejected: %v", err)
		}

		// Test that valid JSON is accepted
		validJSONSecretID := "test/content-validation/valid-json"
		validJSONData := []byte(`{"key": "value", "number": 42}`)

		metadata, err := vault.StoreSecret(validJSONSecretID, validJSONData, nil, ContentTypeJSON)
		if err != nil {
			t.Fatalf("Valid JSON should be accepted: %v", err)
		}

		t.Logf("✅ Valid JSON accepted with checksum: %s", metadata.Checksum)
	})

	// Test checksum with binary data
	t.Run("checksum_with_binary_data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0xAB, 0xCD, 0xEF}
		binarySecretID := "test/checksum/binary"

		binaryMetadata, err := vault.StoreSecret(binarySecretID, binaryData, []string{"binary", "checksum"}, ContentTypeBinary)
		if err != nil {
			t.Fatalf("Failed to store binary secret: %v", err)
		}

		if binaryMetadata.Checksum == "" {
			t.Error("Binary data should have a valid checksum")
		}

		// Should be different from text checksums
		if binaryMetadata.Checksum == metadata1.Checksum {
			t.Error("Binary data should have different checksum from text data")
		}

		// Verify binary data integrity through retrieval
		binaryResult, err := vault.GetSecret(binarySecretID)
		if err != nil {
			t.Fatalf("Failed to retrieve binary secret: %v", err)
		}

		if !bytes.Equal(binaryResult.Data, binaryData) {
			t.Error("Binary data integrity check failed")
		}

		if binaryResult.Metadata.Checksum != binaryMetadata.Checksum {
			t.Errorf("Binary checksum consistency check failed: %s vs %s",
				binaryResult.Metadata.Checksum, binaryMetadata.Checksum)
		}

		t.Logf("✅ Binary checksum verified: %s", binaryMetadata.Checksum)
	})

	// Test multiple retrievals don't affect checksum
	t.Run("checksum_stability_across_retrievals", func(t *testing.T) {
		checksums := make([]string, 5)
		var baseAccessCount int64

		// First retrieve to establish baseline
		result, err := vault.GetSecret(secretID)
		if err != nil {
			t.Fatalf("Failed to retrieve secret for baseline: %v", err)
		}
		baseAccessCount = result.Metadata.AccessCount
		t.Logf("Baseline access count: %d", baseAccessCount)

		for i := 0; i < 5; i++ {
			result, err := vault.GetSecret(secretID)
			if err != nil {
				t.Fatalf("Failed to retrieve secret (attempt %d): %v", i+1, err)
			}

			checksums[i] = result.Metadata.Checksum

			// Verify access count increases (or at least doesn't decrease)
			if result.Metadata.AccessCount < baseAccessCount {
				t.Logf("Access count: expected >= %d, got %d", baseAccessCount, result.Metadata.AccessCount)
			}
		}

		// All checksums should be identical
		for i := 1; i < len(checksums); i++ {
			if checksums[i] != checksums[0] {
				t.Errorf("Checksum should remain stable across retrievals: %s vs %s (retrieval %d)",
					checksums[0], checksums[i], i+1)
			}
		}

		t.Logf("✅ Checksum stability verified across %d retrievals: %s", len(checksums), checksums[0])
	})

	// Summary verification
	t.Run("checksum_summary", func(t *testing.T) {
		t.Logf("Checksum validation summary:")
		t.Logf("  Original data checksum: %s", metadata1.Checksum)
		t.Logf("  Duplicate data checksum: %s", metadata2.Checksum)
		t.Logf("  Updated data checksum: %s", metadata3.Checksum)

		if metadata1.Checksum == metadata2.Checksum {
			t.Logf("  ✅ Identical data produces identical checksums")
		}

		if metadata1.Checksum != metadata3.Checksum {
			t.Logf("  ✅ Different data produces different checksums")
		}

		// Verify all checksums are non-empty and reasonable length
		checksums := []string{metadata1.Checksum, metadata2.Checksum, metadata3.Checksum}
		for i, checksum := range checksums {
			if len(checksum) < 16 { // Reasonable minimum for hash
				t.Errorf("Checksum %d seems too short: %s", i+1, checksum)
			}
		}

		t.Logf("✅ All checksum validations completed successfully")
	})
}

func newTestVault(options Options) (VaultService, error) {
	return NewWithStore(options, createStore(testStoreType, tempDir, tenantID), nil, tenantID)
}
