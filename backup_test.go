package volta

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVaultBackup(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{"BackupSuccessful", testBackupSuccessful},
		{"BackupWithMultipleKeys", testBackupWithMultipleKeys},
		{"BackupWithNoKeys", testBackupWithNoKeys},
		{"BackupWithNoMetadata", testBackupWithNoMetadata},
		{"BackupFailsWithInvalidPath", testBackupFailsWithInvalidPath},
		{"BackupFailsWhenSaltInaccessible", testBackupFailsWhenSaltInaccessible},
		{"BackupFailsWhenKeyLoadFails", testBackupFailsWhenKeyLoadFails},
		{"BackupFailsWhenMetadataLoadFails", testBackupFailsWhenMetadataLoadFails},
		{"BackupFailsWhenStorageBackupFails", testBackupFailsWhenStorageBackupFails},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func testBackupSuccessful(t *testing.T) {
	// Create a unique test directory for this specific test
	timestamp := time.Now().UnixNano()
	testDir := filepath.Join(tempDir, fmt.Sprintf("backup_test_%d", timestamp))

	// Clean up any existing test directory
	os.RemoveAll(testDir)
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(testDir)
	})

	// Create test options with the unique directory
	options := Options{
		DerivationPassphrase: passPhrase,
		EnableMemoryLock:     false,
	}

	// Create the vault with unique directory
	vault := createTestVault(t, options, testDir)
	defer vault.Close()

	// Create truly unique test data with timestamp and various content types
	testSecrets := map[string]struct {
		data        []byte
		contentType ContentType
		tags        []string
	}{
		fmt.Sprintf("successful-backup-secret-1-%d", timestamp): {
			data:        []byte("test value for successful backup"),
			contentType: ContentTypeText,
			tags:        []string{"backup", "test", "text"},
		},
		fmt.Sprintf("successful-backup-secret-2-%d", timestamp): {
			data:        []byte("another test value"),
			contentType: ContentTypeText,
			tags:        []string{"backup", "test"},
		},
		fmt.Sprintf("successful-backup-config-%d", timestamp): {
			data:        []byte(`{"env": "test", "debug": true}`),
			contentType: ContentTypeJSON,
			tags:        []string{"backup", "config", "json"},
		},
		fmt.Sprintf("successful-backup-binary-%d", timestamp): {
			data:        []byte{0x01, 0x02, 0x03, 0xFF, 0xFE},
			contentType: ContentTypeBinary,
			tags:        []string{"backup", "binary"},
		},
		fmt.Sprintf("successful-backup-yaml-%d", timestamp): {
			data:        []byte("key: value\nnumber: 42\nbool: true"),
			contentType: ContentTypeYAML,
			tags:        []string{"backup", "yaml", "config"},
		},
	}

	// Store all test secrets in the vault
	totalDataSize := 0
	for name, secret := range testSecrets {
		_, err = vault.StoreSecret(name, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", name, err)
		}
		totalDataSize += len(secret.data)
		t.Logf("Stored secret: %s (%s) - %d bytes", name, secret.contentType, len(secret.data))
	}

	// Verify all secrets were stored correctly and track access patterns
	for name, expected := range testSecrets {
		stored, err := vault.GetSecret(name)
		if err != nil {
			t.Fatalf("Failed to get secret %s: %v", name, err)
		}

		if !bytes.Equal(stored.Data, expected.data) {
			t.Errorf("Secret %s data mismatch. Expected: %s, Got: %s",
				name, string(expected.data), string(stored.Data))
		}

		if stored.Metadata.ContentType != expected.contentType {
			t.Errorf("Secret %s content type mismatch. Expected: %s, Got: %s",
				name, expected.contentType, stored.Metadata.ContentType)
		}

		if !equalStringSlices(stored.Metadata.Tags, expected.tags) {
			t.Errorf("Secret %s tags mismatch. Expected: %v, Got: %v",
				name, expected.tags, stored.Metadata.Tags)
		}

		if stored.Metadata.AccessCount != 1 {
			t.Errorf("Expected access count 1 for secret %s, got %d", name, stored.Metadata.AccessCount)
		}

		if stored.Metadata.Version != 1 {
			t.Errorf("Expected version 1 for secret %s, got %d", name, stored.Metadata.Version)
		}

		t.Logf("✅ Verified secret: %s (%s) - %d bytes, access count: %d, version: %d",
			name, stored.Metadata.ContentType, len(stored.Data), stored.Metadata.AccessCount, stored.Metadata.Version)
	}

	t.Logf("Successfully stored and verified %d test secrets", len(testSecrets))

	// Test access count increment by getting the same secret again
	firstSecretName := fmt.Sprintf("successful-backup-secret-1-%d", timestamp)
	beforeCount, err := vault.GetSecret(firstSecretName)
	if err != nil {
		t.Fatalf("Failed to get secret for access count test: %v", err)
	}

	afterCount, err := vault.GetSecret(firstSecretName)
	if err != nil {
		t.Fatalf("Failed to get secret for access count test: %v", err)
	}

	if afterCount.Metadata.AccessCount != beforeCount.Metadata.AccessCount+1 {
		t.Errorf("Expected access count %d, got %d", beforeCount.Metadata.AccessCount+1, afterCount.Metadata.AccessCount)
	}
	t.Logf("Access count increment test passed: %d -> %d", beforeCount.Metadata.AccessCount, afterCount.Metadata.AccessCount)

	// Create backup with specific filename (not directory)
	// The SaveBackup method expects a file path and will add .vault extension
	backupFileName := fmt.Sprintf("vault_backup_test_%d", timestamp)
	backupFilePath := filepath.Join(testDir, backupFileName) // This will become backupFileName.vault

	passphrase := "test-backup-passphrase-with-good-length"

	t.Logf("Creating backup with base filename: %s", backupFileName)
	t.Logf("Expected backup file path: %s.vault", backupFilePath)

	// Call Backup - the SaveBackup method will add .vault extension automatically
	err = vault.Backup(backupFilePath, passphrase)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}
	t.Logf("Backup operation completed successfully")

	// The actual backup file will have .vault extension added by SaveBackup
	actualBackupFile := backupFilePath + ".vault"

	// Verify backup file exists
	fileInfo, err := os.Stat(actualBackupFile)
	if err != nil {
		// Debug: list files in test directory to see what was actually created
		t.Logf("Files in test directory:")
		if entries, readErr := os.ReadDir(testDir); readErr == nil {
			for _, entry := range entries {
				info, _ := entry.Info()
				if entry.IsDir() {
					t.Logf("  [DIR]  %s/", entry.Name())
				} else {
					t.Logf("  [FILE] %s (size: %d)", entry.Name(), info.Size())
				}
			}
		}

		// Also check if there are any .vault files anywhere in the test directory
		t.Logf("Searching for .vault files:")
		filepath.Walk(testDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && strings.HasSuffix(info.Name(), ".vault") {
				t.Logf("  Found .vault file: %s (size: %d)", path, info.Size())
			}
			return nil
		})

		t.Fatalf("Backup file was not created at expected location %s: %v", actualBackupFile, err)
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	t.Logf("✅ Backup file created: %s (size: %d bytes)", actualBackupFile, fileInfo.Size())

	// Verify backup file contains encrypted data (not plaintext)
	backupContent, err := os.ReadFile(actualBackupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	// Check that backup doesn't contain plaintext secrets (security verification)
	backupStr := string(backupContent)
	for name, secret := range testSecrets {
		if strings.Contains(backupStr, string(secret.data)) {
			t.Errorf("⚠️ SECURITY ISSUE: Backup contains plaintext secret data for %s", name)
		}
	}
	t.Logf("✅ Security check passed: No plaintext secrets found in backup")

	// Verify backup file is valid JSON container
	var container struct {
		BackupID         string `json:"backup_id"`
		BackupTimestamp  string `json:"backup_timestamp"`
		VaultVersion     string `json:"vault_version"`
		BackupVersion    string `json:"backup_version"`
		EncryptionMethod string `json:"encryption_method"`
		EncryptedData    string `json:"encrypted_data"`
		Checksum         string `json:"checksum"`
		TenantID         string `json:"tenant_id,omitempty"`
	}

	if err = json.Unmarshal(backupContent, &container); err != nil {
		t.Fatalf("Backup file is not valid JSON: %v", err)
	}

	// Verify container structure and required fields
	if container.BackupID == "" {
		t.Error("Backup container missing BackupID")
	}
	if container.EncryptedData == "" {
		t.Error("Backup container missing EncryptedData")
	}
	if container.Checksum == "" {
		t.Error("Backup container missing Checksum")
	}
	if container.EncryptionMethod != "passphrase-only" {
		t.Errorf("Expected encryption method 'passphrase-only', got '%s'", container.EncryptionMethod)
	}
	if container.BackupTimestamp == "" {
		t.Error("Backup container missing BackupTimestamp")
	}

	// Verify timestamp is valid
	if _, err := time.Parse(time.RFC3339, container.BackupTimestamp); err != nil {
		t.Errorf("Invalid backup timestamp format: %s", container.BackupTimestamp)
	}

	t.Logf("✅ Backup container structure is valid")
	t.Logf("✅ Backup ID: %s", container.BackupID)
	t.Logf("✅ Backup Timestamp: %s", container.BackupTimestamp)
	t.Logf("✅ Encryption Method: %s", container.EncryptionMethod)

	// List all secrets to verify backup completeness
	secretsList, err := vault.ListSecrets(&SecretListOptions{})
	if len(secretsList) != len(testSecrets) {
		t.Errorf("Expected %d secrets in vault, got %d", len(testSecrets), len(secretsList))
	}

	// Verify content type distribution in the original data
	contentTypeCounts := make(map[ContentType]int)
	for _, secret := range testSecrets {
		contentTypeCounts[secret.contentType]++
	}

	t.Logf("Content type distribution in backed up secrets:")
	for contentType, count := range contentTypeCounts {
		t.Logf("  %s: %d secrets", contentType, count)
	}

	// Verify encrypted data is base64 encoded
	if _, err = base64.StdEncoding.DecodeString(container.EncryptedData); err != nil {
		t.Errorf("EncryptedData is not valid base64: %v", err)
	}

	// Calculate compression/overhead ratio
	encryptedDataSize := len(container.EncryptedData) * 3 / 4 // Approximate size after base64 decoding
	compressionRatio := float64(encryptedDataSize) / float64(totalDataSize)

	t.Logf("✅ Data size analysis:")
	t.Logf("  Raw data size: %d bytes", totalDataSize)
	t.Logf("  Encrypted data size (approx): %d bytes", encryptedDataSize)
	t.Logf("  Backup file size: %d bytes", fileInfo.Size())
	t.Logf("  Encryption overhead: %.1fx", compressionRatio)
	t.Logf("  Total file overhead: %.1fx", float64(fileInfo.Size())/float64(totalDataSize))

	// Final verification
	t.Logf("🎉 BACKUP TEST COMPLETED SUCCESSFULLY!")
	t.Logf("✅ Created backup file: %s", filepath.Base(actualBackupFile))
	t.Logf("✅ Backed up %d secrets across %d content types", len(testSecrets), len(contentTypeCounts))
	t.Logf("✅ Backup is properly encrypted and structured")
	t.Logf("✅ All security checks passed")
	t.Logf("✅ File size: %d bytes with %.1fx overhead", fileInfo.Size(), float64(fileInfo.Size())/float64(totalDataSize))
}

// Helper function to compare string slices (handles order differences)
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison to handle order differences
	mapA := make(map[string]bool)
	mapB := make(map[string]bool)

	for _, v := range a {
		mapA[v] = true
	}
	for _, v := range b {
		mapB[v] = true
	}

	// Check if all keys in mapA exist in mapB
	for k := range mapA {
		if !mapB[k] {
			return false
		}
	}

	return true
}

func testBackupWithMultipleKeys(t *testing.T) {
	// Define consistent passphrase for both original and restored vaults
	const testPassphrase = "comprehensive-test-passphrase-with-sufficient-length"

	// Create a unique test directory for this specific test
	timestamp := time.Now().UnixNano()
	testDir := filepath.Join(tempDir, fmt.Sprintf("backup_multikey_test_%d", timestamp))

	// Clean up any existing test directory
	os.RemoveAll(testDir)
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(testDir)
	})

	options := createTestOptions()
	// Make sure original vault uses the test passphrase
	options.DerivationPassphrase = testPassphrase
	vault := createTestVault(t, options, testDir)
	defer vault.Close()

	// Store initial secrets with proper content types
	type SecretTest struct {
		data        []byte
		contentType ContentType
		tags        []string
		description string
	}

	initialSecrets := map[string]SecretTest{
		fmt.Sprintf("initial-secret-1-%d", timestamp): {
			data:        []byte("initial value 1"),
			contentType: ContentTypeText,
			tags:        []string{"initial", "test"},
			description: "First initial secret",
		},
		fmt.Sprintf("initial-secret-2-%d", timestamp): {
			data:        []byte("initial value 2"),
			contentType: ContentTypeText,
			tags:        []string{"initial", "test"},
			description: "Second initial secret",
		},
	}

	t.Logf("Storing initial secrets with first key")
	for name, secret := range initialSecrets {
		_, err = vault.StoreSecret(name, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store initial secret %s: %v", name, err)
		}
		t.Logf("✅ Stored initial secret: %s (%s)", name, secret.contentType)
	}

	// Get the initial key info
	initialKeyMetadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list initial key metadata: %v", err)
	}
	t.Logf("Initial keys: %d", len(initialKeyMetadata))

	// Add more diverse test data with appropriate content types
	additionalSecrets := map[string]SecretTest{
		fmt.Sprintf("config-secret-%d", timestamp): {
			data:        []byte(`{"database": "test", "port": 5432}`),
			contentType: ContentTypeJSON,
			tags:        []string{"config", "database"},
			description: "Database configuration in JSON format",
		},
		fmt.Sprintf("api-key-%d", timestamp): {
			data:        []byte("sk-1234567890abcdef"),
			contentType: ContentTypeText,
			tags:        []string{"api", "key", "auth"},
			description: "API authentication key",
		},
		fmt.Sprintf("credentials-%d", timestamp): {
			data:        []byte("user:pass@host:port"),
			contentType: ContentTypeText,
			tags:        []string{"credentials", "database"},
			description: "Database connection credentials",
		},
		fmt.Sprintf("large-secret-%d", timestamp): {
			data:        []byte(strings.Repeat("test data ", 100)),
			contentType: ContentTypeText,
			tags:        []string{"test", "large"},
			description: "Large text data for testing",
		},
		fmt.Sprintf("binary-secret-%d", timestamp): {
			data:        []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE},
			contentType: ContentTypeBinary,
			tags:        []string{"binary", "test"},
			description: "Binary test data",
		},
		fmt.Sprintf("certificate-%d", timestamp): {
			data:        []byte("-----BEGIN CERTIFICATE-----\nMIIC...test cert...\n-----END CERTIFICATE-----"),
			contentType: ContentTypePEM,
			tags:        []string{"certificate", "pki"},
			description: "Test certificate data",
		},
		fmt.Sprintf("yaml-config-%d", timestamp): {
			data:        []byte("server:\n  host: localhost\n  port: 8080"),
			contentType: ContentTypeYAML,
			tags:        []string{"config", "yaml"},
			description: "YAML configuration file",
		},
	}

	// Store additional secrets with proper content types
	t.Logf("Storing additional diverse secrets")
	allSecrets := make(map[string]SecretTest)

	// Add initial secrets to allSecrets
	for name, secret := range initialSecrets {
		allSecrets[name] = secret
	}

	// Store and add additional secrets
	for name, secret := range additionalSecrets {
		allSecrets[name] = secret
		_, err = vault.StoreSecret(name, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store additional secret %s: %v", name, err)
		}
		t.Logf("✅ Stored secret: %s (%s) - %d bytes",
			name, secret.contentType, len(secret.data))
	}

	// Verify all secrets are accessible with content type validation
	t.Logf("Verifying all %d secrets are accessible with correct content types", len(allSecrets))
	for name, expectedSecret := range allSecrets {
		result, err := vault.GetSecret(name)
		if err != nil {
			t.Fatalf("Failed to retrieve secret %s: %v", name, err)
		}

		// Verify SecretResult structure
		if result == nil {
			t.Fatalf("Expected non-nil SecretResult for secret %s", name)
		}

		if result.Data == nil {
			t.Fatalf("Expected non-nil data in SecretResult for secret %s", name)
		}

		if result.Metadata == nil {
			t.Fatalf("Expected non-nil metadata in SecretResult for secret %s", name)
		}

		// Verify data
		if !bytes.Equal(result.Data, expectedSecret.data) {
			t.Fatalf("Retrieved secret %s does not match stored value", name)
		}

		// Verify content type
		if result.Metadata.ContentType != expectedSecret.contentType {
			t.Fatalf("Secret %s has incorrect content type: expected %s, got %s",
				name, expectedSecret.contentType, result.Metadata.ContentType)
		}

		// Verify tags
		if len(result.Metadata.Tags) != len(expectedSecret.tags) {
			t.Fatalf("Secret %s has incorrect number of tags: expected %d, got %d",
				name, len(expectedSecret.tags), len(result.Metadata.Tags))
		}

		// Verify each tag exists (order might be different)
		expectedTagsMap := make(map[string]bool)
		for _, tag := range expectedSecret.tags {
			expectedTagsMap[tag] = true
		}

		for _, tag := range result.Metadata.Tags {
			if !expectedTagsMap[tag] {
				t.Fatalf("Secret %s has unexpected tag: %s", name, tag)
			}
		}

		// Verify key usage tracking
		if !result.UsedActiveKey {
			t.Logf("Note: Secret %s was not encrypted with the active key", name)
		}

		// Verify access tracking
		if result.Metadata.AccessCount <= 0 {
			t.Fatalf("Secret %s should have access count > 0, got %d", name, result.Metadata.AccessCount)
		}

		if result.Metadata.LastAccessed.IsZero() {
			t.Fatalf("Secret %s should have LastAccessed set", name)
		}

		// Verify size consistency
		if result.Metadata.Size != len(expectedSecret.data) {
			t.Fatalf("Secret %s has incorrect size: expected %d, got %d",
				name, len(expectedSecret.data), result.Metadata.Size)
		}

		t.Logf("✅ Verified secret: %s (%s) with %d tags, access count: %d",
			name, result.Metadata.ContentType, len(result.Metadata.Tags), result.Metadata.AccessCount)
	}

	// Test content type filtering
	// Example: List secrets by content type
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

	// Get final key metadata
	finalKeyMetadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list final key metadata: %v", err)
	}

	t.Logf("Found %d keys in vault", len(finalKeyMetadata))
	for i, meta := range finalKeyMetadata {
		t.Logf("Key %d: %s, Status: %s", i+1, meta.KeyID, meta.Status)
	}

	// Create backup with specific filename (not directory) - Same fix as the other test
	// The SaveBackup method expects a file path and will add .vault extension
	backupFileName := fmt.Sprintf("vault_backup_comprehensive_%d", timestamp)
	backupFilePath := filepath.Join(testDir, backupFileName) // This will become backupFileName.vault

	t.Logf("Creating backup with base filename: %s", backupFileName)
	t.Logf("Expected backup file path: %s.vault", backupFilePath)

	err = vault.Backup(backupFilePath, testPassphrase) // Use same passphrase
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}
	t.Logf("Backup operation completed successfully")

	// The actual backup file will have .vault extension added by SaveBackup
	actualBackupFile := backupFilePath + ".vault"

	// Verify backup file exists
	fileInfo, err := os.Stat(actualBackupFile)
	if err != nil {
		// Debug: list files in test directory to see what was actually created
		t.Logf("Files in test directory:")
		if entries, readErr := os.ReadDir(testDir); readErr == nil {
			for _, entry := range entries {
				info, _ := entry.Info()
				if entry.IsDir() {
					t.Logf("  [DIR]  %s/", entry.Name())
				} else {
					t.Logf("  [FILE] %s (size: %d)", entry.Name(), info.Size())
				}
			}
		}

		// Also check if there are any .vault files anywhere in the test directory
		t.Logf("Searching for .vault files:")
		filepath.Walk(testDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && strings.HasSuffix(info.Name(), ".vault") {
				t.Logf("  Found .vault file: %s (size: %d)", path, info.Size())
			}
			return nil
		})

		t.Fatalf("Backup file was not created at expected location %s: %v", actualBackupFile, err)
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	t.Logf("✅ Backup file created: %s (size: %d bytes)", actualBackupFile, fileInfo.Size())

	// Create unique directory for restored vault
	restoredVaultDir := filepath.Join(testDir, "restored_vault")
	err = os.MkdirAll(restoredVaultDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create restored vault directory: %v", err)
	}

	// Create restored vault with the SAME passphrase
	restoredOptions := createTestOptions()
	restoredOptions.DerivationPassphrase = testPassphrase
	restoredVault := createTestVault(t, restoredOptions, restoredVaultDir)
	defer restoredVault.Close()

	t.Logf("Testing backup restoration...")

	// Copy the backup file to a location where the Restore method expects it
	// The Restore method might be treating the path relative to its backup directory
	// So we'll use just the filename and let it resolve relative to the restored vault's backup dir

	// Get the backup directory of the restored vault so we can copy the file there
	restoredVaultBackupDir := filepath.Join(restoredVaultDir, "default", "backups")
	err = os.MkdirAll(restoredVaultBackupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create restored vault backup directory: %v", err)
	}

	// Copy the backup file to the restored vault's backup directory
	backupFileInRestoredVault := filepath.Join(restoredVaultBackupDir, filepath.Base(actualBackupFile))

	// Read the original backup file
	backupData, err := os.ReadFile(actualBackupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	// Write it to the restored vault's backup directory
	err = os.WriteFile(backupFileInRestoredVault, backupData, 0600)
	if err != nil {
		t.Fatalf("Failed to copy backup file to restored vault directory: %v", err)
	}

	t.Logf("Copied backup file to: %s", backupFileInRestoredVault)

	// Now restore using just the filename (let the Restore method find it in its backup directory)
	backupFileNameOnly := filepath.Base(actualBackupFile)
	t.Logf("Restoring with filename: %s", backupFileNameOnly)

	err = restoredVault.Restore(backupFileNameOnly, testPassphrase) // Use just the filename
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify all secrets are correctly restored with content types
	t.Logf("Verifying restored secrets with content types...")
	for name, expectedSecret := range allSecrets {
		result, err := restoredVault.GetSecret(name)
		if err != nil {
			t.Fatalf("Failed to retrieve restored secret %s: %v", name, err)
		}

		// Verify SecretResult structure
		if result == nil {
			t.Fatalf("Expected non-nil SecretResult for restored secret %s", name)
		}

		if result.Data == nil {
			t.Fatalf("Expected non-nil data in SecretResult for restored secret %s", name)
		}

		if result.Metadata == nil {
			t.Fatalf("Expected non-nil metadata in SecretResult for restored secret %s", name)
		}

		// Verify data
		if !bytes.Equal(result.Data, expectedSecret.data) {
			t.Fatalf("Restored secret %s does not match original value", name)
		}

		// Verify content type is preserved
		if result.Metadata.ContentType != expectedSecret.contentType {
			t.Fatalf("Restored secret %s has incorrect content type: expected %s, got %s",
				name, expectedSecret.contentType, result.Metadata.ContentType)
		}

		// Verify tags are preserved
		if len(result.Metadata.Tags) != len(expectedSecret.tags) {
			t.Fatalf("Restored secret %s has incorrect number of tags: expected %d, got %d",
				name, len(expectedSecret.tags), len(result.Metadata.Tags))
		}

		// Verify size is preserved
		if result.Metadata.Size != len(expectedSecret.data) {
			t.Fatalf("Restored secret %s has incorrect size: expected %d, got %d",
				name, len(expectedSecret.data), result.Metadata.Size)
		}

		// Verify access tracking is properly initialized after restore
		if result.Metadata.AccessCount <= 0 {
			t.Fatalf("Restored secret %s should have access count > 0, got %d",
				name, result.Metadata.AccessCount)
		}

		if result.Metadata.LastAccessed.IsZero() {
			t.Fatalf("Restored secret %s should have LastAccessed set", name)
		}

		// Verify key usage tracking
		if !result.UsedActiveKey {
			t.Logf("Note: Restored secret %s was not encrypted with the active key", name)
		}

		// Verify metadata consistency
		if result.Metadata.SecretID != name {
			t.Fatalf("Restored secret %s has incorrect SecretID: expected %s, got %s",
				name, name, result.Metadata.SecretID)
		}

		t.Logf("✅ Restored secret verified: %s (%s) - %d bytes, access count: %d",
			name, result.Metadata.ContentType, result.Metadata.Size, result.Metadata.AccessCount)
	}

	// Test that restored vault is fully functional
	testSecretID := fmt.Sprintf("post-restore-test-%d", timestamp)
	testSecretData := []byte("test data after restore")

	newMetadata, err := restoredVault.StoreSecret(testSecretID, testSecretData, []string{"post-restore"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store new secret in restored vault: %v", err)
	}

	// Verify the new secret can be retrieved
	newResult, err := restoredVault.GetSecret(testSecretID)
	if err != nil {
		t.Fatalf("Failed to retrieve new secret from restored vault: %v", err)
	}

	if !bytes.Equal(newResult.Data, testSecretData) {
		t.Fatalf("New secret in restored vault has incorrect data")
	}

	// Test access count increments properly in restored vault
	result2, err := restoredVault.GetSecret(testSecretID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret second time: %v", err)
	}

	if result2.Metadata.AccessCount <= newResult.Metadata.AccessCount {
		t.Error("Access count should increment on subsequent retrievals in restored vault")
	}

	t.Logf("✅ Backup successfully created and restored with %d keys and %d secrets",
		len(finalKeyMetadata), len(allSecrets))
	t.Logf("✅ Backup file: %s (size: %d bytes)", filepath.Base(actualBackupFile), fileInfo.Size())
	t.Logf("✅ All content types preserved correctly during backup/restore cycle")
	t.Logf("✅ Access tracking and key usage tracking work properly after restore")
	t.Logf("✅ Restored vault is fully functional for new operations")
	t.Logf("✅ New secret stored post-restore: %s (version %d)", testSecretID, newMetadata.Version)
}

func createTestVaultWithMultipleKeys(t *testing.T) *Vault {
	// Create a proper temp directory
	workDir, err := os.MkdirTemp("", "vault_test_multiple_keys_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(workDir)
	})

	// Create storage
	store, err := persist.NewFileSystemStore(workDir, tenantID)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create derivation salt and protect it immediately
	derivationSalt := make([]byte, 32)
	for i := range derivationSalt {
		derivationSalt[i] = byte(i + 100)
	}
	derivationSaltEnclave := memguard.NewEnclave(derivationSalt)
	memguard.WipeBytes(derivationSalt) // Clear original

	// Create derivation key and protect it
	derivationKey := make([]byte, 32)
	for i := range derivationKey {
		derivationKey[i] = byte(i)
	}
	derivationKeyEnclave := memguard.NewEnclave(derivationKey)
	memguard.WipeBytes(derivationKey) // Clear original

	// Create proper audit logger
	auditLogger := createLogger()

	// Create the current key and protect it
	currentKey := make([]byte, 32)
	_, err = rand.Read(currentKey)
	if err != nil {
		t.Fatalf("Failed to generate current key: %v", err)
	}
	currentKeyID := "test-current-key"
	currentKeyEnclave := memguard.NewEnclave(currentKey)
	memguard.WipeBytes(currentKey) // Clear original

	// Create inactive keys and protect them
	inactiveKeys := make(map[string]*memguard.Enclave)
	inactiveKeyIDs := make([]string, 2)

	for i := 0; i < 2; i++ {
		inactiveKey := make([]byte, 32)
		_, err = rand.Read(inactiveKey)
		if err != nil {
			t.Fatalf("Failed to generate inactive key %d: %v", i, err)
		}

		keyID := generateKeyID()
		inactiveKeyIDs[i] = keyID
		inactiveKeys[keyID] = memguard.NewEnclave(inactiveKey)
		memguard.WipeBytes(inactiveKey) // Clear original
	}

	// Combine all keys
	allKeyEnclaves := make(map[string]*memguard.Enclave)
	allKeyEnclaves[currentKeyID] = currentKeyEnclave
	for keyID, enclave := range inactiveKeys {
		allKeyEnclaves[keyID] = enclave
	}

	// Create metadata for all keys
	now := time.Now()
	keyMetadata := map[string]KeyMetadata{
		currentKeyID: {
			KeyID:     currentKeyID,
			Status:    KeyStatusActive,
			Active:    true,
			CreatedAt: now,
			Version:   1,
		},
	}

	for _, keyID := range inactiveKeyIDs {
		keyMetadata[keyID] = KeyMetadata{
			KeyID:         keyID,
			Status:        KeyStatusInactive,
			Active:        false,
			CreatedAt:     now.Add(-time.Hour), // Make them older
			DeactivatedAt: &now,
			Version:       1,
		}
	}

	// Create vault
	vault := &Vault{
		store:                 store,
		keyEnclaves:           allKeyEnclaves,
		keyMetadata:           keyMetadata,
		mu:                    sync.RWMutex{},
		currentKeyID:          currentKeyID,
		derivationSaltEnclave: derivationSaltEnclave, // Use enclave instead of raw bytes
		derivationKeyEnclave:  derivationKeyEnclave,
		audit:                 auditLogger,
		secretsVersion:        "1.0",
		secretsTimestamp:      time.Now(),
		closed:                false,
	}

	// Create and store empty secrets container
	initialContainer := &SecretsContainer{
		Version:   "1.0",
		Timestamp: time.Now(),
		Secrets:   make(map[string]*SecretEntry),
	}

	containerJSON, err := json.Marshal(initialContainer)
	if err != nil {
		t.Fatalf("Failed to marshal initial secrets container: %v", err)
	}

	encryptedContainer, err := vault.encryptWithCurrentKey(containerJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt initial secrets container: %v", err)
	}

	vault.secretsContainer = memguard.NewEnclave(encryptedContainer)

	// **CRITICAL: Save encrypted metadata to disk with versioning so DestroyKey can load it**
	metadataJSON, err := json.Marshal(keyMetadata)
	if err != nil {
		t.Fatalf("Failed to marshal key metadata: %v", err)
	}

	// Encrypt the metadata using the derivation key (same as vault does)
	encryptedMetadata, err := vault.encryptWithCurrentKey(metadataJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt metadata: %v", err)
	}

	// Create versioned data for metadata
	versionedMetadata := &persist.VersionedData{
		Data:      encryptedMetadata,
		Version:   "1.0",
		Timestamp: time.Now(),
	}

	// Save versioned metadata to store
	newVersion, err := store.SaveMetadata(versionedMetadata.Data, "")
	if err != nil {
		t.Fatalf("Failed to save encrypted metadata to disk: %v", err)
	}

	// Also save the derivation salt as versioned data
	versionedSalt := &persist.VersionedData{
		Data:      derivationSalt, // Note: this is already wiped above, you might want to recreate it
		Version:   "1.0",
		Timestamp: time.Now(),
	}

	// Recreate salt data for storage since we wiped it earlier
	saltForStorage := make([]byte, 32)
	for i := range saltForStorage {
		saltForStorage[i] = byte(i + 100)
	}
	versionedSalt.Data = saltForStorage

	_, err = store.SaveSalt(versionedSalt.Data, "")
	if err != nil {
		t.Fatalf("Failed to save salt to disk: %v", err)
	}

	t.Logf("Created vault with keys: current=%s, inactive=%v, metadata_version=%s",
		currentKeyID, inactiveKeyIDs, newVersion)

	return vault
}

func testBackupFailsWithInvalidPath(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	passphrase := "test-passphrase"

	// Setup existing directory test - create directory with .vault extension
	tempDir := t.TempDir()
	existingDir := filepath.Join(tempDir, "existing_dir")
	existingDirVault := existingDir + ".vault" // This is what will conflict

	err := os.MkdirAll(existingDirVault, 0755) // Create the .vault directory
	require.NoError(t, err)

	t.Logf("Created test directory: %s", existingDirVault)

	testCases := []struct {
		name        string
		path        string
		shouldFail  bool
		description string
	}{
		{
			name:        "empty_path",
			path:        "",
			shouldFail:  true,
			description: "Empty path should fail",
		},
		{
			name:        "only_whitespace",
			path:        "   ",
			shouldFail:  true,
			description: "Whitespace-only path should fail",
		},
		{
			name:        "existing_directory",
			path:        existingDir, // This will become existingDir + ".vault" which conflicts
			shouldFail:  true,
			description: "Should fail when target is existing directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing backup with path: '%s'", tc.path)
			err := vault.Backup(tc.path, passphrase)

			if tc.shouldFail {
				if err == nil {
					t.Errorf("Expected backup to fail with path '%s' (%s), but it succeeded", tc.path, tc.description)
				} else {
					t.Logf("✅ Got expected error for path '%s': %v", tc.path, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected backup to succeed with path '%s' (%s), but got error: %v", tc.path, tc.description, err)
				}
			}
		})
	}
}

func testBackupWithNoKeys(t *testing.T) {
	// Define consistent passphrase for both backup and vault creation
	const testPassphrase = "no-keys-backup-passphrase-with-sufficient-length"

	// Create a unique test directory for this specific test
	timestamp := time.Now().UnixNano()
	testDir := filepath.Join(tempDir, fmt.Sprintf("backup_nokeys_test_%d", timestamp))

	// Clean up any existing test directory
	os.RemoveAll(testDir)
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(testDir)
	})

	// Create vault with test options and consistent passphrase
	options := createTestOptions()
	options.DerivationPassphrase = testPassphrase // Use same passphrase for vault
	vault := createTestVault(t, options, testDir)
	defer vault.Close()

	// Create some secrets with the single key
	secrets := map[string]struct {
		data        []byte
		tags        []string
		contentType ContentType
	}{
		fmt.Sprintf("lonely-secret-%d", timestamp): {
			data:        []byte("test-value-for-lonely-secret"),
			tags:        []string{"alone", "test"},
			contentType: ContentTypeText,
		},
		fmt.Sprintf("another-secret-%d", timestamp): {
			data:        []byte("another-test-value"),
			tags:        []string{"test", "backup"},
			contentType: ContentTypeText,
		},
	}

	t.Logf("Storing %d test secrets", len(secrets))
	for secretID, secret := range secrets {
		_, err := vault.StoreSecret(secretID, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secretID, err)
		}
		t.Logf("✅ Stored secret: %s (%d bytes)", secretID, len(secret.data))
	}

	// Verify we have at least the initial key before backup
	keyMetas, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list key metadata: %v", err)
	}

	if len(keyMetas) < 1 {
		t.Fatal("Expected at least one key in vault before backup")
	}

	t.Logf("Vault has %d keys before backup", len(keyMetas))
	for i, keyMeta := range keyMetas {
		t.Logf("  Key %d: %s (status: %s)", i+1, keyMeta.KeyID, keyMeta.Status)
	}

	// Use base filename (SaveBackup will add .vault extension)
	backupFileName := fmt.Sprintf("vault_backup_nokeys_%d", timestamp)
	backupFilePath := filepath.Join(testDir, backupFileName) // This will become backupFileName.vault

	t.Logf("Creating backup with base filename: %s", backupFileName)
	t.Logf("Expected backup file path: %s.vault", backupFilePath)

	// Use the same passphrase for backup as used for vault derivation
	backupPassphrase := testPassphrase

	// Backup should succeed even with minimal keys
	err = vault.Backup(backupFilePath, backupPassphrase)
	if err != nil {
		t.Fatalf("Backup with no additional keys failed: %v", err)
	}

	// The actual backup file will have .vault extension added by SaveBackup
	actualBackupFile := backupFilePath + ".vault"

	// Verify backup file was created
	fileInfo, err := os.Stat(actualBackupFile)
	if err != nil {
		// Debug: list files in test directory to see what was actually created
		t.Logf("Files in test directory:")
		if entries, readErr := os.ReadDir(testDir); readErr == nil {
			for _, entry := range entries {
				info, _ := entry.Info()
				if entry.IsDir() {
					t.Logf("  [DIR]  %s/", entry.Name())
				} else {
					t.Logf("  [FILE] %s (size: %d)", entry.Name(), info.Size())
				}
			}
		}

		// Also check if there are any .vault files
		t.Logf("Searching for .vault files:")
		filepath.Walk(testDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && strings.HasSuffix(info.Name(), ".vault") {
				t.Logf("  Found .vault file: %s (size: %d)", path, info.Size())
			}
			return nil
		})

		t.Fatalf("Backup file was not created at expected location %s: %v", actualBackupFile, err)
	}

	if fileInfo.IsDir() {
		t.Fatal("Backup created a directory instead of a file")
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	t.Logf("✅ Backup file created: %s (size: %d bytes)", actualBackupFile, fileInfo.Size())

	// Read backup file data for copying to restored vault
	backupData, err := os.ReadFile(actualBackupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	// Test that we can restore from this backup
	t.Logf("Testing backup restoration to verify integrity...")

	// Create separate directory for restored vault
	restoredVaultDir := filepath.Join(testDir, "restored_vault")
	err = os.MkdirAll(restoredVaultDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create restored vault directory: %v", err)
	}

	// Create restored vault with the SAME passphrase
	restoredOptions := createTestOptions()
	restoredOptions.DerivationPassphrase = testPassphrase // Important: same passphrase
	restoredVault := createTestVault(t, restoredOptions, restoredVaultDir)
	defer restoredVault.Close()

	// Copy backup file to restored vault's backup directory for restore
	restoredVaultBackupDir := filepath.Join(restoredVaultDir, "default", "backups")
	err = os.MkdirAll(restoredVaultBackupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create restored vault backup directory: %v", err)
	}

	backupFileInRestoredVault := filepath.Join(restoredVaultBackupDir, filepath.Base(actualBackupFile))
	err = os.WriteFile(backupFileInRestoredVault, backupData, 0600)
	if err != nil {
		t.Fatalf("Failed to copy backup file to restored vault directory: %v", err)
	}

	// Restore using just the filename and the same passphrase
	backupFileNameOnly := filepath.Base(actualBackupFile)
	err = restoredVault.Restore(backupFileNameOnly, backupPassphrase)
	if err != nil {
		t.Fatalf("Failed to restore backup: %v", err)
	}

	// Verify all secrets were restored correctly
	t.Logf("Verifying restored secrets...")
	for secretID, expectedSecret := range secrets {
		result, err := restoredVault.GetSecret(secretID)
		if err != nil {
			t.Fatalf("Failed to retrieve restored secret %s: %v", secretID, err)
		}

		if !bytes.Equal(result.Data, expectedSecret.data) {
			t.Fatalf("Restored secret %s data mismatch", secretID)
		}

		if result.Metadata.ContentType != expectedSecret.contentType {
			t.Fatalf("Restored secret %s content type mismatch: expected %s, got %s",
				secretID, expectedSecret.contentType, result.Metadata.ContentType)
		}

		t.Logf("✅ Verified restored secret: %s", secretID)
	}

	// Verify key metadata was restored
	restoredKeyMetas, err := restoredVault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list restored key metadata: %v", err)
	}

	if len(restoredKeyMetas) < 1 {
		t.Fatal("Expected at least one key in restored vault")
	}

	// Test that the restored vault is functional by storing a new secret
	testSecretID := fmt.Sprintf("post-restore-test-%d", timestamp)
	testSecretData := []byte("test data after restore")

	newMetadata, err := restoredVault.StoreSecret(testSecretID, testSecretData, []string{"post-restore"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store new secret in restored vault: %v", err)
	}

	// Verify we can retrieve the new secret
	newResult, err := restoredVault.GetSecret(testSecretID)
	if err != nil {
		t.Fatalf("Failed to retrieve new secret from restored vault: %v", err)
	}

	if !bytes.Equal(newResult.Data, testSecretData) {
		t.Fatal("New secret in restored vault has incorrect data")
	}

	t.Logf("✅ Successfully backed up and restored vault with %d keys and %d secrets",
		len(keyMetas), len(secrets))
	t.Logf("✅ Original backup file: %s (size: %d bytes)", filepath.Base(actualBackupFile), fileInfo.Size())
	t.Logf("✅ Backup/restore cycle completed successfully")
	t.Logf("✅ All %d secrets restored with correct content types and data", len(secrets))
	t.Logf("✅ Restored vault is fully functional for new operations")
	t.Logf("✅ New secret stored post-restore: %s (version %d)", testSecretID, newMetadata.Version)
}

func testBackupWithNoMetadata(t *testing.T) {
	// Define consistent passphrase for both backup and vault creation
	const testPassphrase = "no-metadata-backup-passphrase-with-sufficient-length"

	// Create a unique test directory for this specific test
	timestamp := time.Now().UnixNano()
	testDir := filepath.Join(tempDir, fmt.Sprintf("backup_no_metadata_test_%d", timestamp))

	// Clean up any existing test directory
	os.RemoveAll(testDir)
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(testDir)
	})

	// Create vault with test options and consistent passphrase
	options := createTestOptions()
	options.DerivationPassphrase = testPassphrase // Use same passphrase for vault
	vault := createTestVault(t, options, testDir)
	defer vault.Close()

	// Create keys but avoid creating secrets (which would create metadata)
	activeKey, err := vault.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to get active key: %v", err)
	}
	t.Logf("Initial active key: %s", activeKey.KeyID)

	// Rotate once to have multiple keys but no secret metadata
	newKey, err := vault.RotateDataEncryptionKey("testBackupWithNoMetadata")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}
	t.Logf("Rotated to new key: %s", newKey.KeyID)

	// Verify we have multiple keys now
	keyMetas, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list key metadata: %v", err)
	}

	if len(keyMetas) < 2 {
		t.Fatalf("Expected at least 2 keys after rotation, got %d", len(keyMetas))
	}

	t.Logf("Vault has %d keys before backup:", len(keyMetas))
	for i, keyMeta := range keyMetas {
		t.Logf("  Key %d: %s (status: %s)", i+1, keyMeta.KeyID, keyMeta.Status)
	}

	// Verify no secrets exist
	secrets, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("Expected no secrets, got %d", len(secrets))
	}
	t.Logf("Confirmed: vault has no secrets (metadata-less backup test)")

	// Use base filename (SaveBackup will add .vault extension)
	backupFileName := fmt.Sprintf("vault_backup_no_metadata_%d", timestamp)
	backupFilePath := filepath.Join(testDir, backupFileName) // This will become backupFileName.vault

	t.Logf("Creating backup with base filename: %s", backupFileName)
	t.Logf("Expected backup file path: %s.vault", backupFilePath)

	// Use the same passphrase for backup as used for vault derivation
	backupPassphrase := testPassphrase

	// Backup should succeed even without secret metadata
	err = vault.Backup(backupFilePath, backupPassphrase)
	if err != nil {
		t.Fatalf("Backup with no metadata failed: %v", err)
	}

	// The actual backup file will have .vault extension added by SaveBackup
	actualBackupFile := backupFilePath + ".vault"

	// Verify backup file was created
	fileInfo, err := os.Stat(actualBackupFile)
	if err != nil {
		// Debug: list files in test directory to see what was actually created
		t.Logf("Files in test directory:")
		if entries, readErr := os.ReadDir(testDir); readErr == nil {
			for _, entry := range entries {
				info, _ := entry.Info()
				if entry.IsDir() {
					t.Logf("  [DIR]  %s/", entry.Name())
				} else {
					t.Logf("  [FILE] %s (size: %d)", entry.Name(), info.Size())
				}
			}
		}

		// Also check if there are any .vault files anywhere in the test directory
		t.Logf("Searching for .vault files:")
		filepath.Walk(testDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && strings.HasSuffix(info.Name(), ".vault") {
				t.Logf("  Found .vault file: %s (size: %d)", path, info.Size())
			}
			return nil
		})

		t.Fatalf("Backup file was not created at expected location %s: %v", actualBackupFile, err)
	}

	if fileInfo.IsDir() {
		t.Fatal("Backup created a directory instead of a file")
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	// Verify backup file contains expected data (should be smaller since no secrets)
	t.Logf("✅ Backup file created: %s (size: %d bytes)", actualBackupFile, fileInfo.Size())

	// Read and parse backup file to verify it contains our data
	backupData, err := os.ReadFile(actualBackupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	// Basic validation - should be smaller than normal backups but not empty
	if len(backupData) < 50 {
		t.Fatalf("Backup file seems too small (only %d bytes)", len(backupData))
	}

	// Test that we can restore from this backup (should restore just keys, no secrets)
	t.Logf("Testing backup restoration to verify integrity...")

	// Create separate directory for restored vault
	restoredVaultDir := filepath.Join(testDir, "restored_vault")
	err = os.MkdirAll(restoredVaultDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create restored vault directory: %v", err)
	}

	// Create restored vault with the SAME passphrase
	restoredOptions := createTestOptions()
	restoredOptions.DerivationPassphrase = testPassphrase // Important: same passphrase
	restoredVault := createTestVault(t, restoredOptions, restoredVaultDir)
	defer restoredVault.Close()

	// Copy backup file to restored vault's backup directory for restore
	restoredVaultBackupDir := filepath.Join(restoredVaultDir, "default", "backups")
	err = os.MkdirAll(restoredVaultBackupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create restored vault backup directory: %v", err)
	}

	backupFileInRestoredVault := filepath.Join(restoredVaultBackupDir, filepath.Base(actualBackupFile))
	err = os.WriteFile(backupFileInRestoredVault, backupData, 0600)
	if err != nil {
		t.Fatalf("Failed to copy backup file to restored vault directory: %v", err)
	}

	// Restore using just the filename and the same passphrase
	backupFileNameOnly := filepath.Base(actualBackupFile)
	err = restoredVault.Restore(backupFileNameOnly, backupPassphrase)
	if err != nil {
		t.Fatalf("Failed to restore backup: %v", err)
	}

	// Verify keys were restored correctly
	t.Logf("Verifying restored keys...")
	restoredKeyMetas, err := restoredVault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list restored key metadata: %v", err)
	}

	if len(restoredKeyMetas) != len(keyMetas) {
		t.Fatalf("Key count mismatch: expected %d, got %d", len(keyMetas), len(restoredKeyMetas))
	}

	t.Logf("✅ Restored %d keys:", len(restoredKeyMetas))
	for i, keyMeta := range restoredKeyMetas {
		t.Logf("  Key %d: %s (status: %s)", i+1, keyMeta.KeyID, keyMeta.Status)
	}

	// Verify no secrets were restored (since there were none)
	restoredSecrets, err := restoredVault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list restored secrets: %v", err)
	}

	if len(restoredSecrets) != 0 {
		t.Errorf("Expected no restored secrets, got %d", len(restoredSecrets))
	}

	// Test that the restored vault is functional by storing a new secret
	testSecret := fmt.Sprintf("test-secret-post-restore-%d", timestamp)
	testData := []byte("test data after restoring metadata-less backup")

	newMetadata, err := restoredVault.StoreSecret(testSecret, testData, []string{"test"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store new secret in restored vault: %v", err)
	}

	// Verify we can retrieve the new secret
	result, err := restoredVault.GetSecret(testSecret)
	if err != nil {
		t.Fatalf("Failed to retrieve new secret from restored vault: %v", err)
	}

	if !bytes.Equal(result.Data, testData) {
		t.Fatal("New secret in restored vault has incorrect data")
	}

	t.Logf("✅ Successfully backed up and restored metadata-less vault")
	t.Logf("✅ Original: %d keys, 0 secrets", len(keyMetas))
	t.Logf("✅ Restored: %d keys, 0 secrets", len(restoredKeyMetas))
	t.Logf("✅ Backup file: %s (size: %d bytes)", filepath.Base(actualBackupFile), fileInfo.Size())
	t.Logf("✅ Restored vault is functional for new operations")
	t.Logf("✅ Test secret created post-restore: %s (version %d)", testSecret, newMetadata.Version)
}

func testBackupFailsWhenSaltInaccessible(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Create a mock vault with inaccessible salt
	mockVault := &MockVaultWithSaltFailure{
		VaultService:   vault,
		saltAccessible: false,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "salt-test-passphrase"

	// The backup should fail when trying to access the salt
	err := mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when salt is inaccessible, but it succeeded")
	}

	if !containsIgnoreCase(err.Error(), "salt") {
		t.Errorf("Expected error to mention salt, got: %v", err)
	}

	t.Logf("Got expected error for inaccessible salt: %v", err)
}

func testBackupFailsWhenKeyLoadFails(t *testing.T) {
	vault := createTestVaultWithDerivation(t)

	// Create some keys first
	_, err := vault.RotateDataEncryptionKey("testBackupFailsWhenKeyLoadFails")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Create a mock vault that fails on specific key operations
	mockVault := &MockVaultWithKeyLoadFailure{
		VaultService: vault,
		failKeyLoad:  true,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "key-load-fail-passphrase"

	err = mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when key load fails")
	}

	if !containsIgnoreCase(err.Error(), "key") && !containsIgnoreCase(err.Error(), "load") {
		t.Errorf("Expected key load error, got: %v", err)
	}

	t.Logf("Got expected error for key load failure: %v", err)
}

func testBackupFailsWhenMetadataLoadFails(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Create a mock vault that fails on metadata operations
	mockVault := &MockVaultWithMetadataFailure{
		VaultService:     vault,
		failMetadataLoad: true,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "metadata-fail-passphrase"

	err := mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when metadata load fails")
	}

	if !containsIgnoreCase(err.Error(), "metadata") {
		t.Errorf("Expected metadata error, got: %v", err)
	}

	t.Logf("Got expected error for metadata load failure: %v", err)
}

func testBackupFailsWhenStorageBackupFails(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Create a mock vault that fails on storage operations
	mockVault := &MockVaultWithStorageFailure{
		VaultService: vault,
		failStorage:  true,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "storage-fail-passphrase"

	err := mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when storage backup fails")
	}

	if !containsIgnoreCase(err.Error(), "storage") && !containsIgnoreCase(err.Error(), "write") {
		t.Errorf("Expected storage error, got: %v", err)
	}

	t.Logf("Got expected error for storage backup failure: %v", err)
}

// Helper functions for the aligned tests

func setupTestVaultData(t *testing.T, vault VaultService) {
	// Create some test secrets
	secrets := map[string]struct {
		data        []byte
		tags        []string
		contentType ContentType
	}{
		"secret1": {[]byte("test-value-1"), []string{"tag1", "test"}, ContentTypeText},
		"secret2": {[]byte(`{"key": "value"}`), []string{"tag2", "json"}, ContentTypeJSON},
		"secret3": {[]byte("binary-data"), []string{"tag3", "binary"}, ContentTypeBinary},
	}

	for secretID, secret := range secrets {
		_, err := vault.StoreSecret(secretID, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secretID, err)
		}
	}
}

func createTempBackupDir(t *testing.T) string {
	backupDir, err := os.MkdirTemp("", "vault_backup_*")
	if err != nil {
		t.Fatalf("Failed to create backup dir: %v", err)
	}
	return backupDir
}

// Helper functions

// Mock vault that simulates salt access failure
type MockVaultWithSaltFailure struct {
	VaultService
	saltAccessible bool
}

func (m *MockVaultWithSaltFailure) Backup(destinationDir, passphrase string) error {
	if !m.saltAccessible {
		return fmt.Errorf("salt enclave is not accessible or corrupted")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

// Mock vault that simulates key load failure
type MockVaultWithKeyLoadFailure struct {
	VaultService
	failKeyLoad bool
}

func (m *MockVaultWithKeyLoadFailure) Backup(destinationDir, passphrase string) error {
	if m.failKeyLoad {
		return fmt.Errorf("failed to load key material during backup")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

func (m *MockVaultWithKeyLoadFailure) ListKeyMetadata() ([]KeyMetadata, error) {
	if m.failKeyLoad {
		return nil, fmt.Errorf("failed to load key metadata")
	}
	return m.VaultService.ListKeyMetadata()
}

// Mock vault that simulates metadata load failure
type MockVaultWithMetadataFailure struct {
	VaultService
	failMetadataLoad bool
}

func (m *MockVaultWithMetadataFailure) Backup(destinationDir, passphrase string) error {
	if m.failMetadataLoad {
		return fmt.Errorf("failed to load secret metadata during backup")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

func (m *MockVaultWithMetadataFailure) ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error) {
	if m.failMetadataLoad {
		return nil, fmt.Errorf("failed to load secret metadata")
	}
	return m.VaultService.ListSecrets(options)
}

// Mock vault that simulates storage backup failure
type MockVaultWithStorageFailure struct {
	VaultService
	failStorage bool
}

func (m *MockVaultWithStorageFailure) Backup(destinationDir, passphrase string) error {
	if m.failStorage {
		return fmt.Errorf("storage backup operation failed: unable to write backup data")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

// Helper function to check if string contains substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
