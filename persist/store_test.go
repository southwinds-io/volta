package persist

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTenant = "test-tenant"

// Test the Common Store Functionality
func testStoreImplementation(t *testing.T, store Store) {
	// Shared test data
	metaData := []byte("encrypted_metadata")
	salt := []byte("random_salt")
	secretsData := []byte("encrypted_secrets_data")

	// Test data for backup operations
	backupContainer := &BackupContainer{
		BackupID:         "test-backup-001",
		BackupTimestamp:  time.Now(),
		VaultVersion:     "1.0.0",
		BackupVersion:    "1.0.0",
		Checksum:         "abc123def456",
		EncryptionMethod: "AES-256-GCM",
		EncryptedData:    "base64encodeddata",
		TenantID:         testTenant,
	}

	// Health and connectivity tests
	t.Run("Ping", func(t *testing.T) {
		err := store.Ping()
		assert.NoError(t, err, "Store should be reachable")
	})

	t.Run("GetType", func(t *testing.T) {
		storeType := store.GetType()
		assert.NotEmpty(t, storeType, "Store type should not be empty")
		t.Logf("Store type: %s", storeType)
	})

	// Tenant operations
	t.Run("ListTenants", func(t *testing.T) {
		tenants, err := store.ListTenants()
		require.NoError(t, err)
		assert.Len(t, tenants, 1, "Should have exactly one tenant")
		assert.True(t, strings.EqualFold(tenants[0], testTenant),
			"Tenant should be %s, got %s", testTenant, tenants[0])
	})

	// Metadata operations
	t.Run("SaveMetadata", func(t *testing.T) {
		err := store.SaveMetadata(metaData)
		require.NoError(t, err)
	})

	t.Run("MetadataExists", func(t *testing.T) {
		exists, err := store.MetadataExists()
		require.NoError(t, err)
		assert.True(t, exists, "Metadata should exist after saving")
	})

	t.Run("LoadMetadata", func(t *testing.T) {
		loadedMetaData, err := store.LoadMetadata()
		require.NoError(t, err)
		assert.Equal(t, metaData, loadedMetaData,
			"Loaded metadata should match saved metadata")
	})

	// Salt operations
	t.Run("SaveSalt", func(t *testing.T) {
		err := store.SaveSalt(salt)
		require.NoError(t, err)
	})

	t.Run("SaltExists", func(t *testing.T) {
		exists, err := store.SaltExists()
		require.NoError(t, err)
		assert.True(t, exists, "Salt should exist after saving")
	})

	t.Run("LoadSalt", func(t *testing.T) {
		loadedSalt, err := store.LoadSalt()
		require.NoError(t, err)
		assert.Equal(t, salt, loadedSalt,
			"Loaded salt should match saved salt")
	})

	// Secrets operations
	t.Run("SaveSecretsData", func(t *testing.T) {
		err := store.SaveSecretsData(secretsData)
		require.NoError(t, err)
	})

	t.Run("SecretsDataExists", func(t *testing.T) {
		exists, err := store.SecretsDataExists()
		require.NoError(t, err)
		assert.True(t, exists, "Secrets data should exist after saving")
	})

	t.Run("LoadSecretsData", func(t *testing.T) {
		loadedSecretsData, err := store.LoadSecretsData()
		require.NoError(t, err)
		assert.Equal(t, secretsData, loadedSecretsData,
			"Loaded secrets data should match saved secrets data")
	})

	// Backup operations (restructured for better isolation)
	t.Run("BackupOperations", func(t *testing.T) {
		backupPath := "test-backup-path"

		t.Run("SaveBackup", func(t *testing.T) {
			err := store.SaveBackup(backupPath, backupContainer)
			require.NoError(t, err)
		})

		t.Run("ListBackups", func(t *testing.T) {
			backups, err := store.ListBackups()
			require.NoError(t, err)
			assert.NotEmpty(t, backups, "Should have at least one backup after saving")

			// Find our backup
			found := false
			for _, backup := range backups {
				if backup.BackupID == backupContainer.BackupID ||
					(backup.TenantID == backupContainer.TenantID && backup.FileSize > 0) {
					found = true

					// Now we expect these validations to pass
					assert.Equal(t, backupContainer.BackupID, backup.BackupID)
					assert.Equal(t, backupContainer.TenantID, backup.TenantID)
					assert.Equal(t, backupContainer.VaultVersion, backup.VaultVersion)
					assert.Equal(t, backupContainer.BackupVersion, backup.BackupVersion)
					assert.True(t, backup.IsValid, "Backup should be marked as valid")
					assert.True(t, backup.FileSize > 0, "File size should be greater than 0")

					t.Logf("Found backup: ID=%s, Size=%d bytes, Valid=%t, Tenant=%s",
						backup.BackupID, backup.FileSize, backup.IsValid, backup.TenantID)
					break
				}
			}
			assert.True(t, found, "Saved backup should be found in backup list")
		})

		t.Run("RestoreBackup", func(t *testing.T) {
			restoredContainer, err := store.RestoreBackup(backupPath)
			require.NoError(t, err)
			assert.NotNil(t, restoredContainer)

			// Validate restored container matches original
			assert.Equal(t, backupContainer.BackupID, restoredContainer.BackupID)
			assert.Equal(t, backupContainer.TenantID, restoredContainer.TenantID)
			assert.Equal(t, backupContainer.VaultVersion, restoredContainer.VaultVersion)
			assert.Equal(t, backupContainer.BackupVersion, restoredContainer.BackupVersion)
			assert.Equal(t, backupContainer.EncryptionMethod, restoredContainer.EncryptionMethod)
			assert.Equal(t, backupContainer.Checksum, restoredContainer.Checksum)
			assert.Equal(t, backupContainer.EncryptedData, restoredContainer.EncryptedData)
		})

		t.Run("DeleteBackup", func(t *testing.T) {
			// Get backups before deletion for debugging
			backupsBeforeDelete, err := store.ListBackups()
			require.NoError(t, err)

			foundBeforeDelete := false
			for _, backup := range backupsBeforeDelete {
				if backup.BackupID == backupContainer.BackupID {
					foundBeforeDelete = true
					t.Logf("Found backup before deletion: ID=%s, Size=%d, Valid=%t, Tenant=%s",
						backup.BackupID, backup.FileSize, backup.IsValid, backup.TenantID)
					break
				}
			}
			require.True(t, foundBeforeDelete, "Backup should exist before deletion")

			// Delete the backup
			t.Logf("Deleting backup with ID: %s", backupContainer.BackupID)
			err = store.DeleteBackup(backupContainer.BackupID)
			require.NoError(t, err, "DeleteBackup should succeed")

			// Add a small delay to handle potential async operations
			time.Sleep(100 * time.Millisecond)

			// Verify backup is removed from list
			backupsAfterDelete, err := store.ListBackups()
			require.NoError(t, err)

			// Debug: Log all remaining backups
			t.Logf("Backups after deletion (%d total):", len(backupsAfterDelete))
			for i, backup := range backupsAfterDelete {
				t.Logf("  [%d] ID=%s, Size=%d, Valid=%t, Tenant=%s",
					i, backup.BackupID, backup.FileSize, backup.IsValid, backup.TenantID)
			}

			foundAfterDelete := false
			for _, backup := range backupsAfterDelete {
				if backup.BackupID == backupContainer.BackupID {
					foundAfterDelete = true
					t.Errorf("Found deleted backup still in list: ID=%s, Size=%d, Valid=%t",
						backup.BackupID, backup.FileSize, backup.IsValid)
					break
				}
			}
			assert.False(t, foundAfterDelete,
				"Deleted backup should not be found in backup list")

			// Verify backup count decreased
			expectedCount := len(backupsBeforeDelete) - 1
			actualCount := len(backupsAfterDelete)
			assert.Equal(t, expectedCount, actualCount,
				"Backup count should decrease by 1 after deletion (expected: %d, actual: %d)",
				expectedCount, actualCount)
		})

		t.Run("VerifyBackupDeleted", func(t *testing.T) {
			// Try to restore the deleted backup (should fail)
			_, err := store.RestoreBackup(backupPath)
			assert.Error(t, err, "Restoring deleted backup should fail")
		})
	})

	// Error handling tests
	t.Run("ErrorHandling", func(t *testing.T) {
		t.Run("LoadNonexistentMetadata", func(t *testing.T) {
			// First clear any existing data
			// Before error handling tests, delete the tenant data
			err := store.DeleteTenant(testTenant)
			require.NoError(t, err)

			// Try loading metadata that doesn't exist
			_, err = store.LoadMetadata()
			assert.Error(t, err, "Loading nonexistent metadata should return error")

			// Check that metadata doesn't exist
			exists, err := store.MetadataExists()
			require.NoError(t, err)
			assert.False(t, exists, "Metadata should not exist")
		})

		t.Run("LoadNonexistentSalt", func(t *testing.T) {
			// Try loading salt that doesn't exist
			_, err := store.LoadSalt()
			assert.Error(t, err, "Loading nonexistent salt should return error")

			// Check that salt doesn't exist
			exists, err := store.SaltExists()
			require.NoError(t, err)
			assert.False(t, exists, "Salt should not exist")
		})

		t.Run("LoadNonexistentSecretsData", func(t *testing.T) {
			// Try loading secrets data that doesn't exist
			_, err := store.LoadSecretsData()
			assert.Error(t, err, "Loading nonexistent secrets data should return error")

			// Check that secrets data doesn't exist
			exists, err := store.SecretsDataExists()
			require.NoError(t, err)
			assert.False(t, exists, "Secrets data should not exist")
		})

		t.Run("RestoreNonexistentBackup", func(t *testing.T) {
			nonexistentPath := "nonexistent-backup-path"
			_, err := store.RestoreBackup(nonexistentPath)
			assert.Error(t, err, "Restoring nonexistent backup should return error")
		})

		t.Run("DeleteNonexistentBackup", func(t *testing.T) {
			nonexistentID := "nonexistent-backup-id"
			err := store.DeleteBackup(nonexistentID)
			assert.Error(t, err, "Deleting nonexistent backup should return error")
		})

		t.Run("DeleteNonexistentTenant", func(t *testing.T) {
			nonexistentTenant := "nonexistent-tenant"
			err := store.DeleteTenant(nonexistentTenant)
			assert.Error(t, err, "Deleting nonexistent tenant should return error")
		})
	})

	// Tenant deletion test (should be last as it removes data)
	t.Run("DeleteTenant", func(t *testing.T) {
		// First ensure tenant exists by saving some data
		err := store.SaveMetadata(metaData)
		require.NoError(t, err)

		// Verify tenant exists
		tenants, err := store.ListTenants()
		require.NoError(t, err)
		assert.Contains(t, tenants, testTenant, "Tenant should exist before deletion")

		// Delete the tenant
		err = store.DeleteTenant(testTenant)
		require.NoError(t, err)

		// Verify tenant is removed
		tenants, err = store.ListTenants()
		require.NoError(t, err)
		assert.NotContains(t, tenants, testTenant, "Tenant should not exist after deletion")

		// Verify associated data is also removed
		exists, err := store.MetadataExists()
		require.NoError(t, err)
		assert.False(t, exists, "Metadata should be removed when tenant is deleted")
	})

	// Cleanup and close
	t.Run("Close", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err, "Store should close without error")
	})

	t.Run("ConcurrentOperations", func(t *testing.T) {
		const numWriters = 3
		const numReaders = 10
		var wg sync.WaitGroup
		var mu sync.Mutex
		var errors []error

		// Channel to control write operations
		writeQueue := make(chan int, numWriters)
		for i := 0; i < numWriters; i++ {
			writeQueue <- i
		}
		close(writeQueue)

		// Writers - serialize these to avoid conflicts
		for writeID := range writeQueue {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				data := []byte(fmt.Sprintf("test_data_%d", id))
				err := store.SaveMetadata(data)
				if err != nil {
					mu.Lock()
					errors = append(errors, fmt.Errorf("writer %d: %w", id, err))
					mu.Unlock()
				}
			}(writeID)

			// Small delay between writes to avoid conflicts
			time.Sleep(100 * time.Millisecond)
		}

		// Wait for writes to complete
		wg.Wait()

		// Now test concurrent reads
		for i := 0; i < numReaders; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				exists, err := store.MetadataExists()
				if err != nil {
					mu.Lock()
					errors = append(errors, fmt.Errorf("reader %d exists: %w", id, err))
					mu.Unlock()
					return
				}

				if !exists {
					mu.Lock()
					errors = append(errors, fmt.Errorf("reader %d: metadata should exist", id))
					mu.Unlock()
					return
				}

				// Also test loading
				_, err = store.LoadMetadata()
				if err != nil {
					mu.Lock()
					errors = append(errors, fmt.Errorf("reader %d load: %w", id, err))
					mu.Unlock()
				}
			}(i)
		}

		wg.Wait()
		assert.Empty(t, errors, "Concurrent operations should work correctly")
	})

	t.Run("EdgeCases", func(t *testing.T) {
		t.Run("EmptyData", func(t *testing.T) {
			emptyData := []byte{} // Explicitly empty slice

			err := store.SaveMetadata(emptyData)
			require.NoError(t, err, "Should handle empty data")

			loaded, err := store.LoadMetadata()
			require.NoError(t, err, "Loading empty data should not error")

			// Be explicit about what we're testing
			assert.NotNil(t, loaded, "Should return empty slice, not nil")
			assert.Len(t, loaded, 0, "Should be empty")
			assert.Equal(t, emptyData, loaded, "Should return exactly what was saved")
		})

		t.Run("NilData", func(t *testing.T) {
			err := store.SaveMetadata(nil)
			// This might be an error case depending on your implementation
			// Adjust assertion based on expected behavior
			assert.Error(t, err, "Should handle nil data appropriately")
		})

		t.Run("LargeData", func(t *testing.T) {
			// Test with large data (1MB)
			largeData := make([]byte, 1024*1024)
			for i := range largeData {
				largeData[i] = byte(i % 256)
			}

			err := store.SaveMetadata(largeData)
			assert.NoError(t, err, "Should handle large data")

			loaded, err := store.LoadMetadata()
			assert.NoError(t, err)
			assert.Equal(t, largeData, loaded)
		})
	})

}
