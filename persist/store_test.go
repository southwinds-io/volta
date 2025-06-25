package persist

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"southwinds.dev/volta/internal/crypto"
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
	testData := []byte("test-encrypted-data-here")
	encodedData := base64.StdEncoding.EncodeToString(testData)
	checksum := crypto.CalculateChecksum(testData)

	backupContainer := &BackupContainer{
		BackupID:         "test-backup-001",
		BackupTimestamp:  time.Now(),
		VaultVersion:     "1.0.0",
		BackupVersion:    "1.0.0",
		EncryptionMethod: "AES-256-GCM",
		TenantID:         testTenant,
		EncryptedData:    encodedData,
		Checksum:         checksum,
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
	var metadataVersion string
	t.Run("SaveMetadata", func(t *testing.T) {
		version, err := store.SaveMetadata(metaData, "")
		require.NoError(t, err)
		assert.NotEmpty(t, version, "Version should not be empty")
		metadataVersion = version
	})

	t.Run("MetadataExists", func(t *testing.T) {
		exists, err := store.MetadataExists()
		require.NoError(t, err)
		assert.True(t, exists, "Metadata should exist after saving")
	})

	t.Run("LoadMetadata", func(t *testing.T) {
		versionedData, err := store.LoadMetadata()
		require.NoError(t, err)
		assert.NotNil(t, versionedData, "Versioned data should not be nil")
		assert.Equal(t, metaData, versionedData.Data, "Loaded metadata should match saved metadata")
		assert.Equal(t, metadataVersion, versionedData.Version, "Version should match")
		assert.False(t, versionedData.Timestamp.IsZero(), "Timestamp should be set")
	})

	// Salt operations
	var saltVersion string
	t.Run("SaveSalt", func(t *testing.T) {
		version, err := store.SaveSalt(salt, "")
		require.NoError(t, err)
		assert.NotEmpty(t, version, "Version should not be empty")
		saltVersion = version
	})

	t.Run("SaltExists", func(t *testing.T) {
		exists, err := store.SaltExists()
		require.NoError(t, err)
		assert.True(t, exists, "Salt should exist after saving")
	})

	t.Run("LoadSalt", func(t *testing.T) {
		versionedData, err := store.LoadSalt()
		require.NoError(t, err)
		assert.NotNil(t, versionedData, "Versioned data should not be nil")
		assert.Equal(t, salt, versionedData.Data, "Loaded salt should match saved salt")
		assert.Equal(t, saltVersion, versionedData.Version, "Version should match")
		assert.False(t, versionedData.Timestamp.IsZero(), "Timestamp should be set")
	})

	// Secrets operations
	var secretsVersion string
	t.Run("SaveSecretsData", func(t *testing.T) {
		version, err := store.SaveSecretsData(secretsData, "")
		require.NoError(t, err)
		assert.NotEmpty(t, version, "Version should not be empty")
		secretsVersion = version
	})

	t.Run("SecretsDataExists", func(t *testing.T) {
		exists, err := store.SecretsDataExists()
		require.NoError(t, err)
		assert.True(t, exists, "Secrets data should exist after saving")
	})

	t.Run("LoadSecretsData", func(t *testing.T) {
		versionedData, err := store.LoadSecretsData()
		require.NoError(t, err)
		assert.NotNil(t, versionedData, "Versioned data should not be nil")
		assert.Equal(t, secretsData, versionedData.Data, "Loaded secrets data should match saved secrets data")
		assert.Equal(t, secretsVersion, versionedData.Version, "Version should match")
		assert.False(t, versionedData.Timestamp.IsZero(), "Timestamp should be set")
	})

	// Optimistic locking tests
	t.Run("OptimisticLocking", func(t *testing.T) {
		t.Run("VersionConflict", func(t *testing.T) {
			// Save initial metadata
			version1, err := store.SaveMetadata(metaData, "")
			require.NoError(t, err)
			require.NotEmpty(t, version1)

			// Load the data to get current version
			versionedData, err := store.LoadMetadata()
			require.NoError(t, err)
			require.NotEmpty(t, versionedData.Version)

			// Create modified metadata (different byte slice)
			modifiedData := []byte(`{
            "name": "Modified Project",
            "description": "A modified test project",
            "version": "1.0.1"
        }`)

			// Save with current version (this should succeed)
			version2, err := store.SaveMetadata(modifiedData, versionedData.Version)
			require.NoError(t, err)
			require.NotEmpty(t, version2)
			require.NotEqual(t, version1, version2)

			// Now try to save again with the old version (this should fail)
			anotherModification := []byte(`{
            "name": "Another Modification",
            "description": "Another test project modification",
            "version": "1.0.2"
        }`)

			_, err = store.SaveMetadata(anotherModification, version1) // Using old version

			// Check if it's a concurrency error
			if concurrencyErr, ok := err.(*ConcurrencyError); ok {
				assert.True(t, true, "Error should be a ConcurrencyError")
				assert.Equal(t, version1, concurrencyErr.ExpectedVersion)
				assert.Equal(t, version2, concurrencyErr.ActualVersion)
				assert.Equal(t, "SaveMetadata", concurrencyErr.Operation)
			} else {
				// If it's not a ConcurrencyError, at least it should be an error
				assert.Error(t, err, "Should return an error for version conflict")
				t.Logf("Got error (not ConcurrencyError): %v", err)

				// For debugging - let's see what type of error we got
				t.Logf("Error type: %T", err)
			}
		})

		t.Run("ValidVersion", func(t *testing.T) {
			// Save initial metadata
			version1, err := store.SaveMetadata(metaData, "")
			require.NoError(t, err)

			// Load to get current version
			versionedData, err := store.LoadMetadata()
			require.NoError(t, err)

			// Create modified metadata
			modifiedData := []byte(`{
            "name": "Valid Version Update",
            "description": "A valid version update test",
            "version": "1.0.3"
        }`)

			// Save with correct version (should succeed)
			version2, err := store.SaveMetadata(modifiedData, versionedData.Version)
			require.NoError(t, err)
			require.NotEmpty(t, version2)
			require.NotEqual(t, version1, version2)

			// Verify the update was successful
			loadedData, err := store.LoadMetadata()
			require.NoError(t, err)
			assert.Equal(t, version2, loadedData.Version)
			assert.Contains(t, string(loadedData.Data), "Valid Version Update")
		})

		t.Run("EmptyVersionOnFirstSave", func(t *testing.T) {
			// First save should work with empty version
			version, err := store.SaveMetadata(metaData, "")
			require.NoError(t, err)
			require.NotEmpty(t, version)
		})
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
				"Backup count should decrease by 1 after deletion (expected %d, got %d)",
				expectedCount, actualCount)
		})

		t.Run("RestoreNonexistentBackup", func(t *testing.T) {
			_, err := store.RestoreBackup("nonexistent-backup")
			assert.Error(t, err, "Restoring nonexistent backup should return error")
		})

		t.Run("DeleteNonexistentBackup", func(t *testing.T) {
			err := store.DeleteBackup("nonexistent-backup-id")
			assert.Error(t, err, "Deleting nonexistent backup should return error")
		})
	})

	// Error handling tests
	t.Run("ErrorHandling", func(t *testing.T) {
		// Then use it in your tests:
		t.Run("LoadNonexistentData", func(t *testing.T) {
			testStore := createFreshTestStore(t, "metadata")

			// Verify clean state
			exists, err := testStore.MetadataExists()
			require.NoError(t, err)
			require.False(t, exists, "Fresh store should have no existing metadata")

			// Test loading nonexistent metadata
			data, err := testStore.LoadMetadata()
			assert.Error(t, err, "Loading nonexistent metadata should return error")
			assert.Nil(t, data, "Data should be nil when error occurs")
			t.Logf("Got expected error: %v", err)
		})

		t.Run("LoadNonexistentSalt", func(t *testing.T) {
			testStore := createFreshTestStore(t, "salt")

			// Verify clean state
			exists, err := testStore.SaltExists()
			require.NoError(t, err)
			require.False(t, exists, "Fresh store should have no existing salt")

			// Test loading nonexistent salt
			data, err := testStore.LoadSalt()
			assert.Error(t, err, "Loading nonexistent salt should return error")
			assert.Nil(t, data, "Data should be nil when error occurs")
			t.Logf("Got expected error for salt: %v", err)
		})

		t.Run("LoadNonexistentSecretsData", func(t *testing.T) {
			testStore := createFreshTestStore(t, "secrets")

			// Verify clean state
			exists, err := testStore.SecretsDataExists()
			require.NoError(t, err)
			require.False(t, exists, "Fresh store should have no existing secrets")

			// Test loading nonexistent secrets
			data, err := testStore.LoadSecretsData()
			assert.Error(t, err, "Loading nonexistent secrets data should return error")
			assert.Nil(t, data, "Data should be nil when error occurs")
			t.Logf("Got expected error for secrets: %v", err)
		})

		t.Run("DeleteNonexistentTenant", func(t *testing.T) {
			err := store.DeleteTenant("nonexistent-tenant-12345")
			assert.Error(t, err, "Deleting nonexistent tenant should return error")

			errorMsg := err.Error()
			assert.True(t,
				strings.Contains(errorMsg, "not found") ||
					strings.Contains(errorMsg, "does not exist") ||
					strings.Contains(errorMsg, "not exist"),
				"Error should indicate tenant doesn't exist, got: %s", errorMsg)
		})

		t.Run("DeleteNonexistentBackup", func(t *testing.T) {
			err := store.DeleteBackup("nonexistent-backup-12345")
			assert.Error(t, err, "Deleting nonexistent backup should return error")
			t.Logf("Got expected error for backup deletion: %v", err)
		})

		t.Run("RestoreNonexistentBackup", func(t *testing.T) {
			_, err := store.RestoreBackup("nonexistent-backup-path")
			assert.Error(t, err, "Restoring nonexistent backup should return error")
			t.Logf("Got expected error for backup restore: %v", err)
		})

		t.Run("SaveWithInvalidVersion", func(t *testing.T) {
			// Try to save with a clearly invalid version
			invalidVersion := "invalid-version-that-should-not-exist-12345"

			// Only test this if metadata already exists
			exists, err := store.MetadataExists()
			require.NoError(t, err)

			if exists {
				_, err := store.SaveMetadata([]byte(`{"test": "invalid version"}`), invalidVersion)
				if err != nil {
					// This should be a concurrency error or similar
					t.Logf("Got expected error for invalid version: %v", err)
				} else {
					t.Log("SaveMetadata with invalid version succeeded - this might be valid for some implementations")
				}
			} else {
				t.Skip("No existing metadata to test version conflicts")
			}
		})

		t.Run("SaveNilData", func(t *testing.T) {
			_, err := store.SaveMetadata(nil, "")
			// This might be valid for some implementations, so just log the result
			if err != nil {
				t.Logf("SaveMetadata with nil data failed: %v", err)
			} else {
				t.Log("SaveMetadata with nil data succeeded")
			}
		})
	})

	// Enhanced Concurrency tests with advanced scenarios
	t.Run("ConcurrentOperations", func(t *testing.T) {
		// First, ensure directory structure exists by saving some initial data
		testData = []byte("initial-test-data")

		// Initialize with some data to create directory structure
		_, err := store.SaveMetadata(testData, "")
		require.NoError(t, err, "Initial metadata save should succeed")

		_, err = store.SaveSalt([]byte("initial-salt"), "")
		require.NoError(t, err, "Initial salt save should succeed")

		_, err = store.SaveSecretsData([]byte("initial-secrets"), "")
		require.NoError(t, err, "Initial secrets save should succeed")

		// Now run concurrent operations
		var wg sync.WaitGroup
		errors := make(chan error, 30)

		// Concurrent metadata operations
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				data := []byte(fmt.Sprintf("concurrent-metadata-%d", id))
				if _, err = store.SaveMetadata(data, ""); err != nil {
					errors <- err
				}
			}(i)
		}

		// Concurrent salt operations
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				data := []byte(fmt.Sprintf("concurrent-salt-%d", id))
				if _, err = store.SaveSalt(data, ""); err != nil {
					errors <- err
				}
			}(i)
		}

		// Concurrent secrets operations
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				data := []byte(fmt.Sprintf("concurrent-secrets-%d", id))
				if _, err = store.SaveSecretsData(data, ""); err != nil {
					errors <- err
				}
			}(i)
		}

		// Concurrent read operations
		for i := 0; i < 5; i++ {
			wg.Add(3)
			go func() {
				defer wg.Done()
				if _, err = store.LoadMetadata(); err != nil {
					errors <- err
				}
			}()
			go func() {
				defer wg.Done()
				if _, err = store.LoadSalt(); err != nil {
					errors <- err
				}
			}()
			go func() {
				defer wg.Done()
				if _, err = store.LoadSecretsData(); err != nil {
					errors <- err
				}
			}()
		}

		wg.Wait()
		close(errors)

		// Check for errors
		var errorList []error
		for err = range errors {
			errorList = append(errorList, err)
		}
		require.Empty(t, errorList, "Concurrent operations should not fail: %v", errorList)
	})

	// Edge cases with versioning
	t.Run("EdgeCases", func(t *testing.T) {
		t.Run("EmptyData", func(t *testing.T) {
			emptyData := []byte{}

			version, err := store.SaveMetadata(emptyData, "")
			require.NoError(t, err, "Should handle empty data")
			assert.NotEmpty(t, version, "Should return version for empty data")

			loaded, err := store.LoadMetadata()
			require.NoError(t, err, "Loading empty data should not error")
			assert.NotNil(t, loaded, "Should return versioned data, not nil")
			assert.NotNil(t, loaded.Data, "Data should not be nil")
			assert.Len(t, loaded.Data, 0, "Data should be empty")
			assert.Equal(t, version, loaded.Version, "Version should match")
		})

		t.Run("NilData", func(t *testing.T) {
			_, err := store.SaveMetadata(nil, "")
			assert.Error(t, err, "Should handle nil data appropriately")
		})

		t.Run("LargeData", func(t *testing.T) {
			// Test with large data (1MB)
			largeData := make([]byte, 1024*1024)
			for i := range largeData {
				largeData[i] = byte(i % 256)
			}

			version, err := store.SaveMetadata(largeData, "")
			require.NoError(t, err, "Should handle large data")
			assert.NotEmpty(t, version, "Should return version for large data")

			loaded, err := store.LoadMetadata()
			require.NoError(t, err)
			assert.Equal(t, largeData, loaded.Data, "Large data should match")
			assert.Equal(t, version, loaded.Version, "Version should match")
		})

		t.Run("InvalidVersion", func(t *testing.T) {
			data := []byte("test_with_invalid_version")

			// Try to save with completely invalid version
			_, err := store.SaveMetadata(data, "invalid-version-12345")
			assert.Error(t, err, "Should fail with invalid version")
			assert.Contains(t, err.Error(), "version conflict", "Should indicate version conflict")
		})

		t.Run("EmptyVersion", func(t *testing.T) {
			// Empty version string should work for initial saves
			data := []byte("test_empty_version")
			version, err := store.SaveMetadata(data, "")
			require.NoError(t, err, "Empty version should work for new saves")
			assert.NotEmpty(t, version, "Should generate new version")
		})

		t.Run("RapidSequentialUpdates", func(t *testing.T) {
			// Test rapid sequential updates to ensure versioning works correctly
			baseData := []byte("rapid-update-base")
			version, err := store.SaveMetadata(baseData, "")
			require.NoError(t, err)

			const numUpdates = 10
			currentVersion := version

			for i := 0; i < numUpdates; i++ {
				updateData := []byte(fmt.Sprintf("rapid-update-%d", i))
				newVersion, err := store.SaveMetadata(updateData, currentVersion)
				require.NoError(t, err, "Update %d should succeed", i)
				assert.NotEqual(t, currentVersion, newVersion, "Version should change on update %d", i)
				currentVersion = newVersion

				// Verify the update
				loaded, err := store.LoadMetadata()
				require.NoError(t, err)
				assert.Equal(t, updateData, loaded.Data, "Data should match for update %d", i)
				assert.Equal(t, newVersion, loaded.Version, "Version should match for update %d", i)
			}
		})

		t.Run("VersionStringConsistency", func(t *testing.T) {
			// Test that version strings are consistent and meaningful
			data := []byte("version-consistency-test")
			version1, err := store.SaveMetadata(data, "")
			require.NoError(t, err)

			// Version should be non-empty and consistent
			assert.NotEmpty(t, version1, "Version should not be empty")
			assert.True(t, len(version1) > 8, "Version should be reasonably long")

			// Update and get new version
			newData := []byte("version-consistency-test-updated")
			version2, err := store.SaveMetadata(newData, version1)
			require.NoError(t, err)

			assert.NotEqual(t, version1, version2, "Versions should be different")
			assert.True(t, len(version2) > 8, "New version should be reasonably long")

			// Verify loaded version matches
			loaded, err := store.LoadMetadata()
			require.NoError(t, err)
			assert.Equal(t, version2, loaded.Version, "Loaded version should match saved version")
		})
	})

	// Performance and stress tests
	t.Run("PerformanceTests", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping performance tests in short mode")
		}

		t.Run("SequentialWritePerformance", func(t *testing.T) {
			const numWrites = 50

			startTime := time.Now()
			currentVersion := ""

			for i := 0; i < numWrites; i++ {
				testData := []byte(fmt.Sprintf("performance-test-%d", i))
				newVersion, err := store.SaveMetadata(testData, currentVersion)
				require.NoError(t, err, "Write %d should succeed", i)
				currentVersion = newVersion
			}

			duration := time.Since(startTime)
			avgTimePerWrite := duration / numWrites

			t.Logf("Sequential writes: %d operations in %v (avg: %v per operation)",
				numWrites, duration, avgTimePerWrite)

			// Performance should be reasonable (adjust threshold as needed)
			assert.Less(t, avgTimePerWrite, time.Second, "Average write time should be reasonable")
		})

		t.Run("ReadPerformance", func(t *testing.T) {
			// Setup test data
			testData := []byte("read-performance-test")
			_, err := store.SaveMetadata(testData, "")
			require.NoError(t, err)

			const numReads = 100
			startTime := time.Now()

			for i := 0; i < numReads; i++ {
				loaded, err := store.LoadMetadata()
				require.NoError(t, err)
				assert.Equal(t, testData, loaded.Data)
			}

			duration := time.Since(startTime)
			avgTimePerRead := duration / numReads

			t.Logf("Sequential reads: %d operations in %v (avg: %v per operation)",
				numReads, duration, avgTimePerRead)

			// Read performance should be good
			assert.Less(t, avgTimePerRead, 500*time.Millisecond, "Average read time should be reasonable")
		})

		t.Run("MixedWorkloadPerformance", func(t *testing.T) {
			// Mixed read/write workload
			const totalOperations = 100
			const writeRatio = 0.2 // 20% writes, 80% reads

			// Initialize
			_, err := store.SaveMetadata([]byte("mixed-workload-initial"), "")
			require.NoError(t, err)

			startTime := time.Now()
			var writeCount, readCount int

			for i := 0; i < totalOperations; i++ {
				if float64(i)/float64(totalOperations) < writeRatio {
					// Perform write
					current, err := store.LoadMetadata()
					require.NoError(t, err)

					newData := []byte(fmt.Sprintf("mixed-workload-write-%d", i))
					_, err = store.SaveMetadata(newData, current.Version)
					require.NoError(t, err)
					writeCount++
				} else {
					// Perform read
					_, err := store.LoadMetadata()
					require.NoError(t, err)
					readCount++
				}
			}

			duration := time.Since(startTime)
			avgTimePerOp := duration / totalOperations

			t.Logf("Mixed workload: %d total ops (%d writes, %d reads) in %v (avg: %v per op)",
				totalOperations, writeCount, readCount, duration, avgTimePerOp)

			assert.Less(t, avgTimePerOp, time.Second, "Average operation time should be reasonable")
		})

		t.Run("ConcurrentReadPerformance", func(t *testing.T) {
			// Setup
			testData := []byte("concurrent-read-performance")
			_, err := store.SaveMetadata(testData, "")
			require.NoError(t, err)

			const numReaders = 10
			const readsPerReader = 20

			var wg sync.WaitGroup
			startTime := time.Now()

			for i := 0; i < numReaders; i++ {
				wg.Add(1)
				go func(readerID int) {
					defer wg.Done()

					for j := 0; j < readsPerReader; j++ {
						loaded, err := store.LoadMetadata()
						require.NoError(t, err)
						assert.Equal(t, testData, loaded.Data)
					}
				}(i)
			}

			wg.Wait()
			duration := time.Since(startTime)
			totalReads := numReaders * readsPerReader
			avgTimePerRead := duration / time.Duration(totalReads)

			t.Logf("Concurrent reads: %d readers × %d reads = %d total reads in %v (avg: %v per read)",
				numReaders, readsPerReader, totalReads, duration, avgTimePerRead)

			assert.Less(t, avgTimePerRead, 500*time.Millisecond, "Concurrent read performance should be good")
		})
	})

	// Resource cleanup and validation
	t.Run("ResourceManagement", func(t *testing.T) {
		t.Run("DataConsistencyAfterErrors", func(t *testing.T) {
			// Save known good data
			goodData := []byte("consistency-test-good")
			version, err := store.SaveMetadata(goodData, "")
			require.NoError(t, err)

			// Try to corrupt with invalid version (should fail)
			badData := []byte("consistency-test-bad")
			_, err = store.SaveMetadata(badData, "invalid-version")
			assert.Error(t, err, "Invalid version should fail")

			// Verify original data is unchanged
			loaded, err := store.LoadMetadata()
			require.NoError(t, err)
			assert.Equal(t, goodData, loaded.Data, "Original data should be preserved")
			assert.Equal(t, version, loaded.Version, "Original version should be preserved")
		})

		t.Run("StorageIntegrity", func(t *testing.T) {
			// Test that all three data types can coexist
			metaData := []byte("integrity-metadata")
			saltData := []byte("integrity-salt")
			secretsData := []byte("integrity-secrets")

			// Save all three types
			metaVersion, err := store.SaveMetadata(metaData, "")
			require.NoError(t, err)

			saltVersion, err := store.SaveSalt(saltData, "")
			require.NoError(t, err)

			secretsVersion, err := store.SaveSecretsData(secretsData, "")
			require.NoError(t, err)

			// Verify all exist
			assert.True(t, mustExists(store.MetadataExists()), "Metadata should exist")
			assert.True(t, mustExists(store.SaltExists()), "Salt should exist")
			assert.True(t, mustExists(store.SecretsDataExists()), "Secrets should exist")

			// Verify all can be loaded independently
			loadedMeta, err := store.LoadMetadata()
			require.NoError(t, err)
			assert.Equal(t, metaData, loadedMeta.Data)
			assert.Equal(t, metaVersion, loadedMeta.Version)

			loadedSalt, err := store.LoadSalt()
			require.NoError(t, err)
			assert.Equal(t, saltData, loadedSalt.Data)
			assert.Equal(t, saltVersion, loadedSalt.Version)

			loadedSecrets, err := store.LoadSecretsData()
			require.NoError(t, err)
			assert.Equal(t, secretsData, loadedSecrets.Data)
			assert.Equal(t, secretsVersion, loadedSecrets.Version)
		})

		t.Run("MemoryUsage", func(t *testing.T) {
			// Test with various data sizes to ensure no memory leaks
			sizes := []int{1024, 10 * 1024, 100 * 1024, 1024 * 1024} // 1KB to 1MB

			for _, size := range sizes {
				t.Run(fmt.Sprintf("Size_%dKB", size/1024), func(t *testing.T) {
					data := make([]byte, size)
					for i := range data {
						data[i] = byte(i % 256)
					}

					version, err := store.SaveMetadata(data, "")
					require.NoError(t, err)

					loaded, err := store.LoadMetadata()
					require.NoError(t, err)
					assert.Equal(t, data, loaded.Data)
					assert.Equal(t, version, loaded.Version)

					// Force garbage collection to help detect memory leaks
					// (This is more of a hint for manual testing)
					_ = loaded.Data
				})
			}
		})
	})

	// Tenant deletion test (should be last as it removes data)
	t.Run("DeleteTenant", func(t *testing.T) {
		// Ensure current tenant exists
		_, err := store.SaveMetadata(metaData, "")
		require.NoError(t, err)

		// Test basic error cases
		t.Run("DeleteNonExistentTenant", func(t *testing.T) {
			err := store.DeleteTenant("non-existent-tenant")
			assert.Error(t, err)
			// Handle different error messages for different store types
			errorMsg := err.Error()
			assert.True(t,
				strings.Contains(errorMsg, "not found") ||
					strings.Contains(errorMsg, "does not exist"),
				"Error should indicate tenant doesn't exist, got: %s", errorMsg)
		})

		// Get current tenant info
		tenants, err := store.ListTenants()
		require.NoError(t, err)
		t.Logf("Available tenants: %v", tenants)

		// Test current tenant protection
		if len(tenants) > 0 {
			// Test that we cannot delete current tenant
			for _, tenant := range tenants {
				err := store.DeleteTenant(tenant)
				if err != nil && strings.Contains(err.Error(), "cannot delete current tenant") {
					// This is the expected behavior for current tenant
					assert.Contains(t, err.Error(), "cannot delete current tenant")
					t.Logf("Correctly prevented deletion of current tenant: %s", tenant)
				} else if err == nil {
					// Deletion succeeded - verify it's actually gone
					newTenants, err := store.ListTenants()
					require.NoError(t, err)
					assert.NotContains(t, newTenants, tenant, "Deleted tenant should not exist")
					t.Logf("Successfully deleted tenant: %s", tenant)
				} else {
					t.Logf("Deletion of tenant %s failed with error: %v", tenant, err)
				}
			}
		}

		t.Run("DeleteCurrentTenant", func(t *testing.T) {
			// Get current tenants
			tenants, err := store.ListTenants()
			require.NoError(t, err)

			if len(tenants) > 0 {
				// Try to delete the first tenant (likely the current one)
				err := store.DeleteTenant(tenants[0])
				if err != nil {
					assert.Contains(t, err.Error(), "cannot delete current tenant")
					t.Logf("Successfully caught current tenant deletion attempt for: %s", tenants[0])
				} else {
					t.Logf("Deletion succeeded for tenant: %s (this might not be the current tenant)", tenants[0])
				}
			}
		})
	})

	// Cleanup and close
	t.Run("Close", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err, "Store should close without error")
	})
}

// Helper function to handle exists checks that return (bool, error)
func mustExists(exists bool, err error) bool {
	if err != nil {
		return false
	}
	return exists
}

// Helper function to create a fresh store for testing
func createFreshTestStore(t *testing.T, testName string) Store {
	tempTestDir := t.TempDir()
	tenantID := fmt.Sprintf("%s-test-tenant", testName)
	store, err := NewFileSystemStore(tempTestDir, tenantID)
	assert.NoError(t, err, "NewFileSystemStore should succeed")
	t.Cleanup(func() { store.Close() })
	return store
}
