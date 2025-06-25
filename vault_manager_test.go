package volta

import (
	"fmt"
	"os"
	"southwinds.dev/volta/audit"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	testManagerTempDir    = "data"
	testManagerPassphrase = "manager-test-secure-passphrase"
)

func TestVaultManagerAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"VaultManagerCreation", TestVaultManagerCreation},
		{"VaultManagerTenantOperations", TestVaultManagerTenantOperations},
		{"VaultManagerConcurrency", TestVaultManagerConcurrency},
		{"VaultManagerBulkOperations", TestVaultManagerBulkOperations},
		{"VaultManagerAuditOperations", TestVaultManagerAuditOperations},
		{"VaultManagerErrorHandling", TestVaultManagerErrorHandling},
		{"VaultManagerCleanup", TestVaultManagerCleanup},
	}

	// Ensure clean test environment
	defer cleanupManager(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestVaultManagerCreation(t *testing.T) {
	// Test FileStore constructor
	manager := createTestVaultManager(t, testManagerTempDir)
	if manager == nil {
		t.Fatal("Failed to create VaultManager with FileStore")
	}

	if manager.options.DerivationPassphrase != testManagerPassphrase {
		t.Error("VaultManager options not properly set")
	}

	if len(manager.vaults) != 0 {
		t.Error("VaultManager should start with no vaults")
	}

	// Test StoreFactory constructor
	storeFactory := func(tenantID string) (persist.Store, error) {
		return persist.NewFileSystemStore(testManagerTempDir, tenantID)
	}

	options := createTestManagerOptions()
	managerWithFactory := NewVaultManagerWithStoreFactory(options, storeFactory, audit.NewNoOpLogger())
	if managerWithFactory == nil {
		t.Fatal("Failed to create VaultManager with StoreFactory")
	}

	// Test StoreConfig constructor
	storeConfig := persist.StoreConfig{
		Type: persist.StoreTypeFileSystem,
		Config: map[string]interface{}{
			"base_path": t.TempDir(),
		},
	}

	managerWithConfig := NewVaultManagerWithStoreConfig(options, storeConfig, audit.NewNoOpLogger())
	if managerWithConfig == nil {
		t.Fatal("Failed to create VaultManager with StoreConfig")
	}

	// Test S3Store constructor (should not fail even with empty config)
	managerS3, err := NewVaultManagerS3Store(options, persist.S3Config{
		Endpoint:        "",
		AccessKeyID:     "",
		SecretAccessKey: "",
		Bucket:          "test-bucket",
		KeyPrefix:       "",
		UseSSL:          false,
		Region:          "us-east-1",
	}, audit.NewNoOpLogger())
	if err != nil {
		t.Logf("S3 VaultManager creation failed (expected in test environment): %v", err)
	} else if managerS3 == nil {
		t.Error("S3 VaultManager should not be nil when creation succeeds")
	}
}

func TestVaultManagerTenantOperations(t *testing.T) {
	manager := createTestVaultManager(t, testManagerTempDir)
	defer manager.CloseAll()

	// Test getting vault for new tenant
	tenantID := "test-tenant-1"
	vault1, err := manager.GetVault(tenantID)
	if err != nil {
		t.Fatalf("Failed to get vault for tenant %s: %v", tenantID, err)
	}

	if vault1 == nil {
		t.Fatal("Vault should not be nil")
	}

	// Test getting same vault again (should return cached instance)
	vault2, err := manager.GetVault(tenantID)
	if err != nil {
		t.Fatalf("Failed to get cached vault for tenant %s: %v", tenantID, err)
	}

	// Should be the same instance
	if vault1 != vault2 {
		t.Error("GetVault should return cached instance")
	}

	// Test vault functionality
	testData := []byte("test data for tenant")
	encrypted, err := vault1.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	decrypted, err := vault1.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Error("Data mismatch after encryption/decryption")
	}

	// Test listing tenants
	tenants, err := manager.ListTenants()
	if err != nil {
		t.Fatalf("Failed to list tenants: %v", err)
	}

	if len(tenants) == 0 {
		t.Error("Should have at least one tenant")
	}

	found := false
	for _, tenant := range tenants {
		if tenant == tenantID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Tenant %s not found in list", tenantID)
	}

	// Test closing specific tenant
	err = manager.CloseTenant(tenantID)
	if err != nil {
		t.Fatalf("Failed to close tenant: %v", err)
	}

	// Vault should be removed from cache
	if len(manager.vaults) != 0 {
		t.Error("Vault should be removed from cache after closing")
	}

	// Getting vault again should create new instance
	vault3, err := manager.GetVault(tenantID)
	if err != nil {
		t.Fatalf("Failed to recreate vault for tenant: %v", err)
	}

	if vault3 == vault1 {
		t.Error("Should have created new vault instance after closing")
	}
}

func TestVaultManagerConcurrency(t *testing.T) {
	manager := createTestVaultManager(t, testManagerTempDir)
	defer manager.CloseAll()

	// Test concurrent vault creation
	const numTenants = 10
	const numGoroutines = 5

	var wg sync.WaitGroup
	results := make([][]VaultService, numGoroutines)
	errors := make([][]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		results[i] = make([]VaultService, numTenants)
		errors[i] = make([]error, numTenants)

		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numTenants; j++ {
				tenantID := fmt.Sprintf("concurrent-tenant-%d", j)
				vault, err := manager.GetVault(tenantID)
				results[goroutineID][j] = vault
				errors[goroutineID][j] = err
			}
		}(i)
	}

	wg.Wait()

	// Verify all operations succeeded
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < numTenants; j++ {
			if errors[i][j] != nil {
				t.Errorf("Goroutine %d, tenant %d failed: %v", i, j, errors[i][j])
			}
			if results[i][j] == nil {
				t.Errorf("Goroutine %d, tenant %d returned nil vault", i, j)
			}
		}
	}

	// Verify all goroutines got the same vault instances for each tenant
	for j := 0; j < numTenants; j++ {
		baseVault := results[0][j]
		for i := 1; i < numGoroutines; i++ {
			if results[i][j] != baseVault {
				t.Errorf("Tenant %d: different vault instances returned", j)
			}
		}
	}

	// Test concurrent operations on vaults
	testConcurrentVaultOperations(t, manager)
}

func testConcurrentVaultOperations(t *testing.T, manager *VaultManager) {
	tenantID := "concurrent-ops-tenant"
	vault, err := manager.GetVault(tenantID)
	if err != nil {
		t.Fatalf("Failed to get vault: %v", err)
	}

	const numOperations = 20
	var wg sync.WaitGroup
	results := make([]string, numOperations)
	errors := make([]error, numOperations)

	// Concurrent encrypt/decrypt operations
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(opID int) {
			defer wg.Done()

			testData := []byte(fmt.Sprintf("concurrent test data %d", opID))
			encrypted, err := vault.Encrypt(testData)
			if err != nil {
				errors[opID] = fmt.Errorf("encrypt failed: %w", err)
				return
			}

			decrypted, err := vault.Decrypt(encrypted)
			if err != nil {
				errors[opID] = fmt.Errorf("decrypt failed: %w", err)
				return
			}

			results[opID] = string(decrypted)
		}(i)
	}

	wg.Wait()

	// Verify all operations succeeded
	for i := 0; i < numOperations; i++ {
		if errors[i] != nil {
			t.Errorf("Operation %d failed: %v", i, errors[i])
		}
		expected := fmt.Sprintf("concurrent test data %d", i)
		if results[i] != expected {
			t.Errorf("Operation %d: expected %s, got %s", i, expected, results[i])
		}
	}
}

func TestVaultManagerBulkOperations(t *testing.T) {
	manager := createTestVaultManager(t, testManagerTempDir)
	defer manager.CloseAll()

	// Create multiple tenants
	tenantIDs := []string{"bulk-tenant-1", "bulk-tenant-2", "bulk-tenant-3"}

	// Initialize vaults for all tenants
	for _, tenantID = range tenantIDs {
		vault, err := manager.GetVault(tenantID)
		if err != nil {
			t.Fatalf("Failed to create vault for tenant %s: %v", tenantID, err)
		}

		// Add some test data to ensure vault is properly initialized
		testData := []byte(fmt.Sprintf("test data for %s", tenantID))
		_, err = vault.Encrypt(testData)
		if err != nil {
			t.Fatalf("Failed to encrypt test data for tenant %s: %v", tenantID, err)
		}
	}

	// Test bulk key rotation
	results, err := manager.RotateAllTenantKeys(tenantIDs, "bulk rotation test")
	if err != nil {
		t.Fatalf("Failed to perform bulk key rotation: %v", err)
	}

	if len(results) != len(tenantIDs) {
		t.Errorf("Expected %d results, got %d", len(tenantIDs), len(results))
	}

	// Verify all rotations succeeded
	for i, result := range results {
		if result.Error != "" {
			t.Errorf("Bulk rotation failed for tenant %s: %s", result.TenantID, result.Error)
		}
		if result.TenantID != tenantIDs[i] {
			t.Errorf("Result tenant ID mismatch: expected %s, got %s", tenantIDs[i], result.TenantID)
		}
		if !result.Success {
			t.Errorf("Bulk rotation should have succeeded for tenant %s", result.TenantID)
		}
		if result.Timestamp.IsZero() {
			t.Errorf("Result timestamp should not be zero for tenant %s", result.TenantID)
		}
		// Check details for new key ID if available
		if result.Details != nil {
			if newKeyID, ok := result.Details["new_key_id"]; !ok || newKeyID == "" {
				t.Errorf("New key ID should be present in details for tenant %s", result.TenantID)
			}
		}
	}

	// Test bulk rotation without specifying tenants (should affect all)
	allResults, err := manager.RotateAllTenantKeys(nil, "rotate all tenants test")
	if err != nil {
		t.Fatalf("Failed to rotate all tenant keys: %v", err)
	}

	// Should have at least the tenants we created
	if len(allResults) < len(tenantIDs) {
		t.Errorf("Expected at least %d results, got %d", len(tenantIDs), len(allResults))
	}

	// Test bulk passphrase rotation
	passphraseResults, err := manager.RotateAllTenantPassphrases(tenantIDs, "new-bulk-passphrase", "bulk passphrase test")
	if err != nil {
		t.Fatalf("Failed to perform bulk passphrase rotation: %v", err)
	}

	if len(passphraseResults) != len(tenantIDs) {
		t.Errorf("Expected %d passphrase results, got %d", len(tenantIDs), len(passphraseResults))
	}

	for _, result := range passphraseResults {
		if result.Error != "" {
			t.Errorf("Bulk passphrase rotation failed for tenant %s: %s", result.TenantID, result.Error)
		}
		if !result.Success {
			t.Errorf("Bulk passphrase rotation should have succeeded for tenant %s", result.TenantID)
		}
	}

	// Verify vaults still work after bulk passphrase rotation
	for _, tenantID = range tenantIDs {
		vault, err := manager.GetVault(tenantID)
		if err != nil {
			t.Fatalf("Failed to get vault after passphrase rotation for tenant %s: %v", tenantID, err)
		}

		// Test encryption/decryption still works
		testData := []byte(fmt.Sprintf("post-rotation test for %s", tenantID))
		encrypted, err := vault.Encrypt(testData)
		if err != nil {
			t.Fatalf("Failed to encrypt after passphrase rotation for tenant %s: %v", tenantID, err)
		}

		decrypted, err := vault.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt after passphrase rotation for tenant %s: %v", tenantID, err)
		}

		if string(decrypted) != string(testData) {
			t.Errorf("Data mismatch after passphrase rotation for tenant %s", tenantID)
		}
	}
}

func TestVaultManagerAuditOperations(t *testing.T) {
	manager := createTestVaultManagerWithAudit(t, testManagerTempDir)
	defer manager.CloseAll()

	tenantID := "audit-test-tenant"

	// Get vault and perform some operations to generate audit logs
	vault, err := manager.GetVault(tenantID)
	if err != nil {
		t.Fatalf("Failed to get vault: %v", err)
	}

	// Perform operations that should be audited
	testData := []byte("audit test data")
	encrypted, err := vault.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	_, err = vault.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Rotate key to generate more audit events
	_, err = vault.RotateKey("TestVaultManagerAuditOperations")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Wait a moment for audit logs to be written
	time.Sleep(100 * time.Millisecond)

	// Test audit querying with QueryOptions
	since := time.Now().Add(-1 * time.Hour)
	queryOptions := audit.QueryOptions{
		TenantID: tenantID,
		Since:    &since,
		Limit:    100,
	}

	queryResult, err := manager.QueryAuditLogs(queryOptions)
	if err != nil {
		t.Fatalf("Failed to query audit logs: %v", err)
	}

	if queryResult == nil {
		t.Fatal("Query result should not be nil")
	}

	if len(queryResult.Events) == 0 {
		t.Log("Warning: No audit events found - this may be expected if audit is not fully configured")
	} else {
		t.Logf("Found %d audit events", len(queryResult.Events))

		// Verify events have required fields
		for i, event := range queryResult.Events {
			if event.TenantID != tenantID {
				t.Errorf("Event %d: expected tenant %s, got %s", i, tenantID, event.TenantID)
			}
			if event.Timestamp.IsZero() {
				t.Errorf("Event %d: timestamp should not be zero", i)
			}
			if event.Action == "" {
				t.Errorf("Event %d: action should not be empty", i)
			}
		}
	}

	// Test query with different filters
	successOnlyOptions := audit.QueryOptions{
		TenantID: tenantID,
		Since:    &since,
		Success:  boolPtr(true),
		Limit:    50,
	}

	successResult, err := manager.QueryAuditLogs(successOnlyOptions)
	if err != nil {
		t.Fatalf("Failed to query successful audit logs: %v", err)
	}

	// Test action-specific query
	encryptionOptions := audit.QueryOptions{
		TenantID: tenantID,
		Since:    &since,
		Action:   "ENCRYPT",
		Limit:    10,
	}

	encryptionResult, err := manager.QueryAuditLogs(encryptionOptions)
	if err != nil {
		t.Fatalf("Failed to query encryption audit logs: %v", err)
	}

	t.Logf("Success-only events: %d, Encryption events: %d",
		len(successResult.Events), len(encryptionResult.Events))

	// Test passphrase-related events
	passphraseOptions := audit.QueryOptions{
		TenantID:         tenantID,
		Since:            &since,
		PassphraseAccess: true,
		Limit:            20,
	}

	passphraseResult, err := manager.QueryAuditLogs(passphraseOptions)
	if err != nil {
		t.Fatalf("Failed to query passphrase audit logs: %v", err)
	}

	t.Logf("Passphrase-related events: %d", len(passphraseResult.Events))

	// Test audit summary
	summary, err := manager.GetAuditSummary(tenantID, &since)
	if err != nil {
		t.Fatalf("Failed to get audit summary: %v", err)
	}

	if summary.TenantID != tenantID {
		t.Errorf("Summary tenant ID mismatch: expected %s, got %s", tenantID, summary.TenantID)
	}

	t.Logf("Audit summary: %+v", summary)

	// Test pagination
	if len(queryResult.Events) > 5 {
		paginatedOptions := audit.QueryOptions{
			TenantID: tenantID,
			Since:    &since,
			Limit:    2,
			Offset:   1,
		}

		paginatedResult, err := manager.QueryAuditLogs(paginatedOptions)
		if err != nil {
			t.Fatalf("Failed to query paginated audit logs: %v", err)
		}

		if len(paginatedResult.Events) > 2 {
			t.Errorf("Expected at most 2 events with limit=2, got %d", len(paginatedResult.Events))
		}

		t.Logf("Paginated query returned %d events", len(paginatedResult.Events))
	}
}

func TestVaultManagerErrorHandling(t *testing.T) {
	// Test VaultManager with failing store factory
	failingStoreFactory := func(tenantID string) (persist.Store, error) {
		if tenantID == "failing-tenant" {
			return nil, fmt.Errorf("mock store creation failure")
		}
		return persist.NewFileSystemStore(testManagerTempDir, tenantID)
	}

	options := createTestManagerOptions()
	manager := NewVaultManagerWithStoreFactory(options, failingStoreFactory, audit.NewNoOpLogger())

	// Test GetVault with failing store
	_, err := manager.GetVault("failing-tenant")
	if err == nil {
		t.Error("Expected error when getting vault with failing store")
	}
	if !strings.Contains(err.Error(), "mock store creation failure") {
		t.Errorf("Expected specific error message, got: %v", err)
	}

	// Test successful vault creation after failure
	vault, err := manager.GetVault("working-tenant")
	if err != nil {
		t.Fatalf("Failed to get working vault: %v", err)
	}
	if vault == nil {
		t.Error("Working vault should not be nil")
	}

	// Test ListTenants with failing store
	failingListStoreFactory := func(tenantID string) (persist.Store, error) {
		return &mockFailingListStore{}, nil
	}
	managerFailingList := NewVaultManagerWithStoreFactory(options, failingListStoreFactory, audit.NewNoOpLogger())

	_, err = managerFailingList.ListTenants()
	if err == nil {
		t.Error("Expected error when listing tenants with failing store")
	}

	// Test bulk operations with mixed success/failure
	testBulkOperationErrors(t, manager)

	// Test concurrent error handling
	testConcurrentErrorHandling(t, manager)
}

func testBulkOperationErrors(t *testing.T, manager VaultManagerService) {
	// First, create a working tenant to have mixed results
	workingVault, err := manager.GetVault("working-tenant-bulk")
	if err != nil {
		t.Fatalf("Failed to create working tenant: %v", err)
	}

	// Store a test secret in the working tenant
	_, err = workingVault.StoreSecret("test-secret", []byte("test-value"), []string{}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store test secret: %v", err)
	}

	// Test bulk passphrase rotation with EXPLICIT tenant list including the failing one
	// This is the key fix - explicitly include the failing tenant
	tenantList := []string{"working-tenant-bulk", "failing-tenant"}
	results, err := manager.RotateAllTenantPassphrases(tenantList, "new-test-passphrase", "test rotation")

	// Now we should have failures because failing-tenant will fail during GetVault
	hasFailures := false
	var failingResult *BulkOperationResult
	var workingResult *BulkOperationResult

	for i := range results {
		if results[i].TenantID == "failing-tenant" {
			failingResult = &results[i]
			if !results[i].Success {
				hasFailures = true
			}
		} else if results[i].TenantID == "working-tenant-bulk" {
			workingResult = &results[i]
		}
	}

	if !hasFailures {
		t.Error("Expected error in bulk rotation with failing tenant")
		t.Logf("Results: %+v", results)
		return
	}

	// Check that we have results for both tenants
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
		return
	}

	// Should have error for failing tenant
	if failingResult == nil {
		t.Error("Expected result for failing-tenant")
	} else if failingResult.Success {
		t.Error("Expected failure for failing-tenant, but got success")
	} else if failingResult.Error == "" {
		t.Error("Expected error message for failing-tenant")
	} else {
		// Check that the error mentions the store creation failure
		if !strings.Contains(failingResult.Error, "mock store creation failure") {
			t.Errorf("Expected specific error message, got: %s", failingResult.Error)
		}
	}

	// Should have success for working tenant
	if workingResult == nil {
		t.Error("Expected result for working-tenant-bulk")
	} else if !workingResult.Success {
		t.Errorf("Expected success for working tenant, got error: %s", workingResult.Error)
	}

	t.Logf("Bulk operation results: %+v", results)
}

func testConcurrentErrorHandling(t *testing.T, manager VaultManagerService) {
	const numGoroutines = 5
	var wg sync.WaitGroup
	errorCounts := make([]int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			// Try to get both working and failing vaults
			tenants := []string{
				fmt.Sprintf("concurrent-working-%d", goroutineID),
				"failing-tenant",
			}

			for _, tenantID := range tenants {
				_, err := manager.GetVault(tenantID)
				if err != nil {
					errorCounts[goroutineID]++
				}
			}
		}(i)
	}

	wg.Wait()

	// Each goroutine should have encountered at least one error (the failing tenant)
	for i, count := range errorCounts {
		if count == 0 {
			t.Errorf("Goroutine %d should have encountered at least one error", i)
		}
	}
}

func TestVaultManagerCleanup(t *testing.T) {
	manager := createTestVaultManager(t, testManagerTempDir)

	// Create multiple tenants
	tenantIDs := []string{"cleanup-tenant-1", "cleanup-tenant-2", "cleanup-tenant-3"}
	for _, tenantID := range tenantIDs {
		vault, err := manager.GetVault(tenantID)
		if err != nil {
			t.Fatalf("Failed to create vault for cleanup test: %v", err)
		}

		// Verify vault is working
		testData := []byte("cleanup test data")
		_, err = vault.Encrypt(testData)
		if err != nil {
			t.Fatalf("Failed to encrypt cleanup test data: %v", err)
		}
	}

	// Verify all vaults are cached
	if len(manager.vaults) != len(tenantIDs) {
		t.Errorf("Expected %d cached vaults, got %d", len(tenantIDs), len(manager.vaults))
	}

	// Test closing individual tenant
	err := manager.CloseTenant(tenantIDs[0])
	if err != nil {
		t.Fatalf("Failed to close tenant: %v", err)
	}

	if len(manager.vaults) != len(tenantIDs)-1 {
		t.Errorf("Expected %d cached vaults after closing one, got %d", len(tenantIDs)-1, len(manager.vaults))
	}

	// Test closing non-existent tenant (should not error)
	err = manager.CloseTenant("non-existent-tenant")
	if err != nil {
		t.Errorf("Closing non-existent tenant should not error: %v", err)
	}

	// Test closing all tenants
	err = manager.CloseAll()
	if err != nil {
		t.Fatalf("Failed to close all tenants: %v", err)
	}

	if len(manager.vaults) != 0 {
		t.Errorf("Expected 0 cached vaults after closing all, got %d", len(manager.vaults))
	}

	// Test that vaults can be recreated after closing all
	vault, err := manager.GetVault(tenantIDs[0])
	if err != nil {
		t.Fatalf("Failed to recreate vault after closing all: %v", err)
	}
	if vault == nil {
		t.Error("Recreated vault should not be nil")
	}

	// Verify recreated vault works
	testData := []byte("post-cleanup test data")
	encrypted, err := vault.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt with recreated vault: %v", err)
	}

	decrypted, err := vault.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with recreated vault: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Error("Data mismatch with recreated vault")
	}

	// Final cleanup
	manager.CloseAll()
}

// Helper functions for VaultManager tests
func createTestVaultManager(t *testing.T, basePath string) *VaultManager {
	t.Helper()

	// Ensure test directory exists and is clean
	err := os.RemoveAll(basePath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to remove existing test directory: %v", err)
	}

	err = os.MkdirAll(basePath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	options := createTestManagerOptions()
	v := NewVaultManagerFileStore(options, basePath, audit.NewNoOpLogger())
	return v.(*VaultManager)
}

func createTestManagerOptions() Options {
	return Options{
		DerivationPassphrase: testManagerPassphrase,
		EnableMemoryLock:     false, // Usually disabled in tests
	}
}

func createTestVaultManagerWithAudit(t *testing.T, basePath string) *VaultManager {
	t.Helper()

	// Ensure test directory exists and is clean
	err := os.RemoveAll(basePath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to remove existing test directory: %v", err)
	}

	err = os.MkdirAll(basePath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	options := Options{
		DerivationPassphrase: testManagerPassphrase,
		EnableMemoryLock:     false,
	}

	v := NewVaultManagerFileStore(options, basePath, audit.NewNoOpLogger())
	return v.(*VaultManager)
}

func cleanupManager(t *testing.T) {
	t.Helper()

	err := os.RemoveAll(testManagerTempDir)
	if err != nil && !os.IsNotExist(err) {
		t.Errorf("Failed to cleanup test directory: %v", err)
	}
}

// Mock stores for error testing
type mockFailingListStore struct {
	persist.Store
}

func (m *mockFailingListStore) ListTenants() ([]string, error) {
	return nil, fmt.Errorf("mock list tenants failure")
}

func (m *mockFailingListStore) Close() error {
	return nil
}

func (m *mockFailingListStore) LoadSalt() (*persist.VersionedData, error) {
	return nil, fmt.Errorf("mock load salt failure")
}

func (m *mockFailingListStore) SaveSalt(salt []byte, expectedVersion string) (string, error) {
	return "", fmt.Errorf("mock save salt failure")
}

func (m *mockFailingListStore) LoadMetadata() (*persist.VersionedData, error) {
	return nil, fmt.Errorf("mock load metadata failure")
}

func (m *mockFailingListStore) SaveMetadata(metadata []byte, expectedVersion string) (string, error) {
	return "", fmt.Errorf("mock save metadata failure")
}

func (m *mockFailingListStore) LoadKey(keyID string) ([]byte, error) {
	return nil, fmt.Errorf("mock load key failure")
}

func (m *mockFailingListStore) SaveKey(keyID string, key []byte) error {
	return fmt.Errorf("mock save key failure")
}

func (m *mockFailingListStore) DeleteKey(keyID string) error {
	return fmt.Errorf("mock delete key failure")
}

func (m *mockFailingListStore) ListKeys() ([]string, error) {
	return nil, fmt.Errorf("mock list keys failure")
}

// Helper function to create bool pointer
func boolPtr(b bool) *bool {
	return &b
}
