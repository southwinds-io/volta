package volta

import (
	"crypto/rand"
	"encoding/json"
	"github.com/awnumar/memguard"
	"os"
	"path/filepath"
	"southwinds.dev/volta/audit"
	"southwinds.dev/volta/internal/misc"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	tenantID      = "default"
	testStoreType = persist.StoreTypeFileSystem
	tempDir       = "data"
	passPhrase    = "this-is-a-secure-passphrase-for-testing"
)

func TestVaultAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"VaultCreation", TestVaultCreation},
		{"MemoryProtection", TestMemoryProtection},
	}

	// Ensure clean test environment
	defer cleanup(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestVaultCreation(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)

	// Verify vault was properly initialized
	if vault.store == nil {
		t.Error("Store was not initialized")
	}

	if len(vault.keyEnclaves) == 0 {
		t.Error("No key enclaves were created")
	}

	if vault.currentKeyID == "" {
		t.Error("Current key ID was not set")
	}

	// Verify metadata exists
	if len(vault.keyMetadata) == 0 {
		t.Error("No key metadata was created")
	}
}

func createStore(storeType persist.StoreType, basePath, tenantID string) persist.Store {
	switch storeType {
	case persist.StoreTypeS3:
		store, err := persist.NewS3Store(persist.S3Config{
			Endpoint:        "",
			AccessKeyID:     "",
			SecretAccessKey: "",
			UseSSL:          false,
			Bucket:          basePath,
			KeyPrefix:       "",
			Region:          "",
		}, tenantID)
		if err != nil {
			panic(err)
		}
		return store
	case persist.StoreTypeFileSystem:
		store, err := persist.NewFileSystemStore(basePath, tenantID)
		if err != nil {
			panic(err)
		}
		return store
	default:
		panic("invalid store type")
	}
}

func TestMemoryProtection(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	// Check memory protection level
	protectionInfo := vault.SecureMemoryProtection()
	t.Logf("Memory protection level: %s", protectionInfo)

	// Memory protection level should not be "None" if we requested it
	// (though it might be "Partial" if full protection isn't available)
	if protectionInfo == "None - sensitive data may be swapped to disk" && options.EnableMemoryLock {
		t.Log("Warning: Memory lock requested but no protection achieved")
	}
}

// Helper functions

func createTestOptions() Options {
	return Options{
		DerivationPassphrase: passPhrase,
		EnableMemoryLock:     false,
	}
}

func cleanup(t *testing.T) {
	// Clean up the hardcoded tempDir if it exists
	if _, err := os.Stat(tempDir); err == nil {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: failed to clean up %s: %v", tempDir, err)
		}
	}

	// Clean up any test temp directories that might be lingering
	tempBase := os.TempDir()
	entries, err := os.ReadDir(tempBase)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() &&
				(strings.HasPrefix(entry.Name(), "vault_test_") ||
					strings.HasPrefix(entry.Name(), "test_vault_")) {
				fullPath := filepath.Join(tempBase, entry.Name())
				if err := os.RemoveAll(fullPath); err != nil {
					t.Logf("Warning: failed to clean up temp dir %s: %v", fullPath, err)
				}
			}
		}
	}
}

// Helper function to create a test vault instance for internal testing
func createTestVault(t *testing.T, options Options, basePath string) *Vault {
	// Clear temp directory before creating vault
	os.RemoveAll(basePath)
	err := os.MkdirAll(basePath, 0755)
	if err != nil {
		t.Fatalf("Failed to recreate temp directory: %v", err)
	}

	cryptoManager := NewVaultManagerFileStore(options, basePath, audit.NewNoOpLogger())

	vault, err := cryptoManager.GetVault("default")
	if err != nil {
		t.Fatalf("%v", err)
	}

	var _ VaultService = &Vault{}
	return vault.(*Vault)
}

func createEmptyTestVault(t *testing.T) *Vault {
	tempDir, err := os.MkdirTemp("", "vault_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	// Create storage
	store, _ := persist.NewFileSystemStore(tempDir, "default")

	// Generate a derivation key
	derivationKey := make([]byte, 32)
	_, err = rand.Read(derivationKey)
	if err != nil {
		t.Fatalf("Failed to generate derivation key: %v", err)
	}

	// Create enclave for the derivation key - THIS IS WHAT'S MISSING
	derivationKeyEnclave := memguard.NewEnclave(derivationKey)

	// Create vault with proper initialization
	vault := &Vault{
		store:                store,
		derivationKeyEnclave: derivationKeyEnclave,
		keyMetadata:          make(map[string]KeyMetadata),
		currentKeyID:         "",
		audit:                createLogger(),
	}

	// Create initial key and save metadata
	err = vault.createNewKey()
	if err != nil {
		t.Fatalf("Failed to create initial key: %v", err)
	}

	return vault
}

// Helper function to create a test vault for restore (doesn't clear directory)
func createTestVaultForRestore(t *testing.T, passphrase string) *Vault {
	// Create fresh temp directory for restore
	restoreDir, err := os.MkdirTemp("", "vault_restore_test_*")
	if err != nil {
		t.Fatalf("Failed to create restore temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(restoreDir) })

	// Create options with fresh store
	options := createTestOptions()
	options.DerivationPassphrase = passphrase
	store := createStore(testStoreType, restoreDir, tenantID) // Use the restore directory

	// Create vault but DON'T initialize it
	vault, err := NewWithStore(options, store, nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault for restore: %v", err)
	}

	// ✅ Return uninitialized vault - restore will handle keys
	return vault.(*Vault)
}

func createUninitializedVault(t *testing.T) *Vault {
	tempDir, err := os.MkdirTemp("", "vault_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	store, _ := persist.NewFileSystemStore(tempDir, tenantID)

	// Create vault WITHOUT calling any initialization methods
	logger := createLogger()
	vault := &Vault{
		store:                store,
		derivationKeyEnclave: nil,
		keyMetadata:          nil,
		currentKeyID:         "",
		audit:                logger,
	}

	return vault
}

func createLogger() audit.Logger {
	logger, err := audit.NewLogger(&audit.Config{
		Enabled:  true,
		LogLevel: "error",
		Type:     audit.FileAuditType,
	})

	if err != nil {
		// Return a no-op logger instead of nil
		return &audit.NoOpLogger{}
	}

	// Double-check that logger is not nil
	if logger == nil {
		return &audit.NoOpLogger{}
	}

	return logger
}

func createTestVaultWithDerivation(t *testing.T) *Vault {
	// Ensure tempDir exists or use system temp
	var baseDir string
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		os.MkdirAll(tempDir, misc.FilePermissions)
	}

	workDir, err := os.MkdirTemp(baseDir, "vault_test_derivation_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create storage
	store, _ := persist.NewFileSystemStore(workDir, tenantID)

	// Create derivation salt and protect it
	derivationSalt := make([]byte, 32)
	for i := range derivationSalt {
		derivationSalt[i] = byte(i + 100)
	}
	derivationSaltEnclave := memguard.NewEnclave(derivationSalt)
	memguard.WipeBytes(derivationSalt) // Clear original

	// Use deterministic derivation key for consistent testing
	derivationKey := make([]byte, 32)
	for i := range derivationKey {
		derivationKey[i] = byte(i)
	}
	derivationKeyEnclave := memguard.NewEnclave(derivationKey)
	memguard.WipeBytes(derivationKey) // Clear original

	// Create a test encryption key
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i + 50)
	}
	testKeyEnclave := memguard.NewEnclave(testKey)
	memguard.WipeBytes(testKey) // Clear original

	// Create vault with proper initialization
	vault := &Vault{
		store: store,
		keyEnclaves: map[string]*memguard.Enclave{
			"test-current-key": testKeyEnclave,
		},
		keyMetadata: map[string]KeyMetadata{
			"test-current-key": {
				KeyID:     "test-current-key",
				Status:    KeyStatusActive,
				CreatedAt: time.Now(),
			},
		},
		mu:                    sync.RWMutex{},
		currentKeyID:          "test-current-key",
		derivationSaltEnclave: derivationSaltEnclave,
		derivationKeyEnclave:  derivationKeyEnclave,
		audit:                 createLogger(),
		secretsVersion:        "1.0",
		secretsTimestamp:      time.Now(),
	}

	// **CRITICAL: Initialize the secrets container**
	// Create an empty secrets container
	initialContainer := &SecretsContainer{
		Version:   "1.0",
		Timestamp: time.Now(),
		Secrets:   make(map[string]*SecretEntry),
	}

	// Serialize the container to JSON
	containerJSON, err := json.Marshal(initialContainer)
	if err != nil {
		// Clean up on error
		vault.Close()
		t.Fatalf("Failed to marshal initial secrets container: %v", err)
	}
	defer memguard.WipeBytes(containerJSON) // Clean up JSON data

	// Encrypt the container using the vault's encryption method
	encryptedContainer, err := vault.encryptWithCurrentKey(containerJSON)
	if err != nil {
		// Clean up on error
		vault.Close()
		t.Fatalf("Failed to encrypt initial secrets container: %v", err)
	}

	// Store the encrypted container in a memguard enclave
	vault.secretsContainer = memguard.NewEnclave(encryptedContainer)
	memguard.WipeBytes(encryptedContainer) // Clear original

	return vault
}

func createTestVaultWithKeys(t *testing.T) *Vault {
	vault := createEmptyTestVault(t)

	// Add a dummy key enclave to simulate initialized vault
	dummyEnclave := memguard.NewEnclave(make([]byte, 32))
	vault.keyEnclaves["dummy"] = dummyEnclave

	return vault
}
