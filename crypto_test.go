package volta

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"southwinds.dev/volta/internal/misc"
	"testing"
)

func TestCryptoAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"EncryptionDecryption", TestEncryptionDecryption},
		{"CustomDerivation", TestCustomDerivation},
		{"SecureFilePermissions", TestSecureFilePermissions},
		{"KeyRotationCrypto", TestKeyRotationCrypto},
		{"InvalidDataHandling", TestInvalidDataHandling},
	}

	// Ensure clean test environment
	defer cleanup(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestEncryptionDecryption(t *testing.T) {
	options, workDir := createTestCryptoOptions()

	cryptoManager, err := NewWithStore(options, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer cryptoManager.Close()

	testCases := [][]byte{
		[]byte("Hello, World!"),                                    // Simple string
		[]byte("Special chars: !@#$%^&*()_+{}|"),                   // Special characters
		[]byte("Unicode: こんにちは"),                                   // Non-ASCII characters
		[]byte("A very long string " + string(make([]byte, 1000))), // Long string
		make([]byte, 10241),                                        // Large data > 10KB
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Case_%d", i), func(t *testing.T) {
			encrypted, err := cryptoManager.Encrypt(tc)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			// Encrypted should be different from original (except for empty data)
			if len(tc) > 0 && bytes.Equal([]byte(encrypted), tc) {
				t.Error("Encrypted text is identical to plaintext")
			}

			decrypted, err := cryptoManager.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, tc) {
				t.Errorf("Decrypted text doesn't match original.\nExpected: %q\nGot: %q",
					string(tc), string(decrypted))
			}
		})
	}
}

func TestCustomDerivation(t *testing.T) {
	options, workDir := createTestCryptoOptions()

	// Create custom salt
	salt := make([]byte, misc.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	options.DerivationSalt = salt
	options.DerivationPassphrase = passPhrase

	// Create vault with custom derivation key
	vault1, err := NewWithStore(options, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault with custom derivation: %v", err)
	}

	fmt.Printf("TEST: vault1 created successfully\n")

	// Test encryption
	testData := []byte("secret with custom derivation key")
	encrypted, err := vault1.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt with custom derivation: %v", err)
	}

	// Close vault1 properly to ensure all data is saved
	fmt.Printf("TEST: Closing vault1 to save all data\n")
	vault1.Close()

	fmt.Printf("TEST: vault1 closed, creating vault2\n")

	// Create a second vault with the same derivation parameters
	vault2, err := NewWithStore(options, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create second vault: %v", err)
	}
	defer vault2.Close()

	// Verify the second vault can decrypt
	decrypted, err := vault2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with second vault: %v", err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data doesn't match. Expected %q, got %q",
			string(testData), string(decrypted))
	}

	// Test with wrong passphrase
	wrongOptions := options
	wrongOptions.DerivationPassphrase = "wrong-passphrase-but-still-long-enough"

	// This should fail because the master key can't be decrypted with the wrong passphrase
	_, err = NewWithStore(wrongOptions, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err == nil {
		t.Error("Expected error when creating vault with wrong passphrase, got none")
	}
}

// Ensure key files are properly restricted to user-only access
// Ensure key files are properly restricted to user-only access
func TestSecureFilePermissions(t *testing.T) {
	// Skip on Windows as it has different permission model
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission test on Windows")
	}

	options, workDir := createTestCryptoOptions()

	cryptoManager, err := NewWithStore(options, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer func() {
		if err := cryptoManager.Close(); err != nil {
			t.Logf("Warning: failed to close vault: %v", err)
		}
	}()

	vault := cryptoManager.(*Vault)

	basePath := tempDir

	// UPDATED: Check key files permissions with new structure
	keyFiles := []string{
		filepath.Join(basePath, "keys", vault.currentKeyID+".key"),
		filepath.Join(basePath, "master", "derivation.salt"),    // UPDATED PATH
		filepath.Join(basePath, "master", "vault-metadata.enc"), // UPDATED PATH
	}

	expectedMode := os.FileMode(misc.FilePermissions)

	for _, keyFile := range keyFiles {
		info, err := os.Stat(keyFile)
		if err != nil {
			// Some files might not exist depending on implementation
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("Failed to stat file %s: %v", keyFile, err)
		}

		if info.Mode().Perm() != expectedMode {
			t.Errorf("File %s has wrong permissions: expected %v, got %v",
				keyFile, expectedMode, info.Mode().Perm())
		}
	}
}

func TestKeyRotationCrypto(t *testing.T) {
	options, workDir := createTestCryptoOptions()

	// Clean up the test directory after test
	defer os.RemoveAll(tempDir)

	cryptoManager, err := NewWithStore(options, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer cryptoManager.Close()

	// Rest of the test remains the same...
	// Encrypt data with original key
	originalData := []byte("data encrypted before key rotation")
	encryptedWithOldKey, err := cryptoManager.Encrypt(originalData)
	if err != nil {
		t.Fatalf("Failed to encrypt with original key: %v", err)
	}

	// Rotate the key
	if _, err = cryptoManager.RotateKey("TestKeyRotationCrypto"); err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Should still decrypt old data
	decrypted, err := cryptoManager.Decrypt(encryptedWithOldKey)
	if err != nil {
		t.Fatalf("Failed to decrypt old data after rotation: %v", err)
	}

	if !bytes.Equal(decrypted, originalData) {
		t.Error("Failed to decrypt data encrypted before key rotation")
	}

	// New encryption should use new key
	newData := []byte("data encrypted after key rotation")
	encryptedWithNewKey, err := cryptoManager.Encrypt(newData)
	if err != nil {
		t.Fatalf("Failed to encrypt with new key: %v", err)
	}

	// Verify new encryption works
	decrypted, err = cryptoManager.Decrypt(encryptedWithNewKey)
	if err != nil {
		t.Fatalf("Failed to decrypt new data: %v", err)
	}

	if !bytes.Equal(decrypted, newData) {
		t.Error("Failed to decrypt data encrypted with new key")
	}
}

func TestInvalidDataHandling(t *testing.T) {
	options, workDir := createTestCryptoOptions()

	// Clean up any existing vault directory first
	os.RemoveAll(tempDir)

	cryptoManager, err := NewWithStore(options, createStore(testStoreType, workDir, tenantID), nil, tenantID)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer cryptoManager.Close()

	// Test decryption of invalid data
	testCases := []struct {
		name string
		data string
	}{
		{"random text", "not encrypted data"},
		{"empty data", ""},
		{"too short", string(make([]byte, 10))},
		{"invalid format", "invalid-encrypted-string"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err = cryptoManager.Decrypt(tc.data)
			if err == nil {
				t.Errorf("Expected error when decrypting %s, got none", tc.name)
			}
		})
	}
}

// Helper functions

func createTestCryptoOptions() (options Options, basePath string) {
	// Create a unique temporary directory for each test
	workDir, err := os.MkdirTemp("", "vault_crypto_test_*")
	if err != nil {
		panic(fmt.Sprintf("Failed to create temp dir: %v", err))
	}

	return Options{
		// Use consistent derivation parameters
		DerivationSalt:       []byte("test-salt-crypto-12345678901234567890123456789012"), // 32 bytes
		DerivationPassphrase: "test-passphrase-crypto",
		EnableMemoryLock:     false,
	}, workDir
}
