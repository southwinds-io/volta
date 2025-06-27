package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
)

const (
	// IMPORTANT: ensure the passphrase remains the same for the creation and restoration of the backup and the creation of a vault that will
	// be backed up and restored
	passphrase = "Z5vmvP3^6UE*YwvjPZ5qZRJ7FoArSN57MRCQ@9fV2V7y&X3efYXht*LV#vX8"
)

func main() {
	fmt.Println("### Example: Vault Backup and Restore Operations with Data Integrity Verification ###")
	fmt.Printf("🎯 Goal: Demonstrate complete backup/restore cycle with encrypted PII and secrets\n\n")

	// 1. Configure VaultManager Options.
	options := volta.Options{
		DerivationPassphrase: passphrase,
		EnableMemoryLock:     true,
	}
	fmt.Println("✅ VaultManager options configured")

	// 2. Initialize the audit logger.
	auditFilePath, _ := os.MkdirTemp("", "audit-log-")
	auditFile := filepath.Join(auditFilePath, "audit.log")
	auditLogger, err := createAuditLogger(auditFile)
	if err != nil {
		log.Fatalf("❌ Failed to create audit logger: %v", err)
	}
	fmt.Println("✅ Audit logger initialized")

	defer func(path string) {
		fmt.Printf("✅ Audit logger removed: %s\n", path)
		if err = os.RemoveAll(path); err != nil {
			fmt.Printf("Failed to remove %q: %v\n", path, err)
		}
	}(auditFilePath)

	// 3. Create directories for backup/restore
	basePath, _ := os.MkdirTemp("", "backup-test-vault-")
	backupFileName := "vault_backup.vault"
	backupDestination, _ := os.MkdirTemp("", "backup-temp-test-")

	// Clean the directory if it already exists
	if _, err = os.Stat(basePath); err == nil {
		_ = os.RemoveAll(basePath)
	}

	defer func() {
		cleanupPaths := []string{basePath, backupDestination}
		for _, path := range cleanupPaths {
			if err = os.RemoveAll(path); err != nil {
				fmt.Printf("⚠️ Failed to remove directory %s: %v\n", path, err)
			} else {
				fmt.Printf("✅ Cleaned up directory: %s\n", path)
			}
		}
	}()

	fmt.Printf("✅ Using temporary vault storage at: %s\n", basePath)

	// 4. Create the VaultManager instance.
	vaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)
	fmt.Println("✅ VaultManager initialized successfully")

	// --- Initial Data Setup and Population ---
	fmt.Println("\n--- 🔐 Initial Data Setup and Population ---")
	tenantID := "backup-restore-service"

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("❌ Failed to get vault for tenant %s: %v", tenantID, err)
	}

	// Populate vault with test secrets
	fmt.Println("\n✅ Populating Vault with Test Data...")
	secrets := map[string][]byte{
		"secret_1": []byte("4eC39HqLyjWDarjtT1zdp7dc"),
		"secret_2": []byte("SuperSecureDBP@ssw0rd123!"),
		"secret_3": []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"),
		"secret_4": []byte("abc123def456ghi789jkl012mno345pqr678"),
	}

	for id, data := range secrets {
		_, err = vault.StoreSecret(id, data, nil, volta.ContentTypeText)
		if err != nil {
			log.Fatalf("❌ Failed to store secret %s: %v", id, err)
		}
		fmt.Printf("✅ Secret %s stored\n", id)
	}

	// Perform backup operation
	fmt.Println("\n--- 💾 Vault Backup Operation ---")
	err = vault.Backup(backupFileName, passphrase)
	if err != nil {
		log.Fatalf("❌ Failed to backup vault: %v", err)
	}
	fmt.Printf("✅ Backup completed successfully: %s\n", backupFileName)

	// 5. Copy the backup to a safe location
	err = copyBackupFile(filepath.Join(basePath, tenantID, "backups", backupFileName), backupDestination)
	if err != nil {
		log.Fatalf("❌ Failed to copy backup file to destination: %v", err)
	}
	fmt.Printf("✅ Backup file copied to safe location: %s\n", backupDestination)

	// Clean the original Vault data
	if err = vault.Close(); err != nil {
		log.Fatalf("❌ Failed to close original vault: %v", err)
	}

	if err = os.RemoveAll(basePath); err != nil {
		log.Fatalf("❌ Failed to simulate loss of vault data: %v", err)
	}
	fmt.Println("✅ Original vault data removed (simulated loss)")

	// Restore from backup
	fmt.Println("\n--- 📥 Vault Restore Operation ---")
	newVaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)
	restoreVault, err := newVaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("❌ Failed to get vault for restoration: %v", err)
	}

	backupLocation, err := filepath.Abs(filepath.Join(backupDestination, backupFileName))
	if err != nil {
		log.Fatalf("❌ Failed to get backup location: %v", err)
	}

	err = restoreVault.Restore(backupLocation, passphrase)
	if err != nil {
		log.Fatalf("❌ Failed to restore vault: %v", err)
	}
	fmt.Println("✅ Restore completed successfully")

	// Verify restored secrets
	fmt.Println("\n--- 🔍 Verifying Restored Data Integrity ---")
	for id, originalData := range secrets {
		result, err := restoreVault.GetSecret(id)
		if err != nil {
			log.Fatalf("❌ Failed to retrieve restored secret %s: %v", id, err)
		}
		if !bytes.Equal(result.Data, originalData) {
			log.Fatalf("❌ Data integrity check failed for %s", id)
		}
		fmt.Printf("✅ Restored secret %s verified\n", id)
	}

	fmt.Println("\n### 🎉 Backup and Restore Example Completed Successfully ###")
}

// copyBackupFile copies the backup file to the specified destination
func copyBackupFile(src, dstDir string) error {
	dst := filepath.Join(dstDir, filepath.Base(src))
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// createAuditLogger initializes a logger for recording audit events.
func createAuditLogger(auditFile string) (audit.Logger, error) {
	fmt.Printf("✅ Initializing file-based audit logger to: %s\n", auditFile)
	return audit.NewLogger(&audit.Config{
		Enabled: true,
		Type:    audit.FileAuditType,
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
}
