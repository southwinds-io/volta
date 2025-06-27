package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"

	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
)

func main() {
	fmt.Println("### Example: Show Key Encryption Key (KEK) rotation while maintaining access to existing encrypted data without requiring data re-encryption. ###")

	// 1. Configure VaultManager Options.
	// The derivation passphrase is a master secret for the entire VaultManager.
	// It must be stored securely and not be hardcoded in production.
	options := volta.Options{
		// In production, load this from a secure source
		// Do not protect the passphrase with another secret, grant access to the passphrase based on a trusted identity
		// e.g. a cloud platform (like AWS, GCP, or Azure) assigns a unique, cryptographic identity to the running application (e.g., an AWS IAM Role for an EC2 instance or ECS container).
		// This identity is managed entirely by the platform and used to access the platform Vault where Volta's passphrase is stored.
		DerivationPassphrase: "Z5vmvP3^6UE*YwvjPZ5qZRJ7FoArSN57MRCQ@9fV2V7y&X3efYXht*LV#vX8",
		// Attempts to lock sensitive data (keys, secrets) in RAM.
		EnableMemoryLock: true,
	}

	// 2. Initialize the audit logger.
	// This logger records all significant vault management and cryptographic events.
	auditLogger, err := createAuditLogger()
	if err != nil {
		log.Fatalf("Failed to create audit logger: %v", err)
	}

	// 3. Define the base path for vault storage.
	// In a real application, this must be a persistent and secure directory.
	basePath, err := os.MkdirTemp("", "volta_filestore_example_")
	if err != nil {
		log.Fatalf("Failed to create temporary directory for base path: %v", err)
	}
	// The temporary directory is cleaned up for this example only.
	defer func(path string) {
		if err = os.RemoveAll(path); err != nil {
			fmt.Printf("Failed to remove temporary directory: %v", err)
		}
	}(basePath)
	fmt.Printf("Using temporary vault storage at: %s\n", basePath)

	// 4. Create the VaultManager instance.
	// This manager will orchestrate multiple tenant vaults, each stored as an
	// encrypted file within the specified base path.
	vaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)
	fmt.Println("VaultManager initialized.")

	// --- KEK Rotation and Data Access Operations ---
	fmt.Println("\n--- KEK Rotation and Data Access Operations ---")
	tenantID := "pii-processor-service"

	// Step 1: Get vault instance and encrypt PII data
	fmt.Println("\n🔐 Step 1: Initial PII Encryption")
	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("Failed to get vault for tenant %s: %v", tenantID, err)
	}
	fmt.Printf("✓ Obtained vault for tenant: %s\n", tenantID)

	// Define sample PII payload to be protected
	piiData := []byte(`{"name":"Jane Doe","ssn":"123-45-6789","address":"456 Privacy Lane","phone":"555-0123"}`)
	fmt.Printf("Original PII data: %s\n", string(piiData))

	// Encrypt the PII data with current KEK
	ciphertext, err := vault.Encrypt(piiData)
	if err != nil {
		log.Fatalf("Failed to encrypt PII: %v", err)
	}
	fmt.Printf("✓ Encrypted ciphertext: %s\n", ciphertext)

	// Step 2: Verify initial decryption works
	fmt.Println("\n🔓 Step 2: Verify Initial Decryption")
	decryptedData, err := vault.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt with original KEK: %v", err)
	}
	if !bytes.Equal(piiData, decryptedData) {
		log.Fatal("Initial data integrity check failed")
	}
	fmt.Printf("✓ Successfully decrypted with original KEK: %s\n", string(decryptedData))

	// Step 3: Rotate the Key Encryption Key (KEK)
	fmt.Println("\n🔄 Step 3: Rotating Key Encryption Key (KEK)")
	rotationStart := time.Now()

	newPassphrase := "Z9vmvP5^1UE*YwvjPZ5qZRJ7FoArSN57MRCQ@9fV1V6y&X7efYXht*LV#vX4"
	rotationReason := "Scheduled KEK rotation - demonstrating seamless data access without re-encryption"

	if err = vault.RotateKeyEncryptionKey(newPassphrase, rotationReason); err != nil {
		log.Fatalf("Failed to rotate Key Encryption Key: %v", err)
	}

	rotationDuration := time.Since(rotationStart)
	fmt.Printf("✓ KEK rotation completed successfully\n")
	fmt.Printf("✓ Rotation duration: %d milliseconds\n", rotationDuration.Milliseconds())
	fmt.Printf("✓ Rotation reason: %s\n", rotationReason)

	// Step 4: Retrieve and destroy old KEK metadata (commented out for safety)
	fmt.Println("\n🗑️  Step 4: Key Cleanup (Simulated)")
	fmt.Println("Note: In production, old KEK would be destroyed after grace period")

	// Uncomment below for actual key destruction in production scenarios
	/*
	   keys, err := vault.ListKeyMetadata()
	   if err != nil {
	       log.Fatalf("Failed to list key metadata: %v", err)
	   }

	   // Destroy all non-active keys
	   destroyedCount := 0
	   for _, key := range keys {
	       if !key.Active {
	           if err = vault.DestroyKey(key.KeyID); err != nil {
	               log.Fatalf("Failed to destroy key ID=%s: %v", key.KeyID, err)
	           }
	           destroyedCount++
	           fmt.Printf("✓ Destroyed old key: %s\n", key.KeyID)
	       }
	   }
	   fmt.Printf("✓ Destroyed %d old key(s)\n", destroyedCount)
	*/

	// Step 5: Verify decryption works with new KEK (without re-encryption)
	fmt.Println("\n🔓 Step 5: Verify Decryption with New KEK")
	fmt.Println("Attempting to decrypt original ciphertext with new KEK...")

	finalDecryptedData, err := vault.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext with new KEK: %v", err)
	}
	fmt.Printf("✓ Successfully decrypted with new KEK: %s\n", string(finalDecryptedData))

	// Step 6: Final data integrity verification
	fmt.Println("\n✅ Step 6: Final Data Integrity Verification")
	if !bytes.Equal(piiData, finalDecryptedData) {
		log.Fatal("❌ Final data integrity check failed: decrypted data does not match original data")
	}
	fmt.Println("✓ Verification successful: Decrypted data matches original PII")
	fmt.Println("✓ KEK rotation completed without requiring data re-encryption")

	// Clean up and close vault
	if err = vault.Close(); err != nil {
		log.Printf("WARNING: error closing vault for tenant %s: %v\n", tenantID, err)
	} else {
		fmt.Printf("✓ Vault for tenant %s closed successfully\n", tenantID)
	}

	fmt.Println("\n### Example Completed Successfully ###")
	fmt.Println("Summary:")
	fmt.Println("1. ✓ Encrypted PII data with original KEK")
	fmt.Println("2. ✓ Verified initial decryption works")
	fmt.Println("3. ✓ Successfully rotated Key Encryption Key (KEK)")
	fmt.Println("4. ✓ Simulated cleanup of old KEK")
	fmt.Println("5. ✓ Decrypted original ciphertext with new KEK")
	fmt.Println("6. ✓ Verified data integrity throughout KEK rotation")
	fmt.Printf("7. ✓ Total rotation time: %d milliseconds\n", rotationDuration.Milliseconds())

	fmt.Println("\n🎯 Key Achievement: KEK rotation without data re-encryption!")
	fmt.Println("   This demonstrates envelope encryption where DEKs are re-encrypted")
	fmt.Println("   with the new KEK, but the original data ciphertext remains unchanged.")
}

// createAuditLogger initializes a logger for recording audit events.
func createAuditLogger() (audit.Logger, error) {
	// For this example, logs are written to a local file.
	// In production, consider a more robust logging setup (e.g., structured logs to stdout for collection).
	auditFilePath := ".volta_audit.log"

	fmt.Printf("Initializing file-based audit logger to: %s\n", auditFilePath)
	return audit.NewLogger(&audit.Config{
		Enabled: true,
		Type:    audit.FileAuditType, // A constant representing the file logger type.
		Options: map[string]interface{}{
			"file_path": auditFilePath,
		},
	})
}
