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
	fmt.Println("### Example: Show the complete lifecycle of Data Encryption Key (DEK) rotation and its impact on encrypted data accessibility. ###")

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

	// --- PII Encryption and DEK Rotation Operations ---
	fmt.Println("\n--- PII Encryption and DEK Rotation Operations ---")
	tenantID := "pii-processor-service"

	// Get a vault instance for a service that handles PII.
	// A new vault is created on the first call for a given tenant.
	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("Failed to get vault for tenant %s", tenantID)
	}
	fmt.Printf("Obtained vault for tenant: %s.\n", tenantID)

	// Define a sample PII payload to be protected.
	piiData := []byte(`{"name":"Jane Doe","ssn":"000-00-0000","address":"123 Anystreet"}`)
	fmt.Printf("Original PII data: %s\n", string(piiData))

	// Encrypt the PII. The result is a ciphertext string containing the encrypted
	// data and the ID of the key used, making it self-contained for decryption.
	ciphertext, err := vault.Encrypt(piiData)
	if err != nil {
		log.Fatalf("Failed to encrypt PII: %v", err)
	}
	fmt.Printf("Encrypted ciphertext (safe for storage): %s\n", ciphertext)

	// First, decrypt the data successfully with the original DEK
	fmt.Printf("\nStep 1: Decrypting data with original DEK (should succeed)\n")
	decryptedData, err := vault.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext with original DEK: %v", err)
	}
	fmt.Printf("Decrypted PII data (original DEK): %s\n", string(decryptedData))

	// Verify that the decrypted data matches the original plaintext.
	if !bytes.Equal(piiData, decryptedData) {
		log.Fatal("Data integrity check failed: decrypted data does not match original data.")
	}
	fmt.Println("✓ Verification successful: Original DEK can decrypt the data.")

	// Rotate the Data Encryption Key (DEK) - create a new key for encryption
	fmt.Printf("\nStep 2: Rotating the Data Encryption Key (DEK)\n")
	now := time.Now()
	if _, err = vault.RotateDataEncryptionKey("Rotating DEK for enhanced security"); err != nil {
		log.Fatalf("Failed to create new DEK: %v", err)
	}
	elapsed := time.Since(now).Milliseconds()
	fmt.Printf("New DEK created in %d milliseconds\n", elapsed)

	// Retrieve a list of keys to identify the old DEK
	keys, err := vault.ListKeyMetadata()
	if err != nil {
		log.Fatalf("Failed to list KeyMetadata")
	}

	var oldKeyID string
	fmt.Printf("\nStep 3: Identifying and destroying old DEK\n")
	for _, key := range keys {
		if !key.Active {
			oldKeyID = key.KeyID
			fmt.Printf("Found old (inactive) DEK with ID: %s\n", oldKeyID)
			if err = vault.DestroyKey(key.KeyID); err != nil {
				log.Fatalf("Failed to destroy key ID=%s: %v", key.KeyID, err)
			}
			fmt.Printf("✓ Old DEK destroyed: %s\n", oldKeyID)
			break
		}
	}

	// Attempt to decrypt the original ciphertext after destroying the old DEK
	// This should fail because the key used to encrypt the data no longer exists
	fmt.Printf("\nStep 4: Attempting to decrypt original ciphertext after DEK destruction (should fail)\n")
	_, err = vault.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("✓ Expected failure: Cannot decrypt with destroyed DEK: %v\n", err)
	} else {
		log.Fatal("UNEXPECTED: Decryption succeeded when it should have failed after DEK destruction")
	}

	// Re-encrypt the original PII data with the new DEK
	fmt.Printf("\nStep 5: Re-encrypting PII data with new DEK\n")
	newCiphertext, err := vault.Encrypt(piiData)
	if err != nil {
		log.Fatalf("Failed to re-encrypt PII with new DEK: %v", err)
	}
	fmt.Printf("New ciphertext with new DEK: %s\n", newCiphertext)

	// Decrypt the new ciphertext with the new DEK (should succeed)
	fmt.Printf("\nStep 6: Decrypting new ciphertext with new DEK (should succeed)\n")
	finalDecryptedData, err := vault.Decrypt(newCiphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext with new DEK: %v", err)
	}
	fmt.Printf("Decrypted PII data (new DEK): %s\n", string(finalDecryptedData))

	// Verify that the final decrypted data matches the original plaintext.
	if !bytes.Equal(piiData, finalDecryptedData) {
		log.Fatal("Data integrity check failed: final decrypted data does not match original data.")
	}
	fmt.Println("✓ Verification successful: New DEK can decrypt the re-encrypted data.")

	// Close the vault to release file handles and clear sensitive data from memory.
	if err = vault.Close(); err != nil {
		log.Printf("WARNING: error closing vault for tenant %s: %v\n", tenantID, err)
	} else {
		fmt.Printf("Vault for tenant %s closed.\n", tenantID)
	}

	fmt.Println("\n### Example Completed Successfully ###")
	fmt.Println("Summary:")
	fmt.Println("1. ✓ Encrypted PII data with original DEK")
	fmt.Println("2. ✓ Successfully decrypted with original DEK")
	fmt.Println("3. ✓ Rotated DEK (created new key)")
	fmt.Println("4. ✓ Destroyed old DEK")
	fmt.Println("5. ✓ Confirmed decryption fails with destroyed DEK")
	fmt.Println("6. ✓ Re-encrypted data with new DEK")
	fmt.Println("7. ✓ Successfully decrypted with new DEK")
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
