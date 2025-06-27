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
	fmt.Println("### Example: Encrypting and Decrypting PII with a Tenant Vault ###")
	fmt.Println("🎯 Goal: Demonstrate basic PII encryption/decryption operations with performance metrics")

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
	fmt.Println("✓ VaultManager options configured")

	// 2. Initialize the audit logger.
	// This logger records all significant vault management and cryptographic events.
	auditLogger, err := createAuditLogger()
	if err != nil {
		log.Fatalf("❌ Failed to create audit logger: %v", err)
	}
	fmt.Println("✓ Audit logger initialized")

	// 3. Define the base path for vault storage.
	// In a real application, this must be a persistent and secure directory.
	basePath, err := os.MkdirTemp("", "volta_filestore_example_")
	if err != nil {
		log.Fatalf("❌ Failed to create temporary directory for base path: %v", err)
	}
	// The temporary directory is cleaned up for this example only.
	defer func(path string) {
		if err = os.RemoveAll(path); err != nil {
			fmt.Printf("⚠️ Failed to remove temporary directory: %v", err)
		} else {
			fmt.Printf("✓ Temporary directory cleaned up: %s\n", path)
		}
	}(basePath)
	fmt.Printf("✓ Using temporary vault storage at: %s\n", basePath)

	// 4. Create the VaultManager instance.
	// This manager will orchestrate multiple tenant vaults, each stored as an
	// encrypted file within the specified base path.
	vaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)
	fmt.Println("✓ VaultManager initialized successfully")

	// --- PII Encryption and Decryption Operations ---
	fmt.Println("\n--- 🔐 PII Encryption and Decryption Operations ---")
	tenantID := "pii-processor-service"

	// Get a vault instance for a service that handles PII.
	// A new vault is created on the first call for a given tenant.
	fmt.Printf("🔑 Obtaining vault for tenant: %s\n", tenantID)
	vaultStartTime := time.Now()
	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("❌ Failed to get vault for tenant %s: %v", tenantID, err)
	}
	vaultInitDuration := time.Since(vaultStartTime)
	fmt.Printf("✓ Vault obtained for tenant: %s (initialization time: %v)\n", tenantID, vaultInitDuration)

	// Define a sample PII payload to be protected.
	piiData := []byte(`{"name":"Jane Doe","ssn":"000-00-0000","address":"123 Anystreet","phone":"555-1234","email":"jane.doe@example.com"}`)
	fmt.Printf("📋 Original PII data (%d bytes): %s\n", len(piiData), string(piiData))

	// --- ENCRYPTION OPERATION ---
	fmt.Println("\n🔐 Starting PII Encryption Operation...")
	encryptStartTime := time.Now()

	// Encrypt the PII. The result is a ciphertext string containing the encrypted
	// data and the ID of the key used, making it self-contained for decryption.
	ciphertext, err := vault.Encrypt(piiData)
	if err != nil {
		log.Fatalf("❌ Failed to encrypt PII: %v", err)
	}

	encryptDuration := time.Since(encryptStartTime)
	fmt.Printf("✓ Encryption completed in %v (%d microseconds)\n", encryptDuration, encryptDuration.Microseconds())
	fmt.Printf("🔒 Encrypted ciphertext (%d bytes, safe for storage):\n   %s\n", len(ciphertext), ciphertext)

	// --- DECRYPTION OPERATION ---
	fmt.Println("\n🔓 Starting PII Decryption Operation...")
	decryptStartTime := time.Now()

	// Decrypt the ciphertext to retrieve the original PII.
	// Volta automatically uses the correct key based on the ID in the ciphertext.
	decryptedData, err := vault.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("❌ Failed to decrypt ciphertext: %v", err)
	}

	decryptDuration := time.Since(decryptStartTime)
	fmt.Printf("✓ Decryption completed in %v (%d microseconds)\n", decryptDuration, decryptDuration.Microseconds())
	fmt.Printf("📋 Decrypted PII data (%d bytes): %s\n", len(decryptedData), string(decryptedData))

	// --- DATA INTEGRITY VERIFICATION ---
	fmt.Println("\n🔍 Performing Data Integrity Verification...")
	verifyStartTime := time.Now()

	// Verify that the decrypted data matches the original plaintext.
	if !bytes.Equal(piiData, decryptedData) {
		log.Fatal("❌ Data integrity check failed: decrypted data does not match original data")
	}

	verifyDuration := time.Since(verifyStartTime)
	fmt.Printf("✅ Data integrity verification successful in %v\n", verifyDuration)
	fmt.Println("✓ Decrypted data matches original PII perfectly")

	// --- PERFORMANCE SUMMARY ---
	totalOperationTime := encryptDuration + decryptDuration + verifyDuration
	fmt.Println("\n⏱️ Performance Summary:")
	fmt.Printf("   • Vault Initialization: %v\n", vaultInitDuration)
	fmt.Printf("   • Encryption Time:      %v (%d μs)\n", encryptDuration, encryptDuration.Microseconds())
	fmt.Printf("   • Decryption Time:      %v (%d μs)\n", decryptDuration, decryptDuration.Microseconds())
	fmt.Printf("   • Verification Time:    %v\n", verifyDuration)
	fmt.Printf("   • Total Crypto Ops:    %v\n", totalOperationTime)
	fmt.Printf("   • Data Throughput:      %.2f KB/s\n", float64(len(piiData)*2)/totalOperationTime.Seconds()/1024)

	// --- CLEANUP ---
	fmt.Println("\n🧹 Performing Cleanup Operations...")

	// Close the vault to release file handles and clear sensitive data from memory.
	if err = vault.Close(); err != nil {
		fmt.Printf("⚠️ Warning: error closing vault for tenant %s: %v\n", tenantID, err)
	} else {
		fmt.Printf("✓ Vault for tenant %s closed successfully\n", tenantID)
	}

	fmt.Println("\n### 🎉 Example Completed Successfully ###")
	fmt.Println("Summary of Operations:")
	fmt.Println("1. ✓ Configured VaultManager with secure options")
	fmt.Println("2. ✓ Initialized file-based audit logging")
	fmt.Println("3. ✓ Created temporary vault storage")
	fmt.Println("4. ✓ Obtained tenant-specific vault instance")
	fmt.Println("5. ✓ Encrypted PII data with performance tracking")
	fmt.Println("6. ✓ Decrypted ciphertext with performance tracking")
	fmt.Println("7. ✓ Verified data integrity")
	fmt.Println("8. ✓ Cleaned up resources")
	fmt.Printf("9. ✓ Total execution time: %v\n", time.Since(vaultStartTime))

	fmt.Println("\n📊 Key Achievements:")
	fmt.Println("   • Demonstrated secure PII encryption/decryption cycle")
	fmt.Println("   • Measured cryptographic operation performance")
	fmt.Println("   • Validated data integrity throughout the process")
	fmt.Println("   • Implemented proper resource cleanup")
}

// createAuditLogger initializes a logger for recording audit events.
func createAuditLogger() (audit.Logger, error) {
	// For this example, logs are written to a local file.
	// In production, consider a more robust logging setup (e.g., structured logs to stdout for collection).
	auditFilePath := ".volta_audit.log"

	fmt.Printf("🔍 Initializing file-based audit logger to: %s\n", auditFilePath)
	return audit.NewLogger(&audit.Config{
		Enabled: true,
		Type:    audit.FileAuditType, // A constant representing the file logger type.
		Options: map[string]interface{}{
			"file_path": auditFilePath,
		},
	})
}
