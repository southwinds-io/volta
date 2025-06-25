package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
)

func main() {
	fmt.Println("### Example: Managing Multiple Tenant Vaults with FileStore ###")

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

	// 2. Initialise the audit logger.
	// This logger records all significant vault management and cryptographic events.
	auditLogger, err := createAuditLogger()
	if err != nil {
		log.Fatalf("Failed to create audit logger: %v", err)
	}

	// 3. Define the base path for vault storage (assuming a file system store).
	// In a real application, this must be a persistent and secure directory.
	basePath, err := os.MkdirTemp("", "volta_filestore_example_")
	if err != nil {
		log.Fatalf("Failed to create temporary directory for base path: %v", err)
	}
	// The temporary directory is cleaned up for this example only.
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			fmt.Printf("Failed to remove temporary directory: %v\n", err)
		}
	}(basePath)
	fmt.Printf("Using temporary vault storage at: %s\n", basePath)

	// 4. Create the VaultManager instance.
	// This manager will orchestrate multiple tenant vaults, each stored as an
	// encrypted file within the specified base path.
	vaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)
	fmt.Println("VaultManager initialised.")

	// --- Operations for Tenant 'tenant-001-alpha' ---
	fmt.Println("\n--- Operations for Tenant 'tenant-001-alpha' ---")
	tenant001Id := "tenant-001-alpha"
	tenant001SecretID := "api-key-service-a"
	tenant001SecretValue := "QWERTYUIOPasdfghjkl123"

	// Get a vault instance for the tenant. A new vault is created if one doesn't exist.
	// Failure here could indicate incorrect manager passphrase or underlying file system issues.
	vault001, err := vaultManager.GetVault(tenant001Id)
	if err != nil {
		log.Fatalf("Failed to get vault for tenant %s", tenant001Id)
	}
	fmt.Printf("Obtained vault for tenant: %s.\n", tenant001Id)

	// Store a secret. The secret data is encrypted before being written to storage.
	_, err = vault001.StoreSecret(
		tenant001SecretID,
		[]byte(tenant001SecretValue),        // secret content
		[]string{"api-key", "owner:team-a"}, // secret tags
		volta.ContentTypeText,
	)
	if err != nil {
		log.Fatalf("Failed to store secret '%s' for tenant %s: %v", tenant001SecretID, tenant001Id, err)
	}
	fmt.Printf("Stored secret '%s' for tenant %s.\n", tenant001SecretID, tenant001Id)

	// Use the secret within a secure callback.
	// This pattern retrieves, decrypts, and exposes the plaintext only within the
	// scope of the provided function, after which the memory is cleared.
	err = vault001.UseSecret(tenant001SecretID, func(retrievedData []byte) error {
		fmt.Printf("Callback for secret '%s': Verifying content.\n", tenant001SecretID)
		if !strings.EqualFold(string(retrievedData), tenant001SecretValue) {
			return fmt.Errorf("retrieved secret value does not match expected value")
		}
		// The plaintext secret is now available for use (e.g., to configure a client).
		return nil // Return nil on successful use.
	})
	if err != nil {
		log.Fatalf("Failed to use secret '%s' for tenant %s: %v", tenant001SecretID, tenant001Id, err)
	}
	fmt.Printf("Successfully used secret '%s'.\n", tenant001SecretID)

	// Close the vault to release file handles and clear sensitive data from memory.
	if err = vault001.Close(); err != nil {
		log.Printf("Warning: error closing vault for tenant %s: %v\n", tenant001Id, err)
	} else {
		fmt.Printf("Vault for tenant %s closed.\n", tenant001Id)
	}

	// --- Operations for Tenant 'tenant-002-beta' ---
	fmt.Println("\n--- Operations for Tenant 'tenant-002-beta' ---")
	tenant002Id := "tenant-002-beta"
	tenant002SecretID := "db-credentials-staging"
	tenant002SecretValue := "dslknvceonertv0_XYZ987"

	vault002, err := vaultManager.GetVault(tenant002Id)
	if err != nil {
		log.Fatalf("Failed to get vault for tenant %s", tenant002Id)
	}
	fmt.Printf("Obtained vault for tenant: %s.\n", tenant002Id)

	// Store another secret, this time marked as binary content.
	_, err = vault002.StoreSecret(
		tenant002SecretID,
		[]byte(tenant002SecretValue),        // secret content
		[]string{"database", "env:staging"}, // secret tags
		volta.ContentTypeText,
	)
	if err != nil {
		log.Fatalf("Failed to store secret '%s' for tenant %s: %v", tenant002SecretID, tenant002Id, err)
	}
	fmt.Printf("Stored secret '%s' for tenant %s.\n", tenant002SecretID, tenant002Id)

	// Use the second secret.
	err = vault002.UseSecret(tenant002SecretID, func(retrievedData []byte) error {
		fmt.Printf("Callback for secret '%s': Verifying content.\n", tenant002SecretID)
		if !strings.EqualFold(string(retrievedData), tenant002SecretValue) {
			return fmt.Errorf("retrieved secret value does not match expected value")
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to use secret '%s' for tenant %s: %v", tenant002SecretID, tenant002Id, err)
	}
	fmt.Printf("Successfully used secret '%s'.\n", tenant002SecretID)

	// Close the second vault.
	if err = vault002.Close(); err != nil {
		log.Printf("Warning: error closing vault for tenant %s: %v\n", tenant002Id, err)
	} else {
		fmt.Printf("Vault for tenant %s closed.\n", tenant002Id)
	}

	fmt.Println("\n### Example Completed ###")
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
			// Additional options like "max_size_mb", "compress", etc. could be supported.
		},
	})
}
