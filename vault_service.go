// Package volta provides a secure vault service for encrypting, decrypting, and managing secrets.
// It implements a hierarchical key management system with automatic key rotation, secure backups,
// and comprehensive audit logging. The vault uses authenticated encryption and follows cryptographic
// best practices for secret management.
//
// Key Features:
//   - Hierarchical key management with automatic rotation
//   - Authenticated encryption using ChaCha20-Poly1305
//   - Secure backup and restore functionality
//   - Secret metadata management with versioning
//   - Comprehensive audit logging
//   - Memory protection for sensitive data
//
// Basic Usage:
//
//	vault, err := volta.New(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer vault.Close()
//
//	// Store a secret
//	metadata, err := vault.StoreSecret("my-secret", []byte("secret-data"), []string{"tag1"}, volta.ContentTypeText)
//
//	// Retrieve a secret
//	data, metadata, err := vault.GetSecret("my-secret")
package volta

import (
	"context"
	"southwinds.dev/volta/audit"
	"time"
)

// KeyStatus represents the lifecycle state of a vault key.
//
// Keys progress through different states during their lifecycle:
//   - Active: The key is currently used for new encryption operations
//   - Inactive: The key is no longer used for new encryptions but remains available for decryption
//
// This status system enables key rotation while maintaining the ability to decrypt
// existing data encrypted with older keys.
type KeyStatus string

const (
	// KeyStatusActive indicates the key is currently used for new encryptions.
	// Only one key should be active at any given time. When a new key is generated
	// through rotation, it becomes active and the previous active key becomes inactive.
	KeyStatusActive KeyStatus = "active"

	// KeyStatusInactive indicates the key is not used for new encryptions,
	// but can still be used for decryption of existing data.
	// Inactive keys are retained to ensure data encrypted with them remains accessible.
	// Inactive keys can be destroyed if no longer needed, but this makes associated
	// encrypted data permanently unrecoverable.
	KeyStatusInactive KeyStatus = "inactive"
)

// CryptoAlgorithm represents the cryptographic algorithm used for encryption operations.
//
// The vault supports multiple encryption algorithms, though ChaCha20-Poly1305 is currently
// the primary implementation. This enumeration allows for future algorithm support
// while maintaining backward compatibility.
type CryptoAlgorithm string

const (
	// ChaCha20Poly1305 represents the ChaCha20-Poly1305 authenticated encryption algorithm.
	// This is a modern, fast, and secure AEAD (Authenticated Encryption with Additional Data)
	// cipher that provides both confidentiality and authenticity. It's resistant to timing
	// attacks and performs well on both hardware with and without AES acceleration.
	//
	// Key characteristics:
	//   - 256-bit key size
	//   - 96-bit nonce (automatically generated)
	//   - 128-bit authentication tag
	//   - Constant-time implementation
	ChaCha20Poly1305 CryptoAlgorithm = "chacha20poly1305"
)

// ContentType represents the type of data stored in a secret.
//
// Content types help with proper handling, validation, and presentation of secret data.
// They provide metadata that applications can use to correctly interpret the stored
// information without needing to examine the actual secret content.
type ContentType string

const (
	// ContentTypeText indicates plain text content (UTF-8 encoded).
	// Use for passwords, API keys, simple configuration values, etc.
	ContentTypeText ContentType = "text/plain"

	// ContentTypeJSON indicates JSON-formatted data.
	// Use for structured configuration data, API responses, or complex secret structures.
	ContentTypeJSON ContentType = "application/json"

	// ContentTypeTOML indicates TOML-formatted data.
	// Use for structured configuration data, API responses, or complex secret structures.
	ContentTypeTOML ContentType = "application/toml"

	// ContentTypeXML indicates XML-formatted data.
	// Use for structured configuration data, API responses, or complex secret structures.
	ContentTypeXML ContentType = "application/xml"

	// ContentTypeYAML indicates YAML-formatted data.
	// Use for configuration files, Kubernetes secrets, or structured data in YAML format.
	ContentTypeYAML ContentType = "application/yaml"

	// ContentTypePEM indicates PEM-encoded data (certificates, private keys).
	// Use for SSL certificates, private keys, public keys, or other cryptographic material.
	ContentTypePEM ContentType = "application/x-pem-file"

	// ContentTypeBinary indicates arbitrary binary data.
	// Use for encrypted files, binary keys, or any non-text data.
	ContentTypeBinary ContentType = "application/octet-stream"
)

// SecretResult represents the complete result of a GetSecret operation
type SecretResult struct {
	Data          []byte
	Metadata      *SecretMetadata
	UsedActiveKey bool
}

// SecretsContainer contains metadata about a stored secret and serves as the top-level
// structure for persisting secrets to storage.
//
// This container provides versioning and timestamp information for the entire collection
// of secrets, enabling migration strategies and data integrity verification.
//
// The container is typically serialized to JSON when persisted to disk or transmitted
// over the network in encrypted form.
type SecretsContainer struct {
	// Version indicates the schema version of the secrets container format.
	// This enables backward compatibility and migration strategies when the
	// container format evolves.
	Version string `json:"version"`

	// Timestamp indicates when this container was last modified.
	// This can be used for synchronization, backup verification, and audit purposes.
	Timestamp time.Time `json:"timestamp"`

	// Secrets contains the actual secret entries, indexed by their unique identifiers.
	// The map key is the secret ID, and the value contains both the encrypted data
	// and associated metadata.
	Secrets map[string]*SecretEntry `json:"secrets"`
}

// SecretEntry represents a complete secret record including encrypted data and metadata.
//
// This structure contains everything needed to manage a secret throughout its lifecycle:
// the encrypted payload, descriptive metadata, versioning information, and audit trails.
//
// SecretEntry is used internally by the vault for storage and retrieval operations.
// The encrypted Data field is only decrypted when explicitly requested through
// the GetSecret operation.
type SecretEntry struct {
	// ID is the unique identifier for this secret within the vault.
	// IDs should be unique across the entire vault namespace and are used
	// for all retrieval, update, and deletion operations.
	ID string `json:"id"`

	// Data contains the encrypted secret payload.
	// This data is encrypted using the vault's current encryption algorithm
	// and includes authentication information to detect tampering.
	// The data remains encrypted at rest and is only decrypted in memory
	// during GetSecret operations.
	Data []byte `json:"data"`

	// Metadata contains descriptive information about the secret.
	// This includes content type, description, tags, encryption details,
	// access patterns, and custom fields. Metadata is stored in encrypted form
	// alongside the secret data.
	Metadata *SecretMetadata `json:"metadata"`

	// CreatedAt indicates when this secret was first stored in the vault.
	// This timestamp is set once during initial secret creation and never changes.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt indicates when this secret was last modified.
	// This includes updates to the secret data, metadata, or tags.
	// It's updated automatically during UpdateSecret operations.
	UpdatedAt time.Time `json:"updated_at"`

	// Tags provide a way to categorize and filter secrets.
	// Tags can be used for organizing secrets, implementing access controls,
	// or facilitating batch operations. They're indexed for efficient querying.
	Tags []string `json:"tags,omitempty"`

	// Version indicates the current version number of this secret.
	// The version is incremented each time the secret is updated,
	// providing a simple way to track changes and detect concurrent modifications.
	Version int `json:"version"`
}

// SecretMetadata contains descriptive and operational information about a secret.
//
// Metadata provides rich context about secrets without exposing the actual secret data.
// This information supports secret lifecycle management, access control, audit requirements,
// and operational monitoring.
//
// The metadata is stored alongside the encrypted secret data and is itself encrypted
// at rest to prevent information leakage.
type SecretMetadata struct {
	// SecretID is the unique identifier matching the parent SecretEntry.ID.
	// This redundancy ensures metadata can be processed independently
	// and provides data integrity validation.
	SecretID string `json:"secret_id"`

	// Version matches the parent SecretEntry version number.
	// This provides consistency checking and helps detect data corruption
	// or synchronization issues.
	Version int `json:"version"`

	// ContentType indicates the format/type of the secret data.
	// This helps applications properly interpret and handle the decrypted data
	// without needing to examine the content itself.
	ContentType ContentType `json:"content_type,omitempty"`

	// Description provides human-readable information about the secret's purpose.
	// This can include usage instructions, owner information, or context
	// about when and why the secret was created.
	Description string `json:"description,omitempty"`

	// Tags enable categorization and filtering of secrets.
	// Common patterns include environment tags (prod, staging, dev),
	// application tags, or security classification tags.
	Tags []string `json:"tags,omitempty"`

	// KeyID identifies which vault key was used to encrypt this secret.
	// This enables the vault to select the correct key for decryption
	// and supports key rotation scenarios where multiple keys may be active.
	KeyID string `json:"key_id"`

	// CreatedAt indicates when this secret was first created.
	// This timestamp is immutable and used for audit trails and lifecycle management.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt indicates when this secret was last modified.
	// This includes changes to the secret data, metadata, or tags.
	UpdatedAt time.Time `json:"updated_at"`

	// Size indicates the size in bytes of the original (decrypted) secret data.
	// This helps with capacity planning and provides insight into secret
	// sizes without requiring decryption.
	Size int `json:"size"`

	// Checksum provides integrity verification for the decrypted secret data.
	// This can be used to detect corruption or unauthorized modification
	// of secret data during storage or transmission.
	Checksum string `json:"checksum,omitempty"`

	// AccessCount tracks how many times this secret has been retrieved.
	// This metric supports usage analysis, license compliance,
	// and identification of unused secrets.
	AccessCount int64 `json:"access_count"`

	// LastAccessed indicates when this secret was last retrieved.
	// Combined with AccessCount, this provides usage pattern analysis
	// and helps identify stale or abandoned secrets.
	LastAccessed *time.Time `json:"last_accessed,omitempty"`

	// ExpiresAt provides automatic expiration for time-sensitive secrets.
	// When set, the vault can warn about or automatically handle
	// expired secrets according to configured policies.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// CustomFields allows applications to store additional structured metadata.
	// This provides extensibility for application-specific requirements
	// without modifying the core metadata schema.
	// Examples: cost center, compliance classification, rotation schedule.
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

// SecretListEntry represents a secret entry for listing operations without exposing encrypted data.
//
// This structure provides all the information needed for secret management operations
// (listing, filtering, metadata operations) while maintaining security by excluding
// the actual encrypted secret payload.
//
// SecretListEntry is returned by ListSecrets and similar operations where bulk
// secret information is needed without the overhead and security implications
// of including encrypted data.
type SecretListEntry struct {
	// ID is the unique identifier for this secret.
	// This is used for subsequent operations like GetSecret, UpdateSecret, or DeleteSecret.
	ID string `json:"id"`

	// Metadata contains all descriptive information about the secret.
	// This includes content type, tags, creation dates, access patterns,
	// and custom fields, but excludes the encrypted payload.
	Metadata *SecretMetadata `json:"metadata"`

	// CreatedAt indicates when this secret was first stored.
	// Duplicated from metadata for convenient access during listing operations.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt indicates when this secret was last modified.
	// Duplicated from metadata for convenient sorting and filtering.
	UpdatedAt time.Time `json:"updated_at"`

	// Tags provide categorization information for filtering and organization.
	// Duplicated from metadata for efficient query operations.
	Tags []string `json:"tags,omitempty"`

	// Version indicates the current version of this secret.
	// Useful for detecting changes and managing concurrent access.
	Version int `json:"version"`

	// DataSize indicates the size of the encrypted data in bytes.
	// This provides storage utilization information without exposing
	// the actual secret size or content.
	DataSize int `json:"data_size"`
}

// SecretListOptions provides filtering and pagination options for listing secrets.
//
// These options enable efficient querying of large secret collections without
// requiring full table scans or loading unnecessary data into memory.
//
// Multiple filter criteria can be combined (AND logic) to narrow results.
// Pagination options help manage large result sets and API response times.
type SecretListOptions struct {
	// Tags filters results to include only secrets that have ALL specified tags.
	// This implements AND logic - a secret must have every tag in this list
	// to be included in results. Use empty slice or nil for no tag filtering.
	Tags []string `json:"tags,omitempty"`

	// Prefix filters results to include only secrets whose ID starts with this string.
	// This enables hierarchical secret organization (e.g., "app1/", "prod/")
	// and efficient range-based queries. Case-sensitive matching is used.
	Prefix string `json:"prefix,omitempty"`

	// Limit restricts the maximum number of results returned.
	// Use 0 or negative values for no limit. When combined with Offset,
	// this enables pagination through large result sets.
	Limit int `json:"limit,omitempty"`

	// Offset specifies how many matching results to skip before returning data.
	// Use with Limit to implement pagination. Results should be consistently
	// ordered (typically by ID or creation time) for reliable pagination.
	Offset int `json:"offset,omitempty"`

	// ContentType filters results to include only secrets of the specified type.
	// This helps applications find secrets of specific formats
	// (e.g., only certificates, only JSON configurations).
	ContentType ContentType `json:"contentType,omitempty"`
}

// VaultService defines the public interface for interacting with the vault.
//
// The vault manages its primary keys internally and ensures they are not directly exportable.
// It uses these keys to encrypt and decrypt provided data while maintaining strict
// separation between key material and application data.
//
// Key Design Principles:
//   - Zero-trust: Keys are never exposed outside the vault instance
//   - Fail-secure: Operations fail safely when keys are unavailable
//   - Audit-first: All operations are logged for compliance and security monitoring
//   - Memory-safe: Sensitive data is cleared from memory when no longer needed
//
// Thread Safety:
// Implementations of VaultService should be thread-safe for concurrent access,
// though individual operations may acquire locks as needed for consistency.
//
// Error Handling:
// All operations return errors that provide sufficient detail for troubleshooting
// while avoiding information disclosure that could aid attackers.
type VaultService interface {

	// === Core Cryptographic Operations ===

	// Encrypt encrypts plaintext data using the current active key.
	//
	// The returned string is a base64 encoded representation that includes
	// the KeyID necessary for decryption in a non-malleable format.
	// The ciphertext includes authentication data to detect tampering.
	//
	// Parameters:
	//   - plaintext: The data to encrypt (any byte sequence)
	//
	// Returns:
	//   - ciphertextWithKeyID: Base64-encoded ciphertext with embedded key identifier
	//   - err: Error if encryption fails (no active key, cryptographic failure, etc.)
	//
	// Security Notes:
	//   - A fresh nonce is generated for each encryption operation
	//   - The same plaintext will produce different ciphertexts each time
	//   - The KeyID is authenticated as part of the ciphertext to prevent substitution attacks
	//
	// Example:
	//   ciphertext, err := vault.Encrypt([]byte("my secret data"))
	//   if err != nil {
	//       return fmt.Errorf("encryption failed: %w", err)
	//   }
	Encrypt(plaintext []byte) (ciphertextWithKeyID string, err error)

	// Decrypt decrypts data that was previously encrypted by this vault instance
	// (or another instance sharing the same underlying key material and metadata).
	//
	// It automatically identifies the correct key using the KeyID embedded
	// in the ciphertext and verifies the authentication tag to detect tampering.
	//
	// Parameters:
	//   - base64CiphertextWithKeyID: The base64-encoded ciphertext returned by Encrypt
	//
	// Returns:
	//   - plaintext: The original data that was encrypted
	//   - err: Error if decryption fails (invalid format, wrong key, authentication failure, etc.)
	//
	// Security Notes:
	//   - Authentication is verified before returning any plaintext
	//   - Timing attacks are mitigated through constant-time operations
	//   - Invalid ciphertexts fail fast without revealing information about keys or plaintext
	//
	// Example:
	//   plaintext, err := vault.Decrypt(ciphertext)
	//   if err != nil {
	//       return fmt.Errorf("decryption failed: %w", err)
	//   }
	//   fmt.Printf("Secret: %s\n", string(plaintext))
	Decrypt(base64CiphertextWithKeyID string) (plaintext []byte, err error)

	// === Key Management Operations ===

	// RotateKey generates a new key, makes it the active key for
	// new encryptions, and deactivates the previously active key (marking it as inactive).
	//
	// The old key remains available for decrypting existing data, ensuring no data loss.
	// This operation should be performed regularly as part of key lifecycle management.
	//
	// Parameters:
	//   - reason: Human-readable explanation for the key rotation (for audit logs)
	//
	// Returns:
	//   - KeyMetadata: Metadata for the newly created active key
	//   - error: Error if rotation fails (entropy issues, storage problems, etc.)
	//
	// Security Notes:
	//   - New keys use cryptographically secure random generation
	//   - The operation is atomic - either fully succeeds or leaves the vault unchanged
	//   - All key state changes are logged for audit purposes
	//
	// Example:
	//   metadata, err := vault.RotateKey("scheduled monthly rotation")
	//   if err != nil {
	//       return fmt.Errorf("key rotation failed: %w", err)
	//   }
	//   fmt.Printf("New active key: %s\n", metadata.KeyID)
	RotateKey(reason string) (*KeyMetadata, error)

	// DestroyKey permanently removes an inactive key and its material from the vault.
	//
	// Once a key is destroyed, any data encrypted solely with this key will be
	// irrecoverable by the vault. This operation is irreversible and should only
	// be performed after ensuring no encrypted data depends on the key.
	//
	// Parameters:
	//   - keyID: The identifier of the key to destroy (must be inactive)
	//
	// Returns:
	//   - error: Error if destruction fails (key is active, key not found, etc.)
	//
	// Security Notes:
	//   - Key material is securely wiped from memory and storage
	//   - The operation is logged for audit and compliance purposes
	//   - Attempting to destroy the active key returns an error
	//
	// Example:
	//   err := vault.DestroyKey("old-key-id-123")
	//   if err != nil {
	//       return fmt.Errorf("key destruction failed: %w", err)
	//   }
	DestroyKey(keyID string) error

	// === Backup and Recovery Operations ===

	// Backup creates an encrypted backup of all non-decommissioned keys,
	// their operational metadata, and the vault's derivation salt to the
	// specified destination directory.
	//
	// This backup's key material is encrypted using the vault's Key Encryption Key (KEK),
	// which is derived from the vault's passphrase and the (now backed up) salt.
	// This provides a comprehensive backup for vault recovery scenarios.
	//
	// Parameters:
	//   - destinationDir: Directory where backup files will be created
	//   - passphrase: Passphrase used to encrypt the backup (should be strong and securely stored)
	//
	// Returns:
	//   - error: Error if backup fails (I/O issues, encryption problems, etc.)
	//
	// Backup Structure:
	//   - destinationDir/keys/ - Encrypted key material files
	//   - destinationDir/metadata.enc - Encrypted key metadata
	//   - destinationDir/derivation.salt.backup - Key derivation salt
	//
	// Security Notes:
	//   - All sensitive data in the backup is encrypted
	//   - The backup passphrase should be different from the vault passphrase
	//   - Backup integrity can be verified before attempting restoration
	//
	// Example:
	//   err := vault.Backup("/secure/backup/location", "strong-backup-passphrase")
	//   if err != nil {
	//       return fmt.Errorf("backup failed: %w", err)
	//   }
	Backup(destinationDir, passphrase string) error

	// Restore recovers vault state from a previously created backup.
	//
	// This operation reconstructs the vault's keys, metadata, and derivation salt
	// from encrypted backup files. The vault instance should be newly created
	// or reset before calling this method.
	//
	// Parameters:
	//   - destinationDir: Directory containing the backup files
	//   - passphrase: Passphrase used when creating the backup
	//
	// Returns:
	//   - error: Error if restoration fails (wrong passphrase, corrupted backup, etc.)
	//
	// Security Notes:
	//   - The correct backup passphrase is required for successful restoration
	//   - Backup integrity is verified before applying any changes
	//   - The operation is atomic - either fully succeeds or leaves vault unchanged
	//
	// Example:
	//   err := vault.Restore("/secure/backup/location", "strong-backup-passphrase")
	//   if err != nil {
	//       return fmt.Errorf("restore failed: %w", err)
	//   }
	Restore(destinationDir, passphrase string) error

	// === Key Metadata and Status Operations ===

	// ListKeyMetadata returns metadata for all known keys managed by the vault,
	// including active, inactive, and decommissioned keys.
	//
	// This provides visibility into the vault's key lifecycle state and supports
	// key management operations like rotation scheduling and cleanup.
	//
	// Returns:
	//   - []KeyMetadata: List of metadata for all keys (actual key material not included)
	//   - error: Error if metadata retrieval fails
	//
	// The returned metadata includes creation times, status, usage statistics,
	// and other operational information but never includes actual key material.
	//
	// Example:
	//   keys, err := vault.ListKeyMetadata()
	//   if err != nil {
	//       return err
	//   }
	//   for _, key := range keys {
	//       fmt.Printf("Key %s: %s (created %v)\n", key.KeyID, key.Status, key.CreatedAt)
	//   }
	ListKeyMetadata() ([]KeyMetadata, error)

	// GetActiveKeyMetadata returns the metadata for the key currently
	// active for encryption operations.
	//
	// Returns:
	//   - KeyMetadata: Metadata for the active key
	//   - error: Error if no key is active or metadata retrieval fails
	//
	// This is useful for monitoring key age, planning rotations, and
	// understanding current encryption capabilities.
	//
	// Example:
	//   activeKey, err := vault.GetActiveKeyMetadata()
	//   if err != nil {
	//       return fmt.Errorf("no active key available: %w", err)
	//   }
	//   fmt.Printf("Active key %s created %v\n", activeKey.KeyID, activeKey.CreatedAt)
	GetActiveKeyMetadata() (KeyMetadata, error)

	// === Secret CRUD Operations ===

	// StoreSecret encrypts and stores secret data with optional metadata.
	//
	// The secret data is encrypted using the current active key and stored
	// with rich metadata for lifecycle management and organization.
	//
	// Parameters:
	//   - secretID: Unique identifier for the secret (must be unique within the vault)
	//   - secretData: The actual secret data to encrypt and store
	//   - tags: Optional tags for categorization and filtering
	//   - contentType: The type/format of the secret data
	//
	// Returns:
	//   - *SecretMetadata: Metadata for the stored secret (including generated fields)
	//   - error: Error if storage fails (duplicate ID, encryption failure, etc.)
	//
	// Security Notes:
	//   - Secret data is encrypted before being written to storage
	//   - Metadata includes integrity checksums for tamper detection
	//   - All operations are logged for audit purposes
	//
	// Example:
	//   metadata, err := vault.StoreSecret(
	//       "database-password",
	//       []byte("super-secret-password"),
	//       []string{"database", "production"},
	//       volta.ContentTypeText,
	//   )
	//   if err != nil {
	//       return fmt.Errorf("failed to store secret: %w", err)
	//   }
	StoreSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)

	GetSecret(secretID string) (*SecretResult, error)

	// UpdateSecret updates existing secret data and increments the version number.
	//
	// This operation preserves the original creation timestamp while updating
	// the modification timestamp and version number.
	//
	// Parameters:
	//   - secretID: The unique identifier of the secret to update
	//   - secretData: The new secret data to encrypt and store
	//   - tags: Updated tags (replaces existing tags)
	//   - contentType: Updated content type
	//
	// Returns:
	//   - *SecretMetadata: Updated metadata reflecting the changes
	//   - error: Error if update fails (secret not found, encryption failure, etc.)
	//
	// Security Notes:
	//   - Old secret data is securely overwritten
	//   - Version numbers prevent lost update problems
	//   - All changes are logged for audit purposes
	//
	// Example:
	//   metadata, err := vault.UpdateSecret(
	//       "database-password",
	//       []byte("new-super-secret-password"),
	//       []string{"database", "production", "rotated"},
	//       volta.ContentTypeText,
	//   )
	//   if err != nil {
	//       return fmt.Errorf("failed to update secret: %w", err)
	//   }
	//   fmt.Printf("Secret updated to version %d\n", metadata.Version)
	UpdateSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)

	// DeleteSecret removes a secret and its metadata from the vault.
	//
	// This operation is irreversible. Once deleted, the secret cannot be recovered
	// without restoring from a backup.
	//
	// Parameters:
	//   - secretID: The unique identifier of the secret to delete
	//
	// Returns:
	//   - error: Error if deletion fails (secret not found, storage error, etc.)
	//
	// Security Notes:
	//   - Secret data is securely wiped from storage
	//   - The operation is logged for audit purposes
	//   - Deletion is atomic - either fully succeeds or leaves data unchanged
	//
	// Example:
	//   err := vault.DeleteSecret("old-api-key")
	//   if err != nil {
	//       return fmt.Errorf("failed to delete secret: %w", err)
	//   }
	DeleteSecret(secretID string) error

	// SecretExists checks if a secret exists without retrieving its data.
	//
	// This is useful for conditional operations and avoiding unnecessary
	// decryption operations when only existence needs to be verified.
	//
	// Parameters:
	//   - secretID: The unique identifier to check
	//
	// Returns:
	//   - bool: true if the secret exists, false otherwise
	//   - error: Error if the existence check fails (storage error, etc.)
	//
	// Security Notes:
	//   - No secret data is decrypted during this operation
	//   - The check may still be logged for audit purposes
	//
	// Example:
	//   exists, err := vault.SecretExists("api-key")
	//   if err != nil {
	//       return fmt.Errorf("existence check failed: %w", err)
	//   }
	//   if !exists {
	//       // Create the secret
	//   }
	SecretExists(secretID string) (bool, error)

	// ListSecrets returns secret metadata based on filter options.
	//
	// This operation provides efficient querying and pagination over large
	// secret collections without decrypting any actual secret data.
	//
	// Parameters:
	//   - options: Filter and pagination options (nil for default behavior)
	//
	// Returns:
	//   - []*SecretListEntry: List of matching secrets (without encrypted data)
	//   - error: Error if listing fails (storage error, invalid options, etc.)
	//
	// The returned entries include all metadata but exclude the encrypted
	// secret payload for security and performance reasons.
	//
	// Example:
	//   options := &volta.SecretListOptions{
	//       Tags: []string{"production"},
	//       Prefix: "api-",
	//       Limit: 50,
	//   }
	//   secrets, err := vault.ListSecrets(options)
	//   if err != nil {
	//       return fmt.Errorf("failed to list secrets: %w", err)
	//   }
	//   for _, secret := range secrets {
	//       fmt.Printf("%s: %s (v%d)\n", secret.ID, secret.Metadata.Description, secret.Version)
	//   }
	ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error)

	// GetSecretMetadata returns only the metadata for a secret without decrypting the data.
	//
	// This is useful for displaying secret information, checking expiration,
	// or performing management operations without the overhead of decryption.
	//
	// Parameters:
	//   - secretID: The unique identifier of the secret
	//
	// Returns:
	//   - *SecretMetadata: Complete metadata for the secret
	//   - error: Error if metadata retrieval fails (secret not found, etc.)
	//
	// Security Notes:
	//   - No secret data is decrypted during this operation
	//   - Access may still be logged for audit purposes
	//   - Metadata itself is stored encrypted and decrypted for this operation
	//
	// Example:
	//   metadata, err := vault.GetSecretMetadata("database-password")
	//   if err != nil {
	//       return fmt.Errorf("failed to get metadata: %w", err)
	//   }
	//   if metadata.ExpiresAt != nil && metadata.ExpiresAt.Before(time.Now()) {
	//       fmt.Printf("Warning: Secret %s has expired\n", secretID)
	//   }
	GetSecretMetadata(secretID string) (*SecretMetadata, error)

	// === System Operations ===

	// Close securely wipes all sensitive key material (active key, KEK candidate, salt cache)
	// from the vault's memory and releases associated resources.
	//
	// After Close() is called, the vault instance becomes unusable and any further
	// calls to its methods will likely result in errors. This method should be called
	// when the vault is no longer needed to prevent keys from lingering in memory.
	//
	// Returns:
	//   - error: Error if cleanup fails (though the vault should still be considered closed)
	//
	// Security Notes:
	//   - All cryptographic key material is securely zeroed in memory
	//   - File handles and other resources are properly released
	//   - The operation is idempotent - safe to call multiple times
	//   - Memory protection mechanisms are disabled after successful close
	//
	// Example:
	//   vault, err := volta.New(config)
	//   if err != nil {
	//       return err
	//   }
	//   defer func() {
	//       if err := vault.Close(); err != nil {
	//           log.Printf("Warning: vault cleanup failed: %v", err)
	//       }
	//   }()
	Close() error

	// =============================================================================
	// VAULT SECURE SECRET ACCESS INTERFACE
	// =============================================================================

	// UseSecret executes a function with a secret and ensures automatic cleanup.
	//
	// This is the RECOMMENDED method for accessing secrets securely. The secret data
	// is automatically cleared from memory when the function returns, regardless of
	// success or failure.
	//
	// Parameters:
	//   - secretID: Unique identifier for the secret (e.g., "api/keys/stripe", "db/credentials/prod")
	//   - fn: Function to execute with the secret data. The data slice is only valid
	//         within this function and will be cleared immediately after return.
	//
	// Returns:
	//   - error: Returns any error from secret retrieval or from the executed function
	//
	// Security Notes:
	//   - Secret data is stored in secure memory and cleared with multiple overwrites
	//   - Data is automatically zeroed even if the function panics
	//   - The data slice becomes invalid after the function returns
	//   - Memory is force garbage collected after clearing
	//
	// Examples:
	//
	//	// Database connection
	//	err := vault.UseSecret("db/password", func(password []byte) error {
	//	    dsn := fmt.Sprintf("user=app password=%s host=localhost", string(password))
	//	    db, err := sql.Open("postgres", dsn)
	//	    if err != nil {
	//	        return err
	//	    }
	//	    defer db.Close()
	//	    return db.Ping()
	//	})
	//
	//	// API authentication
	//	err := vault.UseSecret("api/token", func(token []byte) error {
	//	    req.Header.Set("Authorization", "Bearer "+string(token))
	//	    return client.Do(req)
	//	})
	//
	//	// File encryption
	//	err := vault.UseSecret("encryption/key", func(key []byte) error {
	//	    cipher, err := aes.NewCipher(key)
	//	    if err != nil {
	//	        return err
	//	    }
	//	    return encryptFile(cipher, inputFile, outputFile)
	//	})
	//
	// Best Practices:
	//   - Do NOT store references to the data slice outside the function
	//   - Do NOT copy the data to long-lived variables without proper clearing
	//   - Process the secret immediately within the function
	//   - Keep the function execution time as short as possible
	//
	// Thread Safety: Safe for concurrent use
	UseSecret(secretID string, fn func(data []byte) error) error

	// UseSecretWithTimeout executes a function with a secret with automatic timeout.
	//
	// Similar to UseSecret but with a timeout mechanism. If the function execution
	// exceeds the timeout, the context is cancelled and the secret is immediately
	// cleared from memory.
	//
	// Parameters:
	//   - secretID: Unique identifier for the secret
	//   - timeout: Maximum duration to wait for function completion
	//   - fn: Function to execute with the secret data
	//
	// Returns:
	//   - error: Returns context.DeadlineExceeded if timeout occurs,
	//            retrieval errors, or errors from the executed function
	//
	// Security Notes:
	//   - All security guarantees of UseSecret apply
	//   - Secret is cleared immediately when timeout occurs
	//   - Function execution is monitored via goroutine
	//   - Panic recovery ensures cleanup even on function panic
	//
	// Examples:
	//
	//	// API call with timeout
	//	err := vault.UseSecretWithTimeout("api/key", 30*time.Second, func(key []byte) error {
	//	    client := &http.Client{Timeout: 25 * time.Second}
	//	    req.Header.Set("X-API-Key", string(key))
	//	    resp, err := client.Do(req)
	//	    if err != nil {
	//	        return err
	//	    }
	//	    defer resp.Body.Close()
	//	    return processResponse(resp)
	//	})
	//	if err == context.DeadlineExceeded {
	//	    log.Println("API call timed out")
	//	}
	//
	//	// Database operation with timeout
	//	err := vault.UseSecretWithTimeout("db/password", 10*time.Second, func(pwd []byte) error {
	//	    ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	//	    defer cancel()
	//	    return performDatabaseOperation(ctx, string(pwd))
	//	})
	//
	// Use Cases:
	//   - Network operations that might hang
	//   - Database queries with unknown execution time
	//   - External service calls
	//   - Any operation where you need guaranteed cleanup time
	//
	// Thread Safety: Safe for concurrent use
	UseSecretWithTimeout(secretID string, timeout time.Duration, fn func(data []byte) error) error

	// UseSecretWithContext executes a function with a secret using a custom context.
	//
	// Provides full context control for secret usage. The secret is cleared when
	// the function completes OR when the context is cancelled, whichever comes first.
	//
	// Parameters:
	//   - ctx: Context for controlling execution (cancellation, timeout, deadlines)
	//   - secretID: Unique identifier for the secret
	//   - fn: Function to execute with the secret data
	//
	// Returns:
	//   - error: Returns context errors (Cancelled, DeadlineExceeded),
	//            retrieval errors, or errors from the executed function
	//
	// Context Behavior:
	//   - If context is already cancelled, returns immediately with context error
	//   - If context is cancelled during execution, function may continue but
	//     secret will be cleared when context cancellation is detected
	//   - Function execution happens in separate goroutine to monitor context
	//
	// Security Notes:
	//   - All security guarantees of UseSecret apply
	//   - Context cancellation triggers immediate secret clearing
	//   - Goroutine-safe execution with panic recovery
	//   - Secret clearing is guaranteed regardless of context state
	//
	// Examples:
	//
	//	// User-cancellable operation
	//	ctx, cancel := context.WithCancel(context.Background())
	//	go func() {
	//	    <-userCancelSignal
	//	    cancel()
	//	}()
	//	err := vault.UseSecretWithContext(ctx, "crypto/key", func(key []byte) error {
	//	    return performLongCryptographicOperation(key)
	//	})
	//
	//	// Request-scoped secret usage
	//	func handleRequest(w http.ResponseWriter, r *http.Request) {
	//	    err := vault.UseSecretWithContext(r.Context(), "api/secret", func(secret []byte) error {
	//	        return callDownstreamService(r.Context(), secret)
	//	    })
	//	    if err != nil {
	//	        http.Error(w, "Service unavailable", 503)
	//	    }
	//	}
	//
	//	// Batch processing with cancellation
	//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	//	defer cancel()
	//	err := vault.UseSecretWithContext(ctx, "batch/key", func(key []byte) error {
	//	    for _, item := range batchItems {
	//	        select {
	//	        case <-ctx.Done():
	//	            return ctx.Err()
	//	        default:
	//	            if err := processItem(item, key); err != nil {
	//	                return err
	//	            }
	//	        }
	//	    }
	//	    return nil
	//	})
	//
	// Use Cases:
	//   - Request-scoped operations in web servers
	//   - User-cancellable long-running operations
	//   - Integration with existing context-aware code
	//   - Complex timeout and deadline scenarios
	//
	// Thread Safety: Safe for concurrent use
	UseSecretWithContext(ctx context.Context, secretID string, fn func(data []byte) error) error

	// UseSecretString executes a function with a secret as a string and ensures cleanup.
	//
	// Convenience method for secrets that are naturally string-based (passwords,
	// tokens, keys, etc.). Provides the same security guarantees as UseSecret
	// but with string handling.
	//
	// Parameters:
	//   - secretID: Unique identifier for the secret
	//   - fn: Function to execute with the secret string. The string is only valid
	//         within this function and underlying memory is cleared after return.
	//
	// Returns:
	//   - error: Returns any error from secret retrieval or from the executed function
	//
	// Security Notes:
	//   - String and underlying byte data are both securely cleared
	//   - Multiple memory overwrites before zeroing
	//   - Automatic cleanup even on function panic
	//   - String becomes invalid/empty after function returns
	//
	// Examples:
	//
	//	// JWT token usage
	//	err := vault.UseSecretString("auth/jwt-secret", func(secret string) error {
	//	    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//	    tokenString, err := token.SignedString([]byte(secret))
	//	    if err != nil {
	//	        return err
	//	    }
	//	    return sendTokenToClient(tokenString)
	//	})
	//
	//	// Password validation
	//	err := vault.UseSecretString("users/admin/password", func(password string) error {
	//	    if !validatePasswordComplexity(password) {
	//	        return fmt.Errorf("password does not meet complexity requirements")
	//	    }
	//	    return updateUserPassword("admin", password)
	//	})
	//
	//	// Configuration with secrets
	//	err := vault.UseSecretString("config/database-url", func(dbURL string) error {
	//	    config := &AppConfig{
	//	        DatabaseURL: dbURL,
	//	        // ... other config
	//	    }
	//	    return initializeApplication(config)
	//	})
	//
	//	// API key usage
	//	err := vault.UseSecretString("external/api-key", func(apiKey string) error {
	//	    client := externalapi.NewClient(apiKey)
	//	    result, err := client.FetchData()
	//	    if err != nil {
	//	        return err
	//	    }
	//	    return processExternalData(result)
	//	})
	//
	// Best Practices:
	//   - Do NOT assign the string to variables outside the function
	//   - Do NOT store the string in structs that outlive the function
	//   - Process string-based secrets immediately
	//   - Use for passwords, tokens, URLs with embedded secrets, etc.
	//
	// Thread Safety: Safe for concurrent use
	UseSecretString(secretID string, fn func(secret string) error) error

	// GetSecretWithTimeout retrieves a secret with automatic timeout-based cleanup.
	//
	// ADVANCED METHOD: Returns a SecretWithContext that provides direct access to
	// secret data but with automatic cleanup when the timeout expires. Use this
	// when you need persistent access to secret data across multiple operations
	// within a time limit.
	//
	// Parameters:
	//   - secretID: Unique identifier for the secret
	//   - timeout: Duration after which the secret will be automatically cleared
	//
	// Returns:
	//   - *SecretWithContext: Object providing access to secret data and metadata
	//   - error: Any error from secret retrieval
	//
	// IMPORTANT: Always call Close() on the returned SecretWithContext to ensure
	// immediate cleanup. The timeout provides a safety net but should not be
	// relied upon for timely cleanup.
	//
	// SecretWithContext Methods:
	//   - Data() []byte - Returns secret data (nil after timeout/close)
	//   - Metadata() *SecretMetadata - Returns secret metadata
	//   - Done() <-chan struct{} - Channel that closes when timeout occurs
	//   - Close() - Immediately clear secret and cancel timeout
	//   - IsCleared() bool - Check if secret has been cleared
	//
	// Security Notes:
	//   - Secret is automatically cleared when timeout expires
	//   - Background goroutine monitors timeout
	//   - Memory is securely overwritten on cleanup
	//   - Close() should be called for immediate cleanup
	//   - Data() returns nil after timeout or close
	//
	// Examples:
	//
	//	// Multi-step operation with timeout
	//	secretCtx, err := vault.GetSecretWithTimeout("crypto/key", 5*time.Minute)
	//	if err != nil {
	//	    return err
	//	}
	//	defer secretCtx.Close() // Always cleanup
	//
	//	// Step 1: Initialize
	//	cipher, err := aes.NewCipher(secretCtx.Data())
	//	if err != nil {
	//	    return err
	//	}
	//
	//	// Step 2: Process multiple files
	//	for _, file := range filesToEncrypt {
	//	    select {
	//	    case <-secretCtx.Done():
	//	        return fmt.Errorf("operation timed out")
	//	    default:
	//	        if err := encryptFile(cipher, file); err != nil {
	//	            return err
	//	        }
	//	    }
	//	}
	//
	//	// Connection pooling with secret rotation
	//	secretCtx, err := vault.GetSecretWithTimeout("db/password", 1*time.Hour)
	//	if err != nil {
	//	    return err
	//	}
	//	defer secretCtx.Close()
	//
	//	pool := &ConnectionPool{}
	//	for {
	//	    select {
	//	    case <-secretCtx.Done():
	//	        // Secret expired, need to refresh
	//	        pool.Close()
	//	        return refreshSecret()
	//	    case req := <-connectionRequests:
	//	        conn := pool.GetConnection(secretCtx.Data())
	//	        go handleRequest(conn, req)
	//	    }
	//	}
	//
	// Use Cases:
	//   - Multi-step operations requiring the same secret
	//   - Connection pools with authentication
	//   - Batch processing with time limits
	//   - Operations where UseSecret callback pattern is insufficient
	//
	// Thread Safety: Safe for concurrent use. The returned SecretWithContext
	// is also thread-safe for read operations.
	//
	// WARNING: This method provides direct access to secret data. Ensure proper
	// cleanup and do not store references beyond the intended lifetime.
	GetSecretWithTimeout(secretID string, timeout time.Duration) (*SecretWithContext, error)

	// GetSecretWithContext retrieves a secret with custom context-based cleanup.
	//
	// ADVANCED METHOD: Returns a SecretWithContext tied to the provided context.
	// The secret is automatically cleared when the context is cancelled or expires.
	// Use this for integrating secret access with existing context-aware code.
	//
	// Parameters:
	//   - ctx: Context controlling the secret lifetime
	//   - secretID: Unique identifier for the secret
	//
	// Returns:
	//   - *SecretWithContext: Object providing access to secret data and metadata
	//   - error: Any error from secret retrieval
	//
	// IMPORTANT: The returned SecretWithContext will be automatically cleared when
	// the provided context is cancelled. Always call Close() for immediate cleanup
	// if needed before context cancellation.
	//
	// Context Behavior:
	//   - Secret is cleared when context is cancelled/expires
	//   - If context is already cancelled, secret is still retrieved but immediately scheduled for cleanup
	//   - Child context is created to avoid affecting parent context
	//   - Background goroutine monitors context state
	//
	// Security Notes:
	//   - All security guarantees of GetSecretWithTimeout apply
	//   - Context cancellation triggers immediate secure cleanup
	//   - Data() returns nil after context cancellation or Close()
	//   - Memory is securely overwritten on cleanup
	//
	// Examples:
	//
	//	// Request-scoped database access
	//	func handleDatabaseRequest(ctx context.Context, query string) error {
	//	    secretCtx, err := vault.GetSecretWithContext(ctx, "db/credentials")
	//	    if err != nil {
	//	        return err
	//	    }
	//	    defer secretCtx.Close()
	//
	//	    db, err := sql.Open("postgres", buildDSN(secretCtx.Data()))
	//	    if err != nil {
	//	        return err
	//	    }
	//	    defer db.Close()
	//
	//	    return db.QueryRowContext(ctx, query).Scan(&result)
	//	}
	//
	//	// Background service with graceful shutdown
	//	func runBackgroundService(ctx context.Context) error {
	//	    secretCtx, err := vault.GetSecretWithContext(ctx, "service/api-key")
	//	    if err != nil {
	//	        return err
	//	    }
	//	    defer secretCtx.Close()
	//
	//	    client := api.NewClient(string(secretCtx.Data()))
	//	    ticker := time.NewTicker(30 * time.Second)
	//	    defer ticker.Stop()
	//
	//	    for {
	//	        select {
	//	        case <-ctx.Done():
	//	            return ctx.Err()
	//	        case <-secretCtx.Done():
	//	            return fmt.Errorf("secret context expired")
	//	        case <-ticker.C:
	//	            if err := performPeriodicTask(client); err != nil {
	//	                return err
	//	            }
	//	        }
	//	    }
	//	}
	//
	//	// Stream processing with cancellation
	//	func processStream(ctx context.Context, stream <-chan Data) error {
	//	    secretCtx, err := vault.GetSecretWithContext(ctx, "encryption/key")
	//	    if err != nil {
	//	        return err
	//	    }
	//	    defer secretCtx.Close()
	//
	//	    cipher, err := aes.NewCipher(secretCtx.Data())
	//	    if err != nil {
	//	        return err
	//	    }
	//
	//	    for {
	//	        select {
	//	        case <-ctx.Done():
	//	            return ctx.Err()
	//	        case data, ok := <-stream:
	//	            if !ok {
	//	                return nil // Stream closed
	//	            }
	//	            if err := processData(cipher, data); err != nil {
	//	                return err
	//	            }
	//	        }
	//	    }
	//	}
	//
	// Use Cases:
	//   - Request-scoped operations in web applications
	//   - Background services with graceful shutdown
	//   - Stream processing with cancellation
	//   - Integration with existing context-aware APIs
	//   - Long-running operations that can be cancelled
	//
	// Thread Safety: Safe for concurrent use. The returned SecretWithContext
	// is also thread-safe for read operations.
	//
	// Best Practices:
	//   - Always use defer secretCtx.Close() immediately after creation
	//   - Monitor secretCtx.Done() channel in long-running operations
	//   - Do not store secretCtx beyond the lifetime of the controlling context
	//   - Use IsCleared() to check secret state in error conditions
	//
	// WARNING: This method provides direct access to secret data. The secret
	// remains in memory until context cancellation or Close() is called.
	GetSecretWithContext(ctx context.Context, secretID string) (*SecretWithContext, error)

	// =============================================================================
	// MULTI-SECRET INTERFACE METHODS - Secure handling of multiple secrets
	// =============================================================================
	// USAGE GUIDELINES
	//
	// METHOD SELECTION GUIDE:
	//
	// Use UseSecrets when:
	// • Working with 3+ secrets simultaneously
	// • Secret count varies at runtime
	// • Need maximum flexibility in secret handling
	// • Working with mixed binary/text secret types
	//
	// Use UseSecretsString when:
	// • Working with 3+ text-based secrets
	// • All secrets are UTF-8 strings
	// • Want to avoid manual string conversion
	//
	// Use UseSecretPair when:
	// • Working with exactly 2 binary secrets
	// • Want compile-time parameter verification
	// • Prefer named parameters over map access
	// • Working with cryptographic key pairs
	//
	// Use UseSecretPairString when:
	// • Working with exactly 2 text-based secrets
	// • Want both ergonomic API and string conversion
	// • Common username/password or key/secret patterns
	//
	// SECURITY BEST PRACTICES:
	//
	// 1. NEVER retain secret references beyond callback scope
	// 2. NEVER pass secrets to concurrent goroutines
	// 3. NEVER store secrets in persistent data structures
	// 4. Complete all secret operations before callback return
	// 5. Handle callback errors appropriately (secrets still cleaned up)
	// 6. Use most specific method for your use case (better type safety)
	// 7. Validate secret data within callback before use
	// 8. Consider secret interdependencies when designing operations
	//
	// ERROR HANDLING PATTERNS:
	//
	// All multi-secret methods guarantee cleanup regardless of error conditions:
	// • Secret retrieval failures: No secrets exposed, immediate error return
	// • Callback panics: All secrets cleaned up before panic propagation
	// • Callback errors: All secrets cleaned up before error return
	// • System errors: Partial cleanup completed, resources released
	//
	// PERFORMANCE CONSIDERATIONS:
	//
	// • Multi-secret operations have higher memory overhead
	// • Prefer batch operations over multiple single-secret calls
	// • Consider secret locality and access patterns
	// • Use appropriate method for expected secret count
	// • Batch related operations within single callback when possible

	// UseSecrets provides secure access to multiple secrets within a single callback.
	//
	// OVERVIEW:
	// This method extends Volta's secure callback pattern to operations requiring
	// multiple secrets simultaneously. It implements atomic retrieval semantics
	// where all secrets must be successfully loaded before any are exposed to the
	// callback, preventing partial secret exposure in error scenarios.
	//
	// CORE PRINCIPLES:
	//
	//   ALL-OR-NOTHING RETRIEVAL:
	//   Either all requested secrets are successfully retrieved and made available
	//   to the callback, or the operation fails completely with no secrets exposed.
	//   This prevents scenarios where some secrets are accessible while others fail,
	//   which could lead to incomplete operations or security vulnerabilities.
	//
	//   SYNCHRONIZED LIFECYCLE:
	//   All secrets share the same lifecycle within the callback scope. They are
	//   simultaneously opened before callback execution and simultaneously destroyed
	//   after callback completion, ensuring no temporal security gaps where some
	//   secrets remain in memory while others are cleared.
	//
	//   MEMGUARD PROTECTION PER SECRET:
	//   Each secret is independently protected using memguard's secure memory
	//   allocation, providing per-secret isolation while maintaining collective
	//   security guarantees. Memory corruption or attacks against one secret
	//   cannot compromise others.
	//
	// SECURITY MODEL:
	// - Atomic exposure (all secrets available simultaneously)
	// - Atomic cleanup (all secrets cleared simultaneously)
	// - Individual memory protection for each secret
	// - Guaranteed cleanup on panic or error conditions
	// - No residual data in system memory after completion
	//
	// USE CASES:
	// • Multi-factor authentication (password + TOTP seed + backup codes)
	// • Cryptographic operations (private key + certificate + CA chain)
	// • API orchestration (primary token + refresh token + service keys)
	// • Database clustering (primary credentials + replica credentials + admin key)
	// • Multi-tenant operations requiring tenant-specific secrets
	//
	// Parameters:
	//   secretIDs: Array of unique secret identifiers. Duplicates will cause error.
	//   fn: Callback receiving map[secretID]secretData for all requested secrets.
	//
	// Returns:
	//   error: nil on success, detailed error on retrieval or callback failure.
	UseSecrets(secretIDs []string, fn func(secrets map[string][]byte) error) error

	// UseSecretsString provides secure access to multiple secrets as UTF-8 strings.
	//
	// OVERVIEW:
	// String-optimized variant of UseSecrets designed specifically for text-based
	// secrets such as passwords, API keys, tokens, and configuration values. This
	// method provides the same security guarantees as UseSecrets while eliminating
	// the need for manual byte-to-string conversion within the callback.
	//
	// STRING HANDLING GUARANTEES:
	//
	//   SECURE CONVERSION:
	//   Byte-to-string conversion occurs within the memguard-protected memory
	//   context, ensuring no intermediate string copies exist in unprotected
	//   heap memory. The string data remains under memguard protection throughout
	//   the callback execution.
	//
	//   UTF-8 SAFETY:
	//   All secrets are treated as UTF-8 encoded strings. Invalid UTF-8 sequences
	//   are handled according to Go's standard string conversion semantics, with
	//   replacement characters used for invalid bytes.
	//
	//   STRING POOL ISOLATION:
	//   The converted strings are ephemeral and do not enter Go's string literal
	//   pool, preventing long-term retention in program memory beyond the callback
	//   scope. Each invocation creates fresh string instances.
	//
	// PERFORMANCE CHARACTERISTICS:
	// - Zero-copy string creation where possible
	// - Batch conversion of all secrets before callback execution
	// - Optimized for scenarios with multiple text-based secrets
	// - Memory overhead equivalent to UseSecrets plus string headers
	//
	// USE CASES:
	// • Configuration management (database URLs + API endpoints + service tokens)
	// • Authentication flows (username + password + MFA codes)
	// • Multi-service API integration (service keys + authentication tokens)
	// • Certificate processing (PEM-encoded certificates + private keys)
	// • Multi-environment deployments (environment-specific credentials)
	//
	// Parameters:
	//   secretIDs: Array of unique secret identifiers for text-based secrets.
	//   fn: Callback receiving map[secretID]secretString for all requested secrets.
	//
	// Returns:
	//   error: nil on success, detailed error on retrieval or callback failure.
	UseSecretsString(secretIDs []string, fn func(secrets map[string]string) error) error

	// UseSecretPair provides secure access to exactly two secrets with ergonomic API.
	//
	// OVERVIEW:
	// Specialized variant optimized for the common pattern of operations requiring
	// exactly two secrets, such as public/private key pairs, username/password
	// combinations, or primary/backup credential sets. This method provides a more
	// ergonomic interface than UseSecrets for two-secret scenarios while maintaining
	// identical security guarantees.
	//
	// DESIGN RATIONALE:
	//
	//   COMPILE-TIME CORRECTNESS:
	//   By accepting exactly two secret parameters and providing them as separate
	//   callback arguments, this method eliminates runtime errors associated with
	//   map key lookups and provides compile-time verification of secret usage
	//   patterns in two-secret operations.
	//
	//   ERGONOMIC ADVANTAGE:
	//   The callback receives secrets as individual named parameters rather than
	//   requiring map access, leading to cleaner, more readable code for common
	//   two-secret patterns. This reduces the cognitive overhead of secret handling
	//   in straightforward scenarios.
	//
	//   SEMANTIC CLARITY:
	//   The method signature clearly communicates the expectation of exactly two
	//   secrets, making the API more self-documenting and reducing the likelihood
	//   of incorrect usage patterns in two-secret scenarios.
	//
	// COMMON PATTERNS:
	// - Asymmetric cryptography (private key + certificate)
	// - Database operations (username + password)
	// - API authentication (client ID + client secret)
	// - Backup strategies (primary credential + backup credential)
	// - Key derivation (base key + salt/password)
	//
	// SECURITY GUARANTEES:
	// Identical to UseSecrets: atomic retrieval, synchronized cleanup, individual
	// memguard protection, and guaranteed cleanup on all exit paths.
	//
	// Parameters:
	//   secretID1: Identifier for the first secret (provided as first callback parameter).
	//   secretID2: Identifier for the second secret (provided as second callback parameter).
	//   fn: Callback receiving both secrets as separate byte slice parameters.
	//
	// Returns:
	//   error: nil on success, detailed error on retrieval or callback failure.
	UseSecretPair(secretID1, secretID2 string, fn func(secret1, secret2 []byte) error) error

	// UseSecretPairString provides secure access to exactly two secrets as UTF-8 strings.
	//
	// OVERVIEW:
	// String-optimized variant of UseSecretPair that combines the ergonomic benefits
	// of two-parameter secret access with automatic string conversion. This method is
	// specifically designed for text-based two-secret operations such as username/password
	// authentication, API key/secret pairs, and configuration key/value combinations.
	//
	// OPTIMIZATION BENEFITS:
	//
	//   TYPE SAFETY:
	//   By providing string parameters directly, this method eliminates the need for
	//   error-prone string conversion within callback functions and provides compile-time
	//   type safety for string-based secret operations.
	//
	//   REDUCED BOILERPLATE:
	//   Applications working with text-based secret pairs can avoid repetitive
	//   byte-to-string conversion code, leading to cleaner and more maintainable
	//   secret handling logic.
	//
	//   SEMANTIC PRECISION:
	//   The method name and signature clearly indicate intent to work with text-based
	//   secrets, improving code self-documentation and reducing the likelihood of
	//   type-related errors in string secret operations.
	//
	// TYPICAL APPLICATIONS:
	// - User authentication (username + password verification)
	// - OAuth flows (client_id + client_secret)
	// - Database connections (username + password for connection strings)
	// - API integrations (API key + API secret)
	// - Certificate operations (certificate PEM + private key PEM)
	// - Configuration pairs (encryption key + signing key as text)
	//
	// STRING PROCESSING NOTES:
	// - All UTF-8 encoding considerations from UseSecretsString apply
	// - Both secrets are converted within secure memory context
	// - No intermediate string copies in unprotected memory
	// - Strings are ephemeral and cleared on callback completion
	//
	// Parameters:
	//   secretID1: Identifier for the first secret (provided as first string parameter).
	//   secretID2: Identifier for the second secret (provided as second string parameter).
	//   fn: Callback receiving both secrets as separate string parameters.
	//
	// Returns:
	//   error: nil on success, detailed error on retrieval or callback failure.
	UseSecretPairString(secretID1, secretID2 string, fn func(secret1, secret2 string) error) error

	// SecureMemoryProtection returns information about the memory protection
	// mechanisms currently active for this vault instance.
	//
	// This can include details about memory locking (mlock), guard pages,
	// secure allocation methods, or other platform-specific protections.
	//
	// Returns:
	//   - string: Human-readable description of active memory protection features
	//
	// The returned information is primarily for diagnostic and security
	// assessment purposes. Different implementations may provide different
	// levels of memory protection based on platform capabilities.
	//
	// Example:
	//   protection := vault.SecureMemoryProtection()
	//   fmt.Printf("Memory protection: %s\n", protection)
	//   // Output might be: "mlock enabled, guard pages active, secure heap in use"
	SecureMemoryProtection() string

	// RotatePassphrase changes the vault's master passphrase used for key derivation.
	//
	// This operation re-encrypts all key material with a new Key Encryption Key (KEK)
	// derived from the new passphrase. This is a sensitive operation that affects
	// the security of all stored keys and secrets.
	//
	// Parameters:
	//   - newPassphrase: The new passphrase to use (should meet security requirements)
	//   - reason: Human-readable explanation for the rotation (for audit logs)
	//
	// Returns:
	//   - error: Error if rotation fails (weak passphrase, cryptographic failure, etc.)
	//
	// Security Notes:
	//   - The operation is atomic - either fully succeeds or leaves vault unchanged
	//   - Old passphrase-derived keys are securely wiped from memory
	//   - All key re-encryption is performed in memory before persisting
	//   - The operation is logged extensively for audit purposes
	//
	// Example:
	//   err := vault.RotatePassphrase("new-strong-passphrase-123!", "security policy compliance")
	//   if err != nil {
	//       return fmt.Errorf("passphrase rotation failed: %w", err)
	//   }
	//   fmt.Println("Passphrase successfully rotated")
	RotatePassphrase(newPassphrase string, reason string) error

	// GetAudit returns the audit logger instance used by this vault.
	//
	// The audit logger captures all significant operations performed by the vault,
	// including key operations, secret access, administrative changes, and security events.
	// This supports compliance requirements, security monitoring, and forensic analysis.
	//
	// Returns:
	//   - audit.Logger: The audit logger instance (never nil for properly initialized vaults)
	//
	// The audit logger typically records:
	//   - Timestamp and operation type
	//   - User/session context (where available)
	//   - Resource identifiers (key IDs, secret IDs)
	//   - Operation outcomes (success/failure)
	//   - Security-relevant events (authentication failures, suspicious patterns)
	//
	// Example:
	//   auditLogger := vault.GetAudit()
	//   auditLogger.LogSecurityEvent("vault_accessed", map[string]interface{}{
	//       "source_ip": "192.168.1.100",
	//       "user_agent": "MyApplication/1.0",
	//   })
	GetAudit() audit.Logger

	// DeleteTenant securely removes all resources (secrets, keys, metadata) associated with a tenant.
	// This operation is irreversible, ensuring that no data can be recovered after deletion.
	DeleteTenant(tenantID string) error
}
