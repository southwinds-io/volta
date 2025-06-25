package persist

import (
	"fmt"
	"time"
)

// VersionedData represents data with its version information
type VersionedData struct {
	Data      []byte
	Version   string // ETag, version number, or hash
	Timestamp time.Time
}

// Store defines the interface for persisting vault data.
// The methods in this interface allow for the management of tenant information,
// vault metadata, salt, secrets, and backup operations. All data passed to
// this interface is assumed to be encrypted by the vault layer, ensuring
// security and confidentiality.
type Store interface {

	// Tenants

	// ListTenants retrieves a list of tenant IDs currently stored in the vault.
	// Returns:
	// - A slice of strings containing tenant IDs.
	// - An error if the operation fails.
	ListTenants() ([]string, error)

	// DeleteTenant removes the specified tenant from the vault.
	// Parameters:
	// - tenantID: The ID of the tenant to be deleted.
	// Returns:
	// - An error if the operation fails, or if the tenant does not exist.
	DeleteTenant(tenantID string) error

	// Vault operations

	SaveMetadata(encryptedMetadata []byte, expectedVersion string) (newVersion string, err error)

	// LoadMetadata retrieves the encrypted metadata from the vault.
	// Returns:
	// - A byte slice containing the encrypted metadata.
	// - An error if the operation fails or if no metadata exists.
	LoadMetadata() (*VersionedData, error)

	// MetadataExists checks if metadata is present in the vault.
	// Returns:
	// - A boolean indicating whether metadata exists.
	// - An error if the operation fails.
	MetadataExists() (bool, error)

	SaveSalt(saltData []byte, expectedVersion string) (newVersion string, err error)

	// LoadSalt retrieves the salt data from the vault.
	// Returns:
	// - A byte slice containing the salt data.
	// - An error if the operation fails or if no salt data exists.
	LoadSalt() (*VersionedData, error)

	// SaltExists checks if salt data is present in the vault.
	// Returns:
	// - A boolean indicating whether salt data exists.
	// - An error if the operation fails.
	SaltExists() (bool, error)

	// Secrets operations

	SaveSecretsData(encryptedSecretsData []byte, expectedVersion string) (newVersion string, err error)

	LoadSecretsData() (*VersionedData, error)

	// SecretsDataExists checks if encrypted secrets data is present in the vault.
	// Returns:
	// - A boolean indicating whether secrets data exists.
	// - An error if the operation fails.
	SecretsDataExists() (bool, error)

	// Backup operations

	// SaveBackup stores a backup of the vault's data.
	// Parameters:
	// - backupPath: A string specifying the path where the backup will be saved.
	// - container: A pointer to a BackupContainer containing the backup data.
	// Returns:
	// - An error if the operation fails.
	SaveBackup(backupPath string, container *BackupContainer) error

	// RestoreBackup restores the vault's data from a backup.
	// Parameters:
	// - backupPath: A string specifying the path from which the backup will be restored.
	// Returns:
	// - A pointer to a BackupContainer containing the restored data.
	// - An error if the operation fails or if the backup does not exist.
	RestoreBackup(backupPath string) (*BackupContainer, error)

	// ListBackups retrieves a list of backup information.
	// Returns:
	// - A slice of BackupInfo structures containing information about the backups.
	// - An error if the operation fails.
	ListBackups() ([]BackupInfo, error)

	// DeleteBackup removes a specified backup from the vault.
	// Parameters:
	// - backupID: The ID of the backup to be deleted.
	// Returns:
	// - An error if the operation fails or if the backup does not exist.
	DeleteBackup(backupID string) error

	// Health and utilities

	// Ping tests the connectivity for remote backends.
	// Returns:
	// - An error if the connectivity test fails.
	Ping() error // Test connectivity for remote backends

	// Close closes the store and releases any resources it holds.
	// Returns:
	// - An error if the operation fails.
	Close() error

	// GetType retrieves the type of store being used.
	// Returns:
	// - A string indicating the type of store (e.g., "SQL", "NoSQL", "InMemory").
	GetType() string
}

// BackupContainer represents the outer backup format with metadata
type BackupContainer struct {
	// BackupID is a universally unique identifier (UUID) assigned to each backup for tracking purposes.
	// It ensures that each backup can be uniquely identified and referenced throughout the storage and restoration processes.
	BackupID string `json:"backup_id"`

	// BackupTimestamp indicates the precise timestamp when the backup was created.
	// This field captures the date and time of the backup creation, allowing users to manage and restore backups from specific points in time.
	BackupTimestamp time.Time `json:"backup_timestamp"`

	// VaultVersion specifies the version of the vault system that created the backup.
	// This helps in understanding compatibility and features available at the time the backup was made.
	VaultVersion string `json:"vault_version"`

	// BackupVersion denotes the version of the backup format used in this container.
	// Different versions may have different structures or capabilities, so tracking this ensures proper handling during backups and restores.
	BackupVersion string `json:"backup_version"`

	// Checksum is a SHA-256 hash of the EncryptedData.
	// This serves as a verification mechanism to ensure the integrity of the backup data. It allows users to confirm that the data has not been altered or corrupted.
	Checksum string `json:"checksum"`

	// EncryptionMethod describes the method used for encrypting the backup data.
	// For example, it may indicate "vault+passphrase", providing users insight into the security measures employed for protecting the data.
	EncryptionMethod string `json:"encryption_method"`

	// EncryptedData contains the actual backup data in an encrypted format.
	// This data is typically base64 encoded to ensure it can be safely transmitted over various mediums without corruption.
	EncryptedData string `json:"encrypted_data"`

	// TenantID identifies the tenant or user associated with the backup.
	// This field is crucial for multi-tenant environments where backups belong to different users or organizations, helping to ensure data isolation and correct access.
	TenantID string `json:"tenant_id"`
}

// BackupData represents the actual vault data to be backed up.
// It contains sensitive information that is necessary for restoring
// the vault's state in the event of data loss or corruption.
// The structure is organized to facilitate secure and efficient backups.
type BackupData struct {
	// Salt is a byte slice that stores a randomly generated salt used
	// for hashing keys. This adds an additional layer of security
	// by ensuring that stored keys are unique even if the same
	// key is used multiple times. The salt should be sufficiently
	// random and unique for each backup instance.
	Salt []byte `json:"salt,omitempty"`

	// VaultMetadata stores metadata about the vault's keys, including
	// information that helps in identifying and managing the keys.
	// This could include attributes such as key creation dates,
	// encryption algorithms, and other related key information.
	VaultMetadata []byte `json:"vault_metadata,omitempty"`

	// SecretsData contains all the secrets along with their
	// associated metadata. This is where sensitive information like
	// passwords, API keys, and other confidential data are stored.
	// Proper encryption should be applied to this data to prevent
	// unauthorized access.
	SecretsData []byte `json:"secrets_data,omitempty"`
}

// BackupInfo holds essential metadata about a backup that is stored
// without requiring decryption. It provides key details such as the
// unique identifier, timestamps, version information, and validation
// status of the backup file. This information is useful for monitoring,
// auditing, and managing backups efficiently in a storage system.
type BackupInfo struct {
	// BackupID uniquely identifies the backup instance.
	// This ID can be used to retrieve or reference this specific backup.
	BackupID string `json:"backup_id"`

	// BackupTimestamp marks the exact date and time when the backup was created.
	// This timestamp is crucial for determining the age of the backup
	// and for managing retention policies.
	BackupTimestamp time.Time `json:"backup_timestamp"`

	// VaultVersion indicates the version of the vault where the backup is stored.
	// This version information can help in ensuring compatibility
	// and understanding the features available in the backup.
	VaultVersion string `json:"vault_version"`

	// BackupVersion specifies the version of the backup itself.
	// This is important for keeping track of changes or improvements
	// made to the backup format or data structure over time.
	BackupVersion string `json:"backup_version"`

	// EncryptionMethod describes the encryption algorithm or method
	// used to secure the contents of the backup.
	// Knowing the method is essential for verifying security
	// and understanding how to properly access the backup data.
	EncryptionMethod string `json:"encryption_method"`

	// FileSize represents the size of the backup file in bytes.
	// This field is useful for assessing storage requirements and
	// for monitoring disk usage.
	FileSize int64 `json:"file_size"`

	// IsValid indicates the result of the checksum validation.
	// A value of true means the backup file is considered valid
	// and has not been corrupted, while false indicates potential issues
	// with the integrity of the backup.
	IsValid bool `json:"is_valid"` // checksum validation result

	// TenantID denotes the unique identifier for the tenant or customer
	// associated with the backup. This allows for multi-tenant support
	// and ensures data segregation for privacy and security.
	TenantID string `json:"tenant_id"`

	Checksum string `json:"checksum"`

	StorePath string `json:"store_path"` // Store-agnostic path/identifier
}

// DetailedBackupInfo provides detailed information regarding a backup that requires decryption.
// It includes counts and sizes of keys and secrets, as well as flags indicating the presence of specific features.
type DetailedBackupInfo struct {
	BackupInfo // Embedded basic info containing general backup metadata.

	// KeyCount represents the total number of encryption keys included in the backup.
	// This field helps to understand how many keys may need to be managed during restoration.
	KeyCount int `json:"key_count"`

	// SecretCount indicates the total number of secrets stored in the backup.
	// It is crucial for determining the volume of sensitive information that needs to be handled.
	SecretCount int `json:"secret_count"`

	// TotalKeySize specifies the cumulative size, in bytes, of all keys included in the backup.
	// This metric can assist in evaluating the overall footprint of the keys on storage.
	TotalKeySize int64 `json:"total_key_size"`

	// TotalSecretSize represents the total size, in bytes, of all secrets contained in the backup.
	// Similar to TotalKeySize, this field is vital for understanding the storage impact of the secrets.
	TotalSecretSize int64 `json:"total_secret_size"`

	// HasSalt indicates whether the backup includes salt values for enhancing cryptographic security.
	// A true value means that salt is present, which can provide additional protection against attacks.
	HasSalt bool `json:"has_salt"`

	// HasMetadata signifies if the backup contains metadata that may be relevant for data restoration.
	// If true, it implies that additional information beyond just keys and secrets is available.
	HasMetadata bool `json:"has_metadata"`
}

// StoreConfig provides configuration for different storage backends.
//
// The StoreConfig struct is designed to hold the parameters needed to interact with
// various storage systems. It consists of a type that specifies which storage
// backend to use, and a configuration map that contains specific settings for
// that backend. Supported storage types may vary and can include file systems,
// cloud storage services, and potentially others in the future.
//
// Example usage:
//
//	config := StoreConfig{
//	    Type:   StoreTypeFileSystem,
//	    Config: map[string]interface{}{"path": "/data/storage"},
//	}
type StoreConfig struct {
	// Type specifies the storage backend to be used.
	// This field must be one of the predefined StoreType constants.
	// Example values: "filesystem", "s3".
	Type StoreType `json:"type"`

	// Config contains configuration settings specific to the chosen storage backend.
	// This is a map of key-value pairs where the key is a string and the value is
	// of an empty interface type, allowing for flexibility. The actual keys and values
	// will depend on the requirements of the specific storage type in use.
	// For example, when using StoreTypeS3, this may include keys like "bucketName" and "region".
	Config map[string]interface{} `json:"config"`
}

// StoreType represents the different types of storage backends that can be used.
type StoreType string

// Supported storage types.
const (
	// StoreTypeFileSystem indicates that the file system should be used for storage.
	// Configuration related to file system paths will be provided in the Config field.
	StoreTypeFileSystem StoreType = "filesystem"

	// StoreTypeS3 indicates that Amazon S3 should be used as the storage backend.
	// Configuration related to S3, such as bucketName name and credentials, will be provided in the Config field.
	StoreTypeS3 StoreType = "s3"
)

// ConcurrencyError represents version conflict errors
type ConcurrencyError struct {
	ExpectedVersion string
	ActualVersion   string
	Operation       string
}

func (e ConcurrencyError) Error() string {
	return fmt.Sprintf("version conflict in %s: expected version %s, but found %s",
		e.Operation, e.ExpectedVersion, e.ActualVersion)
}

func (e ConcurrencyError) IsConcurrencyError() bool {
	return true
}
