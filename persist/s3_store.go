package persist

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"southwinds.dev/volta/internal/crypto"
	"southwinds.dev/volta/internal/debug"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	ctxTimeout = 10 * time.Second
)

// S3Store implements the Store interface using MinIO as the backend with multitenancy.
// S3 Object Structure (with multitenancy):
// This structure outlines how tenant data is organized within the specified S3 bucketName, facilitating
// data isolation and management of backups for each tenant.
//
// bucketName/
// ├── [keyPrefix/]tenant1/
// │   ├── vault.meta          # Vault metadata (encrypted keys + key metadata) for tenant1
// │   ├── vault.salt          # Key derivation salt for tenant1
// │   ├── secrets.meta        # All secrets + secret metadata (encrypted) for tenant1
// │   └── backups/
// │       ├── backup_20240101_120000.vault  # Backup file for tenant1 dated 2024-01-01
// │       └── backup_20240102_130000.vault  # Backup file for tenant1 dated 2024-01-02
// ├── [keyPrefix/]tenant2/
// │   ├── vault.meta          # Vault metadata for tenant2
// │   ├── vault.salt          # Key derivation salt for tenant2
// │   ├── secrets.meta        # All secrets + secret metadata for tenant2
// │   └── backups/
// │       ├── backup_20240101_120000.vault  # Backup file for tenant2 dated 2024-01-01
// │       └── backup_20240102_130000.vault  # Backup file for tenant2 dated 2024-01-02
// └── [keyPrefix/]default/
// ├── vault.meta          # Vault metadata for default tenant
// ├── vault.salt          # Key derivation salt for default tenant
// ├── secrets.meta        # All secrets + secret metadata for default tenant
// └── backups/
// ├── backup_20240101_120000.vault  # Backup file for default tenant dated 2024-01-01
// └── backup_20240102_130000.vault  # Backup file for default tenant dated 2024-01-02
type S3Store struct {
	// client is the MinIO client used to interact with the MinIO server.
	client *minio.Client

	// bucketName is the name of the S3 bucketName used to store tenant data and backups.
	bucketName string

	// keyPrefix is an optional prefix for the keys in the bucketName, allowing for namespace separation
	// if multiple applications use the same bucketName.
	keyPrefix string

	// tenantID uniquely identifies the tenant whose data is being stored. This is used to correctly
	// route requests and ensure data isolation between different tenants.
	tenantID string
}

// NewS3Store initializes a new S3Store instance using the provided S3 configuration
// and tenant ID. It establishes a connection to a MinIO server and ensures that the
// specified bucketName exists. If no tenant ID is provided, it defaults to "default".
//
// Parameters:
//   - config (S3Config): Configuration structure containing:
//   - Endpoint (string): The endpoint URL for the MinIO server.
//   - AccessKeyID (string): The access key ID for authentication.
//   - SecretAccessKey (string): The secret access key for authentication.
//   - UseSSL (bool): Indicates whether to use SSL for the connection.
//   - Region (string): The region where the MinIO server is located.
//   - Bucket (string): The name of the bucketName to use.
//   - KeyPrefix (string): A prefix for keys stored in the bucketName.
//   - tenantID (string): A unique identifier for the tenant. If not provided, defaults to "default".
//
// Returns:
//   - (*S3Store, error): A pointer to an S3Store instance if successful, or an error in case of failure.
//
// Errors:
//   - Returns an error if the tenant ID is invalid, if the MinIO client fails to initialize,
//     if the bucketName does not exist, or if vault configuration initialization fails.
func NewS3Store(config S3Config, tenantID string) (*S3Store, error) {
	if tenantID == "" {
		tenantID = "default"
	}

	// Validate tenant ID (basic security check)
	if err := validateTenantID(tenantID); err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Create MinIO client
	client, err := minio.New(config.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
		Region: config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	store := &S3Store{
		client:     client,
		bucketName: config.Bucket,
		keyPrefix:  config.KeyPrefix,
		tenantID:   tenantID,
	}

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Ensure bucketName exists (REMOVE THE DUPLICATE)
	if err = store.ensureBucket(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to ensure bucketName exists: %w", err)
	}

	// Initialize vault config (similar to FileSystemStore)
	if err = store.initializeVaultConfig(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize vault config: %w", err)
	}

	return store, nil
}

// NewS3StoreFromConfig initializes a new S3Store instance from the given StoreConfig.
// It validates the store type and unmarshals the configuration.
//
// Parameters:
//   - config: Configuration parameters for the storage backend.
//   - tenantID: The ID representing the tenant using the store.
//
// Returns:
//   - A pointer to the newly created S3Store if successful, or an error.
func NewS3StoreFromConfig(config StoreConfig, tenantID string) (*S3Store, error) {
	if config.Type != StoreTypeS3 {
		return nil, fmt.Errorf("invalid store type for MinIO: %s", config.Type)
	}

	// Parse the config map into S3Config
	configBytes, err := json.Marshal(config.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var s3Config S3Config
	if err = json.Unmarshal(configBytes, &s3Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal S3 config: %w", err)
	}

	return NewS3Store(s3Config, tenantID)
}

// S3Config contains the configuration required to connect to S3 (MinIO).
type S3Config struct {
	Endpoint        string // The endpoint for the S3 service.
	AccessKeyID     string // The Access Key ID for accessing the S3 service.
	SecretAccessKey string // The Secret Access Key for accessing the S3 service.
	Bucket          string // The S3 bucketName to use.
	KeyPrefix       string // The prefix for keys stored in the S3 bucketName.
	UseSSL          bool   // Whether to use SSL for the connection.
	Region          string // The region of the S3 bucketName.
}

func (s3s *S3Store) initializeVaultConfig(ctx context.Context) error {
	objectName := s3s.buildTenantPath("vault.config")

	// Add debugging to see what object name is generated
	debug.Print("Generated object name: '%s'\n", objectName)
	debug.Print("Tenant ID: '%s'\n", s3s.tenantID)
	debug.Print("Key prefix: '%s'\n", s3s.keyPrefix)

	// Check if config already exists
	_, err := s3s.client.StatObject(ctx, s3s.bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		// Check if it's a not found error
		if minioErr := minio.ToErrorResponse(err); minioErr.Code == "NoSuchKey" {
			// Config doesn't exist, create it
			config := VaultConfig{
				Version:    "1.0.0",
				TenantID:   s3s.tenantID,
				CreatedAt:  time.Now().UTC(),
				LastAccess: time.Now().UTC(),
				Structure:  "v1", // Structure version for migrations
			}

			data, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal vault config: %w", err)
			}

			_, err = s3s.client.PutObject(
				ctx,
				s3s.bucketName,
				objectName,
				bytes.NewReader(data),
				int64(len(data)),
				minio.PutObjectOptions{
					ContentType: "application/json",
					UserMetadata: map[string]string{
						"vault-config":      "true",
						"data-type":         "vault-config",
						"tenant-id":         s3s.tenantID,
						"version":           config.Version,
						"structure-version": config.Structure,
						"created-at":        config.CreatedAt.Format(time.RFC3339),
					},
				},
			)
			if err != nil {
				return fmt.Errorf("failed to create vault config: %w", err)
			}
		} else {
			return fmt.Errorf("failed to check vault config: %w", err)
		}
	}

	return nil
}

// ListTenants returns all tenant IDs that have vaults in the bucketName
func (s3s *S3Store) ListTenants() ([]string, error) {
	// Build base prefix for listing - fix the logic here
	basePrefix := s3s.keyPrefix
	if basePrefix != "" && !strings.HasSuffix(basePrefix, "/") {
		basePrefix = basePrefix + "/"
	}

	debug.Print("ListTenants: basePrefix: '%s'\n", basePrefix)

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// List all objects to find tenant directories
	objectCh := s3s.client.ListObjects(ctx, s3s.bucketName, minio.ListObjectsOptions{
		Prefix:    basePrefix,
		Recursive: true, // Change to true to get actual files, not just directories
	})

	tenantSet := make(map[string]bool)
	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", object.Err)
		}

		debug.Print("ListTenants: found object: '%s'\n", object.Key)

		// Skip directory entries (objects ending with '/')
		if strings.HasSuffix(object.Key, "/") {
			debug.Print("ListTenants: Skipping directory entry: '%s'\n", object.Key)
			continue
		}

		// Extract tenant ID from object path
		relativePath := strings.TrimPrefix(object.Key, basePrefix)
		debug.Print("ListTenants: Relative path: '%s'\n", relativePath)

		parts := strings.Split(relativePath, "/")
		debug.Print("ListTenants: Parts: %v\n", parts)

		if len(parts) > 0 && parts[0] != "" {
			debug.Print("ListTenants: Adding tenant: '%s'\n", parts[0])
			tenantSet[parts[0]] = true
		}
	}

	// Convert to sorted slice
	var tenants []string
	for tenant := range tenantSet {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)

	debug.Print("ListTenants: Final tenants list: %v\n", tenants)
	return tenants, nil
}

// DeleteTenant removes all data for a tenant (USE WITH EXTREME CAUTION)
func (s3s *S3Store) DeleteTenant(tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Build tenant prefix
	tenantPrefix := s3s.buildTenantPathForTenant(tenantID) + "/"

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// List all objects for this tenant
	objectCh := s3s.client.ListObjects(ctx, s3s.bucketName, minio.ListObjectsOptions{
		Prefix:    tenantPrefix,
		Recursive: true,
	})

	// Collect object names to delete
	var objectNames []string
	for object := range objectCh {
		if object.Err != nil {
			return fmt.Errorf("failed to list tenant objects: %w", object.Err)
		}
		objectNames = append(objectNames, object.Key)
	}

	// Check if tenant exists (has any objects)
	if len(objectNames) == 0 {
		return fmt.Errorf("tenant %s not found or has no data", tenantID)
	}

	// Delete objects in batches
	for _, objectName := range objectNames {
		err := s3s.client.RemoveObject(ctx, s3s.bucketName, objectName, minio.RemoveObjectOptions{})
		if err != nil {
			// Don't fail if object was already deleted
			if minioErr := minio.ToErrorResponse(err); minioErr.Code != "NoSuchKey" {
				return fmt.Errorf("failed to delete object %s: %w", objectName, err)
			}
		}
	}

	return nil
}

func (s3s *S3Store) SaveMetadata(data []byte, expectedVersion string) (string, error) {
	if data == nil {
		return "", fmt.Errorf("metadata cannot be nil")
	}

	ctx := context.Background()
	objectName := s3s.getMetadataObjectName()

	// Set upload options with timestamp
	putOptions := minio.PutObjectOptions{
		UserMetadata: map[string]string{
			"Created-At": time.Now().Format(time.RFC3339),
		},
	}

	// Handle versioning if expectedVersion is provided
	if expectedVersion != "" {
		// Verify current version before update
		current, err := s3s.LoadMetadata()
		if err != nil {
			return "", fmt.Errorf("failed to verify current version: %w", err)
		}

		if current.Version != expectedVersion {
			return "", fmt.Errorf("version conflict: expected %s, found %s", expectedVersion, current.Version)
		}

		// Set if-match condition for atomic update
		putOptions.SetMatchETag(expectedVersion)
	}

	// Upload the object
	uploadInfo, err := s3s.client.PutObject(ctx, s3s.bucketName, objectName,
		bytes.NewReader(data), int64(len(data)), putOptions)
	if err != nil {
		if s3s.isPreconditionFailedError(err) {
			return "", fmt.Errorf("version conflict: metadata was modified by another process")
		}
		return "", fmt.Errorf("failed to save metadata: %w", err)
	}

	return s3s.cleanETag(uploadInfo.ETag), nil
}

func (s3s *S3Store) LoadMetadata() (*VersionedData, error) {
	ctx := context.Background()
	objectName := s3s.getMetadataObjectName()

	// Get object
	object, err := s3s.client.GetObject(ctx, s3s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		if s3s.isNotFoundError(err) {
			return nil, fmt.Errorf("metadata not found")
		}
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}
	defer object.Close()

	// Read object data
	metadataBytes, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	// Get object info for metadata and version
	objectInfo, err := object.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata info: %w", err)
	}

	// Parse timestamp from metadata, fallback to LastModified
	var timestamp time.Time
	if createdAt, exists := objectInfo.UserMetadata["Created-At"]; exists {
		if parsedTime, err := time.Parse(time.RFC3339, createdAt); err == nil {
			timestamp = parsedTime
		}
	}

	// If no timestamp in metadata or parsing failed, use LastModified
	if timestamp.IsZero() {
		timestamp = objectInfo.LastModified
	}

	return &VersionedData{
		Data:      metadataBytes,
		Version:   s3s.cleanETag(objectInfo.ETag),
		Timestamp: timestamp, // Make sure this is set
	}, nil
}

func (s3s *S3Store) MetadataExists() (bool, error) {
	objectName := s3s.getMetadataObjectName()

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	_, err := s3s.client.StatObject(ctx, s3s.bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check metadata existence: %w", err)
	}

	return true, nil
}

// Salt operations
func (s3s *S3Store) SaveSalt(saltData []byte, expectedVersion string) (string, error) {
	objectName := s3s.getSaltObjectName()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Validate expected version if provided
	if expectedVersion != "" {
		currentVersion, err := s3s.getObjectVersion(ctx, objectName)
		if err != nil {
			return "", fmt.Errorf("failed to check current version: %w", err)
		}
		if currentVersion != expectedVersion {
			return "", ConcurrencyError{
				ExpectedVersion: expectedVersion,
				ActualVersion:   currentVersion,
				Operation:       "SaveSalt",
			}
		}
	}

	// Create metadata (consistent with FileSystem store)
	putOptions := minio.PutObjectOptions{
		ContentType:  "application/octet-stream",
		UserMetadata: createSaltMetadata(s3s.tenantID),
	}

	info, err := s3s.client.PutObject(ctx, s3s.bucketName, objectName,
		bytes.NewReader(saltData), int64(len(saltData)), putOptions)
	if err != nil {
		if s3s.isPreconditionFailedError(err) {
			currentVersion, _ := s3s.getObjectVersion(ctx, objectName)
			return "", ConcurrencyError{
				ExpectedVersion: expectedVersion,
				ActualVersion:   currentVersion,
				Operation:       "SaveSalt",
			}
		}
		return "", fmt.Errorf("failed to save salt: %w", err)
	}

	return s3s.cleanETag(info.ETag), nil
}

func (s3s *S3Store) LoadSalt() (*VersionedData, error) {
	objectName := s3s.getSaltObjectName()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Get object with metadata
	object, err := s3s.client.GetObject(ctx, s3s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		if s3s.isNotFoundError(err) {
			return nil, fmt.Errorf("salt not found")
		}
		return nil, fmt.Errorf("failed to load salt: %w", err)
	}
	defer object.Close()

	// Read object data
	saltData, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("failed to read salt data: %w", err)
	}

	// Get object info for metadata and version
	objectInfo, err := object.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get salt metadata: %w", err)
	}

	// Parse timestamp from metadata
	var timestamp time.Time
	if createdAt, exists := objectInfo.UserMetadata["Created-At"]; exists {
		if parsedTime, err := time.Parse(time.RFC3339, createdAt); err == nil {
			timestamp = parsedTime
		}
	}

	// If no timestamp in metadata, use LastModified as fallback
	if timestamp.IsZero() {
		timestamp = objectInfo.LastModified
	}

	return &VersionedData{
		Data:      saltData,
		Version:   s3s.cleanETag(objectInfo.ETag),
		Timestamp: timestamp,
	}, nil
}

func (s3s *S3Store) SaltExists() (bool, error) {
	objectName := s3s.getSaltObjectName()

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	_, err := s3s.client.StatObject(ctx, s3s.bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check salt existence: %w", err)
	}

	return true, nil
}

// Secrets operations
func (s3s *S3Store) SaveSecretsData(data []byte, expectedVersion string) (string, error) {
	if data == nil {
		return "", fmt.Errorf("secrets data cannot be nil")
	}

	ctx := context.Background()
	objectName := s3s.getSecretsMetaObjectName()

	// Set upload options with timestamp
	putOptions := minio.PutObjectOptions{
		UserMetadata: map[string]string{
			"Created-At": time.Now().Format(time.RFC3339),
		},
	}

	// Handle versioning if expectedVersion is provided
	if expectedVersion != "" {
		// Verify current version before update
		current, err := s3s.LoadSecretsData()
		if err != nil {
			return "", fmt.Errorf("failed to verify current version: %w", err)
		}

		if current.Version != expectedVersion {
			return "", fmt.Errorf("version conflict: expected %s, found %s", expectedVersion, current.Version)
		}

		// Set if-match condition for atomic update
		putOptions.SetMatchETag(expectedVersion)
	}

	// Upload the object
	uploadInfo, err := s3s.client.PutObject(ctx, s3s.bucketName, objectName,
		bytes.NewReader(data), int64(len(data)), putOptions)
	if err != nil {
		if s3s.isPreconditionFailedError(err) {
			return "", fmt.Errorf("version conflict: secrets data was modified by another process")
		}
		return "", fmt.Errorf("failed to save secrets data: %w", err)
	}

	return s3s.cleanETag(uploadInfo.ETag), nil
}

func (s3s *S3Store) LoadSecretsData() (*VersionedData, error) {
	ctx := context.Background()
	objectName := s3s.getSecretsMetaObjectName()

	// Get object
	object, err := s3s.client.GetObject(ctx, s3s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		if s3s.isNotFoundError(err) {
			return nil, fmt.Errorf("secrets data not found")
		}
		return nil, fmt.Errorf("failed to load secrets data: %w", err)
	}
	defer object.Close()

	// Read object data
	secretsBytes, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets data: %w", err)
	}

	// Get object info for metadata and version
	objectInfo, err := object.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets data info: %w", err)
	}

	// Parse timestamp from metadata, fallback to LastModified
	var timestamp time.Time
	if createdAt, exists := objectInfo.UserMetadata["Created-At"]; exists {
		if parsedTime, err := time.Parse(time.RFC3339, createdAt); err == nil {
			timestamp = parsedTime
		}
	}

	// If no timestamp in metadata or parsing failed, use LastModified
	if timestamp.IsZero() {
		timestamp = objectInfo.LastModified
	}

	return &VersionedData{
		Data:      secretsBytes,
		Version:   s3s.cleanETag(objectInfo.ETag),
		Timestamp: timestamp,
	}, nil
}

func (s3s *S3Store) SecretsDataExists() (bool, error) {
	objectName := s3s.getSecretsMetaObjectName()

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	_, err := s3s.client.StatObject(ctx, s3s.bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secrets data existence: %w", err)
	}

	return true, nil
}

// Backup operations
func (s3s *S3Store) SaveBackup(backupPath string, container *BackupContainer) error {
	// Serialize the backup container
	data, err := json.Marshal(container)
	if err != nil {
		return fmt.Errorf("failed to marshal backup container: %w", err)
	}

	// Build the object path
	objectPath := s3s.buildTenantPath("backups") + "/" + backupPath + ".vault"

	// Use consistent lowercase-hyphen keys for maximum portability across S3 backends
	metadata := map[string]string{
		"backup-id":         container.BackupID,
		"backup-version":    container.BackupVersion,
		"vault-version":     container.VaultVersion,
		"encryption-method": container.EncryptionMethod,
		"checksum":          container.Checksum,
		"tenant-id":         container.TenantID,
		"backup-timestamp":  container.BackupTimestamp.Format(time.RFC3339),
	}

	debug.Print("ListBackups:  SaveBackup: Saving to path: %s\n", objectPath)
	debug.Print("ListBackups:  SaveBackup: Metadata to save:\n")
	for key, value := range metadata {
		debug.Print("ListBackups:  SaveBackup:   %s = %s\n", key, value)
	}

	// Create reader from serialized data
	reader := bytes.NewReader(data)

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Save to S3 with metadata
	putInfo, err := s3s.client.PutObject(ctx, s3s.bucketName, objectPath, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType:  "application/json",
		UserMetadata: metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to save backup to S3: %w", err)
	}

	debug.Print("ListBackups:  SaveBackup: Successfully saved backup, size: %d\n", putInfo.Size)

	return nil
}

func (s3s *S3Store) RestoreBackup(backupPath string) (*BackupContainer, error) {
	// Validate backup path
	if backupPath == "" {
		return nil, fmt.Errorf("backup path cannot be empty")
	}

	// Build object name
	objectName := s3s.buildTenantPath("backups", backupPath+".vault")

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Get the backup object
	object, err := s3s.client.GetObject(ctx, s3s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("backup '%s' not found for tenant %s", backupPath, s3s.tenantID)
		}
		return nil, fmt.Errorf("failed to get backup: %w", err)
	}
	defer object.Close()

	// Read container data
	containerData, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup container: %w", err)
	}

	// Unmarshal container
	var container BackupContainer
	if err := json.Unmarshal(containerData, &container); err != nil {
		return nil, fmt.Errorf("failed to parse backup container: %w", err)
	}

	// Basic validation
	if container.BackupID == "" {
		return nil, fmt.Errorf("invalid backup: missing backup ID")
	}

	if container.BackupVersion == "" {
		return nil, fmt.Errorf("invalid backup: missing backup version")
	}

	if container.EncryptedData == "" {
		return nil, fmt.Errorf("invalid backup: missing encrypted data")
	}

	// Warn if backup is from a different tenant
	if container.TenantID != "" && container.TenantID != s3s.tenantID {
		fmt.Printf("Warning: Restoring backup from tenant %s to tenant %s\n",
			container.TenantID, s3s.tenantID)
	}

	return &container, nil
}

func (s3s *S3Store) DeleteBackup(backupID string) error {
	debug.Print(" DeleteBackup: Looking for backup with ID: %s\n", backupID)

	// List backups to find the one with matching ID
	backups, err := s3s.ListBackups()
	if err != nil {
		return fmt.Errorf("failed to list backups for deletion: %w", err)
	}

	var storePath string
	for _, backup := range backups {
		if backup.BackupID == backupID {
			storePath = backup.StorePath
			break
		}
	}

	if storePath == "" {
		return fmt.Errorf("backup %s not found for tenant %s", backupID, s3s.tenantID)
	}

	debug.Print(" DeleteBackup: Deleting backup at store path: %s\n", storePath)

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Delete the backup object using the store path as S3 object key
	err = s3s.client.RemoveObject(ctx, s3s.bucketName, storePath, minio.RemoveObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code != "NoSuchKey" {
			return fmt.Errorf("failed to delete backup '%s': %w", backupID, err)
		}
	}

	debug.Print(" DeleteBackup: Successfully deleted backup: %s\n", backupID)
	return nil
}

func (s3s *S3Store) ListBackups() ([]BackupInfo, error) {
	prefix := s3s.buildTenantPath("backups") + "/"

	debug.Print("ListBackups: Looking for backups with prefix: %s\n", prefix)

	var backups []BackupInfo

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// List objects to get the file list
	objectCh := s3s.client.ListObjects(ctx, s3s.bucketName, minio.ListObjectsOptions{
		Prefix: prefix,
	})

	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("error listing objects: %w", object.Err)
		}

		// Skip if not a vault file
		if !strings.HasSuffix(object.Key, ".vault") {
			continue
		}

		debug.Print("ListBackups: Found vault file: %s\n", object.Key)

		// Use StatObject to get metadata (ListObjects doesn't include user metadata)
		statInfo, err := s3s.client.StatObject(ctx, s3s.bucketName, object.Key, minio.StatObjectOptions{})
		if err != nil {
			debug.Print("ListBackups: Failed to stat object %s: %v\n", object.Key, err)
			continue
		}

		debug.Print("ListBackups: StatObject found %d metadata entries\n", len(statInfo.UserMetadata))

		// Convert StatObject result to ObjectInfo format for getBackupInfoFromMetadata
		objectInfo := minio.ObjectInfo{
			Key:          statInfo.Key,
			LastModified: statInfo.LastModified,
			Size:         statInfo.Size,
			ContentType:  statInfo.ContentType,
			UserMetadata: statInfo.UserMetadata,
		}

		// Extract backup info from metadata
		backupInfo, err := s3s.getBackupInfoFromMetadata(objectInfo)
		if err != nil {
			debug.Print("ListBackups:  ListBackups: Failed to extract metadata for %s: %v\n", object.Key, err)
			// Create a minimal BackupInfo for invalid backups
			backupInfo = &BackupInfo{
				BackupID:        extractBackupIDFromPath(object.Key),
				BackupTimestamp: object.LastModified,
				TenantID:        s3s.tenantID,
				FileSize:        object.Size,
				IsValid:         false,
			}
		}

		backups = append(backups, *backupInfo)
	}

	debug.Print("ListBackups: Found %d total backups\n", len(backups))
	return backups, nil
}

// Helper function to extract backup ID from file path when metadata is missing
func extractBackupIDFromPath(objectKey string) string {
	// Extract filename without extension
	parts := strings.Split(objectKey, "/")
	if len(parts) == 0 {
		return "unknown"
	}

	filename := parts[len(parts)-1]
	if strings.HasSuffix(filename, ".vault") {
		return strings.TrimSuffix(filename, ".vault")
	}

	return filename
}

// Health and utilities
func (s3s *S3Store) Ping() error {
	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// For S3, test connectivity by checking if bucketName exists
	exists, err := s3s.client.BucketExists(ctx, s3s.bucketName)
	if err != nil {
		return fmt.Errorf("failed to ping S3: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucketName %s does not exist", s3s.bucketName)
	}
	return nil
}

func (s3s *S3Store) Close() error {
	// Update last access time in config (similar to FileSystemStore)
	objectName := s3s.buildTenantPath("vault.config")

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Try to load existing config
	object, err := s3s.client.GetObject(ctx, s3s.bucketName, objectName, minio.GetObjectOptions{})
	if err == nil {
		defer object.Close()

		if configData, err := io.ReadAll(object); err == nil {
			var config VaultConfig
			if err := json.Unmarshal(configData, &config); err == nil {
				// Update last access time
				config.LastAccess = time.Now().UTC()

				if updatedData, err := json.MarshalIndent(config, "", "  "); err == nil {
					// Save updated config
					_, _ = s3s.client.PutObject(
						ctx,
						s3s.bucketName,
						objectName,
						bytes.NewReader(updatedData),
						int64(len(updatedData)),
						minio.PutObjectOptions{
							ContentType: "application/json",
							UserMetadata: map[string]string{
								"vault-config": "true",
								"data-type":    "vault-config",
								"tenant-id":    s3s.tenantID,
								"updated-at":   time.Now().UTC().Format(time.RFC3339),
							},
						},
					)
				}
			}
		}
	}
	return nil
}

func (s3s *S3Store) GetType() string {
	return string(StoreTypeS3)
}

// Helper methods
func (s3s *S3Store) buildPath(components ...string) string {
	var parts []string
	if s3s.keyPrefix != "" {
		parts = append(parts, s3s.keyPrefix)
	}
	parts = append(parts, components...)
	return strings.Join(parts, "/")
}

func (s3s *S3Store) buildTenantPath(components ...string) string {
	return s3s.buildTenantPathForTenant(s3s.tenantID, components...)
}

// Update buildTenantPathForTenant to handle all edge cases
func (s3s *S3Store) buildTenantPathForTenant(tenantID string, components ...string) string {
	var parts []string

	// Add key prefix if it exists and is not empty
	if s3s.keyPrefix != "" {
		// Clean the key prefix - remove leading/trailing slashes
		cleanPrefix := strings.Trim(s3s.keyPrefix, "/")
		if cleanPrefix != "" {
			parts = append(parts, cleanPrefix)
		}
	}

	// Add tenant ID if it exists and is not empty
	if tenantID != "" {
		parts = append(parts, tenantID)
	}

	// Add all components, skipping empty ones
	for _, component := range components {
		if component != "" {
			parts = append(parts, component)
		}
	}

	// Join all parts with single slashes
	return strings.Join(parts, "/")
}

func (s3s *S3Store) ensureBucket(ctx context.Context) error {
	exists, err := s3s.client.BucketExists(ctx, s3s.bucketName)
	if err != nil {
		return fmt.Errorf("failed to check if bucketName exists: %w", err)
	}

	if !exists {
		err = s3s.client.MakeBucket(ctx, s3s.bucketName, minio.MakeBucketOptions{})
		if err != nil {
			return fmt.Errorf("failed to create bucketName: %w", err)
		}
	}

	return nil
}

func (s3s *S3Store) getBackupInfoFromMetadata(object minio.ObjectInfo) (*BackupInfo, error) {
	// Debug logging
	debug.Print(" getBackupInfoFromMetadata: === Available metadata for %s ===\n", object.Key)
	debug.Print(" getBackupInfoFromMetadata: UserMetadata count: %d\n", len(object.UserMetadata))

	for k, v := range object.UserMetadata {
		debug.Print(" getBackupInfoFromMetadata: '%s' = '%s'\n", k, v)
	}
	debug.Print(" getBackupInfoFromMetadata: === End of metadata ===\n")

	// Helper function for case-insensitive metadata lookup
	getMetadata := func(metadataMap map[string]string, key string) string {
		// Normalize the search key
		searchKey := strings.ToLower(strings.ReplaceAll(key, "_", "-"))

		for k, v := range metadataMap {
			// Normalize the metadata key
			normalizedKey := strings.ToLower(strings.ReplaceAll(k, "_", "-"))
			if normalizedKey == searchKey {
				return v
			}
		}
		return ""
	}

	// Extract metadata
	backupID := getMetadata(object.UserMetadata, "backup-id")
	vaultVersion := getMetadata(object.UserMetadata, "vault-version")
	backupVersion := getMetadata(object.UserMetadata, "backup-version")
	encryptionMethod := getMetadata(object.UserMetadata, "encryption-method")
	tenantID := getMetadata(object.UserMetadata, "tenant-id")
	checksum := getMetadata(object.UserMetadata, "checksum")
	timestampStr := getMetadata(object.UserMetadata, "backup-timestamp")

	debug.Print(" getBackupInfoFromMetadata: Extracted metadata: backupID='%s', version='%s', tenant='%s'\n",
		backupID, vaultVersion, tenantID)

	// Parse timestamp
	var backupTimestamp time.Time
	if timestampStr != "" {
		if parsed, err := time.Parse(time.RFC3339, timestampStr); err == nil {
			backupTimestamp = parsed
		} else {
			backupTimestamp = object.LastModified
		}
	} else {
		backupTimestamp = object.LastModified
	}

	return &BackupInfo{
		BackupID:         backupID,
		BackupTimestamp:  backupTimestamp,
		VaultVersion:     vaultVersion,
		BackupVersion:    backupVersion,
		EncryptionMethod: encryptionMethod,
		TenantID:         tenantID,
		Checksum:         checksum,
		FileSize:         object.Size,
		IsValid:          backupID != "",
		StorePath:        object.Key, // Store the S3 object key as store path
	}, nil
}

func (s3s *S3Store) getBackupInfoFromContent(backupPath string, fileSize int64) (*BackupInfo, error) {
	// Load the backup to get info
	container, err := s3s.RestoreBackup(backupPath)
	if err != nil {
		return nil, err
	}

	// Verify checksum
	isValid := false
	if container.Checksum != "" && container.EncryptedData != "" {
		encryptedData, err := base64.StdEncoding.DecodeString(container.EncryptedData)
		if err == nil {
			actualChecksum := crypto.CalculateChecksum(encryptedData)
			isValid = actualChecksum == container.Checksum
		}
	}

	// Use current tenant if not specified in backup
	tenantID := container.TenantID
	if tenantID == "" {
		tenantID = s3s.tenantID
	}

	return &BackupInfo{
		BackupID:         container.BackupID,
		BackupTimestamp:  container.BackupTimestamp,
		VaultVersion:     container.VaultVersion,
		BackupVersion:    container.BackupVersion,
		EncryptionMethod: container.EncryptionMethod,
		TenantID:         tenantID,
		FileSize:         fileSize,
		IsValid:          isValid,
	}, nil
}

// Add this method to your S3Store for debugging
func (s3s *S3Store) debugObjectMetadata(objectPath string) {
	debug.Print("debugObjectMetadata: Checking stored metadata for: %s\n", objectPath)

	// Create a fresh context for this operation
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// Get object info directly
	objInfo, err := s3s.client.StatObject(ctx, s3s.bucketName, objectPath, minio.StatObjectOptions{})
	if err != nil {
		debug.Print("debugObjectMetadata: Error getting object info: %v\n", err)
		return
	}

	debug.Print("debugObjectMetadata: StatObject UserMetadata count: %d\n", len(objInfo.UserMetadata))
	for key, value := range objInfo.UserMetadata {
		debug.Print("debugObjectMetadata: StatObject metadata: '%s' = '%s'\n", key, value)
	}
}

// Helper methods for version management
func (s3s *S3Store) getObjectVersion(ctx context.Context, objectName string) (string, error) {
	objInfo, err := s3s.client.StatObject(ctx, s3s.bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return "", nil // Object doesn't exist, version is empty
		}
		return "", err
	}
	return s3s.cleanETag(objInfo.ETag), nil
}

func (s3s *S3Store) cleanETag(etag string) string {
	// Remove quotes from ETag
	return strings.Trim(etag, "\"")
}

func (s3s *S3Store) calculateContentHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func (s3s *S3Store) isPreconditionFailedError(err error) bool {
	if minioErr := minio.ToErrorResponse(err); minioErr.Code == "PreconditionFailed" {
		return true
	}
	return false
}

func (s3s *S3Store) isNotFoundError(err error) bool {
	var errResp minio.ErrorResponse
	if errors.As(err, &errResp) {
		return errResp.Code == "NoSuchKey" || errResp.Code == "NotFound"
	}
	return false
}

func (s3s *S3Store) getMetadataObjectName() string {
	return s3s.buildTenantPath("metadata.json")
}

func (s3s *S3Store) getSaltObjectName() string {
	return s3s.buildTenantPath("vault.salt")
}

func (s3s *S3Store) getSecretsMetaObjectName() string {
	return s3s.buildTenantPath("secrets.meta")
}
