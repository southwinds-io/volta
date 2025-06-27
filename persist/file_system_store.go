package persist

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"southwinds.dev/volta/internal/crypto"
	"southwinds.dev/volta/internal/debug"
	"strings"
	"time"
)

const (
	FilePermissions os.FileMode = 0600
	DirPermissions  os.FileMode = 0700
)

// FileSystemStore implements Store for local filesystem with multitenancy and optimistic concurrency control
type FileSystemStore struct {
	basePath    string
	tenantID    string
	tenantPath  string // basePath/tenantID/
	backupsDir  string // basePath/tenantID/backups/
	tempDir     string // basePath/tenantID/temp/
	vaultConfig string // basePath/tenantID/vault.json
	vaultMeta   string // basePath/tenantID/vault.meta     - vault metadata (keys + key metadata)
	vaultSalt   string // basePath/tenantID/derivation.salt - derivation salt
	secretsMeta string // basePath/tenantID/secrets.meta   - secrets + secret metadata
}

// VaultConfig represents the vault configuration and metadata
type VaultConfig struct {
	Version     string    `json:"version"`
	TenantID    string    `json:"tenant_id"`
	CreatedAt   time.Time `json:"created_at"`
	LastAccess  time.Time `json:"last_access"`
	Structure   string    `json:"structure_version"`
	Description string    `json:"description,omitempty"`
}

// NewFileSystemStore initializes and returns a new instance of FileSystemStore
func NewFileSystemStore(basePath string, tenantID string) (*FileSystemStore, error) {
	if tenantID == "" {
		tenantID = "default"
	}

	// Validate tenant ID (basic security check)
	if err := validateTenantID(tenantID); err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	tenantPath := filepath.Join(basePath, tenantID)

	fs := &FileSystemStore{
		basePath:    basePath,
		tenantID:    tenantID,
		tenantPath:  tenantPath,
		backupsDir:  filepath.Join(tenantPath, "backups"),
		tempDir:     filepath.Join(tenantPath, "temp"),
		vaultConfig: filepath.Join(tenantPath, "vault.json"),
		vaultMeta:   filepath.Join(tenantPath, "vault.meta"),
		vaultSalt:   filepath.Join(tenantPath, "derivation.salt"),
		secretsMeta: filepath.Join(tenantPath, "secrets.meta"),
	}

	// Create necessary directories
	dirs := []string{
		fs.tenantPath,
		fs.backupsDir,
		fs.tempDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, DirPermissions); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Initialize vault config if needed
	if err := fs.initializeVaultConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize vault config: %w", err)
	}

	return fs, nil
}

// NewFileSystemStoreFromConfig creates a FileSystemStore from StoreConfig
func NewFileSystemStoreFromConfig(config StoreConfig, tenantID string) (*FileSystemStore, error) {
	basePath, ok := config.Config["base_path"].(string)
	if !ok {
		return nil, fmt.Errorf("base_path is required for filesystem store")
	}

	return NewFileSystemStore(basePath, tenantID)
}

func (fs *FileSystemStore) initializeVaultConfig() error {
	if _, err := os.Stat(fs.vaultConfig); os.IsNotExist(err) {
		config := VaultConfig{
			Version:    "1.0.0",
			TenantID:   fs.tenantID,
			CreatedAt:  time.Now(),
			LastAccess: time.Now(),
			Structure:  "v1",
		}

		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}

		return writeSecureFile(fs.vaultConfig, data, FilePermissions)
	}
	return nil
}

// ListTenants returns all tenant IDs that have vaults in the base path
func (fs *FileSystemStore) ListTenants() ([]string, error) {
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read base directory: %w", err)
	}

	var tenants []string
	for _, entry := range entries {
		if entry.IsDir() {
			vaultConfigPath := filepath.Join(fs.basePath, entry.Name(), "vault.json")
			if _, err := os.Stat(vaultConfigPath); err == nil {
				tenants = append(tenants, entry.Name())
			}
		}
	}

	sort.Strings(tenants)
	return tenants, nil
}

// DeleteTenant removes all data for a tenant
func (fs *FileSystemStore) DeleteTenant(tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	tenantPath := filepath.Join(fs.basePath, tenantID)

	if tenantID == fs.tenantID {
		return fmt.Errorf("cannot delete current tenant")
	}

	// Check if the tenant directory exists
	if _, err := os.Stat(tenantPath); os.IsNotExist(err) {
		return fmt.Errorf("tenant %s does not exist", tenantID)
	} else if err != nil {
		return fmt.Errorf("failed to check tenant directory: %w", err)
	}

	if err := os.RemoveAll(tenantPath); err != nil {
		return fmt.Errorf("failed to delete tenant data: %w", err)
	}

	return nil
}

// SaveMetadata with optimistic concurrency control
func (fs *FileSystemStore) SaveMetadata(encryptedMetadata []byte, expectedVersion string) (string, error) {
	if encryptedMetadata == nil {
		return "", fmt.Errorf("metadata cannot be nil")
	}
	// Validate expected version if provided
	if expectedVersion != "" {
		currentVersion, err := fs.getFileVersion(fs.vaultMeta)
		if err != nil {
			return "", fmt.Errorf("failed to check current version: %w", err)
		}
		if currentVersion != expectedVersion {
			return "", ConcurrencyError{
				ExpectedVersion: expectedVersion,
				ActualVersion:   currentVersion,
				Operation:       "SaveMetadata",
			}
		}
	}

	if err := os.MkdirAll(fs.tenantPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create tenant directory: %w", err)
	}

	if err := writeSecureFile(fs.vaultMeta, encryptedMetadata, FilePermissions); err != nil {
		return "", err
	}

	// Calculate and return new version based on what was actually written
	newVersion := calculateFileVersion(encryptedMetadata)
	return newVersion, nil
}

// LoadMetadata returns versioned metadata
func (fs *FileSystemStore) LoadMetadata() (*VersionedData, error) {
	// Get file info to extract timestamp
	fileInfo, err := os.Stat(fs.vaultMeta)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to stat vault metadata: %w", err)
	}

	data, err := os.ReadFile(fs.vaultMeta)
	if err != nil {
		return nil, fmt.Errorf("failed to load vault metadata: %w", err)
	}

	version := calculateFileVersion(data)

	return &VersionedData{
		Data:      data,
		Version:   version,
		Timestamp: fileInfo.ModTime(),
	}, nil
}

func (fs *FileSystemStore) MetadataExists() (bool, error) {
	return fileExists(fs.vaultMeta)
}

// SaveSalt with optimistic concurrency control
func (fs *FileSystemStore) SaveSalt(saltData []byte, expectedVersion string) (string, error) {
	if saltData == nil || len(saltData) == 0 {
		return "", fmt.Errorf("salt is required")
	}
	// Validate expected version if provided
	if expectedVersion != "" {
		currentVersion, err := fs.getFileVersion(fs.vaultSalt)
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

	if err := os.MkdirAll(fs.tenantPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create tenant directory: %w", err)
	}

	// Write file with metadata (stored as extended attributes or separate file)
	if err := writeSecureFileWithMetadata(fs.vaultSalt, saltData, FilePermissions, createSaltMetadata(fs.tenantID)); err != nil {
		return "", fmt.Errorf("failed to save salt: %w", err)
	}

	// Calculate and return new version
	newVersion := calculateFileVersion(saltData)
	return newVersion, nil
}

// LoadSalt returns versioned salt data
func (fs *FileSystemStore) LoadSalt() (*VersionedData, error) {
	// Check if salt file exists
	if _, err := os.Stat(fs.vaultSalt); os.IsNotExist(err) {
		return nil, fmt.Errorf("salt not found")
	}

	// Read salt data
	saltData, err := os.ReadFile(fs.vaultSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to load salt: %w", err)
	}

	// Read metadata
	metadata, err := readMetadata(fs.vaultSalt)
	if err != nil {
		// Fallback for legacy files without metadata
		metadata = make(map[string]string)
	}

	// Parse timestamp from metadata
	var timestamp time.Time
	if createdAt, exists := metadata["created-at"]; exists {
		if parsedTime, err := time.Parse(time.RFC3339, createdAt); err == nil {
			timestamp = parsedTime
		}
	}

	// If no timestamp in metadata, use file modification time as fallback
	if timestamp.IsZero() {
		if fileInfo, err := os.Stat(fs.vaultSalt); err == nil {
			timestamp = fileInfo.ModTime()
		}
	}

	// Calculate current version
	version := calculateFileVersion(saltData)

	return &VersionedData{
		Data:      saltData,
		Version:   version,
		Timestamp: timestamp,
	}, nil
}

func (fs *FileSystemStore) SaltExists() (bool, error) {
	return fileExists(fs.vaultSalt)
}

// SaveSecretsData with optimistic concurrency control
func (fs *FileSystemStore) SaveSecretsData(encryptedSecretsData []byte, expectedVersion string) (string, error) {
	if encryptedSecretsData == nil || len(encryptedSecretsData) == 0 {
		return "", fmt.Errorf("metadata is required")
	}
	// Validate expected version if provided
	if expectedVersion != "" {
		currentVersion, err := fs.getFileVersion(fs.secretsMeta)
		if err != nil {
			return "", fmt.Errorf("failed to check current version: %w", err)
		}
		if currentVersion != expectedVersion {
			return "", ConcurrencyError{
				ExpectedVersion: expectedVersion,
				ActualVersion:   currentVersion,
				Operation:       "SaveSecretsData",
			}
		}
	}

	if err := os.MkdirAll(fs.tenantPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create tenant directory: %w", err)
	}

	if err := writeSecureFile(fs.secretsMeta, encryptedSecretsData, FilePermissions); err != nil {
		return "", err
	}

	// Calculate and return new version
	newVersion := calculateFileVersion(encryptedSecretsData)
	return newVersion, nil
}

// LoadSecretsData returns versioned secrets data
func (fs *FileSystemStore) LoadSecretsData() (*VersionedData, error) {
	debug.Print("LoadSecretsData: Reading from %s (tenant: %s)\n", fs.secretsMeta, fs.tenantID)

	// Get file info to extract timestamp
	fileInfo, err := os.Stat(fs.secretsMeta)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to stat secrets data: %w", err)
	}

	data, err := os.ReadFile(fs.secretsMeta)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to load secrets data: %w", err)
	}

	debug.Print("LoadSecretsData: Read %d bytes for tenant %s, first 32: %x\n",
		len(data), fs.tenantID, data[:min(32, len(data))])

	version := calculateFileVersion(data)

	return &VersionedData{
		Data:      data,
		Version:   version,
		Timestamp: fileInfo.ModTime(), // Add this line
	}, nil
}

func (fs *FileSystemStore) SecretsDataExists() (bool, error) {
	return fileExists(fs.secretsMeta)
}

// Backup operations
func (fs *FileSystemStore) SaveBackup(backupPath string, container *BackupContainer) error {
	debug.Print("SaveBackup: called with backupPath: %s\n", backupPath)
	debug.Print("SaveBackup: fs.backupsDir: %s\n", fs.backupsDir)

	// Input validation
	backupPath = strings.TrimSpace(backupPath)

	if backupPath == "" {
		return fmt.Errorf("backup path cannot be empty or whitespace-only")
	}

	// Check for invalid characters
	if strings.ContainsAny(backupPath, "\x00") {
		return fmt.Errorf("backup path contains invalid characters")
	}

	// Clean the path
	backupPath = filepath.Clean(backupPath)

	// Handle relative paths - convert simple filenames to use backupsDir
	if !filepath.IsAbs(backupPath) && !strings.Contains(backupPath, string(os.PathSeparator)) {
		backupPath = filepath.Join(fs.backupsDir, backupPath)
		debug.Print("SaveBackup: Updated backupPath to: %s\n", backupPath)
	}

	// Ensure the backup file has .vault extension
	if !strings.HasSuffix(backupPath, ".vault") {
		backupPath += ".vault"
		debug.Print("SaveBackup: Added .vault extension: %s\n", backupPath)
	}

	// NOW check if the final target path is an existing directory
	if stat, err := os.Stat(backupPath); err == nil {
		if stat.IsDir() {
			return fmt.Errorf("cannot create backup file %s: path is an existing directory", backupPath)
		}
	}

	// Validate the final path
	if err := fs.validateBackupPath(backupPath); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	backupDir := filepath.Dir(backupPath)
	debug.Print("SaveBackup: Creating backup directory: %s\n", backupDir)

	if err := os.MkdirAll(backupDir, DirPermissions); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	if container.TenantID == "" {
		container.TenantID = fs.tenantID
		debug.Print("SaveBackup: Set container.TenantID to: %s\n", container.TenantID)
	}

	containerData, err := json.MarshalIndent(container, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup container: %w", err)
	}

	debug.Print("SaveBackup: About to write backup file to: %s\n", backupPath)

	if err = writeSecureFile(backupPath, containerData, FilePermissions); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	// Verify the file was actually created
	if _, err = os.Stat(backupPath); err != nil {
		debug.Print("SaveBackup: ERROR - File was not created successfully: %v\n", err)
		return fmt.Errorf("backup file was not created: %w", err)
	} else {
		debug.Print("SaveBackup: SUCCESS - Backup file created at: %s\n", backupPath)
	}

	return nil
}

// validateBackupPath performs additional validation on the backup path
func (fs *FileSystemStore) validateBackupPath(backupPath string) error {
	// Check path length (reasonable limit)
	if len(backupPath) > 4096 {
		return fmt.Errorf("path too long (max 4096 characters)")
	}

	// Clean the path and check for directory traversal attempts
	cleanPath := filepath.Clean(backupPath)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path contains directory traversal")
	}

	// Check if trying to overwrite critical system files (Unix-like systems)
	if runtime.GOOS != "windows" {
		systemPaths := []string{"/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/boot/"}
		for _, sysPath := range systemPaths {
			if strings.HasPrefix(cleanPath, sysPath) {
				return fmt.Errorf("cannot create backup in system directory")
			}
		}
	}

	// Check for Windows system paths
	if runtime.GOOS == "windows" {
		upperPath := strings.ToUpper(cleanPath)
		windowsSystemPaths := []string{"C:\\WINDOWS\\", "C:\\PROGRAM FILES\\", "C:\\PROGRAM FILES (X86)\\"}
		for _, sysPath := range windowsSystemPaths {
			if strings.HasPrefix(upperPath, sysPath) {
				return fmt.Errorf("cannot create backup in system directory")
			}
		}
	}

	return nil
}

func (fs *FileSystemStore) RestoreBackup(backupPath string) (*BackupContainer, error) {
	debug.Print("RestoreBackup: called with backupPath: %s\n", backupPath)

	// Build the full path - check if it's already a full path or just a filename
	var fullPath string
	if filepath.IsAbs(backupPath) {
		fullPath = backupPath
	} else {
		// It's a relative path, so build it from backupsDir
		fullPath = filepath.Join(fs.backupsDir, backupPath)
	}

	// Add .vault extension if not present
	if !strings.HasSuffix(fullPath, ".vault") {
		fullPath += ".vault"
	}

	debug.Print("RestoreBackup: Looking for backup file at: %s\n", fullPath)

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("backup file %s does not exist", fullPath)
	}

	// Read the backup file
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	// Parse the JSON
	var container BackupContainer
	if err = json.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to parse backup file: %w", err)
	}

	// Validate the backup
	if isValid, validationError := fs.validateBackupContainer(&container, filepath.Base(fullPath)); !isValid {
		return nil, fmt.Errorf("invalid backup file: %s", validationError)
	}

	debug.Print("RestoreBackup: Successfully loaded and validated backup: %s\n", container.BackupID)
	return &container, nil
}

func (fs *FileSystemStore) DeleteBackup(backupID string) error {
	debug.Print("DeleteBackup: called with backupID: %s\n", backupID)

	// First, we need to find which file contains this backup ID
	if _, err := os.Stat(fs.backupsDir); os.IsNotExist(err) {
		return fmt.Errorf("backups directory does not exist")
	}

	entries, err := os.ReadDir(fs.backupsDir)
	if err != nil {
		return fmt.Errorf("failed to read backups directory: %w", err)
	}

	// Search through all backup files to find the one with matching ID
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(fs.backupsDir, entry.Name())
		debug.Print("DeleteBackup: Checking file: %s\n", entry.Name())

		// Read and parse the backup file
		data, err := os.ReadFile(filePath)
		if err != nil {
			debug.Print("DeleteBackup: Failed to read file %s: %v\n", entry.Name(), err)
			continue
		}

		var container BackupContainer
		if err := json.Unmarshal(data, &container); err != nil {
			debug.Print("DeleteBackup: Failed to parse file %s: %v\n", entry.Name(), err)
			continue
		}

		// Check if this is the backup we're looking for
		if container.BackupID == backupID {
			debug.Print("DeleteBackup: Found backup %s in file %s\n", backupID, entry.Name())

			// Delete the file
			if err := os.Remove(filePath); err != nil {
				return fmt.Errorf("failed to delete backup file %s: %w", entry.Name(), err)
			}

			debug.Print("DeleteBackup: Successfully deleted backup %s\n", backupID)
			return nil
		}
	}

	// If we get here, the backup ID was not found
	return fmt.Errorf("backup %s does not exist", backupID)
}

func (fs *FileSystemStore) ListBackups() ([]BackupInfo, error) {
	debug.Print("ListBackups: Looking for backups in directory: %s\n", fs.backupsDir)

	if _, err := os.Stat(fs.backupsDir); os.IsNotExist(err) {
		debug.Print("ListBackups: Backup directory does not exist\n")
		return []BackupInfo{}, nil
	}

	entries, err := os.ReadDir(fs.backupsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backups directory: %w", err)
	}

	debug.Print("ListBackups: Found %d entries in backup directory\n", len(entries))

	var backups []BackupInfo
	for _, entry := range entries {
		debug.Print("ListBackups: Entry: %s, IsDir: %t\n", entry.Name(), entry.IsDir())

		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(fs.backupsDir, entry.Name())
		debug.Print("ListBackups: Processing backup file: %s\n", entry.Name())

		// Read and parse the backup file
		data, err := os.ReadFile(filePath)
		if err != nil {
			debug.Print("ListBackups: WARNING - Failed to read backup file %s: %v\n", entry.Name(), err)
			continue
		}

		var container BackupContainer
		if err := json.Unmarshal(data, &container); err != nil {
			debug.Print("ListBackups: WARNING - Failed to parse backup file %s: %v\n", entry.Name(), err)
			continue
		}

		// Validate the backup with detailed error reporting
		isValid, validationError := fs.validateBackupContainer(&container, entry.Name())

		info, err := entry.Info()
		if err != nil {
			debug.Print("ListBackups: WARNING - Failed to get file info for %s: %v\n", entry.Name(), err)
			continue
		}

		backup := BackupInfo{
			BackupID:        container.BackupID,
			BackupTimestamp: container.BackupTimestamp,
			FileSize:        info.Size(),
			IsValid:         isValid,
			TenantID:        container.TenantID,
			StorePath:       entry.Name(),
			VaultVersion:    container.VaultVersion,
			BackupVersion:   container.BackupVersion,
		}

		if !isValid {
			debug.Print("ListBackups: WARNING - Backup %s is invalid: %s\n", entry.Name(), validationError)
		} else {
			debug.Print("ListBackups: Successfully processed backup: %s\n", container.BackupID)
		}

		backups = append(backups, backup)
	}

	debug.Print("ListBackups: Returning %d backups (%d valid)\n", len(backups), countValidBackups(backups))
	return backups, nil
}

// Add this new validation method
func (fs *FileSystemStore) validateBackupContainer(container *BackupContainer, filename string) (bool, string) {
	// Check required fields
	if container.BackupID == "" {
		return false, "missing BackupID"
	}
	if container.EncryptedData == "" {
		return false, "missing EncryptedData"
	}
	if container.Checksum == "" {
		return false, "missing Checksum"
	}

	// Validate base64 encoding
	encryptedData, err := base64.StdEncoding.DecodeString(container.EncryptedData)
	if err != nil {
		return false, fmt.Sprintf("invalid base64 in EncryptedData: %v", err)
	}

	// Validate checksum
	actualChecksum := crypto.CalculateChecksum(encryptedData)
	if actualChecksum != container.Checksum {
		return false, fmt.Sprintf("checksum mismatch - expected: %s, actual: %s",
			container.Checksum, actualChecksum)
	}

	debug.Print("ListBackups: Checksum validation passed for %s\n", filename)
	return true, ""
}

// Helper function
func countValidBackups(backups []BackupInfo) int {
	count := 0
	for _, backup := range backups {
		if backup.IsValid {
			count++
		}
	}
	return count
}

func (fs *FileSystemStore) GetType() string {
	return string(StoreTypeFileSystem)
}

// Health and utilities
func (fs *FileSystemStore) Ping() error {
	_, err := os.Stat(fs.tenantPath)
	return err
}

func (fs *FileSystemStore) Close() error {
	if configData, err := os.ReadFile(fs.vaultConfig); err == nil {
		var config VaultConfig
		if err := json.Unmarshal(configData, &config); err == nil {
			config.LastAccess = time.Now()
			if updatedData, err := json.MarshalIndent(config, "", "  "); err == nil {
				_ = writeSecureFile(fs.vaultConfig, updatedData, FilePermissions)
			}
		}
	}
	return nil
}

// Helper methods for versioning support
func (fs *FileSystemStore) getFileVersion(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // File doesn't exist, version is empty
		}
		return "", err
	}
	return calculateFileVersion(data), nil
}

func calculateFileVersion(data []byte) string {
	// Use MD5 hash of file contents as version identifier
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// Helper functions
func writeSecureFileWithMetadata(filePath string, data []byte, perm os.FileMode, metadata map[string]string) error {
	if err := writeSecureFile(filePath, data, perm); err != nil {
		return err
	}

	// Store metadata in a separate file or as extended attributes
	metadataPath := filePath + ".meta"
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return writeSecureFile(metadataPath, metadataBytes, perm)
}

// Helper method to read metadata
func readMetadata(filePath string) (map[string]string, error) {
	metadataPath := filePath + ".meta"
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if err = json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, nil
}

func writeSecureFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err = tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err = tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err = tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err = os.Chmod(tmpPath, perm); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	if err = os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
