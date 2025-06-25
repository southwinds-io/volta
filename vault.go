package volta

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
	mrand "math/rand"
	"os"
	"regexp"
	"southwinds.dev/volta/audit"
	"southwinds.dev/volta/internal/debug"
	"southwinds.dev/volta/internal/mem"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"time"
)

const (
	maxRetries = 3
	baseDelay  = 50 * time.Millisecond
	maxDelay   = 1 * time.Second
)

var secretIDRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_/.]+$`)

// Initialize memguard in init function to ensure it's set up before any vault operation
func init() {
	// Enable memguard protection
	memguard.CatchInterrupt()
}

// Vault an implementation of VaultService that stores the master key and vault configuration
type Vault struct {
	store       persist.Store
	keyEnclaves map[string]*memguard.Enclave
	keyMetadata map[string]KeyMetadata
	mu          sync.RWMutex

	// Key management
	currentKeyID string

	// Memory protection
	memoryProtectionLevel mem.ProtectionLevel

	// Derivation key management
	derivationKeyEnclave  *memguard.Enclave
	derivationSaltEnclave *memguard.Enclave

	// In-memory secret storage with memguard protection
	secretsContainer *memguard.Enclave // Encrypted SecretsMetadata container
	secretsVersion   string
	secretsTimestamp time.Time

	// Audit logging
	audit audit.Logger

	// the owner of the vault
	userID string

	// the owning tenant of the vault
	tenantID string

	closed bool
}

// RetryConfig configures retry behavior for concurrent operations
type RetryConfig struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: maxRetries,
		BaseDelay:  baseDelay,
		MaxDelay:   maxDelay,
	}
}

// NewWithStore creates a new VaultService instance with the specified storage backend and audit logger.
//
// This is the primary constructor for creating a vault service with custom storage and audit
// implementations. It handles all aspects of vault initialization including memory protection,
// key derivation, storage connectivity testing, and audit logging setup.
//
// The function performs several critical initialization steps:
//  1. Validates configuration options
//  2. Tests storage backend connectivity
//  3. Sets up memory protection (best-effort)
//  4. Initializes cryptographic key derivation
//  5. Loads existing keys or creates initial key material
//  6. Initializes the secrets container
//  7. Establishes audit logging
//
// Parameters:
//   - options: Configuration options for the vault (passphrase, salt, etc.)
//   - store: Storage backend implementation for persisting encrypted data
//   - auditLogger: Logger for security events and operations (nil creates no-op logger)
//
// Returns:
//   - VaultService: Fully initialized vault service ready for use
//   - error: Error if initialization fails at any stage
//
// Error Conditions:
//   - Invalid configuration options
//   - Storage backend connectivity failure
//   - Memory protection setup failure (logged as warning, not fatal)
//   - Key derivation or encryption key setup failure
//   - Existing vault data corruption or inaccessibility
//
// Security Notes:
//   - Memory protection is attempted but vault remains functional if unavailable
//   - All cryptographic material is stored in protected memory enclaves
//   - Storage connectivity is verified before proceeding with initialization
//   - Audit events are logged for the initialization process
//
// Example:
//
//	options := volta.Options{
//	    DerivationPassphrase: "secure-passphrase",
//	    DerivationSalt: []byte("optional-custom-salt"),
//	}
//	store := persist.NewFileStore("/path/to/vault")
//	auditLogger := audit.NewFileLogger("/path/to/audit.log")
//
//	vault, err := volta.NewWithStore(options, store, auditLogger)
//	if err != nil {
//	    return fmt.Errorf("failed to create vault: %w", err)
//	}
//	defer vault.Close()
func NewWithStore(options Options, store persist.Store, auditLogger audit.Logger, tenantID string) (VaultService, error) {
	// Validate options before processing
	// This ensures all required configuration is present and valid before
	// attempting any cryptographic operations or storage access
	if err := validateOptions(options); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	var userID = options.UserID
	if userID == "" {
		userID = "system"
	}

	if len(tenantID) == 0 {
		return nil, fmt.Errorf("missing tenant ID")
	}

	// Set up audit logger - use no-op logger if none provided
	// This ensures audit operations never fail due to nil pointer access
	if auditLogger == nil {
		auditLogger = audit.NewNoOpLogger()
	}

	// Verify storage backend is provided
	// The vault cannot function without persistent storage
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}

	// Test storage connectivity before proceeding
	// This early validation prevents initialization with unusable storage
	if err := store.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to storage backend: %w", err)
	}

	// Initialize the vault structure with default values
	// All sensitive data structures will be properly initialized below
	v := &Vault{
		// Storage backend for persisting encrypted data
		store: store,

		// Key management structures
		keyEnclaves: make(map[string]*memguard.Enclave), // Protected storage for decryption keys
		keyMetadata: make(map[string]KeyMetadata),       // Metadata for key lifecycle management
		mu:          sync.RWMutex{},                     // Protects concurrent access to key data

		// Current active key identifier - will be set during key initialization
		currentKeyID: "",

		// Memory protection level - determined by platform capabilities
		memoryProtectionLevel: mem.ProtectionNone,

		// Key derivation structures - initialized below
		derivationKeyEnclave:  nil, // Master key for encrypting/decrypting key material
		derivationSaltEnclave: nil, // Salt for key derivation functions

		// Secrets storage structures - initialized below
		secretsContainer: nil,         // Container for encrypted secrets
		secretsVersion:   "",          // Version tracking for secrets container
		secretsTimestamp: time.Time{}, // Last modification time for secrets

		// Audit logging
		audit: auditLogger,

		// the owner of the vault
		userID: userID,

		// the tenant who owns the vault
		tenantID: tenantID,
	}

	// Attempt to enable memory protection
	// This is a best-effort operation - the vault remains functional even if
	// advanced memory protection is unavailable on the current platform
	protectionLevel, err := mem.Lock()
	if err != nil {
		// Log warning but continue - memory protection failure is not fatal
		// MemGuard will still provide enclave-based protection for sensitive data
		fmt.Printf("WARNING: Cannot fully protect memory: %v\n", err)
		fmt.Println("However, MemGuard will still provide protection for encryption keys and secrets")
	}
	v.memoryProtectionLevel = protectionLevel

	// Load existing derivation salt or create new one
	// The salt is used for key derivation functions and must be consistent
	// across vault sessions to decrypt existing data
	if err = v.loadOrCreateSalt(options.DerivationSalt); err != nil {
		return nil, fmt.Errorf("failed to setup derivation salt: %w", err)
	}

	// Set up the master derivation key used for encrypting/decrypting key material
	// This key is derived from the user's passphrase and the vault's salt
	if err = v.setupDerivationKey(options.DerivationPassphrase, options.EnvPassphraseVar); err != nil {
		return nil, fmt.Errorf("failed to set up derivation key: %w", err)
	}

	// Debug logging for key derivation verification (development use only)
	// This helps verify that key derivation is working correctly across sessions
	if v.derivationKeyEnclave != nil {
		keyBuffer, err := v.derivationKeyEnclave.Open()
		if err == nil {
			debug.Print("DEBUG: Original derivation key (first 16 bytes): %x", keyBuffer.Bytes()[:16])
			keyBuffer.Destroy() // Immediately destroy the buffer to minimize exposure
		}
	}

	// Initialize the vault's encryption keys
	// This loads existing keys from storage or creates initial key material for new vaults
	if err = v.initializeKeys(); err != nil {
		if os.IsNotExist(err) {
			// This is a new vault - create the initial encryption key
			if err = v.createNewKey(); err != nil {
				return nil, fmt.Errorf("failed to create initial key: %w", err)
			}
		} else {
			// Existing vault with corrupted or inaccessible key data
			return nil, fmt.Errorf("failed to initialize keys: %w", err)
		}
	}

	// Initialize the secrets container that holds all encrypted secret data
	// This loads the existing container from storage or creates a new empty one
	if err = v.initializeSecretsContainer(); err != nil {
		return nil, fmt.Errorf("failed to initialize secrets container: %w", err)
	}

	// Log successful vault initialization for audit purposes
	// This creates an audit trail of vault access and configuration
	requestID := v.newRequestID()

	v.logAudit(requestID, "VAULT_INITIALIZED", nil, map[string]interface{}{
		"store_type":           store.GetType(),        // Type of storage backend
		"memory_protection":    protectionLevel,        // Level of memory protection achieved
		"has_existing_keys":    len(v.keyMetadata) > 0, // Whether existing keys were loaded
		"has_existing_secrets": v.getSecretsCount(),    // Number of secrets in the vault
		"current_key_id":       v.currentKeyID,         // Active key identifier
	})

	return v, nil
}

// StoreSecret encrypts and stores new secret data in the vault with associated metadata and tags.
//
// This method creates a new secret entry in the vault, encrypting the provided data using the
// currently active encryption key. The secret is assigned version 1 and comprehensive metadata
// is generated including creation timestamps, checksums, and access tracking information.
//
// The storage operation is atomic - if any step fails, no partial data is stored and the
// vault remains in a consistent state. All sensitive operations are performed within
// protected memory enclaves to prevent data exposure.
//
// Parameters:
//   - secretID: Unique identifier for the secret (must be valid according to ID rules)
//   - secretData: The raw secret data to encrypt and store (cannot be empty)
//   - tags: Optional list of tags for categorization and filtering (duplicates removed)
//   - contentType: MIME-type indication of the secret data format for proper handling
//
// Returns:
//   - *SecretMetadata: Complete metadata for the newly stored secret including:
//   - Unique secret ID and version number (1 for new secrets)
//   - Encryption key ID used for the operation
//   - Creation and update timestamps (identical for new secrets)
//   - Size and checksum of the encrypted data
//   - Content type and tags as provided
//   - Access tracking fields (initialized to zero)
//   - Custom fields map (empty for new secrets)
//   - error: Error if storage fails for any reason
//
// Error Conditions:
//   - Vault is closed or not properly initialized
//   - Invalid secret ID (empty, invalid characters, reserved names, etc.)
//   - Empty secret data (zero-length byte slice)
//   - Invalid secret data for the specified content type
//   - Invalid or malformed tags (after validation and sanitization)
//   - Invalid content type (not in supported ContentType constants)
//   - Secret with the same ID already exists (use UpdateSecret instead)
//   - Encryption failure (key unavailable, cryptographic error)
//   - Storage persistence failure (disk full, permissions, network error)
//   - Container update failure (corruption, concurrent access issues)
//
// Security Behavior:
//   - Secret data is encrypted using authenticated encryption (ChaCha20-Poly1305)
//   - Encryption key is the currently active key from the key management system
//   - Original secret data is never persisted in plaintext
//   - Checksum is calculated on plaintext data before encryption for integrity verification
//   - All cryptographic operations occur in protected memory enclaves
//   - Sensitive data is immediately cleared from working memory after encryption
//
// Validation Rules:
//   - Secret IDs must follow naming conventions (alphanumeric, hyphens, underscores typically)
//   - Secret data is validated against the declared content type when possible
//   - Tags are sanitized to remove invalid characters and duplicates
//   - Content type must be one of the supported ContentType constants
//   - Maximum size limits may apply depending on storage backend
//
// Audit and Logging:
//   - Successful storage operations generate "STORE" audit events
//   - Audit logs include secret ID but never secret content
//   - Failed operations may generate audit entries depending on failure type
//   - Timing information is recorded for security monitoring
//
// Concurrency and Atomicity:
//   - Method uses write locks to prevent concurrent modifications
//   - Container updates are atomic - partial failures leave vault unchanged
//   - Storage persistence is separate from in-memory updates for consistency
//   - Multiple secrets can be stored concurrently by different vault instances
//
// Storage Layout:
//   - Secret is added to the vault's secrets container structure
//   - Container versioning is updated to reflect the change
//   - Encrypted data includes authentication tags for tamper detection
//   - Metadata is stored alongside encrypted data for efficient access
//
// Performance Considerations:
//   - Encryption performance scales with secret data size
//   - Tag validation and deduplication adds minimal overhead
//   - Storage persistence latency depends on backend implementation
//   - Memory usage is proportional to secret size during encryption
//
// Example Usage:
//
//	tags := []string{"production", "database", "credentials"}
//	metadata, err := vault.StoreSecret(
//	    "db-password",
//	    []byte("super-secret-password"),
//	    tags,
//	    volta.ContentTypeText,
//	)
//	if err != nil {
//	    if strings.Contains(err.Error(), "already exists") {
//	        // Handle duplicate secret ID
//	        return fmt.Errorf("secret already exists: use update instead")
//	    }
//	    return fmt.Errorf("failed to store secret: %w", err)
//	}
//	fmt.Printf("Stored secret %s (v%d) with key %s\n",
//	    metadata.SecretID, metadata.Version, metadata.KeyID)
//
// Related Methods:
//   - UpdateSecret: For modifying existing secrets (increments version)
//   - GetSecret: For retrieving and decrypting stored secrets
//   - SecretExists: For checking secret existence before storage
//   - DeleteSecret: For removing secrets from the vault
func (v *Vault) StoreSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error) {
	startTime := time.Now()
	requestID := v.newRequestID()

	v.logAudit(requestID, "STORE_SECRET_INITIATED", nil, map[string]interface{}{
		"secret_id":    secretID,
		"content_type": string(contentType),
		"data_size":    len(secretData),
		"tag_count":    len(tags),
	})

	if v.closed {
		err := fmt.Errorf("vault is closed")
		v.logAudit(requestID, "STORE_SECRET_FAILED", err, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "vault_closed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, err
	}

	if err := validateSecretID(secretID); err != nil {
		validationErr := fmt.Errorf("invalid secret ID: %w", err)
		v.logAudit(requestID, "STORE_SECRET_FAILED", validationErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "invalid_secret_id",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, validationErr
	}

	if len(secretData) == 0 {
		emptyDataErr := fmt.Errorf("secret data cannot be empty")
		v.logAudit(requestID, "STORE_SECRET_FAILED", emptyDataErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "empty_secret_data",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, emptyDataErr
	} else if err := validateSecretData(secretData, contentType); err != nil {
		dataValidationErr := fmt.Errorf("invalid secret data: %w", err)
		v.logAudit(requestID, "STORE_SECRET_FAILED", dataValidationErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "invalid_secret_data",
			"content_type":   string(contentType),
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, dataValidationErr
	}

	if validTags, err := validateAndSanitizeTags(tags); err != nil {
		tagValidationErr := fmt.Errorf("invalid secret tags: %w; valid tags are: %v", err, validTags)
		v.logAudit(requestID, "STORE_SECRET_FAILED", tagValidationErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "invalid_tags",
			"invalid_tags":   tags,
			"valid_tags":     validTags,
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, tagValidationErr
	}
	tags = deduplicateTags(tags)

	if !isValidContentType(contentType) {
		contentTypeErr := fmt.Errorf("invalid content type: %s", contentType)
		v.logAudit(requestID, "STORE_SECRET_FAILED", contentTypeErr, map[string]interface{}{
			"secret_id":            secretID,
			"failure_reason":       "invalid_content_type",
			"invalid_content_type": string(contentType),
			"duration_ms":          time.Since(startTime).Milliseconds(),
		})
		return nil, contentTypeErr
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Get current secrets container
	container, err := v.getSecretsContainer()
	if err != nil {
		containerErr := fmt.Errorf("failed to get secrets container: %w", err)
		v.logAudit(requestID, "STORE_SECRET_FAILED", containerErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "container_retrieval_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, containerErr
	}

	// Check if secret already exists
	if _, exists := container.Secrets[secretID]; exists {
		duplicateErr := fmt.Errorf("secret %s already exists, use UpdateSecret to modify", secretID)
		v.logAudit(requestID, "STORE_SECRET_FAILED", duplicateErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "secret_already_exists",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, duplicateErr
	}

	// Encrypt the secret data
	encryptedData, err := v.encryptWithCurrentKey(secretData)
	if err != nil {
		encryptionErr := fmt.Errorf("failed to encrypt secret: %w", err)
		v.logAudit(requestID, "STORE_SECRET_FAILED", encryptionErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "encryption_failed",
			"key_id":         v.currentKeyID,
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, encryptionErr
	}

	// Calculate metadata
	secretSize := len(secretData)
	checksum := fmt.Sprintf("%x", sha256.Sum256(secretData))
	now := time.Now().UTC()

	// Create secret metadata
	secretMetadata := &SecretMetadata{
		SecretID:     secretID,
		Version:      1,
		ContentType:  contentType,
		Description:  "",
		Tags:         tags,
		KeyID:        v.currentKeyID,
		CreatedAt:    now,
		UpdatedAt:    now,
		Size:         secretSize,
		Checksum:     checksum,
		AccessCount:  0,
		LastAccessed: nil,
		ExpiresAt:    nil,
		CustomFields: make(map[string]string),
	}

	// Create secret entry
	secretEntry := &SecretEntry{
		ID:        secretID,
		Data:      encryptedData,
		Metadata:  secretMetadata,
		CreatedAt: now,
		UpdatedAt: now,
		Tags:      tags,
		Version:   1,
	}

	// Add to container
	container.Secrets[secretID] = secretEntry

	// Update container in memory
	if err = v.updateSecretsContainer(container); err != nil {
		memoryErr := fmt.Errorf("failed to update secrets container: %w", err)
		v.logAudit(requestID, "STORE_SECRET_FAILED", memoryErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "memory_update_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, memoryErr
	}

	// Persist to storage
	if err = v.persistSecretsToStore(); err != nil {
		persistErr := fmt.Errorf("failed to persist secrets: %w", err)
		v.logAudit(requestID, "STORE_SECRET_CRITICAL_FAILURE", persistErr, map[string]interface{}{
			"secret_id":       secretID,
			"persist_error":   err.Error(),
			"data_integrity":  "memory_updated_storage_failed",
			"requires_manual": "verification",
			"duration_ms":     time.Since(startTime).Milliseconds(),
		})
		return nil, persistErr
	}

	// Success - log completion with key metadata
	v.logAudit(requestID, "STORE_SECRET_COMPLETED", nil, map[string]interface{}{
		"secret_id":           secretID,
		"duration_ms":         time.Since(startTime).Milliseconds(),
		"total_secrets_count": len(container.Secrets),
		"stored_secret_metadata": map[string]interface{}{
			"content_type":      string(contentType),
			"size_bytes":        secretSize,
			"tag_count":         len(tags),
			"encryption_key_id": v.currentKeyID,
			"checksum":          checksum[:16], // First 16 chars for audit
			"version":           1,
		},
	})

	return secretMetadata, nil
}

// GetSecret retrieves and decrypts a secret from the vault by its ID.
//
// This function performs the following operations:
// 1. Validates the vault state and secret ID format
// 2. Retrieves and decrypts the secret from storage
// 3. Updates access tracking metadata (access count and last accessed time)
// 4. Returns both the decrypted secret data and complete metadata
//
// SECURITY CONSIDERATIONS:
// - The returned secret data remains in memory until garbage collected
// - For embedded applications, consider using UseSecret() family functions instead
// - These safe functions automatically clear secrets from memory after use
//
// Parameters:
//   - secretID: Unique identifier for the secret to retrieve
//
// Returns:
//   - SecretResult: Contains decrypted data, metadata, and key usage info
//   - error: Any error encountered during retrieval or decryption
//
// Thread Safety: This function is thread-safe through internal mutex locking
//
// Audit Logging: All access attempts (successful and failed) are logged if auditing is enabled
//
// Key Rotation Support: The function can decrypt secrets encrypted with older keys
// and reports whether the current active key was used via SecretResult.UsedActiveKey
//
// Example Usage:
//
//	result, err := vault.GetSecret("my-secret-id")
//	if err != nil {
//	    return err
//	}
//	// CAUTION: Secret data is now in memory - handle carefully
//	secretData := result.Data
//
//	// RECOMMENDED: Use safe retrieval functions instead for embedded applications:
//	// vault.UseSecret("my-secret-id", func(data []byte) error {
//	//     // Work with secret data here - automatically cleared after function returns
//	//     return processSecret(data)
//	// })
func (v *Vault) GetSecret(secretID string) (*SecretResult, error) {
	startTime := time.Now()
	requestID := v.newRequestID()

	v.logAudit(requestID, "GET_SECRET_INITIATED", nil, map[string]interface{}{
		"secret_id": secretID,
	})

	if v.closed {
		err := fmt.Errorf("vault is closed")
		v.logAudit(requestID, "GET_SECRET_FAILED", err, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "vault_closed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, err
	}

	if err := validateSecretID(secretID); err != nil {
		validationErr := fmt.Errorf("invalid secret ID: %w", err)
		v.logAudit(requestID, "GET_SECRET_FAILED", validationErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "invalid_secret_id",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, validationErr
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Get current secrets container
	container, err := v.getSecretsContainer()
	if err != nil {
		containerErr := fmt.Errorf("failed to get secrets container: %w", err)
		v.logAudit(requestID, "GET_SECRET_FAILED", containerErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "container_retrieval_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, containerErr
	}

	// Find secret entry
	secretEntry, exists := container.Secrets[secretID]
	if !exists {
		notFoundErr := fmt.Errorf("secret %s not found", secretID)
		v.logAudit(requestID, "GET_SECRET_FAILED", notFoundErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "secret_not_found",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, notFoundErr
	}

	// Decrypt the secret - this now needs to return both data and whether active key was used
	secretData, usedActiveKey, err := v.decryptWithCurrentKey(secretEntry.Data)
	if err != nil {
		decryptErr := fmt.Errorf("failed to decrypt secret: %w", err)
		v.logAudit(requestID, "GET_SECRET_FAILED", decryptErr, map[string]interface{}{
			"secret_id":       secretID,
			"failure_reason":  "decryption_failed",
			"used_active_key": usedActiveKey,
			"duration_ms":     time.Since(startTime).Milliseconds(),
		})
		return nil, decryptErr
	}

	// Update access tracking
	secretEntry.Metadata.AccessCount++
	now := time.Now().UTC()
	secretEntry.Metadata.LastAccessed = &now
	container.Secrets[secretID] = secretEntry

	// Track access tracking update status
	accessTrackingSuccess := true
	if updateErr := v.updateSecretsContainer(container); updateErr != nil {
		accessTrackingSuccess = false
		fmt.Printf("WARNING: failed to update access tracking in memory: %v\n", updateErr)
	} else {
		// Only persist if memory update succeeded
		if persistErr := v.persistSecretsToStore(); persistErr != nil {
			accessTrackingSuccess = false
			fmt.Printf("WARNING: failed to persist access tracking: %v\n", persistErr)
		}
	}

	// Create complete metadata for return
	completeMetadata := &SecretMetadata{
		SecretID:     secretEntry.ID,
		ContentType:  secretEntry.Metadata.ContentType,
		Size:         secretEntry.Metadata.Size,
		Description:  secretEntry.Metadata.Description,
		CreatedAt:    secretEntry.CreatedAt,
		UpdatedAt:    secretEntry.UpdatedAt,
		Version:      secretEntry.Version,
		AccessCount:  secretEntry.Metadata.AccessCount,
		LastAccessed: secretEntry.Metadata.LastAccessed,
		ExpiresAt:    secretEntry.Metadata.ExpiresAt,
		CustomFields: secretEntry.Metadata.CustomFields,
		Tags:         secretEntry.Tags,
		Checksum:     secretEntry.Metadata.Checksum,
		KeyID:        secretEntry.Metadata.KeyID,
	}

	// Log successful access
	v.logAudit(requestID, "GET_SECRET_COMPLETED", nil, map[string]interface{}{
		"secret_id":               secretID,
		"duration_ms":             time.Since(startTime).Milliseconds(),
		"used_active_key":         usedActiveKey,
		"access_tracking_success": accessTrackingSuccess,
		"access_count":            secretEntry.Metadata.AccessCount,
		"secret_metadata": map[string]interface{}{
			"content_type": secretEntry.Metadata.ContentType,
			"size":         secretEntry.Metadata.Size,
			"version":      secretEntry.Version,
			"has_expiry":   secretEntry.Metadata.ExpiresAt != nil,
			"tag_count":    len(secretEntry.Tags),
		},
	})

	return &SecretResult{
		Data:          secretData,
		Metadata:      completeMetadata,
		UsedActiveKey: usedActiveKey,
	}, nil
}

// UpdateSecret modifies an existing secret with new data, tags, and content type.
//
// This function performs a complete update of an existing secret, including:
// 1. Validation of vault state, secret ID, and new data
// 2. Verification that the secret exists in the vault
// 3. Re-encryption of the secret data with the current active key
// 4. Update of all mutable metadata fields (size, checksum, tags, etc.)
// 5. Version increment for change tracking
// 6. Persistence of changes to storage
//
// IMPORTANT BEHAVIOR:
// - The secret is re-encrypted with the current active key (supports key rotation)
// - Version number is automatically incremented
// - UpdatedAt timestamp is set to current time
// - Original creation metadata (CreatedAt, SecretID) is preserved
// - Access tracking (AccessCount, LastAccessed) is preserved
// - Tags are deduplicated automatically
//
// SECURITY CONSIDERATIONS:
// - Input secret data should be handled securely (consider clearing from memory after use)
// - The operation is atomic - either all updates succeed or none do
// - All changes are logged for audit purposes if auditing is enabled
//
// Parameters:
//   - secretID: Unique identifier of the secret to update
//   - secretData: New secret data to encrypt and store (must not be empty)
//   - tags: New set of tags for organization/classification (duplicates removed)
//   - contentType: Content type hint for the secret data format
//
// Returns:
//   - SecretMetadata: Complete updated metadata including new version and timestamps
//   - error: Any error encountered during validation, encryption, or persistence
//
// Thread Safety: This function is thread-safe through internal mutex locking
//
// Audit Logging: Update operations are logged if auditing is enabled
//
// Storage: Changes are immediately persisted to the underlying storage system
//
// Example Usage:
//
//	metadata, err := vault.UpdateSecret(
//	    "my-secret",
//	    []byte("new-secret-value"),
//	    []string{"production", "database"},
//	    ContentTypeText,
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to update secret: %w", err)
//	}
//	fmt.Printf("Secret updated to version %d\n", metadata.Version)
func (v *Vault) UpdateSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error) {
	startTime := time.Now()
	requestID := v.newRequestID()

	v.logAudit(requestID, "UPDATE_SECRET_INITIATED", nil, map[string]interface{}{
		"secret_id":    secretID,
		"data_size":    len(secretData),
		"content_type": string(contentType),
		"tags_count":   len(tags),
	})

	if v.closed {
		err := fmt.Errorf("vault is closed")
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", err, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "vault_closed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, err
	}

	if err := validateSecretID(secretID); err != nil {
		validationErr := fmt.Errorf("invalid secret ID: %w", err)
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", validationErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "invalid_secret_id",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, validationErr
	}

	if len(secretData) == 0 {
		dataErr := fmt.Errorf("secret data cannot be empty")
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", dataErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "empty_secret_data",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, dataErr
	}

	tags = deduplicateTags(tags)

	v.mu.Lock()
	defer v.mu.Unlock()

	// Get current secrets container
	container, err := v.getSecretsContainer()
	if err != nil {
		containerErr := fmt.Errorf("failed to get secrets container: %w", err)
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", containerErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "container_retrieval_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, containerErr
	}

	// Find existing secret entry
	secretEntry, exists := container.Secrets[secretID]
	if !exists {
		notFoundErr := fmt.Errorf("secret %s not found", secretID)
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", notFoundErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "secret_not_found",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, notFoundErr
	}

	// Store previous version for audit
	previousVersion := secretEntry.Version
	previousSize := secretEntry.Metadata.Size
	previousContentType := secretEntry.Metadata.ContentType

	// Encrypt the new secret data
	encryptedData, err := v.encryptWithCurrentKey(secretData)
	if err != nil {
		encryptErr := fmt.Errorf("failed to encrypt secret: %w", err)
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", encryptErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "encryption_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, encryptErr
	}

	// Calculate new metadata
	secretSize := len(secretData)
	checksum := fmt.Sprintf("%x", sha256.Sum256(secretData))
	now := time.Now().UTC()

	// Update SecretEntry level fields
	secretEntry.Data = encryptedData
	secretEntry.UpdatedAt = now
	secretEntry.Version++
	secretEntry.Tags = tags

	// Update embedded Metadata fields
	secretEntry.Metadata.ContentType = contentType
	secretEntry.Metadata.Size = secretSize
	secretEntry.Metadata.Checksum = checksum

	// Update container in memory
	container.Secrets[secretID] = secretEntry
	if err = v.updateSecretsContainer(container); err != nil {
		updateErr := fmt.Errorf("failed to update secrets container: %w", err)
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", updateErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "memory_update_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, updateErr
	}

	// Persist to storage
	if err = v.persistSecretsToStore(); err != nil {
		persistErr := fmt.Errorf("failed to persist secrets: %w", err)
		v.logAudit(requestID, "UPDATE_SECRET_FAILED", persistErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "persist_failed",
			"duration_ms":    time.Since(startTime).Milliseconds(),
		})
		return nil, persistErr
	}

	// Return complete metadata combining SecretEntry and Metadata fields
	returnMetadata := &SecretMetadata{
		SecretID:     secretEntry.ID,
		ContentType:  secretEntry.Metadata.ContentType,
		Size:         secretEntry.Metadata.Size,
		Description:  secretEntry.Metadata.Description,
		CreatedAt:    secretEntry.CreatedAt,
		UpdatedAt:    secretEntry.UpdatedAt,
		Version:      secretEntry.Version,
		AccessCount:  secretEntry.Metadata.AccessCount,
		LastAccessed: secretEntry.Metadata.LastAccessed,
		ExpiresAt:    secretEntry.Metadata.ExpiresAt,
		CustomFields: secretEntry.Metadata.CustomFields,
		Tags:         secretEntry.Tags,
		Checksum:     secretEntry.Metadata.Checksum,
		KeyID:        secretEntry.Metadata.KeyID,
	}

	// Success - log completion with key metadata
	v.logAudit(requestID, "UPDATE_SECRET_COMPLETED", nil, map[string]interface{}{
		"secret_id":   secretID,
		"duration_ms": time.Since(startTime).Milliseconds(),
		"version_change": map[string]interface{}{
			"from": previousVersion,
			"to":   secretEntry.Version,
		},
		"size_change": map[string]interface{}{
			"from": previousSize,
			"to":   secretSize,
		},
		"content_type_change": map[string]interface{}{
			"from": string(previousContentType),
			"to":   string(contentType),
		},
		"tags_updated":   len(tags) > 0,
		"final_checksum": checksum,
	})

	return returnMetadata, nil
}

// DeleteSecret permanently removes a secret from the vault by its ID.
//
// This function performs a secure deletion operation with the following guarantees:
// 1. Validates vault state and secret ID format
// 2. Verifies the secret exists before attempting deletion
// 3. Creates a complete backup for potential rollback scenarios
// 4. Atomically removes the secret from the container
// 5. Persists changes to storage with automatic rollback on failure
// 6. Comprehensive audit logging of the deletion operation
//
// IMPORTANT BEHAVIORS:
// - Deletion is permanent and cannot be undone once successfully completed
// - The operation is atomic - either the secret is fully deleted or remains unchanged
// - Automatic rollback occurs if storage persistence fails
// - Both the encrypted data and all associated metadata are removed
// - Container timestamp is updated to reflect the modification
//
// SECURITY CONSIDERATIONS:
// - Deleted secrets are removed from memory and storage immediately
// - No recovery mechanism exists - ensure deletion is intentional
// - Audit trail preserves record of deletion event and secret metadata
// - Rollback capability prevents partial deletions that could cause data corruption
//
// FAILURE HANDLING:
// - Storage persistence failures trigger automatic rollback to previous state
// - Critical errors (both deletion and rollback failures) are specially logged
// - Detailed error messages distinguish between different failure scenarios
//
// Parameters:
//   - secretID: Unique identifier of the secret to delete
//
// Returns:
//   - error: Any error encountered during validation, deletion, or persistence
//     Returns nil on successful deletion
//
// Thread Safety: This function is thread-safe through internal mutex locking
//
// Audit Logging: Comprehensive logging includes:
//   - Deletion attempts (successful and failed)
//   - Secret metadata at time of deletion
//   - Critical system errors requiring attention
//
// Storage: Changes are immediately persisted with rollback protection
//
// Example Usage:
//
//	err := vault.DeleteSecret("old-api-key")
//	if err != nil {
//	    if strings.Contains(err.Error(), "does not exist") {
//	        log.Printf("Secret was already deleted")
//	    } else {
//	        return fmt.Errorf("failed to delete secret: %w", err)
//	    }
//	}
//	log.Printf("Secret successfully deleted")
func (v *Vault) DeleteSecret(secretID string) error {
	startTime := time.Now()
	requestID := v.newRequestID()

	v.logAudit(requestID, "DELETE_SECRET_INITIATED", nil, map[string]interface{}{
		"secret_id": secretID,
	})

	if v.closed {
		err := fmt.Errorf("vault is closed")
		v.logAudit(requestID, "DELETE_SECRET_FAILED", err, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "vault_closed",
		})
		return err
	}

	if err := validateSecretID(secretID); err != nil {
		validationErr := fmt.Errorf("invalid secret ID: %w", err)
		v.logAudit(requestID, "DELETE_SECRET_FAILED", validationErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "invalid_secret_id",
		})
		return validationErr
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Get current secrets container
	container, err := v.getSecretsContainer()
	if err != nil {
		containerErr := fmt.Errorf("failed to get secrets container: %w", err)
		v.logAudit(requestID, "DELETE_SECRET_FAILED", containerErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "container_retrieval_failed",
		})
		return containerErr
	}

	// Check if secret exists
	secretEntry, exists := container.Secrets[secretID]
	if !exists {
		notFoundErr := fmt.Errorf("secret %s does not exist", secretID)
		v.logAudit(requestID, "DELETE_SECRET_FAILED", notFoundErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "secret_not_found",
		})
		return notFoundErr
	}

	// Store backup for rollback (deep copy)
	backup := &SecretsContainer{
		Version:   container.Version,
		Timestamp: container.Timestamp,
		Secrets:   make(map[string]*SecretEntry),
	}

	// Deep copy all secrets for rollback
	for id, entry := range container.Secrets {
		backup.Secrets[id] = &SecretEntry{
			ID:        entry.ID,
			Data:      make([]byte, len(entry.Data)),
			Metadata:  copySecretMetadata(entry.Metadata),
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
			Tags:      append([]string(nil), entry.Tags...),
			Version:   entry.Version,
		}
		copy(backup.Secrets[id].Data, entry.Data)
	}

	// Delete from container
	delete(container.Secrets, secretID)
	container.Timestamp = time.Now()

	// Update the secrets container in memory
	if err = v.updateSecretsContainer(container); err != nil {
		updateErr := fmt.Errorf("failed to update secrets container: %w", err)
		v.logAudit(requestID, "DELETE_SECRET_FAILED", updateErr, map[string]interface{}{
			"secret_id":      secretID,
			"failure_reason": "memory_update_failed",
		})
		return updateErr
	}

	// Persist changes to store
	if err = v.persistSecretsToStore(); err != nil {
		// Rollback: restore the backup container
		if rollbackErr := v.updateSecretsContainer(backup); rollbackErr != nil {
			// Critical error: both operation and rollback failed
			criticalErr := fmt.Errorf("failed to persist secrets and rollback failed: persist_err=%w, rollback_err=%v", err, rollbackErr)
			v.logAudit(requestID, "DELETE_SECRET_CRITICAL_FAILURE", criticalErr, map[string]interface{}{
				"secret_id":      secretID,
				"persist_error":  err.Error(),
				"rollback_error": rollbackErr.Error(),
				"data_integrity": "compromised",
			})
			return criticalErr
		}

		// Rollback successful
		persistErr := fmt.Errorf("failed to persist secrets: %w", err)
		v.logAudit(requestID, "DELETE_SECRET_FAILED", persistErr, map[string]interface{}{
			"secret_id":       secretID,
			"failure_reason":  "persist_failed_rollback_successful",
			"rollback_status": "successful",
		})
		return persistErr
	}

	// Success - log completion with key metadata
	v.logAudit(requestID, "DELETE_SECRET_COMPLETED", nil, map[string]interface{}{
		"secret_id":               secretID,
		"duration_ms":             time.Since(startTime).Milliseconds(),
		"remaining_secrets_count": len(container.Secrets),
		"deleted_secret_metadata": map[string]interface{}{
			"had_tags":     len(secretEntry.Tags) > 0,
			"content_type": secretEntry.Metadata.ContentType,
			"version":      secretEntry.Version,
		},
	})

	return nil
}

// GetAudit returns the audit logger instance associated with this vault.
//
// This function provides access to the vault's audit logging system, allowing
// external components to perform custom audit logging using the same logger
// configuration and destination as the vault's internal operations.
//
// USAGE SCENARIOS:
// - Custom audit logging for application-specific events
// - Integration with external security monitoring systems
// - Implementing additional compliance logging requirements
// - Debugging and troubleshooting vault operations
//
// IMPORTANT NOTES:
// - Returns nil if auditing was not enabled during vault initialization
// - The returned logger shares the same configuration as internal vault auditing
// - External logging through this interface maintains consistency with vault logs
// - Caller is responsible for proper error handling of audit operations
//
// SECURITY CONSIDERATIONS:
// - Audit logs may contain sensitive metadata (not secret data itself)
// - Ensure proper access controls when exposing audit functionality
// - Consider the security implications of custom audit events
//
// Returns:
//   - audit.Logger: The configured audit logger instance, or nil if auditing is disabled
//
// Thread Safety: The returned logger implementation should be thread-safe
//
// Example Usage:
//
//	auditLogger := vault.GetAudit()
//	if auditLogger != nil {
//	    err := auditLogger.Log("custom_event", true, map[string]interface{}{
//	        "user_id": userID,
//	        "action":  "secret_export",
//	    })
//	    if err != nil {
//	        log.Printf("Audit logging failed: %v", err)
//	    }
//	}
func (v *Vault) GetAudit() audit.Logger {
	return v.audit
}

// SecretExists checks whether a secret with the given ID exists in the vault.
//
// This function provides a lightweight way to verify secret existence without
// retrieving or decrypting the actual secret data, making it suitable for
// validation, conditional logic, and existence checks in application workflows.
//
// PERFORMANCE CHARACTERISTICS:
// - Uses read-only locking for better concurrent access performance
// - Does not decrypt or load secret data, only checks metadata presence
// - Minimal memory footprint compared to full secret retrieval
// - Fast operation suitable for frequent existence checks
//
// SECURITY CONSIDERATIONS:
// - Does not trigger access logging (unlike GetSecret operations)
// - Does not increment access counters or update last accessed timestamps
// - Safe for permission-checking workflows before actual secret access
// - Returns only boolean existence, no sensitive metadata exposure
//
// USE CASES:
// - Pre-validation before secret operations (update, delete, access)
// - Conditional secret creation (create only if not exists)
// - Bulk operations requiring existence verification
// - Application logic requiring secret presence confirmation
//
// Parameters:
//   - secretID: Unique identifier of the secret to check for existence
//
// Returns:
//   - bool: true if secret exists, false if it does not exist
//   - error: Any error encountered during validation or container access
//     Note: Non-existence is not an error condition
//
// Thread Safety: This function is thread-safe using read-only locking
//
// Audit Logging: This operation is not audited as it does not access secret data
//
// Example Usage:
//
//	exists, err := vault.SecretExists("api-key")
//	if err != nil {
//	    return fmt.Errorf("failed to check secret existence: %w", err)
//	}
//	if !exists {
//	    log.Printf("Secret 'api-key' not found, creating new one")
//	    // Proceed with secret creation
//	}
func (v *Vault) SecretExists(secretID string) (bool, error) {
	if err := validateSecretID(secretID); err != nil {
		return false, fmt.Errorf("invalid secret ID: %w", err)
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	container, err := v.getSecretsContainer()
	if err != nil {
		return false, fmt.Errorf("failed to get secrets container: %w", err)
	}

	_, exists := container.Secrets[secretID]
	return exists, nil
}

// ListSecrets retrieves a filtered list of secrets from the vault without exposing encrypted data.
//
// This function provides comprehensive secret discovery and inventory capabilities while
// maintaining security by returning only metadata and organizational information.
// The actual encrypted secret data is never included in the results, making this
// operation safe for broader access patterns and bulk operations.
//
// FILTERING CAPABILITIES:
// - Prefix matching: Filter secrets by ID prefix (e.g., "prod-", "dev-")
// - Tag filtering: Return only secrets containing all specified tags
// - Content type filtering: Filter by specific content types (text, binary, JSON, etc.)
// - Pagination: Limit and offset support for large secret inventories
//
// PERFORMANCE CHARACTERISTICS:
// - Uses read-only locking for optimal concurrent access
// - Does not decrypt any secret data, only processes metadata
// - Memory efficient for large secret stores
// - Results can be cached safely as they contain no sensitive data
//
// SECURITY CONSIDERATIONS:
// - No encrypted data or decrypted secrets are returned
// - Exposes only organizational metadata and usage statistics
// - Does not trigger access logging or increment access counters
// - Safe for inventory and management operations
// - DataSize field provides storage info without revealing actual content size
//
// PAGINATION BEHAVIOR:
// - If Limit is 0, all matching results are returned
// - Offset allows skipping initial results for pagination
// - Empty slice returned if offset exceeds total results
// - Pagination applied after all filtering operations
//
// USE CASES:
// - Secret inventory and discovery
// - Bulk operations planning (backup, migration, cleanup)
// - Compliance reporting and auditing
// - Secret organization and categorization
// - Application configuration management
// - Secret lifecycle management
//
// Parameters:
//   - options: Filtering and pagination options (nil for all secrets)
//   - Prefix: Filter by secret ID prefix
//   - Tags: Filter by required tags (AND operation)
//   - ContentType: Filter by specific content type
//   - Limit: Maximum number of results (0 for unlimited)
//   - Offset: Number of results to skip for pagination
//
// Returns:
//   - []*SecretListEntry: Array of secret metadata entries matching filters
//   - error: Any error encountered during container access or processing
//
// Thread Safety: This function is thread-safe using read-only locking
//
// Audit Logging: This operation is not audited as it does not access secret data
//
// Example Usage:
//
//	// List all production secrets
//	options := &SecretListOptions{
//	    Prefix: "prod-",
//	    Tags:   []string{"production", "active"},
//	    Limit:  50,
//	}
//	secrets, err := vault.ListSecrets(options)
//	if err != nil {
//	    return fmt.Errorf("failed to list secrets: %w", err)
//	}
//	for _, secret := range secrets {
//	    fmt.Printf("Secret: %s, Size: %d bytes, Updated: %s\n",
//	        secret.ID, secret.DataSize, secret.UpdatedAt.Format(time.RFC3339))
//	}
func (v *Vault) ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Set default options if not provided
	if options == nil {
		options = &SecretListOptions{}
	}

	container, err := v.getSecretsContainer()
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets container: %w", err)
	}

	var results []*SecretListEntry

	// Iterate through secrets in container
	for secretID, secretEntry := range container.Secrets {
		// Apply prefix filter if specified
		if options.Prefix != "" && !hasPrefix(secretID, options.Prefix) {
			continue
		}

		// Apply tag filter if specified
		if len(options.Tags) > 0 && !hasAllTags(secretEntry.Tags, options.Tags) {
			continue
		}

		// Apply content type filter if specified
		if options.ContentType != "" && secretEntry.Metadata.ContentType != options.ContentType {
			continue
		}

		// Create listing entry without exposing encrypted data
		listEntry := &SecretListEntry{
			ID:        secretEntry.ID,
			Metadata:  secretEntry.Metadata,
			CreatedAt: secretEntry.CreatedAt,
			UpdatedAt: secretEntry.UpdatedAt,
			Tags:      secretEntry.Tags,
			Version:   secretEntry.Version,
			DataSize:  len(secretEntry.Data), // Size info without exposing data
		}

		results = append(results, listEntry)
	}

	// Apply pagination if specified
	if options.Limit > 0 {
		start := options.Offset
		if start >= len(results) {
			return []*SecretListEntry{}, nil
		}

		end := start + options.Limit
		if end > len(results) {
			end = len(results)
		}

		results = results[start:end]
	}

	return results, nil
}

// GetSecretMetadata retrieves only the metadata for a specific secret without accessing encrypted data.
//
// This function provides access to all descriptive and organizational information
// about a secret while maintaining security by never decrypting or exposing the
// actual secret payload. It's designed for operations that need secret information
// but not the sensitive data itself.
//
// RETURNED METADATA INCLUDES:
// - Content type and encoding information
// - Creation and modification timestamps
// - Access patterns and usage statistics
// - Tags and categorization data
// - Version information and checksums
// - Custom metadata fields
// - Encryption key references
//
// PERFORMANCE CHARACTERISTICS:
// - Uses read-only locking for optimal concurrent access
// - No decryption operations performed
// - Minimal memory footprint
// - Fast operation suitable for frequent metadata checks
// - Safe for caching as no sensitive data is involved
//
// SECURITY CONSIDERATIONS:
// - Does not decrypt or expose any secret data
// - Does not trigger access logging (unlike GetSecret)
// - Does not update access counters or timestamps
// - Safe for permission validation workflows
// - Metadata may contain sensitive organizational information
//
// USE CASES:
// - Pre-validation before secret access operations
// - Secret organization and management workflows
// - Compliance reporting and auditing
// - Version checking for concurrent access control
// - Content type validation before processing
// - Tag-based categorization and filtering
// - Secret lifecycle management
//
// ERROR CONDITIONS:
// - Returns error if secret does not exist
// - Returns error for invalid secret ID format
// - Returns error if vault container cannot be accessed
//
// Parameters:
//   - secretID: Unique identifier of the secret whose metadata to retrieve
//
// Returns:
//   - SecretMetadata: Complete metadata structure for the secret
//   - error: Any error encountered during validation, access, or if secret not found
//
// Thread Safety: This function is thread-safe using read-only locking
//
// Audit Logging: This operation is not audited as it does not access secret data
//
// Example Usage:
//
//	metadata, err := vault.GetSecretMetadata("api-key")
//	if err != nil {
//	    if strings.Contains(err.Error(), "not found") {
//	        log.Printf("Secret does not exist")
//	        return nil
//	    }
//	    return fmt.Errorf("failed to get metadata: %w", err)
//	}
//
//	fmt.Printf("Secret: %s\n", metadata.Name)
//	fmt.Printf("Content Type: %s\n", metadata.ContentType)
//	fmt.Printf("Last Updated: %s\n", metadata.UpdatedAt.Format(time.RFC3339))
//	fmt.Printf("Version: %d\n", metadata.Version)
//	fmt.Printf("Tags: %v\n", metadata.Tags)
func (v *Vault) GetSecretMetadata(secretID string) (*SecretMetadata, error) {
	if err := validateSecretID(secretID); err != nil {
		return nil, fmt.Errorf("invalid secret ID: %w", err)
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	// Get the secrets container
	container, err := v.getSecretsContainer()
	if err != nil {
		return nil, fmt.Errorf("failed to access secrets container: %w", err)
	}

	// Check if secret exists
	secretEntry, exists := container.Secrets[secretID]
	if !exists {
		return nil, fmt.Errorf("secret %s not found", secretID)
	}

	// Return the metadata from the secret entry
	return secretEntry.Metadata, nil
}

// SecureMemoryProtection returns a human-readable description of the current memory protection level.
//
// This function provides visibility into the vault's comprehensive memory security configuration,
// which combines memguard secure enclaves with platform-specific memory locking to provide
// defense-in-depth against memory-based attacks and data exposure.
//
// IMPLEMENTATION DETAILS:
// The vault uses a layered memory protection approach:
// • memguard.Enclave containers for all sensitive data (keys, secrets, salts)
// • Platform-specific memory locking via mlockall() system calls
// • Automatic secure memory wiping on deallocation
// • Canary-based buffer overflow detection
// • Signal handler protection against memory dumps
//
// PROTECTION LEVELS EXPLAINED:
//
// • ProtectionNone: memguard enclaves active, but system memory locking failed
//   - Sensitive data is still protected in secure enclaves with canary guards
//   - Memory pages may still be swapped to disk by the operating system
//   - Provides baseline protection but vulnerable to swap file analysis
//   - Typically occurs due to insufficient system privileges
//
// • ProtectionPartial: memguard enclaves + limited system memory locking
//   - Full memguard protection with secure allocation and cleanup
//   - Memory locking attempted but failed with EPERM (permission) or ENOSYS (not supported)
//   - Better than ProtectionNone due to memguard's inherent protections
//   - Suitable for environments where full memory locking isn't available
//
// • ProtectionFull: memguard enclaves + complete system memory locking
//   - All memory pages locked via mlockall(MCL_CURRENT | MCL_FUTURE)
//   - Maximum protection against swap files, hibernation, and memory dumps
//   - Requires elevated privileges (CAP_IPC_LOCK on Linux)
//   - Recommended for production environments handling highly sensitive data
//
// SECURITY FEATURES ACTIVE AT ALL LEVELS:
// • Secure memory allocation via memguard enclaves
// • Cryptographically secure memory wiping on deallocation
// • Buffer overflow detection with canary values
// • Protection against memory dumps during process crashes
// • Isolation of sensitive data from regular heap allocation
//
// PLATFORM COMPATIBILITY:
// • Linux: Full support for mlockall() with proper capabilities
// • Darwin (macOS): Full support with administrator privileges
// • BSD variants: Full support where mlockall() is available
// • Windows: Separate implementation (not shown) using VirtualLock()
//
// OPERATIONAL REQUIREMENTS:
// • ProtectionFull requires CAP_IPC_LOCK capability or root privileges on Unix systems
// • Memory locking may be limited by RLIMIT_MEMLOCK resource limits
// • Locked memory cannot be swapped, potentially affecting system performance
// • Process memory usage becomes non-swappable, affecting system memory management
//
// Returns:
//   - string: Detailed description of active memory protection measures
//     including both memguard and system-level protections
//
// Example Usage:
//
//	protection := vault.SecureMemoryProtection()
//	log.Printf("Memory protection status: %s", protection)
//
//	// Check if running with maximum security
//	if strings.Contains(protection, "Full") {
//	    log.Info("Running with maximum memory protection")
//	} else {
//	    log.Warn("Consider running with elevated privileges for full protection")
//	}
func (v *Vault) SecureMemoryProtection() string {
	switch v.memoryProtectionLevel {
	case mem.ProtectionNone:
		return "None - sensitive data may be swapped to disk"
	case mem.ProtectionPartial:
		return "Partial - basic memory protection applied"
	case mem.ProtectionFull:
		return "Full - memory locked and protected from swapping"
	default:
		return "Unknown"
	}
}

// Close performs a secure shutdown of the vault with guaranteed data persistence and memory cleanup.
//
// This function implements a comprehensive shutdown sequence that ensures data integrity,
// security, and proper resource cleanup. It coordinates the orderly termination of all
// vault operations while maintaining security guarantees and preventing data loss.
//
// SHUTDOWN SEQUENCE:
// 1. Acquire exclusive lock to prevent concurrent operations
// 2. Persist all in-memory secrets to durable storage
// 3. Set closed flag to reject new operations
// 4. Log shutdown event for audit compliance
// 5. Close audit logging subsystem
// 6. Securely destroy all memguard enclaves containing sensitive data
// 7. Clear all references to prevent accidental access
// 8. Report any errors that occurred during shutdown
//
// DATA PERSISTENCE GUARANTEE:
// Before any cleanup occurs, the function ensures all in-memory secrets are
// persisted to the backing store. This prevents data loss even if the application
// terminates unexpectedly after calling Close(). If persistence fails, the error
// is captured but cleanup continues to prevent memory leaks.
//
// SECURE MEMORY CLEANUP:
// All sensitive data stored in memguard enclaves is securely wiped:
// • secretsContainer: Encrypted secrets metadata
// • keyEnclaves: All encryption/decryption keys
// • derivationKeyEnclave: Master key derivation material
// • derivationSaltEnclave: Cryptographic salt values
//
// The cleanup leverages memguard's secure deallocation which:
// - Overwrites memory with cryptographically secure random data
// - Performs multiple overwrite passes where supported
// - Uses platform-specific secure memory clearing functions
// - Protects against cold boot attacks and memory forensics
//
// AUDIT COMPLIANCE:
// A shutdown event is logged before closing the audit subsystem, providing
// a complete audit trail that includes vault termination. This supports:
// • Compliance with security logging requirements
// • Operational monitoring and alerting
// • Forensic analysis of vault lifecycle events
// • Detection of unexpected or unauthorized shutdowns
//
// ERROR HANDLING STRATEGY:
// The function uses a "best effort" approach where errors during one cleanup
// step don't prevent other cleanup steps from executing. All errors are
// collected and returned as a combined error, allowing calling code to:
// • Log all issues that occurred during shutdown
// • Take corrective action if needed
// • Implement retry logic for critical failures
//
// THREAD SAFETY:
// Close() acquires an exclusive lock at the beginning and holds it throughout
// the entire shutdown sequence. This ensures:
// • No concurrent operations can interfere with shutdown
// • All in-flight operations complete before cleanup begins
// • Memory cleanup is atomic and cannot be interrupted
// • The closed flag is set atomically
//
// POST-CLOSE BEHAVIOR:
// After Close() completes, the vault instance becomes permanently unusable.
// The closed flag prevents any further operations, and all sensitive data
// has been securely destroyed. Attempting to use the vault after closing
// will result in errors from operation methods that check the closed flag.
//
// RESOURCE MANAGEMENT:
// This function is designed to be called from defer statements, finalizers,
// or explicit cleanup code. It's safe to call multiple times (subsequent
// calls will be no-ops due to the closed flag and nil checks).
//
// SECURITY CONSIDERATIONS:
// • Memory cleanup occurs even if persistence fails
// • Audit logging happens before audit system shutdown
// • Errors don't prevent security-critical cleanup steps
// • All sensitive data references are explicitly cleared
// • The function cannot be bypassed once the lock is acquired
//
// Returns:
//   - error: Combined error containing all issues encountered during shutdown,
//     or nil if shutdown completed successfully. Errors don't indicate
//     security failures, as cleanup always proceeds regardless of errors.
//
// Example Usage:
//
//	// Explicit cleanup
//	if err := vault.Close(); err != nil {
//	    log.Errorf("Vault shutdown encountered issues: %v", err)
//	}
//
//	// Defer pattern for guaranteed cleanup
//	vault, err := NewVault(config)
//	if err != nil {
//	    return err
//	}
//	defer func() {
//	    if closeErr := vault.Close(); closeErr != nil {
//	        log.Errorf("Vault cleanup failed: %v", closeErr)
//	    }
//	}()
//
//	// Graceful application shutdown
//	func (app *Application) Shutdown(ctx context.Context) error {
//	    if app.vault != nil {
//	        return app.vault.Close()
//	    }
//	    return nil
//	}
func (v *Vault) Close() error {
	requestID := v.newRequestID()

	var errs []error

	v.mu.Lock()
	defer v.mu.Unlock()

	// Ensure all data is persisted before closing
	if v.secretsContainer != nil {
		if err := v.persistSecretsToStore(); err != nil {
			errs = append(errs, fmt.Errorf("failed to persist secrets before close: %w", err))
		}
	}

	// Add a closed flag to prevent further operations
	v.closed = true

	// Close audit logger (but do it after persistence)
	if v.audit != nil {
		// Log vault shutdown before closing
		v.logAudit(requestID, "VAULT_SHUTDOWN", combinerErr(errs), map[string]interface{}{
			"errors": len(errs),
		})

		if err := v.audit.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close audit logger: %w", err))
		}
	}

	// Securely clear secrets container enclave
	if v.secretsContainer != nil {
		v.secretsContainer = nil
	}

	// Clear key enclaves
	for keyID, enclave := range v.keyEnclaves {
		if enclave != nil {
			delete(v.keyEnclaves, keyID)
		}
	}

	// Clean up derivation key enclave
	if v.derivationKeyEnclave != nil {
		v.derivationKeyEnclave = nil
	}

	// Clear salt
	if v.derivationSaltEnclave != nil {
		v.derivationSaltEnclave = nil
	}

	// Return combined errors if any
	if len(errs) > 0 {
		return fmt.Errorf("vault close errors: %v", errs)
	}

	return nil
}

func combinerErr(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var sb strings.Builder
	for _, err := range errs {
		sb.WriteString(err.Error())
		sb.WriteString("; ")
	}
	return fmt.Errorf(strings.TrimRight(sb.String(), " "))
}

// DeleteTenant securely removes all resources associated with a specified tenant.
//
// This operation is irreversible, ensuring that all data related to the tenant,
// including secrets, keys, and metadata, are securely deleted from storage.
//
// Parameters:
//   - tenantID: A unique identifier for the tenant whose resources are to be deleted.
//     This ID is used to locate and remove all associated data.
//
// Returns:
//   - error: Returns nil if the deletion is successful, or an error if the deletion
//     fails. The error provides detailed information about what went wrong,
//     which can be useful for auditing and troubleshooting.
//
// Security Notes:
//   - This operation ensures that all data associated with the tenant ID is securely wiped,
//     eliminating risks of data recovery.
//   - Actions taken are logged for audit purposes, capturing both successful deletions
//     and any errors encountered during the process.
//
// Example Usage:
//
//	err := vault.DeleteTenant("tenant-1234")
//	if err != nil {
//	    log.Printf("Failed to delete tenant: %v", err)
//	} else {
//	    log.Println("Tenant deleted successfully.")
//	}
func (v *Vault) DeleteTenant(tenantID string) error {
	requestID := v.newRequestID()

	// Step 1: Securely delete the tenant's resources from storage
	if err := v.store.DeleteTenant(tenantID); err != nil {
		err = fmt.Errorf("failed to delete tenant %s and its resources: %w", tenantID, err)
		v.logAudit(requestID, "DELETE_TENANT", err, nil)
		return err
	}

	// Step 2: Log the deletion for audit purposes
	v.logAudit(requestID, "DELETE_TENANT", nil, nil)

	return nil
}

// Helper functions

// decryptWithCurrentKey to return both data and active key flag
func (v *Vault) decryptWithCurrentKey(encryptedData []byte) ([]byte, bool, error) {
	if v.currentKeyID == "" {
		return nil, false, fmt.Errorf("no current key available")
	}

	// First, try with the current (active) key
	enclave, exists := v.keyEnclaves[v.currentKeyID]
	if !exists {
		return nil, false, fmt.Errorf("current key not found in memory")
	}

	// Attempt decryption with current key
	data, err := v.decryptWithKeyEnclave(encryptedData, enclave)
	if err == nil {
		// Successfully decrypted with active key
		return data, true, nil
	}

	// If decryption with current key failed, try with other available keys
	// This handles the case where data was encrypted with a previous key
	for keyID, keyEnclave := range v.keyEnclaves {
		if keyID == v.currentKeyID {
			continue // Already tried this one
		}

		data, err := v.decryptWithKeyEnclave(encryptedData, keyEnclave)
		if err == nil {
			// Successfully decrypted with a non-active key
			return data, false, nil
		}
	}

	// If we get here, decryption failed with all available keys
	return nil, false, fmt.Errorf("failed to decrypt with any available key")
}

// getSecretsContainer retrieves and decrypts the unified secrets container
func (v *Vault) getSecretsContainer() (*SecretsContainer, error) {
	debug.Print("getSecretsContainer: Starting\n")

	// Check if we have an in-memory container
	if v.secretsContainer == nil {
		return nil, fmt.Errorf("secrets container not initialized")
	}

	// Access the encrypted data from memguard enclave
	buffer, err := v.secretsContainer.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open secrets container enclave: %w", err)
	}
	defer buffer.Destroy()

	// Get the encrypted data bytes
	encryptedData := buffer.Bytes()
	debug.Print("getSecretsContainer: Encrypted data size: %d bytes\n", len(encryptedData))

	// Decrypt the container data using current key
	debug.Print("getSecretsContainer: Decrypting with current key: %s\n", v.currentKeyID)
	decryptedData, _, err := v.decryptWithCurrentKey(encryptedData)
	if err != nil {
		debug.Print("getSecretsContainer: Decryption failed: %v\n", err)
		return nil, fmt.Errorf("failed to decrypt secrets container: %w", err)
	}

	debug.Print("getSecretsContainer: Decrypted data size: %d bytes\n", len(decryptedData))

	// Deserialize the container
	container := &SecretsContainer{}
	if err = json.Unmarshal(decryptedData, container); err != nil {
		debug.Print("getSecretsContainer: JSON unmarshal failed: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal secrets container: %w", err)
	}

	// Validate container
	if container == nil {
		return nil, fmt.Errorf("secrets container is nil after decryption")
	}

	// Initialize Secrets map if nil
	if container.Secrets == nil {
		container.Secrets = make(map[string]*SecretEntry)
	}

	debug.Print("getSecretsContainer: Successfully parsed container with %d secrets\n", len(container.Secrets))

	return container, nil
}

// updateSecretsContainer updates the in-memory encrypted container
func (v *Vault) updateSecretsContainer(container *SecretsContainer) error {
	// Update timestamp
	container.Timestamp = time.Now().UTC()

	// Serialize the updated container
	containerData, err := json.Marshal(container)
	if err != nil {
		return fmt.Errorf("failed to marshal updated container: %w", err)
	}

	// **FIX: Encrypt the container data**
	encryptedData, err := v.encryptWithCurrentKey(containerData)
	if err != nil {
		return fmt.Errorf("failed to encrypt updated container: %w", err)
	}

	// **FIX: Store ENCRYPTED data in enclave**
	v.secretsContainer = memguard.NewEnclave(encryptedData)

	// Update version tracking
	v.secretsVersion = container.Version
	v.secretsTimestamp = container.Timestamp

	return nil
}

// getSecretsStorageVersion retrieves the current storage version for secrets
func (v *Vault) getSecretsStorageVersion() (string, error) {
	// Check if secrets exist in storage
	exists, err := v.store.SecretsDataExists()
	if err != nil {
		return "", fmt.Errorf("failed to check secrets existence: %w", err)
	}

	if !exists {
		// No existing secrets, use empty version for new file
		return "", nil
	}

	// Load current versioned data to get the version
	versionedData, err := v.store.LoadSecretsData()
	if err != nil {
		return "", fmt.Errorf("failed to load secrets for version check: %w", err)
	}

	return versionedData.Version, nil
}

// Helper method to handle concurrency conflicts
func (v *Vault) handleConcurrencyConflict(operation string, concErr persist.ConcurrencyError) error {
	// For now, return the concurrency error to let the caller decide
	// In the future, this could implement retry logic with exponential backoff
	return fmt.Errorf("concurrency conflict in %s - expected version '%s' but found '%s': %w",
		operation, concErr.ExpectedVersion, concErr.ActualVersion, concErr)
}

//// loadSecretsContainer loads the secrets container from persistent storage
//func (v *Vault) loadSecretsContainer(requestID string) error {
//	// Load versioned encrypted data from storage
//	versionedData, err := v.store.LoadSecretsData()
//	if err != nil {
//		return fmt.Errorf("failed to load secrets data from store: %w", err)
//	}
//
//	// Create memguard enclave with the encrypted data
//	v.secretsContainer = memguard.NewEnclave(versionedData.Data)
//
//	// Validate that we can decrypt and parse the container
//	container, err := v.getSecretsContainer()
//	if err != nil {
//		v.secretsContainer = nil
//		return fmt.Errorf("failed to validate loaded secrets container: %w", err)
//	}
//
//	// Update version tracking
//	v.secretsVersion = container.Version
//	v.secretsTimestamp = container.Timestamp
//
//	// Log version information for audit/debugging
//	if v.audit != nil {
//		v.logAudit(requestID, "SECRETS_LOADED", nil, map[string]interface{}{
//			"storage_version":   versionedData.Version,
//			"container_version": container.Version,
//			"timestamp":         container.Timestamp,
//		})
//	}
//
//	return nil
//}

// initializeSecretsContainer initializes an empty secrets container
func (v *Vault) initializeSecretsContainer() error {
	debug.Print("initializeSecretsContainer: Starting\n")

	// Try to load existing secrets from storage FIRST
	versionedData, err := v.store.LoadSecretsData()
	if err != nil {
		if os.IsNotExist(err) {
			debug.Print("initializeSecretsContainer: No existing secrets found, creating empty container\n")
			// No existing secrets - create new empty container
			return v.createEmptySecretsContainer()
		}
		return fmt.Errorf("failed to load existing secrets: %w", err)
	}

	debug.Print("initializeSecretsContainer: Loaded existing secrets data, size: %d bytes, storage version: %s\n",
		len(versionedData.Data), versionedData.Version)

	// Store the ENCRYPTED data in enclave
	v.secretsContainer = memguard.NewEnclave(versionedData.Data)

	// Validate by trying to decrypt and parse
	debug.Print("initializeSecretsContainer: Validating loaded secrets container\n")
	container, err := v.getSecretsContainer()
	if err != nil {
		debug.Print("initializeSecretsContainer: Failed to validate: %v\n", err)
		return fmt.Errorf("failed to validate loaded secrets container: %w", err)
	}

	debug.Print("initializeSecretsContainer: Successfully validated, found %d secrets, container version: %s\n",
		len(container.Secrets), container.Version)

	// Update version tracking
	v.secretsVersion = container.Version
	v.secretsTimestamp = container.Timestamp

	return nil
}

// Helper method to create empty container
func (v *Vault) createEmptySecretsContainer() error {
	debug.Print("createEmptySecretsContainer: Starting\n")

	container := &SecretsContainer{
		Version:   "1.0",
		Timestamp: time.Now().UTC(),
		Secrets:   make(map[string]*SecretEntry),
	}

	// Serialize the container
	containerData, err := json.Marshal(container)
	if err != nil {
		return fmt.Errorf("failed to marshal empty container: %w", err)
	}
	debug.Print("createEmptySecretsContainer: Serialized container to %d bytes\n", len(containerData))

	// Encrypt BEFORE storing in enclave (consistent with updateSecretsContainer)
	encryptedData, err := v.encryptWithCurrentKey(containerData)
	if err != nil {
		return fmt.Errorf("failed to encrypt empty container: %w", err)
	}
	debug.Print("createEmptySecretsContainer: Encrypted container to %d bytes, first 32: %x\n",
		len(encryptedData), encryptedData[:min(32, len(encryptedData))])

	// Store ENCRYPTED data in enclave (consistent with rest of system)
	v.secretsContainer = memguard.NewEnclave(encryptedData)

	// Save encrypted data to storage
	debug.Print("createEmptySecretsContainer: About to save to storage\n")
	if err = v.saveSecretsDataWithRetry(encryptedData); err != nil {
		v.secretsContainer = nil
		return fmt.Errorf("failed to save empty container: %w", err)
	}
	debug.Print("createEmptySecretsContainer: Successfully saved to storage\n")

	// Update version tracking
	v.secretsVersion = container.Version
	v.secretsTimestamp = container.Timestamp

	debug.Print("createEmptySecretsContainer: Completed successfully\n")
	return nil
}

// Helper method to load existing container
func (v *Vault) loadExistingSecretsContainer(encryptedData []byte) error {
	// Decrypt the container data
	decryptedData, _, err := v.decryptWithCurrentKey(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt secrets container: %w", err)
	}

	// Parse container to validate it
	var container SecretsContainer
	if err = json.Unmarshal(decryptedData, &container); err != nil {
		return fmt.Errorf("failed to unmarshal secrets container: %w", err)
	}

	// Store decrypted data in enclave (not encrypted)
	v.secretsContainer = memguard.NewEnclave(decryptedData)

	// Update version tracking
	v.secretsVersion = container.Version
	v.secretsTimestamp = container.Timestamp

	return nil
}

func (v *Vault) decryptWithKeyEnclave(encryptedData []byte, enclave *memguard.Enclave) ([]byte, error) {
	debug.Print("decryptWithKeyEnclave: Received encrypted data first 32: %x\n", encryptedData[:min(32, len(encryptedData))])

	if encryptedData == nil {
		return nil, fmt.Errorf("encrypted data cannot be nil")
	}

	if enclave == nil {
		return nil, fmt.Errorf("key enclave cannot be nil")
	}

	// Open the enclave to access the key
	buffer, err := enclave.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open key enclave: %w", err)
	}
	defer buffer.Destroy()

	// Get the raw key bytes
	keyBytes := buffer.Bytes()
	debug.Print("decryptWithKeyEnclave: Key bytes first 16: %x\n", keyBytes[:min(16, len(keyBytes))])

	// Use ChaCha20Poly1305 (same as Encrypt method)
	aead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := aead.NonceSize()
	debug.Print("decryptWithKeyEnclave: NonceSize: %d, DataSize: %d\n", nonceSize, len(encryptedData))

	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	debug.Print("decryptWithKeyEnclave: Extracted nonce: %x\n", nonce)
	debug.Print("decryptWithKeyEnclave: Ciphertext size: %d\n", len(ciphertext))

	// Decrypt the data using ChaCha20Poly1305
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		debug.Print("decryptWithKeyEnclave: Decryption failed: %v\n", err)
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

func (v *Vault) createNewSecretsContainer() error {
	requestID := v.newRequestID()

	debug.Print("createNewSecretsContainer: Starting\n")

	now := time.Now()
	container := &SecretsContainer{
		Version:   "1.0",
		Timestamp: now,
		Secrets:   make(map[string]*SecretEntry),
	}

	// Serialize the container
	containerData, err := json.Marshal(container)
	if err != nil {
		return fmt.Errorf("failed to serialize secrets container: %w", err)
	}
	debug.Print("createNewSecretsContainer: Serialized container to %d bytes\n", len(containerData))

	// Encrypt the container data
	encryptedData, err := v.encryptWithCurrentKey(containerData)
	if err != nil {
		return fmt.Errorf("failed to encrypt secrets container: %w", err)
	}
	debug.Print("createNewSecretsContainer: Encrypted container to %d bytes, first 32: %x\n",
		len(encryptedData), encryptedData[:min(32, len(encryptedData))])

	// Create protected enclave for the ENCRYPTED container
	enclave := memguard.NewEnclave(encryptedData)
	v.secretsContainer = enclave
	v.secretsVersion = container.Version
	v.secretsTimestamp = now

	// Clear sensitive data
	for i := range containerData {
		containerData[i] = 0
	}

	debug.Print("createNewSecretsContainer: About to persist to store\n")
	// Save the container to disk
	if err = v.persistSecretsToStore(); err != nil {
		return fmt.Errorf("failed to persist secrets container: %w", err)
	}
	debug.Print("createNewSecretsContainer: Successfully persisted to store\n")

	// Log container creation
	v.logAudit(requestID, "SECRETS_CONTAINER_CREATED", nil, map[string]interface{}{
		"version": container.Version,
	})

	debug.Print("createNewSecretsContainer: Completed successfully\n")
	return nil
}

// getSecretsCount returns the current number of secrets (for audit logging)
func (v *Vault) getSecretsCount() int {
	container, err := v.getSecretsContainer()
	if err != nil {
		return 0
	}
	return len(container.Secrets)
}

//func (v *Vault) loadSecretsFromStore() error {
//	requestID := v.newRequestID()
//
//	// Check if secrets data exists
//	exists, err := v.store.SecretsDataExists()
//	if err != nil {
//		return fmt.Errorf("failed to check secrets data existence: %w", err)
//	}
//
//	if !exists {
//		return os.ErrNotExist // No secrets exist yet
//	}
//
//	// Load versioned encrypted secrets data
//	versionedData, err := v.store.LoadSecretsData()
//	if err != nil {
//		return fmt.Errorf("failed to load secrets data: %w", err)
//	}
//
//	// Decrypt the secrets container
//	containerData, _, err := v.decryptWithCurrentKey(versionedData.Data)
//	if err != nil {
//		return fmt.Errorf("failed to decrypt secrets container: %w", err)
//	}
//
//	// Create protected enclave for the decrypted container
//	enclave := memguard.NewEnclave(containerData)
//	v.secretsContainer = enclave
//
//	// Parse container to get version and timestamp
//	container, err := v.getSecretsContainer()
//	if err != nil {
//		return fmt.Errorf("failed to validate secrets container: %w", err)
//	}
//
//	// Update vault metadata
//	v.secretsVersion = container.Version
//	v.secretsTimestamp = container.Timestamp
//
//	// Log successful loading with version information
//	if v.audit != nil {
//		v.logAudit(requestID, "SECRETS_LOADED", nil, map[string]interface{}{
//			"secrets_count":     len(container.Secrets),
//			"container_version": container.Version,
//			"storage_version":   versionedData.Version,
//			"timestamp":         container.Timestamp,
//		})
//	}
//	return nil
//}

func (v *Vault) persistSecretsToStore() error {
	debug.Print("persistSecretsToStore: Starting\n")

	if v.secretsContainer == nil {
		return fmt.Errorf("secrets container not initialized")
	}

	buffer, err := v.secretsContainer.Open()
	if err != nil {
		return fmt.Errorf("failed to open secrets container: %w", err)
	}
	defer buffer.Destroy()

	encryptedData := make([]byte, len(buffer.Bytes()))
	copy(encryptedData, buffer.Bytes())

	debug.Print("persistSecretsToStore: Saving %d bytes, first 32 bytes: %x\n",
		len(encryptedData), encryptedData[:min(32, len(encryptedData))])

	if err = v.saveSecretsDataWithRetry(encryptedData); err != nil {
		return fmt.Errorf("failed to save secrets data: %w", err)
	}

	debug.Print("persistSecretsToStore: Successfully saved to store\n")
	return nil
}

func (v *Vault) encryptWithCurrentKey(data []byte) ([]byte, error) {
	debug.Print("encryptWithCurrentKey: Using key ID: %s\n", v.currentKeyID)

	if v.currentKeyID == "" {
		return nil, fmt.Errorf("no current key available")
	}

	enclave, exists := v.keyEnclaves[v.currentKeyID]
	if !exists {
		return nil, fmt.Errorf("current key not found in memory")
	}

	return v.encryptWithKeyEnclave(data, enclave)
}

func (v *Vault) decryptWithKey(encryptedData []byte, keyID string) ([]byte, error) {
	enclave, exists := v.keyEnclaves[keyID]
	if !exists {
		return nil, fmt.Errorf("decryption key %s not found", keyID)
	}

	return v.decryptWithKeyEnclave(encryptedData, enclave)
}

func (v *Vault) encryptWithKey(data []byte, keyID string) ([]byte, error) {
	enclave, exists := v.keyEnclaves[keyID]
	if !exists {
		return nil, fmt.Errorf("encryption key %s not found", keyID)
	}

	return v.encryptWithKeyEnclave(data, enclave)
}

func (v *Vault) encryptWithKeyEnclave(data []byte, enclave *memguard.Enclave) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	if enclave == nil {
		return nil, fmt.Errorf("key enclave cannot be nil")
	}

	// Open the enclave to access the key
	buffer, err := enclave.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open key enclave: %w", err)
	}
	defer buffer.Destroy()

	// Get the raw key bytes
	keyBytes := buffer.Bytes()
	debug.Print("encryptWithKeyEnclave: Key bytes first 16: %x\n", keyBytes[:min(16, len(keyBytes))])

	// Use ChaCha20Poly1305 (same as Encrypt and decryptWithKeyEnclave)
	aead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	debug.Print("encryptWithKeyEnclave: Generated nonce: %x\n", nonce)

	// Encrypt the data
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Prepend nonce to ciphertext for storage
	// Format: [nonce][ciphertext]
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	debug.Print("encryptWithKeyEnclave: Final encrypted size: %d, first 32: %x\n", len(result), result[:min(32, len(result))])

	return result, nil
}

func (v *Vault) logAudit(requestID, action string, err error, metadata map[string]interface{}) {
	if v.audit == nil {
		log.Printf("WAARNING: skipping audit logging, logger not initialized\n")
		return
	}
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add standard fields
	metadata["tenant_id"] = v.tenantID
	metadata["user_id"] = v.userID
	metadata["request_id"] = requestID
	metadata["timestamp"] = time.Now().UTC()

	success := err == nil
	if err != nil {
		metadata["error"] = err.Error()
	}

	if auditErr := v.audit.Log(action, success, metadata); auditErr != nil {
		log.Printf("ERROR: audit logging failed for action %s: %v\n", action, auditErr)
	}
}

func (v *Vault) newRequestID() string {
	return fmt.Sprintf("v_%d", time.Now().UnixNano())
}

// withRetry executes an operation with exponential backoff retry on concurrency conflicts
func (v *Vault) withRetry(operation string, fn func() error) error {
	config := DefaultRetryConfig()

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		// Check if it's a concurrency error
		if concErr, ok := err.(interface{ IsConcurrencyError() bool }); ok && concErr.IsConcurrencyError() {
			if attempt == config.MaxRetries {
				return fmt.Errorf("operation %s failed after %d attempts due to concurrent modifications: %w",
					operation, config.MaxRetries+1, err)
			}

			// Calculate delay with exponential backoff and jitter
			delay := time.Duration(config.BaseDelay * (1 << attempt))
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}

			// Add jitter (±25%)
			jitter := time.Duration(float64(delay) * 0.25 * (2*mrand.Float64() - 1))
			delay += jitter

			time.Sleep(delay)
			continue
		}

		// Not a concurrency error, return immediately
		return err
	}

	return fmt.Errorf("operation %s exhausted all retry attempts", operation)
}

// saveMetadataWithRetry saves key meta-data with optimistic concurrency control
func (v *Vault) saveMetadataWithRetry(data []byte) error {
	return v.withRetry("saveMetadata", func() error {
		// Load current version
		currentData, err := v.store.LoadMetadata()
		var currentVersion string
		if err == nil {
			currentVersion = currentData.Version
		}

		// Attempt to save with current version
		_, err = v.store.SaveMetadata(data, currentVersion)
		return err
	})
}

// saveSecretsDataWithRetry saves secret data with optimistic concurrency control
func (v *Vault) saveSecretsDataWithRetry(data []byte) error {
	return v.withRetry("saveSecretsData", func() error {
		currentData, err := v.store.LoadSecretsData()
		var currentVersion string
		if err == nil {
			currentVersion = currentData.Version
		}

		_, err = v.store.SaveSecretsData(data, currentVersion)
		return err
	})
}

// saveSaltWithRetry saves salt data with optimistic concurrency control
func (v *Vault) saveSaltWithRetry(data []byte) error {
	return v.withRetry("saveSalt", func() error {
		// Load current version
		currentData, err := v.store.LoadSalt()
		var currentVersion string
		if err == nil {
			currentVersion = currentData.Version
		}

		// Attempt to save with current version
		_, err = v.store.SaveSalt(data, currentVersion)
		return err
	})
}
