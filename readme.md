![volta](volta.jpeg)
# Volta: Secure Secret Storage and Data Encryption for Go Applications

## Introduction and Core Concepts

Volta is a Go library engineered to provide robust, secure secret storage and data encryption capabilities. It is designed for direct embedding within Go applications, establishing zero-dependency and zero-trust boundaries for managing sensitive information. This approach helps applications meet stringent GDPR and Data Protection requirements without relying on external services or complex infrastructure.

Volta's philosophy balances comprehensive security features with operational simplicity, catering to the demands of modern enterprise-level security. Key architectural tenets include:

*   **Multitenancy:** Securely isolate data and operations for different applications, services, or organizational units.
*   **Pluggable Backends:** Offers flexibility through well-defined abstractions for storage and audit logging, allowing custom implementations to fit diverse operational environments.
*   **In-Memory Protection:** Incorporates measures to safeguard critical information, such as cryptographic keys, while resident in application memory.
*   **No REST API**: as it is primarily designed to be embedded. If access REST APIs are required, they can built based on your specific requirements, limiting exposure of operations, implementing the required authentication and access controls methods.
*   **Non-Exportable Keys**: encryption keys are non-exportable.  
*   **Command Line interface**: is provided for vault management operations.

This document serves as a guide to understanding Volta's architecture, its components, and how to leverage its capabilities effectively.

For additional articles expanding the understanding of Volta see:

- [Feature Set](docs/features.md)
- [Compariing with HashiCorp Vault](docs/compare_vault.md)
- [Facilitating GDPR compliance](docs/gdpr.md)
- [Facilitating HIPAA compliance](docs/hipaa.md)
- [Facilitating PCI-DSS compliance](docs/pci_dss.md)
- [Facilitating Zero Trust Architecture](docs/zta.md)
- [Secret Access Guidelines](docs/secret_access.md)

### Core Concepts

Understanding the following concepts is fundamental to working with Volta:

1.  **Tenancy:**
    Volta's multitenant architecture enables a single instance to serve multiple, isolated tenants. Each tenant (e.g., a distinct application, microservice, or department) operates within its own secure context, with dedicated encryption keys, secrets, and audit trails. This isolation is crucial for managing data access and compliance across different entities.

2.  **Vault (`VaultService`):**
    The `VaultService` interface represents an individual tenant's vault. It is the primary interaction point for all cryptographic operations and secret management activities pertinent to that tenant. This includes encrypting and decrypting data, managing the lifecycle of secrets (storing, retrieving, updating, deleting), and handling tenant-specific encryption keys. Each `VaultService` instance is scoped to a single tenant.

3.  **Vault Manager (`VaultManagerService`):**
    The `VaultManagerService` interface acts as the top-level orchestrator for the entire Volta deployment. It manages the lifecycle of tenant vaults (e.g., retrieving a vault for a specific tenant, closing tenant sessions). It also supports administrative operations that span across multiple tenants, such as bulk key rotations, passphrase changes, and querying aggregated audit logs from various tenants. This service is the main entry point for applications interacting with Volta.

4.  **Secrets:**
    In Volta, a "secret" refers to any piece of sensitive information that requires secure storage and controlled access. Examples include API keys, database credentials, personal identifiable information (PII), or configuration parameters. Volta ensures secrets are encrypted at rest using strong cryptographic measures, with access governed by the tenant's vault.

5.  **Encryption Keys:**
    Cryptographic keys are the cornerstone of Volta's security. Volta manages the lifecycle of these keys—including generation, rotation, and secure destruction—on a per-tenant basis. Data and secrets are encrypted using these keys, ensuring that even if the underlying storage is compromised, the sensitive information remains protected.

6.  **Storage Backend (`Store` Interface):**
    Volta abstracts its persistence layer through the `Store` interface. This design allows developers to integrate Volta with various storage mechanisms, such as local file systems, distributed key-value stores, or cloud-based storage services. While Volta may provide default implementations, the pluggable nature of the `Store` interface ensures that organizations can use storage solutions that align with their existing infrastructure and policies. The store is responsible for persisting encrypted key metadata, encrypted secrets data, and other essential vault state.

7.  **Audit Backend (`audit.Logger` Interface):**
    Comprehensive and immutable audit trails are critical for security monitoring, compliance, and forensic analysis. Volta utilizes the `audit.Logger` interface to log significant events. These events include key management operations (creation, rotation, destruction), secret access patterns (creation, retrieval, updates, deletion), administrative actions, and failed operations. Like the storage backend, the audit backend is pluggable, enabling integration with various logging systems, Security Information and Event Management (SIEM) tools, or custom audit repositories.

8.  **In-Memory Protection:**
    Protecting sensitive data, especially cryptographic keys, while it is actively being used in application memory is a significant challenge. Volta incorporates techniques to mitigate risks associated with memory exposure (e.g., from memory dumps or certain side-channel attacks). This is achieved through mechanisms like leveraging secure memory enclaves and careful handling of sensitive byte slices. The `VaultService.SecureMemoryProtection()` method provides insight into the status or configuration of these protections.

### High-Level Operational Flow

A typical interaction with Volta involves the following conceptual steps:

1.  **Initialization:**
    An application initializes the `VaultManagerService`. This step typically involves configuring the desired storage and audit backends.
2.  **Tenant Vault Access:**
    The application requests a `VaultService` instance for a specific `tenantID` from the `VaultManagerService`. If a vault for this tenant doesn't exist and auto-creation is configured (or a specific provisioning step is taken), it might be initialized.
3.  **Secure Operations:**
    Using the obtained `VaultService` instance, the application can:
    *   Encrypt and decrypt data.
    *   Store, retrieve, update, and delete secrets securely.
    *   Manage encryption keys (e.g., initiate key rotation).
    *   Utilize features like `UseSecret` for safely working with secret data in memory for a limited scope.
4.  **Auditing:**
    All significant operations are automatically audited through the configured audit backend, providing a trail of activities.
5.  **Tenant Closure:**
    When a tenant's operations are complete, or during application shutdown, the `VaultManagerService` can be used to close individual tenant vaults or all active vaults to release resources and ensure data is securely persisted.

## Core Service Interfaces

This section details the primary service interfaces in Volta: `VaultManagerService` and `VaultService`. These interfaces define the contract for interacting with Volta's management and operational capabilities.

### `VaultManagerService` Interface

The `VaultManagerService` is the central administrative and orchestration point for all Volta operations. It manages the lifecycle of tenant-specific vaults and provides capabilities for cross-tenant administration and auditing.

```go
type VaultManagerService interface {
    GetVault(tenantID string) (VaultService, error)
    CloseTenant(tenantID string) error
    CloseAll() error
    ListTenants() ([]string, error)
    RotateAllTenantKeys(tenantIDs []string, reason string) ([]BulkOperationResult, error)
    RotateAllTenantPassphrases(tenantIDs []string, newPassphrase string, reason string) ([]BulkOperationResult, error)
    QueryAuditLogs(options audit.QueryOptions) (*audit.QueryResult, error)
    GetAuditSummary(tenantID string, since *time.Time) (AuditSummary, error)
    QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]audit.Event, error)
    QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]audit.Event, error)
    QueryFailedOperations(tenantID string, since *time.Time) ([]audit.Event, error)
    QueryPassphraseAccessLogs(tenantID string, since *time.Time) ([]audit.Event, error)
    QueryAllTenantsAuditLogs(options audit.QueryOptions) (map[string]audit.QueryResult, error)
    QueryTenantAuditLogs(tenantID string, options audit.QueryOptions) (audit.QueryResult, error)
}
```

#### Methods

*   **`GetVault(tenantID string) (VaultService, error)`**
    Retrieves or initializes a `VaultService` instance for the specified `tenantID`. This is the primary mechanism for applications to gain access to a tenant's isolated vault for performing cryptographic operations and secret management. If a vault for the tenant does not exist, its creation might be implicitly handled by the underlying implementation or require an explicit provisioning step depending on the Volta configuration.

*   **`CloseTenant(tenantID string) error`**
    Closes the vault associated with the specified `tenantID`. This action releases any resources held by the tenant's vault, flushes any pending data to the persistence layer, and ensures cryptographic materials are securely cleared from memory, if applicable. It is good practice to close tenant vaults when they are no longer actively needed.

*   **`CloseAll() error`**
    Closes all currently active tenant vaults managed by this `VaultManagerService`. This is typically used during application shutdown to ensure a graceful and secure termination of all Volta operations.

*   **`ListTenants() ([]string, error)`**
    Returns a list of `tenantID` strings for all tenants known to the Volta instance. This can be useful for administrative tasks, such as iterating through all tenants for maintenance operations.

*   **`RotateAllTenantKeys(tenantIDs []string, reason string) ([]BulkOperationResult, error)`**
    Initiates a key rotation process for all specified tenants. If `tenantIDs` is nil or empty, the operation may apply to all tenants known to the system (behaviour subject to implementation). Key rotation is a critical security practice where a new encryption key is generated for a tenant, and future encryptions use this new key. Data encrypted with old keys remains decryptable. The `reason` parameter provides an auditable context for the rotation. Each element in the returned `BulkOperationResult` slice indicates the outcome for a specific tenant.
    
*   **`RotateAllTenantPassphrases(tenantIDs []string, newPassphrase string, reason string) ([]BulkOperationResult, error)`**
    Changes the master passphrase for the specified tenants. The master passphrase is typically used to derive a key encryption key (KEK) or to protect the vault's master key. This operation re-encrypts critical vault metadata with a key derived from the `newPassphrase`. The `reason` parameter ensures this sensitive operation is auditable. Similar to key rotation, `BulkOperationResult` reports the outcome for each tenant. *Caution: Loss of the new passphrase can result in irrecoverable loss of access to the tenant's vault.*

*   **`QueryAuditLogs(options audit.QueryOptions) (*audit.QueryResult, error)`**
    Executes a query against the audit logs based on the provided `audit.QueryOptions`. This method might query a global audit log if such a unified log exists, or it may require specific configuration to target logs. The `audit.QueryOptions` structure allows for filtering by various criteria. (See `audit.QueryOptions` and `audit.QueryResult` in a later section for details).

*   **`GetAuditSummary(tenantID string, since *time.Time) (AuditSummary, error)`**
    Retrieves a summary of audit activity for a specific `tenantID`. The `since` parameter allows scoping the summary to events after a certain timestamp.
    
*   **`QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]audit.Event, error)`**
    Retrieves audit events specifically related to operations performed on a particular encryption `keyID` within a given `tenantID`. The `since` parameter filters events to those occurring after the specified time. This is useful for tracking the lifecycle and usage of individual keys.

*   **`QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]audit.Event, error)`**
    Queries audit events related to access and modifications of a specific `secretID` within a given `tenantID`. The `since` parameter restricts the search to recent events. This helps in monitoring who accessed or attempted to access specific secrets and when.

*   **`QueryFailedOperations(tenantID string, since *time.Time) ([]audit.Event, error)`**
    Returns a list of audit events that represent failed operations for a given `tenantID`. This is crucial for security monitoring and identifying potential misuse or system issues. The `since` parameter allows focusing on recent failures.

*   **`QueryPassphraseAccessLogs(tenantID string, since *time.Time) ([]audit.Event, error)`**
    Retrieves audit events specifically related to passphrase access or modification attempts for the specified `tenantID`. This can include successful passphrase changes or failed attempts to unlock a vault with an incorrect passphrase.

*   **`QueryAllTenantsAuditLogs(options audit.QueryOptions) (map[string]audit.QueryResult, error)`**
    Performs an audit log query across all tenants accessible to the `VaultManagerService`, filtered by the provided `audit.QueryOptions`. The results are returned as a map where keys are `tenantID`s and values are the corresponding `audit.QueryResult` for that tenant. This enables a centralized view of auditable activities across the entire system.

*   **`QueryTenantAuditLogs(tenantID string, options audit.QueryOptions) (audit.QueryResult, error)`**
    Queries the audit logs specifically for a single `tenantID`, applying the filters defined in `audit.QueryOptions`. This provides a focused view of a particular tenant's auditable events.

### `VaultService` Interface

The `VaultService` interface provides the core cryptographic and secret management functionalities for an individual tenant. An instance of `VaultService` is obtained through the `VaultManagerService.GetVault` method and operates exclusively within the context of that tenant.

```go
type VaultService interface {
    Encrypt(plaintext []byte) (ciphertextWithKeyID string, err error)
    Decrypt(base64CiphertextWithKeyID string) (plaintext []byte, err error)
    RotateKey(reason string) (*KeyMetadata, error)
    DestroyKey(keyID string) error
    Backup(destinationDir string, passphrase string) error
    Restore(destinationDir string, passphrase string) error
    ListKeyMetadata() ([]KeyMetadata, error)
    GetActiveKeyMetadata() (KeyMetadata, error)
    StoreSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)
    GetSecret(secretID string) (*SecretResult, error)
    UpdateSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)
    DeleteSecret(secretID string) error
    SecretExists(secretID string) (bool, error)
    ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error)
    GetSecretMetadata(secretID string) (*SecretMetadata, error)
    Close() error
    UseSecret(secretID string, fn func(data []byte) error) error
    UseSecretWithTimeout(secretID string, timeout time.Duration, fn func(data []byte) error) error
    UseSecretWithContext(ctx context.Context, secretID string, fn func(data []byte) error) error
    UseSecretString(secretID string, fn func(secret string) error) error
    GetSecretWithTimeout(secretID string, timeout time.Duration) (*SecretWithContext, error)
    GetSecretWithContext(ctx context.Context, secretID string) (*SecretWithContext, error)
    UseSecrets(secretIDs []string, fn func(secrets map[string][]byte) error) error
    UseSecretsString(secretIDs []string, fn func(secrets map[string]string) error) error
    SecureMemoryProtection() mem.ProtectionLevel
}
```

#### Methods

**Core Encryption/Decryption:**

*   **`Encrypt(plaintext []byte) (ciphertextWithKeyID string, err error)`**
    Encrypts the provided `plaintext` byte array using the tenant's active encryption key. The returned `ciphertextWithKeyID` is typically a string (often Base64 encoded) that includes an identifier for the key used for encryption. This key identifier is crucial for decryption, allowing Volta to select the correct key.

*   **`Decrypt(base64CiphertextWithKeyID string) (plaintext []byte, err error)`**
    Decrypts the provided `base64CiphertextWithKeyID` string. Volta uses the embedded key identifier to retrieve the appropriate decryption key. It returns the original `plaintext` byte array.

**Key Management:**

*   **`RotateKey(reason string) (*KeyMetadata, error)`**
    Generates a new active encryption key for the tenant and deactivates the previous key. The old key is retained for decrypting data previously encrypted with it. The `reason` parameter provides an auditable context for this operation. Returns metadata about the newly generated key.
    *   `KeyMetadata` (conceptual): Likely contains information such as `KeyID`, `CreationTime`, `Status` (active/inactive), `Algorithm`, etc.

*   **`DestroyKey(keyID string) error`**
    Securely destroys the specified encryption `keyID`. *Caution: This is an irreversible operation. Any data encrypted solely with this key will become permanently undecryptable.* This function should be used with extreme care, typically for keys that are no longer needed and whose associated data has been re-encrypted with a new key or securely deleted.

*   **`ListKeyMetadata() ([]KeyMetadata, error)`**
    Returns a list of `KeyMetadata` objects for all encryption keys (active and inactive) associated with the tenant.

*   **`GetActiveKeyMetadata() (KeyMetadata, error)`**
    Returns the `KeyMetadata` for the tenant's current active encryption key. This is the key that will be used for new `Encrypt` operations.

**Secret Management (CRUD):**

*   **`StoreSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)`**
    Stores a new secret, encrypting `secretData` before persistence. `secretID` is a unique identifier for the secret within the tenant's vault. `tags` can be used for categorization or future search capabilities. `contentType` may indicate the nature of the secret data (e.g., "text/plain", "application/json"). Returns metadata about the stored secret.
    *   `ContentType` (conceptual enum): Represents the MIME type or format of the secret data (e.g., `Text`, `Binary`, `JSON`).
    *   `SecretMetadata` (conceptual): Would include `SecretID`, `CreationTimestamp`, `LastUpdateTimestamp`, `Version`, `Tags`, `ContentType`, `Size`, etc.

*   **`GetSecret(secretID string) (*SecretResult, error)`**
    Retrieves and decrypts the secret identified by `secretID`.
    *   `SecretResult` (conceptual): Likely contains the decrypted `SecretData ([]byte)` and potentially `SecretMetadata`.

*   **`UpdateSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)`**
    Updates an existing secret identified by `secretID` with new `secretData`, `tags`, and `contentType`. The new data is encrypted before persistence. Returns metadata about the updated secret. This operation might involve versioning of secrets.

*   **`DeleteSecret(secretID string) error`**
    Securely deletes the secret identified by `secretID` from the vault. This operation should be considered permanent.

*   **`SecretExists(secretID string) (bool, error)`**
    Checks if a secret with the given `secretID` exists within the tenant's vault.

*   **`ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error)`**
    Lists secrets within the tenant's vault, potentially filtered by `options`.
    *   `SecretListOptions` (conceptual): May include filters for `Tags`, `CreationDateRange`, `Prefix` for `SecretID`, `Limit`, `Offset` for pagination.
    *   `SecretListEntry` (conceptual): A lightweight structure for list results, possibly containing `SecretID`, `Tags`, `CreationTimestamp`, `Size`, `ContentType` (but not the secret data itself).

*   **`GetSecretMetadata(secretID string) (*SecretMetadata, error)`**
    Retrieves only the metadata for the secret identified by `secretID`, without decrypting or returning the secret data itself.

**Secure Secret Usage (In-Memory Protection Focus):**
These methods are designed to minimize the exposure time of plaintext secrets in application memory. They typically decrypt the secret, allow the application to use it within a callback function, and then ensure the plaintext is securely cleared from memory immediately after the callback completes.

*   **`UseSecret(secretID string, fn func(data []byte) error) error`**
    Retrieves the specified secret, decrypts it, and passes the plaintext `data` to the provided callback function `fn`. Volta aims to clear the plaintext secret from memory after `fn` returns (or panics).

*   **`UseSecretWithTimeout(secretID string, timeout time.Duration, fn func(data []byte) error) error`**
    Similar to `UseSecret`, but the operation (including the execution of `fn`) is subject to a `timeout`. If the timeout is exceeded, the operation may be aborted, and an error returned.

*   **`UseSecretWithContext(ctx context.Context, secretID string, fn func(data []byte) error) error`**
    Similar to `UseSecret`, but allows passing a `context.Context` for cancellation or deadline propagation.

*   **`UseSecretString(secretID string, fn func(secret string) error) error`**
    A convenience wrapper around `UseSecret` for secrets that are known to be UTF-8 strings. It decodes the byte slice to a string before passing it to the callback.

*   **`GetSecretWithTimeout(secretID string, timeout time.Duration) (*SecretWithContext, error)`**
    Retrieves and decrypts a secret, returning it within a `SecretWithContext` structure. This structure is designed to manage the lifecycle of the decrypted secret, potentially providing methods to explicitly clear it or linking it to a context for automated cleanup. The operation is subject to a `timeout`.
    *   `SecretWithContext` (conceptual): A specialized container for a decrypted secret, possibly holding `Data ([]byte)`, `String() string`, and a `Close()` or `Destroy()` method to securely wipe the plaintext from memory.

*   **`GetSecretWithContext(ctx context.Context, secretID string) (*SecretWithContext, error)`**
    Similar to `GetSecretWithTimeout`, but uses a `context.Context` for cancellation and lifecycle management of the retrieved secret.

*   **`UseSecrets(secretIDs []string, fn func(secrets map[string][]byte) error) error`**
    Retrieves multiple secrets, decrypts them, and passes them as a map (`secretID` to plaintext `data`) to the callback function `fn`. This is more efficient than calling `UseSecret` multiple times.

*   **`UseSecretsString(secretIDs []string, fn func(secrets map[string]string) error) error`**
    Similar to `UseSecrets`, but for secrets that are UTF-8 strings. Decodes the byte slices to strings before passing them to the callback.

**Backup and Restore:**

*   **`Backup(destinationDir string, passphrase string) error`**
    Creates an encrypted backup of the tenant's vault (including its keys and secrets) to the specified `destinationDir`. The backup is itself encrypted with a key derived from the provided `passphrase`. *It is critical to store this passphrase securely and separately from the backup file.*

*   **`Restore(destinationDir string, passphrase string) error`**
    Restores a tenant's vault from a backup located in `destinationDir`, using the `passphrase` that was used during the backup process. This will overwrite the current state of the tenant's vault if it exists. *Caution: This operation can lead to data loss if not handled carefully.*

**Lifecycle:**

*   **`Close() error`**
    Closes the current tenant `VaultService` instance. This releases resources, ensures data is persisted, and clears sensitive material from memory. It is analogous to `VaultManagerService.CloseTenant` but called directly on a `VaultService` instance.

## Part 3: Data Structures and Core Internal Architecture

This section describes key data structures used within Volta, particularly those related to backup and restore operations, configuration, and provides a glimpse into the internal `Vault` structure to better understand its operational mechanics.

### Backup and Restore Data Structures

Volta provides mechanisms for backing up and restoring tenant vaults. This is essential for disaster recovery, data migration, and archival purposes. The backups themselves are encrypted to ensure the confidentiality of the stored secrets and keys even when the backup files are at rest.

#### `BackupContainer`

The `BackupContainer` structure represents the serialized format of a vault backup. This structure is encrypted and written to a file or storage medium during a backup operation.

```go
type BackupContainer struct {
    BackupID         string    `json:"backup_id"`
    BackupTimestamp  time.Time `json:"backup_timestamp"`
    VaultVersion     string    `json:"vault_version"`
    BackupVersion    string    `json:"backup_version"`
    Checksum         string    `json:"checksum"`
    EncryptionMethod string    `json:"encryption_method"`
    EncryptedData    string    `json:"encrypted_data"` // Likely Base64 encoded encrypted BackupData
    TenantID         string    `json:"tenant_id"`
}
```

*   **`BackupID`**: A unique identifier for this specific backup instance.
*   **`BackupTimestamp`**: The Coordinated Universal Time (UTC) timestamp indicating when the backup was created.
*   **`VaultVersion`**: The version of the Volta library or vault internal format at the time of backup. This aids in compatibility checks during restoration.
*   **`BackupVersion`**: The version of the backup format itself. This allows for evolution of the backup structure while maintaining backward compatibility where possible.
*   **`Checksum`**: A cryptographic hash (e.g., SHA256) of the `EncryptedData` (or potentially the unencrypted `BackupData` before its encryption, depending on implementation). This is used to verify the integrity of the backup data during restoration, ensuring it hasn't been corrupted or tampered with.
*   **`EncryptionMethod`**: Specifies the cryptographic algorithm and mode used to encrypt the `EncryptedData` (e.g., AES-256-GCM). This field is critical for the restore process to correctly decrypt the backup.
*   **`EncryptedData`**: The core backup content, encrypted. 
*   **`TenantID`**: The identifier of the tenant whose vault data is contained in this backup.

#### `BackupData`

The `BackupData` structure defines the actual content that is encrypted and stored within the `EncryptedData` field of a `BackupContainer`.

```go
type BackupData struct {
    Salt          []byte `json:"salt,omitempty"`
    VaultMetadata []byte `json:"vault_metadata,omitempty"`
    SecretsData   []byte `json:"secrets_data,omitempty"`
}
```

*   **`Salt`**: A random salt used, for instance, in the key derivation function (KDF) that generates the encryption key from the user-supplied backup passphrase. Including a unique salt per backup enhances security by preventing rainbow table attacks against the passphrase.
*   **`VaultMetadata`**: Serialized metadata critical for restoring the vault's operational state. This would typically include tenant-specific configuration, information about encryption keys (e.g., encrypted key material, key IDs, rotation history), and other vault settings.
*   **`SecretsData`**: Serialized and encrypted representation of all the secrets stored within the tenant's vault at the time of backup. Individual secrets within this blob are themselves encrypted with the tenant's data encryption keys (DEKs).

#### `BackupInfo`

The `BackupInfo` structure provides metadata about a backup without requiring the decryption of the entire backup content. This is useful for listing available backups and displaying their summary information.

```go
type BackupInfo struct {
    BackupID         string    `json:"backup_id"`
    BackupTimestamp  time.Time `json:"backup_timestamp"`
    VaultVersion     string    `json:"vault_version"`
    BackupVersion    string    `json:"backup_version"`
    EncryptionMethod string    `json:"encryption_method"`
    FileSize         int64     `json:"file_size"`
    IsValid          bool      `json:"is_valid"` // Indicates if the backup file passed basic integrity checks (e.g., checksum validation)
    TenantID         string    `json:"tenant_id"`
}
```

*   **`BackupID`**: Unique identifier of the backup.
*   **`BackupTimestamp`**: Timestamp of backup creation.
*   **`VaultVersion`**: Volta version at backup time.
*   **`BackupVersion`**: Backup format version.
*   **`EncryptionMethod`**: Encryption method used for the backup.
*   **`FileSize`**: The size of the backup file on disk, in bytes.
*   **`IsValid`**: A boolean flag indicating whether the backup appears to be structurally sound and its checksum (if validated from `BackupContainer`) matches. This doesn't guarantee the content is decryptable (which requires the correct passphrase) but suggests the file isn't overtly corrupted.
*   **`TenantID`**: The tenant ID associated with this backup.

#### `DetailedBackupInfo`

The `DetailedBackupInfo` structure extends `BackupInfo` with more granular details about the contents of a backup. Accessing this level of detail might, in some implementations, require decrypting parts of the backup metadata (but not necessarily all secrets).

```go
type DetailedBackupInfo struct {
    BackupInfo
    KeyCount        int   `json:"key_count"`
    SecretCount     int   `json:"secret_count"`
    TotalKeySize    int64 `json:"total_key_size"`    // Aggregate size of key material
    TotalSecretSize int64 `json:"total_secret_size"` // Aggregate size of (encrypted) secret data
    HasSalt         bool  `json:"has_salt"`
    HasMetadata     bool  `json:"has_metadata"`
}
```

*   **`BackupInfo`**: Embeds all fields from the `BackupInfo` structure.
*   **`KeyCount`**: The number of distinct encryption keys (active and inactive) included in the backup for this tenant.
*   **`SecretCount`**: The total number of individual secrets stored in the backup.
*   **`TotalKeySize`**: The aggregate size (in bytes) of the key material stored within the backup. This would refer to the size of the encrypted keys or their metadata.
*   **`TotalSecretSize`**: The aggregate size (in bytes) of the encrypted secret data.
*   **`HasSalt`**: Indicates if a salt (for backup passphrase key derivation) is present in the `BackupData`.
*   **`HasMetadata`**: Indicates if `VaultMetadata` is present in the `BackupData`.

### Configuration Structures

#### `StoreConfig`

Volta's design emphasizes pluggability for its storage backend. The `StoreConfig` structure is used to define the type of store to be used and provide its specific configuration parameters.

```go
type StoreConfig struct {
    Type   StoreType              `json:"type"`   // E.g., "filesystem", "database", "cloud_storage"
    Config map[string]interface{} `json:"config"` // Backend-specific configuration options
}
```

*   **`Type`**: An enumeration or string (`StoreType`) specifying the kind of storage backend to instantiate (e.g., "filesystem", "postgresql", "s3", "azure_blob", "etcd"). Volta would typically have registered handlers for different store types.
    *   `StoreType` (conceptual): An enum or aliased string type that defines supported storage backends.
*   **`Config`**: A map containing key-value pairs specific to the chosen `Type`. For example:
    *   For a "filesystem" store, it might include `{"path": "/var/lib/volta/data"}`.
    *   For a "database" store, it might include `{"connection_string": "user:pass@host/db", "table_prefix": "volta_"}`.
    *   For a "cloud\_storage" store, it might include `{"bucket_name": "my-volta-backups", "region": "us-east-1"}`.

This structure allows applications to configure Volta's persistence layer flexibly, adapting to various deployment environments and preferences without altering Volta's core logic.

### Core Internal `Vault` Structure (Conceptual Insight)

While applications interact with Volta through the `VaultService` and `VaultManagerService` interfaces, the `Vault` struct provides a conceptual look at how a tenant's vault might be organized internally. This is not directly exposed to the user but understanding its components illuminates Volta's design.

```go
type Vault struct {
    store                 persist.Store        // Instance of the configured persistence backend
    keyEnclaves           map[string]*memguard.Enclave // In-memory secure storage for DEKs
    keyMetadata           map[string]KeyMetadata   // Metadata for all keys (active/inactive)
    mu                    sync.RWMutex         // Mutex for concurrent access control
    currentKeyID          string               // ID of the current active Data Encryption Key (DEK)
    memoryProtectionLevel mem.ProtectionLevel  // Configuration for in-memory data protection
    derivationKeyEnclave  *memguard.Enclave    // Secure enclave for a key encryption key (KEK) or master key derivative
    derivationSaltEnclave *memguard.Enclave    // Secure enclave for salt used with the KEK
    secretsContainer      *memguard.Enclave    // In-memory secure storage for currently accessed secrets (if applicable)
    secretsVersion        string               // Version of the secrets data structure/format
    secretsTimestamp      time.Time            // Timestamp of the last secrets modification
    audit                 audit.Logger         // Instance of the configured audit logger
    closed                bool                 // Flag indicating if the vault is closed
}
```

*   **`store persist.Store`**: An instance of the underlying persistence layer (e.g., filesystem, database) conforming to Volta's `persist.Store` interface. This handles the actual saving and loading of encrypted data and metadata.
*   **`keyEnclaves map[string]*memguard.Enclave`**: A map where keys are key IDs (`string`) and values are `memguard.Enclave` pointers. `memguard` is a library for handling sensitive data in protected memory regions. This suggests that Data Encryption Keys (DEKs), once decrypted or generated, are held in these secure enclaves to protect them from memory scraping attacks.
*   **`keyMetadata map[string]KeyMetadata`**: In-memory cache of metadata for all encryption keys associated with this tenant's vault. `KeyMetadata` would include details like creation date, status (active/archived), algorithm, etc.
*   **`mu sync.RWMutex`**: A read-write mutex to ensure thread-safe access to the vault's internal state, critical for concurrent applications.
*   **`currentKeyID string`**: The ID of the encryption key currently marked as "active" for this tenant. New `Encrypt` operations will use this key.
*   **`memoryProtectionLevel mem.ProtectionLevel`**: Indicates the level or strategy of in-memory protection applied (e.g., using `memguard` features like guard pages, canary values, encryption in RAM if supported by the OS/hardware).
*   **`derivationKeyEnclave *memguard.Enclave`**: An enclave holding a Key Encryption Key (KEK) or a derivative of the tenant's master passphrase. This KEK would be used to encrypt/decrypt the DEKs (`keyEnclaves`) before they are persisted by the `store`.
*   **`derivationSaltEnclave *memguard.Enclave`**: An enclave holding the salt used in conjunction with the master passphrase to derive the `derivationKeyEnclave`. Storing salt securely is good practice.
*   **`secretsContainer *memguard.Enclave`**: Potentially an enclave used for temporarily holding plaintext secret data when accessed via methods like `UseSecret`. This ensures the plaintext exists in protected memory for the shortest duration necessary.
*   **`secretsVersion string`**: A version identifier for the format or structure in which secrets are stored or managed within this vault. Useful for migrations.
*   **`secretsTimestamp time.Time`**: Timestamp of the last modification to the collective set of secrets, useful for caching or concurrency control.
*   **`audit audit.Logger`**: An instance of the audit logger, conforming to Volta's `audit.Logger` interface. All significant operations within this vault instance are routed through this logger.
*   **`closed bool`**: A flag indicating whether the vault instance has been closed. Closed vaults should not perform operations.

## Operational Guidance and Extensibility

This section provides guidance on good practices for operating Volta, discusses important security considerations, and outlines how Volta's pluggable architecture allows for extensibility.

### Good Practices for Utilizing Volta

Effective and secure operation of Volta relies on adhering to sound security principles and operational disciplines:

1.  **Secure Tenant Passphrase Management:**
    Volta uses a single passphrase to generate a derived key. The security of the entire tenant vault hinges on the secrecy and strength of this initial passphrase. Applications integrating Volta must implement robust mechanisms for managing these passphrases, ensuring they are not hardcoded, exposed in logs, or insecurely stored. Consider using environment variables, dedicated secret management systems (for bootstrapping Volta's passphrase), or user-provided input where appropriate.

2.  **Regular Key Rotation:**
    Volta supports key rotation (`VaultService.RotateKey` and `VaultManagerService.RotateAllTenantKeys`). Regularly rotating Data Encryption Keys (DEKs) is a crucial security hygiene practice. It limits the amount of data encrypted with any single key, reducing the impact if a key is ever compromised. Establish a policy for key rotation frequency based on your organization's risk assessment and compliance requirements. Provide clear, auditable `reason` strings for each rotation.

3.  **Backup Management and Testing:**
    *   **Secure Backup Passphrases:** Backup archives created by Volta are encrypted. The passphrase used for backup encryption must be strong and managed with extreme care, separately from the backup files themselves. Losing this passphrase means losing access to the backup.
    *   **Regular Backups:** Implement a regular schedule for backing up tenant vaults. The frequency should align with your Recovery Point Objectives (RPOs).
    *   **Test Restore Procedures:** Regularly test the restoration process (`VaultService.RestoreBackup`) in a non-production environment to ensure backup integrity and verify that your recovery procedures are effective. Untested backups provide a false sense of security.
    *   **Secure Backup Storage:** Store backup files in a secure, access-controlled location, separate from the primary operational environment.

4.  **Principle of Least Privilege:**
    When designing applications that interact with `VaultManagerService`, ensure that access to administrative functions (like `RotateAllTenantKeys`, `RotateAllTenantPassphrases`, or broad audit queries) is restricted to privileged components or users. Individual application instances should typically only interact with their designated `VaultService`.

5.  **Audit Log Monitoring:**
    Volta provides comprehensive auditing capabilities. Regularly monitor and review audit logs (`QueryAuditLogs`, `GetAuditSummary`, etc.) for suspicious activities, unauthorized access attempts, frequent failed operations, or unusual patterns. Integrate audit logs with your central Security Information and Event Management (SIEM) system if possible.

6.  **Graceful Shutdown and Resource Management:**
    Ensure that `VaultService.Close()` (for individual tenant vaults) and `VaultManagerService.CloseTenant()` or `VaultManagerService.CloseAll()` are called appropriately during application shutdown or when a tenant's session ends. This ensures that resources are released, pending writes are flushed, and sensitive data is cleared from memory.

7.  **Scope of Plaintext Secret Exposure:**
    While methods like `Decrypt` provide direct access to plaintext, exercise caution. Prefer using scoped access patterns like those implied by `UseSecret` (not explicitly defined but a common secure pattern) where plaintext exists in memory for the shortest necessary duration and within a controlled function scope. When handling plaintext byte slices, ensure they are explicitly cleared from memory as soon as they are no longer needed, if not managed by Volta's secure memory enclaves.

8.  **Backend Selection:**
    Choose storage (`StoreConfig`) and audit backends that align with your operational environment, security requirements, and scalability needs. Consider factors like data durability, availability, access control mechanisms, and existing infrastructure.

9.  **Understanding Memory Protection:**
    Be aware of the configured `memoryProtectionLevel` (as suggested by the internal `Vault` struct). Understand what protections are offered (e.g., non-swappable memory, guard pages) and their limitations. While Volta aims to protect critical data in memory, this is part of a defense-in-depth strategy.

### Security Considerations

Volta is designed with security as a core tenet, but its overall security posture also depends on the environment and practices surrounding its deployment.

1.  **Root of Trust - Tenant Passphrase/Key:**
    The ultimate security of a tenant's data within Volta relies on the protection of its primary secret (e.g., passphrase or master key) from which its Key Encryption Key (KEK) is derived. If this root secret is compromised, the encrypted data it protects can be decrypted. Volta itself does not manage this initial secret but uses it to bootstrap its own internal key hierarchy.

2.  **In-Memory Protection (`memguard`):**
    Volta's use of libraries like `memguard` to protect sensitive data (keys, temporarily held secrets) in memory significantly raises the bar for attackers. However, no in-memory protection is infallible. Sophisticated attackers with sufficient privileges on the host OS (e.g., root access) or those exploiting severe kernel vulnerabilities might still be able to bypass or undermine these protections. Physical memory attacks (e.g., cold boot attacks) also remain a theoretical concern for extremely high-security scenarios.

3.  **Storage Backend Security:**
    Volta encrypts data before writing it to the `persist.Store`. However, the underlying storage system (filesystem, database, cloud storage) must also be secured. This includes proper access controls, encryption at rest for the storage medium itself (as an additional layer), and protection against unauthorized administrative access to the backend.

4.  **Audit Log Integrity and Security:**
    The audit backend should be configured to be as tamper-evident as possible. For instance, append-only logs, logs shipped to a separate, secured system, or cryptographic signing of log entries can enhance integrity. Unauthorized modification or deletion of audit logs can mask malicious activity.

5.  **Application-Layer Vulnerabilities:**
    Volta secures secrets *within its boundary*. If the application embedding Volta has vulnerabilities (e.g., SQL injection, Remote Code Execution, insecure API endpoints), these could be exploited to misuse Volta's `VaultService` API, potentially leading to secret exposure. Application security is a critical complementary layer.

6.  **Backup Security:**
    Backup files (`BackupContainer`) contain encrypted copies of highly sensitive data. These files must be protected with strong access controls, both in transit and at rest in their storage location. The backup encryption passphrase is a critical secret.

7.  **Physical Security:**
    Physical access to the systems running Volta can bypass many software-based security controls. Ensure appropriate physical security measures are in place for the host infrastructure.

8.  **Operational Security:**
    Secure operational practices, such as restricting access to production environments, robust identity and access management, and regular security patching of the underlying OS and Go runtime, are essential.

### Extensibility and Pluggability

A key design principle of Volta is its adaptability through pluggable components. This allows integration into diverse environments and extension with custom functionality.

1.  **Pluggable Storage Backends (`persist.Store`):**
    Volta allows applications to define their own persistence mechanisms for storing encrypted vault data. This is achieved by implementing a `persist.Store` interface (the exact definition of which would be provided by Volta). A custom storage backend might interact with various systems:
    *   Relational databases (PostgreSQL, MySQL, SQL Server)
    *   NoSQL databases (MongoDB, Cassandra, DynamoDB)
    *   Distributed key-value stores (etcd, Consul, ZooKeeper)
    *   Cloud storage services (AWS S3, Google Cloud Storage, Azure Blob Storage) beyond any built-in support.
    *   Proprietary in-house storage solutions.
        The implementation would need to handle safe storage and retrieval of byte arrays (representing encrypted data and metadata) keyed by tenant ID and potentially other identifiers.
        The `StoreConfig` structure facilitates configuring these custom (or pre-built) backends.

2.  **Pluggable Audit Backends (`audit.Logger`):**
    Similarly, Volta enables custom audit logging implementations by adhering to an `audit.Logger` interface. This allows audit events to be routed to various destinations:
    *   Local log files in specific formats (e.g., JSON, CEF).
    *   Centralized logging systems (Splunk, ELK Stack, Graylog).
    *   Cloud-native monitoring services (AWS CloudWatch Logs, Google Cloud Logging, Azure Monitor).
    *   Databases designed for audit trails.
        A custom logger would receive `audit.Event` data (or similar structured information) and be responsible for its durable and secure recording.

By providing these well-defined abstractions for storage and auditing, Volta empowers developers to tailor its deployment to specific infrastructure and security requirements, ensuring that it can evolve with changing needs without compromising its core mission of providing simple, secure secret management.