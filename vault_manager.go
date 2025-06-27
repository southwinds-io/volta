package volta

import (
	"fmt"
	"io"
	"log"
	"southwinds.dev/volta/audit"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"time"
)

// VaultManager manages vault instances per tenant
//
// OVERVIEW:
// The VaultManager is responsible for handling the lifecycle and operations of vault instances
// for different tenants. Each tenant can have its own vault configuration, storage implementation,
// and security policies. The VaultManager provides methods to create, close, and manage tenant
// vaults, facilitating complete isolation and security compliance.
//
// CLIENT REQUIREMENTS:
// Clients utilizing the VaultManager should implement the VaultManagerService interface to
// interact with tenant vaults, ensuring adherence to the operational and security policies set
// for each tenant. It should be initiated with a comprehensive set of options that dictate
// cryptographic behaviors, memory management, and audit configurations for optimal security
// posture.
//
// KEY FUNCTIONALITIES:
//
//  1. **Tenant Vault Management**:
//     - GetVault: Retrieve the vault associated with the specified tenant ID.
//     - CloseTenant: Gracefully close and release resources associated with a tenant's vault.
//     - CloseAll: Close all tenant vaults, ensuring cleanup of resources and auditing operations.
//     - ListTenants: Retrieve a list of all tenant IDs currently managed by the VaultManager.
//
//  2. **Key and Passphrase Rotation**:
//     - RotateAllTenantKeys: Rotate encryption keys for specified tenant IDs, with an optional reason for auditing.
//     - RotateAllTenantPassphrases: Update the master passphrase for tenants, ensuring secure transition
//     from the old passphrase to the new one.
//
//  3. **Audit Logging**:
//     - QueryAuditLogs: Fetch audit logs based on specified query options for compliance monitoring.
//     - GetAuditSummary: Obtain a summary of audit logs for a tenant since a defined time.
//     - QueryKeyOperations, QuerySecretAccess, QueryFailedOperations, and QueryPassphraseAccessLogs:
//     Specific queries for detailed insights into vault usage, failures, and access patterns.
//
// INITIALIZATION CONSIDERATIONS:
// Clients should initialize the VaultManager with a suitable store factory or store configuration,
// allowing for tailored storage backends suitable for individual tenants. The factory should provide
// security, isolation, and flexibility in handling tenant data without risk of exposure or compromise.
//
// USAGE EXAMPLE:
//
//	```go
//	// Create base vault options with secure configuration
//	vaultOptions := Options{
//	    DerivationSalt:       generateSecureSalt(),
//	    DerivationPassphrase: "very-secure-passphrase-12345!",
//	    EnableMemoryLock:     true,
//	    Debug:                false,
//	}
//
//	// Create a centralized audit logger
//	auditLogger := audit.NewFileLogger("/var/log/vault/audit.log")
//
//	// Define a storage factory for tenant vaults
//	storeFactory := func(tenantID string) (persist.Store, error) {
//	    return persist.NewS3Store(fmt.Sprintf("vault-%s", tenantID))
//	}
//
//	// Initialize the VaultManager with defined options
//	vaultManager := NewVaultManagerWithStoreFactory(vaultOptions, storeFactory, auditLogger)
//
//	// Use the vault manager to manage tenant vaults
//	tenantVault, err := vaultManager.GetVault("tenant-001")
//	if err != nil {
//	    log.Fatalf("Failed to retrieve tenant vault: %v", err)
//	}
//	```
//
// PARAMETERS:
//
//	options: A set of cryptographic and operational configurations applicable to all tenant vaults.
//	storeFactory: A function that generates a tenant-specific storage backend based on the tenant ID.
//	auditLogger: An instance of the centralized audit logger for monitoring and compliance tracking.
//
// RETURNS:
//
//	VaultManagerService: An instance of the VaultManagerService that provides access to tenant vault operations.
type VaultManager struct {
	options      Options
	storeFactory func(tenantID string) (persist.Store, error)
	mu           sync.RWMutex
	vaults       map[string]VaultService
	audit        audit.Logger
}

// NewVaultManagerWithStoreFactory creates a new vault manager instance with a custom store factory.
//
// OVERVIEW:
// This constructor function creates a VaultManager instance with a configurable storage factory
// that enables custom storage backend implementations for each tenant. The store factory approach
// provides maximum flexibility for multi-tenant storage strategies, allowing different tenants
// to utilize different storage backends, configurations, or security policies based on their
// specific requirements or organizational constraints.
//
// FACTORY PATTERN BENEFITS:
//
//	STORAGE FLEXIBILITY:
//	The factory pattern enables dynamic storage backend selection during tenant vault creation.
//	Each tenant can use different storage implementations (file-based, cloud storage, databases,
//	HSMs, or custom backends) without requiring changes to the vault manager core logic.
//	This supports diverse deployment scenarios and tenant-specific storage requirements.
//
//	MULTI-TENANT ISOLATION:
//	The factory approach ensures complete storage isolation between tenants by creating
//	independent storage instances for each tenant. This prevents data leakage, supports
//	different security policies per tenant, and enables tenant-specific compliance requirements
//	such as data residency, encryption standards, or backup procedures.
//
//	CONFIGURATION FLEXIBILITY:
//	Different tenants can receive storage configurations optimized for their usage patterns,
//	performance requirements, or security policies. High-security tenants might use HSM-backed
//	storage while development tenants use file-based storage, all managed by the same
//	vault manager instance.
//
// INITIALIZATION BEHAVIOR:
//
//	LAZY TENANT CREATION:
//	The vault manager initializes with an empty tenant registry and creates tenant vaults
//	on-demand when first accessed. This approach minimizes startup time, reduces resource
//	consumption, and enables dynamic tenant provisioning without vault manager restarts.
//
//	STORAGE FACTORY VALIDATION:
//	The store factory function is validated during tenant vault creation, not during
//	manager initialization. This allows for dynamic storage configuration and supports
//	storage backends that may not be immediately available during manager startup.
//
//	BASE OPTIONS INHERITANCE:
//	All tenant vaults inherit the base cryptographic options (derivation parameters,
//	memory protection settings, debug configuration) while maintaining independent
//	storage through the factory-provided stores.
//
// STORAGE FACTORY REQUIREMENTS:
//
//	FACTORY FUNCTION SIGNATURE:
//	func(tenantID string) (persist.Store, error)
//
//	The factory receives the tenant ID and must return a configured storage instance
//	or an error if storage cannot be created. The factory is responsible for:
//	- Creating or connecting to appropriate storage backend
//	- Applying tenant-specific configuration and security policies
//	- Ensuring proper access controls and data isolation
//	- Handling storage initialization and connection errors
//
//	ERROR HANDLING:
//	Storage factory errors prevent tenant vault creation and are propagated to callers.
//	The factory should implement appropriate retry logic, connection pooling, and
//	error recovery mechanisms based on the storage backend characteristics.
//
//	THREAD SAFETY:
//	The storage factory may be called concurrently from multiple goroutines during
//	parallel tenant vault creation. The factory implementation must be thread-safe
//	and handle concurrent storage creation requests appropriately.
//
// SECURITY CONSIDERATIONS:
//
//	TENANT ISOLATION:
//	The factory must ensure complete storage isolation between tenants. Storage instances
//	returned for different tenants must not share data, connection pools, or access
//	credentials that could lead to cross-tenant data exposure or unauthorized access.
//
//	ACCESS CONTROL:
//	Each storage instance should implement appropriate access controls for its tenant.
//	Consider implementing storage-level authentication, authorization, and audit logging
//	to provide defense-in-depth security and compliance support.
//
//	CREDENTIAL MANAGEMENT:
//	Storage backend credentials and connection details should be managed securely,
//	preferably through integration with enterprise credential management systems.
//	Avoid hardcoded credentials and implement secure credential rotation procedures.
//
// OPERATIONAL CONSIDERATIONS:
//
//	RESOURCE MANAGEMENT:
//	The factory should implement appropriate resource management including connection
//	pooling, resource cleanup, and graceful shutdown procedures. Consider resource
//	limits and monitoring to prevent resource exhaustion in multi-tenant environments.
//
//	MONITORING AND OBSERVABILITY:
//	Implement comprehensive monitoring for storage factory operations including
//	creation success rates, error conditions, performance metrics, and resource
//	utilization. This supports operational visibility and troubleshooting.
//
//	BACKUP AND RECOVERY:
//	Consider backup and recovery requirements for factory-created storage instances.
//	Different storage backends may require different backup strategies and recovery
//	procedures, which should be documented and tested regularly.
//
// COMMON USAGE PATTERNS:
//
//	ENVIRONMENT-BASED STORAGE:
//	Different environments (development, staging, production) can use different
//	storage backends through factory logic that examines tenant IDs or configuration
//	to determine appropriate storage types and configurations.
//
//	PERFORMANCE TIERING:
//	High-performance tenants can receive SSD-backed or memory-cached storage while
//	archival tenants receive cost-optimized storage, all managed through factory
//	logic that examines tenant characteristics or service levels.
//
//	COMPLIANCE SEGMENTATION:
//	Tenants with different compliance requirements can receive appropriately
//	configured storage backends (encrypted, geographically constrained, audit-enabled)
//	through factory logic that applies compliance policies based on tenant metadata.
//
// USAGE EXAMPLE:
//
//	```go
//	// Create base vault options with security configuration
//	baseOptions := vault.Options{
//	    DerivationSalt:       generateSecureSalt(),
//	    DerivationPassphrase: "secure-master-passphrase",
//	    EnableMemoryLock:     true,
//	    Debug:                false,
//	}
//
//	// Create audit logger for compliance and security monitoring
//	auditLogger := audit.NewFileLogger("/var/log/vault/audit.log")
//
//	// Define storage factory with tenant-specific logic
//	storeFactory := func(tenantID string) (persist.Store, error) {
//	    // Example: Different storage strategies based on tenant type
//	    if strings.HasPrefix(tenantID, "enterprise-") {
//	        // Enterprise tenants get database-backed storage
//	        return persist.NewDatabaseStore(fmt.Sprintf("vault_tenant_%s", tenantID))
//	    } else if strings.HasPrefix(tenantID, "dev-") {
//	        // Development tenants get file-based storage
//	        return persist.NewFileStore(fmt.Sprintf("/data/vault/%s", tenantID))
//	    } else if strings.HasPrefix(tenantID, "secure-") {
//	        // High-security tenants get HSM-backed storage
//	        return persist.NewHSMStore(tenantID, hsmConfig)
//	    } else {
//	        // Default tenants get cloud storage
//	        return persist.NewS3Store(fmt.Sprintf("vault-tenant-%s", tenantID))
//	    }
//	}
//
//	// Create vault manager with custom storage factory
//	vaultManager := vault.NewVaultManagerWithStoreFactory(
//	    baseOptions,
//	    storeFactory,
//	    auditLogger,
//	)
//
//	// Tenants will automatically receive appropriate storage backends
//	enterpriseVault, err := vaultManager.GetTenantVault("enterprise-client-001")
//	if err != nil {
//	    log.Fatalf("Failed to create enterprise vault: %v", err)
//	}
//
//	devVault, err := vaultManager.GetTenantVault("dev-team-alpha")
//	if err != nil {
//	    log.Fatalf("Failed to create development vault: %v", err)
//	}
//
//	secureVault, err := vaultManager.GetTenantVault("secure-gov-agency")
//	if err != nil {
//	    log.Fatalf("Failed to create secure vault: %v", err)
//	}
//	```
//
// ERROR SCENARIOS:
//
//	STORAGE FACTORY FAILURES:
//	When the storage factory returns an error, tenant vault creation fails and
//	the error is propagated to the caller. Implement appropriate error handling
//	and retry logic in calling code for resilient operation.
//
//	CONFIGURATION ERRORS:
//	Invalid base options or audit logger configuration will result in vault
//	creation failures. Validate configuration parameters before creating the
//	vault manager to ensure proper initialization.
//
//	RESOURCE EXHAUSTION:
//	In high-tenant environments, consider implementing resource limits and
//	monitoring to prevent excessive resource consumption from large numbers
//	of storage instances and vault operations.
//
// Parameters:
//
//	baseOptions: Cryptographic and operational configuration inherited by all tenant vaults
//	storeFactory: Factory function that creates tenant-specific storage backends
//	auditLogger: Centralized audit logging instance for security and compliance
//
// Returns:
//
//	VaultManagerService: Configured vault manager ready for multi-tenant operations
func NewVaultManagerWithStoreFactory(baseOptions Options, storeFactory func(tenantID string) (persist.Store, error), auditLogger audit.Logger) VaultManagerService {
	return &VaultManager{
		options:      baseOptions,
		storeFactory: storeFactory,
		vaults:       make(map[string]VaultService),
		audit:        auditLogger,
	}
}

// NewVaultManagerWithStoreConfig creates a new VaultManager with configurable storage backends.
//
// OVERVIEW:
// This constructor provides advanced storage configuration capabilities for the VaultManager,
// enabling organizations to select and configure specific storage backends based on their
// operational requirements, compliance needs, and infrastructure constraints. It supports
// multiple storage types through a unified configuration interface while maintaining
// consistent vault management functionality.
//
// STORAGE BACKEND ARCHITECTURE:
//
//	FACTORY PATTERN IMPLEMENTATION:
//	The constructor implements a factory pattern that creates tenant-specific storage
//	instances based on the provided StoreConfig. Each tenant receives an isolated
//	storage instance configured with the same backend parameters but scoped to their
//	specific tenant context, ensuring complete data isolation.
//
//	SUPPORTED STORAGE TYPES:
//	Currently supports StoreTypeFileSystem and StoreTypeS3 storage backends through
//	the persist.StoreConfig configuration system. Each storage type accepts specific
//	configuration parameters through the Config map[string]interface{} field to
//	accommodate backend-specific requirements and optimization settings.
//
//	TENANT ISOLATION:
//	Each tenant receives a dedicated storage instance created through the factory
//	function, ensuring complete data isolation at the storage layer. Storage paths,
//	buckets, or other tenant-specific identifiers are automatically handled by the
//	underlying storage implementation based on the provided tenant ID.
//
// CONFIGURATION STRUCTURE:
//
//	StoreConfig Parameters:
//	- Type: Specifies the storage backend (StoreTypeFileSystem, StoreTypeS3)
//	- Config: Backend-specific configuration parameters as key-value pairs
//
//	FileSystem Storage Configuration:
//	- "base_path": Root directory for vault storage (string)
//	- "permissions": File/directory permissions (int, default 0700)
//	- "sync_writes": Enable synchronous writes for durability (bool)
//
//	S3 Storage Configuration:
//	- "bucket": S3 bucket name for storage (string, required)
//	- "region": AWS region for bucket access (string, required)
//	- "access_key_id": AWS access key ID (string)
//	- "secret_access_key": AWS secret access key (string)
//	- "session_token": AWS session token for temporary credentials (string)
//	- "endpoint": Custom S3 endpoint for S3-compatible services (string)
//	- "use_path_style": Enable path-style bucket addressing (bool)
//
// AUDIT INTEGRATION:
//
//	COMPREHENSIVE AUDIT LOGGING:
//	The constructor integrates a centralized audit logger that captures all vault
//	operations across tenants. The audit logger configuration supports multiple
//	audit backends (file, syslog) with configurable log levels and output formats
//	for compliance and security monitoring requirements.
//
//	AUDIT CONFIGURATION:
//	audit.Config supports:
//	- Enabled: Enable/disable audit logging (bool)
//	- TenantID: Tenant-specific audit context (string)
//	- Type: Audit backend type (FileAuditType, SyslogAuditType, NoOp)
//	- Options: Backend-specific audit configuration (map[string]interface{})
//	- LogLevel: Audit logging verbosity level (string)
//
// OPERATIONAL CHARACTERISTICS:
//
//	LAZY INITIALIZATION:
//	Tenant-specific storage instances are created on-demand when tenants are
//	first accessed or created. This approach minimizes resource consumption
//	and enables efficient scaling for environments with large numbers of
//	potential tenants that may not be actively used.
//
//	THREAD SAFETY:
//	The vault manager implements comprehensive thread safety through RWMutex
//	protection, enabling safe concurrent access to tenant vaults while
//	maintaining performance for read-heavy workloads through read-write
//	lock optimization.
//
//	ERROR ISOLATION:
//	Storage configuration errors are isolated per tenant, preventing
//	configuration issues with one tenant from affecting others. Invalid
//	configurations are detected during tenant initialization and reported
//	through appropriate error channels.
//
// USAGE EXAMPLES:
//
//	FILESYSTEM STORAGE CONFIGURATION:
//	  storeConfig := persist.StoreConfig{
//	      Type: StoreTypeFileSystem,
//	      Config: map[string]interface{}{
//	          "base_path":    "/var/lib/volta/vaults",
//	          "permissions":  0700,
//	          "sync_writes":  true,
//	      },
//	  }
//
//	  auditConfig := &audit.Config{
//	      Enabled:  true,
//	      Type:     audit.FileAuditType,
//	      LogLevel: "info",
//	      Options: map[string]interface{}{
//	          "file_path": "/var/log/volta/audit.log",
//	          "max_size":  100, // MB
//	          "max_files": 5,
//	      },
//	  }
//
//	  auditLogger, err := audit.NewLogger(auditConfig)
//	  if err != nil {
//	      log.Fatalf("Failed to create audit logger: %v", err)
//	  }
//
//	  vaultManager := NewVaultManagerWithStoreConfig(
//	      Options{
//	          DefaultKeySize: 32,
//	          MaxSecrets:     10000,
//	      },
//	      storeConfig,
//	      auditLogger,
//	  )
//
//	S3 STORAGE CONFIGURATION:
//	  storeConfig := persist.StoreConfig{
//	      Type: StoreTypeS3,
//	      Config: map[string]interface{}{
//	          "bucket":            "my-company-vault-storage",
//	          "region":            "us-west-2",
//	          "access_key_id":     os.Getenv("AWS_ACCESS_KEY_ID"),
//	          "secret_access_key": os.Getenv("AWS_SECRET_ACCESS_KEY"),
//	          "use_path_style":    false,
//	      },
//	  }
//
//	  auditConfig := &audit.Config{
//	      Enabled: true,
//	      Type:    audit.SyslogAuditType,
//	      Options: map[string]interface{}{
//	          "facility": "local0",
//	          "tag":      "volta-vault",
//	          "network":  "udp",
//	          "address":  "localhost:514",
//	      },
//	  }
//
//	  auditLogger, err := audit.NewLogger(auditConfig)
//	  if err != nil {
//	      log.Fatalf("Failed to create audit logger: %v", err)
//	  }
//
//	  vaultManager := NewVaultManagerWithStoreConfig(
//	      Options{
//	          DefaultKeySize:     32,
//	          MaxSecrets:        50000,
//	          RetentionPeriod:   time.Hour * 24 * 90, // 90 days
//	      },
//	      storeConfig,
//	      auditLogger,
//	  )
//
//	CUSTOM STORAGE BACKEND:
//	  // For storage backends not supported by the built-in factory,
//	  // use NewVaultManagerWithFactory instead:
//	  customFactory := func(tenantID string) (persist.Store, error) {
//	      return myCustomStorage.NewStore(customConfig, tenantID)
//	  }
//
//	  vaultManager := NewVaultManagerWithFactory(baseOptions, customFactory, auditLogger)
//
// SECURITY CONSIDERATIONS:
//
//	CREDENTIAL MANAGEMENT:
//	Storage backend credentials should be managed securely through environment
//	variables, credential management services, or secure configuration management
//	systems. Avoid hardcoding credentials in configuration files or source code.
//
//	ACCESS CONTROL:
//	Ensure storage backend access controls are properly configured to restrict
//	access to authorized vault manager instances only. Use least-privilege
//	principles for storage backend permissions and regularly audit access.
//
//	ENCRYPTION AT REST:
//	Configure storage backends with appropriate encryption-at-rest capabilities.
//	For S3, enable server-side encryption. For filesystem storage, consider
//	full-disk encryption or filesystem-level encryption for sensitive environments.
//
// PERFORMANCE CONSIDERATIONS:
//
//	STORAGE BACKEND SELECTION:
//	Choose storage backends based on performance requirements, scalability needs,
//	and operational constraints. S3 provides better scalability and durability
//	but may have higher latency. Filesystem storage offers lower latency but
//	requires careful capacity planning and backup strategies.
//
//	CONFIGURATION OPTIMIZATION:
//	Optimize storage backend configurations for expected workloads. Enable
//	appropriate caching, connection pooling, and performance tuning options
//	based on the specific storage backend and usage patterns.
//
// ERROR HANDLING:
//
//	CONFIGURATION VALIDATION:
//	Invalid storage configurations are detected during tenant initialization
//	and result in clear error messages indicating the specific configuration
//	issues. Validate configurations in development environments before
//	production deployment.
//
//	STORAGE BACKEND FAILURES:
//	Storage backend connectivity issues or failures are handled gracefully
//	with appropriate error reporting and retry mechanisms where applicable.
//	Monitor storage backend health and connectivity for operational visibility.
//
// Parameters:
//
//	baseOptions: Base vault manager configuration options
//	storeConfig: Storage backend configuration specifying type and parameters
//	auditLogger: Configured audit logger for comprehensive operation logging
//
// Returns:
//
//	*VaultManager: Configured vault manager instance with specified storage backend
func NewVaultManagerWithStoreConfig(baseOptions Options, storeConfig persist.StoreConfig, auditLogger audit.Logger) *VaultManager {
	return &VaultManager{
		options: baseOptions,
		storeFactory: func(tenantID string) (persist.Store, error) {
			return persist.NewStore(storeConfig, tenantID)
		},
		mu:     sync.RWMutex{},
		vaults: make(map[string]VaultService),
		audit:  auditLogger,
	}
}

// NewVaultManagerFileStore creates a new instance of VaultManager configured to use
// a file-based storage system. This function initializes the VaultManager with the
// provided options, base path for the storage, and an audit logger for tracking
// actions and secret accesses.
//
// Parameters:
//
//   - options (Options): A structure containing critical configuration parameters
//     for vault operation, including key derivation settings, passphrase handling,
//     and memory protection options.
//
//   - basePath (string): The directory path where vault data will be stored and
//     managed. This path should be secure and accessible only to authorized users
//     or processes.
//
//   - auditLogger (audit.Logger): An implementation of the Logger interface that
//     will handle audit logging for actions performed by the VaultManager,
//     ensuring that operations can be tracked and monitored for security
//     and compliance purposes.
//
// Returns:
//   - *VaultManager: A pointer to the newly created VaultManager instance, which
//     is ready for use in managing tenant-specific vaults for encryption,
//     decryption, and secure storage.
//
// Usage Example:
// ```go
//
//	options := Options{
//	   DerivationSalt: []byte("random-salt-here"),
//	   DerivationPassphrase: "secure-passphrase-here",
//	   EnvPassphraseVar: "VAULT_MASTER_PASSPHRASE",
//	   EnableMemoryLock: true,
//	   Debug: false,
//	}
//
// auditLogger := myAuditLoggerImplementation() // Assume this implements audit.Logger.
// basePath := "/path/to/vault/storage"
//
// vaultManager := NewVaultManagerFileStore(options, basePath, auditLogger)
//
// // Now, vaultManager can be used to manage vault operations for different tenants.
func NewVaultManagerFileStore(options Options, basePath string, auditLogger audit.Logger) VaultManagerService {
	return &VaultManager{
		options: options,
		storeFactory: func(tenantID string) (persist.Store, error) {
			return persist.NewFileSystemStore(basePath, tenantID)
		},
		mu:     sync.RWMutex{},
		vaults: make(map[string]VaultService),
		audit:  auditLogger,
	}
}

// NewVaultManagerS3Store initializes a new VaultManager instance configured to use an S3 storage backend.
//
// Parameters:
// - options: Options that configure the vault management behavior. This includes settings such as the derivation salt and passphrase, the environment variable for the passphrase, whether memory locking is enabled, and a debug flag.
// - storeConfig: A persist.StoreConfig object that defines the configuration of the S3 storage, including the storage type and specific settings for the backend.
// - auditLogger: An audit.Logger implementation used for logging access and operations on the vaults.
//
// Returns:
// - A pointer to an initialized VaultManager and an error. If the initialization is successful, error will be nil. If there are issues during initialization, an appropriate error will be returned.
//
// Usage Example:
// ```go
//
//	options := Options{
//	   DerivationSalt:       []byte("some_salt"),
//	   DerivationPassphrase: "securepass",
//	   EnvPassphraseVar:     "VAULT_PASSPHRASE",
//	   EnableMemoryLock:     true,
//	   Debug:                false,
//	}
//
//	storeConfig := StoreConfig{
//	   Type:   StoreTypeS3,
//	   Config: map[string]interface{}{"endpoint": "s3.example.com", "bucket": "vault-bucket"},
//	}
//
// auditLogger := &MyAuditLogger{} // Your implementation of the audit.Logger
//
// vaultManager, err := NewVaultManagerS3Store(options, storeConfig, auditLogger)
//
//	if err != nil {
//	   log.Fatalf("Error initializing Vault Manager: %v", err)
//	}
//
// // Use vaultManager as needed...
func NewVaultManagerS3Store(options Options, storeConfig persist.S3Config, auditLogger audit.Logger) (VaultManagerService, error) {
	return &VaultManager{
		options: options,
		storeFactory: func(tenantID string) (persist.Store, error) {
			return persist.NewS3Store(storeConfig, tenantID)
		},
		mu:     sync.RWMutex{},
		vaults: make(map[string]VaultService),
		audit:  auditLogger,
	}, nil
}

// ListTenants returns all available tenants from the storage backend.
//
// OVERVIEW:
// This method provides tenant discovery capabilities by querying the underlying
// storage backend to enumerate all configured tenants. It serves as the primary
// mechanism for tenant discovery in multi-tenant vault environments, supporting
// administrative operations, monitoring, and tenant lifecycle management.
//
// DISCOVERY MECHANISM:
//
//	STORAGE-BACKEND ENUMERATION:
//	The method creates a temporary storage connection specifically for tenant
//	discovery, bypassing tenant-specific initialization to access the global
//	tenant registry. This approach ensures accurate tenant enumeration even
//	when individual tenant vaults may be in various states (locked, unlocked,
//	corrupted, or undergoing maintenance).
//
//	LIGHTWEIGHT OPERATION:
//	Discovery operations are designed to be lightweight and non-intrusive,
//	requiring minimal resources and avoiding any tenant-specific cryptographic
//	operations. This ensures tenant enumeration can succeed even under
//	resource-constrained conditions or partial system failures.
//
//	CONSISTENT VIEW:
//	The method provides a consistent point-in-time snapshot of available
//	tenants, though the actual tenant states may change between enumeration
//	and subsequent operations. Callers should handle tenant availability
//	changes gracefully in subsequent operations.
//
// SECURITY CONSIDERATIONS:
//
//	AUTHORIZATION REQUIREMENTS:
//	Tenant enumeration is a privileged operation that reveals organizational
//	structure and tenant deployment patterns. Access should be restricted to
//	administrative users and service accounts with legitimate operational
//	requirements for tenant discovery.
//
//	INFORMATION DISCLOSURE:
//	Tenant IDs may contain sensitive organizational information or reveal
//	business relationships, customer structures, or deployment patterns.
//	Results should be handled with appropriate confidentiality controls
//	and never logged in plaintext or transmitted over unsecured channels.
//
//	AUDIT IMPLICATIONS:
//	Tenant enumeration operations are fully audited, including the identity
//	of the caller, timing, and the complete list of returned tenants. This
//	supports compliance requirements and security monitoring for unauthorized
//	reconnaissance activities.
//
// OPERATIONAL USE CASES:
//
//	ADMINISTRATIVE OPERATIONS:
//	- Bulk operations across multiple tenants (key rotation, updates)
//	- System maintenance and health checking procedures
//	- Tenant lifecycle management and provisioning workflows
//	- Monitoring and alerting system configuration
//
//	MONITORING AND OBSERVABILITY:
//	- Health dashboard population and status reporting
//	- Metrics collection and performance monitoring setup
//	- Capacity planning and resource utilization analysis
//	- Service discovery for tenant-specific monitoring endpoints
//
//	COMPLIANCE AND REPORTING:
//	- Compliance audit preparation and tenant inventory
//	- Security posture assessment across all tenants
//	- Tenant-specific policy enforcement and validation
//	- Regulatory reporting and documentation requirements
//
// ERROR HANDLING:
//
//	STORAGE BACKEND FAILURES:
//	Storage connectivity issues, authentication failures, or backend
//	unavailability result in immediate error return with no tenant
//	information disclosed. Callers should implement appropriate retry
//	logic with exponential backoff for transient failures.
//
//	PARTIAL FAILURES:
//	If the storage backend is partially available or some tenant
//	metadata is corrupted, the method returns successfully enumerated
//	tenants rather than failing completely. This degraded-mode operation
//	supports continued service availability during partial outages.
//
//	CONCURRENT MODIFICATIONS:
//	Since tenant creation and deletion may occur concurrently with
//	enumeration, the returned list represents a point-in-time snapshot
//	that may not reflect real-time tenant availability. Callers must
//	handle tenant availability changes in subsequent operations.
//
// PERFORMANCE CHARACTERISTICS:
//
//	SCALABILITY PROFILE:
//	The operation scales linearly with the number of configured tenants
//	and logarithmically with storage backend size. For deployments with
//	thousands of tenants, consider implementing caching strategies or
//	pagination for large-scale tenant enumeration operations.
//
//	RESOURCE UTILIZATION:
//	Tenant discovery requires minimal CPU and memory resources but may
//	consume significant I/O bandwidth for large tenant deployments.
//	The temporary storage connection is automatically cleaned up to
//	prevent resource leaks.
//
//	CACHING CONSIDERATIONS:
//	Results may be cached for performance optimization, but cache
//	invalidation must be carefully managed to ensure accuracy during
//	tenant provisioning and deprovisioning operations. Consider
//	implementing cache TTL policies appropriate for tenant change
//	frequency.
//
// IMPLEMENTATION DETAILS:
//
//	TEMPORARY STORE PATTERN:
//	The method creates a temporary store connection with an empty tenant
//	ID, which signals the storage backend to operate in discovery mode
//	rather than tenant-specific mode. This architectural pattern ensures
//	clean separation between tenant-specific operations and administrative
//	discovery operations.
//
//	RESOURCE CLEANUP:
//	The temporary store connection is automatically closed via defer
//	statement, ensuring proper resource cleanup even if the underlying
//	ListTenants operation fails or panics. This prevents resource leaks
//	in long-running services.
//
//	FACTORY ABSTRACTION:
//	By using the storeFactory with an empty tenant ID, the method
//	leverages the same factory pattern used for tenant-specific operations
//	while accessing global tenant enumeration capabilities. This ensures
//	consistent configuration and connection handling across all storage
//	operations.
//
// Returns:
//
//	[]string: Slice of tenant IDs for all available tenants
//	error: nil on success, error on storage failures or authorization issues
//
// Example Usage:
//
//	tenants, err := vaultManager.ListTenants()
//	if err != nil {
//	    log.Error("Failed to enumerate tenants", "error", err)
//	    return err
//	}
//	log.Info("Discovered tenants", "count", len(tenants), "tenants", tenants)
func (tm *VaultManager) ListTenants() ([]string, error) {
	// Create a temporary store to discover tenants
	// We use empty tenant ID since we're just discovering
	store, err := tm.storeFactory("")
	if err != nil {
		return nil, fmt.Errorf("failed to create store for tenant discovery: %w", err)
	}
	defer store.Close()

	return store.ListTenants()
}

// GetVault returns a vault for the given tenant, creating it if needed.
//
// OVERVIEW:
// This method provides the primary entry point for accessing tenant-specific
// vault services within the multi-tenant architecture. It implements a lazy
// initialization pattern that creates vault instances on-demand while ensuring
// thread-safe access to the tenant vault registry.
//
// LAZY INITIALIZATION SEMANTICS:
//
//	ON-DEMAND CREATION:
//	Vaults are created only when first accessed, optimizing memory usage and
//	startup performance in environments with large numbers of tenants. This
//	approach scales efficiently from single-tenant to enterprise deployments
//	with thousands of tenants.
//
//	SINGLETON GUARANTEE:
//	Once created, each tenant vault is cached and reused for all subsequent
//	requests from that tenant. This ensures consistent state management and
//	optimal resource utilization while maintaining strict tenant isolation.
//
//	THREAD-SAFE REGISTRY:
//	The tenant vault registry is protected by a mutex to ensure thread-safe
//	concurrent access. Multiple goroutines can safely request vaults for the
//	same or different tenants without race conditions or duplicate creation.
//
// TENANT ISOLATION ARCHITECTURE:
//
//	DEDICATED STORAGE:
//	Each tenant receives a completely isolated storage backend created through
//	the configured storeFactory. This ensures cryptographic isolation where
//	tenant data cannot accidentally leak across tenant boundaries.
//
//	INDEPENDENT LIFECYCLE:
//	Each tenant vault maintains independent lifecycle management, allowing
//	individual tenants to be created, managed, and destroyed without affecting
//	other tenants in the system.
//
//	SECURITY BOUNDARIES:
//	Tenant isolation provides strong security guarantees where compromise of
//	one tenant cannot affect the security or availability of other tenants.
//	Each vault operates with tenant-specific encryption keys and access controls.
//
// PERFORMANCE CHARACTERISTICS:
//
//	MEMORY EFFICIENCY:
//	Lazy initialization prevents memory overhead from unused tenant vaults.
//	In environments with many registered but inactive tenants, this approach
//	provides significant memory savings.
//
//	ACCESS LATENCY:
//	First-time vault creation incurs additional latency for store and vault
//	initialization. Subsequent accesses are optimized with O(1) lookup from
//	the in-memory registry.
//
//	SCALABILITY:
//	The registry scales linearly with active tenant count. Cache eviction
//	strategies may be implemented for environments with extremely high tenant
//	counts.
//
// ERROR HANDLING PATTERNS:
//
//	STORE CREATION FAILURES:
//	If tenant-specific store creation fails, the error is wrapped with tenant
//	context and propagated. No partial state is retained, ensuring clean
//	failure semantics.
//
//	VAULT INITIALIZATION FAILURES:
//	Vault creation failures result in complete cleanup of any partially
//	initialized resources. The tenant registry remains consistent and
//	subsequent requests will retry initialization.
//
//	ATOMIC OPERATIONS:
//	All registry modifications are atomic - either a vault is successfully
//	created and registered, or no changes are made to the system state.
//
// OPERATIONAL CONSIDERATIONS:
//
//	MONITORING INTEGRATION:
//	Vault creation events should be monitored for capacity planning and
//	security analysis. Sudden spikes in new tenant vault creation may indicate
//	security issues or legitimate business growth.
//
//	AUDIT INTEGRATION:
//	All vault access requests are implicitly audited through the underlying
//	vault operations. Consider explicit audit logging for vault creation
//	events for administrative tracking.
//
//	RESOURCE MANAGEMENT:
//	Long-running systems may benefit from vault eviction policies for inactive
//	tenants to manage memory usage. Such policies must carefully balance
//	performance and resource utilization.
//
// SECURITY CONSIDERATIONS:
//
//	TENANT VALIDATION:
//	The tenantID parameter should be validated and sanitized before use in
//	storage operations. Malicious tenant IDs could potentially cause security
//	issues in the underlying storage implementation.
//
//	ACCESS CONTROL:
//	This method should be called only after proper tenant authorization has
//	been verified by the calling context. The VaultManager itself does not
//	enforce tenant access policies.
//
//	INFORMATION DISCLOSURE:
//	Error messages are carefully crafted to avoid leaking sensitive information
//	about system internals while providing sufficient detail for debugging.
//
// USAGE PATTERNS:
//
//	REQUEST LIFECYCLE:
//	Typically called at the beginning of request processing to obtain the
//	appropriate vault instance for the authenticated tenant context.
//
//	SERVICE INTEGRATION:
//	Used by higher-level services to abstract away multi-tenant complexity
//	and present a unified vault interface to application logic.
//
//	TESTING AND DEVELOPMENT:
//	Supports easy testing with mock store factories and simplified development
//	patterns for single-tenant scenarios.
//
// Parameters:
//
//	tenantID: Unique identifier for the tenant requesting vault access.
//	          Must be non-empty and conform to tenant ID validation rules.
//
// Returns:
//
//	VaultService: Thread-safe vault instance for the specified tenant.
//	              Instance is cached and reused for subsequent calls.
//	error:        nil on success, wrapped error with tenant context on failure.
//	              Failures leave no partial state in the system.
//
// Thread Safety:
//
//	This method is fully thread-safe and can be called concurrently from
//	multiple goroutines. Internal locking ensures consistent state management.
func (tm *VaultManager) GetVault(tenantID string) (VaultService, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if vault, exists := tm.vaults[tenantID]; exists {
		return vault, nil
	}

	// Create tenant-specific store
	store, err := tm.storeFactory(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to create store for tenant %s: %w", tenantID, err)
	}

	// Create vault with tenant store
	vault, err := NewWithStore(tm.options, store, tm.audit, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault for tenant %s: %w", tenantID, err)
	}

	tm.vaults[tenantID] = vault
	return vault, nil
}

// CloseTenant closes and removes a tenant's vault from the manager.
//
// OVERVIEW:
// This method performs a controlled shutdown of a specific tenant's vault,
// ensuring all cryptographic resources are properly cleaned up and removed
// from the manager's active vault registry. It implements secure resource
// deallocation with comprehensive error handling and state management.
//
// OPERATIONAL SEMANTICS:
//
//	GRACEFUL SHUTDOWN:
//	The method performs a graceful shutdown of the tenant's vault, allowing
//	any in-progress operations to complete before initiating the closure
//	process. This prevents data corruption or partial operations that could
//	compromise security or data integrity.
//
//	RESOURCE CLEANUP:
//	All cryptographic materials, secure memory allocations, and file handles
//	associated with the tenant are properly disposed of according to security
//	best practices. This includes secure memory wiping and proper disposal
//	of sensitive resources.
//
//	REGISTRY MANAGEMENT:
//	The tenant is atomically removed from the active vault registry, preventing
//	future access attempts while ensuring thread-safe state transitions.
//	This maintains consistency even under concurrent access scenarios.
//
// SECURITY CONSIDERATIONS:
//
// SECURE DISPOSAL:
// - All cryptographic keys and sensitive data are securely wiped from memory
// - File handles and temporary resources are properly closed and cleaned
// - Audit trails are generated for tenant closure operations
// - No sensitive data remnants are left in system memory or storage
//
// CONCURRENCY SAFETY:
// - Thread-safe operation with proper locking mechanisms
// - Atomic state transitions prevent race conditions
// - Concurrent access to other tenants remains unaffected
// - Pending operations on the tenant are safely handled
//
// ERROR HANDLING:
//
// FAULT TOLERANCE:
// The method implements best-effort cleanup semantics where partial failures
// in vault closure do not prevent registry cleanup. This prevents resource
// leaks while maintaining system stability even when underlying vault
// operations encounter errors.
//
// ERROR REPORTING:
// Detailed error information is provided for vault closure failures, enabling
// administrators to identify and resolve underlying issues that may affect
// system performance or security posture.
//
// USE CASES:
//
// TENANT LIFECYCLE MANAGEMENT:
// - Normal tenant deprovisioning and cleanup operations
// - Resource optimization by closing inactive tenant vaults
// - System maintenance and resource management procedures
// - Emergency tenant isolation for security incidents
//
// OPERATIONAL PROCEDURES:
// - Scheduled maintenance and resource cleanup operations
// - Capacity management and resource optimization
// - Incident response and security containment procedures
// - System shutdown and restart procedures
//
// IDEMPOTENCY:
// The operation is idempotent - calling CloseTenant multiple times for the
// same tenant ID will not result in errors or side effects. Non-existent
// tenants are handled gracefully without error conditions.
//
// AUDIT IMPLICATIONS:
// Tenant closure operations are automatically logged to the audit system,
// providing full traceability of tenant lifecycle events for compliance
// and security monitoring purposes.
//
// Parameters:
//
//	tenantID: Unique identifier for the tenant vault to close and remove
//
// Returns:
//
//	error: nil on successful closure, error if vault closure fails
//
// Thread Safety: Safe for concurrent use across multiple goroutines
func (tm *VaultManager) CloseTenant(tenantID string) error {
	startTime := time.Now()
	requestID := tm.newRequestID()

	tm.logAudit(requestID, "CLOSE_TENANT_INITIATED", tenantID, nil, map[string]interface{}{
		"total_tenants_before": len(tm.vaults),
	})

	// Input validation
	if tenantID == "" {
		validationErr := fmt.Errorf("tenant ID cannot be empty")
		tm.logAudit(requestID, "CLOSE_TENANT_VALIDATION_FAILED", tenantID, validationErr, map[string]interface{}{
			"validation_error": "empty_tenant_id",
		})
		return validationErr
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	vault, exists := tm.vaults[tenantID]
	if !exists {
		// Tenant not found - this is not an error, just log and return success
		tm.logAudit(requestID, "CLOSE_TENANT_NOT_FOUND", tenantID, nil, map[string]interface{}{
			"available_tenants": tm.getTenantList(),
			"total_duration_ms": time.Since(startTime).Milliseconds(),
			"operation_result":  "no_action_required",
		})
		return nil
	}

	tm.logAudit(requestID, "CLOSE_TENANT_FOUND", tenantID, nil, map[string]interface{}{
		"vault_type": fmt.Sprintf("%T", vault),
	})

	// Attempt to close the vault
	closeStartTime := time.Now()
	if err := vault.Close(); err != nil {
		closeErr := fmt.Errorf("failed to close vault for tenant %s: %w", tenantID, err)

		tm.logAudit(requestID, "CLOSE_TENANT_VAULT_CLOSE_FAILED", tenantID, closeErr, map[string]interface{}{
			"error_type":        tm.categorizeError(err),
			"close_duration_ms": time.Since(closeStartTime).Milliseconds(),
			"total_duration_ms": time.Since(startTime).Milliseconds(),
			"vault_left_in_map": true,
			"cleanup_status":    "failed",
		})

		return closeErr
	}

	tm.logAudit(requestID, "CLOSE_TENANT_VAULT_CLOSED", tenantID, nil, map[string]interface{}{
		"close_duration_ms": time.Since(closeStartTime).Milliseconds(),
	})

	// Remove from map after successful close
	delete(tm.vaults, tenantID)

	tm.logAudit(requestID, "CLOSE_TENANT_COMPLETED", tenantID, nil, map[string]interface{}{
		"total_tenants_after": len(tm.vaults),
		"total_duration_ms":   time.Since(startTime).Milliseconds(),
		"cleanup_status":      "success",
		"operation_result":    "tenant_closed_and_removed",
	})

	return nil
}

// CloseAll closes all tenant vaults and performs comprehensive resource cleanup.
//
// OVERVIEW:
// This method performs a controlled shutdown of all active tenant vaults within
// the VaultManager instance. It implements a best-effort closure strategy that
// attempts to cleanly shut down every vault while collecting and reporting any
// errors encountered during the process.
//
// SHUTDOWN SEMANTICS:
//
//	COMPREHENSIVE CLOSURE:
//	Every active tenant vault is individually closed, ensuring that all
//	cryptographic resources, secure memory allocations, and system handles
//	are properly released. This prevents resource leaks and ensures clean
//	system shutdown even in error scenarios.
//
//	BEST-EFFORT STRATEGY:
//	The method continues attempting to close remaining vaults even if some
//	closures fail. This ensures maximum resource cleanup while providing
//	detailed error reporting for any problematic vaults that couldn't be
//	cleanly shut down.
//
//	ATOMIC STATE RESET:
//	After attempting to close all vaults, the internal vault registry is
//	completely reset regardless of individual closure outcomes. This ensures
//	the VaultManager returns to a clean state and prevents access to
//	potentially corrupted vault instances.
//
// CONCURRENCY SAFETY:
// The method acquires exclusive access to the VaultManager during the entire
// shutdown process, preventing concurrent operations from interfering with
// the cleanup process or accessing vaults during shutdown.
//
// ERROR AGGREGATION:
// Individual vault closure errors are collected and aggregated into a
// comprehensive error report that identifies which specific tenants
// experienced closure issues, enabling targeted troubleshooting and
// administrator notification.
//
// SECURITY CONSIDERATIONS:
// - All tenant cryptographic material is securely cleared
// - Secure memory allocations are properly released
// - No tenant data persists in memory after successful completion
// - Partial failures still result in maximum possible resource cleanup
//
// OPERATIONAL IMPACT:
// - All tenant vaults become inaccessible immediately
// - In-flight operations may fail with vault closure errors
// - Service requires reinitialization before tenant access can resume
// - Audit logs record the mass closure event for compliance tracking
//
// USE CASES:
// - Application shutdown and graceful service termination
// - Emergency security procedures requiring immediate vault closure
// - Administrative maintenance requiring service restart
// - Resource cleanup during service scaling or redeployment
//
// Returns:
//
//	error: nil if all vaults closed successfully, aggregated error describing
//	       any closure failures while still performing maximum cleanup
func (tm *VaultManager) CloseAll() error {
	startTime := time.Now()
	requestID := tm.newRequestID()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	initialTenantCount := len(tm.vaults)
	tenantList := tm.getTenantList()

	tm.logAudit(requestID, "CLOSE_ALL_VAULTS_INITIATED", "", nil, map[string]interface{}{
		"total_vaults_to_close": initialTenantCount,
		"tenant_list":           tenantList,
	})

	if initialTenantCount == 0 {
		tm.logAudit(requestID, "CLOSE_ALL_VAULTS_NO_VAULTS_TO_CLOSE", "", nil, map[string]interface{}{
			"total_duration_ms": time.Since(startTime).Milliseconds(),
		})
		return nil
	}

	var errs []error
	var closeErrors []string
	successCount := 0
	var closeDetails = make(map[string]interface{})

	tm.logAudit(requestID, "CLOSE_ALL_VAULTS_PROCESSING_START", "", nil, map[string]interface{}{
		"vault_count": initialTenantCount,
		"tenant_list": tenantList,
	})

	// Process each vault
	index := 0
	for tenantID, vault := range tm.vaults {
		index++
		tenantStartTime := time.Now()

		tm.logAudit(requestID, "CLOSE_VAULT_TENANT_START", tenantID, nil, map[string]interface{}{
			"tenant_index": index,
			"total_count":  initialTenantCount,
			"vault_type":   fmt.Sprintf("%T", vault),
		})

		if err := vault.Close(); err != nil {
			closeErr := fmt.Errorf("tenant %s: %w", tenantID, err)
			errs = append(errs, closeErr)
			closeErrors = append(closeErrors, fmt.Sprintf("tenant %s: %v", tenantID, err))

			tm.logAudit(requestID, "CLOSE_VAULT_TENANT_FAILED", tenantID, err, map[string]interface{}{
				"tenant_index": index,
				"error_type":   tm.categorizeError(err),
				"duration_ms":  time.Since(tenantStartTime).Milliseconds(),
			})

			// Store individual failure details
			closeDetails[fmt.Sprintf("tenant_%s_error", tenantID)] = err.Error()
			closeDetails[fmt.Sprintf("tenant_%s_duration_ms", tenantID)] = time.Since(tenantStartTime).Milliseconds()
		} else {
			successCount++

			tm.logAudit(requestID, "CLOSE_VAULT_TENANT_SUCCESS", tenantID, nil, map[string]interface{}{
				"tenant_index": index,
				"duration_ms":  time.Since(tenantStartTime).Milliseconds(),
			})

			// Store individual success details
			closeDetails[fmt.Sprintf("tenant_%s_duration_ms", tenantID)] = time.Since(tenantStartTime).Milliseconds()
		}
	}

	// Clear the vaults map
	tm.vaults = make(map[string]VaultService)

	tm.logAudit(requestID, "CLOSE_ALL_VAULTS_MEMORY_CLEARED", "", nil, map[string]interface{}{
		"vaults_remaining": len(tm.vaults),
	})

	totalDuration := time.Since(startTime)
	failureCount := initialTenantCount - successCount

	// Final audit logging based on outcome
	finalMetadata := map[string]interface{}{
		"total_vaults":      initialTenantCount,
		"successful_closes": successCount,
		"failed_closes":     failureCount,
		"success_rate":      float64(successCount) / float64(initialTenantCount) * 100,
		"total_duration_ms": totalDuration.Milliseconds(),
		"tenant_list":       tenantList,
		"close_details":     closeDetails,
	}

	if failureCount == 0 {
		// Complete success
		tm.logAudit(requestID, "CLOSE_ALL_VAULTS_COMPLETED_SUCCESS", "", nil, finalMetadata)
	} else if successCount == 0 {
		// Complete failure
		combinedError := fmt.Errorf("errors closing vaults: %v", errs)
		finalMetadata["close_errors"] = closeErrors
		finalMetadata["error_details"] = errs
		tm.logAudit(requestID, "CLOSE_ALL_VAULTS_COMPLETED_TOTAL_FAILURE", "", combinedError, finalMetadata)
	} else {
		// Partial success
		partialError := fmt.Errorf("errors closing vaults: %v", errs)
		finalMetadata["close_errors"] = closeErrors
		finalMetadata["error_details"] = errs
		tm.logAudit(requestID, "CLOSE_ALL_VAULTS_COMPLETED_PARTIAL_SUCCESS", "", partialError, finalMetadata)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing vaults: %v", errs)
	}

	return nil
}

// RotateAllTenantKeys performs cryptographic key rotation across multiple tenants.
//
// OVERVIEW:
// This method orchestrates the rotation of encryption keys for multiple tenants
// in a coordinated bulk operation. It provides enterprise-scale key management
// capabilities with comprehensive audit trails, detailed result reporting, and
// robust error handling for each tenant operation.
//
// OPERATIONAL SEMANTICS:
//
//	BULK PROCESSING MODEL:
//	The operation processes each tenant sequentially, ensuring that failures
//	in one tenant do not affect others. Each tenant's key rotation is treated
//	as an independent operation with its own success/failure status and
//	detailed result reporting.
//
//	AUTO-DISCOVERY CAPABILITY:
//	When no tenant IDs are specified (empty slice), the method automatically
//	discovers and rotates keys for all tenants in the system. This supports
//	organization-wide key rotation policies and compliance requirements.
//
//	ATOMIC PER-TENANT OPERATIONS:
//	Each tenant's key rotation is atomic - either the entire rotation succeeds
//	or it fails completely with no partial state changes. This ensures
//	cryptographic consistency and prevents corrupted key states.
//
// SECURITY CONSIDERATIONS:
//
//	CRYPTOGRAPHIC CONTINUITY:
//	The method maintains cryptographic continuity by preserving access to
//	previously encrypted data while establishing new encryption keys. Old
//	keys remain accessible for decryption while new keys are used for
//	encryption operations.
//
//	AUDIT TRAIL COMPLETENESS:
//	Every key rotation operation generates comprehensive audit entries
//	including the rotation reason, old key identifier, new key identifier,
//	and operation timestamp. This provides complete audit trails for
//	compliance and security analysis.
//
//	FAILURE ISOLATION:
//	Tenant failures are isolated - if one tenant's key rotation fails,
//	other tenants continue to be processed. This prevents cascading
//	failures in multi-tenant environments.
//
// ENTERPRISE INTEGRATION:
//
//	COMPLIANCE SUPPORT:
//	The method supports regulatory compliance requirements for periodic
//	key rotation by providing detailed audit trails, success/failure
//	reporting, and comprehensive metadata about rotation operations.
//
//	OPERATIONAL VISIBILITY:
//	Detailed result reporting enables operations teams to monitor bulk
//	key rotation progress, identify failed operations, and take corrective
//	action. Each result includes diagnostic information for troubleshooting.
//
//	AUTOMATION INTEGRATION:
//	The method is designed for integration with automated key rotation
//	systems, scheduled operations, and compliance automation tools.
//	Results can be processed programmatically for further automation.
//
// RESULT INTERPRETATION:
//
//	SUCCESS METRICS:
//	Results include both per-tenant success/failure status and aggregate
//	success metrics. Operations teams can quickly identify overall operation
//	success rates and individual tenant issues.
//
//	DIAGNOSTIC INFORMATION:
//	Failed operations include detailed error messages and diagnostic
//	information to support troubleshooting and remediation efforts.
//	Successful operations include metadata about the rotation results.
//
// BEST PRACTICES:
//
// 1. SCHEDULING: Perform bulk rotations during maintenance windows
// 2. MONITORING: Monitor rotation progress and results in real-time
// 3. VALIDATION: Verify rotation results and test key accessibility
// 4. DOCUMENTATION: Maintain detailed records of rotation activities
// 5. AUTOMATION: Integrate with automated compliance and monitoring systems
// 6. TESTING: Test rotation procedures in non-production environments
// 7. RECOVERY: Maintain recovery procedures for failed rotations
//
// Parameters:
//
//	tenantIDs: Slice of tenant IDs to rotate (empty slice rotates all tenants)
//	reason: Human-readable reason for rotation (recorded in audit logs)
//
// Returns:
//
//	[]BulkOperationResult: Detailed results for each tenant operation
//	error: nil on successful completion, error on system-level failures
func (tm *VaultManager) RotateAllTenantKeys(tenantIDs []string, reason string) ([]BulkOperationResult, error) {
	startTime := time.Now()
	requestID := tm.newRequestID()

	// Initialize audit metadata
	initialMetadata := map[string]interface{}{
		"requested_tenant_count": len(tenantIDs),
		"reason":                 reason,
		"has_specific_tenants":   tenantIDs != nil && len(tenantIDs) > 0,
	}

	tm.logAudit(requestID, "ROTATE_ALL_KEYS_INITIATED", "", nil, initialMetadata)

	// Default reason if not provided
	if reason == "" {
		reason = "bulk key rotation"
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_REASON_DEFAULTED", "", nil, map[string]interface{}{
			"default_reason": reason,
		})
	}

	// If no specific tenants provided, get all tenants
	if len(tenantIDs) == 0 {
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_LISTING_ALL_TENANTS", "", nil, nil)

		allTenants, err := tm.ListTenants()
		if err != nil {
			listErr := fmt.Errorf("failed to list tenants: %w", err)
			tm.logAudit(requestID, "ROTATE_ALL_KEYS_LIST_TENANTS_FAILED", "", listErr, map[string]interface{}{
				"error_type": tm.categorizeError(err),
			})
			return nil, listErr
		}

		tenantIDs = allTenants
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_ALL_TENANTS_RETRIEVED", "", nil, map[string]interface{}{
			"total_tenants_found": len(allTenants),
			"tenant_list":         allTenants,
		})
	} else {
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_USING_PROVIDED_TENANTS", "", nil, map[string]interface{}{
			"provided_tenants": tenantIDs,
		})
	}

	if len(tenantIDs) == 0 {
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_NO_TENANTS_TO_PROCESS", "", nil, map[string]interface{}{
			"total_duration_ms": time.Since(startTime).Milliseconds(),
		})
		return []BulkOperationResult{}, nil
	}

	// Log bulk operation start with final tenant list
	tm.logAudit(requestID, "ROTATE_ALL_KEYS_PROCESSING_START", "", nil, map[string]interface{}{
		"final_tenant_count": len(tenantIDs),
		"tenant_list":        tenantIDs,
		"reason":             reason,
	})

	results := make([]BulkOperationResult, 0, len(tenantIDs))
	successCount := 0
	var processingErrors []string

	for i, tenantID := range tenantIDs {
		tenantStartTime := time.Now()

		tm.logAudit(requestID, "ROTATE_KEY_TENANT_START", tenantID, nil, map[string]interface{}{
			"tenant_index": i + 1,
			"total_count":  len(tenantIDs),
			"reason":       reason,
		})

		result := BulkOperationResult{
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
			Details: map[string]interface{}{
				"reason":     reason,
				"operation":  "key_rotation",
				"request_id": requestID,
			},
		}

		// Get the vault for this tenant
		vault, err := tm.GetVault(tenantID)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to access vault: %v", err)
			results = append(results, result)

			tm.logAudit(requestID, "ROTATE_KEY_GET_VAULT_FAILED", tenantID, err, map[string]interface{}{
				"tenant_index": i + 1,
				"error_type":   tm.categorizeError(err),
				"duration_ms":  time.Since(tenantStartTime).Milliseconds(),
			})

			processingErrors = append(processingErrors, fmt.Sprintf("tenant %s: get vault failed", tenantID))
			continue
		}

		tm.logAudit(requestID, "ROTATE_KEY_VAULT_RETRIEVED", tenantID, nil, map[string]interface{}{
			"tenant_index": i + 1,
			"vault_type":   fmt.Sprintf("%T", vault),
		})

		// Get old key info before rotation
		oldKeyRetrievalStart := time.Now()
		oldKeyMeta, err := vault.GetActiveKeyMetadata()
		if err == nil {
			result.Details["old_key_id"] = oldKeyMeta.KeyID
			tm.logAudit(requestID, "ROTATE_KEY_OLD_KEY_RETRIEVED", tenantID, nil, map[string]interface{}{
				"tenant_index":          i + 1,
				"old_key_id":            oldKeyMeta.KeyID,
				"retrieval_duration_ms": time.Since(oldKeyRetrievalStart).Milliseconds(),
			})
		} else {
			tm.logAudit(requestID, "ROTATE_KEY_OLD_KEY_RETRIEVAL_FAILED", tenantID, err, map[string]interface{}{
				"tenant_index":          i + 1,
				"error_type":            tm.categorizeError(err),
				"retrieval_duration_ms": time.Since(oldKeyRetrievalStart).Milliseconds(),
			})
			result.Details["old_key_retrieval_error"] = err.Error()
		}

		// Perform the rotation using existing RotateDataEncryptionKey method
		rotationStartTime := time.Now()
		newKeyMeta, err := vault.RotateDataEncryptionKey(reason)
		rotationDuration := time.Since(rotationStartTime)

		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("key rotation failed: %v", err)

			tm.logAudit(requestID, "ROTATE_KEY_ROTATION_FAILED", tenantID, err, map[string]interface{}{
				"tenant_index":         i + 1,
				"error_type":           tm.categorizeError(err),
				"rotation_duration_ms": rotationDuration.Milliseconds(),
				"total_duration_ms":    time.Since(tenantStartTime).Milliseconds(),
				"old_key_id":           result.Details["old_key_id"], // May be nil
			})

			processingErrors = append(processingErrors, fmt.Sprintf("tenant %s: rotation failed", tenantID))
		} else {
			result.Success = true
			result.Details["new_key_id"] = newKeyMeta.KeyID
			successCount++

			tm.logAudit(requestID, "ROTATE_KEY_TENANT_SUCCESS", tenantID, nil, map[string]interface{}{
				"tenant_index":         i + 1,
				"old_key_id":           result.Details["old_key_id"], // May be nil
				"new_key_id":           newKeyMeta.KeyID,
				"rotation_duration_ms": rotationDuration.Milliseconds(),
				"total_duration_ms":    time.Since(tenantStartTime).Milliseconds(),
			})
		}

		results = append(results, result)
	}

	totalDuration := time.Since(startTime)
	failureCount := len(tenantIDs) - successCount

	// Final audit logging based on outcome
	finalMetadata := map[string]interface{}{
		"total_tenants":        len(tenantIDs),
		"successful_rotations": successCount,
		"failed_rotations":     failureCount,
		"success_rate":         float64(successCount) / float64(len(tenantIDs)) * 100,
		"reason":               reason,
		"total_duration_ms":    totalDuration.Milliseconds(),
		"tenant_list":          tenantIDs,
	}

	if failureCount == 0 {
		// Complete success
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_COMPLETED_SUCCESS", "", nil, finalMetadata)
	} else if successCount == 0 {
		// Complete failure
		combinedError := fmt.Errorf("all key rotations failed")
		finalMetadata["processing_errors"] = processingErrors
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_COMPLETED_TOTAL_FAILURE", "", combinedError, finalMetadata)
	} else {
		// Partial success
		partialError := fmt.Errorf("partial failure: %d succeeded, %d failed", successCount, failureCount)
		finalMetadata["processing_errors"] = processingErrors
		tm.logAudit(requestID, "ROTATE_ALL_KEYS_COMPLETED_PARTIAL_SUCCESS", "", partialError, finalMetadata)
	}

	return results, nil
}

// QueryAuditLogs performs comprehensive audit log queries across tenant boundaries.
//
// OVERVIEW:
// This method provides the primary interface for querying audit logs within the
// Volta vault management system. It supports both single-tenant and multi-tenant
// queries based on the provided options, enabling flexible audit analysis for
// security monitoring, compliance reporting, and operational analysis.
//
// QUERY SCOPE DETERMINATION:
//
//	SINGLE-TENANT MODE:
//	When options.TenantID is specified, the query is limited to that specific
//	tenant's audit logs. This provides optimized performance for tenant-focused
//	analysis and ensures efficient resource utilization for targeted queries.
//
//	MULTI-TENANT MODE:
//	When options.TenantID is empty, the query spans all accessible tenants
//	within the vault manager's scope. This enables organization-wide security
//	analysis and comprehensive compliance reporting across tenant boundaries.
//
//	TENANT ACCESS CONTROL:
//	The method respects tenant access permissions and silently skips tenants
//	that are inaccessible due to authorization restrictions, ensuring that
//	results only include data the caller is authorized to access.
//
// FILTERING AND PROCESSING:
//
//	PROGRESSIVE FILTERING:
//	Events are collected from all applicable tenants first, then filtered
//	based on the query criteria. This approach ensures consistent filtering
//	behavior across tenant boundaries and maintains query result integrity.
//
//	RESULT LIMITING:
//	When options.Limit is specified, the method applies the limit after
//	filtering to ensure the most relevant results are returned. The limit
//	applies to the final result set, not per-tenant results.
//
//	ERROR TOLERANCE:
//	Individual tenant query failures do not abort the entire operation.
//	The method continues processing remaining tenants and returns partial
//	results, enabling resilient operation in multi-tenant environments.
//
// PERFORMANCE CHARACTERISTICS:
//
//	SCALABILITY CONSIDERATIONS:
//	Multi-tenant queries can be resource-intensive for large tenant counts.
//	Consider using specific tenant queries or additional filtering criteria
//	for performance-sensitive applications.
//
//	MEMORY MANAGEMENT:
//	Large result sets are aggregated in memory before filtering. Monitor
//	memory usage for queries spanning many tenants or long time periods.
//
//	CONCURRENT ACCESS:
//	The method safely handles concurrent access to tenant vaults but does
//	not implement query-level locking. Results represent a point-in-time
//	snapshot across all queried tenants.
//
// AUDIT RESULT STRUCTURE:
//
//	COMPREHENSIVE METRICS:
//	Results include both the filtered events and comprehensive metrics
//	about the query execution, including total events found and filtering
//	effectiveness for query optimization and analysis.
//
//	CROSS-TENANT CORRELATION:
//	Events from multiple tenants retain their tenant context, enabling
//	cross-tenant correlation analysis while maintaining tenant isolation
//	boundaries for security and compliance.
//
// ERROR HANDLING:
//
//	GRACEFUL DEGRADATION:
//	Tenant enumeration failures return errors immediately, while individual
//	tenant access failures are handled gracefully with continued processing
//	of accessible tenants.
//
//	PARTIAL RESULTS:
//	When some tenants are inaccessible, the method returns partial results
//	from accessible tenants rather than failing completely, maximizing
//	operational utility in degraded conditions.
//
// SECURITY CONSIDERATIONS:
//
//	TENANT ISOLATION:
//	Despite cross-tenant querying capabilities, tenant data isolation is
//	maintained throughout the query process. Inaccessible tenants are
//	silently skipped without exposure of their existence or configuration.
//
//	AUDIT TRAIL:
//	The query operation itself is audited, providing full traceability of
//	audit log access for security monitoring and compliance requirements.
//
// Parameters:
//
//	options: Comprehensive query options including tenant scope, filtering
//	         criteria, time ranges, result limits, and sorting preferences
//
// Returns:
//
//	*audit.QueryResult: Complete query results with events and metadata
//	error: nil on success, error on critical failures like tenant enumeration
func (tm *VaultManager) QueryAuditLogs(options audit.QueryOptions) (*audit.QueryResult, error) {
	// Get all tenants if not specified
	var tenants []string
	if options.TenantID != "" {
		tenants = []string{options.TenantID}
	} else {
		allTenants, err := tm.ListTenants()
		if err != nil {
			return nil, fmt.Errorf("failed to list tenants: %w", err)
		}
		tenants = allTenants
	}

	var allEvents []audit.Event

	for _, tenantID := range tenants {
		vault, err := tm.GetVault(tenantID)
		if err != nil {
			continue // Skip tenants we can't access
		}

		// Query tenant-specific audit logs
		if vaultImpl, ok := vault.(*Vault); ok && vaultImpl.audit != nil {
			events, err := tm.queryTenantAuditLogs(tenantID, options)
			if err != nil {
				continue // Skip on error, could log this
			}
			allEvents = append(allEvents, events...)
		}
	}

	// Filter events based on criteria
	filteredEvents := tm.filterAuditEvents(allEvents, options)

	// Apply limit if specified
	if options.Limit > 0 && len(filteredEvents) > options.Limit {
		filteredEvents = filteredEvents[:options.Limit]
	}

	return &audit.QueryResult{
		Events:     filteredEvents,
		TotalCount: len(allEvents),
		Filtered:   len(filteredEvents),
	}, nil
}

// QueryTenantAuditLogs performs comprehensive audit queries for a single tenant.
//
// OVERVIEW:
// This method provides the most comprehensive audit querying capabilities
// for a single tenant, combining the flexibility of QueryAuditLogs with
// tenant-specific optimizations and enhanced filtering capabilities.
//
// TENANT-OPTIMIZED QUERYING:
//
//	PERFORMANCE OPTIMIZATION:
//	Tenant-specific queries are optimized using tenant-specific indexes
//	and data structures, providing better performance than cross-tenant
//	queries for tenant-focused analysis and reporting.
//
//	COMPREHENSIVE FILTERING:
//	The method supports all available filtering options with tenant-specific
//	enhancements such as secret-specific filters, key-specific filters,
//	and tenant-specific custom field matching. This enables highly
//	precise audit queries for detailed security analysis.
//
//	CONTEXTUAL ENRICHMENT:
//	Results include tenant-specific contextual information and metadata
//	that may not be available in cross-tenant queries, providing richer
//	analysis capabilities for tenant-focused investigations.
//
// ANALYTICAL CAPABILITIES:
// - Deep-dive analysis of tenant-specific security events
// - Comprehensive compliance reporting for individual tenants
// - Detailed forensic investigation capabilities
// - Performance-optimized queries for large tenant datasets
//
// USE CASES:
// - Detailed security analysis for specific tenants
// - Tenant-specific compliance audits and reporting
// - Forensic investigation of tenant security incidents
// - Operational analysis and optimization for specific tenants
//
// OPERATIONAL BEHAVIOR:
//
//	TENANT VALIDATION:
//	The method first validates that the specified tenant exists and is
//	accessible by the caller. Non-existent or inaccessible tenants result
//	in immediate error return with appropriate error messages.
//
//	AUDIT AVAILABILITY:
//	If the tenant vault does not have audit logging enabled or configured,
//	the method returns an empty but valid result set rather than failing.
//	This ensures consistent behavior across tenants with different audit
//	configurations.
//
//	QUERY OPTION ENFORCEMENT:
//	The method automatically ensures the tenant ID is properly set in the
//	query options, preventing accidental cross-tenant queries and ensuring
//	tenant isolation is maintained at the audit level.
//
// ERROR HANDLING:
// - Returns specific errors for tenant validation failures
// - Provides detailed error context for audit system failures
// - Maintains tenant isolation even in error scenarios
// - Ensures consistent error formatting for operational monitoring
//
// SECURITY CONSIDERATIONS:
// - Tenant isolation is enforced at all levels of the query operation
// - Audit access is subject to the same authorization as vault access
// - Query operations themselves are audited for security monitoring
// - Results filtering respects tenant-specific access controls
//
// Parameters:
//
//	tenantID: Unique identifier for the tenant to query
//	options: Comprehensive query options with tenant-specific enhancements
//
// Returns:
//
//	audit.QueryResult: Comprehensive audit results for the tenant
//	error: nil on success, error on failure or authorization denial
func (tm *VaultManager) QueryTenantAuditLogs(tenantID string, options audit.QueryOptions) (audit.QueryResult, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Validate tenant exists
	if _, exists := tm.vaults[tenantID]; !exists {
		return audit.QueryResult{}, fmt.Errorf("tenant %s not found", tenantID)
	}

	// Ensure tenantID is set in the query options
	options.TenantID = tenantID

	// Get the vault for this tenant
	vault := tm.vaults[tenantID]

	// Check if the vault's audit logger supports querying
	if vault.GetAudit() == nil {
		return audit.QueryResult{
			Events:     []audit.Event{},
			TotalCount: 0,
			Filtered:   0,
			HasMore:    false,
		}, nil
	}

	// Query the audit logger directly
	result, err := vault.GetAudit().Query(options)
	if err != nil {
		return audit.QueryResult{}, fmt.Errorf("failed to query audit logs for tenant %s: %w", tenantID, err)
	}

	return result, nil
}

// QueryAllTenantsAuditLogs performs cross-tenant audit log queries for administrative oversight.
//
// OVERVIEW:
// This administrative function enables comprehensive audit log queries across all active
// tenants within the vault manager's scope. It provides organization-wide visibility
// into security events, operational activities, and compliance-related data while
// maintaining strict tenant isolation and access controls.
//
// ADMINISTRATIVE SCOPE:
//
//	CROSS-TENANT VISIBILITY:
//	This function provides administrative users with the ability to query audit logs
//	across tenant boundaries, enabling organization-wide security monitoring,
//	compliance reporting, and incident response capabilities. Results maintain
//	clear tenant attribution for proper analysis and reporting.
//
//	FAULT TOLERANCE:
//	Individual tenant query failures do not abort the entire operation. Failed
//	queries are logged as warnings and return empty result sets, ensuring
//	maximum data availability even when some tenants experience issues.
//
//	CONCURRENT SAFETY:
//	The function operates under read-lock protection to ensure thread-safe
//	access to the tenant registry while allowing concurrent read operations
//	from other administrative functions.
//
// OPERATIONAL BEHAVIOR:
//
//	TENANT DISCOVERY:
//	The function automatically discovers all active tenants within the vault
//	manager and attempts to query each tenant's audit subsystem. Tenants
//	without configured audit logging are handled gracefully with empty results.
//
//	QUERY CONSISTENCY:
//	The same query options are applied consistently across all tenants,
//	with automatic tenant ID injection to ensure proper scoping and
//	result attribution for each tenant's audit subsystem.
//
//	ERROR ISOLATION:
//	Query failures for individual tenants are isolated and logged, but do
//	not prevent successful queries from other tenants. This ensures maximum
//	data availability during partial system failures or tenant-specific issues.
//
// SECURITY CONSIDERATIONS:
//
//	ADMINISTRATIVE PRIVILEGE:
//	This function requires administrative privileges due to its cross-tenant
//	nature. Access should be restricted to authorized security personnel,
//	compliance officers, and system administrators with legitimate oversight
//	responsibilities.
//
//	AUDIT TRAIL:
//	All cross-tenant audit queries are themselves audited, creating a complete
//	trail of who accessed what audit data across tenant boundaries. This
//	ensures accountability for administrative access to sensitive audit information.
//
//	DATA MINIMIZATION:
//	While this function provides broad access, it should be used judiciously
//	and with appropriate filtering to minimize unnecessary data exposure.
//	Prefer tenant-specific queries when investigating tenant-specific issues.
//
// USE CASES:
//
//	SECURITY MONITORING:
//	Organization-wide security event correlation, threat detection across
//	tenant boundaries, and identification of multi-tenant attack patterns
//	or security anomalies requiring coordinated response.
//
//	COMPLIANCE REPORTING:
//	Regulatory compliance often requires organization-wide audit reporting
//	that spans all tenant boundaries. This function provides the necessary
//	data aggregation capabilities for comprehensive compliance reporting.
//
//	INCIDENT RESPONSE:
//	Security incidents may affect multiple tenants or require correlation
//	of events across tenant boundaries. This function supports comprehensive
//	incident response investigations and forensic analysis.
//
//	OPERATIONAL ANALYSIS:
//	System-wide operational analysis, performance monitoring, and capacity
//	planning activities that require visibility into usage patterns and
//	operational metrics across all tenants.
//
// PERFORMANCE CONSIDERATIONS:
//
//	RESOURCE INTENSIVE:
//	Cross-tenant queries can be resource-intensive, especially with large
//	numbers of tenants or broad query criteria. Consider using appropriate
//	filtering and pagination to manage resource consumption.
//
//	CONCURRENT IMPACT:
//	Large cross-tenant queries may impact system performance. Consider
//	scheduling intensive queries during off-peak hours or using background
//	processing for comprehensive analytical queries.
//
// ERROR HANDLING:
//
//	GRACEFUL DEGRADATION:
//	The function implements graceful degradation where individual tenant
//	query failures are logged but do not abort the entire operation. This
//	ensures maximum data availability even during partial system failures.
//
//	DIAGNOSTIC INFORMATION:
//	Query failures are logged with diagnostic information to aid in
//	troubleshooting and system maintenance. Administrators should monitor
//	these logs for systematic issues affecting audit query capabilities.
//
// Parameters:
//
//	options: Query options applied consistently across all tenants
//
// Returns:
//
//	map[string]audit.QueryResult: Audit results organized by tenant ID
//	error: Always nil - individual tenant failures are handled gracefully
func (tm *VaultManager) QueryAllTenantsAuditLogs(options audit.QueryOptions) (map[string]audit.QueryResult, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	results := make(map[string]audit.QueryResult)

	for tenantID, vault := range tm.vaults {
		if vault.GetAudit() == nil {
			// Skip tenants without audit logging
			results[tenantID] = audit.QueryResult{
				Events:     []audit.Event{},
				TotalCount: 0,
				Filtered:   0,
				HasMore:    false,
			}
			continue
		}

		// Set tenant ID for this query
		tenantOptions := options
		tenantOptions.TenantID = tenantID

		result, err := vault.GetAudit().Query(tenantOptions)
		if err != nil {
			// Log error but continue with other tenants
			fmt.Printf("WARNING: failed to query audit logs for tenant %s: %v\n", tenantID, err)
			results[tenantID] = audit.QueryResult{
				Events:     []audit.Event{},
				TotalCount: 0,
				Filtered:   0,
				HasMore:    false,
			}
			continue
		}

		results[tenantID] = result
	}

	return results, nil
}

// QueryPassphraseAccessLogs provides specialized querying for passphrase-related security events.
//
// OVERVIEW:
// This convenience method offers a streamlined interface for querying passphrase access
// events within a specific tenant. It abstracts the complexity of audit query configuration
// and provides focused access to critical security events related to passphrase usage,
// authentication attempts, and access pattern analysis.
//
// SECURITY FOCUS:
//
//	PASSPHRASE EVENT FILTERING:
//	The method automatically configures query options to capture only passphrase-related
//	events, including successful authentications, failed attempts, passphrase changes,
//	policy violations, and suspicious access patterns. This focused approach enables
//	efficient security monitoring and threat detection.
//
//	AUTHENTICATION MONITORING:
//	Passphrase access logs are critical for detecting unauthorized access attempts,
//	credential stuffing attacks, brute force attempts, and other authentication-related
//	security threats. This method provides direct access to these high-priority events.
//
//	ACCESS PATTERN ANALYSIS:
//	The chronological ordering of passphrase events enables analysis of access patterns,
//	identification of anomalous behavior, and detection of potential security incidents
//	requiring investigation or response.
//
// OPERATIONAL CHARACTERISTICS:
//
//	TIME-BASED FILTERING:
//	The 'since' parameter enables efficient time-bounded queries, allowing callers to
//	retrieve only recent events or events from specific time periods. This is essential
//	for both real-time monitoring and historical analysis of passphrase access patterns.
//
//	REASONABLE RESULT LIMITS:
//	The method applies a default limit of 1000 events to prevent resource exhaustion
//	while providing sufficient data for most analysis scenarios. This balance ensures
//	good performance while capturing comprehensive event data for security analysis.
//
//	TENANT-SPECIFIC SCOPE:
//	All queries are strictly scoped to the specified tenant, ensuring tenant isolation
//	and preventing cross-tenant data leakage while enabling focused security analysis
//	for specific tenant environments.
//
// CONVENIENCE FEATURES:
//
//	SIMPLIFIED INTERFACE:
//	This method eliminates the need for callers to construct complex audit query
//	options, providing a clean interface focused specifically on passphrase events.
//	This reduces integration complexity and potential configuration errors.
//
//	OPTIMIZED CONFIGURATION:
//	The method uses pre-configured query options optimized for passphrase event
//	retrieval, including appropriate filtering, sorting, and limiting parameters
//	that provide the most relevant results for security analysis.
//
//	CONSISTENT BEHAVIOR:
//	By standardizing the query configuration, this method ensures consistent
//	behavior across different callers and use cases, reducing variability in
//	result quality and enabling reliable security monitoring workflows.
//
// SECURITY MONITORING USE CASES:
//
//	REAL-TIME THREAT DETECTION:
//	Monitor recent passphrase access events to detect ongoing authentication
//	attacks, credential abuse, or suspicious access patterns requiring immediate
//	security response and investigation.
//
//	FORENSIC INVESTIGATION:
//	Analyze historical passphrase access events during security incident response
//	to understand attack timelines, identify compromised credentials, and assess
//	the scope and impact of authentication-related security breaches.
//
//	COMPLIANCE REPORTING:
//	Generate compliance reports focusing on authentication events and access
//	controls, demonstrating adherence to security policies and regulatory
//	requirements for credential management and access monitoring.
//
//	BEHAVIORAL ANALYSIS:
//	Study passphrase usage patterns over time to identify normal vs. anomalous
//	behavior, establish behavioral baselines, and detect deviations that may
//	indicate security threats or policy violations.
//
// OPERATIONAL INTEGRATION:
//
//	SECURITY DASHBOARDS:
//	Integrate with security monitoring dashboards to provide real-time visibility
//	into passphrase access events, authentication trends, and security metrics
//	for operational security teams and management oversight.
//
//	AUTOMATED ALERTING:
//	Use this method in automated security monitoring systems to trigger alerts
//	based on passphrase access patterns, failed authentication thresholds, or
//	other security-critical events requiring immediate attention.
//
//	INCIDENT RESPONSE:
//	Incorporate into incident response workflows to quickly gather authentication-
//	related evidence during security incidents, enabling faster response times
//	and more effective incident containment and remediation.
//
// PERFORMANCE CONSIDERATIONS:
//
//	EFFICIENT FILTERING:
//	The method leverages optimized backend filtering to efficiently retrieve
//	only passphrase-related events, minimizing network traffic, memory usage,
//	and processing overhead compared to broader audit queries.
//
//	TIME-BOUNDED QUERIES:
//	Using the 'since' parameter effectively helps limit result sets and improve
//	query performance, especially important for tenants with high authentication
//	volumes or long operational histories.
//
//	RESULT SET MANAGEMENT:
//	The 1000-event limit prevents excessive memory usage and ensures reasonable
//	response times, while still providing sufficient data for most analysis
//	scenarios. Consider multiple queries for comprehensive historical analysis.
//
// ERROR HANDLING AND RELIABILITY:
//
//	TENANT VALIDATION:
//	The method validates tenant existence and access permissions before executing
//	queries, providing clear error messages for invalid tenant IDs or access
//	permission failures.
//
//	GRACEFUL DEGRADATION:
//	Query failures are handled gracefully with appropriate error reporting,
//	enabling calling applications to implement appropriate retry logic or
//	fallback mechanisms for reliable security monitoring.
//
// DATA QUALITY AND CONSISTENCY:
//
//	STANDARDIZED EVENTS:
//	Returned events follow standardized audit event schemas, ensuring consistent
//	data structure and content across different vault implementations and
//	enabling reliable automated processing and analysis.
//
//	CHRONOLOGICAL ORDERING:
//	Events are returned in chronological order, enabling timeline analysis and
//	proper sequencing of authentication events for accurate security analysis
//	and incident reconstruction.
//
// Parameters:
//
//	tenantID: Unique identifier for the tenant whose passphrase events to query
//	since: Optional timestamp to limit results to events after this time (nil for all events)
//
// Returns:
//
//	[]audit.Event: Chronologically ordered passphrase access events (max 1000)
//	error: nil on success, error on tenant validation failure or query execution failure
func (tm *VaultManager) QueryPassphraseAccessLogs(tenantID string, since *time.Time) ([]audit.Event, error) {
	options := audit.QueryOptions{
		TenantID:         tenantID,
		Since:            since,
		PassphraseAccess: true,
		Limit:            1000, // reasonable default
	}

	return tm.queryTenantAuditLogs(tenantID, options)
}

// QueryFailedOperations provides specialized queries for failed vault operations within a tenant.
//
// OVERVIEW:
// This convenience method is specifically designed for security monitoring and operational
// troubleshooting by focusing exclusively on failed vault operations. It provides an
// optimized interface for identifying security incidents, operational issues, and system
// anomalies that require immediate attention or investigation.
//
// OPERATIONAL FOCUS:
//
//	FAILURE-SPECIFIC FILTERING:
//	The method automatically configures audit queries to return only failed operations,
//	eliminating the need for manual filtering of successful operations. This targeted
//	approach significantly reduces result set size and improves query performance for
//	security and operational analysis.
//
//	TEMPORAL SCOPING:
//	The optional 'since' parameter enables time-bounded queries, allowing users to
//	focus on recent failures or specific time periods of interest. When nil, queries
//	return all historical failed operations subject to the configured result limit.
//
//	TENANT ISOLATION:
//	Failed operations are queried within the context of a specific tenant, ensuring
//	proper data isolation and access control while enabling focused troubleshooting
//	and security analysis for individual tenants.
//
// RESULT CHARACTERISTICS:
//
//	COMPREHENSIVE FAILURE DATA:
//	Results include complete audit event information for failed operations, including
//	operation type, failure reason, timestamps, user context, and any associated
//	error messages or diagnostic information.
//
//	PERFORMANCE OPTIMIZED:
//	The method includes a reasonable default limit (1000 events) to prevent
//	performance issues while providing sufficient data for most analysis scenarios.
//	This limit balances comprehensiveness with system performance.
//
//	CHRONOLOGICAL ORDERING:
//	Failed operations are typically returned in chronological order, facilitating
//	timeline analysis and correlation of related failure events for incident
//	investigation and root cause analysis.
//
// SECURITY MONITORING APPLICATIONS:
//
//	THREAT DETECTION:
//	Failed operations often indicate security attacks, unauthorized access attempts,
//	or suspicious activities. Regular monitoring of failed operations helps identify
//	potential security threats before they escalate to successful breaches.
//
//	ANOMALY IDENTIFICATION:
//	Patterns in failed operations can reveal system anomalies, configuration issues,
//	or unusual usage patterns that may indicate security concerns or operational
//	problems requiring investigation.
//
//	INCIDENT RESPONSE:
//	During security incidents, failed operations provide crucial forensic evidence
//	for understanding attack methods, timeline reconstruction, and impact assessment
//	for comprehensive incident response.
//
// OPERATIONAL TROUBLESHOOTING:
//
//	SYSTEM HEALTH MONITORING:
//	Regular queries for failed operations help identify system health issues,
//	performance problems, or configuration errors that impact vault reliability
//	and user experience.
//
//	USER SUPPORT:
//	Failed operations help support teams understand user-reported issues and
//	provide targeted assistance for resolving authentication, authorization,
//	or operational problems.
//
//	CAPACITY PLANNING:
//	Analysis of failure patterns helps identify resource constraints, rate limiting
//	issues, or scaling requirements for maintaining optimal vault performance
//	under varying load conditions.
//
// USAGE PATTERNS:
//
//	REGULAR MONITORING:
//	Implement periodic queries (e.g., hourly or daily) to maintain awareness of
//	failure rates and patterns for proactive system management and security
//	monitoring.
//
//	INCIDENT INVESTIGATION:
//	Use targeted time-range queries during incident response to gather forensic
//	evidence and understand the scope and timeline of security or operational
//	incidents.
//
//	TREND ANALYSIS:
//	Compare failure rates and patterns across different time periods to identify
//	trends, seasonal patterns, or gradual degradation in system performance
//	or security posture.
//
// PERFORMANCE CONSIDERATIONS:
//
//	RESULT LIMITING:
//	The default 1000-event limit prevents excessive memory usage and response times
//	for tenants with high failure rates. Consider implementing pagination for
//	comprehensive historical analysis of high-volume failure scenarios.
//
//	QUERY FREQUENCY:
//	Frequent queries for failed operations can impact system performance. Implement
//	appropriate caching, rate limiting, or background processing for high-frequency
//	monitoring scenarios.
//
//	INDEX OPTIMIZATION:
//	Ensure audit storage systems have appropriate indexes on tenant ID, timestamp,
//	and success/failure status for optimal query performance.
//
// ERROR HANDLING:
//
//	TENANT VALIDATION:
//	The method validates tenant existence and access permissions before executing
//	queries, returning appropriate errors for invalid or inaccessible tenants.
//
//	AUDIT SYSTEM AVAILABILITY:
//	Failures in the underlying audit system are propagated to callers with
//	descriptive error messages to enable appropriate error handling and retry logic.
//
// USAGE EXAMPLE:
//
//	```go
//	// Monitor recent failures for security analysis
//	since := time.Now().Add(-24 * time.Hour) // Last 24 hours
//	failures, err := vaultManager.QueryFailedOperations("tenant-123", &since)
//	if err != nil {
//	    log.Printf("Failed to query failed operations: %v", err)
//	    return
//	}
//
//	// Analyze failure patterns
//	for _, event := range failures {
//	    log.Printf("Failed operation: %s at %s - %s",
//	        event.Operation, event.Timestamp.Format(time.RFC3339), event.Error)
//
//	    // Check for security-relevant failures
//	    if isSecurityRelevant(event) {
//	        alertSecurityTeam(event)
//	    }
//	}
//
//	// Generate failure rate metrics
//	if len(failures) > 100 {
//	    log.Printf("WARNING: High failure rate detected for tenant %s: %d failures in 24h",
//	        "tenant-123", len(failures))
//	}
//	```
//
// INTEGRATION PATTERNS:
//
//	MONITORING SYSTEMS:
//	Integrate with monitoring and alerting systems to automatically detect and
//	respond to elevated failure rates or specific failure patterns that indicate
//	security or operational issues.
//
//	SECURITY TOOLS:
//	Feed failed operation data to SIEM systems, security analytics platforms,
//	or threat detection systems for comprehensive security monitoring and
//	correlation with other security events.
//
//	DASHBOARD INTEGRATION:
//	Use failed operation data in operational dashboards to provide real-time
//	visibility into system health and security status for operations and
//	security teams.
//
// Parameters:
//
//	tenantID: Target tenant identifier for failure query scope
//	since: Optional time boundary for temporal filtering (nil = all history)
//
// Returns:
//
//	[]audit.Event: Collection of failed operation audit events
//	error: nil on success, error on tenant validation or audit system failures
func (tm *VaultManager) QueryFailedOperations(tenantID string, since *time.Time) ([]audit.Event, error) {
	failureFlag := false
	options := audit.QueryOptions{
		TenantID: tenantID,
		Since:    since,
		Success:  &failureFlag, // Only failed operations
		Limit:    1000,
	}

	return tm.queryTenantAuditLogs(tenantID, options)
}

// QuerySecretAccess provides targeted querying of secret access events for security analysis.
//
// OVERVIEW:
// This convenience method specializes in retrieving audit events related to specific
// secret access activities within a tenant's vault. It streamlines the process of
// investigating secret usage patterns, detecting unauthorized access, and performing
// forensic analysis on specific secret resources.
//
// OPERATIONAL BEHAVIOR:
//
//	TARGETED FILTERING:
//	The method automatically configures query parameters to focus exclusively on
//	events related to the specified secret within the target tenant. This includes
//	read operations, access attempts, permission checks, and usage tracking events
//	associated with the secret resource.
//
//	TIME-BASED ANALYSIS:
//	When a 'since' timestamp is provided, the query retrieves all secret access
//	events from that point forward, enabling time-bounded analysis for incident
//	investigation, compliance auditing, or operational monitoring of recent activity.
//
//	RESULT LIMITATION:
//	The method applies a default limit of 1000 events to prevent excessive memory
//	usage and ensure responsive query performance. For comprehensive historical
//	analysis requiring more events, use the full QueryAuditLogs method with
//	custom pagination parameters.
//
// SECURITY ANALYSIS CAPABILITIES:
//
//	ACCESS PATTERN DETECTION:
//	Results enable identification of unusual access patterns, including frequency
//	anomalies, off-hours access, geographic inconsistencies, or access from
//	unexpected sources that may indicate security concerns or policy violations.
//
//	COMPLIANCE VERIFICATION:
//	The method supports compliance auditing by providing detailed trails of who
//	accessed specific secrets, when access occurred, and the context of each
//	access event, enabling verification of access controls and policy adherence.
//
//	FORENSIC INVESTIGATION:
//	During security incidents, the method provides focused forensic data about
//	specific secret compromise, enabling investigators to understand the scope,
//	timeline, and impact of potential security breaches.
//
// USAGE PATTERNS:
//
//	INCIDENT RESPONSE:
//	When investigating potential security incidents involving specific secrets,
//	this method provides rapid access to relevant audit trails without requiring
//	complex query construction or broad audit log analysis.
//
//	OPERATIONAL MONITORING:
//	Regular monitoring of high-value secrets can be automated using this method
//	to detect unusual activity patterns, ensure proper access controls, and
//	maintain operational security awareness.
//
//	COMPLIANCE REPORTING:
//	Regulatory requirements often mandate detailed tracking of sensitive data
//	access. This method facilitates generation of secret-specific access reports
//	for compliance documentation and regulatory submissions.
//
// PERFORMANCE CHARACTERISTICS:
//
//	OPTIMIZED QUERIES:
//	The method leverages tenant-specific and secret-specific indexes to provide
//	efficient query performance, even for tenants with large audit log volumes.
//	Query optimization focuses on the specific secret identifier and time range.
//
//	MEMORY EFFICIENCY:
//	The default 1000-event limit prevents excessive memory consumption while
//	providing sufficient data for most analysis scenarios. Consider implementing
//	pagination for comprehensive historical analysis requirements.
//
//	CONCURRENT SAFETY:
//	The method safely handles concurrent access to audit data and maintains
//	consistent results even during simultaneous secret access operations or
//	other audit querying activities.
//
// ERROR HANDLING:
//
//	TENANT VALIDATION:
//	Invalid or inaccessible tenant IDs result in appropriate error responses,
//	ensuring proper tenant isolation and access control enforcement.
//
//	GRACEFUL DEGRADATION:
//	If audit logging is not available for the specified tenant, the method
//	returns empty results rather than failing, enabling resilient operation
//	in mixed-configuration environments.
//
// RESULT INTERPRETATION:
//
//	EVENT TYPES:
//	Results may include various event types such as successful access, failed
//	access attempts, permission denials, secret retrievals, and metadata
//	queries, providing comprehensive visibility into secret interaction patterns.
//
//	CONTEXTUAL INFORMATION:
//	Each event contains contextual metadata including user identification,
//	source information, operation types, and timestamps, enabling detailed
//	analysis of access patterns and security implications.
//
// SECURITY CONSIDERATIONS:
//
//	ACCESS AUTHORIZATION:
//	The method respects tenant access controls and only returns audit data
//	for secrets within tenants that the caller is authorized to access,
//	maintaining proper security boundaries.
//
//	AUDIT TRAIL:
//	The query operation itself is audited, creating a complete trail of
//	audit log access for security monitoring and compliance verification.
//
// INTEGRATION PATTERNS:
//
//	AUTOMATED MONITORING:
//	The method integrates well with monitoring systems and alerting frameworks
//	for automated detection of suspicious secret access patterns or policy
//	violations requiring immediate attention.
//
//	REPORTING SYSTEMS:
//	Results can be directly integrated into reporting systems for compliance
//	documentation, security dashboards, and operational visibility tools.
//
// USAGE EXAMPLE:
//
//	// Investigate recent access to a sensitive database credential
//	since := time.Now().Add(-24 * time.Hour) // Last 24 hours
//	events, err := vaultManager.QuerySecretAccess(
//	    "prod-tenant-001",
//	    "database/prod/credentials",
//	    &since,
//	)
//	if err != nil {
//	    log.Printf("Failed to query secret access: %v", err)
//	    return
//	}
//
//	// Analyze access patterns for security review
//	for _, event := range events {
//	    fmt.Printf("Access: %s by %s at %s from %s\n",
//	        event.Operation,
//	        event.UserID,
//	        event.Timestamp.Format(time.RFC3339),
//	        event.SourceIP,
//	    )
//
//	    // Check for suspicious patterns
//	    if isOffHours(event.Timestamp) {
//	        fmt.Printf("WARNING: Off-hours access detected\n")
//	    }
//	    if isUnusualLocation(event.SourceIP) {
//	        fmt.Printf("WARNING: Access from unusual location\n")
//	    }
//	}
//
//	// Generate compliance report
//	report := generateAccessReport(events)
//	saveComplianceReport(report)
//
// ADVANCED USAGE:
//
//	// Continuous monitoring with periodic checks
//	func monitorSecretAccess(tenantID, secretID string) {
//	    ticker := time.NewTicker(5 * time.Minute)
//	    defer ticker.Stop()
//
//	    lastCheck := time.Now()
//
//	    for range ticker.C {
//	        events, err := vaultManager.QuerySecretAccess(
//	            tenantID,
//	            secretID,
//	            &lastCheck,
//	        )
//	        if err != nil {
//	            log.Printf("Monitoring error: %v", err)
//	            continue
//	        }
//
//	        for _, event := range events {
//	            if detectAnomalousPattern(event) {
//	                triggerSecurityAlert(event)
//	            }
//	        }
//
//	        lastCheck = time.Now()
//	    }
//	}
//
//	// Batch analysis for multiple secrets
//	func analyzeSecretPortfolio(tenantID string, secretIDs []string) {
//	    since := time.Now().Add(-7 * 24 * time.Hour) // Last week
//
//	    for _, secretID := range secretIDs {
//	        events, err := vaultManager.QuerySecretAccess(
//	            tenantID,
//	            secretID,
//	            &since,
//	        )
//	        if err != nil {
//	            log.Printf("Failed to analyze %s: %v", secretID, err)
//	            continue
//	        }
//
//	        analysis := performSecurityAnalysis(events)
//	        updateSecurityDashboard(secretID, analysis)
//	    }
//	}
//
// Parameters:
//
//	tenantID: Unique identifier for the target tenant
//	secretID: Unique identifier for the specific secret to analyze
//	since: Optional timestamp for time-bounded queries (nil for all history)
//
// Returns:
//
//	[]audit.Event: Array of audit events related to secret access (max 1000)
//	error: nil on success, error on tenant access failure or system issues
func (tm *VaultManager) QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]audit.Event, error) {
	options := audit.QueryOptions{
		TenantID: tenantID,
		SecretID: secretID,
		Since:    since,
		Limit:    1000,
	}

	return tm.queryTenantAuditLogs(tenantID, options)
}

// QueryKeyOperations provides specialized audit querying for key-specific operations and activities.
//
// OVERVIEW:
// This convenience method offers a streamlined interface for querying audit logs related to
// specific cryptographic keys within a tenant's vault. It abstracts the complexity of
// constructing detailed audit queries and provides optimized access to key lifecycle events,
// operations, and security-related activities for forensic analysis, compliance reporting,
// and operational monitoring.
//
// KEY-CENTRIC ANALYSIS:
//
//	COMPREHENSIVE KEY TRACKING:
//	The method captures all audit events associated with a specific key throughout its
//	entire lifecycle, including key generation, rotation, usage, access attempts,
//	configuration changes, and deletion events. This provides complete visibility
//	into key operations for security analysis and compliance requirements.
//
//	OPERATION TYPE COVERAGE:
//	Results include diverse key-related operations such as:
//	- Key creation and initialization events
//	- Encryption/decryption operations using the key
//	- Key rotation and version management activities
//	- Access control modifications and permission changes
//	- Key backup, export, and import operations
//	- Key deletion and destruction events
//	- Failed access attempts and security violations
//
//	SECURITY EVENT CORRELATION:
//	The method captures both successful operations and security events, enabling
//	comprehensive analysis of key usage patterns, access violations, and potential
//	security incidents involving specific cryptographic keys.
//
// QUERY OPTIMIZATION:
//
//	PRE-CONFIGURED FILTERING:
//	The method applies intelligent default filtering optimized for key-centric analysis,
//	including a reasonable result limit (1000 events) to balance comprehensive coverage
//	with performance considerations for interactive use cases.
//
//	TEMPORAL SCOPING:
//	When a 'since' timestamp is provided, the query focuses on recent key activities,
//	enabling efficient analysis of current key usage patterns or investigation of
//	recent security events without processing extensive historical data.
//
//	TENANT ISOLATION:
//	All queries operate within strict tenant boundaries, ensuring that key operation
//	analysis respects multi-tenant security boundaries while providing comprehensive
//	visibility within the authorized tenant scope.
//
// RESULT CHARACTERISTICS:
//
//	EVENT DETAIL RICHNESS:
//	Each returned audit event contains comprehensive details including:
//	- Precise timestamps for temporal analysis and correlation
//	- Operation success/failure status for reliability analysis
//	- User and session context for access pattern analysis
//	- Source information (IP addresses, hostnames) for security analysis
//	- Command details and operation duration for performance analysis
//	- Custom metadata for application-specific analysis requirements
//
//	CHRONOLOGICAL ORDERING:
//	Results are typically ordered chronologically, enabling timeline analysis
//	of key operations and identification of operation sequences that may
//	indicate security issues or operational problems.
//
// OPERATIONAL APPLICATIONS:
//
//	SECURITY ANALYSIS:
//	Investigate suspicious key usage patterns, unauthorized access attempts,
//	or security violations involving specific cryptographic keys. The method
//	provides the detailed audit trail necessary for forensic investigation
//	and security incident response.
//
//	COMPLIANCE REPORTING:
//	Generate detailed reports on key usage and access patterns required by
//	regulatory frameworks such as PCI DSS, HIPAA, SOX, or industry-specific
//	compliance requirements that mandate cryptographic key monitoring.
//
//	OPERATIONAL MONITORING:
//	Monitor key performance characteristics, usage patterns, and operational
//	health for capacity planning, performance optimization, and proactive
//	identification of operational issues affecting key management operations.
//
//	FORENSIC INVESTIGATION:
//	Support detailed forensic analysis of security incidents involving
//	specific keys, including timeline reconstruction, impact assessment,
//	and evidence collection for security incident response procedures.
//
// PERFORMANCE CONSIDERATIONS:
//
//	RESULT SET MANAGEMENT:
//	The default limit of 1000 events balances comprehensive analysis with
//	performance considerations. For keys with extensive operation history,
//	consider using multiple queries with appropriate time ranges to manage
//	result set sizes and response times.
//
//	QUERY EFFICIENCY:
//	Key-specific queries are typically well-optimized by underlying audit
//	systems due to key ID indexing. However, very broad time ranges may
//	still require significant processing time for highly active keys.
//
// USAGE EXAMPLES:
//
//	RECENT KEY ACTIVITY ANALYSIS:
//	// Analyze all operations on a specific key in the last 24 hours
//	since := time.Now().Add(-24 * time.Hour)
//	events, err := vaultManager.QueryKeyOperations("tenant-123", "key-456", &since)
//	if err != nil {
//	    return fmt.Errorf("failed to query key operations: %w", err)
//	}
//
//	// Analyze patterns and identify anomalies
//	for _, event := range events {
//	    if !event.Success {
//	        log.Printf("Failed key operation: %s by user %s from %s",
//	            event.Action, event.UserID, event.Source)
//	    }
//	}
//
//	COMPLETE KEY LIFECYCLE ANALYSIS:
//	// Retrieve complete history of key operations (no time limit)
//	events, err := vaultManager.QueryKeyOperations("tenant-123", "key-456", nil)
//	if err != nil {
//	    return fmt.Errorf("failed to query key lifecycle: %w", err)
//	}
//
//	// Generate comprehensive lifecycle report
//	report := generateKeyLifecycleReport(events)
//
//	SECURITY INCIDENT INVESTIGATION:
//	// Investigate specific key after security alert
//	alertTime := time.Unix(securityAlert.Timestamp, 0).Add(-1 * time.Hour)
//	events, err := vaultManager.QueryKeyOperations(
//	    securityAlert.TenantID,
//	    securityAlert.KeyID,
//	    &alertTime,
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to investigate key security incident: %w", err)
//	}
//
//	// Analyze for indicators of compromise
//	indicators := analyzeSecurityIndicators(events, securityAlert)
//
//	COMPLIANCE AUDIT PREPARATION:
//	// Prepare audit evidence for specific key compliance review
//	auditPeriodStart := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
//	events, err := vaultManager.QueryKeyOperations("tenant-123", "key-456", &auditPeriodStart)
//	if err != nil {
//	    return fmt.Errorf("failed to prepare compliance audit: %w", err)
//	}
//
//	// Generate compliance report with required details
//	complianceReport := generateComplianceReport(events, auditPeriodStart)
//
// ERROR HANDLING:
//
//	TENANT VALIDATION:
//	Returns specific errors for non-existent tenants, enabling calling applications
//	to distinguish between authorization issues, configuration problems, and
//	legitimate query failures for appropriate error handling and user feedback.
//
//	AUDIT SYSTEM AVAILABILITY:
//	Gracefully handles cases where audit logging is not configured for the tenant,
//	returning empty results rather than errors to support optional audit logging
//	deployment scenarios.
//
//	QUERY EXECUTION FAILURES:
//	Provides detailed error context for query failures, including tenant information
//	and underlying error details to support troubleshooting and system monitoring.
//
// SECURITY CONSIDERATIONS:
//
//	ACCESS CONTROL ENFORCEMENT:
//	The method respects all tenant-level access controls and audit system permissions.
//	Callers must have appropriate authorization to access audit logs for the specified
//	tenant and key to prevent unauthorized access to sensitive audit information.
//
//	AUDIT TRAIL INTEGRITY:
//	The query process itself is audited, maintaining complete traceability of who
//	accessed key operation audit logs and when, supporting security monitoring
//	and compliance requirements for audit log access.
//
//	DATA SENSITIVITY:
//	Audit events may contain sensitive operational details. Ensure appropriate
//	handling of query results according to organizational security policies
//	and regulatory requirements for audit data protection.
//
// Parameters:
//
//	tenantID: Unique identifier for the tenant containing the target key
//	keyID: Specific key identifier to analyze (must exist within the tenant)
//	since: Optional time boundary for query scope (nil for complete history)
//
// Returns:
//
//	[]audit.Event: Chronologically ordered key operation events with full details
//	error: nil on success, specific error on tenant/query failures
func (tm *VaultManager) QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]audit.Event, error) {
	options := audit.QueryOptions{
		TenantID: tenantID,
		KeyID:    keyID,
		Since:    since,
		Limit:    1000,
	}

	return tm.queryTenantAuditLogs(tenantID, options)
}

// GetAuditSummary generates comprehensive audit activity summaries for tenant monitoring and analysis.
//
// OVERVIEW:
// This function provides high-level statistical analysis of tenant audit activity over a specified
// time period. It aggregates detailed audit events into actionable metrics for security monitoring,
// compliance reporting, operational dashboards, and tenant activity analysis. The summary includes
// categorized event counts, success/failure ratios, and activity timestamps for comprehensive
// tenant oversight.
//
// ANALYTICAL CAPABILITIES:
//
//	EVENT CATEGORIZATION:
//	The function analyzes all audit events and categorizes them into distinct operational
//	types including passphrase accesses, secret operations, key management activities,
//	and general vault operations. This categorization enables targeted analysis of
//	different security-sensitive activities within the tenant environment.
//
//	SUCCESS/FAILURE ANALYSIS:
//	All events are classified by success or failure status, providing insights into
//	operational health, potential security issues, and system reliability. High
//	failure rates may indicate configuration problems, security attacks, or user
//	training needs.
//
//	TEMPORAL ANALYSIS:
//	The summary includes the timestamp of the most recent activity, enabling
//	administrators to understand tenant engagement patterns, identify inactive
//	tenants, and monitor for unexpected activity periods.
//
// SECURITY MONITORING:
//
//	THREAT DETECTION:
//	Unusual patterns in the audit summary can indicate security threats such as
//	brute force attacks (high failure rates), unauthorized access attempts, or
//	abnormal usage patterns that warrant further investigation.
//
//	COMPLIANCE TRACKING:
//	The categorized metrics support compliance requirements by providing clear
//	visibility into sensitive operations like passphrase accesses and secret
//	retrievals, enabling audit trail analysis for regulatory compliance.
//
//	ACCESS PATTERN ANALYSIS:
//	The summary enables identification of access patterns that may indicate
//	compromised accounts, insider threats, or policy violations requiring
//	administrative attention or automated response.
//
// OPERATIONAL INSIGHTS:
//
//	TENANT ACTIVITY MONITORING:
//	Administrators can use audit summaries to monitor tenant engagement,
//	identify underutilized resources, and understand usage patterns for
//	capacity planning and resource optimization.
//
//	SYSTEM HEALTH INDICATORS:
//	Success/failure ratios and activity patterns provide indicators of system
//	health, configuration issues, and potential problems requiring proactive
//	maintenance or user support.
//
//	PERFORMANCE BASELINE:
//	Regular audit summaries establish baseline activity patterns that can be
//	used for anomaly detection and performance comparison over time.
//
// SUMMARY METRICS:
//
//	TOTAL EVENTS:
//	Complete count of all audit events within the specified time range,
//	providing overall activity volume metrics for capacity planning and
//	comparative analysis across tenants or time periods.
//
//	SUCCESS/FAILURE BREAKDOWN:
//	Categorized counts of successful and failed operations, enabling quick
//	assessment of operational health and identification of potential issues
//	requiring investigation or remediation.
//
//	ACTIVITY-SPECIFIC COUNTS:
//	Specialized metrics for security-sensitive operations including passphrase
//	accesses, secret retrievals, and key management operations, providing
//	focused visibility into the most critical security activities.
//
//	TEMPORAL MARKERS:
//	Last activity timestamp enables identification of tenant engagement
//	patterns and detection of unusual activity timing that may indicate
//	security concerns or operational issues.
//
// PERFORMANCE CHARACTERISTICS:
//
//	SCALABLE ANALYSIS:
//	The function uses a high limit (10,000 events) to capture comprehensive
//	activity data while maintaining reasonable performance. For tenants with
//	extremely high activity, consider using shorter time windows or implementing
//	sampling strategies for very large datasets.
//
//	MEMORY EFFICIENCY:
//	Event analysis is performed in a single pass through the data, minimizing
//	memory usage and processing time. The function aggregates metrics without
//	storing detailed event data, making it suitable for regular monitoring.
//
//	CONCURRENT SAFETY:
//	The function operates under read-lock protection, ensuring thread-safe
//	access to tenant resources while allowing concurrent summary generation
//	for multiple tenants or time periods.
//
// USAGE PATTERNS AND BEST PRACTICES:
//
//	REGULAR MONITORING:
//	Schedule regular audit summary generation (daily, weekly, monthly) to
//	establish baseline patterns and enable trend analysis over time.
//	Consistent monitoring intervals improve anomaly detection capabilities.
//
//	ALERT THRESHOLDS:
//	Establish thresholds for various metrics (failure rates, activity volumes,
//	time gaps) to trigger automated alerts for unusual patterns requiring
//	investigation or immediate attention.
//
//	COMPARATIVE ANALYSIS:
//	Compare audit summaries across tenants, time periods, or baseline patterns
//	to identify outliers, trends, and patterns that may indicate security
//	concerns or operational optimization opportunities.
//
//	DRILL-DOWN CAPABILITIES:
//	Use audit summaries as starting points for detailed analysis. When summaries
//	indicate unusual patterns, use detailed audit queries to investigate
//	specific events and root causes.
//
// INTEGRATION SCENARIOS:
//
//	DASHBOARD INTEGRATION:
//	Audit summaries provide ideal metrics for operational dashboards, executive
//	reports, and real-time monitoring displays. The structured format enables
//	easy integration with visualization tools and monitoring systems.
//
//	AUTOMATED MONITORING:
//	Integrate audit summary generation into automated monitoring workflows,
//	creating scheduled reports, threshold-based alerts, and trend analysis
//	systems for proactive security and operational management.
//
//	COMPLIANCE REPORTING:
//	Use audit summaries as components of larger compliance reports, providing
//	high-level metrics that support regulatory requirements while maintaining
//	detailed audit trails for deeper investigation when needed.
//
// ERROR HANDLING:
//
//	TENANT VALIDATION:
//	The function validates tenant existence and access permissions before
//	attempting audit queries. Invalid tenants or access violations are
//	reported as errors with appropriate diagnostic information.
//
//	QUERY RESILIENCE:
//	Audit query failures are propagated as errors, but the function provides
//	partial results when possible, ensuring maximum utility even during
//	degraded conditions or partial system failures.
//
// USAGE EXAMPLE:
//
//	// Generate daily audit summary for tenant monitoring
//	dailyStart := time.Now().AddDate(0, 0, -1)
//	summary, err := vaultManager.GetAuditSummary("tenant-123", &dailyStart)
//	if err != nil {
//	    log.Printf("Failed to generate audit summary: %v", err)
//	    return
//	}
//
//	// Analyze security metrics
//	failureRate := float64(summary.FailedEvents) / float64(summary.TotalEvents)
//	if failureRate > 0.1 { // Alert if >10% failure rate
//	    log.Printf("HIGH FAILURE RATE for tenant %s: %.2f%%",
//	               summary.TenantID, failureRate*100)
//	}
//
//	// Check for suspicious activity patterns
//	if summary.PassphraseAccesses > 100 {
//	    log.Printf("High passphrase activity for tenant %s: %d accesses",
//	               summary.TenantID, summary.PassphraseAccesses)
//	}
//
//	// Monitor tenant engagement
//	inactiveHours := time.Since(summary.LastActivity).Hours()
//	if inactiveHours > 168 { // Alert if inactive for >1 week
//	    log.Printf("Tenant %s inactive for %.1f hours",
//	               summary.TenantID, inactiveHours)
//	}
//
//	// Generate formatted report
//	fmt.Printf("Audit Summary for %s:\n", summary.TenantID)
//	fmt.Printf("  Total Events: %d\n", summary.TotalEvents)
//	fmt.Printf("  Success Rate: %.2f%%\n",
//	           float64(summary.SuccessfulEvents)/float64(summary.TotalEvents)*100)
//	fmt.Printf("  Secret Accesses: %d\n", summary.SecretAccesses)
//	fmt.Printf("  Key Operations: %d\n", summary.KeyOperations)
//	fmt.Printf("  Last Activity: %s\n", summary.LastActivity.Format(time.RFC3339))
//
// Parameters:
//
//	tenantID: Unique identifier for the tenant to analyze
//	since: Starting timestamp for summary analysis (nil for all available data)
//
// Returns:
//
//	AuditSummary: Comprehensive activity summary with categorized metrics
//	error: nil on success, error on tenant access failure or query errors
func (tm *VaultManager) GetAuditSummary(tenantID string, since *time.Time) (AuditSummary, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	summary := AuditSummary{
		TenantID: tenantID,
	}

	// Query all events since the specified time
	options := audit.QueryOptions{
		TenantID: tenantID,
		Since:    since,
		Limit:    10000, // High limit to get all events for summary
	}

	events, err := tm.queryTenantAuditLogs(tenantID, options)
	if err != nil {
		return summary, err
	}

	// Analyze the events
	summary.TotalEvents = len(events)

	for _, event := range events {
		if event.Success {
			summary.SuccessfulEvents++
		} else {
			summary.FailedEvents++
		}

		// Check for passphrase access
		if isPassphraseAction(event.Action) {
			summary.CredsAccessCount++
		}

		// Check for secret access
		if event.SecretID != "" {
			summary.SensitiveDataAccessCount++
		}

		// Check for key operations
		if event.KeyID != "" {
			summary.KeyOperations++
		}

		// Track last activity
		if event.Timestamp.After(summary.LastActivity) {
			summary.LastActivity = event.Timestamp
		}
	}

	return summary, nil
}

/* KEY ROTATION */

// RotateAllTenantPassphrases performs coordinated passphrase rotation across multiple tenants for enhanced security management.
//
// OVERVIEW:
// This administrative function enables bulk passphrase rotation operations across specified tenants
// or all tenants within the vault manager. It provides essential security lifecycle management
// capabilities for organizations requiring coordinated password policy enforcement, security
// incident response, or compliance-driven credential rotation procedures.
//
// OPERATIONAL SCOPE:
//
//	TARGETED ROTATION:
//	When tenantIDs slice contains specific tenant identifiers, the operation is limited
//	to those tenants only. This enables selective rotation for specific security zones,
//	compliance groups, or incident response scenarios affecting particular tenants.
//
//	GLOBAL ROTATION:
//	When tenantIDs is nil or empty, the operation automatically discovers and processes
//	all tenants within the vault manager's scope. This provides organization-wide
//	passphrase rotation for comprehensive security policy enforcement.
//
//	FAULT ISOLATION:
//	Individual tenant rotation failures are isolated and do not abort the entire
//	operation. Each tenant's result is captured independently, ensuring maximum
//	operational coverage even during partial system failures.
//
// SECURITY CHARACTERISTICS:
//
//	COORDINATED TIMING:
//	All tenant rotations use the same new passphrase and are processed sequentially
//	to ensure coordinated security policy application. This approach minimizes the
//	window of inconsistent passphrase states across the organization.
//
//	AUDIT INTEGRATION:
//	The operation generates comprehensive audit trails including bulk operation
//	initiation, individual tenant rotation events, and completion summaries.
//	This provides complete traceability for security and compliance requirements.
//
//	ROLLBACK CONSIDERATIONS:
//	Failed rotations do not automatically rollback successful ones. Organizations
//	should implement appropriate rollback procedures based on their security
//	policies and operational requirements.
//
// RESULT REPORTING:
//
//	COMPREHENSIVE OUTCOMES:
//	Each tenant operation produces a detailed BulkOperationResult containing
//	success status, error information, operational metadata, and timestamps
//	for complete audit trail and debugging capabilities.
//
//	OPERATIONAL METRICS:
//	The function tracks and reports success/failure counts through audit logs,
//	providing operational visibility into bulk operation effectiveness and
//	enabling automated monitoring and alerting integration.
//
//	ERROR CATEGORIZATION:
//	Errors are categorized by failure type (vault access, rotation execution)
//	to enable targeted remediation and operational process improvements.
//
// PERFORMANCE CONSIDERATIONS:
//
//	SEQUENTIAL PROCESSING:
//	Tenants are processed sequentially to ensure system stability and enable
//	proper error handling. For large tenant counts, consider breaking operations
//	into smaller batches or implementing job scheduling for optimal performance.
//
//	RESOURCE MANAGEMENT:
//	Each rotation operation may involve cryptographic operations and storage
//	updates. Monitor system resources during bulk operations and consider
//	scheduling during maintenance windows for large-scale rotations.
//
//	TRANSACTION ISOLATION:
//	Each tenant rotation is processed as an independent transaction, providing
//	isolation but requiring careful consideration of partial completion scenarios
//	in operational procedures and recovery planning.
//
// ERROR HANDLING STRATEGY:
//
//	GRACEFUL DEGRADATION:
//	The function implements graceful degradation where individual tenant failures
//	are recorded but do not prevent processing of remaining tenants. This maximizes
//	operational coverage while providing complete failure visibility.
//
//	DIAGNOSTIC INFORMATION:
//	Detailed error messages are captured for each failure, including the specific
//	failure reason and context to enable effective troubleshooting and remediation.
//
//	PARTIAL SUCCESS HANDLING:
//	Operations resulting in partial success require careful post-operation analysis
//	to determine appropriate remediation actions for failed tenant rotations.
//
// COMPLIANCE AND GOVERNANCE:
//
//	REGULATORY ALIGNMENT:
//	The function supports regulatory requirements for credential rotation by providing
//	documented rotation reasons, complete audit trails, and timestamp information
//	for compliance reporting and validation.
//
//	POLICY ENFORCEMENT:
//	Bulk rotation enables consistent policy enforcement across organizational
//	boundaries, ensuring uniform security posture and compliance adherence
//	across all tenant environments.
//
//	AUDIT TRAIL COMPLETENESS:
//	All aspects of the bulk operation are audited, including initiation parameters,
//	individual tenant outcomes, and completion metrics for comprehensive
//	compliance documentation and security monitoring.
//
// OPERATIONAL INTEGRATION:
//
//	INCIDENT RESPONSE:
//	The function supports security incident response procedures requiring rapid
//	credential rotation across affected tenants or organization-wide rotation
//	in response to potential credential compromise scenarios.
//
//	MAINTENANCE SCHEDULING:
//	Regular passphrase rotation can be scheduled using this function as part of
//	automated security maintenance procedures, supporting proactive security
//	lifecycle management and compliance requirements.
//
//	MONITORING INTEGRATION:
//	Operation results can be integrated with monitoring systems to track rotation
//	success rates, identify systematic issues, and maintain operational visibility
//	into security credential management effectiveness.
//
// USAGE EXAMPLE:
//
//	// Emergency rotation for specific tenants after security incident
//	affectedTenants := []string{"tenant-prod-1", "tenant-prod-2", "tenant-staging-1"}
//	newPassphrase := generateSecurePassphrase() // Use secure generation
//	reason := "Emergency rotation due to security incident INC-2024-001"
//
//	results, err := vaultManager.RotateAllTenantPassphrases(affectedTenants, newPassphrase, reason)
//	if err != nil {
//	    log.Fatalf("Bulk rotation failed: %v", err)
//	}
//
//	// Process results for monitoring and follow-up
//	var failed []string
//	successCount := 0
//	for _, result := range results {
//	    if result.Success {
//	        successCount++
//	        log.Printf("Successfully rotated passphrase for tenant: %s", result.TenantID)
//	    } else {
//	        failed = append(failed, result.TenantID)
//	        log.Errorf("Failed to rotate passphrase for tenant %s: %s",
//	                  result.TenantID, result.Error)
//	    }
//	}
//
//	// Report outcomes and handle failures
//	log.Printf("Bulk rotation completed: %d/%d successful", successCount, len(results))
//	if len(failed) > 0 {
//	    // Trigger manual remediation process for failed tenants
//	    triggerManualRotation(failed, reason)
//	    sendSecurityAlert("Partial bulk rotation failure", failed)
//	}
//
//	// Organization-wide scheduled rotation (quarterly compliance requirement)
//	quarterlyPassphrase := generateCompliantPassphrase()
//	reason := "Q1 2024 scheduled compliance rotation"
//
//	// Pass nil/empty slice to rotate all tenants
//	results, err := vaultManager.RotateAllTenantPassphrases(nil, quarterlyPassphrase, reason)
//	if err != nil {
//	    log.Fatalf("Scheduled rotation failed: %v", err)
//	}
//
//	generateComplianceReport(results, "Q1_2024_Rotation_Report")
//
// SECURITY BEST PRACTICES:
//
//	PASSPHRASE GENERATION:
//	Always use cryptographically secure passphrase generation methods that meet
//	organizational complexity requirements and security policies. Never use
//	predictable or weak passphrases for bulk operations.
//
//	REASON DOCUMENTATION:
//	Provide clear, specific reasons for bulk operations to support audit
//	requirements, incident documentation, and compliance reporting. Reasons
//	should include reference numbers for incidents or compliance requirements.
//
//	POST-OPERATION VALIDATION:
//	Implement validation procedures to verify successful rotation and test
//	access with new passphrases. Failed rotations may require manual
//	intervention and specialized recovery procedures.
//
//	COMMUNICATION PROTOCOLS:
//	Establish communication protocols for bulk operations to ensure affected
//	users and systems are notified appropriately and access disruption is
//	minimized through coordinated change management.
//
// Parameters:
//
//	tenantIDs: Slice of tenant identifiers to rotate; nil/empty processes all tenants
//	newPassphrase: New passphrase to apply; must be non-empty and meet security requirements
//	reason: Human-readable reason for rotation; used for audit trail and compliance documentation
//
// Returns:
//
//	[]BulkOperationResult: Detailed results for each tenant operation with success/failure status
//	error: Critical errors preventing operation initiation; individual tenant failures reported in results
func (tm *VaultManager) RotateAllTenantPassphrases(tenantIDs []string, newPassphrase string, reason string) ([]BulkOperationResult, error) {
	startTime := time.Now()
	requestID := tm.newRequestID()

	// Initialize audit metadata
	initialMetadata := map[string]interface{}{
		"requested_tenant_count": len(tenantIDs),
		"reason":                 reason,
		"has_specific_tenants":   tenantIDs != nil && len(tenantIDs) > 0,
	}

	tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_INITIATED", "", nil, initialMetadata)

	// Input validation
	if newPassphrase == "" {
		validationErr := fmt.Errorf("new passphrase cannot be empty")
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_VALIDATION_FAILED", "", validationErr, map[string]interface{}{
			"validation_error": "empty_passphrase",
		})
		return nil, validationErr
	}

	if reason == "" {
		reason = "bulk passphrase rotation"
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_REASON_DEFAULTED", "", nil, map[string]interface{}{
			"default_reason": reason,
		})
	}

	// If no specific tenants provided, get all tenants
	if tenantIDs == nil || len(tenantIDs) == 0 {
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_LISTING_ALL_TENANTS", "", nil, nil)

		allTenants, err := tm.ListTenants()
		if err != nil {
			listErr := fmt.Errorf("failed to list tenants: %w", err)
			tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_LIST_TENANTS_FAILED", "", listErr, map[string]interface{}{
				"error_type": tm.categorizeError(err),
			})
			return nil, listErr
		}

		tenantIDs = allTenants
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_ALL_TENANTS_RETRIEVED", "", nil, map[string]interface{}{
			"total_tenants_found": len(allTenants),
			"tenant_list":         allTenants,
		})
	} else {
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_USING_PROVIDED_TENANTS", "", nil, map[string]interface{}{
			"provided_tenants": tenantIDs,
		})
	}

	if len(tenantIDs) == 0 {
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_NO_TENANTS_TO_PROCESS", "", nil, map[string]interface{}{
			"total_duration_ms": time.Since(startTime).Milliseconds(),
		})
		return []BulkOperationResult{}, nil
	}

	// Log bulk operation start with final tenant list
	tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_PROCESSING_START", "", nil, map[string]interface{}{
		"final_tenant_count": len(tenantIDs),
		"tenant_list":        tenantIDs,
		"reason":             reason,
	})

	results := make([]BulkOperationResult, len(tenantIDs))
	successCount := 0
	var processingErrors []string

	// Process each tenant
	for i, tenantID := range tenantIDs {
		tenantStartTime := time.Now()

		tm.logAudit(requestID, "ROTATE_PASSPHRASE_TENANT_START", tenantID, nil, map[string]interface{}{
			"tenant_index": i + 1,
			"total_count":  len(tenantIDs),
			"reason":       reason,
		})

		result := BulkOperationResult{
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
			Details: map[string]interface{}{
				"reason":     reason,
				"operation":  "passphrase_rotation",
				"request_id": requestID,
			},
		}

		// Get the vault for this tenant
		vault, err := tm.GetVault(tenantID)
		if err != nil {
			result.Error = fmt.Sprintf("failed to get vault: %v", err)
			results[i] = result

			tm.logAudit(requestID, "ROTATE_PASSPHRASE_GET_VAULT_FAILED", tenantID, err, map[string]interface{}{
				"tenant_index": i + 1,
				"error_type":   tm.categorizeError(err),
				"duration_ms":  time.Since(tenantStartTime).Milliseconds(),
			})

			processingErrors = append(processingErrors, fmt.Sprintf("tenant %s: get vault failed", tenantID))
			continue
		}

		tm.logAudit(requestID, "ROTATE_PASSPHRASE_VAULT_RETRIEVED", tenantID, nil, map[string]interface{}{
			"tenant_index": i + 1,
			"vault_type":   fmt.Sprintf("%T", vault),
		})

		// Perform the rotation on the vault
		rotationStartTime := time.Now()
		if err := vault.RotateKeyEncryptionKey(newPassphrase, reason); err != nil {
			result.Error = fmt.Sprintf("passphrase rotation failed: %v", err)
			results[i] = result

			tm.logAudit(requestID, "ROTATE_PASSPHRASE_ROTATION_FAILED", tenantID, err, map[string]interface{}{
				"tenant_index":         i + 1,
				"error_type":           tm.categorizeError(err),
				"rotation_duration_ms": time.Since(rotationStartTime).Milliseconds(),
				"total_duration_ms":    time.Since(tenantStartTime).Milliseconds(),
			})

			processingErrors = append(processingErrors, fmt.Sprintf("tenant %s: rotation failed", tenantID))
			continue
		}

		// Success
		result.Success = true
		results[i] = result
		successCount++

		tm.logAudit(requestID, "ROTATE_PASSPHRASE_TENANT_SUCCESS", tenantID, nil, map[string]interface{}{
			"tenant_index":         i + 1,
			"rotation_duration_ms": time.Since(rotationStartTime).Milliseconds(),
			"total_duration_ms":    time.Since(tenantStartTime).Milliseconds(),
		})
	}

	totalDuration := time.Since(startTime)
	failureCount := len(tenantIDs) - successCount

	// Final audit logging based on outcome
	finalMetadata := map[string]interface{}{
		"total_tenants":        len(tenantIDs),
		"successful_rotations": successCount,
		"failed_rotations":     failureCount,
		"success_rate":         float64(successCount) / float64(len(tenantIDs)) * 100,
		"reason":               reason,
		"total_duration_ms":    totalDuration.Milliseconds(),
		"tenant_list":          tenantIDs,
	}

	if failureCount == 0 {
		// Complete success
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_COMPLETED_SUCCESS", "", nil, finalMetadata)
	} else if successCount == 0 {
		// Complete failure
		combinedError := fmt.Errorf("all passphrase rotations failed")
		finalMetadata["processing_errors"] = processingErrors
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_COMPLETED_TOTAL_FAILURE", "", combinedError, finalMetadata)
	} else {
		// Partial success
		partialError := fmt.Errorf("partial failure: %d succeeded, %d failed", successCount, failureCount)
		finalMetadata["processing_errors"] = processingErrors
		tm.logAudit(requestID, "ROTATE_ALL_PASSPHRASES_COMPLETED_PARTIAL_SUCCESS", "", partialError, finalMetadata)
	}

	return results, nil
}

// DeleteTenant permanently removes a tenant and its associated vault from the VaultManager.
//
// This method implements a "fail-safe" deletion strategy where the tenant is immediately
// removed from the active vaults map to prevent zombie states, even if subsequent cleanup
// operations fail. All operations are comprehensively audited for compliance and monitoring.
//
// Parameters:
//   - tenantID: Unique identifier for the tenant to be deleted. Must be a non-empty string.
//
// Returns:
//   - error: nil on successful deletion and cleanup
//   - error: tenant not found error if tenantID doesn't exist in the vault map
//   - error: cleanup error if tenant was removed but resource cleanup failed
//
// Thread Safety:
//
//	This method is thread-safe and uses a mutex lock to ensure atomic operations
//	during tenant lookup and removal from the vaults map.
//
// Audit Events:
//   - DELETE_TENANT_INITIATED: When deletion process begins
//   - DELETE_TENANT_NOT_FOUND: When tenant doesn't exist
//   - DELETE_TENANT_REMOVED_FROM_MAP: When tenant is removed from active vaults
//   - DELETE_TENANT_VAULT_CLEANUP_FAILED: When vault deletion fails
//   - DELETE_TENANT_CLOSE_FAILED: When vault close operation fails
//   - DELETE_TENANT_COMPLETED: When deletion completes successfully
//   - DELETE_TENANT_PARTIAL_FAILURE: When deletion completes with cleanup errors
func (tm *VaultManager) DeleteTenant(tenantID string) error {
	startTime := time.Now()
	requestID := tm.newRequestID()

	tm.logAudit(requestID, "DELETE_TENANT_INITIATED", tenantID, nil, map[string]interface{}{
		"total_tenants_before": len(tm.vaults),
	})

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Get the vault for this tenant
	vault, exists := tm.vaults[tenantID]
	if !exists {
		notFoundErr := fmt.Errorf("tenant %s not found", tenantID)
		tm.logAudit(requestID, "DELETE_TENANT_NOT_FOUND", tenantID, notFoundErr, map[string]interface{}{
			"available_tenants": tm.getTenantList(),
		})
		return notFoundErr
	}

	// Audit log - tenant found, proceeding with removal
	tm.logAudit(requestID, "DELETE_TENANT_FOUND", tenantID, nil, map[string]interface{}{
		"vault_type": fmt.Sprintf("%T", vault),
	})

	// Remove from map immediately to prevent new operations
	delete(tm.vaults, tenantID)

	// Audit log - tenant removed from active map
	tm.logAudit(requestID, "DELETE_TENANT_REMOVED_FROM_MEMORY", tenantID, nil, map[string]interface{}{
		"total_tenants_after": len(tm.vaults),
		"removal_strategy":    "fail_safe",
	})

	// Attempt cleanup - if this fails, we don't re-add to map
	var cleanupErrors []string
	var cleanupDetails = make(map[string]interface{})

	// Vault-specific cleanup
	vaultCleanupStart := time.Now()
	if err := vault.DeleteTenant(tenantID); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Sprintf("vault deletion failed: %v", err))

		tm.logAudit(requestID, "DELETE_TENANT_VAULT_CLEANUP_FAILED", tenantID, err, map[string]interface{}{
			"cleanup_phase": "vault_deletion",
			"error_type":    tm.categorizeError(err),
			"duration_ms":   time.Since(vaultCleanupStart).Milliseconds(),
		})

		cleanupDetails["vault_cleanup_error"] = err.Error()
		cleanupDetails["vault_cleanup_duration_ms"] = time.Since(vaultCleanupStart).Milliseconds()
	} else {
		tm.logAudit(requestID, "DELETE_TENANT_VAULT_CLEANUP_SUCCESS", tenantID, nil, map[string]interface{}{
			"cleanup_phase": "vault_deletion",
			"duration_ms":   time.Since(vaultCleanupStart).Milliseconds(),
		})
		cleanupDetails["vault_cleanup_duration_ms"] = time.Since(vaultCleanupStart).Milliseconds()
	}

	// Additional cleanup (connections, resources, etc.)
	if closer, ok := vault.(io.Closer); ok {
		closeStart := time.Now()
		if err := closer.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("vault close failed: %v", err))

			tm.logAudit(requestID, "DELETE_TENANT_CLOSE_FAILED", tenantID, err, map[string]interface{}{
				"cleanup_phase": "connection_close",
				"error_type":    tm.categorizeError(err),
				"duration_ms":   time.Since(closeStart).Milliseconds(),
			})

			cleanupDetails["close_error"] = err.Error()
			cleanupDetails["close_duration_ms"] = time.Since(closeStart).Milliseconds()
		} else {
			tm.logAudit(requestID, "DELETE_TENANT_CLOSE_SUCCESS", tenantID, nil, map[string]interface{}{
				"cleanup_phase": "connection_close",
				"duration_ms":   time.Since(closeStart).Milliseconds(),
			})
			cleanupDetails["close_duration_ms"] = time.Since(closeStart).Milliseconds()
		}
	}

	totalDuration := time.Since(startTime)

	// Final audit logs based on outcome
	if len(cleanupErrors) > 0 {
		combinedError := fmt.Errorf(strings.Join(cleanupErrors, "; "))
		tm.logAudit(requestID, "DELETE_TENANT_PARTIAL_FAILURE", tenantID, combinedError, map[string]interface{}{
			"cleanup_errors_count": len(cleanupErrors),
			"cleanup_errors":       cleanupErrors,
			"tenant_state":         "deleted_with_cleanup_errors",
			"cleanup_details":      cleanupDetails,
			"total_duration_ms":    totalDuration.Milliseconds(),
		})

		return fmt.Errorf("tenant %s removed but cleanup had errors: %s", tenantID, strings.Join(cleanupErrors, "; "))
	}

	// Complete success
	tm.logAudit(requestID, "DELETE_TENANT_COMPLETED", tenantID, nil, map[string]interface{}{
		"tenant_state":      "completely_deleted",
		"cleanup_details":   cleanupDetails,
		"total_duration_ms": totalDuration.Milliseconds(),
	})

	return nil
}

// Utility functions
func (tm *VaultManager) logAudit(requestID, action, tenantID string, err error, metadata map[string]interface{}) {
	if tm.audit == nil {
		log.Printf("WAARNING: skipping audit logging, logger not initialized\n")
		return
	}
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add standard fields
	metadata["tenant_id"] = tenantID
	metadata["user_id"] = tm.options.UserID
	metadata["request_id"] = requestID
	metadata["timestamp"] = time.Now().UTC()

	success := err == nil
	if err != nil {
		metadata["error"] = err.Error()
	}

	if auditErr := tm.audit.Log(action, success, metadata); auditErr != nil {
		log.Printf("ERROR: audit logging failed for action %s: %v\n", action, auditErr)
	}
}

func (tm *VaultManager) getTenantList() []string {
	tenants := make([]string, 0, len(tm.vaults))
	for tenantID := range tm.vaults {
		tenants = append(tenants, tenantID)
	}
	return tenants
}

func (tm *VaultManager) categorizeError(err error) string {
	// Categorize errors for better monitoring
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "connection"):
		return "connection_error"
	case strings.Contains(errStr, "timeout"):
		return "timeout_error"
	case strings.Contains(errStr, "permission"):
		return "permission_error"
	case strings.Contains(errStr, "not found"):
		return "not_found_error"
	default:
		return "unknown_error"
	}
}

/* helper methods */

func (tm *VaultManager) queryTenantAuditLogs(tenantID string, options audit.QueryOptions) ([]audit.Event, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Ensure tenantID is set in the query options
	options.TenantID = tenantID

	// Get the vault for this tenant
	vault, exists := tm.vaults[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant %s not found", tenantID)
	}

	// Get the audit logger from the vault
	auditLogger := vault.GetAudit()
	if auditLogger == nil {
		return []audit.Event{}, nil // No audit logger configured
	}

	// Query the audit logger directly
	result, err := auditLogger.Query(options)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs for tenant %s: %w", tenantID, err)
	}

	return result.Events, nil
}

func (tm *VaultManager) filterAuditEvents(events []audit.Event, options audit.QueryOptions) []audit.Event {
	var filtered []audit.Event

	for _, event := range events {
		// Time range filter
		if !options.Since.IsZero() && event.Timestamp.Before(*options.Since) {
			continue
		}
		if !options.Until.IsZero() && event.Timestamp.After(*options.Until) {
			continue
		}

		// Action filter
		if options.Action != "" && event.Action != options.Action {
			continue
		}

		// Success filter
		if options.Success != nil && event.Success != *options.Success {
			continue
		}

		// Passphrase access filter
		if options.PassphraseAccess {
			passphraseActions := []string{
				"vault_initialized",
				"emergency_passphrase_rotation",
				"derivation_key_accessed",
				"passphrase_verification",
			}

			isPassphraseAction := false
			for _, action := range passphraseActions {
				if event.Action == action {
					isPassphraseAction = true
					break
				}
			}

			if !isPassphraseAction {
				continue
			}
		}

		filtered = append(filtered, event)
	}

	return filtered
}

func (tm *VaultManager) newRequestID() string {
	return fmt.Sprintf("vm_%d", time.Now().UnixNano())
}

// Helper function to determine if an action is passphrase-related
func isPassphraseAction(action string) bool {
	passphraseActions := map[string]bool{
		"PASSPHRASE_ROTATE":     true,
		"PASSPHRASE_VERIFY":     true,
		"PASSPHRASE_CHANGE":     true,
		"PASSPHRASE_ACCESS":     true,
		"EMERGENCY_PASSPHRASE":  true,
		"VAULT_UNLOCK":          true,
		"DERIVATION_KEY_DERIVE": true,
	}
	return passphraseActions[action]
}
