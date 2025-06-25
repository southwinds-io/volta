package volta

import (
	"southwinds.dev/volta/audit"
	"time"
)

// =============================================================================
// VAULT MANAGER SERVICE - Multi-tenant vault orchestration and administration
// =============================================================================

// BulkOperationResult represents the outcome of a bulk operation on a tenant.
//
// OVERVIEW:
// This structure provides comprehensive result information for bulk operations
// that affect multiple tenants simultaneously, such as key rotation, passphrase
// updates, or administrative actions. It enables detailed tracking of operation
// outcomes across tenant boundaries with full audit trail support.
//
// RESULT SEMANTICS:
//
//	SUCCESS DETERMINATION:
//	The Success field indicates whether the operation completed successfully
//	for the specific tenant. This is a binary determination - partial success
//	is considered failure with details provided in the Error and Details fields.
//
//	ERROR REPORTING:
//	Failed operations include human-readable error messages in the Error field
//	and structured diagnostic information in the Details field. This dual
//	approach supports both user-facing error reporting and programmatic
//	error handling.
//
//	TEMPORAL TRACKING:
//	The Timestamp field records the exact moment when the operation completed
//	(successfully or unsuccessfully) for the tenant, enabling precise audit
//	trails and temporal analysis of bulk operations.
//
// AUDIT INTEGRATION:
// All bulk operation results are automatically integrated with the audit
// system, providing full traceability of administrative actions across
// tenant boundaries. Results can be correlated with audit events using
// the timestamp and tenant ID fields.
//
// Fields:
//
//	TenantID:  Unique identifier for the tenant affected by the operation
//	Success:   Boolean indicating successful completion for this tenant
//	Error:     Human-readable error message if Success is false
//	Details:   Structured diagnostic data for programmatic error handling
//	Timestamp: Exact completion time for audit and temporal correlation
type BulkOperationResult struct {
	TenantID  string                 `json:"tenant_id"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// AuditSummary provides aggregated audit statistics for tenant activity analysis.
//
// OVERVIEW:
// This structure delivers high-level audit metrics for a specific tenant,
// enabling rapid assessment of tenant activity patterns, security posture,
// and operational health. It provides both quantitative metrics and temporal
// context for comprehensive tenant monitoring.
//
// ANALYTICAL CAPABILITIES:
//
//	ACTIVITY PROFILING:
//	The summary enables creation of tenant activity profiles by categorizing
//	operations into functional groups (passphrase access, secret operations,
//	key management) and providing success/failure ratios for each category.
//
//	SECURITY MONITORING:
//	By tracking failed events alongside successful operations, the summary
//	supports security monitoring workflows that can identify unusual patterns,
//	potential attacks, or system issues affecting specific tenants.
//
//	OPERATIONAL HEALTH:
//	The ratio of successful to failed operations provides immediate insight
//	into tenant operational health and can trigger automated alerting or
//	remediation workflows when thresholds are exceeded.
//
// METRIC CATEGORIES:
// - Total Events: Complete audit trail volume for the tenant
// - Success/Failure Breakdown: Operational health indicators
// - Operation Type Breakdown: Functional usage patterns
// - Temporal Context: Activity recency and pattern analysis
//
// PERFORMANCE CONSIDERATIONS:
// Summary generation is optimized for frequent querying and can be efficiently
// cached for dashboard and monitoring applications. The structure is designed
// to support both real-time monitoring and historical trend analysis.
//
// Fields:
//
//	TenantID:           Unique identifier for the tenant being summarized
//	TotalEvents:        Complete count of all audit events for the tenant
//	SuccessfulEvents:   Count of operations that completed successfully
//	FailedEvents:       Count of operations that failed or were denied
//	CredsAccessCount: 	Count of passphrase-related operations
//	SensitiveDataAccessCount: Count of secret retrieval and manipulation operations
//	KeyOperations:      Count of cryptographic key operations
//	LastActivity:       Timestamp of the most recent audit event
type AuditSummary struct {
	TenantID                 string    `json:"tenant_id"`
	TotalEvents              int       `json:"total_events"`
	SuccessfulEvents         int       `json:"successful_events"`
	FailedEvents             int       `json:"failed_events"`
	CredsAccessCount         int       `json:"passphrase_access_count"`
	SensitiveDataAccessCount int       `json:"secret_access_count"`
	KeyOperations            int       `json:"key_operations"`
	LastActivity             time.Time `json:"last_activity"`
}

// VaultManagerService provides multi-tenant vault orchestration and administration.
//
// OVERVIEW:
// This service interface defines the administrative and orchestration layer
// for managing multiple isolated vault instances in a multi-tenant environment.
// It provides capabilities for tenant lifecycle management, bulk operations,
// comprehensive audit querying, and cross-tenant administrative functions.
//
// ARCHITECTURAL ROLE:
//
//	TENANT ISOLATION:
//	The service ensures complete isolation between tenants while providing
//	centralized management capabilities. Each tenant's vault operates
//	independently with its own encryption keys, audit trails, and access
//	controls, preventing any form of cross-tenant data leakage.
//
//	ADMINISTRATIVE ORCHESTRATION:
//	Bulk operations enable efficient management of multiple tenants
//	simultaneously, supporting enterprise-scale deployments where hundreds
//	or thousands of tenants require coordinated administrative actions.
//
//	AUDIT AGGREGATION:
//	The service provides both tenant-specific and cross-tenant audit
//	capabilities, enabling comprehensive security monitoring and compliance
//	reporting across the entire multi-tenant deployment.
//
// SECURITY MODEL:
//
//	PRINCIPLE OF LEAST PRIVILEGE:
//	Administrative operations require explicit authorization and are subject
//	to role-based access controls. The service supports delegation of
//	administrative privileges with fine-grained permission scoping.
//
//	AUDIT COMPLETENESS:
//	All administrative operations are fully audited with immutable audit
//	trails. Bulk operations create detailed audit records for each affected
//	tenant, enabling complete reconstruction of administrative actions.
//
//	TENANT BOUNDARY ENFORCEMENT:
//	The service enforces strict tenant boundaries and prevents unauthorized
//	cross-tenant access even by administrative users. Tenant isolation is
//	maintained at the cryptographic level with separate encryption keys.
//
// OPERATIONAL CHARACTERISTICS:
//
//	SCALABILITY:
//	The service is designed to support large-scale multi-tenant deployments
//	with thousands of tenants. Operations are optimized for concurrent
//	execution and can be distributed across multiple service instances.
//
//	RELIABILITY:
//	Bulk operations implement transactional semantics where possible, with
//	detailed error reporting and rollback capabilities. Failed operations
//	on individual tenants do not affect operations on other tenants.
//
//	PERFORMANCE:
//	The service includes caching and optimization strategies for frequently
//	accessed tenant data and audit information. Administrative operations
//	are designed to minimize impact on tenant-facing vault operations.
//
// =============================================================================
type VaultManagerService interface {
	// =========================================================================
	// TENANT LIFECYCLE MANAGEMENT - Core tenant operations and resource management
	// =========================================================================

	// GetVault retrieves a VaultService instance for a specific tenant.
	//
	// OVERVIEW:
	// This method provides access to tenant-specific vault instances, serving
	// as the primary entry point for tenant-scoped operations. It implements
	// lazy initialization patterns and resource pooling to optimize performance
	// while maintaining strict tenant isolation.
	//
	// RESOURCE MANAGEMENT:
	//
	//   LAZY INITIALIZATION:
	//   Vault instances are created on-demand when first accessed, reducing
	//   memory footprint and startup time for deployments with many inactive
	//   tenants. Initialization includes loading tenant-specific encryption
	//   keys and establishing secure memory contexts.
	//
	//   CONNECTION POOLING:
	//   The service maintains a pool of initialized vault instances to avoid
	//   repeated initialization costs. Pool management includes automatic
	//   cleanup of idle instances and load balancing across active instances.
	//
	//   TENANT ISOLATION:
	//   Each returned VaultService instance is completely isolated from other
	//   tenants, with separate encryption keys, audit contexts, and resource
	//   allocations. Cross-tenant contamination is prevented at the service
	//   architecture level.
	//
	// SECURITY CONSIDERATIONS:
	// - Tenant access is subject to authorization checks
	// - Audit logging captures all vault instance requests
	// - Encryption keys are tenant-specific and never shared
	// - Resource limits prevent tenant-based denial of service
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant vault to retrieve
	//
	// Returns:
	//   VaultService: Tenant-specific vault instance for secret operations
	//   error: nil on success, detailed error on failure or access denial
	GetVault(tenantID string) (VaultService, error)

	// CloseTenant gracefully shuts down and cleans up resources for a tenant.
	//
	// OVERVIEW:
	// This method performs controlled shutdown of a tenant's vault instance,
	// ensuring all resources are properly cleaned up and all sensitive data
	// is securely wiped from memory. It supports both graceful shutdown
	// scenarios and emergency cleanup operations.
	//
	// CLEANUP OPERATIONS:
	//
	//   MEMORY SANITIZATION:
	//   All tenant-specific encryption keys, cached secrets, and intermediate
	//   cryptographic material are securely wiped from memory using
	//   cryptographically secure wiping techniques that prevent recovery
	//   through memory dump analysis.
	//
	//   RESOURCE DEALLOCATION:
	//   File handles, network connections, and system resources allocated
	//   to the tenant are properly closed and released. This includes
	//   cleaning up any temporary files or cached data structures.
	//
	//   AUDIT FINALIZATION:
	//   Pending audit events are flushed to persistent storage and audit
	//   streams are properly closed. Final audit events record the tenant
	//   shutdown operation with timestamp and reason information.
	//
	// SAFETY GUARANTEES:
	// - Secure memory wiping prevents data recovery attacks
	// - Graceful shutdown preserves audit trail integrity
	// - Resource cleanup prevents memory leaks in long-running services
	// - Operation is idempotent (safe to call multiple times)
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant to shut down
	//
	// Returns:
	//   error: nil on successful cleanup, error on shutdown failures
	CloseTenant(tenantID string) error

	// CloseAll performs graceful shutdown of all active tenant vaults.
	//
	// OVERVIEW:
	// This method orchestrates shutdown of all tenant vault instances,
	// typically used during service shutdown or emergency maintenance
	// operations. It ensures orderly cleanup across all tenants while
	// maintaining audit trail integrity and security guarantees.
	//
	// SHUTDOWN ORCHESTRATION:
	//
	//   PARALLEL SHUTDOWN:
	//   Tenant shutdown operations are executed in parallel to minimize
	//   total shutdown time. The degree of parallelism is configurable
	//   to balance shutdown speed with system resource utilization.
	//
	//   FAILURE ISOLATION:
	//   Shutdown failures for individual tenants do not prevent shutdown
	//   of other tenants. The method collects and reports all shutdown
	//   errors while ensuring maximum cleanup is achieved.
	//
	//   AUDIT PRESERVATION:
	//   All audit data is preserved during shutdown operations, with
	//   special audit events recorded for the service-wide shutdown
	//   operation and any tenant-specific shutdown failures.
	//
	// OPERATIONAL USES:
	// - Service shutdown and restart operations
	// - Emergency maintenance procedures
	// - Resource cleanup after configuration changes
	// - Disaster recovery preparation
	//
	// Parameters: None
	//
	// Returns:
	//   error: nil if all tenants shut down successfully, error with details
	//          of any failures (partial success still cleans up other tenants)
	CloseAll() error

	// ListTenants returns identifiers for all currently active tenants.
	//
	// OVERVIEW:
	// This method provides discovery of active tenant vault instances,
	// supporting administrative operations, monitoring, and bulk operation
	// planning. It returns only tenants that are currently active or
	// have been recently active within the service.
	//
	// TENANT DISCOVERY:
	//
	//   ACTIVE TENANT DETECTION:
	//   The method returns tenants that have active vault instances or
	//   have been accessed within a configurable time window. This
	//   prevents returning stale tenant identifiers from historical
	//   operations while ensuring recently active tenants are visible.
	//
	//   AUTHORIZATION FILTERING:
	//   The returned list is filtered based on the caller's authorization
	//   level. Administrative users may see all tenants, while limited
	//   users may only see tenants they have been granted access to.
	//
	//   PERFORMANCE OPTIMIZATION:
	//   The method is optimized for frequent polling by monitoring and
	//   dashboard applications. Results may be cached for short periods
	//   to reduce overhead on the underlying tenant management system.
	//
	// SECURITY CONSIDERATIONS:
	// - Tenant list access is subject to authorization checks
	// - Audit logging captures tenant discovery operations
	// - Results are filtered based on caller permissions
	// - No sensitive tenant data is included in the response
	//
	// Parameters: None
	//
	// Returns:
	//   []string: Array of tenant identifiers for active tenants
	//   error: nil on success, error on authorization failure or system error
	ListTenants() ([]string, error)

	// =========================================================================
	// BULK OPERATIONS - Multi-tenant administrative operations
	// =========================================================================

	// RotateAllTenantKeys performs encryption key rotation for multiple tenants.
	//
	// OVERVIEW:
	// This method orchestrates simultaneous key rotation across multiple tenants,
	// supporting compliance requirements, security hardening, and routine
	// key lifecycle management. It ensures cryptographic continuity while
	// upgrading encryption keys to maintain security posture.
	//
	// KEY ROTATION PROCESS:
	//
	//   CRYPTOGRAPHIC CONTINUITY:
	//   Key rotation is performed using a migration process that maintains
	//   access to existing encrypted data while establishing new encryption
	//   keys for future operations. This ensures no data loss or service
	//   interruption during the rotation process.
	//
	//   ATOMIC OPERATIONS:
	//   Key rotation for each tenant is atomic - either the rotation completes
	//   successfully or the tenant remains on the previous key with no
	//   partial state. This prevents cryptographic inconsistencies that
	//   could result in data loss or security vulnerabilities.
	//
	//   ROLLBACK CAPABILITIES:
	//   The rotation process supports rollback to previous keys if issues
	//   are detected during or after rotation. Rollback operations are
	//   also atomic and maintain the same security guarantees.
	//
	// SECURITY ENHANCEMENTS:
	// - New keys use latest cryptographic algorithms and key sizes
	// - Forward secrecy: compromise of old keys doesn't affect new operations
	// - Audit trail includes complete key lifecycle events
	// - Secure key material destruction after successful rotation
	//
	// OPERATIONAL CONSIDERATIONS:
	// - Operations are performed in parallel across tenants
	// - Resource usage is controlled to prevent system overload
	// - Progress monitoring and status reporting for long-running operations
	// - Automatic retry logic for transient failures
	//
	// Parameters:
	//   tenantIDs: Array of tenant identifiers to rotate keys for
	//   reason: Human-readable reason for the rotation (for audit trail)
	//
	// Returns:
	//   []BulkOperationResult: Per-tenant results with success/failure details
	//   error: nil on successful orchestration, error on systematic failures
	RotateAllTenantKeys(tenantIDs []string, reason string) ([]BulkOperationResult, error)

	// RotateAllTenantPassphrases updates master passphrases for multiple tenants.
	//
	// OVERVIEW:
	// This method performs coordinated passphrase rotation across multiple
	// tenants, supporting security policies that require periodic passphrase
	// updates, incident response procedures, or administrative access changes.
	// It maintains cryptographic integrity while updating authentication
	// credentials.
	//
	// PASSPHRASE ROTATION MECHANICS:
	//
	//   CRYPTOGRAPHIC RE-ENCRYPTION:
	//   Passphrase rotation involves re-encrypting the tenant's master key
	//   using the new passphrase-derived key. This process maintains access
	//   to all existing secrets while updating the authentication layer.
	//
	//   SECURE PASSPHRASE HANDLING:
	//   The new passphrase is handled using secure memory techniques throughout
	//   the rotation process. Intermediate cryptographic material is protected
	//   using memguard and securely wiped after use.
	//
	//   VERIFICATION PROCESS:
	//   After rotation, the new passphrase is verified by attempting to
	//   unlock the tenant vault. Only after successful verification is
	//   the old passphrase material destroyed, ensuring the rotation
	//   process cannot result in locked-out tenants.
	//
	// COMPLIANCE SUPPORT:
	// - Audit events record passphrase rotation with timestamps
	// - Rotation reason is preserved for compliance reporting
	// - Support for compliance-driven rotation schedules
	// - Integration with identity management systems
	//
	// SECURITY CONSIDERATIONS:
	// - New passphrase is never logged or stored in plaintext
	// - Old passphrase material is cryptographically wiped
	// - Rotation process is resistant to timing attacks
	// - Failed rotations do not compromise existing security
	//
	// Parameters:
	//   tenantIDs: Array of tenant identifiers to rotate passphrases for
	//   newPassphrase: New passphrase to set for all specified tenants
	//   reason: Human-readable reason for the rotation (for audit trail)
	//
	// Returns:
	//   []BulkOperationResult: Per-tenant results with success/failure details
	//   error: nil on successful orchestration, error on systematic failures
	RotateAllTenantPassphrases(tenantIDs []string, newPassphrase string, reason string) ([]BulkOperationResult, error)

	// =========================================================================
	// AUDIT OPERATIONS - Comprehensive audit querying and analysis
	// =========================================================================

	// QueryAuditLogs performs flexible audit log queries with advanced filtering.
	//
	// OVERVIEW:
	// This method provides comprehensive audit log querying capabilities with
	// support for complex filtering, temporal ranges, and result aggregation.
	// It enables security analysis, compliance reporting, and operational
	// monitoring across single tenants or the entire multi-tenant deployment.
	//
	// QUERY CAPABILITIES:
	//
	//   FLEXIBLE FILTERING:
	//   The QueryOptions parameter supports complex filtering criteria including
	//   tenant scope, operation types, time ranges, success/failure status,
	//   and custom field matching. Multiple filters can be combined using
	//   logical operators for sophisticated queries.
	//
	//   PERFORMANCE OPTIMIZATION:
	//   Query execution is optimized for large audit datasets using indexing,
	//   result pagination, and streaming responses. Large result sets are
	//   handled efficiently without overwhelming system resources.
	//
	//   RESULT AGGREGATION:
	//   The method supports aggregation operations such as counting, grouping,
	//   and statistical analysis of audit events. This enables dashboard
	//   applications and analytical tools to efficiently process audit data.
	//
	// SECURITY AND COMPLIANCE:
	// - Audit queries are themselves audited for security monitoring
	// - Result sets are filtered based on caller authorization
	// - Immutable audit trail ensures tamper detection
	// - Support for regulatory compliance queries and reporting
	//
	// Parameters:
	//   options: Comprehensive query options including filters and aggregations
	//
	// Returns:
	//   *audit.QueryResult: Structured query results with metadata
	//   error: nil on success, error on query failure or authorization denial
	QueryAuditLogs(options audit.QueryOptions) (*audit.QueryResult, error)

	// GetAuditSummary generates aggregated audit statistics for a tenant.
	//
	// OVERVIEW:
	// This method produces comprehensive audit summaries for individual tenants,
	// providing key operational metrics and activity patterns. It supports
	// monitoring dashboards, security analysis, and tenant health assessment
	// through pre-calculated statistical summaries.
	//
	// SUMMARY GENERATION:
	//
	//   STATISTICAL AGGREGATION:
	//   The summary includes counts, ratios, and temporal analysis of audit
	//   events categorized by operation type and outcome. Statistical
	//   calculations are performed efficiently using pre-built indexes
	//   and incremental aggregation techniques.
	//
	//   TEMPORAL ANALYSIS:
	//   When a 'since' parameter is provided, the summary covers only events
	//   from that point forward, enabling trend analysis and delta reporting.
	//   Without the parameter, the summary covers the tenant's complete
	//   audit history.
	//
	//   PERFORMANCE CACHING:
	//   Summary data is cached and incrementally updated to support frequent
	//   polling by monitoring applications. Cache invalidation ensures
	//   summaries reflect recent activity while maintaining query performance.
	//
	// MONITORING INTEGRATION:
	// - Designed for integration with monitoring and alerting systems
	// - Supports threshold-based alerting on activity patterns
	// - Provides baseline metrics for anomaly detection
	// - Enables capacity planning and usage trend analysis
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant to summarize
	//   since: Optional timestamp to limit summary to recent events
	//
	// Returns:
	//   AuditSummary: Comprehensive audit statistics for the tenant
	//   error: nil on success, error on failure or authorization denial
	GetAuditSummary(tenantID string, since *time.Time) (AuditSummary, error)

	// QueryKeyOperations retrieves audit events for cryptographic key operations.
	//
	// OVERVIEW:
	// This method provides specialized querying for cryptographic key operations
	// within a tenant's audit trail. It supports security analysis of key
	// usage patterns, compliance auditing of key lifecycle events, and
	// investigation of key-related security incidents.
	//
	// KEY OPERATION TRACKING:
	//
	//   COMPREHENSIVE KEY LIFECYCLE:
	//   The method returns events for all key-related operations including
	//   key generation, rotation, usage, and destruction. This provides
	//   complete visibility into key lifecycle management for security
	//   analysis and compliance reporting.
	//
	//   CRYPTOGRAPHIC ANALYSIS:
	//   Results include sufficient detail for cryptographic security analysis
	//   such as key algorithms, key sizes, usage patterns, and performance
	//   metrics. This supports security assessments and algorithm migration
	//   planning.
	//
	//   TEMPORAL CORRELATION:
	//   Key operation events can be correlated with other audit events to
	//   analyze the relationship between key operations and secret access
	//   patterns, supporting comprehensive security analysis.
	//
	// SECURITY MONITORING:
	// - Detects unusual key usage patterns that may indicate compromise
	// - Supports forensic analysis of cryptographic operations
	// - Enables compliance reporting for key management standards
	// - Provides evidence for incident response investigations
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant to query
	//   keyID: Specific key identifier to filter events for
	//   since: Optional timestamp to limit results to recent events
	//
	// Returns:
	//   []audit.Event: Array of key operation events matching the criteria
	//   error: nil on success, error on failure or authorization denial
	QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]audit.Event, error)

	// QuerySecretAccess retrieves audit events for secret access operations.
	//
	// OVERVIEW:
	// This method provides specialized querying for secret access operations,
	// supporting security monitoring, access pattern analysis, and investigation
	// of unauthorized access attempts. It enables detailed tracking of how
	// secrets are accessed and used within a tenant's vault.
	//
	// ACCESS PATTERN ANALYSIS:
	//
	//   DETAILED ACCESS TRACKING:
	//   The method returns comprehensive information about secret access
	//   including access timestamps, operation types (read/write/delete),
	//   success/failure status, and contextual information about the
	//   access attempt.
	//
	//   BEHAVIORAL ANALYSIS:
	//   Access patterns can be analyzed to establish baselines for normal
	//   secret usage and detect anomalies that may indicate unauthorized
	//   access, compromised credentials, or misuse of privileged access.
	//
	//   COMPLIANCE REPORTING:
	//   The detailed access logs support compliance requirements for
	//   sensitive data access tracking, including who accessed what
	//   secrets when and for what purpose.
	//
	// SECURITY APPLICATIONS:
	// - Unauthorized access detection and incident response
	// - Compliance auditing for sensitive secret access
	// - Usage pattern analysis for security optimization
	// - Forensic investigation of security incidents
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant to query
	//   secretID: Specific secret identifier to filter events for
	//   since: Optional timestamp to limit results to recent events
	//
	// Returns:
	//   []audit.Event: Array of secret access events matching the criteria
	//   error: nil on success, error on failure or authorization denial
	QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]audit.Event, error)

	// QueryFailedOperations retrieves audit events for failed operations.
	//
	// OVERVIEW:
	// This method provides specialized querying for failed operations across
	// all vault functions, supporting security monitoring, troubleshooting,
	// and incident response. It enables rapid identification of security
	// issues, system problems, and attack patterns.
	//
	// FAILURE ANALYSIS:
	//
	//   SECURITY INCIDENT DETECTION:
	//   Failed operations often indicate security events such as unauthorized
	//   access attempts, brute force attacks, or compromised credentials.
	//   The method supports rapid identification and analysis of potential
	//   security incidents.
	//
	//   SYSTEM HEALTH MONITORING:
	//   Patterns of failed operations can indicate system issues, resource
	//   constraints, or configuration problems that require operational
	//   attention. This supports proactive system maintenance and optimization.
	//
	//   ATTACK PATTERN RECOGNITION:
	//   Clustering and analysis of failed operations can reveal attack
	//   patterns, reconnaissance activities, and systematic attempts to
	//   compromise the vault system.
	//
	// OPERATIONAL USES:
	// - Security incident detection and response
	// - System troubleshooting and health monitoring
	// - Attack pattern analysis and threat intelligence
	// - Operational optimization and error reduction
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant to query
	//   since: Optional timestamp to limit results to recent events
	//
	// Returns:
	//   []audit.Event: Array of failed operation events matching the criteria
	//   error: nil on success, error on failure or authorization denial
	QueryFailedOperations(tenantID string, since *time.Time) ([]audit.Event, error)

	// QueryPassphraseAccessLogs retrieves audit events for passphrase operations.
	//
	// OVERVIEW:
	// This method provides specialized querying for passphrase-related operations
	// including authentication attempts, passphrase changes, and vault unlock
	// operations. It supports security monitoring of authentication events
	// and analysis of passphrase-based attack patterns.
	//
	// AUTHENTICATION MONITORING:
	//
	//   CREDENTIAL SECURITY:
	//   Passphrase access events are critical security indicators that can
	//   reveal unauthorized access attempts, credential compromise, or
	//   authentication system issues. The method provides detailed tracking
	//   of all passphrase-related security events.
	//
	//   ATTACK DETECTION:
	//   Failed passphrase attempts, unusual timing patterns, or high-frequency
	//   access attempts may indicate brute force attacks, credential stuffing,
	//   or other authentication-based attacks.
	//
	//   COMPLIANCE TRACKING:
	//   Many compliance frameworks require detailed logging of authentication
	//   events. This method provides the necessary audit trail for regulatory
	//   compliance and security certifications.
	//
	// SECURITY MONITORING:
	// - Brute force attack detection and prevention
	// - Credential compromise investigation
	// - Authentication system health monitoring
	// - Compliance reporting for access control systems
	//
	// Parameters:
	//   tenantID: Unique identifier for the tenant to query
	//   since: Optional timestamp to limit results to recent events
	//
	// Returns:
	//   []audit.Event: Array of passphrase access events matching the criteria
	//   error: nil on success, error on failure or authorization denial
	QueryPassphraseAccessLogs(tenantID string, since *time.Time) ([]audit.Event, error)

	// QueryAllTenantsAuditLogs performs cross-tenant audit log queries.
	//
	// OVERVIEW:
	// This method enables audit log queries across multiple tenants simultaneously,
	// supporting organization-wide security monitoring, compliance reporting,
	// and incident response operations. It provides comprehensive visibility
	// into multi-tenant security events while maintaining tenant isolation.
	//
	// CROSS-TENANT ANALYSIS:
	//
	//   ORGANIZATIONAL SECURITY:
	//   Cross-tenant queries enable detection of security patterns that span
	//   multiple tenants, such as coordinated attacks, compromised administrative
	//   accounts, or systematic reconnaissance activities.
	//
	//   COMPLIANCE REPORTING:
	//   Many regulatory frameworks require organization-wide audit reporting
	//   that spans all tenant boundaries. This method provides the necessary
	//   capabilities for comprehensive compliance reporting.
	//
	//   INCIDENT RESPONSE:
	//   Security incidents often affect multiple tenants or require correlation
	//   of events across tenant boundaries. This method supports comprehensive
	//   incident response investigations.
	//
	// AUTHORIZATION AND ISOLATION:
	// - Results are filtered based on caller's cross-tenant permissions
	// - Tenant data isolation is maintained even in cross-tenant queries
	// - Administrative audit trails track cross-tenant access
	// - Results are organized by tenant for analysis and reporting
	//
	// Parameters:
	//   options: Comprehensive query options applied across all tenants
	//
	// Returns:
	//   map[string]audit.QueryResult: Results organized by tenant ID
	//   error: nil on success, error on failure or authorization denial
	QueryAllTenantsAuditLogs(options audit.QueryOptions) (map[string]audit.QueryResult, error)

	// QueryTenantAuditLogs performs comprehensive audit queries for a single tenant.
	//
	// OVERVIEW:
	// This method provides the most comprehensive audit querying capabilities
	// for a single tenant, combining the flexibility of QueryAuditLogs with
	// tenant-specific optimizations and enhanced filtering capabilities.
	//
	// TENANT-OPTIMIZED QUERYING:
	//
	//   PERFORMANCE OPTIMIZATION:
	//   Tenant-specific queries are optimized using tenant-specific indexes
	//   and data structures, providing better performance than cross-tenant
	//   queries for tenant-focused analysis and reporting.
	//
	//   COMPREHENSIVE FILTERING:
	//
	// COMPREHENSIVE FILTERING:
	// The method supports all available filtering options with tenant-specific
	// enhancements such as secret-specific filters, key-specific filters,
	// and tenant-specific custom field matching. This enables highly
	// precise audit queries for detailed security analysis.
	//
	// CONTEXTUAL ENRICHMENT:
	// Results include tenant-specific contextual information and metadata
	// that may not be available in cross-tenant queries, providing richer
	// analysis capabilities for tenant-focused investigations.
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
	// Parameters:
	// tenantID: Unique identifier for the tenant to query
	// options: Comprehensive query options with tenant-specific enhancements
	//
	// Returns:
	// audit.QueryResult: Comprehensive audit results for the tenant
	// error: nil on success, error on failure or authorization denial
	QueryTenantAuditLogs(tenantID string, options audit.QueryOptions) (audit.QueryResult, error)

	DeleteTenant(tenatID string) error
}
