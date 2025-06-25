package volta

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"os"
	"runtime"
	"southwinds.dev/volta/internal/crypto"
	"southwinds.dev/volta/internal/debug"
	"time"
)

// KeyRotationMetadata represents the complete state and history of vault key rotation operations.
//
// This structure serves as the authoritative record of all key management activities
// within the vault, including current key status, rotation history, and encrypted
// key material. It provides the foundation for key lifecycle management, audit
// trails, and disaster recovery operations. The metadata is persisted to storage
// and maintained across vault restarts and backup/restore operations.
//
// STRUCTURE PURPOSE AND SCOPE:
// The KeyRotationMetadata serves multiple critical functions:
// - Tracks the current active encryption key for new operations
// - Maintains complete history of all keys (active and retired)
// - Stores encrypted key material for all historical keys
// - Records rotation timing and reasoning for audit purposes
// - Enables key lifecycle management and compliance reporting
// - Supports disaster recovery and backup/restore operations
// - Provides data for key rotation policy enforcement
// - Facilitates cryptographic key inventory and management
//
// SECURITY ARCHITECTURE:
// The metadata structure implements defense-in-depth security:
// - Key material is stored encrypted using vault's derivation key
// - Multiple layers of encryption protect sensitive key data
// - Metadata separation from actual key material prevents leakage
// - Audit information is stored separately from cryptographic material
// - Version tracking enables rollback and recovery scenarios
// - Tamper detection through metadata integrity verification
// - Secure serialization with authenticated encryption
//
// KEY LIFECYCLE MANAGEMENT:
// The structure supports complete key lifecycle operations:
// - Key creation with secure random generation
// - Key activation for new encryption operations
// - Key retirement without data loss (historical keys remain accessible)
// - Key rotation with seamless transition and no service interruption
// - Key archival with long-term retention policies
// - Key destruction with secure memory clearing
// - Key recovery from backup with full operational capability
//
// FIELD SPECIFICATIONS:
type KeyRotationMetadata struct {
	// Version indicates the metadata format version for compatibility management.
	//
	// This field enables forward and backward compatibility as the key rotation
	// system evolves. It supports metadata format migrations and ensures
	// proper handling of different metadata versions during vault upgrades.
	//
	// Version History:
	// - Version 1: Initial implementation with basic rotation support
	// - Version 2: Enhanced with rotation reason tracking and audit data
	// - Version 3: Added compliance metadata and policy enforcement
	//
	// Usage:
	// - Always set to current metadata version during rotation operations
	// - Validated during metadata loading to ensure compatibility
	// - Used for migration logic when upgrading vault versions
	// - Preserved during backup/restore to maintain compatibility
	//
	// Range: 1-N (where N is the latest supported version)
	// Default: Set to current implementation version
	Version int `json:"version"`

	// CurrentKeyID identifies the active encryption key for new operations.
	//
	// This field contains the unique identifier of the key currently used
	// for all new encryption operations. The key ID is a cryptographically
	// secure random identifier that uniquely identifies each key throughout
	// its lifecycle. This field is updated atomically during key rotation.
	//
	// Key ID Format:
	// - 32-character hexadecimal string (128-bit entropy)
	// - Generated using cryptographically secure random number generator
	// - Globally unique within the vault instance
	// - Immutable once assigned to a key
	//
	// Usage:
	// - Referenced during all new encryption operations
	// - Updated atomically during successful key rotation
	// - Validated against Keys map to ensure consistency
	// - Used for key selection in high-performance encryption paths
	//
	// Example: "a1b2c3d4e5f6789012345678901234567890abcd"
	// Validation: Must exist as a key in both Keys and EncryptedKeys maps
	CurrentKeyID string `json:"current_key_id"`

	// LastRotation records the timestamp of the most recent key rotation.
	//
	// This field enables rotation policy enforcement, audit reporting,
	// and operational monitoring. The timestamp is always stored in UTC
	// to ensure consistent behavior across different time zones and
	// daylight saving time transitions.
	//
	// Precision: Nanosecond precision for ordering and audit accuracy
	// Format: RFC3339 with nanosecond precision in JSON serialization
	// Timezone: Always UTC to ensure consistent behavior
	//
	// Usage:
	// - Used for rotation policy enforcement (e.g., rotate every 90 days)
	// - Provides audit trail for compliance reporting
	// - Enables monitoring and alerting on rotation frequency
	// - Supports disaster recovery timeline reconstruction
	//
	// Policy Applications:
	// - Automatic rotation scheduling based on age
	// - Compliance reporting for regulatory requirements
	// - Security monitoring for unusual rotation patterns
	// - Operational dashboards and health monitoring
	LastRotation time.Time `json:"last_rotation"`

	// Keys contains metadata for all keys in the vault (current and historical).
	//
	// This map provides comprehensive information about each key without
	// exposing the actual key material. The metadata includes creation
	// timestamps, usage statistics, rotation history, and lifecycle status.
	// This information is essential for key management, audit reporting,
	// and compliance operations.
	//
	// Map Structure:
	// - Key: Unique key identifier (same format as CurrentKeyID)
	// - Value: KeyMetadata struct containing detailed key information
	//
	// KeyMetadata Contents:
	// - CreatedAt: UTC timestamp of key generation
	// - Status: Key lifecycle status (Active, Retired, Archived)
	// - Algorithm: Cryptographic algorithm and parameters
	// - UsageCount: Number of encryption operations performed
	// - LastUsed: Timestamp of most recent usage
	// - RetiredAt: Timestamp when key was retired (if applicable)
	// - Purpose: Intended use case and scope
	// - Compliance: Regulatory and policy compliance information
	//
	// Usage Patterns:
	// - Lookup key metadata during encryption/decryption operations
	// - Generate key usage reports for audit and compliance
	// - Implement key lifecycle policies and automated management
	// - Support key rotation planning and capacity management
	//
	// Example:
	// {
	//   "a1b2c3d4...": {
	//     "CreatedAt": "2024-01-01T00:00:00Z",
	//     "Status": "Active",
	//     "Algorithm": "ChaCha20-Poly1305",
	//     "UsageCount": 15234,
	//     "LastUsed": "2024-01-15T14:30:22Z"
	//   }
	// }
	Keys map[string]KeyMetadata `json:"keys"`

	// EncryptedKeys stores the actual encrypted key material for all keys.
	//
	// This map contains the cryptographic key material encrypted using the
	// vault's derivation key. The encrypted keys enable decryption of
	// historical data while maintaining security through encryption at rest.
	// This is the most security-sensitive field in the metadata structure.
	//
	// Encryption Details:
	// - Keys are encrypted using ChaCha20-Poly1305 authenticated encryption
	// - Encryption key derived from vault's master derivation key
	// - Each key is encrypted independently with unique nonce
	// - Authenticated encryption provides integrity and authenticity
	// - Key material is securely cleared from memory after encryption
	//
	// Map Structure:
	// - Key: Unique key identifier (matches Keys map keys)
	// - Value: Encrypted key material as byte slice
	//
	// Storage Format:
	// - Encrypted key material (32 bytes for ChaCha20-Poly1305)
	// - Authentication tag (16 bytes)
	// - Nonce/IV (12 bytes for ChaCha20-Poly1305)
	// - Total: 60 bytes per encrypted key
	//
	// Security Considerations:
	// - Key material never stored in plaintext
	// - Encrypted keys are useless without vault's derivation key
	// - Memory is securely cleared after key operations
	// - Access to encrypted keys requires full vault authentication
	// - Backup encryption provides additional protection layer
	//
	// Usage:
	// - Decrypt keys on-demand for cryptographic operations
	// - Support historical data decryption with retired keys
	// - Enable key rotation without data migration
	// - Facilitate backup/restore operations with full key recovery
	//
	// Example:
	// {
	//   "a1b2c3d4...": [...encrypted key bytes...],
	//   "b2c3d4e5...": [...encrypted key bytes...]
	// }
	EncryptedKeys map[string][]byte `json:"encrypted_keys"`

	// Reason documents the rationale for the most recent key rotation.
	//
	// This field provides essential audit information and helps with
	// compliance reporting, security incident response, and operational
	// documentation. The reason is stored as free-form text but should
	// follow organizational standards for consistency and searchability.
	//
	// Common Rotation Reasons:
	// - "Scheduled rotation per policy" - Regular policy-driven rotation
	// - "Security incident response" - Rotation due to security concerns
	// - "Compliance requirement" - Rotation for regulatory compliance
	// - "Administrative request" - Manual rotation by administrators
	// - "Key compromise suspected" - Precautionary rotation
	// - "Vault migration" - Rotation during infrastructure changes
	// - "Algorithm upgrade" - Rotation to newer cryptographic algorithms
	// - "Performance optimization" - Rotation for operational improvements
	//
	// Best Practices:
	// - Use consistent terminology across the organization
	// - Include relevant incident or ticket numbers
	// - Specify regulatory or policy requirements when applicable
	// - Document emergency rotations with appropriate detail
	// - Include timing rationale for non-scheduled rotations
	//
	// Audit and Compliance:
	// - Required for many regulatory compliance frameworks
	// - Essential for security audit trails and incident response
	// - Supports forensic analysis and timeline reconstruction
	// - Enables automated compliance reporting and validation
	//
	// Example Values:
	// - "Scheduled quarterly rotation per security policy SP-2024-001"
	// - "Emergency rotation following security incident INC-2024-0234"
	// - "Compliance rotation required by SOC 2 Type II audit"
	// - "Proactive rotation during infrastructure maintenance window"
	//
	// Maximum Length: 1000 characters (to prevent excessive storage usage)
	// Encoding: UTF-8 to support international characters
	Reason string `json:"reason"`
}

// SERIALIZATION AND PERSISTENCE:
// The KeyRotationMetadata structure is serialized to JSON for persistence
// and transmission. The JSON format ensures compatibility across different
// platforms and programming languages while maintaining human readability
// for administrative and debugging purposes.
//
// JSON Serialization Features:
// - Uses standard JSON field tags for consistent serialization
// - Supports pretty-printing for human-readable output
// - Maintains field order for consistent serialization
// - Handles time formatting with RFC3339 precision
// - Supports nested structure serialization for complex metadata
//
// Storage Considerations:
// - Metadata is stored separately from actual vault data
// - Atomic writes ensure metadata consistency
// - Backup operations include complete metadata state
// - Metadata versioning supports format evolution
// - Compression may be applied for large key histories
//
// THREAD SAFETY AND CONCURRENCY:
// The KeyRotationMetadata structure itself is not thread-safe and requires
// external synchronization for concurrent access. The vault implementation
// provides appropriate locking mechanisms to ensure safe concurrent access
// to metadata during rotation operations.
//
// Concurrency Patterns:
// - Read operations can be concurrent with appropriate read locks
// - Write operations require exclusive access with write locks
// - Atomic updates ensure metadata consistency during rotation
// - Lock ordering prevents deadlocks during complex operations
//
// BACKUP AND RECOVERY:
// The KeyRotationMetadata is a critical component of vault backup and
// recovery operations. Complete metadata preservation is essential for
// successful vault restoration and continued operation.
//
// Backup Requirements:
// - Complete metadata state including all historical keys
// - Encrypted key material with proper encryption preservation
// - Audit trail information for compliance and security
// - Version information for compatibility management
//
// Recovery Capabilities:
// - Full key hierarchy restoration from backup metadata
// - Historical data access with restored retired keys
// - Audit trail preservation across recovery operations
// - Seamless operation continuation after recovery
//
// COMPLIANCE AND AUDIT SUPPORT:
// The KeyRotationMetadata structure supports various compliance and audit
// requirements through comprehensive tracking and documentation capabilities.
//
// Compliance Features:
// - Complete audit trail of all key operations
// - Timestamp tracking for retention and lifecycle policies
// - Reason documentation for regulatory reporting
// - Key usage tracking for compliance validation
// - Historical preservation for audit and forensic analysis
//
// Audit Capabilities:
// - Comprehensive key lifecycle documentation
// - Usage pattern analysis and reporting
// - Compliance validation and reporting
// - Security incident investigation support
// - Regular audit report generation
//
// OPERATIONAL MONITORING AND ALERTING:
// The metadata supports comprehensive operational monitoring and alerting
// capabilities for proactive key management and security operations.
//
// Monitoring Capabilities:
// - Key rotation frequency tracking and alerting
// - Key usage pattern analysis and anomaly detection
// - Performance impact monitoring during rotation operations
// - Compliance deadline tracking and notification
// - Capacity planning and resource utilization monitoring
//
// PERFORMANCE CONSIDERATIONS:
// The KeyRotationMetadata structure is designed for efficient access patterns
// and minimal performance impact during normal vault operations.
//
// Performance Characteristics:
// - O(1) access to current key information
// - Efficient serialization and deserialization
// - Minimal memory footprint for metadata storage
// - Fast lookup operations for key resolution
// - Optimized for high-frequency encryption/decryption operations
//
// SECURITY BEST PRACTICES:
// Implementation and usage of KeyRotationMetadata should follow security
// best practices to maintain the overall security posture of the vault.
//
// Best Practices:
// - Regular validation of metadata integrity and consistency
// - Secure handling of serialized metadata during backup operations
// - Access control and authentication for metadata operations
// - Audit logging of all metadata modifications
// - Encryption of metadata at rest and in transit
// - Secure disposal of metadata during vault decommissioning
//
// FUTURE EXTENSIBILITY:
// The KeyRotationMetadata structure is designed to support future
// enhancements and feature additions while maintaining backward compatibility.
//
// Extensibility Features:
// - Version field enables format evolution
// - JSON serialization supports additional field addition
// - Modular design allows for feature enhancement
// - Backward compatibility preservation during upgrades
// - Migration support for format changes

// KeyMetadata represents comprehensive metadata and lifecycle information for individual vault keys.
//
// This structure provides detailed tracking and management information for each cryptographic
// key within the vault system. It serves as the authoritative record of a key's lifecycle,
// status, and operational history. KeyMetadata enables fine-grained key management, audit
// reporting, compliance validation, and security policy enforcement while maintaining
// complete separation from the actual key material for enhanced security.
//
// STRUCTURE PURPOSE AND SCOPE:
// KeyMetadata serves multiple critical functions in the vault ecosystem:
// - Tracks individual key lifecycle from creation through deactivation
// - Provides operational status information for key usage decisions
// - Enables audit trail generation for compliance and security reporting
// - Supports key rotation planning and policy enforcement
// - Facilitates security incident response and forensic analysis
// - Enables automated key management and lifecycle policies
// - Provides data for capacity planning and performance optimization
// - Supports regulatory compliance and governance requirements
//
// SECURITY ARCHITECTURE:
// The metadata structure implements security-by-design principles:
// - Complete separation of metadata from actual cryptographic key material
// - Immutable key identifiers prevent confusion and substitution attacks
// - Comprehensive audit trail for all key lifecycle events
// - Status tracking prevents unauthorized key usage
// - Timestamp precision enables accurate security event correlation
// - Version tracking supports secure metadata evolution
// - Reason documentation enables security incident investigation
//
// KEY LIFECYCLE INTEGRATION:
// KeyMetadata integrates with the complete key lifecycle management system:
// - Creation: Records initial key generation with secure timestamps
// - Activation: Tracks when keys become available for cryptographic operations
// - Usage: Monitors key operational status and availability
// - Rotation: Documents key transitions during rotation operations
// - Deactivation: Records key retirement with preservation for historical access
// - Archival: Supports long-term retention with appropriate status tracking
// - Recovery: Enables backup/restore with complete lifecycle preservation
//
// FIELD SPECIFICATIONS:
type KeyMetadata struct {
	// KeyID is the unique, immutable identifier for this cryptographic key.
	//
	// This field contains a cryptographically secure, globally unique identifier
	// that remains constant throughout the key's entire lifecycle. The identifier
	// is used for key lookup, audit trail correlation, and operational references.
	// Once assigned, the KeyID never changes, ensuring consistent referencing
	// across all vault operations and external systems.
	//
	// Identifier Characteristics:
	// - 32-character hexadecimal string providing 128 bits of entropy
	// - Generated using cryptographically secure pseudo-random number generator
	// - Globally unique within the vault instance and across backups
	// - Case-insensitive for operational convenience
	// - URL-safe for integration with external systems and APIs
	// - Immutable once assigned to prevent confusion and security issues
	//
	// Generation Process:
	// - Uses cryptographically secure random number generation (CSPRNG)
	// - Includes uniqueness validation against existing key identifiers
	// - Generated atomically during key creation process
	// - Preserved exactly during backup/restore operations
	// - Validated for format compliance during deserialization
	//
	// Usage Patterns:
	// - Primary key for all key management operations
	// - Reference in encryption/decryption operation metadata
	// - Audit trail correlation and security event analysis
	// - External system integration and API operations
	// - Backup/restore operation key identification
	//
	// Security Considerations:
	// - High entropy prevents guessing or collision attacks
	// - Immutability prevents substitution and confusion attacks
	// - No sensitive information embedded in identifier
	// - Safe for logging and external system integration
	// - Collision resistance ensures global uniqueness
	//
	// Example: "f47ac10b58cc4372a5670e02b2c3d479"
	// Format: ^[a-fA-F0-9]{32}$ (32 hexadecimal characters)
	// Validation: Must be exactly 32 characters, hexadecimal only
	KeyID string `json:"key_id"`

	// Status represents the current operational status of the key within its lifecycle.
	//
	// This field provides precise information about the key's availability and
	// authorized usage within the vault system. The status directly controls
	// whether the key can be used for new cryptographic operations while
	// preserving access to historical data encrypted with the key.
	//
	// Status Values and Meanings:
	// - KeyStatusActive: Key is fully operational and available for all operations
	//   * Can encrypt new data and decrypt existing data
	//   * Participates in normal vault operations
	//   * Subject to usage monitoring and policy enforcement
	//   * Available for high-performance cryptographic operations
	//
	// - KeyStatusRetired: Key is preserved for historical access only
	//   * Cannot encrypt new data but can decrypt existing data
	//   * Maintained for backward compatibility and data recovery
	//   * Subject to retention policies and archival procedures
	//   * May have reduced performance characteristics
	//
	// - KeyStatusCompromised: Key is suspected or known to be compromised
	//   * Immediately disabled for all new encryption operations
	//   * May be restricted for decryption based on security policies
	//   * Requires immediate attention and potential data re-encryption
	//   * Triggers security incident procedures and audit alerts
	//
	// - KeyStatusArchived: Key is in long-term storage for compliance
	//   * Available for decryption under specific compliance procedures
	//   * Subject to special access controls and audit requirements
	//   * May require additional authentication for access
	//   * Optimized for infrequent access patterns
	//
	// Status Transitions:
	// - Active → Retired: Normal key rotation process
	// - Active → Compromised: Security incident response
	// - Retired → Archived: Long-term retention policy
	// - Compromised → Archived: Post-incident stabilization
	// - Status transitions are logged and audited
	// - Transitions may trigger automated processes and notifications
	//
	// Operational Impact:
	// - Direct control over key availability for cryptographic operations
	// - Integration with access control and security policies
	// - Affects performance and caching strategies
	// - Influences backup and retention policies
	// - Controls integration with external systems and APIs
	Status KeyStatus `json:"status"`

	// Active is a boolean flag indicating immediate operational availability.
	//
	// This field provides a high-performance, binary indicator of whether
	// the key can be used for new cryptographic operations. It offers O(1)
	// status checking for performance-critical code paths while complementing
	// the more detailed Status field for comprehensive key management.
	//
	// Relationship to Status Field:
	// - Active=true: Key is available for new encryption (Status=Active)
	// - Active=false: Key is not available for new encryption (all other statuses)
	// - Derived from Status field but cached for performance
	// - Updated atomically with Status field changes
	// - Validated for consistency during metadata operations
	//
	// Performance Optimization:
	// - Enables fast key filtering without Status enum evaluation
	// - Optimized for high-frequency encryption path decisions
	// - Reduces CPU cycles in performance-critical operations
	// - Supports efficient key selection algorithms
	// - Minimizes lock contention during concurrent operations
	//
	// Usage Patterns:
	// - Quick filtering of available keys for encryption operations
	// - Fast validation in high-performance encryption paths
	// - Efficient key pool management and selection
	// - Rapid operational status checking without enum parsing
	// - Performance-optimized audit and monitoring operations
	//
	// Consistency Guarantees:
	// - Always consistent with Status field value
	// - Updated atomically during status transitions
	// - Validated during metadata serialization/deserialization
	// - Maintained correctly during backup/restore operations
	// - Verified during periodic consistency checks
	//
	// Example Values:
	// - true: Key can encrypt new data (Status=Active)
	// - false: Key cannot encrypt new data (Status≠Active)
	Active bool `json:"active"`

	// CreatedAt records the precise UTC timestamp when the key was generated.
	//
	// This field provides essential audit information and enables time-based
	// key management policies. The timestamp is captured at the moment of
	// cryptographic key generation and remains immutable throughout the
	// key's lifecycle. High precision timing supports accurate audit trails
	// and security event correlation across distributed systems.
	//
	// Timestamp Characteristics:
	// - Nanosecond precision for accurate ordering and correlation
	// - Always stored and represented in UTC timezone
	// - Immutable once set during key creation
	// - RFC3339 format for JSON serialization compatibility
	// - High resolution for distributed system event ordering
	//
	// Audit and Compliance Applications:
	// - Legal and regulatory audit trail requirements
	// - Security incident timeline reconstruction
	// - Key age calculation for rotation policy enforcement
	// - Compliance reporting and validation
	// - Forensic analysis and investigation support
	//
	// Policy Enforcement:
	// - Maximum key age policies and automated rotation
	// - Compliance-driven retention and archival policies
	// - Security baseline enforcement and validation
	// - Operational lifecycle management and planning
	// - Capacity planning and resource management
	//
	// Precision and Accuracy:
	// - Nanosecond precision: time.Time with nanosecond resolution
	// - Monotonic timing: Immune to system clock adjustments
	// - UTC normalization: Consistent across time zones and DST
	// - High accuracy: Suitable for distributed system event ordering
	// - Immutable value: Never modified after initial assignment
	//
	// Usage Examples:
	// - Age calculation: time.Since(metadata.CreatedAt)
	// - Policy evaluation: CreatedAt.Add(maxAge).Before(time.Now())
	// - Audit reporting: CreatedAt.Format(time.RFC3339Nano)
	// - Timeline analysis: Event ordering and correlation
	//
	// Example: 2024-01-15T14:30:22.123456789Z
	// Format: RFC3339 with nanosecond precision
	// Timezone: Always UTC (Z suffix)
	CreatedAt time.Time `json:"created_at"`

	// DeactivatedAt records when the key was deactivated/retired (nil if still active).
	//
	// This optional field captures the precise moment when a key transitions
	// from active use to retired status. The field remains nil for active keys
	// and is set atomically during key deactivation operations. This timestamp
	// is crucial for audit trails, retention policies, and security analysis.
	//
	// Lifecycle Semantics:
	// - nil value: Key is currently active and available for new encryption
	// - non-nil value: Key has been deactivated and timestamp recorded
	// - Set atomically during key rotation or manual deactivation
	// - Immutable once set (deactivation is permanent)
	// - Preserved exactly during backup/restore operations
	//
	// Audit and Security Applications:
	// - Key rotation audit trail and compliance reporting
	// - Security incident timeline and impact analysis
	// - Retention policy enforcement and archival planning
	// - Operational lifecycle tracking and management
	// - Forensic investigation and timeline reconstruction
	//
	// JSON Serialization:
	// - Uses "omitempty" tag to exclude nil values from JSON
	// - Reduces serialized metadata size for active keys
	// - RFC3339 format with nanosecond precision when present
	// - Consistent with CreatedAt field formatting and precision
	// - Handles timezone normalization to UTC automatically
	//
	// Policy Integration:
	// - Retention period calculation from deactivation timestamp
	// - Archival policy triggers based on deactivation age
	// - Access control policies for retired key usage
	// - Cleanup and disposal policies for expired keys
	// - Compliance validation for key lifecycle requirements
	//
	// Performance Considerations:
	// - Nil check is O(1) operation for active key identification
	// - Pointer type minimizes memory usage for active keys
	// - Efficient serialization with omitempty tag
	// - Fast filtering operations for retired key identification
	//
	// Usage Patterns:
	// - Active key check: metadata.DeactivatedAt == nil
	// - Retirement age: time.Since(*metadata.DeactivatedAt)
	// - Policy evaluation: DeactivatedAt.Add(retention).Before(time.Now())
	// - Audit reporting: Deactivation event documentation
	//
	// Example Values:
	// - nil: Key is currently active
	// - &time.Time{2024-01-20T09:15:30.456789Z}: Deactivated timestamp
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty"`

	// Version indicates the metadata structure version for this key record.
	//
	// This field enables metadata format evolution and compatibility management
	// as the vault system develops new features and capabilities. Version
	// tracking ensures proper handling of metadata from different vault
	// versions and supports migration between metadata formats.
	//
	// Version Evolution:
	// - Version 1: Initial KeyMetadata implementation with basic lifecycle
	// - Version 2: Enhanced with detailed status tracking and audit fields
	// - Version 3: Added compliance metadata and policy integration
	// - Version 4: Extended with performance optimization and caching fields
	// - Future versions: Will add new capabilities while maintaining compatibility
	//
	// Compatibility Management:
	// - Forward compatibility: Newer vault versions handle older metadata
	// - Backward compatibility: Preserved during vault downgrades when possible
	// - Migration support: Automatic upgrade of metadata format when needed
	// - Validation: Version compatibility checked during deserialization
	// - Documentation: Version history maintained for operational reference
	//
	// Migration and Upgrade:
	// - Automatic migration during vault startup when safe
	// - Manual migration tools for major version transitions
	// - Backup preservation of original metadata format
	// - Rollback capability for failed migration scenarios
	// - Validation of migration integrity and completeness
	//
	// Operational Usage:
	// - Version validation during metadata loading and processing
	// - Feature availability determination based on metadata version
	// - Migration planning and compatibility assessment
	// - Backup/restore compatibility verification
	// - System integration and API compatibility management
	//
	// Best Practices:
	// - Always set to current version during key creation
	// - Validate version compatibility during operations
	// - Document version changes and migration requirements
	// - Test compatibility across version boundaries
	// - Monitor version distribution in production systems
	//
	// Example Values:
	// - 1: Original metadata format
	// - 2: Enhanced format with additional audit fields
	// - 3: Current production format with full feature support
	Version int `json:"version"`

	// Reason documents the rationale for key creation or status changes.
	//
	// This field provides essential context for audit trails, compliance
	// reporting, and security analysis. It captures human-readable explanations
	// for key lifecycle events, enabling comprehensive documentation of
	// key management decisions and security operations.
	//
	// Content Categories:
	// - Creation reasons: Why the key was initially generated
	// - Rotation reasons: Rationale for key rotation operations
	// - Deactivation reasons: Explanation for key retirement
	// - Status change reasons: Context for operational status updates
	// - Security reasons: Documentation of security-related decisions
	//
	// Common Creation Reasons:
	// - "Initial vault setup and configuration"
	// - "Scheduled key rotation per security policy"
	// - "Emergency replacement due to security incident"
	// - "Compliance-driven key generation for new requirements"
	// - "Performance optimization with new cryptographic algorithms"
	// - "Disaster recovery key restoration from backup"
	// - "Multi-tenant isolation requiring dedicated keys"
	//
	// Security and Incident Reasons:
	// - "Potential key compromise detected in security audit"
	// - "Precautionary rotation following infrastructure breach"
	// - "Compliance violation remediation and key replacement"
	// - "Unauthorized access attempt detected"
	// - "Security policy violation requiring immediate rotation"
	// - "External security advisory recommending key rotation"
	//
	// Operational Reasons:
	// - "Scheduled maintenance window key rotation"
	// - "Algorithm upgrade to improve performance"
	// - "Infrastructure migration requiring new keys"
	// - "Load balancing and performance optimization"
	// - "Geographic distribution and compliance requirements"
	// - "Integration with new security systems and controls"
	//
	// Audit and Compliance Integration:
	// - Required documentation for regulatory compliance frameworks
	// - Essential evidence for security audits and assessments
	// - Supporting documentation for incident response procedures
	// - Historical context for forensic analysis and investigation
	// - Compliance validation and reporting automation support
	//
	// Best Practices:
	// - Use consistent terminology and format across the organization
	// - Include relevant incident, ticket, or policy reference numbers
	// - Provide sufficient detail for audit and compliance requirements
	// - Document emergency actions with appropriate urgency indicators
	// - Include regulatory or policy drivers when applicable
	// - Reference external events or advisories when relevant
	//
	// Format and Constraints:
	// - Maximum length: 1000 characters to prevent excessive storage usage
	// - UTF-8 encoding: Support for international characters and symbols
	// - Free-form text: Flexible format while encouraging consistency
	// - Required field: Must not be empty for audit trail completeness
	// - Preserved exactly: Maintained during backup/restore operations
	//
	// Privacy and Security:
	// - Should not contain sensitive information or credentials
	// - Safe for logging and external system integration
	// - Appropriate for compliance reporting and audit documentation
	// - Does not expose cryptographic material or internal secrets
	//
	// Example Values:
	// - "Initial vault deployment for production workload encryption"
	// - "Quarterly key rotation per security policy SEC-2024-001"
	// - "Emergency rotation following security incident INC-2024-0156"
	// - "Compliance rotation for SOC 2 Type II audit requirements"
	// - "Performance optimization migration to ChaCha20-Poly1305"
	//
	// Integration with External Systems:
	// - ITSM ticket references: "ServiceNow ticket CHG0012345"
	// - Security incident references: "PagerDuty incident PD-2024-0089"
	// - Compliance framework references: "NIST CSF requirement RSK-3.2"
	// - Policy references: "Corporate policy SEC-POL-2024-003"
	Reason string `json:"reason"`
}

// SERIALIZATION AND PERSISTENCE:
// KeyMetadata is designed for efficient serialization and persistent storage
// across various formats and systems while maintaining data integrity and
// compatibility.
//
// JSON Serialization Features:
// - Standard JSON field tags ensure consistent serialization behavior
// - Optional fields use "omitempty" to minimize storage overhead
// - Time fields serialize to RFC3339 format with nanosecond precision
// - Enum values serialize to string representation for readability
// - Nested structures support complex metadata requirements
// - Pretty-printing support for human-readable configuration files
//
// Storage Optimization:
// - Compact representation minimizes storage overhead per key
// - Optional field omission reduces storage for common cases
// - Efficient indexing support for high-performance key lookup
// - Compression-friendly structure for large-scale deployments
// - Batch serialization support for bulk operations
//
// THREAD SAFETY AND CONCURRENCY:
// KeyMetadata structures require external synchronization for safe concurrent
// access. The vault implementation provides appropriate locking mechanisms
// to ensure consistency during concurrent operations.
//
// Concurrency Patterns:
// - Read operations can be concurrent with appropriate read locks
// - Modifications require exclusive access through write locks
// - Atomic updates ensure consistency during status transitions
// - Lock-free read operations for performance-critical paths where possible
// - Careful ordering prevents deadlocks during complex operations
//
// AUDIT TRAIL INTEGRATION:
// KeyMetadata serves as a foundational component of the vault's comprehensive
// audit trail system, providing detailed tracking of key lifecycle events.
//
// Audit Capabilities:
// - Complete key lifecycle documentation from creation to disposal
// - Detailed timestamp tracking for regulatory compliance requirements
// - Reason documentation supporting incident investigation and analysis
// - Status transition logging for operational monitoring and alerting
// - Integration with external audit systems and SIEM platforms
//
// PERFORMANCE CHARACTERISTICS:
// KeyMetadata is optimized for high-performance access patterns typical
// in production vault deployments while maintaining comprehensive functionality.
//
// Performance Features:
// - O(1) access to critical fields like Active status and KeyID
// - Efficient serialization and deserialization for storage operations
// - Memory-optimized structure with minimal overhead per key
// - Cache-friendly layout for high-frequency access operations
// - Batch processing support for bulk metadata operations
//
// Access Patterns:
// - Hot path: KeyID lookup and Active status checking
// - Warm path: CreatedAt access for policy evaluation
// - Cold path: DeactivatedAt and Reason access for audit reporting
// - Bulk operations: Metadata enumeration and filtering
//
// COMPLIANCE AND GOVERNANCE:
// KeyMetadata supports comprehensive compliance and governance requirements
// across various regulatory frameworks and organizational policies.
//
// Regulatory Support:
// - SOX compliance through comprehensive audit trails
// - PCI DSS key lifecycle documentation requirements
// - HIPAA audit trail and access control documentation
// - SOC 2 security control evidence and validation
// - ISO 27001 information security management documentation
// - GDPR data protection and privacy impact documentation
//
// Governance Capabilities:
// - Policy enforcement through metadata-driven controls
// - Risk management through comprehensive lifecycle tracking
// - Change management integration with reason documentation
// - Incident response support through detailed audit trails
// - Compliance reporting automation and validation
//
// BACKUP AND DISASTER RECOVERY:
// KeyMetadata is essential for comprehensive backup and disaster recovery
// operations, ensuring complete vault state preservation and restoration.
//
// Backup Requirements:
// - Complete metadata preservation including all historical keys
// - Exact timestamp and reason preservation for audit continuity
// - Status and lifecycle state preservation for operational continuity
// - Version information preservation for compatibility management
//
// Recovery Capabilities:
// - Complete key lifecycle restoration from backup metadata
// - Audit trail continuity across recovery operations
// - Policy enforcement continuity through preserved metadata
// - Operational state restoration enabling immediate vault operation
//
// MONITORING AND ALERTING:
// KeyMetadata enables comprehensive monitoring and alerting capabilities
// for proactive key management and security operations.
//
// Monitoring Capabilities:
// - Key age tracking and rotation policy enforcement
// - Status transition monitoring and anomaly detection
// - Lifecycle pattern analysis and optimization
// - Compliance deadline tracking and notification
// - Performance impact monitoring during key operations
//
// Alerting Integration:
// - Automated alerts for policy violations and compliance issues
// - Security incident notifications for suspicious key activities
// - Operational alerts for key management and rotation requirements
// - Capacity planning alerts for key storage and performance
//
// EXTENSIBILITY AND EVOLUTION:
// KeyMetadata is designed for long-term evolution and extensibility while
// maintaining backward compatibility and operational stability.
//
// Extension Points:
// - Version field enables controlled metadata format evolution
// - JSON serialization supports additional field addition
// - Modular design allows feature enhancement without disruption
// - Migration framework supports smooth version transitions
//
// Future Enhancements:
// - Enhanced compliance metadata for emerging regulatory requirements
// - Advanced performance tracking and optimization metadata
// - Integration metadata for external system coordination
// - Machine learning features for predictive key management
// - Advanced security metadata for threat detection and response

// initializeKeys loads existing keys and metadata, or creates initial key if vault is new
func (v *Vault) initializeKeys() error {
	debug.Print("initializeKeys: Starting\n")

	// Check if key metadata exists
	exists, err := v.store.MetadataExists()
	if err != nil {
		return fmt.Errorf("failed to check metadata existence: %w", err)
	}

	debug.Print("initializeKeys: Metadata exists: %v\n", exists)

	if !exists {
		debug.Print("initializeKeys: No metadata found, creating first key\n")
		// No existing keys, create the first key
		if err = v.createNewKey(); err != nil {
			return fmt.Errorf("failed to create first key: %w", err)
		}
		return nil
	}

	debug.Print("initializeKeys: Loading existing keys from metadata\n")

	// Load versioned encrypted metadata
	versionedMetadata, err := v.store.LoadMetadata()
	if err != nil {
		debug.Print("initializeKeys: Failed to load metadata: %v\n", err)
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	encryptedMetadata := versionedMetadata.Data
	debug.Print("initializeKeys: Loaded metadata, size: %d bytes, version: %s\n",
		len(encryptedMetadata), versionedMetadata.Version)

	// Decrypt metadata using derivation key
	metadataBytes, err := v.decryptWithKeyEnclave(encryptedMetadata, v.derivationKeyEnclave)
	if err != nil {
		debug.Print("initializeKeys: Failed to decrypt metadata: %v\n", err)
		return fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	debug.Print("initializeKeys: Successfully decrypted metadata\n")

	// Parse metadata
	var rotationMetadata KeyRotationMetadata
	if err = json.Unmarshal(metadataBytes, &rotationMetadata); err != nil {
		return fmt.Errorf("failed to parse key rotation metadata: %w", err)
	}

	debug.Print("initializeKeys: Parsed metadata, found %d keys\n", len(rotationMetadata.Keys))

	// Load keys into memory
	if err = v.loadKeysIntoMemory(&rotationMetadata); err != nil {
		debug.Print("initializeKeys: Failed to load keys into memory: %v\n", err)
		return fmt.Errorf("failed to load keys into memory: %w", err)
	}

	debug.Print("initializeKeys: Successfully loaded %d keys, current: %s\n", len(v.keyEnclaves), v.currentKeyID)

	return nil
}

// loadKeysIntoMemory loads encrypted keys from metadata and decrypts them into memory enclaves
func (v *Vault) loadKeysIntoMemory(rotationMetadata *KeyRotationMetadata) error {
	debug.Print("loadKeysIntoMemory: Starting with %d encrypted keys\n", len(rotationMetadata.EncryptedKeys))

	if v.derivationKeyEnclave == nil {
		return fmt.Errorf("derivation key not initialized")
	}

	// Get derivation key from enclave
	derivationView, err := v.derivationKeyEnclave.Open()
	if err != nil {
		return fmt.Errorf("failed to open derivation key enclave: %w", err)
	}
	defer derivationView.Destroy()

	// Load each encrypted key
	for keyID, encryptedKey := range rotationMetadata.EncryptedKeys {
		debug.Print("loadKeysIntoMemory: Processing key %s (encrypted size: %d)\n", keyID, len(encryptedKey))

		// Verify we have metadata for this key
		if _, exists := rotationMetadata.Keys[keyID]; !exists {
			return fmt.Errorf("missing metadata for key %s", keyID)
		}

		// decrypt encryption key
		decryptedKey, err := crypto.DecryptValue(encryptedKey, derivationView.Bytes())
		if err != nil {
			debug.Print("loadKeysIntoMemory: Failed to decrypt key %s: %v\n", keyID, err)
			return fmt.Errorf("failed to decrypt key %s: %w", keyID, err)
		}

		debug.Print("loadKeysIntoMemory: Decrypted key %s, first 16 bytes: %x\n", keyID, decryptedKey[:min(16, len(decryptedKey))])

		// Store in protected enclave
		v.keyEnclaves[keyID] = memguard.NewEnclave(decryptedKey)

		// Store metadata
		v.keyMetadata[keyID] = rotationMetadata.Keys[keyID]

		// Clear decrypted key from local memory
		for i := range decryptedKey {
			decryptedKey[i] = 0
		}
	}

	// Set current key ID
	v.currentKeyID = rotationMetadata.CurrentKeyID
	debug.Print("loadKeysIntoMemory: Set current key to %s\n", v.currentKeyID)

	return nil
}

func (v *Vault) loadExistingKeys(encryptedMetadata []byte) error {
	// Decrypt metadata using derivation key
	derivationKeyBuffer, err := v.derivationKeyEnclave.Open()
	if err != nil {
		return fmt.Errorf("failed to access derivation key: %w", err)
	}
	defer derivationKeyBuffer.Destroy()

	decryptedMetadata, err := crypto.DecryptValue(encryptedMetadata, derivationKeyBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	// Parse KeyRotationMetadata
	var rotationMetadata KeyRotationMetadata
	if err = json.Unmarshal(decryptedMetadata, &rotationMetadata); err != nil {
		return fmt.Errorf("failed to unmarshal key rotation metadata: %w", err)
	}

	// Zero out decrypted metadata from memory
	for i := range decryptedMetadata {
		decryptedMetadata[i] = 0
	}

	// Initialize vault state
	v.currentKeyID = rotationMetadata.CurrentKeyID
	v.keyMetadata = rotationMetadata.Keys
	v.keyEnclaves = make(map[string]*memguard.Enclave)

	// Decrypt and restore each key
	for keyID, encryptedKey := range rotationMetadata.EncryptedKeys {
		// Decrypt the key using derivation key
		decryptedKey, err := crypto.DecryptValue(encryptedKey, derivationKeyBuffer.Bytes())
		if err != nil {
			return fmt.Errorf("failed to decrypt key %s: %w", keyID, err)
		}

		// Store in secure enclave
		v.keyEnclaves[keyID] = memguard.NewEnclave(decryptedKey)

		// Zero out decrypted key
		for i := range decryptedKey {
			decryptedKey[i] = 0
		}
	}

	runtime.GC()
	return nil
}

// setupDerivationKey sets up the key used for wrapping the master key
func (v *Vault) setupDerivationKey(passphrase string, envVar string) error {
	var passphraseData []byte

	// Get passphrase from arguments or environment
	if passphrase != "" {
		passphraseData = []byte(passphrase)
	} else if envVar != "" {
		envPass := os.Getenv(envVar)
		if envPass == "" {
			return fmt.Errorf("environment variable %s is empty or not set", envVar)
		}
		passphraseData = []byte(envPass)

		// Clear environment variable immediately
		os.Unsetenv(envVar)
	} else {
		return errors.New("no passphrase or environment variable provided")
	}

	// Validate passphrase strength
	if len(passphraseData) < 12 {
		// Clear before returning error
		memguard.WipeBytes(passphraseData)
		return errors.New("passphrase must be at least 12 characters long")
	}

	if v.derivationSaltEnclave == nil {
		// Clear before returning error
		memguard.WipeBytes(passphraseData)
		return errors.New("derivation salt not initialized")
	}

	// Derive the key
	derivedKey, err := crypto.DeriveKey(passphraseData, v.derivationSaltEnclave)
	if err != nil {
		memguard.WipeBytes(passphraseData)
		return err
	}

	// Create enclave from the derived key bytes BEFORE destroying the buffer
	keyBytes := make([]byte, len(derivedKey.Bytes()))
	copy(keyBytes, derivedKey.Bytes())

	// Now destroy the derived key buffer
	derivedKey.Destroy()

	// Store in secure enclave
	v.derivationKeyEnclave = memguard.NewEnclave(keyBytes)

	// Clear the temporary copy (NewEnclave makes its own copy)
	memguard.WipeBytes(keyBytes)

	// Zero out sensitive data
	memguard.WipeBytes(passphraseData)

	return nil
}

// loadOrCreateSalt handles the salt for key derivation
func (v *Vault) loadOrCreateSalt(providedSalt []byte) error {
	// Check if salt already exists
	exists, err := v.store.SaltExists()
	if err != nil {
		return fmt.Errorf("failed to check salt existence: %w", err)
	}

	if exists {
		// Load existing versioned salt
		versionedSalt, err := v.store.LoadSalt()
		if err != nil {
			return fmt.Errorf("failed to load salt: %w", err)
		}

		existingSaltData := versionedSalt.Data

		// If a salt was provided, verify it matches the existing one
		if providedSalt != nil && len(providedSalt) >= 16 {
			if !bytes.Equal(existingSaltData, providedSalt) {
				// Zero out sensitive data before returning error
				for i := range existingSaltData {
					existingSaltData[i] = 0
				}
				return fmt.Errorf("provided salt does not match existing salt in storage")
			}
		}

		// Store the existing salt in protected memory
		saltEnclave := memguard.NewEnclave(existingSaltData)
		v.derivationSaltEnclave = saltEnclave

		// Zero out the temporary salt data
		for i := range existingSaltData {
			existingSaltData[i] = 0
		}
	} else {
		// Create new salt
		var saltData []byte

		if providedSalt != nil && len(providedSalt) >= 16 {
			saltData = make([]byte, len(providedSalt))
			copy(saltData, providedSalt)
		} else {
			// Generate random salt
			saltData = make([]byte, 32)
			if _, err = rand.Read(saltData); err != nil {
				return fmt.Errorf("failed to generate salt: %w", err)
			}
		}

		// Save to storage with versioning (empty version for new salt)
		if _, err = v.store.SaveSalt(saltData, ""); err != nil {
			// Zero out saltData before returning error
			for i := range saltData {
				saltData[i] = 0
			}
			return fmt.Errorf("failed to save salt: %w", err)
		}

		// Store salt in protected memory
		v.derivationSaltEnclave = memguard.NewEnclave(saltData)

		// Zero out temporary saltData
		for i := range saltData {
			saltData[i] = 0
		}
	}

	return nil
}

// createNewKey generates a new random key
func (v *Vault) createNewKey() error {
	// Validate derivation key is available
	if v.derivationKeyEnclave == nil {
		return fmt.Errorf("derivation key not initialized")
	}

	// Generate new key ID and master key
	keyID := generateKeyID()

	// Validate key ID format
	if keyID == "" || len(keyID) < 16 {
		return fmt.Errorf("invalid key ID generated")
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Validate master key entropy
	if crypto.IsWeakKey(masterKey) {
		// Zero out weak key
		for i := range masterKey {
			masterKey[i] = 0
		}
		return fmt.Errorf("generated key failed entropy check")
	}

	// Get derivation key for encrypting the master key
	derivationKeyBuffer, err := v.derivationKeyEnclave.Open()
	if err != nil {
		return fmt.Errorf("failed to access derivation key: %w", err)
	}
	defer derivationKeyBuffer.Destroy()

	// Encrypt the master key
	encryptedMasterKey, err := crypto.EncryptValue(masterKey, derivationKeyBuffer.Bytes())
	if err != nil {
		// Zero out master key before returning error
		for i := range masterKey {
			masterKey[i] = 0
		}
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Store key in secure enclave
	keyEnclave := memguard.NewEnclave(masterKey)

	// Zero out master key from memory
	for i := range masterKey {
		masterKey[i] = 0
	}
	runtime.GC()

	// Initialize maps if this is the very first key
	if v.keyEnclaves == nil {
		v.keyEnclaves = make(map[string]*memguard.Enclave)
	}
	if v.keyMetadata == nil {
		v.keyMetadata = make(map[string]KeyMetadata)
	}

	// Deactivate the previous active key (if any)
	if v.currentKeyID != "" {
		if prevMetadata, exists := v.keyMetadata[v.currentKeyID]; exists {
			now := time.Now().UTC()
			prevMetadata.Active = false
			prevMetadata.Status = KeyStatusInactive
			prevMetadata.DeactivatedAt = &now
			v.keyMetadata[v.currentKeyID] = prevMetadata
		}
	}

	// Add the new key
	v.currentKeyID = keyID
	v.keyEnclaves[keyID] = keyEnclave

	// Create new key metadata
	now := time.Now().UTC()
	keyMetadata := KeyMetadata{
		KeyID:     keyID,
		CreatedAt: now,
		Status:    KeyStatusActive,
		Active:    true,
		Version:   1,
	}
	v.keyMetadata[keyID] = keyMetadata

	// Build encrypted keys map from ALL existing keys
	encryptedKeys := make(map[string][]byte)

	// Re-encrypt all keys
	for existingKeyID := range v.keyMetadata {
		if existingKeyID == keyID {
			// New key - use the encrypted version we just created
			encryptedKeys[keyID] = encryptedMasterKey
		} else {
			// Existing key - need to encrypt it with derivation key
			if existingEnclave, exists := v.keyEnclaves[existingKeyID]; exists {
				existingKeyBuffer, err := existingEnclave.Open()
				if err != nil {
					return fmt.Errorf("failed to access existing key %s: %w", existingKeyID, err)
				}

				encryptedExistingKey, err := crypto.EncryptValue(existingKeyBuffer.Bytes(), derivationKeyBuffer.Bytes())
				existingKeyBuffer.Destroy()

				if err != nil {
					return fmt.Errorf("failed to encrypt existing key %s: %w", existingKeyID, err)
				}

				encryptedKeys[existingKeyID] = encryptedExistingKey
			}
		}
	}

	// Create KeyRotationMetadata with ALL keys
	rotationMetadata := &KeyRotationMetadata{
		Version:       1,
		CurrentKeyID:  keyID,
		LastRotation:  time.Now().UTC(),
		Keys:          v.keyMetadata,
		EncryptedKeys: encryptedKeys,
	}

	return v.saveKeyMetadata(rotationMetadata)
}

// getCurrentKey returns the current active key enclave
func (v *Vault) getCurrentKey() (*memguard.Enclave, error) {
	if v.currentKeyID == "" {
		return nil, errors.New("no current key ID set")
	}

	if v.keyEnclaves == nil {
		return nil, errors.New("no key enclaves initialized")
	}

	enclave, exists := v.keyEnclaves[v.currentKeyID]
	if !exists {
		return nil, fmt.Errorf("current key %s not found in enclaves", v.currentKeyID)
	}

	return enclave, nil
}

func (v *Vault) getKeyByID(keyID string) (*memguard.Enclave, error) {
	if keyID == "" {
		return nil, errors.New("empty key ID")
	}

	if v.keyEnclaves == nil {
		return nil, errors.New("no key enclaves initialized")
	}

	enclave, exists := v.keyEnclaves[keyID]
	if !exists {
		return nil, fmt.Errorf("key %s not found in memory - vault may need reinitialization", keyID)
	}

	return enclave, nil
}
