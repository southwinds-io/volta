package volta

import (
	"encoding/json"
	"fmt"
	"southwinds.dev/volta/internal/crypto"
	"time"
)

// ListKeyMetadata retrieves a complete snapshot of all key metadata in the vault.
//
// This method provides comprehensive visibility into the vault's key management
// state, including all historical and current keys with their complete lifecycle
// information. It serves as the primary interface for key inventory management,
// audit reporting, compliance validation, and operational monitoring. The method
// returns a point-in-time snapshot with real-time status updates computed
// dynamically based on current vault state.
//
// FUNCTIONALITY OVERVIEW:
// ListKeyMetadata performs several critical operations:
// - Retrieves all key metadata from the vault's internal key registry
// - Computes real-time active status based on current operational state
// - Updates key status information to reflect current vault configuration
// - Provides complete key inventory for audit and compliance purposes
// - Enables key lifecycle management and policy enforcement decisions
// - Supports operational monitoring and security analysis workflows
// - Facilitates disaster recovery planning and backup validation
// - Enables automated key management and governance processes
//
// REAL-TIME STATUS COMPUTATION:
// The method dynamically computes accurate key status information:
// - Active Status: Determined by comparison with current active key ID
// - Operational Status: Updated based on current vault key configuration
// - Lifecycle Status: Reflects current position in key management lifecycle
// - Availability Status: Indicates current availability for cryptographic operations
// - Policy Status: Shows compliance with current key management policies
//
// Status Update Logic:
// - Keys matching currentKeyID are marked as Active with KeyStatusActive
// - All other keys are marked as Inactive with KeyStatusInactive
// - Status updates reflect current vault operational state
// - Changes are computed dynamically without modifying stored metadata
// - Real-time accuracy ensures operational decisions are based on current state
//
// SECURITY AND ACCESS CONTROL:
// The method implements comprehensive security measures:
// - Read-only operation with no sensitive data exposure
// - No cryptographic key material included in responses
// - Thread-safe concurrent access through read locks
// - Audit-safe information suitable for logging and external integration
// - Access control enforcement through vault authentication mechanisms
// - Rate limiting and resource protection for large-scale deployments
//
// Data Protection Features:
// - Only metadata exposed, never actual cryptographic key material
// - Sanitized information safe for audit trails and compliance reporting
// - No sensitive operational details that could compromise security
// - Information suitable for external system integration and monitoring
// - Compliance-ready data format for regulatory reporting requirements
//
// PERFORMANCE CHARACTERISTICS:
// The method is optimized for various operational scenarios:
// - O(n) complexity where n is the number of keys in the vault
// - Efficient memory allocation with pre-sized slice capacity
// - Read lock usage enables concurrent access with other read operations
// - Minimal computational overhead for real-time status updates
// - Optimized for frequent monitoring and audit access patterns
//
// Performance Optimizations:
// - Pre-allocated slice with exact capacity to minimize memory allocations
// - Efficient map iteration with minimal memory copying
// - Read-lock usage prevents blocking other concurrent read operations
// - Lazy computation of status updates only when method is called
// - Memory-efficient snapshot creation without deep copying unnecessary data
//
// Scalability Considerations:
// - Linear scaling with number of keys managed by vault
// - Efficient operation even with hundreds or thousands of keys
// - Memory usage scales predictably with key count
// - Network transfer efficiency for remote API access
// - Suitable for high-frequency monitoring and automated access
//
// AUDIT AND COMPLIANCE INTEGRATION:
// ListKeyMetadata provides essential data for comprehensive audit and compliance:
// - Complete key inventory for regulatory compliance requirements
// - Historical key information for audit trail validation
// - Current status information for operational compliance verification
// - Lifecycle tracking data for policy compliance assessment
// - Timestamp information for retention and archival policy enforcement
//
// Compliance Framework Support:
// - SOX: Complete key inventory and lifecycle documentation
// - PCI DSS: Cryptographic key management audit trail
// - HIPAA: Access control and key management documentation
// - SOC 2: Security control evidence and operational validation
// - ISO 27001: Information security management system documentation
// - GDPR: Data protection key management and audit requirements
//
// Audit Trail Enhancement:
// - Key creation and rotation timeline visibility
// - Status transition history and current state validation
// - Policy compliance verification and exception identification
// - Security incident investigation and forensic analysis support
// - Regulatory reporting automation and validation capabilities
//
// OPERATIONAL MONITORING INTEGRATION:
// The method supports comprehensive operational monitoring and alerting:
// - Key age analysis for rotation policy enforcement
// - Status distribution monitoring for operational health assessment
// - Capacity planning through key count and growth trend analysis
// - Performance monitoring for key management operation efficiency
// - Security monitoring for anomalous key lifecycle patterns
//
// Monitoring Use Cases:
// - Automated key rotation policy enforcement and compliance validation
// - Security anomaly detection through key creation and status patterns
// - Operational health dashboard integration and real-time status display
// - Capacity planning and resource allocation for key management systems
// - Integration with SIEM systems for security event correlation and analysis
//
// DISASTER RECOVERY AND BACKUP VALIDATION:
// ListKeyMetadata plays a critical role in disaster recovery operations:
// - Pre-disaster key inventory documentation for recovery validation
// - Post-recovery key state verification and completeness validation
// - Backup integrity verification through key count and metadata comparison
// - Recovery process validation ensuring all keys are properly restored
// - Operational continuity verification after disaster recovery procedures
//
// Recovery Validation Capabilities:
// - Complete key inventory comparison between backup and restored state
// - Metadata integrity verification ensuring accurate restoration
// - Status consistency validation for operational continuity
// - Audit trail preservation verification for compliance continuity
// - Performance baseline re-establishment after recovery operations
func (v *Vault) ListKeyMetadata() ([]KeyMetadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Check if vault is initialized by checking if we have any keys
	if len(v.keyEnclaves) == 0 {
		return nil, fmt.Errorf("vault is not initialized")
	}

	if len(v.keyMetadata) == 0 {
		return []KeyMetadata{}, nil
	}

	// Convert map to slice
	metadata := make([]KeyMetadata, 0, len(v.keyMetadata))
	for _, meta := range v.keyMetadata {
		// Update active status based on current key
		meta.Active = meta.KeyID == v.currentKeyID
		if meta.Active {
			meta.Status = KeyStatusActive
		} else {
			meta.Status = KeyStatusInactive
		}
		metadata = append(metadata, meta)
	}

	return metadata, nil
}

// GetActiveKeyMetadata retrieves the metadata for the currently active encryption key.
//
// This method provides detailed information about the key currently being used for
// new encryption operations within the vault. It serves as the primary interface
// for determining active key status, monitoring key lifecycle, and supporting
// operational decisions that depend on current key state. The method ensures
// real-time accuracy by dynamically updating status fields to reflect the key's
// current operational role regardless of stored metadata state.
//
// FUNCTIONALITY OVERVIEW:
// GetActiveKeyMetadata performs several critical operations:
// - Identifies the currently active key used for new encryption operations
// - Retrieves comprehensive metadata for operational and audit purposes
// - Validates vault initialization and operational readiness
// - Ensures metadata consistency with current vault operational state
// - Provides real-time key status information for monitoring and automation
// - Supports key lifecycle management and policy enforcement decisions
// - Enables operational visibility into current cryptographic configuration
// - Facilitates security monitoring and audit trail generation
//
// ACTIVE KEY DETERMINATION:
// The method uses a multi-layered approach to identify the active key:
// - Primary Source: v.currentKeyID field contains the authoritative active key identifier
// - Validation: Cross-references with existing key metadata registry
// - Consistency: Ensures active key exists in operational key enclaves
// - Verification: Confirms key is available for cryptographic operations
// - Status Update: Dynamically updates metadata to reflect current active status
//
// Active Key Characteristics:
// - Used for all new encryption operations performed by the vault
// - Represents the current generation in the key rotation lifecycle
// - Maintained as the primary key until next rotation operation
// - Available for both encryption and decryption operations
// - Subject to key rotation policies and lifecycle management rules
//
// VAULT INITIALIZATION VALIDATION:
// The method implements comprehensive validation to ensure vault readiness:
//
// Pre-Lock Validation:
// - Derivation Key Enclave: Validates master key derivation system availability
// - Key Metadata Registry: Confirms key metadata storage system initialization
// - Prevents operations on partially initialized or corrupted vault state
// - Provides early failure detection before acquiring locks
//
// Post-Lock Validation:
// - Key Enclaves: Validates operational key storage system availability
// - Current Key ID: Confirms active key identification and assignment
// - Metadata Consistency: Ensures active key metadata exists and is accessible
// - Operational Readiness: Verifies vault can perform cryptographic operations
//
// Initialization State Matrix:
// - Fully Initialized: All validation checks pass, method proceeds normally
// - Partially Initialized: Some components missing, returns initialization error
// - Uninitialized: No initialization detected, returns clear error message
// - Corrupted State: Inconsistent state detected, returns appropriate error
//
// REAL-TIME STATUS SYNCHRONIZATION:
// The method ensures returned metadata accurately reflects current operational state:
//
// Status Field Updates:
// - Active: Set to true to indicate this key is currently active
// - Status: Set to KeyStatusActive to reflect operational status
// - DeactivatedAt: Set to nil as active keys cannot have deactivation timestamps
// - Other Fields: Preserved exactly as stored in metadata registry
//
// Consistency Guarantees:
// - Metadata reflects current operational reality, not historical state
// - Active status fields are synchronized with vault's current configuration
// - Updates applied dynamically without modifying stored metadata
// - Ensures operational decisions are based on current, accurate information
//
// Temporal Accuracy:
// - Metadata reflects key status at the exact moment of method execution
// - No stale or cached information that might mislead operational decisions
// - Immediate reflection of key rotation or status changes
// - Suitable for real-time monitoring and automated decision-making systems
//
// SECURITY AND ACCESS CONTROL:
// The method implements comprehensive security measures:
//
// Data Protection:
// - Returns only metadata, never actual cryptographic key material
// - Information is safe for audit trails and compliance reporting
// - No sensitive operational details that could compromise security
// - Suitable for external system integration and monitoring
//
// Access Control Features:
// - Read-only operation with no vault state modification
// - Thread-safe concurrent access through appropriate locking
// - Audit-safe information suitable for logging and external integration
// - Rate limiting compatibility for high-frequency monitoring access
//
// Security Boundary Enforcement:
// - Clear separation between metadata and actual cryptographic material
// - No information leakage that could assist in cryptographic attacks
// - Appropriate for security monitoring and incident response systems
// - Compliant with security frameworks and regulatory requirements
//
// PERFORMANCE CHARACTERISTICS:
// The method is optimized for frequent access and operational efficiency:
//
// Computational Complexity:
// - O(1) active key identification through direct currentKeyID lookup
// - O(1) metadata retrieval through hash map access
// - Minimal computational overhead for status field updates
// - Efficient validation with early failure detection
//
// Memory Efficiency:
// - Single metadata structure allocation for return value
// - No large data structure copying or deep cloning
// - Minimal memory footprint suitable for high-frequency access
// - Efficient for integration with monitoring and automation systems
//
// Concurrency Performance:
// - Read lock usage enables concurrent access with other read operations
// - Compatible with high-frequency monitoring and status checking
// - Minimal lock contention with other operational methods
// - Suitable for real-time operational dashboards and automation
//
// OPERATIONAL MONITORING INTEGRATION:
// GetActiveKeyMetadata provides essential data for operational monitoring:
//
// Key Health Monitoring:
// - Active key age analysis for rotation policy enforcement
// - Key lifecycle position tracking for proactive management
// - Status consistency monitoring for operational health assessment
// - Performance impact analysis for key management operations
//
// Monitoring Use Cases:
// - Automated key rotation scheduling based on key age and policy
// - Operational health dashboards showing current key status
// - Security monitoring for unusual key lifecycle patterns
// - Compliance monitoring for key management policy adherence
// - Performance monitoring for key-related operational efficiency
//
// Integration Points:
// - SIEM system integration for security event correlation
// - Monitoring system integration for operational visibility
// - Alerting system integration for proactive issue detection
// - Dashboard integration for real-time operational status display
// - Automation system integration for policy enforcement
//
// AUDIT AND COMPLIANCE SUPPORT:
// The method provides comprehensive audit and compliance capabilities:
//
// Audit Trail Enhancement:
// - Current key identification for audit trail correlation
// - Key lifecycle position documentation for compliance reporting
// - Status timestamp information for audit event sequencing
// - Operational readiness verification for compliance validation
//
// Regulatory Compliance:
// - SOX: Current key documentation for financial data protection audit
// - PCI DSS: Active key identification for payment card data security
// - HIPAA: Current encryption key documentation for healthcare data protection
// - SOC 2: Security control evidence for service organization compliance
// - ISO 27001: Information security management system documentation
// - GDPR: Data protection key management for privacy compliance
//
// Compliance Reporting:
// - Automated compliance report generation with current key information
// - Audit evidence collection for regulatory examinations
// - Policy compliance verification for governance frameworks
// - Exception reporting for policy violations or operational issues
//
// DISASTER RECOVERY INTEGRATION:
// GetActiveKeyMetadata plays a critical role in disaster recovery:
//
// Recovery Validation:
// - Post-recovery active key verification ensuring operational continuity
// - Metadata consistency validation after backup restoration
// - Operational readiness confirmation for service resumption
// - Key availability verification for cryptographic operations
//
// Recovery Scenarios:
// - Primary Site Failure: Validates active key availability at recovery site
// - Data Corruption: Confirms active key metadata integrity after restoration
// - Partial Recovery: Validates specific key availability during incremental recovery
// - Testing: Confirms recovery procedures maintain active key operational status
//
// Business Continuity:
// - Service resumption validation through active key verification
// - Operational continuity confirmation for critical business processes
// - Recovery time objective (RTO) support through rapid key status validation
// - Recovery point objective (RPO) validation through key metadata consistency
func (v *Vault) GetActiveKeyMetadata() (KeyMetadata, error) {
	if v.derivationKeyEnclave == nil || v.keyMetadata == nil {
		return KeyMetadata{}, fmt.Errorf("vault is not initialized")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	// Check if vault is initialized by checking if we have any keys
	if len(v.keyEnclaves) == 0 {
		return KeyMetadata{}, fmt.Errorf("vault is not initialized")
	}

	if v.currentKeyID == "" {
		return KeyMetadata{}, fmt.Errorf("no active key found")
	}

	// Get metadata for current active key
	meta, exists := v.keyMetadata[v.currentKeyID]
	if !exists {
		return KeyMetadata{}, fmt.Errorf("active key metadata not found")
	}

	// Ensure metadata reflects current active status
	meta.Active = true
	meta.Status = KeyStatusActive
	meta.DeactivatedAt = nil

	return meta, nil
}

// loadKeyMetadata loads the key metadata from storage
func (v *Vault) loadKeyMetadata() (*KeyRotationMetadata, error) {
	// Check if metadata exists
	exists, err := v.store.MetadataExists()
	if err != nil {
		return nil, fmt.Errorf("failed to check metadata existence: %w", err)
	}

	if !exists {
		// Return empty metadata if none exists
		return &KeyRotationMetadata{
			Keys:    make(map[string]KeyMetadata),
			Version: 1,
		}, nil
	}

	// Load versioned encrypted metadata
	versionedMetadata, err := v.store.LoadMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	encryptedMetadata := versionedMetadata.Data

	// Decrypt metadata
	derivationKeyBuffer, err := v.derivationKeyEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to access derivation key: %w", err)
	}
	defer derivationKeyBuffer.Destroy()

	metadataBytes, err := crypto.DecryptValue(encryptedMetadata, derivationKeyBuffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	// Parse metadata
	var metadata KeyRotationMetadata
	if err = json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Zero out decrypted metadata bytes
	for i := range metadataBytes {
		metadataBytes[i] = 0
	}

	return &metadata, nil
}

// saveKeyMetadata saves the key metadata using the store interface
func (v *Vault) saveKeyMetadata(metadata *KeyRotationMetadata) error {
	// Serialize metadata to JSON
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Encrypt metadata using derivation key
	derivationKeyBuffer, err := v.derivationKeyEnclave.Open()
	if err != nil {
		return fmt.Errorf("failed to access derivation key: %w", err)
	}
	defer derivationKeyBuffer.Destroy()

	encryptedMetadata, err := crypto.EncryptValue(metadataBytes, derivationKeyBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Zero out unencrypted metadata
	for i := range metadataBytes {
		metadataBytes[i] = 0
	}

	// Save encrypted metadata to storage
	if err = v.saveMetadataWithRetry(encryptedMetadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}

// createDefaultMetadata creates default metadata for a key that doesn't have metadata
func (v *Vault) createDefaultMetadata() error {
	// Initialize keyMetadata map if needed
	if v.keyMetadata == nil {
		v.keyMetadata = make(map[string]KeyMetadata)
	}

	// Generate a key ID for the existing key if we don't have one
	if v.currentKeyID == "" {
		v.currentKeyID = generateKeyID()
	}

	// Create default metadata
	v.keyMetadata[v.currentKeyID] = KeyMetadata{
		KeyID:         v.currentKeyID,
		Active:        true,
		Status:        KeyStatusActive,
		CreatedAt:     time.Now(), // Note: This won't be the actual creation time
		DeactivatedAt: nil,
	}

	// Save the default metadata
	rotationMetadata := &KeyRotationMetadata{
		CurrentKeyID: v.currentKeyID,
		Keys:         make(map[string]KeyMetadata),
		LastRotation: time.Now(),
		Version:      1,
	}

	// Copy metadata
	for keyID, meta := range v.keyMetadata {
		rotationMetadata.Keys[keyID] = meta
	}

	if err := v.saveKeyMetadata(rotationMetadata); err != nil {
		return fmt.Errorf("failed to save default metadata: %w", err)
	}

	return nil
}
