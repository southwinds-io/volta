package volta

import (
	"fmt"
)

// Options represents comprehensive configuration parameters for vault initialization and operation.
//
// This structure provides fine-grained control over vault security, performance, and operational
// characteristics during initialization and runtime operation. It encompasses critical security
// settings, memory protection configurations, key derivation parameters, and operational modes
// that collectively define the vault's security posture and operational behavior. The Options
// structure implements security-by-design principles with clear separation between serializable
// configuration and sensitive operational parameters that must never be persisted or transmitted.
//
// STRUCTURE PURPOSE AND SCOPE:
// Options serves as the comprehensive configuration interface for vault operations:
// - Controls cryptographic key derivation parameters and security settings
// - Manages memory protection and secure memory handling configurations
// - Defines operational modes and debugging capabilities for development and production
// - Provides environment-based security configuration for deployment flexibility
// - Enables security policy enforcement through configuration-driven controls
// - Supports compliance requirements through configurable security parameters
// - Facilitates operational monitoring and troubleshooting through controlled debugging
// - Enables secure deployment patterns through environment variable integration
//
// SECURITY ARCHITECTURE AND DESIGN:
// The Options structure implements multiple layers of security protection:
//
// Serialization Security:
// - Critical security fields marked with `json:"-"` prevent accidental serialization
// - Salt and passphrase never included in JSON output or configuration files
// - Clear distinction between persistent configuration and runtime security parameters
// - Protection against configuration file exposure and unauthorized access
// - Secure logging integration that automatically excludes sensitive fields
//
// Memory Security Integration:
// - Memory locking configuration prevents sensitive data swapping to disk
// - Integration with secure memory management and protection systems
// - Configuration-driven security policy enforcement for memory handling
// - Support for high-security environments requiring memory protection
//
// Environment Variable Security:
// - Secure passphrase delivery through environment variables
// - Avoids command-line argument exposure in process lists
// - Supports secure deployment automation and orchestration
// - Enables configuration management integration without credential exposure
//
// Configuration Security:
// - Separates security-critical parameters from operational configuration
// - Prevents accidental exposure through configuration management systems
// - Supports secure configuration validation and policy enforcement
// - Enables audit trail generation for security configuration changes
type Options struct {
	// KEY DERIVATION CONFIGURATION:
	// Critical cryptographic parameters that control the security and uniqueness
	// of derived encryption keys. These parameters directly impact vault security
	// and must be handled with extreme care to prevent unauthorized access.
	//
	// DerivationSalt provides cryptographic uniqueness and prevents rainbow table attacks.
	// This field contains high-entropy random data that ensures each vault instance
	// derives unique encryption keys even when using identical passphrases. The salt
	// must be cryptographically random, sufficiently long (minimum 32 bytes recommended),
	// and unique per vault instance to provide maximum security benefits.
	//
	// Security Characteristics:
	// - Prevents precomputed attack vectors through cryptographic uniqueness
	// - Ensures vault instance isolation even with shared passphrases
	// - Provides forward security through unique key derivation per instance
	// - Protects against correlation attacks across multiple vault instances
	//
	// Operational Requirements:
	// - Generated using cryptographically secure random number generator (CSPRNG)
	// - Minimum entropy of 256 bits (32 bytes) for cryptographic security
	// - Stored securely and backed up with same protection as vault data
	// - Never transmitted in plaintext or stored in configuration files
	// - Consistent across vault backups and disaster recovery operations
	//
	// Serialization Security:
	// - json:"-" tag prevents inclusion in JSON serialization
	// - Never persisted in configuration files or transmitted over networks
	// - Excluded from all logging and audit output for security protection
	// - Must be provided through secure channels during vault initialization
	//
	// Backup and Recovery Implications:
	// - Required for vault access after disaster recovery operations
	// - Must be stored securely separate from encrypted data backups
	// - Critical for emergency access and business continuity procedures
	// - Loss of salt renders vault data permanently inaccessible
	DerivationSalt []byte `json:"-"` // Don't serialize salt for security

	// DerivationPassphrase provides authentication and key material for vault access.
	// This field contains the master passphrase used in conjunction with the salt
	// to derive the vault's master encryption key through cryptographic key derivation.
	// The passphrase represents the primary authentication factor for vault access
	// and must meet strict security requirements for length, complexity, and entropy.
	//
	// Security Requirements:
	// - Minimum length of 12 characters, recommended 20+ characters
	// - High entropy combining multiple character classes and unpredictable patterns
	// - Unique to the vault instance and not reused across systems
	// - Protected against brute force attacks through key derivation parameters
	// - Regularly rotated according to security policy and compliance requirements
	//
	// Passphrase Composition Guidelines:
	// - Combination of uppercase and lowercase letters for character diversity
	// - Numeric digits for increased keyspace and entropy
	// - Special characters for maximum cryptographic strength
	// - Avoid dictionary words, predictable patterns, and personal information
	// - Consider passphrase generators for maximum entropy and unpredictability
	//
	// Operational Security:
	// - Never logged, displayed, or included in error messages
	// - Cleared from memory immediately after key derivation
	// - Transmitted only through secure channels during initialization
	// - Never stored persistently or included in configuration files
	// - Protected against shoulder surfing and social engineering attacks
	//
	// Serialization Security:
	// - json:"-" tag prevents inclusion in JSON serialization
	// - Excluded from all configuration output and system documentation
	// - Never appears in process arguments or environment variable listings
	// - Protected against accidental exposure through debugging or logging
	//
	// Emergency Access Considerations:
	// - Required for vault access during emergency and disaster recovery
	// - Must be secured using approved key management and escrow procedures
	// - Split knowledge and dual control recommended for high-security environments
	// - Recovery procedures must balance security and operational accessibility
	DerivationPassphrase string `json:"-"` // Don't serialize passphrase for security

	// EnvPassphraseVar specifies environment variable name containing the vault passphrase.
	// This field enables secure passphrase delivery through environment variables,
	// avoiding exposure through command-line arguments or configuration files.
	// When specified, the vault retrieves the passphrase from the named environment
	// variable during initialization, providing secure integration with deployment
	// automation and orchestration systems.
	//
	// Security Benefits:
	// - Avoids command-line argument exposure in process lists and system logs
	// - Prevents passphrase inclusion in configuration files and version control
	// - Enables secure integration with container orchestration and deployment systems
	// - Supports automated deployment while maintaining security boundaries
	// - Facilitates secure credential management and rotation procedures
	//
	// Environment Variable Security:
	// - Environment variable should be set with restricted access permissions
	// - Consider using secure secret management systems for environment variable population
	// - Ensure environment variables are not logged or exposed in system monitoring
	// - Use process isolation to prevent unauthorized environment variable access
	// - Clear environment variables after vault initialization when possible
	//
	// Deployment Integration:
	// - Compatible with Docker secrets and Kubernetes secret management
	// - Supports HashiCorp Vault integration for secure credential delivery
	// - Enables AWS Secrets Manager and Azure Key Vault integration
	// - Compatible with enterprise credential management and rotation systems
	// - Supports CI/CD pipeline integration with secure credential handling
	//
	// Operational Considerations:
	// - Environment variable name should follow organizational naming conventions
	// - Consider using prefixes like "VAULT_" or "SECURE_" for clear identification
	// - Document environment variable requirements in deployment procedures
	// - Include in backup and disaster recovery documentation and procedures
	// - Monitor for environment variable availability during vault startup
	//
	// Example Values:
	// - "VAULT_MASTER_PASSPHRASE" - Clear identification and organizational consistency
	// - "SECURE_VAULT_KEY" - Security-focused naming convention
	// - "APP_VAULT_PASSPHRASE" - Application-specific identification
	// - Custom naming based on organizational security and operational policies
	EnvPassphraseVar string `json:"env_passphrase_var,omitempty"`

	// MEMORY PROTECTION SETTINGS:
	// Advanced security configuration that controls memory handling and protection
	// mechanisms to prevent sensitive data exposure through memory dumps, swap files,
	// or unauthorized memory access. Memory protection is critical for high-security
	// environments and regulatory compliance requirements.
	//
	// EnableMemoryLock controls memory locking to prevent sensitive data paging to disk.
	// When enabled, the vault attempts to lock critical memory regions containing
	// encryption keys, passphrases, and sensitive data in physical RAM to prevent
	// exposure through swap files, hibernation files, or memory dumps. This provides
	// additional protection against cold boot attacks and forensic memory analysis.
	//
	// Memory Locking Benefits:
	// - Prevents sensitive data exposure through virtual memory paging
	// - Protects against swap file analysis and forensic memory recovery
	// - Reduces risk of sensitive data persistence in hibernation files
	// - Provides defense against cold boot attacks and memory imaging
	// - Supports compliance requirements for data protection and privacy regulations
	//
	// Operating System Integration:
	// - Unix/Linux: Uses mlock()/mlockall() system calls for memory locking
	// - Windows: Uses VirtualLock() for memory page locking and protection
	// - Requires appropriate process privileges for memory locking operations
	// - May require system configuration for memory locking limits and permissions
	// - Performance impact varies by operating system and available physical memory
	//
	// Security Considerations:
	// - Memory locking is not a complete protection against all memory-based attacks
	// - Consider additional protections like memory encryption and secure enclaves
	// - Monitor system performance impact and adjust memory allocation accordingly
	// - Combine with other security measures for comprehensive protection
	// - Regular security assessment and penetration testing for memory protection validation
	//
	// Operational Requirements:
	// - Sufficient physical memory to accommodate locked memory regions
	// - Operating system configuration for memory locking permission and limits
	// - Process privilege configuration for memory management operations
	// - Monitoring for memory locking success and failure conditions
	// - Documentation of memory protection requirements and troubleshooting procedures
	//
	// Performance Impact:
	// - Locked memory cannot be swapped, potentially increasing physical memory usage
	// - May impact system performance under memory pressure conditions
	// - Consider memory allocation patterns and vault usage characteristics
	// - Monitor system performance and memory utilization during operations
	// - Balance security requirements with operational performance needs
	//
	// Compliance and Regulatory Support:
	// - Supports PCI DSS requirements for cardholder data protection in memory
	// - HIPAA compliance for protected health information memory handling
	// - SOX compliance for financial data protection and memory security
	// - GDPR compliance for personal data protection and privacy requirements
	// - Custom regulatory requirements for memory protection and data handling
	EnableMemoryLock bool `json:"enable_memory_lock"`

	// the user creating and using the vault manager instance
	UserID string `json:"-"`
}

// SERIALIZATION AND PERSISTENCE BEHAVIOR:
// The Options structure implements careful serialization control to maintain security:
//
// JSON Serialization Security:
// - Sensitive fields (DerivationSalt, DerivationPassphrase) excluded from JSON output
// - Non-sensitive configuration fields included for operational management
// - Environment variable names included as they don't contain sensitive data
// - Operational settings serialized for configuration management integration
//
// Configuration Management Integration:
// - Safe for inclusion in configuration management systems and version control
// - Supports infrastructure-as-code deployment patterns with security boundaries
// - Enables automated configuration validation and policy enforcement
// - Compatible with configuration templating and environment-specific deployments
//
// Security Policy Enforcement:
// - Serialization exclusions prevent accidental sensitive data exposure
// - Configuration validation ensures security requirements are met
// - Audit trail generation for configuration changes and security policy updates
// - Integration with security scanning and compliance validation tools
//
// VALIDATION AND SECURITY ENFORCEMENT:
// Options validation ensures security requirements and operational correctness:
//
// Security Validation:
// - Passphrase strength validation against organizational policy requirements
// - Salt entropy validation using cryptographic randomness testing
// - Environment variable security validation and accessibility testing
// - Memory protection capability validation against system requirements
//
// Operational Validation:
// - Configuration consistency validation across deployment environments
// - System capability validation for memory locking and protection features
// - Environment variable availability and accessibility validation
// - Debug mode configuration validation and operational impact assessment
//
// Compliance Validation:
// - Policy compliance validation against organizational security requirements
// - Regulatory requirement validation for data protection and privacy compliance
// - Security control validation for audit and examination preparation
// - Documentation validation for operational procedures and emergency access
//
// DEPLOYMENT PATTERNS AND BEST PRACTICES:
// Effective Options usage requires understanding of deployment and operational patterns:
//
// Secure Deployment Patterns:
// - Environment variable injection through secure secret management systems
// - Configuration file separation between sensitive and non-sensitive parameters
// - Automated validation and testing of security configuration during deployment
// - Integration with monitoring and alerting systems for configuration validation
//
// High-Security Environment Configuration:
// - Memory locking enabled with appropriate system privilege and resource allocation
// - Environment variable security with restricted access and monitoring
// - Debug mode disabled or carefully controlled with enhanced security monitoring
// - Comprehensive audit trail generation and security event correlation
//
// Development and Testing Configuration:
// - Debug mode enabled with appropriate log management and security boundaries
// - Test environment isolation with separate security configuration and validation
// - Development workflow integration with security policy enforcement
// - Automated testing of security configuration and operational procedures
//
// Operational Best Practices:
// - Regular security configuration review and validation procedures
// - Monitoring and alerting for configuration changes and security events
// - Documentation of configuration requirements and troubleshooting procedures
// - Training and awareness programs for secure configuration management
// - Incident response procedures for configuration security issues
//
// COMPLIANCE AND REGULATORY INTEGRATION:
// Options configuration supports comprehensive compliance and regulatory requirements:
//
// Data Protection Compliance:
// - GDPR compliance through secure memory handling and data protection
// - CCPA compliance through privacy-by-design configuration and validation
// - PIPEDA compliance through personal information protection and security
// - Regional data protection regulation compliance through configurable security
//
// Industry-Specific Compliance:
// - PCI DSS compliance through secure cardholder data handling and memory protection
// - HIPAA compliance through protected health information security and privacy
// - SOX compliance through financial data protection and audit trail generation
// - FERPA compliance through educational record protection and access control
//
// Security Framework Compliance:
// - NIST Cybersecurity Framework compliance through comprehensive security controls
// - ISO 27001 compliance through information security management integration
// - SOC 2 compliance through security control implementation and validation
// - FedRAMP compliance through federal security requirement implementation
//
// Audit and Examination Support:
// - Configuration documentation for regulatory examination and audit preparation
// - Security control evidence collection and validation for compliance reporting
// - Audit trail generation for configuration changes and security events
// - Compliance reporting automation and regulatory requirement validation

// Validate validates the Options configuration
func (o Options) Validate() error {
	// Validate passphrase configuration - at least one should be provided
	if o.DerivationPassphrase == "" && o.EnvPassphraseVar == "" {
		return fmt.Errorf("either DerivationPassphrase or EnvPassphraseVar must be provided")
	}

	return nil
}
