![volta](volta.jpeg)

![Tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/southwinds-io/volta/main/.github/badges/tests.json&cacheSeconds=0)
![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/southwinds-io/volta/main/.github/badges/coverage.json&cacheSeconds=0)

# Volta: An Embedded Go Library for Multi-Tenant Encryption and Secrets Management

Volta is a zero-dependency Go library designed for multi-tenant encryption and secret management, intended to be embedded directly within an application.

It is used by SouthWinds Tech to protect Personally Identifiable Information (PII) and other sensitive data within their own applications. It establishes a cryptographic boundary within the application's process, providing data protection controls without reliance on external services.

### Design Principles

Volta's architecture is guided by the following principles:

*   **Multi-tenancy:** Provides cryptographic isolation for distinct tenants (e.g., applications, services, or organizational units). Each tenant operates with its own dedicated keys, secrets, and audit trails.
*   **Pluggable Backends:** Storage and audit logging are defined by interfaces (`persist.Store`, `audit.Logger`), enabling integration with various persistence and observability systems.
*   **In-Memory Protection:** Utilizes memory-protection libraries (e.g., `memguard`) to secure keys and plaintext secrets while resident in application memory.
*   **Embedded, API-less Design:** Operates as a library without an external REST API. This minimizes the attack surface and places the control of cryptographic operations within the application's own security context.
*   **Non-Exportable Keys:** Encryption keys are managed internally and are not designed to be exported.
*   **Administrative CLI:** A command-line interface is provided for out-of-band vault management and administrative operations.

### Key Components

1.  **Vault Manager (`VaultManagerService`):**
    The top-level service that manages the lifecycle of all tenant vaults. It is the primary entry point for an application, responsible for retrieving, initializing, and closing tenant-specific vault instances.

2.  **Vault (`VaultService`):**
    Represents an individual tenant's vault. It is the interface for all cryptographic operations and secret management for a single tenant, including encryption, decryption, secret storage, and key management.

### Feature Set

*   Per-tenant data encryption and decryption.
*   CRUD operations for secrets (store, retrieve, update, delete).
*   Secure key lifecycle management (rotation, destruction).
*   Encrypted, passphrase-protected backups and restoration of tenant vaults.
*   Scoped functions (`UseSecret`) to limit plaintext secret exposure in memory.
*   Pluggable auditing of all vault operations.

### Basic Usage

#### Storing and Retrieving Secrets
The example [here](examples/secrets/main.go) demonstrates initializing the vault manager, accessing a tenant's vault, storing and retrieving secrets.

#### Encryption of sensitive data
The example [here](examples/encryption/main.go) demonstrates initializing the vault manager, accessing a tenant's vault, and using it to directly **encrypt and decrypt sensitive data**, such as PII.

### Installation

```sh
go get southwinds.dev/volta
```

### Security Model

The security of a tenant's vault relies on the strength and confidentiality of its **passphrase**. This passphrase is used to derive the Key Encryption Key (KEK) that protects all of the tenant's Data Encryption Keys (DEKs).

Volta uses libraries like `memguard` to provide in-memory protection for sensitive data (e.g., keys, plaintext secrets), making it more difficult for other processes on the host to inspect the application's memory. This is part of a defense-in-depth strategy and is not a substitute for securing the host environment.

### Extensibility

Volta is designed to be adaptable to different infrastructures. Custom backends can be created by implementing the following interfaces:

*   **`persist.Store`:** For connecting to different storage systems (e.g., databases, cloud object storage, key-value stores).
*   **`audit.Logger`:** For routing audit events to centralized logging or observability platforms (e.g., ELK Stack, Splunk, CloudWatch).

### Detailed Documentation

For a deeper understanding of the architecture, data structures, security patterns, and compliance guides, please see the `/docs` directory:

- [Rationale, Architecture, and Advantages](docs/arc.md)
- [Feature Set](docs/features.md)
- [Architectural Patterns in Secret Management and Data Protection](docs/arc_patterns.md)
- [Architectural Patterns for GDPR Compliance using an Embedded Cryptographic Library](docs/gdpr.md)
- [Supporting HIPAA Technical Safeguards with an Embedded Cryptographic Library](docs/hipaa.md)
- [Architectural Patterns for PCI DSS Compliance using an Embedded Cryptographic Library](docs/pci_dss.md)
- [Facilitating Zero Trust Architecture with an Embedded Cryptographic Library](docs/zta.md)
- [Architectural Patterns for Secure Secret Handling in Concurrent Applications](docs/secret_handling.md)

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

Volta allows to tailor its deployment to specific infrastructure and security requirements, ensuring that it can evolve with changing needs without compromising its core mission of providing simple, secure secret management.

### License

Volta is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for the full license text.