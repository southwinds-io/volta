# Envelop Encryption and Key Rotation Scenarios

Volta implements [Envelope Encryption](https://en.wikipedia.org/wiki/Hybrid_cryptosystem#Envelope_encryption), in which a Data Encryption Key (DEK) is used to encrypt data, and a Key Encryption Key (KEK) is used 
to encrypt the DEK. This creates a layered approach to security. The encrypted DEK is often stored alongside the encrypted data.

Let's examine the two rotation scenarios supported by Volta:

**1) DEK Rotation (requires data to be re-encrypted)**

*   **What it means:** In this scenario, Volta generates a new DEK. The new DEK is used to re-encrypt the actual data in the vault (secrets), and the current KEK is used to encrypt this new DEK. Any PII data encrypted with the old DEK and stored outside the vault (e.g. database) must be re-encrypted before the old DEK is destroyed.
*   **Pros:**
    *   **Maximum Security:** This is the most secure approach. If an old DEK was somehow compromised, re-encrypting the data with a new DEK mitigates that risk. Rotating the KEK adds another layer of protection.
    *   **Addresses DEK Compromise:** If there's a suspicion that a DEK has been compromised, simply rotating the KEK is insufficient, as the old DEK can still decrypt the data. A full rotation addresses this.
    *   **Compliance:** Some security standards and regulations may require periodic rotation of keys that directly encrypt data (DEKs).
*   **Cons:**
    *   **Resource Intensive:** Re-encrypting all the data can be a time-consuming and computationally expensive operation, especially for large datasets.
*   **When it makes sense:**
    *   When a DEK is suspected to be compromised.
    *   To comply with stringent security policies or regulations that mandate data re-encryption.
    *   When the age or volume of data encrypted with a single DEK reaches a certain threshold, increasing the risk of cryptanalytic attacks.
    *   To protect against data on lost or old backups from being decrypted if the current DEK is later compromised.

**2) KEK Rotation (avoid the need to re-encrypt data)**

*   **What it means:** In this scenario, Volta generates a new KEK. This new KEK is then used to re-encrypt the *existing* DEK(s). The actual data remains encrypted with the original DEK(s) and is not re-encrypted.
*   **Pros:**
    *   **Efficiency:** This is much less resource-intensive than a full rotation because you are only re-encrypting the DEK(s), which are typically small, rather than the entire dataset.
    *   **Limits KEK Exposure:** Rotating the KEK limits the "blast radius" if the KEK is compromised. A compromised KEK would only expose the DEKs it protects, not necessarily all past DEKs if previous KEKs are retired securely.
    *   **Common Practice:** This is a common and recommended practice for key rotation in envelope encryption.
*   **Cons:**
    *   **Does Not Address DEK Compromise:** If a DEK itself is compromised, rotating only the KEK will not protect the data encrypted by that DEK. The compromised DEK, even if re-wrapped with a new KEK, can still decrypt the data it originally encrypted.
    *   **DEK Lifetime:** The original DEK continues to be the key that protects the data. If that DEK has been in use for a very long time or has encrypted a vast amount of data, it might become a weaker point over time.
*   **When it makes sense:**
    *   As a regular, scheduled security practice to limit the exposure of any single KEK.
    *   When you need to change access policies for the KEK (e.g., if a system or individual with access to the KEK is no longer trusted).
    *   To enable easier key management and reduce reliance on a single KEK for protecting numerous DEKs.
    *   In situations where re-encrypting the entire dataset is impractical due to performance or operational constraints.

Both full and partial rotation scenarios make sense in a vault implementing Key Envelope Encryption, but they serve different purposes and address different risks:

*   **Partial Rotation (KEK only):** This should be a standard, periodic procedure. It's an efficient way to limit the risk associated with a KEK compromise without the significant overhead of data re-encryption. It enhances the security of the DEKs by regularly changing their "wrapper."
*   **Full Rotation (KEK and DEK):** This is a more involved process that should be performed when there's a higher level of risk, such as a suspected DEK compromise, or to meet specific compliance requirements that mandate data re-encryption. It provides the highest level of security refresh.

Ideally, a robust vault system would offer the capability for both types of rotation, allowing administrators to choose the appropriate strategy based on their specific security needs, risk assessments, and operational constraints. Some systems facilitate this by re-encrypting the DEK with the new KEK when the DEK is next unwrapped.

# Is re-encryption mandated?

While many security policies and regulations mandate robust data protection, including encryption, very few explicitly *require* the re-encryption of the underlying data (the DEK-encrypted data in an envelope encryption scheme) on a fixed schedule. Most regulations focus on ensuring data is encrypted using strong, current standards and that the encryption keys themselves are managed securely, which includes key rotation.

Here's a breakdown of how common regulations and standards approach this:

*   **Focus on "Appropriate Technical and Organisational Measures":** Regulations like GDPR (General Data Protection Regulation) and HIPAA (Health Insurance Portability and Accountability Act) require organizations to implement "appropriate technical and organisational measures" to ensure data security. Encryption is consistently cited as a key example of such a measure.
    *   **GDPR:** Does not mandate encryption but strongly recommends it as an appropriate safeguard. If data is encrypted and a breach occurs, it may reduce the risk to individuals and potentially negate the need to notify them. The focus is on rendering data unintelligible to unauthorized parties.
    *   **HIPAA:** Classifies encryption as an "addressable" implementation specification, meaning covered entities must implement it or document why it's not reasonable and appropriate and implement an equivalent alternative. Strong guidance suggests that "addressable" essentially means it should be done. HIPAA expects ePHI (electronic Protected Health Information) to be encrypted at rest and in transit.

*   **Emphasis on Key Management:** Standards like PCI DSS (Payment Card Industry Data Security Standard) and guidance from NIST (National Institute of Standards and Technology) place significant emphasis on strong cryptographic key management. This includes:
    *   **Secure Key Generation and Storage:** Keys must be generated, stored, and protected securely, often recommending Hardware Security Modules (HSMs).
    *   **Key Rotation:** Regularly changing encryption keys (which, in envelope encryption, typically refers to the KEK) is a common requirement or best practice. This limits the amount of data exposed if a single key is compromised.
    *   **PCI DSS:** Mandates strong cryptography for cardholder data both in transit and at rest. It requires secure key management, including key rotation. While it mandates protecting stored cardholder data with encryption, the primary emphasis regarding rotation is on the keys. Re-encrypting all data with a new DEK is not as explicitly and frequently mandated as KEK rotation, though it might be implied by the need to protect data if a key used to encrypt it (DEK) is retired or compromised.

*   **Re-encryption Implicit vs. Explicit:**
    *   Most regulations and standards imply that if a key used to encrypt data (a DEK) is compromised or retired as part of its lifecycle, the data protected by that key would need to be re-encrypted with a new key to remain secure. However, a proactive, scheduled *full data re-encryption* where both DEK and KEK are changed, regardless of compromise, is less commonly an explicit mandate across the board.
    *   Some sources differentiate between "key rotation" (changing the KEK) and "re-encryption" (decrypting with an old key and encrypting with a new key, referring to the data itself). The latter is acknowledged as more performance-intensive.
    *   The New York Department of Financial Services (NYDFS) Cybersecurity Regulation (23 NYCRR 500) mandates encryption for nonpublic information both in transit and at rest, and requires controls based on risk assessment. While it doesn't explicitly detail re-encryption schedules for the data itself, a risk assessment could lead to such a decision.

**Why the Distinction Matters:**

*   **Rotating KEKs (Partial Rotation):** This is a relatively lightweight operation that significantly enhances security by limiting the exposure of DEKs. It's a common best practice.
*   **Re-encrypting Data (Full Rotation):** This is a much heavier operation, consuming significant time and resources. It's typically undertaken when:
    *   A DEK is known or suspected to be compromised.
    *   There's a need to upgrade the cryptographic algorithm used for the DEK.
    *   Specific internal policies or a very high-risk assessment dictates it.
    *   The data has been encrypted with the same DEK for a very extended period, increasing its theoretical risk exposure.

**In Summary:**

While stringent security policies and regulations universally demand strong encryption and secure key management (including KEK rotation), an explicit, universally mandated schedule for *re-encrypting the actual data with new DEKs* is rare. Instead, the requirement for data re-encryption often arises from:

1.  **Compromise:** If a DEK is compromised.
2.  **Key Lifecycle Management:** When a DEK reaches the end of its defined cryptoperiod or needs to be retired for other policy reasons.
3.  **Risk Assessment:** If an organization's risk assessment identifies that the continued use of an existing DEK (even if not compromised) poses an unacceptable risk.
4.  **Technological Upgrades:** When migrating to stronger encryption algorithms for the data itself.

Organizations are generally expected to implement risk-based approaches. If the risk of DEK compromise is high, or if a DEK has been in use for an extremely long time encrypting a vast amount of sensitive data, then re-encrypting the data with a new DEK would be a prudent and often implicitly expected security measure, even if not explicitly scheduled by a specific regulation.

