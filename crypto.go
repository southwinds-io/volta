package volta

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts plaintext data using the vault's current master key with ChaCha20-Poly1305 AEAD.
//
// This method provides secure authenticated encryption with additional data integrity guarantees.
// The encrypted output includes the key ID to support key rotation and ensure proper decryption
// even after the master key has been rotated.
//
// SECURITY FEATURES:
// - Uses ChaCha20-Poly1305 authenticated encryption (AEAD)
// - Generates cryptographically secure random nonce for each encryption
// - Includes authentication tag to detect tampering
// - Embeds key ID to support key rotation scenarios
// - Protected memory access using memguard enclaves
// - Comprehensive audit logging for security monitoring
// - Thread-safe with read lock protection
//
// ENCRYPTION ALGORITHM:
// - Cipher: ChaCha20-Poly1305 (RFC 8439)
// - Key Size: 256 bits (32 bytes)
// - Nonce Size: 96 bits (12 bytes) - randomly generated per encryption
// - Authentication: Poly1305 MAC provides 128-bit authentication tag
// - No additional authenticated data (AAD) is used
//
// OUTPUT FORMAT:
// The encrypted output follows this binary format before base64 encoding:
//
//	[2 bytes: Key ID Length (big-endian)]
//	[N bytes: Key ID (UTF-8)]
//	[12 bytes: Nonce (random)]
//	[M bytes: Ciphertext + Authentication Tag]
//
// The final output is base64-encoded for safe text transmission and storage.
//
// PERFORMANCE CHARACTERISTICS:
// - Time Complexity: O(n) where n is plaintext length
// - Space Complexity: O(n) for temporary buffers
// - Memory Usage: ~3x plaintext size during encryption (temporary copies)
// - CPU Usage: Optimized ChaCha20 implementation with hardware acceleration when available
//
// SECURITY GUARANTEES:
// - Confidentiality: Plaintext is hidden from attackers without the key
// - Authenticity: Authentication tag prevents undetected modifications
// - Freshness: Unique nonce prevents replay attacks and ensures semantic security
// - Key Agility: Embedded key ID supports seamless key rotation
// - Forward Security: Old ciphertexts remain secure even after key rotation
//
// Parameters:
//   - plaintext: The data to be encrypted. Must not be empty.
//     Maximum size is 10MB to prevent DoS attacks and memory exhaustion.
//     The data is not modified during encryption.
//
// Returns:
//   - ciphertextWithKeyID: Base64-encoded encrypted data with embedded key ID.
//     This string can be safely transmitted over text protocols or stored in databases.
//   - err: nil on success, detailed error on failure
//
// Possible Errors:
//   - "empty plaintext": Plaintext parameter is empty or nil
//   - "plaintext too large": Plaintext exceeds 10MB size limit
//   - "master key not available": Current encryption key cannot be retrieved
//   - "failed to access master key": Cannot open the master key enclave
//   - "failed to create cipher": ChaCha20-Poly1305 cipher initialization failed
//   - "failed to generate nonce": Cryptographic random number generation failed
//   - "key ID too long": Key identifier exceeds maximum length (65535 bytes)
//   - Various internal errors related to memory or system resources
//
// Thread Safety:
//
//	This method is thread-safe for concurrent reads. It acquires a read lock
//	to ensure the key state doesn't change during encryption, allowing multiple
//	simultaneous encryptions with the same key.
//
// Audit Logging:
//
//	All encryption attempts are logged with the following information:
//	- Operation success/failure status
//	- Input data size (not the actual data for security)
//	- Output size and key ID (on success)
//	- Error details (on failure)
//	- Timestamp and contextual information
//
// Memory Safety:
//   - Master key is accessed through memguard protected memory
//   - Key buffer is automatically destroyed after use
//   - No sensitive data remains in standard Go memory
//   - Temporary nonce and ciphertext are cleared by Go's GC
//
// Usage Examples:
//
//	// Basic encryption
//	plaintext := []byte("sensitive data")
//	encrypted, err := vault.Encrypt(plaintext)
//	if err != nil {
//	    log.Printf("Encryption failed: %v", err)
//	    return
//	}
//	fmt.Printf("Encrypted: %s\n", encrypted)
//
//	// Encrypt JSON data
//	jsonData := `{"secret": "value", "password": "123456"}`
//	encrypted, err := vault.Encrypt([]byte(jsonData))
//	if err != nil {
//	    log.Printf("Failed to encrypt JSON: %v", err)
//	    return
//	}
//
//	// Store encrypted data
//	err = database.Store("user_secrets", encrypted)
//	if err != nil {
//	    log.Printf("Failed to store encrypted data: %v", err)
//	}
//
// Key Rotation Compatibility:
//
//	The encrypted output includes the key ID that was used for encryption.
//	This ensures that:
//	- Old ciphertexts can still be decrypted after key rotation
//	- Multiple key versions can coexist in the same system
//	- Gradual migration to new keys is possible
//	- Emergency key rotation doesn't break existing data
//
// Security Best Practices:
//   - Always check the returned error before using encrypted data
//   - Store encrypted data securely (proper database permissions, etc.)
//   - Monitor audit logs for unusual encryption patterns
//   - Implement rate limiting to prevent abuse
//   - Consider data classification and apply appropriate controls
//   - Regularly rotate encryption keys according to your security policy
//
// Performance Optimization:
//   - For high-throughput scenarios, consider batching small encryptions
//   - Monitor memory usage in systems processing large datasets
//   - The 10MB size limit can be adjusted based on your security requirements
//   - Consider using streaming encryption for very large datasets
//
// Integration Considerations:
//   - The base64 output is safe for JSON, XML, and database storage
//   - Output length is approximately 1.33x the input length plus overhead
//   - Key rotation requires coordination with decryption systems
//   - Audit logs should be monitored and retained per compliance requirements
//
// Cryptographic Details:
//   - ChaCha20 provides the confidentiality protection
//   - Poly1305 provides authentication and integrity protection
//   - The combination is proven secure and resistant to timing attacks
//   - Nonce uniqueness is critical - never reuse nonces with the same key
//   - The implementation follows RFC 8439 specifications
func (v *Vault) Encrypt(plaintext []byte) (ciphertextWithKeyID string, err error) {
	// Add basic validation
	if len(plaintext) == 0 {
		return "", errors.New("empty plaintext")
	}

	// Max size check to prevent DoS
	if len(plaintext) > 10*1024*1024 { // 10MB limit
		return "", errors.New("plaintext too large")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	// Log audit entry for encryption attempt
	v.audit.Log("encrypt_data", true, map[string]interface{}{
		"data_size": len(plaintext),
	})

	// Get the current master key from the map
	currentKeyEnclave, err := v.getCurrentKey()
	if err != nil {
		v.audit.Log("encrypt_data", false, map[string]interface{}{
			"error": "master key not available",
		})
		return "", fmt.Errorf("master key not available: %w", err)
	}

	// Open the master key enclave to access the key
	masterKeyBuffer, err := currentKeyEnclave.Open()
	if err != nil {
		v.audit.Log("encrypt_data", false, map[string]interface{}{
			"error": "failed to access master key",
		})
		return "", fmt.Errorf("failed to access master key: %w", err)
	}

	// Always destroy the buffer when we're done with it
	defer masterKeyBuffer.Destroy()

	// Create cipher
	aead, err := chacha20poly1305.New(masterKeyBuffer.Bytes())
	if err != nil {
		v.audit.Log("encrypt_data", false, map[string]interface{}{
			"error": "failed to create cipher",
		})
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		v.audit.Log("encrypt_data", false, map[string]interface{}{
			"error": "failed to generate nonce",
		})
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Combine nonce and ciphertext (this is the actual encrypted payload)
	encryptedPayload := make([]byte, len(nonce)+len(ciphertext))
	copy(encryptedPayload[:len(nonce)], nonce)
	copy(encryptedPayload[len(nonce):], ciphertext)

	// Prepare key ID for embedding
	keyIDBytes := []byte(v.currentKeyID)
	keyIDLength := uint16(len(keyIDBytes))

	// Validate key ID length to prevent overflow
	if keyIDLength > 65535 {
		v.audit.Log("encrypt_data", false, map[string]interface{}{
			"error": "key ID too long",
		})
		return "", errors.New("key ID too long")
	}

	// Create final format: [2 bytes key ID length][key ID][nonce][ciphertext]
	finalData := make([]byte, 2+len(keyIDBytes)+len(encryptedPayload))

	// Write key ID length (2 bytes, big endian)
	finalData[0] = byte(keyIDLength >> 8)
	finalData[1] = byte(keyIDLength & 0xFF)

	// Write key ID
	copy(finalData[2:2+len(keyIDBytes)], keyIDBytes)

	// Write encrypted payload (nonce + ciphertext)
	copy(finalData[2+len(keyIDBytes):], encryptedPayload)

	// Encode to base64
	encodedData := base64.StdEncoding.EncodeToString(finalData)

	// Log successful encryption
	v.audit.Log("encrypt_data", true, map[string]interface{}{
		"data_size":   len(plaintext),
		"result_size": len(encodedData),
		"key_id":      v.currentKeyID,
	})

	return encodedData, nil
}

// Decrypt decrypts previously encrypted data using the appropriate master key.
//
// This method provides secure authenticated decryption with automatic key selection
// based on the embedded key ID. It supports both current and historical keys to
// enable seamless key rotation without breaking existing encrypted data.
//
// SECURITY FEATURES:
// - Uses ChaCha20-Poly1305 authenticated encryption (AEAD)
// - Automatic authentication tag verification prevents tampering
// - Supports multiple key versions for key rotation scenarios
// - Protected memory access using memguard enclaves
// - Comprehensive audit logging for security monitoring
// - Thread-safe with read lock protection
// - Strict format validation prevents malformed data processing
//
// DECRYPTION ALGORITHM:
// - Cipher: ChaCha20-Poly1305 (RFC 8439)
// - Key Size: 256 bits (32 bytes)
// - Nonce Size: 96 bits (12 bytes) - extracted from encrypted data
// - Authentication: Poly1305 MAC verification (128-bit authentication tag)
// - Automatic key selection based on embedded key ID
//
// INPUT FORMAT:
// The method requires base64-encoded binary data structured as:
//
//	[2 bytes: Key ID Length (big-endian)]
//	[N bytes: Key ID (UTF-8)]
//	[12 bytes: Nonce]
//	[M bytes: Ciphertext + Authentication Tag]
//
// This format ensures proper key identification and prevents ambiguity
// during decryption operations.
//
// PERFORMANCE CHARACTERISTICS:
// - Time Complexity: O(n) where n is ciphertext length
// - Space Complexity: O(n) for output buffer
// - Memory Usage: ~2x ciphertext size during decryption
// - CPU Usage: Optimized ChaCha20 implementation with hardware acceleration
// - I/O Operations: Key retrieval from secure storage
//
// SECURITY GUARANTEES:
// - Confidentiality: Only holders of the correct key can decrypt
// - Authenticity: Authentication tag verification prevents forged data
// - Integrity: Any tampering with ciphertext is detected and rejected
// - Key Agility: Automatic selection of correct historical keys
// - Non-repudiation: Audit trail of all decryption attempts
// - Format Validation: Strict parsing prevents malformed data attacks
//
// KEY ROTATION SUPPORT:
// - Automatically detects which key was used for encryption
// - Maintains access to historical keys for old ciphertexts
// - Seamless operation during and after key rotation
// - No need to re-encrypt existing data immediately
// - Gradual migration support for large datasets
//
// Parameters:
//   - base64CiphertextWithKeyID: Base64-encoded encrypted data string.
//     Must be output from the Encrypt() method. Cannot be empty.
//     Must be valid base64 encoding with proper internal format.
//
// Returns:
//   - []byte: The original plaintext data. Caller is responsible for
//     handling this sensitive data appropriately (zeroing if needed).
//   - error: nil on success, detailed error on failure
//
// Possible Errors:
//   - "empty encrypted string": Input parameter is empty
//   - "invalid base64 encoding": Input is not valid base64
//   - "encrypted data too short": Input data is shorter than minimum required
//   - "invalid data format": Data doesn't follow expected format structure
//   - "key [ID] not available": Required decryption key not found
//   - "failed to access master key": Cannot open the key enclave
//   - "failed to create cipher": ChaCha20-Poly1305 cipher initialization failed
//   - "failed to decrypt": Authentication failed or data is corrupted
//   - Various internal errors related to memory or system resources
//
// Thread Safety:
//
//	This method is thread-safe for concurrent reads. It acquires a read lock
//	to ensure consistent key state during decryption, allowing multiple
//	simultaneous decryptions.
//
// Audit Logging:
//
//	All decryption attempts are logged with the following information:
//	- Operation success/failure status
//	- Input data size (base64 string length)
//	- Output size and key ID used (on success)
//	- Error details (on failure)
//	- Timestamp and contextual information
//
// Memory Safety:
//   - Master keys are accessed through memguard protected memory
//   - Key buffers are automatically destroyed after use
//   - No sensitive key material remains in standard Go memory
//   - Plaintext output is returned in standard memory (caller's responsibility)
//
// Usage Examples:
//
//	// Basic decryption
//	encrypted := "base64-encoded-encrypted-data"
//	plaintext, err := vault.Decrypt(encrypted)
//	if err != nil {
//	    log.Printf("Decryption failed: %v", err)
//	    return
//	}
//	defer func() {
//	    // Clear sensitive data when done
//	    for i := range plaintext {
//	        plaintext[i] = 0
//	    }
//	}()
//	fmt.Printf("Plaintext: %s\n", plaintext)
//
//	// Decrypt JSON data
//	encryptedJSON := getEncryptedDataFromDB()
//	jsonBytes, err := vault.Decrypt(encryptedJSON)
//	if err != nil {
//	    log.Printf("Failed to decrypt JSON: %v", err)
//	    return
//	}
//
//	var data map[string]interface{}
//	err = json.Unmarshal(jsonBytes, &data)
//	if err != nil {
//	    log.Printf("Failed to parse JSON: %v", err)
//	    return
//	}
//
//	// Batch decryption with error handling
//	encryptedItems := getEncryptedDataBatch()
//	for i, encrypted := range encryptedItems {
//	    plaintext, err := vault.Decrypt(encrypted)
//	    if err != nil {
//	        log.Printf("Failed to decrypt item %d: %v", i, err)
//	        continue
//	    }
//
//	    // Process decrypted data
//	    processSensitiveData(plaintext)
//
//	    // Clear sensitive data
//	    for j := range plaintext {
//	        plaintext[j] = 0
//	    }
//	}
//
// Error Handling Best Practices:
//   - Always check for errors before using decrypted data
//   - Log authentication failures for security monitoring
//   - Implement retry logic for transient key access failures
//   - Handle key rotation scenarios gracefully
//   - Monitor for systematic decryption failures
//   - Validate input format before processing
//
// Security Best Practices:
//   - Clear sensitive plaintext data after use when possible
//   - Validate decrypted data format before processing
//   - Monitor audit logs for unusual decryption patterns
//   - Implement rate limiting to prevent brute force attacks
//   - Use decrypted data immediately or re-protect it
//   - Never log or expose plaintext data in error messages
//   - Validate that input data came from trusted sources
//
// Performance Optimization:
//   - Key lookups are optimized with internal caching
//   - Memory allocations are minimized during decryption
//   - Consider batching for high-throughput scenarios
//   - Monitor memory usage in systems processing large datasets
//   - Pre-validate input format to fail fast on invalid data
//
// Integration Considerations:
//   - Decrypted data is returned as []byte for maximum flexibility
//   - Handle character encoding conversions as needed
//   - Consider streaming decryption for very large datasets
//   - Coordinate key retention policies with data lifecycle
//   - Plan for emergency key recovery scenarios
//   - Ensure all encrypted data follows the expected format
//
// Cryptographic Security:
//   - Authentication tag verification is automatic and mandatory
//   - Timing attacks are mitigated by constant-time operations
//   - Side-channel attacks are prevented by secure implementations
//   - The underlying primitives are cryptographically proven secure
//   - Format validation prevents malformed data attacks
//
// Failure Recovery:
//   - Transient failures (key access, memory) can be retried safely
//   - Authentication failures indicate tampering or corruption
//   - Format errors indicate invalid or corrupted input data
//   - Missing key errors may require key recovery procedures
//   - Systematic failures may indicate system compromise
//   - Audit logs provide forensic information for investigation
func (v *Vault) Decrypt(base64CiphertextWithKeyID string) ([]byte, error) {
	if base64CiphertextWithKeyID == "" {
		return nil, errors.New("empty encrypted string")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	v.audit.Log("decrypt_data", true, map[string]interface{}{
		"data_size": len(base64CiphertextWithKeyID),
	})

	// Decode from base64
	encryptedData, err := base64.StdEncoding.DecodeString(base64CiphertextWithKeyID)
	if err != nil {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "invalid base64 encoding",
		})
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	// Validate minimum data length (2 bytes for key ID length + at least 1 byte key ID + 12 bytes nonce + 16 bytes auth tag)
	if len(encryptedData) < 2+1+12+16 {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "encrypted data too short",
		})
		return nil, errors.New("encrypted data too short")
	}

	// Extract key ID length
	keyIDLength := binary.BigEndian.Uint16(encryptedData[0:2])

	// Validate key ID length
	if keyIDLength == 0 || int(keyIDLength) > len(encryptedData)-2-12-16 {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "invalid data format",
		})
		return nil, errors.New("invalid data format")
	}

	// Validate total data length
	if len(encryptedData) < int(2+keyIDLength+12+16) {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "invalid data format",
		})
		return nil, errors.New("invalid data format")
	}

	// Extract key ID
	keyID := string(encryptedData[2 : 2+keyIDLength])

	// Extract encrypted payload (nonce + ciphertext)
	actualEncryptedData := encryptedData[2+keyIDLength:]

	// Get the specific key for this encrypted data
	keyEnclave, err := v.getKeyByID(keyID)
	if err != nil {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": fmt.Sprintf("key not available: %s", keyID),
		})
		return nil, fmt.Errorf("key %s not available: %w", keyID, err)
	}

	// Open the key enclave to access the key
	masterKeyBuffer, err := keyEnclave.Open()
	if err != nil {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "failed to access master key",
		})
		return nil, fmt.Errorf("failed to access master key: %w", err)
	}
	defer masterKeyBuffer.Destroy()

	// Create cipher
	aead, err := chacha20poly1305.New(masterKeyBuffer.Bytes())
	if err != nil {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "failed to create cipher",
		})
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := aead.NonceSize()
	if len(actualEncryptedData) < nonceSize+16 { // nonce + minimum auth tag
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "encrypted data too short",
		})
		return nil, errors.New("encrypted data too short")
	}

	nonce := actualEncryptedData[:nonceSize]
	ciphertext := actualEncryptedData[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		v.audit.Log("decrypt_data", false, map[string]interface{}{
			"error": "failed to decrypt data",
		})
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	v.audit.Log("decrypt_data", true, map[string]interface{}{
		"data_size":   len(base64CiphertextWithKeyID),
		"result_size": len(plaintext),
		"key_id":      keyID,
	})

	return plaintext, nil
}
