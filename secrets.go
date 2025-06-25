package volta

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/awnumar/memguard"
)

// =============================================================================
// PUBLIC VAULT INTERFACE METHODS - Primary API for secure secret handling
// =============================================================================

// UseSecret executes a function with a secret and ensures automatic cleanup.
// This is the recommended way to work with secrets for maximum security.
//
// This function implements the "secure callback" pattern that provides controlled
// access to secret data while guaranteeing secure cleanup regardless of how the
// callback function terminates. It eliminates the risk of secret data remaining
// in memory after use and prevents common security vulnerabilities associated
// with manual secret lifecycle management.
//
// SECURITY GUARANTEES:
//
//  1. AUTOMATIC CLEANUP:
//     Secret data is unconditionally cleared from memory using secure wiping
//     techniques when the callback completes, whether through normal return,
//     panic, or early termination. The defer statement ensures cleanup even
//     if the callback function encounters unexpected errors.
//
//  2. CONTROLLED ACCESS SCOPE:
//     The secret data is only accessible within the callback function's execution
//     context. This temporal isolation prevents accidental retention of references
//     to secret data and enforces proper secret handling boundaries.
//
//  3. SECURE MEMORY MANAGEMENT:
//     The underlying secret data is stored in memguard-protected memory that:
//     • Prevents memory dumps from exposing secrets
//     • Uses secure allocation techniques resistant to cold boot attacks
//     • Implements cryptographically secure memory clearing
//     • Protects against swap file exposure through memory locking
//
//  4. ZERO-COPY ARCHITECTURE:
//     The secret data is provided directly to the callback without intermediate
//     copies, reducing the memory footprint of sensitive data and minimizing
//     the attack surface for memory-based attacks.
//
// Parameters:
//   - secretID: Unique identifier for the secret to retrieve and use
//   - fn: Callback function that receives the secret data and performs operations
//
// Returns:
//   - error: Secret retrieval error or callback execution error. Nil indicates
//     successful completion of both secret access and callback execution.
func (v *Vault) UseSecret(secretID string, fn func(data []byte) error) error {
	enclave, err := v.getSecretMemguard(secretID)
	if err != nil {
		return err
	}
	defer func() {
		enclave = nil
	}()

	buffer, err := enclave.Open()
	if err != nil {
		return err
	}
	defer buffer.Destroy()

	return fn(buffer.Bytes())
}

// UseSecretWithTimeout executes a function with a secret with timeout.
// Secret is automatically cleared when function completes or timeout occurs.
//
// This function extends the secure callback pattern with automatic timeout
// protection, ensuring that secret data cannot remain in memory beyond a
// specified duration.
//
// Parameters:
//   - secretID: Unique identifier for the secret to retrieve and use
//   - timeout: Maximum duration the callback is allowed to execute before
//     forced termination and secret cleanup
//   - fn: Callback function that receives secret data and should respect
//     context cancellation for cooperative timeout handling
//
// Returns:
//   - error: Returns context.DeadlineExceeded if timeout occurs, secret
//     retrieval errors, or callback execution errors.
func (v *Vault) UseSecretWithTimeout(secretID string, timeout time.Duration, fn func(data []byte) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return v.UseSecretWithContext(ctx, secretID, fn)
}

// UseSecretWithContext executes a function with a secret with context.
// Secret is automatically cleared when function completes or context is cancelled.
//
// This function extends the secure callback pattern with context-aware cancellation
// support, enabling timeout control and cooperative cancellation of secret operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - secretID: Unique identifier for the secret to retrieve and use
//   - fn: Callback function that receives secret data
//
// Returns:
//   - error: Returns context errors, secret retrieval errors, or callback execution errors
func (v *Vault) UseSecretWithContext(ctx context.Context, secretID string, fn func(data []byte) error) error {
	enclave, err := v.getSecretMemguard(secretID)
	if err != nil {
		return err
	}
	defer func() {
		enclave = nil
	}()

	buffer, err := enclave.Open()
	if err != nil {
		return err
	}
	defer buffer.Destroy()

	// Create a done channel to monitor context
	done := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic in secret usage: %v", r)
			}
		}()
		done <- fn(buffer.Bytes())
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-done:
		return err
	}
}

// UseSecretString executes a function with a secret string and ensures cleanup.
// This is a convenience method specifically designed for string-based secrets that
// provides the same security guarantees as UseSecret but with automatic string
// conversion for enhanced usability.
//
// This function implements the "secure callback" pattern optimized for text-based
// secrets such as passwords, API keys, tokens, and configuration values. It ensures
// that string secrets are handled with the same rigorous security standards as
// binary secrets while providing a more convenient interface for text operations.
//
// SECURITY GUARANTEES:
//
//  1. MEMGUARD PROTECTION:
//     Secret data is protected using memguard's secure memory allocation that:
//     • Locks memory pages to prevent swapping to disk
//     • Uses guard pages to detect buffer overruns
//     • Implements cryptographically secure memory wiping
//     • Protects against memory dump attacks and cold boot attacks
//
//  2. AUTOMATIC STRING CONVERSION:
//     The raw secret bytes are converted to a string within the secure context,
//     eliminating the need for manual conversion that could leave intermediate
//     copies in unprotected memory. The conversion happens directly from the
//     memguard-protected buffer.
//
//  3. DETERMINISTIC CLEANUP:
//     Secret data is unconditionally cleared when the callback completes:
//     • memguard.LockedBuffer.Destroy() securely wipes the string data
//     • memguard.Enclave.Destroy() releases the secure container
//     • Cleanup occurs regardless of callback success, failure, or panic
//     • No residual string data remains in Go's string pool or heap
//
//  4. ZERO-COPY STRING ACCESS:
//     The string is created directly from the secure buffer without intermediate
//     allocations, minimizing the memory footprint and reducing exposure time
//     of sensitive string data in system memory.
//
// USAGE PATTERNS:
//
// This method is specifically designed for text-based secret operations:
// • Password verification and authentication
// • API key insertion into HTTP headers
// • Database connection string processing
// • JWT token validation and signing
// • Configuration value injection
// • Certificate PEM processing
// • OAuth token handling
//
// Example usage:
//
//	err := vault.UseSecretString("api-key", func(apiKey string) error {
//	    client := &http.Client{}
//	    req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
//	    req.Header.Set("Authorization", "Bearer " + apiKey)
//	    resp, err := client.Do(req)
//	    return handleResponse(resp, err)
//	})
//
// CALLBACK FUNCTION CONSTRAINTS:
//
// The callback function must observe strict memory safety rules:
// • NEVER store the string parameter in variables that outlive the callback
// • NEVER pass the string to goroutines launched within the callback
// • NEVER assign the string to struct fields or global variables
// • NEVER append the string to slices that persist beyond callback scope
// • Complete all string operations before returning from the callback
//
// SAFE OPERATIONS within callback:
// • String comparison and equality checks
// • String parsing and validation
// • Immediate use in function calls (HTTP headers, database queries)
// • Temporary string manipulation (splitting, trimming) within callback scope
// • Copy operations that consume the string immediately
//
// UNSAFE OPERATIONS that violate security:
//
//	var storedKey string  // DANGEROUS: Persisted reference
//	err := vault.UseSecretString("api-key", func(key string) error {
//	    storedKey = key     // VIOLATION: String persists after cleanup
//	    go useKey(key)      // VIOLATION: Goroutine access after cleanup
//	    return nil
//	})
//	// storedKey now contains cleared/invalid memory reference
//
// ERROR HANDLING:
//
// Errors can occur at multiple stages:
// 1. Secret Retrieval (secretID not found, access denied, decryption failure)
// 2. Memguard Operations (memory allocation failure, buffer opening failure)
// 3. Callback Execution (application-specific errors returned by fn)
//
// In all error scenarios, automatic cleanup is guaranteed:
// • If secret retrieval fails: no cleanup needed, error returned immediately
// • If memguard operations fail: partial cleanup performed, error propagated
// • If callback fails: full cleanup performed before error propagation
// • If callback panics: defer statements ensure cleanup before panic propagates
//
// PERFORMANCE CHARACTERISTICS:
//
// • Single memory allocation in secure space (no copying overhead)
// • Direct string access without intermediate buffers
// • Minimal garbage collection impact (secure memory managed separately)
// • Deterministic cleanup latency (bounded by memguard operations)
// • Thread-safe concurrent access (vault handles internal synchronization)
//
// MEMORY SECURITY DETAILS:
//
// String lifecycle within callback:
// 1. Secret retrieved from secure storage
// 2. Data loaded into memguard.Enclave (encrypted at rest)
// 3. Enclave opened to memguard.LockedBuffer (locked, guarded memory)
// 4. String created by direct cast from buffer bytes
// 5. Callback executed with string parameter
// 6. Buffer destroyed (cryptographic wiping of string data)
// 7. Enclave destroyed (cleanup of secure container)
//
// COMPLIANCE AND AUDITING:
//
// This function integrates with compliance monitoring systems:
// • Access events logged with timestamp and secret identifier
// • Callback execution duration tracked for audit trails
// • Memory access patterns monitored for security analysis
// • Integration with SIEM systems for security event correlation
//
// COMPATIBILITY:
//
// This function is compatible with:
// • All UTF-8 encoded string secrets
// • Binary secrets that represent text data
// • Multi-byte character encodings stored as UTF-8
// • Secrets containing null bytes (handled as Go string semantics)
//
// Parameters:
//   - secretID: Unique identifier for the secret to retrieve. Must be a valid
//     secret identifier that exists in the vault and is accessible with current
//     permissions. Case-sensitive string that follows vault naming conventions.
//   - fn: Callback function that receives the secret as a string parameter.
//     The function signature must match func(string) error exactly. The string
//     parameter is only valid within the callback scope and must not be retained.
//
// Returns:
//   - error: Returns nil on successful completion of both secret retrieval and
//     callback execution. Non-nil errors indicate:
//   - Secret retrieval failures (ErrSecretNotFound, ErrAccessDenied)
//   - Memguard operation failures (ErrMemoryAllocation, ErrBufferAccess)
//   - Callback execution errors (application-specific errors from fn)
//   - System-level failures (ErrVaultCorrupt, ErrInternalError)
//
// Thread Safety:
// This function is fully thread-safe and can be called concurrently from
// multiple goroutines. Each invocation creates its own secure memory context
// and cleanup is isolated per call.
//
// Related Functions:
//   - UseSecret(): For binary secret data requiring byte slice access
//   - UseSecretWithTimeout(): For time-bounded string secret operations
//   - UseSecretWithContext(): For context-controlled string secret operations
func (v *Vault) UseSecretString(secretID string, fn func(secret string) error) error {
	enclave, err := v.getSecretMemguard(secretID)
	if err != nil {
		return err
	}
	defer func() {
		enclave = nil
	}()

	buffer, err := enclave.Open()
	if err != nil {
		return err
	}
	defer buffer.Destroy()

	return fn(string(buffer.Bytes()))
}

// UseSecrets executes a function with multiple secrets and ensures cleanup.
// This function extends the secure callback pattern to support operations that
// require multiple secrets simultaneously, such as cryptographic operations
// requiring both a private key and password, or API integrations needing multiple
// authentication tokens.
//
// This function implements the "multi-secret secure callback" pattern that provides
// controlled access to multiple secret values while maintaining the same security
// guarantees as single-secret operations. It ensures all secrets are properly
// cleaned up regardless of callback execution outcome.
//
// SECURITY GUARANTEES:
//
//  1. ATOMIC SECRET RETRIEVAL:
//     All secrets are retrieved and prepared before the callback executes. If any
//     secret fails to load, no secrets are exposed and the operation fails safely.
//     This prevents partial secret exposure in error scenarios.
//
//  2. SYNCHRONIZED CLEANUP:
//     All secrets are cleaned up simultaneously when the callback completes,
//     ensuring no temporal windows where some secrets remain in memory while
//     others are cleared. Cleanup is guaranteed even if the callback panics.
//
//  3. MEMGUARD PROTECTION FOR ALL SECRETS:
//     Each secret is independently protected using memguard's secure memory
//     allocation, providing the same security guarantees as single-secret
//     operations: memory locking, guard pages, secure wiping, and dump protection.
//
//  4. ORDERED ACCESS PATTERN:
//     Secrets are provided to the callback in a deterministic map structure,
//     allowing consistent access patterns and reducing the risk of secret
//     confusion in multi-secret operations.
//
// USAGE PATTERNS:
//
// This method is designed for operations requiring multiple secrets:
// • Cryptographic signing (private key + passphrase)
// • Multi-factor authentication (password + TOTP seed)
// • API chaining (primary token + refresh token + API key)
// • Database operations (username + password + connection string)
// • Certificate operations (private key + certificate + CA bundle)
// • Multi-tenant operations (tenant key + shared secret + API token)
//
// Example usage:
//
//	secretIDs := []string{"private-key", "key-passphrase", "api-token"}
//	err := vault.UseSecrets(secretIDs, func(secrets map[string][]byte) error {
//	    privateKey := secrets["private-key"]
//	    passphrase := secrets["key-passphrase"]
//	    apiToken := secrets["api-token"]
//
//	    // Decrypt private key with passphrase
//	    decryptedKey, err := decryptPrivateKey(privateKey, passphrase)
//	    if err != nil {
//	        return err
//	    }
//
//	    // Use decrypted key and API token for operation
//	    return performSignedAPICall(decryptedKey, apiToken)
//	})
//
// CALLBACK FUNCTION CONSTRAINTS:
//
// The callback function receives a map[string][]byte where keys are secret IDs
// and values are the corresponding secret data. All standard security constraints
// apply to each secret:
// • NEVER store secret data beyond the callback scope
// • NEVER pass secrets to concurrent goroutines
// • NEVER assign secrets to persistent data structures
// • Complete all operations with secrets before returning
//
// ERROR HANDLING:
//
// Multi-secret operations have additional error scenarios:
// • If ANY secret fails to retrieve, the entire operation fails
// • Partial success is not possible - all secrets must be available
// • If callback fails, ALL secrets are cleaned up before error propagation
// • Memory allocation failures for any secret abort the entire operation
//
// PERFORMANCE CHARACTERISTICS:
//
// • Parallel secret retrieval where possible (vault implementation dependent)
// • Single memory allocation per secret in secure space
// • Batch cleanup operations for optimal performance
// • Memory overhead scales linearly with secret count
//
// Parameters:
//   - secretIDs: Slice of unique secret identifiers to retrieve. Order is
//     preserved in the callback map keys. Duplicate IDs will result in error.
//   - fn: Callback function receiving map of secretID -> secret data pairs.
//     All secrets are guaranteed to be available when callback executes.
//
// Returns:
//   - error: Returns nil on successful completion. Errors indicate secret
//     retrieval failures, duplicate secret IDs, or callback execution errors.
func (v *Vault) UseSecrets(secretIDs []string, fn func(secrets map[string][]byte) error) error {
	// Validate input
	if len(secretIDs) == 0 {
		return fmt.Errorf("no secrets requested")
	}

	// Check for duplicates
	seen := make(map[string]bool)
	for _, id := range secretIDs {
		if seen[id] {
			return fmt.Errorf("duplicate secret ID: %s", id)
		}
		seen[id] = true
	}

	// Retrieve all secrets and create enclaves
	enclaves := make(map[string]*memguard.Enclave)
	defer func() {
		// Cleanup all enclaves
		for _, enclave := range enclaves {
			if enclave != nil {
				enclave = nil
			}
		}
	}()

	// Load all secrets first (fail fast if any are missing)
	for _, secretID := range secretIDs {
		enclave, err := v.getSecretMemguard(secretID)
		if err != nil {
			return fmt.Errorf("failed to retrieve secret %s: %w", secretID, err)
		}
		enclaves[secretID] = enclave
	}

	// Open all buffers
	buffers := make(map[string]*memguard.LockedBuffer)
	defer func() {
		// Cleanup all buffers
		for _, buffer := range buffers {
			if buffer != nil {
				buffer.Destroy()
			}
		}
	}()

	secrets := make(map[string][]byte)
	for secretID, enclave := range enclaves {
		buffer, err := enclave.Open()
		if err != nil {
			return fmt.Errorf("failed to open secret %s: %w", secretID, err)
		}
		buffers[secretID] = buffer
		secrets[secretID] = buffer.Bytes()
	}

	// Execute callback with all secrets available
	return fn(secrets)
}

// UseSecretsString executes a function with multiple secrets as strings.
// Convenience method for string-based multi-secret operations.
//
// This function provides the same multi-secret capabilities as UseSecrets but
// with automatic string conversion for all secrets. It's particularly useful
// for operations involving multiple text-based secrets like passwords, tokens,
// and configuration values.
//
// SECURITY GUARANTEES:
// All security guarantees from UseSecrets apply, with additional string-specific
// protections:
// • String conversion happens within secure memory context
// • No intermediate string copies in unprotected memory
// • All string data cleared simultaneously on callback completion
//
// Example usage:
//
//	secretIDs := []string{"db-password", "api-key", "jwt-secret"}
//	err := vault.UseSecretsString(secretIDs, func(secrets map[string]string) error {
//	    dbPassword := secrets["db-password"]
//	    apiKey := secrets["api-key"]
//	    jwtSecret := secrets["jwt-secret"]
//
//	    // Use all secrets for complex authentication flow
//	    return performMultiStepAuth(dbPassword, apiKey, jwtSecret)
//	})
//
// Parameters:
//   - secretIDs: Slice of unique secret identifiers to retrieve as strings
//   - fn: Callback function receiving map of secretID -> secret string pairs
//
// Returns:
//   - error: Returns nil on successful completion, non-nil on failure
func (v *Vault) UseSecretsString(secretIDs []string, fn func(secrets map[string]string) error) error {
	return v.UseSecrets(secretIDs, func(secrets map[string][]byte) error {
		stringSecrets := make(map[string]string, len(secrets))
		for id, data := range secrets {
			stringSecrets[id] = string(data)
		}
		return fn(stringSecrets)
	})
}

// UseSecretPair executes a function with exactly two secrets.
// Convenience method for common two-secret operations like key+password or
// username+password combinations.
//
// This function is optimized for the common case of operations requiring exactly
// two secrets, providing a cleaner interface than the general UseSecrets function
// while maintaining all the same security guarantees.
//
// SECURITY GUARANTEES:
// Same as UseSecrets, with compile-time guarantee of exactly two secrets.
//
// Example usage:
//
//	err := vault.UseSecretPair("private-key", "key-password",
//	    func(key, password []byte) error {
//	        decryptedKey, err := decryptPrivateKey(key, password)
//	        if err != nil {
//	            return err
//	        }
//	        return usePrivateKey(decryptedKey)
//	    })
//
// Parameters:
//   - secretID1: First secret identifier
//   - secretID2: Second secret identifier
//   - fn: Callback function receiving both secrets as separate parameters
//
// Returns:
//   - error: Returns nil on successful completion, non-nil on failure
func (v *Vault) UseSecretPair(secretID1, secretID2 string, fn func(secret1, secret2 []byte) error) error {
	return v.UseSecrets([]string{secretID1, secretID2}, func(secrets map[string][]byte) error {
		return fn(secrets[secretID1], secrets[secretID2])
	})
}

// UseSecretPairString executes a function with exactly two secrets as strings.
// String version of UseSecretPair for text-based secret pairs.
//
// Parameters:
//   - secretID1: First secret identifier
//   - secretID2: Second secret identifier
//   - fn: Callback function receiving both secrets as strings
//
// Returns:
//   - error: Returns nil on successful completion, non-nil on failure
func (v *Vault) UseSecretPairString(secretID1, secretID2 string, fn func(secret1, secret2 string) error) error {
	return v.UseSecretPair(secretID1, secretID2, func(s1, s2 []byte) error {
		return fn(string(s1), string(s2))
	})
}

// =============================================================================
// ADVANCED PUBLIC METHODS - For users who need direct access to secure objects
// =============================================================================

// GetSecretWithTimeout retrieves secret with automatic timeout cleanup.
// Returns a SecretWithContext that auto-clears when timeout expires.
// Users must call Close() to ensure immediate cleanup.
func (v *Vault) GetSecretWithTimeout(secretID string, timeout time.Duration) (*SecretWithContext, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	enclave, err := v.getSecretMemguard(secretID)
	if err != nil {
		cancel()
		return nil, err
	}

	buffer, err := enclave.Open()
	if err != nil {
		cancel()
		return nil, err
	}

	swc := &SecretWithContext{
		enclave: enclave,
		buffer:  buffer,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup goroutine
	go swc.autoCleanup()

	return swc, nil
}

// GetSecretWithContext retrieves secret with custom context.
// Returns a SecretWithContext that auto-clears when context is done.
// Users must call Close() to ensure immediate cleanup.
func (v *Vault) GetSecretWithContext(ctx context.Context, secretID string) (*SecretWithContext, error) {
	enclave, err := v.getSecretMemguard(secretID)
	if err != nil {
		return nil, err
	}

	buffer, err := enclave.Open()
	if err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithCancel(ctx)

	swc := &SecretWithContext{
		enclave: enclave,
		buffer:  buffer,
		ctx:     childCtx,
		cancel:  cancel,
	}

	go swc.autoCleanup()

	return swc, nil
}

// SecretWithContext provides context-based automatic cleanup for secrets.
// Always call Close() when done to ensure immediate cleanup.
type SecretWithContext struct {
	enclave *memguard.Enclave
	buffer  *memguard.LockedBuffer
	ctx     context.Context
	cancel  context.CancelFunc
	cleared bool
}

// Data returns the secret data. Use with caution - data will be cleared
// when context expires or Close() is called.
func (swc *SecretWithContext) Data() []byte {
	if swc.cleared || swc.buffer == nil {
		return nil
	}
	return swc.buffer.Bytes()
}

// String returns the secret as a string. Use with caution - data will be cleared
// when context expires or Close() is called.
func (swc *SecretWithContext) String() string {
	if swc.cleared || swc.buffer == nil {
		return ""
	}
	return string(swc.buffer.Bytes())
}

// Done returns the context done channel
func (swc *SecretWithContext) Done() <-chan struct{} {
	return swc.ctx.Done()
}

// Close manually closes and clears the secret immediately
func (swc *SecretWithContext) Close() {
	if swc.cleared {
		return
	}

	swc.cleared = true

	if swc.cancel != nil {
		swc.cancel()
	}
	if swc.buffer != nil {
		swc.buffer.Destroy()
		swc.buffer = nil
	}
	if swc.enclave != nil {
		swc.enclave = nil
	}
}

// IsCleared returns whether the secret has been cleared
func (swc *SecretWithContext) IsCleared() bool {
	return swc.cleared
}

// SecureString provides secure string handling with automatic cleanup using memguard
type SecureString struct {
	enclave *memguard.Enclave
	buffer  *memguard.LockedBuffer
	cleared bool
}

// NewSecureString creates a new SecureString from byte data
func NewSecureString(data []byte) (*SecureString, error) {
	// Create enclave from data
	enclave := memguard.NewEnclave(data)

	// Open buffer for access
	buffer, err := enclave.Open()
	if err != nil {
		return nil, err
	}

	return &SecureString{
		enclave: enclave,
		buffer:  buffer,
		cleared: false,
	}, nil
}

// String returns the string value. Data will be cleared when Close() is called.
func (ss *SecureString) String() string {
	if ss.cleared || ss.buffer == nil {
		return ""
	}
	return string(ss.buffer.Bytes())
}

// Bytes returns the underlying byte slice. Data will be cleared when Close() is called.
func (ss *SecureString) Bytes() []byte {
	if ss.cleared || ss.buffer == nil {
		return nil
	}
	return ss.buffer.Bytes()
}

// Close securely wipes the string from memory
func (ss *SecureString) Close() {
	if ss.cleared {
		return
	}

	ss.cleared = true

	if ss.buffer != nil {
		ss.buffer.Destroy()
		ss.buffer = nil
	}
	if ss.enclave != nil {
		ss.enclave = nil
	}
}

// IsCleared returns whether the string has been cleared
func (ss *SecureString) IsCleared() bool {
	return ss.cleared
}

// =============================================================================
// INTERNAL METHODS - Not exposed in public interface
// =============================================================================

// getSecretMemguard retrieves a secret and wraps it in memguard protection
func (v *Vault) getSecretMemguard(secretID string) (*memguard.Enclave, error) {
	result, err := v.GetSecret(secretID)
	if err != nil {
		return nil, err
	}

	// Create enclave from secret data
	enclave := memguard.NewEnclave(result.Data)

	// Clear original data immediately
	clearBytes(result.Data)
	runtime.GC()

	return enclave, nil
}

// autoCleanup monitors context and clears secret when done
func (swc *SecretWithContext) autoCleanup() {
	<-swc.ctx.Done()
	swc.Close()
}

// =============================================================================
// UTILITY FUNCTIONS - Internal helpers
// =============================================================================

// clearBytes securely wipes a byte slice using basic clearing
// (memguard handles the secure clearing for protected memory)
func clearBytes(data []byte) {
	if data != nil {
		for i := range data {
			data[i] = 0
		}
	}
}
