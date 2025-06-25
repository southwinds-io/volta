# **Architectural Guide to Secret Management with Volta**

#### **1. Introduction**
Securely managing secrets (API keys, credentials, encryption keys) in a running application is a critical engineering challenge. Leaks often occur not while secrets are at rest, but in memory during active use. An effective secret management library must therefore be designed to minimize a secret's exposure time and guarantee its cleanup, especially in the face of concurrency, errors, and application panics.

This guide outlines the architectural patterns for in-memory secret management as implemented by Volta. It prioritizes two primary approaches:

1.  **The Scoped Callback:** The most secure pattern, where the secret's lifecycle is entirely managed by the library within an isolated function scope.
2.  **The Managed Handle:** A more flexible pattern for multi-step or long-running operations, which provides a time-bound or context-aware handle to the secret that requires disciplined lifecycle management by the developer.

#### **2. Core Security Philosophy**
Volta's API is built on these foundational principles:

*   **Minimize Exposure:** Secrets should exist in a decrypted state in memory for the absolute shortest duration required.
*   **Guarantee Cleanup:** Memory clearing must be automatic and panic-safe wherever possible.
*   **Fail-Safe by Default:** The simplest and most common methods should also be the most secure, requiring no extra configuration to be safe.
*   **Defense in Depth:** Provide multiple, overlapping layers of protection against accidental secret leakage (e.g., scoping, context cancellation, automatic timeouts).

---

### **Pattern 1: The Scoped Callback (Recommended)**

**Principle:** The developer provides the *logic* to be executed, and the library provides the *secret* to that logic within a secure, ephemeral scope. This pattern is the cornerstone of Volta.

**Implementation:** `UseSecret`, `UseSecretString`, `UseSecretWithContext`, `UseSecretWithTimeout`

This is the default and most secure way to use secrets. The library guarantees that the memory holding the secret is securely cleared immediately after the provided function returns, even if it panics.

**Basic Usage:**
```go
import "fmt"

// For a single, self-contained operation.
func setAuthorizationHeader(vault volta.VaultService, secretID string) error {
	return vault.UseSecret(secretID, func(token []byte) error {
		// The 'token' slice is valid ONLY inside this function.
		// Cleanup is automatic and guaranteed upon return.
		fmt.Printf("Using token to perform an action...\n")
		// e.g., req.Header.Set("Authorization", "Bearer "+string(token))
		return nil
	})
}
```

**Production Best Practice: Usage with Context**
For any operation involving network I/O or that needs to respect application-level cancellation, the `WithContext` variants are strongly recommended. 
They inherit all the security of the basic pattern while adding protection against hung goroutines holding secrets in memory.

```go
import "context"

// Integrates secret access with application lifecycle (e.g., an HTTP request).
func authenticateRequest(ctx context.Context, vault volta.VaultService, secretID string) error {
	return vault.UseSecretWithContext(ctx, secretID, func(key []byte) error {
		// If 'ctx' is cancelled while this logic is running,
		// the operation should respect it. The secret's lifecycle
		// is also bound to this context.
		// e.g., performAuthentication(ctx, key)
		return nil
	})
}
```

**Benefits of this Pattern:**
*   **Guaranteed Cleanup:** The developer cannot forget to clear the secret from memory.
*   **Minimal Scope:** The secret is only accessible within the callback, preventing accidental leakage.
*   **Reference-Safe:** It is impossible to retain a dangling reference to the secret's memory.
*   **Inherently Safe:** It is secure by default.

**When to Use:**
This should be the default choice for over 95% of use cases, including single API calls, database connection setup, and on-the-fly data encryption.

---

### **Pattern 2: The Managed Handle (Advanced)**

**Principle:** For complex use cases, the library provides a time-bound or context-aware "handle" to a secret. 
The developer is responsible for the handle's lifecycle but is aided by automatic expiration.

**Implementation:** `GetSecretWithContext`, `GetSecretWithTimeout` (which return a `*SecretWithContext` handle)

This pattern provides the flexibility needed for multi-step or long-running operations where a single callback is insufficient. 
It demands disciplined handling to maintain security.

**Correct Usage:**
Using this pattern correctly involves two non-negotiable developer responsibilities:
1.  **Always `defer Close()`:** Ensure the handle is closed and its resources are released.
2.  **Always Monitor `Done()`:** Respect the handle's lifecycle by monitoring its expiration channel in `select` statements.

```go
import (
	"context"
	"errors"
	"time"
)

// For a long-running worker that processes items from a queue.
func longRunningWorker(ctx context.Context, vault volta.VaultService) error {
	// Get a managed handle to the secret, tied to the worker's context.
	handle, err := vault.GetSecretWithContext(ctx, "service-key")
	if err != nil {
		return err
	}
	// 1. CRITICAL: Cleanup must be guaranteed, even if the function panics.
	defer handle.Close()

	workQueue := time.NewTicker(2 * time.Second) // Example queue
	defer workQueue.Stop()

	for {
		select {
		// 2. CRITICAL: The handle's Done() channel signals expiration or context cancellation.
		case <-handle.Done():
			return errors.New("secret handle expired or was invalidated")
		case <-workQueue.C:
			// 3. Use the secret data for the immediate operation.
			// Do not store the result of handle.Data() in a long-lived variable.
			err := processWork(handle.Data())
			if err != nil {
				return err
			}
		}
	}
}

func processWork(secretData []byte) error {
	// Use secretData here...
	fmt.Println("Processing work with the secret...")
	return nil
}
```

**When to Use:**
*   Multi-step batch processes that require the same secret repeatedly.
*   Managing authenticated connection pools.
*   Long-running background services with graceful shutdown requirements.

---

### **Core Security Principles**

Adherence to these rules is mandatory for secure operation, especially when using the **Managed Handle** pattern.

1.  **Always Defer Cleanup:** When using a managed handle (`GetSecret...`), `defer handle.Close()` must be the line immediately following the error check.
2.  **Never Store Secret Data:** Do not assign the result of `handle.Data()` to a variable that outlives the immediate operation. It is a temporary view, not a transferable value.
3.  **Monitor Handle Expiration:** The `handle.Done()` channel is a security boundary. It signals that the secret has been cleared from memory and must be handled.
4.  **Do Not Share Handles:** A secret handle must not be passed across untrusted boundaries or to goroutines that do not respect its lifecycle (`Done()` channel).

---

### **Practical Application Patterns**

#### **Database Connection**
The Scoped Callback is ideal for securely providing credentials to a database driver, ensuring the password does not linger in memory.

```go
import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq" // Example using PostgreSQL driver
)

func connectToDatabase(vault volta.VaultService) (*sql.DB, error) {
	var db *sql.DB
	err := vault.UseSecretString("db/password", func(password string) error {
		dsn := fmt.Sprintf("user=app password=%s host=localhost dbname=mydb sslmode=disable", password)
		var err error
		db, err = sql.Open("postgres", dsn)
		if err != nil {
			return err
		}
		return db.Ping()
	})

	if err != nil {
		if db != nil {
			db.Close() // Ensure DB resources are cleaned up on failure.
		}
		return nil, fmt.Errorf("failed to establish database connection: %w", err)
	}
	return db, nil
}
```

#### **Authenticated HTTP Client**
This pattern ensures an API token is only in memory for the duration of the HTTP request.

```go
import (
	"context"
	"net/http"
	"time"
)

func makeAuthenticatedRequest(ctx context.Context, vault volta.VaultService, url string) (*http.Response, error) {
	var resp *http.Response
	err := vault.UseSecretWithContext(ctx, "api/token", func(token []byte) error {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+string(token))

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err = client.Do(req)
		return err
	})

	if err != nil {
		return nil, err
	}
	return resp, nil
}
```