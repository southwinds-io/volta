package persist

import (
	"fmt"
	"strings"
	"time"
)

// NewStore factory function to create storage backends
func NewStore(config StoreConfig, tenantID string) (Store, error) {
	switch config.Type {
	case StoreTypeFileSystem:
		basePath, ok := config.Config["base_path"].(string)
		if !ok {
			return nil, fmt.Errorf("filesystem storage requires 'base_path' in config")
		}
		return NewFileSystemStore(basePath, tenantID)

	case StoreTypeS3:
		return NewS3StoreFromConfig(config, tenantID)

	default:
		return nil, fmt.Errorf("unsupported store type: %s", config.Type)
	}
}

// validateTenantID validates the tenant ID for security
func validateTenantID(tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Basic validation to prevent path traversal and other issues
	if strings.Contains(tenantID, "..") ||
		strings.Contains(tenantID, "/") ||
		strings.Contains(tenantID, "\\") ||
		strings.Contains(tenantID, " ") {
		return fmt.Errorf("tenant ID contains invalid characters")
	}

	// Length check
	if len(tenantID) > 100 {
		return fmt.Errorf("tenant ID too long (max 100 characters)")
	}

	return nil
}

func createSaltMetadata(tenantID string) map[string]string {
	return map[string]string{
		"vault-salt": "true",
		"data-type":  "salt",
		"tenant-id":  tenantID,
		"created-at": time.Now().UTC().Format(time.RFC3339),
	}
}
