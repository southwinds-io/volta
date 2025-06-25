package volta

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// Generate a random key ID
func generateKeyID() string {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		// Fall back to timestamp if random fails
		return fmt.Sprintf("key-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// copySecretMetadata deep copy SecretMetadata
func copySecretMetadata(original *SecretMetadata) *SecretMetadata {
	if original == nil {
		return nil
	}

	secretCopy := &SecretMetadata{
		SecretID:     original.SecretID,
		Version:      original.Version,
		ContentType:  original.ContentType,
		Description:  original.Description,
		Tags:         append([]string(nil), original.Tags...),
		KeyID:        original.KeyID,
		CreatedAt:    original.CreatedAt,
		UpdatedAt:    original.UpdatedAt,
		Size:         original.Size,
		Checksum:     original.Checksum,
		AccessCount:  original.AccessCount,
		LastAccessed: original.LastAccessed,
		ExpiresAt:    original.ExpiresAt,
	}

	// Deep copy custom fields
	if original.CustomFields != nil {
		secretCopy.CustomFields = make(map[string]string)
		for k, v := range original.CustomFields {
			secretCopy.CustomFields[k] = v
		}
	}

	// Copy time pointers
	if original.LastAccessed != nil {
		lastAccessed := *original.LastAccessed
		secretCopy.LastAccessed = &lastAccessed
	}

	if original.ExpiresAt != nil {
		expiresAt := *original.ExpiresAt
		secretCopy.ExpiresAt = &expiresAt
	}

	return secretCopy
}

func hasAllTags(secretTags, requiredTags []string) bool {
	for _, requiredTag := range requiredTags {
		found := false
		for _, secretTag := range secretTags {
			if secretTag == requiredTag {
				found = true
				break
			}
		}
		if !found {
			return false // If any required tag is missing, return false
		}
	}
	return true // All required tags were found
}

func deduplicateTags(tags []string) []string {
	if len(tags) == 0 {
		return tags
	}

	seen := make(map[string]bool)
	result := make([]string, 0, len(tags))

	for _, tag := range tags {
		if tag != "" && !seen[tag] { // Also skip empty tags
			seen[tag] = true
			result = append(result, tag)
		}
	}

	return result
}

func validateOptions(options Options) error {

	// Validate derivation passphrase requirements
	if options.DerivationPassphrase == "" && options.EnvPassphraseVar == "" {
		return fmt.Errorf("either DerivationPassphrase or EnvPassphraseVar must be provided")
	}

	// Validate passphrase strength if provided directly
	if options.DerivationPassphrase != "" {
		if len(options.DerivationPassphrase) < 12 {
			return fmt.Errorf("derivation passphrase must be at least 12 characters long: %s", options.DerivationPassphrase)
		}
	}

	// Validate environment variable name format
	if options.EnvPassphraseVar != "" {
		if !isValidEnvVarName(options.EnvPassphraseVar) {
			return fmt.Errorf("invalid environment variable name: %s", options.EnvPassphraseVar)
		}
	}

	// Validate salt if provided
	if len(options.DerivationSalt) > 0 && len(options.DerivationSalt) < 16 {
		return fmt.Errorf("derivation salt must be at least 16 bytes if provided")
	}

	return nil
}

func isValidEnvVarName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}

	// Must start with letter or underscore
	if !((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z') || name[0] == '_') {
		return false
	}

	// Rest can be letters, numbers, or underscores
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}

	return true
}

func validateSecretData(secretData []byte, contentType ContentType) error {
	if len(secretData) == 0 {
		return fmt.Errorf("secret data cannot be empty")
	}

	// Size limits
	const (
		MaxSecretSize = 10 * 1024 * 1024 // 10MB
		MinSecretSize = 1
	)

	if len(secretData) > MaxSecretSize {
		return fmt.Errorf("secret data too large: %d bytes (max: %d)", len(secretData), MaxSecretSize)
	}

	if len(secretData) < MinSecretSize {
		return fmt.Errorf("secret data too small: %d bytes (min: %d)", len(secretData), MinSecretSize)
	}

	// Validate content type specific requirements
	switch contentType {
	case ContentTypeText:
		if !utf8.Valid(secretData) {
			return fmt.Errorf("text content type requires valid UTF-8 data")
		}
	case ContentTypeJSON:
		if !json.Valid(secretData) {
			return fmt.Errorf("JSON content type requires valid JSON data")
		}
	case ContentTypePEM:
		if !isValidCertificateData(secretData) {
			return fmt.Errorf("certificate content type requires valid certificate data")
		}
	}

	return nil
}

func isValidCertificateData(data []byte) bool {
	// Check for PEM format
	if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Contains(data, []byte("-----BEGIN EC PRIVATE KEY-----")) || bytes.Contains(data, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		return true
	}
	// Check for DER format (basic validation)
	if len(data) > 4 && data[0] == 0x30 {
		return true
	}
	return false
}

func validateAndSanitizeTags(tags []string) ([]string, error) {
	if len(tags) == 0 {
		return []string{}, nil
	}

	const (
		MaxTags      = 50
		MaxTagLength = 128
		MinTagLength = 1
	)

	if len(tags) > MaxTags {
		return nil, fmt.Errorf("too many tags: %d (max: %d)", len(tags), MaxTags)
	}

	validTags := make([]string, 0, len(tags))
	seenTags := make(map[string]bool)

	for _, tag := range tags {
		// Trim whitespace
		tag = strings.TrimSpace(tag)

		// Skip empty tags
		if len(tag) == 0 {
			continue
		}

		// Length validation
		if len(tag) > MaxTagLength {
			return nil, fmt.Errorf("tag too long: %d characters (max: %d)", len(tag), MaxTagLength)
		}

		if len(tag) < MinTagLength {
			return nil, fmt.Errorf("tag too short: %d characters (min: %d)", len(tag), MinTagLength)
		}

		// Format validation - alphanumeric, hyphens, underscores only
		if !isValidTagFormat(tag) {
			return nil, fmt.Errorf("invalid tag format: %s (only alphanumeric, hyphens, and underscores allowed)", tag)
		}

		// Convert to lowercase for consistency
		tag = strings.ToLower(tag)

		// Deduplicate
		if !seenTags[tag] {
			seenTags[tag] = true
			validTags = append(validTags, tag)
		}
	}

	return validTags, nil
}

func isValidTagFormat(tag string) bool {
	if len(tag) == 0 {
		return false
	}

	for _, r := range tag {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == ':' || r == '.') {
			return false
		}
	}

	return true
}

func isValidContentType(ct ContentType) bool {
	validTypes := map[ContentType]bool{
		ContentTypeText:   true,
		ContentTypeBinary: true,
		ContentTypeJSON:   true,
		ContentTypePEM:    true,
		ContentTypeYAML:   true,
		ContentTypeXML:    true,
		ContentTypeTOML:   true,
		// Add other valid content types
	}

	return validTypes[ct]
}

func validateSecretID(secretID string) error {
	if secretID == "" {
		return fmt.Errorf("secret ID cannot be empty")
	}
	if len(secretID) > 255 {
		return fmt.Errorf("secret ID too long (max 255 characters)")
	}

	// Check for path traversal attempts
	if strings.Contains(secretID, "..") {
		return fmt.Errorf("secret ID contains invalid path traversal sequence")
	}

	// Check for double slashes
	if strings.Contains(secretID, "//") {
		return fmt.Errorf("secret ID contains double slashes")
	}

	// Check for leading or trailing slashes
	if strings.HasPrefix(secretID, "/") || strings.HasSuffix(secretID, "/") {
		return fmt.Errorf("secret ID cannot start or end with slash")
	}

	// Use pre-compiled regex for better performance
	if !secretIDRegex.MatchString(secretID) {
		return fmt.Errorf("secret ID '%s' contains invalid characters (allowed: a-z, A-Z, 0-9, -, _, /, .)", secretID)
	}

	return nil
}

// hasPrefix reports whether the string s begins with prefix.
func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}
