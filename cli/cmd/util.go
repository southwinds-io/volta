package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

func getConfigFilePath(global bool) string {
	if global {
		// System-wide config (e.g., /etc/vault/config.yaml)
		return "/etc/vault/config.yaml"
	}

	if cfgFile != "" {
		return cfgFile
	}

	// User config
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vault.yaml")
}

func ensureConfigDir(configFile string) error {
	dir := filepath.Dir(configFile)
	return os.MkdirAll(dir, 0700)
}

func isValidConfigKey(key string) bool {
	validKeys := []string{
		"vault.store_type",
		"vault.path",
		"vault.passphrase",
		"vault.tenant",
		"vault.file.path",
		"vault.s3.bucket",
		"vault.s3.region",
		"vault.s3.prefix",
		"vault.redis.address",
		"vault.redis.db",
		"vault.redis.password",
		"audit.enabled",
		"audit.type",
		"audit.options.file_path",
		"audit.verbose",
	}

	for _, validKey := range validKeys {
		if key == validKey {
			return true
		}
	}
	return false
}

func convertStringValue(value string) (interface{}, error) {
	// Try to convert to appropriate type
	if value == "true" || value == "false" {
		return value == "true", nil
	}

	// Try integer
	if strings.Contains(value, ".") {
		// Try float
		if f, err := parseFloat(value); err == nil {
			return f, nil
		}
	} else {
		// Try integer
		if i, err := parseInt(value); err == nil {
			return i, nil
		}
	}

	// Return as string
	return value, nil
}

func unsetNestedKey(config map[string]interface{}, key string) error {
	parts := strings.Split(key, ".")

	// Navigate to parent
	current := config
	for i, part := range parts[:len(parts)-1] {
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return fmt.Errorf("key path not found at %s", strings.Join(parts[:i+1], "."))
		}
	}

	// Delete the final key
	delete(current, parts[len(parts)-1])
	return nil
}

func getConfigTemplate(template string) map[string]interface{} {
	switch template {
	case "minimal":
		return map[string]interface{}{
			"vault": map[string]interface{}{
				"store_type": "file",
				"path":       ".vault",
				"tenant":     "default",
			},
		}
	case "full":
		return map[string]interface{}{
			"vault": map[string]interface{}{
				"store_type": "file",
				"path":       ".vault",
				"tenant":     "default",
				"file": map[string]interface{}{
					"path": ".vault",
				},
				"s3": map[string]interface{}{
					"bucket": "",
					"region": "us-east-1",
					"prefix": "vault/",
				},
				"redis": map[string]interface{}{
					"address":  "localhost:6379",
					"db":       0,
					"password": "",
				},
			},
			"audit": map[string]interface{}{
				"enabled": false,
				"type":    "file",
				"options": map[string]interface{}{
					"file_path": "audit.log",
				},
				"verbose": false,
			},
		}
	default: // "default"
		return map[string]interface{}{
			"vault": map[string]interface{}{
				"store_type": "file",
				"path":       ".vault",
				"tenant":     "default",
			},
			"audit": map[string]interface{}{
				"enabled": false,
				"type":    "file",
				"options": map[string]interface{}{
					"file_path": "audit.log",
				},
			},
		}
	}
}

func validateConfiguration() []string {
	var errors []string

	// Validate store type
	storeType := viper.GetString("vault.store_type")
	validStoreTypes := []string{"file", "memory", "s3", "redis"}
	if !contains(validStoreTypes, storeType) {
		errors = append(errors, fmt.Sprintf("invalid store type: %s (must be one of: %s)",
			storeType, strings.Join(validStoreTypes, ", ")))
	}

	// Store-specific validation
	switch storeType {
	case "s3":
		if bucket := viper.GetString("vault.s3.bucket"); bucket == "" {
			errors = append(errors, "S3 bucket is required when using S3 store")
		}
	case "redis":
		if addr := viper.GetString("vault.redis.address"); addr == "" {
			errors = append(errors, "Redis address is required when using Redis store")
		}
	}

	// Validate audit configuration
	if viper.GetBool("audit.enabled") {
		auditType := viper.GetString("audit.type")
		validAuditTypes := []string{"file", "syslog"}
		if !contains(validAuditTypes, auditType) {
			errors = append(errors, fmt.Sprintf("invalid audit type: %s (must be one of: %s)",
				auditType, strings.Join(validAuditTypes, ", ")))
		}

		if auditType == "file" {
			if filePath := viper.GetString("audit.options.file_path"); filePath == "" {
				errors = append(errors, "audit file path is required when using file audit")
			}
		}
	}

	return errors
}

func getConfigKeyDescriptions() map[string]string {
	return map[string]string{
		"vault.store_type":        "Storage backend type (file, memory, s3, redis)",
		"vault.path":              "Path to vault storage (for file store)",
		"vault.passphrase":        "Vault passphrase for encryption",
		"vault.tenant":            "Tenant identifier",
		"vault.file.path":         "File store path",
		"vault.s3.bucket":         "S3 bucket name",
		"vault.s3.region":         "S3 region",
		"vault.s3.prefix":         "S3 key prefix",
		"vault.redis.address":     "Redis server address",
		"vault.redis.db":          "Redis database number",
		"vault.redis.password":    "Redis password",
		"audit.enabled":           "Enable audit logging",
		"audit.type":              "Audit logger type (file, syslog)",
		"audit.options.file_path": "Audit log file path",
		"audit.verbose":           "Enable verbose audit logging",
	}
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// parseInt attempts to parse a string as an integer
func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

// parseFloat attempts to parse a string as a float64
func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// printConfigTable prints configuration in table format
func printConfigTable() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "KEY\tVALUE\tSOURCE")
	fmt.Fprintln(w, "---\t-----\t------")

	// Get all settings
	settings := viper.AllSettings()
	var keys []string

	// Flatten nested keys
	flattenKeys(settings, "", &keys)
	sort.Strings(keys)

	for _, key := range keys {
		value := viper.Get(key)
		source := "default"
		if viper.ConfigFileUsed() != "" {
			source = filepath.Base(viper.ConfigFileUsed())
		}

		// Check if this is an environment variable
		envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		if os.Getenv(envKey) != "" || os.Getenv("VAULT_"+envKey) != "" {
			source = "environment"
		}

		// Mask sensitive values
		if isSensitiveConfigKey(key) {
			value = "[REDACTED]"
		}

		fmt.Fprintf(w, "%s\t%v\t%s\n", key, value, source)
	}

	return nil
}

// printConfigJSON prints configuration in JSON format
func printConfigJSON() error {
	config := viper.AllSettings()

	// Mask sensitive values
	maskSensitiveValues(config)

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// printConfigYAML prints configuration in YAML format
func printConfigYAML() error {
	config := viper.AllSettings()

	// Mask sensitive values
	maskSensitiveValues(config)

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

// printConfigKeysTable prints available configuration keys in table format
func printConfigKeysTable(keys map[string]string) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "KEY\tDESCRIPTION")
	fmt.Fprintln(w, "---\t-----------")

	// Sort keys
	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		fmt.Fprintf(w, "%s\t%s\n", key, keys[key])
	}

	return nil
}

// printConfigKeysYAML prints available configuration keys in YAML format
func printConfigKeysYAML(keys map[string]string) error {
	data, err := yaml.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to marshal keys to YAML: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

// printConfigKeysJSON prints available configuration keys in JSON format
func printConfigKeysJSON(keys map[string]string) error {
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// flattenKeys recursively flattens nested maps into dot-notation keys
func flattenKeys(m map[string]interface{}, prefix string, keys *[]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		if nested, ok := v.(map[string]interface{}); ok {
			flattenKeys(nested, key, keys)
		} else {
			*keys = append(*keys, key)
		}
	}
}

// isSensitiveConfigKey checks if a configuration key contains sensitive data
func isSensitiveConfigKey(key string) bool {
	sensitiveKeys := []string{"passphrase", "password", "secret", "key", "token", "auth"}
	lowerKey := strings.ToLower(key)

	for _, sensitive := range sensitiveKeys {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}
	return false
}

// maskSensitiveValues recursively masks sensitive values in configuration
func maskSensitiveValues(config map[string]interface{}) {
	for key, value := range config {
		if isSensitiveConfigKey(key) {
			config[key] = "[REDACTED]"
		} else if nested, ok := value.(map[string]interface{}); ok {
			maskSensitiveValues(nested)
		}
	}
}

// getDefaultEditor returns the default text editor for the current platform
func getDefaultEditor() string {
	// First check EDITOR environment variable
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}

	// Check VISUAL environment variable
	if visual := os.Getenv("VISUAL"); visual != "" {
		return visual
	}

	// Platform-specific defaults
	switch runtime.GOOS {
	case "windows":
		// Try common Windows editors
		editors := []string{"notepad++.exe", "notepad.exe", "code.exe"}
		for _, editor := range editors {
			if _, err := exec.LookPath(editor); err == nil {
				return editor
			}
		}
		return "notepad.exe"
	case "darwin":
		// Try common macOS editors
		editors := []string{"code", "nano", "vim", "vi"}
		for _, editor := range editors {
			if _, err := exec.LookPath(editor); err == nil {
				return editor
			}
		}
		return "nano"
	default:
		// Try common Unix/Linux editors
		editors := []string{"nano", "vim", "vi", "emacs", "code"}
		for _, editor := range editors {
			if _, err := exec.LookPath(editor); err == nil {
				return editor
			}
		}
		return "vi" // ultimate fallback
	}
}

// executeEditor launches the specified editor with the given file
func executeEditor(editor, file string) error {
	// Handle special cases for some editors
	var cmd *exec.Cmd

	switch {
	case strings.Contains(editor, "code"):
		// VS Code - wait for the window to be closed
		cmd = exec.Command(editor, "--wait", file)
	case strings.Contains(editor, "notepad++"):
		// Notepad++ - multiInstances and wait
		cmd = exec.Command(editor, "-multiInst", "-notabbar", file)
	default:
		// Default behavior for most editors
		cmd = exec.Command(editor, file)
	}

	// Connect to current terminal
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// convertValue attempts to convert a string value to its most appropriate type
func convertValue(value string) interface{} {
	// Handle boolean values
	switch strings.ToLower(value) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	}

	// Try to parse as integer
	if intVal, err := strconv.Atoi(value); err == nil {
		return intVal
	}

	// Try to parse as float
	if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
		return floatVal
	}

	// Handle null/nil values
	if strings.ToLower(value) == "null" || strings.ToLower(value) == "nil" {
		return nil
	}

	// Return as string
	return value
}

// validateConfigValue validates a configuration value based on its key
func validateConfigValue(key string, value interface{}) error {
	switch key {
	case "vault.store_type":
		validTypes := []string{"file", "memory", "s3", "redis"}
		if str, ok := value.(string); ok {
			if !contains(validTypes, str) {
				return fmt.Errorf("invalid store type: %s (valid: %s)", str, strings.Join(validTypes, ", "))
			}
		}
	case "vault.redis.db":
		if num, ok := value.(int); ok {
			if num < 0 || num > 15 {
				return fmt.Errorf("redis db must be between 0 and 15")
			}
		}
	case "audit.type":
		validTypes := []string{"file", "syslog", "stdout"}
		if str, ok := value.(string); ok {
			if !contains(validTypes, str) {
				return fmt.Errorf("invalid audit type: %s (valid: %s)", str, strings.Join(validTypes, ", "))
			}
		}
	}
	return nil
}

// promptConfirmation prompts the user for yes/no confirmation
func promptConfirmation(message string) bool {
	fmt.Printf("%s (y/N): ", message)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
