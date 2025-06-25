package cmd

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
	"southwinds.dev/volta/persist"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	vaultPath    string
	passphrase   string
	tenantID     string
	vaultManager volta.VaultManagerService
	vaultSvc     volta.VaultService
	auditLogger  audit.Logger
	cliContext   *CLIContext
)

type CLIContext struct {
	UserID    string
	SessionID string
	Source    string // hostname/IP
	StartTime time.Time
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "A secure embedded vault for managing secrets and encryption keys",
	Long: `A secure embedded vault that provides encryption key management and secret storage.
The vault uses ChaCha20-Poly1305 encryption with automatic key rotation capabilities and 
secure memory protection for sensitive data.`,
	PersistentPreRunE: initializeVault,
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if vaultSvc != nil {
			return vaultSvc.Close()
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags - consistent with config file structure
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault.yaml)")
	rootCmd.PersistentFlags().StringVarP(&vaultPath, "vault-path", "p", "", "path to vault storage")
	rootCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "vault passphrase (or use VAULT_PASSPHRASE env var)")
	rootCmd.PersistentFlags().StringVarP(&tenantID, "tenant", "t", "", "tenant identifier")
	rootCmd.PersistentFlags().String("store-type", "", "storage backend type (file, s3)")

	// Bind flags to viper
	bindFlagOrPanic("vault.path", "vault-path")
	bindFlagOrPanic("vault.passphrase", "passphrase")
	bindFlagOrPanic("vault.tenant", "tenant")
	bindFlagOrPanic("vault.store_type", "store-type")

	// Audit flags
	rootCmd.PersistentFlags().Bool("audit", false, "enable audit logging")
	rootCmd.PersistentFlags().String("audit-type", "", "audit logger type (file, syslog)")
	rootCmd.PersistentFlags().String("audit-file", "", "audit log file path")
	rootCmd.PersistentFlags().Bool("audit-verbose", false, "enable verbose audit logging")

	// Bind audit flags
	bindFlagOrPanic("audit.enabled", "audit")
	bindFlagOrPanic("audit.type", "audit-type")
	bindFlagOrPanic("audit.options.file_path", "audit-file")
	bindFlagOrPanic("audit.verbose", "audit-verbose")

	// S3 flags (for direct CLI usage)
	rootCmd.PersistentFlags().String("s3-endpoint", "", "S3 endpoint URL")
	rootCmd.PersistentFlags().String("s3-region", "", "S3 region")
	rootCmd.PersistentFlags().String("s3-bucket", "", "S3 bucket name")
	rootCmd.PersistentFlags().String("s3-prefix", "", "S3 key prefix")
	rootCmd.PersistentFlags().String("s3-access-key", "", "S3 access key ID")
	rootCmd.PersistentFlags().String("s3-secret-key", "", "S3 secret access key")
	rootCmd.PersistentFlags().Bool("s3-use-ssl", true, "Use SSL for S3 connections")

	// Bind S3 flags
	bindFlagOrPanic("vault.s3.endpoint", "s3-endpoint")
	bindFlagOrPanic("vault.s3.region", "s3-region")
	bindFlagOrPanic("vault.s3.bucket", "s3-bucket")
	bindFlagOrPanic("vault.s3.prefix", "s3-prefix")
	bindFlagOrPanic("vault.s3.access_key_id", "s3-access-key")
	bindFlagOrPanic("vault.s3.secret_access_key", "s3-secret-key")
	bindFlagOrPanic("vault.s3.use_ssl", "s3-use-ssl")
}

func bindFlagOrPanic(configKey, flagName string) {
	if err := viper.BindPFlag(configKey, rootCmd.PersistentFlags().Lookup(flagName)); err != nil {
		panic(fmt.Sprintf("failed to bind %s flag: %v", flagName, err))
	}
}

func initConfig() {
	// Set defaults first
	setDefaults()

	// Configure config file paths
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Search in multiple locations for consistency
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/vault")

		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault") // Consistent naming
	}

	// Environment variable support
	viper.SetEnvPrefix("VAULT") // Changed from VOLTA to VAULT for consistency
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file found but error reading it
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
		}
		// Config file not found is OK - we'll use defaults and env vars
	} else {
		if os.Getenv("DEBUG") == "true" {
			fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
		}
	}
}

func setDefaults() {
	// Vault defaults - consistent paths
	viper.SetDefault("vault.path", ".vault")
	viper.SetDefault("vault.tenant", "default")
	viper.SetDefault("vault.store_type", "file")

	// S3 defaults
	viper.SetDefault("vault.s3.region", "us-east-1")
	viper.SetDefault("vault.s3.prefix", "vault/")
	viper.SetDefault("vault.s3.use_ssl", true)

	// Audit defaults - use consistent path structure
	viper.SetDefault("audit.enabled", false)
	viper.SetDefault("audit.type", "file")
	viper.SetDefault("audit.options.max_size", 100)
	viper.SetDefault("audit.options.max_backups", 5)
	viper.SetDefault("audit.log_level", "info")

	// Set audit file path based on vault path - will be updated in initializeVault
	viper.SetDefault("audit.options.file_path", "audit.log")
}

func initializeVault(cmd *cobra.Command, args []string) error {
	// Skip initialization for help and completion commands
	if cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "__complete" || cmd.Name() == "config" {
		return nil
	}

	// Get configuration values with proper fallbacks
	vaultPath = viper.GetString("vault.path")
	tenantID = viper.GetString("vault.tenant")

	// Set audit file path relative to vault path if not explicitly set
	if viper.GetString("audit.options.file_path") == "audit.log" {
		auditPath := filepath.Join(vaultPath, "audit.log")
		viper.Set("audit.options.file_path", auditPath)
	}

	// Get passphrase from multiple sources
	passphrase = viper.GetString("vault.passphrase")
	if passphrase == "" {
		passphrase = os.Getenv("VAULT_PASSPHRASE") // Consistent with env prefix
	}

	if passphrase == "" {
		return fmt.Errorf("vault passphrase is required. Use --passphrase flag or VAULT_PASSPHRASE environment variable")
	}

	// Create base vault directory if it doesn't exist
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Initialize vault manager with base options
	options := volta.Options{
		DerivationPassphrase: passphrase,
		EnvPassphraseVar:     "VAULT_PASSPHRASE",
	}

	// Initialize CLI context
	cliContext = &CLIContext{
		UserID:    getCurrentUser(),
		SessionID: generateSessionID(),
		Source:    getHostname(),
		StartTime: time.Now(),
	}

	// Create audit logger with config-based settings
	var err error
	auditLogger, err = createAuditLogger()
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Create vault manager
	storeType := viper.GetString("vault.store_type")
	vaultManager, err = createVaultManager(storeType, options, auditLogger)
	if err != nil {
		return fmt.Errorf("failed to create vault manager: %w", err)
	}

	// Get vault for the specified tenant
	vs, err := vaultManager.GetVault(tenantID)
	if err != nil {
		return fmt.Errorf("failed to initialize vault for tenant %s: %w", tenantID, err)
	}
	vaultSvc = vs

	return nil
}

func createAuditLogger() (audit.Logger, error) {
	// Use configuration values instead of hardcoded ones
	return audit.NewLogger(&audit.Config{
		Enabled:  viper.GetBool("audit.enabled"),
		TenantID: viper.GetString("vault.tenant"),
		Type:     audit.ConfigType(viper.GetString("audit.type")),
		Options: map[string]interface{}{
			"file_path":   viper.GetString("audit.options.file_path"),
			"max_size":    viper.GetInt("audit.options.max_size"),
			"max_backups": viper.GetInt("audit.options.max_backups"),
		},
		LogLevel: viper.GetString("audit.log_level"),
	})
}

func createVaultManager(storeType string, options volta.Options, auditLogger audit.Logger) (volta.VaultManagerService, error) {
	switch strings.ToLower(storeType) {
	case "file":
		// Use configured vault path
		path := viper.GetString("vault.path")
		return volta.NewVaultManagerFileStore(options, path, auditLogger), nil

	case "s3":
		s3Config := persist.S3Config{
			Endpoint:        viper.GetString("vault.s3.endpoint"),
			AccessKeyID:     viper.GetString("vault.s3.access_key_id"),
			SecretAccessKey: viper.GetString("vault.s3.secret_access_key"),
			Bucket:          viper.GetString("vault.s3.bucket"),
			KeyPrefix:       viper.GetString("vault.s3.prefix"),
			UseSSL:          viper.GetBool("vault.s3.use_ssl"),
			Region:          viper.GetString("vault.s3.region"),
		}

		if err := validateS3Config(s3Config); err != nil {
			return nil, fmt.Errorf("invalid S3 configuration: %w", err)
		}

		return volta.NewVaultManagerS3Store(options, s3Config, auditLogger)

	default:
		return nil, fmt.Errorf("unsupported store type: %s. Supported types: file, s3", storeType)
	}
}

func validateS3Config(config persist.S3Config) error {
	var missing []string

	if config.Bucket == "" {
		missing = append(missing, "vault.s3.bucket")
	}
	if config.Region == "" {
		missing = append(missing, "vault.s3.region")
	}

	hasAccessKey := config.AccessKeyID != ""
	hasSecretKey := config.SecretAccessKey != ""

	if hasAccessKey && !hasSecretKey {
		missing = append(missing, "vault.s3.secret_access_key")
	}
	if !hasAccessKey && hasSecretKey {
		missing = append(missing, "vault.s3.access_key_id")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	return nil
}

// getStoreConfigSummary returns a summary of the current store configuration (for logging/debugging)
func getStoreConfigSummary(storeType string) string {
	switch strings.ToLower(storeType) {
	case "file":
		return fmt.Sprintf("File store: path=%s", viper.GetString("vault.path"))
	case "s3":
		return fmt.Sprintf("S3 store: bucket=%s, region=%s, prefix=%s",
			viper.GetString("vault.s3.bucket"),
			viper.GetString("vault.s3.region"),
			viper.GetString("vault.s3.prefix"))
	default:
		return fmt.Sprintf("Unknown store type: %s", storeType)
	}
}

// Helper function to check if a flag name is sensitive (for logging purposes)
func isSensitiveFlag(name string) bool {
	sensitive := []string{"passphrase", "password", "secret", "key", "token"}
	lower := strings.ToLower(name)
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// getCurrentUser retrieves the username of the currently logged-in user.
// It returns "unknown_user" if the user cannot be determined.
func getCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		log.Printf("Warning: could not get current user: %v. Falling back to 'unknown_user'.", err)
		// This can happen in restricted environments or certain OSes (e.g., scratch Docker images without /etc/passwd)
		// You might also try OS-specific environment variables like USER or LOGNAME as a fallback.
		// For simplicity, we'll just return a default.
		envUser := os.Getenv("USER")
		if envUser != "" {
			return envUser
		}
		return "unknown_user"
	}
	return currentUser.Username
}

// generateSessionID creates a new unique session identifier.
// Uses UUID v4.
func generateSessionID() string {
	id := uuid.New()
	return id.String()
}

// getHostname retrieves the hostname of the machine.
// It returns "unknown_host" if the hostname cannot be determined.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Warning: could not get hostname: %v. Falling back to 'unknown_host'.", err)
		return "unknown_host"
	}
	return hostname
}

// Debug command to show current configuration
var debugConfigCmd = &cobra.Command{
	Use:   "debug-config",
	Short: "Show current configuration values",
	Long:  "Display the current configuration values read from files, environment variables, and defaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Configuration Debug Information\n")
		fmt.Printf("==============================\n\n")

		if viper.ConfigFileUsed() != "" {
			fmt.Printf("Config file: %s\n", viper.ConfigFileUsed())
		} else {
			fmt.Printf("Config file: none found\n")
		}

		fmt.Printf("\nEnvironment Variables (VAULT_* prefix):\n")
		for _, env := range os.Environ() {
			if strings.HasPrefix(env, "VAULT_") {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) == 2 {
					if isSensitiveFlag(parts[0]) {
						fmt.Printf("  %s=***REDACTED***\n", parts[0])
					} else {
						fmt.Printf("  %s=%s\n", parts[0], parts[1])
					}
				}
			}
		}

		fmt.Printf("\nCurrent Configuration:\n")
		fmt.Printf("  Store Type: %s\n", viper.GetString("vault.store_type"))
		fmt.Printf("  Vault Path: %s\n", viper.GetString("vault.path"))
		fmt.Printf("  Tenant: %s\n", viper.GetString("vault.tenant"))
		fmt.Printf("  Passphrase: %s\n", func() string {
			if viper.GetString("vault.passphrase") != "" {
				return "***SET***"
			}
			return "***NOT SET***"
		}())

		fmt.Printf("\nAudit Configuration:\n")
		fmt.Printf("  Enabled: %v\n", viper.GetBool("audit.enabled"))
		fmt.Printf("  Type: %s\n", viper.GetString("audit.type"))
		fmt.Printf("  File Path: %s\n", viper.GetString("audit.options.file_path"))
		fmt.Printf("  Verbose: %v\n", viper.GetBool("audit.verbose"))

		storeType := viper.GetString("vault.store_type")
		if strings.ToLower(storeType) == "s3" {
			fmt.Printf("\nS3 Configuration:\n")
			fmt.Printf("  Endpoint: %s\n", viper.GetString("vault.s3.endpoint"))
			fmt.Printf("  Region: %s\n", viper.GetString("vault.s3.region"))
			fmt.Printf("  Bucket: %s\n", viper.GetString("vault.s3.bucket"))
			fmt.Printf("  Prefix: %s\n", viper.GetString("vault.s3.prefix"))
			fmt.Printf("  Use SSL: %v\n", viper.GetBool("vault.s3.use_ssl"))
			fmt.Printf("  Access Key: %s\n", func() string {
				if viper.GetString("vault.s3.access_key_id") != "" {
					return "***SET***"
				}
				return "***NOT SET***"
			}())
			fmt.Printf("  Secret Key: %s\n", func() string {
				if viper.GetString("vault.s3.secret_access_key") != "" {
					return "***SET***"
				}
				return "***NOT SET***"
			}())
		}

		fmt.Printf("\nStore Configuration Summary:\n")
		fmt.Printf("  %s\n", getStoreConfigSummary(storeType))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(debugConfigCmd)
}

func auditCmdStart(cmd *cobra.Command, args []string) time.Time {
	now := time.Now()
	err := auditLogger.Log("command_start", true, map[string]interface{}{
		"command":    cmd.CommandPath(),
		"args":       sanitizeArgs(args),
		"flags":      sanitizeFlags(cmd),
		"user_id":    cliContext.UserID,
		"session_id": cliContext.SessionID,
		"source":     cliContext.Source,
	})
	if err != nil {
		log.Printf("ERROR: %v\n", err)
	}
	return now
}

func auditCmdComplete(cmd *cobra.Command, err error, startedTime time.Time) error {
	// Log command completion
	if auditLogger != nil {
		auditLogger.Log("command_complete", err == nil, map[string]interface{}{
			"command":     cmd.CommandPath(),
			"duration_ms": time.Since(startedTime).Milliseconds(),
			"success":     err == nil,
			"error":       formatError(err),
			"user_id":     cliContext.UserID,
			"session_id":  cliContext.SessionID,
		})
	}
	return err
}

func formatError(err error) string {
	if err == nil {
		return ""
	}

	var messages []string

	// Unwrap the error chain and collect all messages
	for err != nil {
		messages = append(messages, err.Error())
		err = errors.Unwrap(err)
	}

	// If we have multiple errors in the chain, show the hierarchy
	if len(messages) > 1 {
		// Remove duplicates that might occur from unwrapping
		uniqueMessages := make([]string, 0, len(messages))
		seen := make(map[string]bool)

		for _, msg := range messages {
			if !seen[msg] {
				uniqueMessages = append(uniqueMessages, msg)
				seen[msg] = true
			}
		}

		if len(uniqueMessages) > 1 {
			return fmt.Sprintf("Error: %s (caused by: %s)",
				uniqueMessages[0],
				strings.Join(uniqueMessages[1:], " -> "))
		}
	}

	// Single error or all messages were the same
	message := messages[0]

	// Basic formatting
	if len(message) > 0 {
		first := string(message[0])
		if first != strings.ToUpper(first) {
			message = strings.ToUpper(first) + message[1:]
		}
	}

	return fmt.Sprintf("Error: %s", message)
}

func sanitizeFlags(cmd *cobra.Command) map[string]interface{} {
	flags := make(map[string]interface{})
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed {
			if isSensitiveFlag(flag.Name) {
				flags[flag.Name] = "[REDACTED]"
			} else {
				flags[flag.Name] = flag.Value.String()
			}
		}
	})
	return flags
}

func sanitizeArgs(args []string) []string {
	// Remove or mask sensitive arguments
	sanitized := make([]string, len(args))
	for i, arg := range args {
		if containsSensitiveData(arg) {
			sanitized[i] = "[REDACTED]"
		} else {
			sanitized[i] = arg
		}
	}
	return sanitized
}

func containsSensitiveData(arg string) bool {
	// TODO: revise and implement
	return false
}
