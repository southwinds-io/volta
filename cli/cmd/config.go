package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage vault configuration",
	Long:  `Manage vault configuration including viewing, setting, and validating settings.`,
}

// configViewCmd shows current configuration
var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View current configuration",
	Long:  `Display the current vault configuration from all sources (config file, environment variables, flags).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigView(cmd, args)
	},
}

// configSetCmd sets configuration values
var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long:  `Set a configuration value in the config file. The key uses dot notation (e.g., vault.store_type).`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigSet(cmd, args)
	},
}

// configGetCmd gets configuration values
var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Long:  `Get a configuration value. The key uses dot notation (e.g., vault.store_type).`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigGet(cmd, args)
	},
}

// configUnsetCmd removes configuration values
var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Remove a configuration value",
	Long:  `Remove a configuration value from the config file. The key uses dot notation.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigUnset(cmd, args)
	},
}

// configInitCmd initializes a new configuration file
var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new configuration file",
	Long:  `Create a new configuration file with default values.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigInit(cmd, args)
	},
}

// configValidateCmd validates the configuration
var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration",
	Long:  `Validate the current configuration for correctness and completeness.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigValidate(cmd, args)
	},
}

// configListCmd lists all available configuration keys
var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration keys",
	Long:  `List all available configuration keys with their descriptions.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigList(cmd, args)
	},
}

// configResetCmd resets configuration to defaults
var configResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset configuration to defaults",
	Long:  `Reset the configuration file to default values. This will overwrite the existing config file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigReset(cmd, args)
	},
}

// configEditCmd opens the config file in an editor
var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit configuration file",
	Long:  `Open the configuration file in the default editor.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigEdit(cmd, args)
	},
}

var (
	configForce    bool
	configGlobal   bool
	configTemplate string
	configFormat   string
)

func init() {
	// Add config command to root
	rootCmd.AddCommand(configCmd)

	// Add subcommands
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configUnsetCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configResetCmd)
	configCmd.AddCommand(configEditCmd)

	// Flags for config commands
	configViewCmd.Flags().StringVarP(&configFormat, "format", "f", "yaml", "output format (yaml, json, table)")
	configViewCmd.Flags().BoolVar(&configGlobal, "global", false, "show global configuration")

	configSetCmd.Flags().BoolVar(&configForce, "force", false, "force set value even if key doesn't exist")
	configSetCmd.Flags().BoolVar(&configGlobal, "global", false, "set in global configuration")

	configInitCmd.Flags().BoolVar(&configForce, "force", false, "overwrite existing config file")
	configInitCmd.Flags().StringVar(&configTemplate, "template", "default", "configuration template (default, minimal, full)")

	configResetCmd.Flags().BoolVar(&configForce, "force", false, "force reset without confirmation")

	configListCmd.Flags().StringVarP(&configFormat, "format", "f", "table", "output format (table, yaml, json)")
}

func runConfigView(cmd *cobra.Command, args []string) error {
	switch configFormat {
	case "json":
		return printConfigJSON()
	case "yaml":
		return printConfigYAML()
	case "table":
		return printConfigTable()
	default:
		return fmt.Errorf("unsupported format: %s", configFormat)
	}
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	// Validate key exists if not forcing
	if !configForce && !isValidConfigKey(key) {
		return fmt.Errorf("unknown configuration key: %s (use --force to override)", key)
	}

	// Convert value to appropriate type
	convertedValue, err := convertStringValue(value)
	if err != nil {
		return fmt.Errorf("failed to convert value: %w", err)
	}

	// Set the value
	viper.Set(key, convertedValue)

	// Write to config file
	configFile := getConfigFilePath(configGlobal)
	if err = ensureConfigDir(configFile); err != nil {
		return fmt.Errorf("failed to ensure config directory: %w", err)
	}

	if err = viper.WriteConfigAs(configFile); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Set %s = %v\n", key, convertedValue)
	fmt.Printf("Configuration saved to: %s\n", configFile)
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	if !viper.IsSet(key) {
		return fmt.Errorf("configuration key not found: %s", key)
	}

	value := viper.Get(key)
	fmt.Printf("%s = %v\n", key, value)

	// Show source of the value
	if configFile := viper.ConfigFileUsed(); configFile != "" {
		fmt.Printf("Source: %s\n", configFile)
	} else {
		fmt.Println("Source: defaults/environment/flags")
	}

	return nil
}

func runConfigUnset(cmd *cobra.Command, args []string) error {
	key := args[0]

	// Read current config
	config := viper.AllSettings()

	// Remove the key
	if err := unsetNestedKey(config, key); err != nil {
		return fmt.Errorf("failed to unset key %s: %w", key, err)
	}

	// Clear viper and reload with new config
	viper.Reset()
	initConfig() // Reinitialize defaults

	// Merge back the modified config
	if err := viper.MergeConfigMap(config); err != nil {
		return fmt.Errorf("failed to merge config: %w", err)
	}

	// Write to config file
	configFile := getConfigFilePath(configGlobal)
	if err := viper.WriteConfigAs(configFile); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Removed configuration key: %s\n", key)
	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	configFile := getConfigFilePath(configGlobal)

	// Check if file exists
	if _, err := os.Stat(configFile); err == nil && !configForce {
		return fmt.Errorf("configuration file already exists: %s (use --force to overwrite)", configFile)
	}

	// Create config based on template
	config := getConfigTemplate(configTemplate)

	// Ensure directory exists
	if err := ensureConfigDir(configFile); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write config file
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Configuration file created: %s\n", configFile)
	fmt.Printf("Template used: %s\n", configTemplate)
	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	errors := validateConfiguration()

	if len(errors) == 0 {
		fmt.Println("✓ Configuration is valid")
		return nil
	}

	fmt.Println("✗ Configuration validation failed:")
	for _, err := range errors {
		fmt.Printf("  - %s\n", err)
	}

	return fmt.Errorf("configuration validation failed with %d errors", len(errors))
}

func runConfigList(cmd *cobra.Command, args []string) error {
	keys := getConfigKeyDescriptions()

	switch configFormat {
	case "table":
		return printConfigKeysTable(keys)
	case "yaml":
		return printConfigKeysYAML(keys)
	case "json":
		return printConfigKeysJSON(keys)
	default:
		return fmt.Errorf("unsupported format: %s", configFormat)
	}
}

func runConfigReset(cmd *cobra.Command, args []string) error {
	if !configForce {
		fmt.Print("This will reset your configuration to defaults. Continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Reset cancelled")
			return nil
		}
	}

	// Reset to default template
	config := getConfigTemplate("default")
	configFile := getConfigFilePath(configGlobal)

	// Write config file
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err = os.WriteFile(configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Configuration reset to defaults: %s\n", configFile)
	return nil
}

func runConfigEdit(cmd *cobra.Command, args []string) error {
	configFile := getConfigFilePath(configGlobal)

	// Ensure config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		if err := runConfigInit(cmd, []string{}); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	// Get editor from environment or use default
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = getDefaultEditor()
	}

	fmt.Printf("Opening %s with %s...\n", configFile, editor)

	// Execute editor
	return executeEditor(editor, configFile)
}
