package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"southwinds.dev/volta"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage encryption keys",
	Long:  `Manage encryption keys for the vault including listing, rotation, and information display.`,
}

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all encryption keys",
	Long:  `List all encryption keys in the vault with their metadata including status, creation time, and tenant information.`,
	RunE:  runKeyList,
}

var keyActiveCmd = &cobra.Command{
	Use:   "active",
	Short: "Show active encryption key",
	Long:  `Display information about the currently active encryption key used for new encryptions.`,
	RunE:  runKeyActive,
}

var keyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the encryption key",
	Long:  `Generate a new encryption key, make it active for new encryptions, and re-encrypt all existing secrets with the new key.`,
	RunE:  runKeyRotate,
}

var keyDestroyCmd = &cobra.Command{
	Use:   "destroy <key-id>",
	Short: "Destroy an inactive encryption key",
	Long:  `Permanently destroy an inactive encryption key. This operation is irreversible and will make any data encrypted solely with this key unrecoverable.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runKeyDestroy,
}

var keyInfoCmd = &cobra.Command{
	Use:   "info <key-id>",
	Short: "Show detailed information about a specific key",
	Long:  `Display detailed information about a specific encryption key including usage statistics and associated secrets.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runKeyInfo,
}

// Flags
var (
	allTenants bool
	jsonOutput bool
)

func init() {
	rootCmd.AddCommand(keysCmd)

	keysCmd.AddCommand(keyListCmd)
	keysCmd.AddCommand(keyActiveCmd)
	keysCmd.AddCommand(keyRotateCmd)
	keysCmd.AddCommand(keyDestroyCmd)
	keysCmd.AddCommand(keyInfoCmd)

	// Add flags
	keyListCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "List keys for all tenants")
	keyListCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	keyActiveCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show active keys for all tenants")
	keyActiveCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	keyInfoCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

func runKeyList(cmd *cobra.Command, args []string) (err error) {
	started := auditCmdStart(cmd, args)
	if allTenants {
		return auditCmdComplete(cmd, listKeysAllTenants(), started)
	}
	return auditCmdComplete(cmd, listKeysForTenant(tenantID), started)
}

func runKeyActive(cmd *cobra.Command, args []string) (err error) {
	started := auditCmdStart(cmd, args)
	if allTenants {
		return auditCmdComplete(cmd, showActiveKeysAllTenants(), started)
	}
	return auditCmdComplete(cmd, showActiveKeyForTenant(tenantID), started)
}

func runKeyRotate(cmd *cobra.Command, args []string) (err error) {
	started := auditCmdStart(cmd, args)
	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		err = fmt.Errorf("failed to get vault for tenant %s: %w", tenantID, err)
		return auditCmdComplete(cmd, err, started)
	}

	fmt.Printf("Rotating key for tenant: %s\n", tenantID)
	fmt.Print("This will generate a new key and re-encrypt all existing secrets. Continue? (y/N): ")

	var response string
	_, _ = fmt.Scanln(&response)

	if response != "y" && response != "Y" {
		fmt.Println("Key rotation cancelled.")
		return auditCmdComplete(cmd, nil, started)
	}

	fmt.Println("Starting key rotation...")

	newKey, err := vault.RotateKey("")
	if err != nil {
		err = fmt.Errorf("failed to rotate key: %w", err)
		return auditCmdComplete(cmd, err, started)
	}

	fmt.Println("Key rotation completed successfully!")
	fmt.Printf("New key ID: %s\n", newKey.KeyID)
	fmt.Printf("Created at: %s\n", newKey.CreatedAt.Format(time.RFC3339))

	return auditCmdComplete(cmd, nil, started)
}

func runKeyDestroy(cmd *cobra.Command, args []string) (err error) {
	started := auditCmdStart(cmd, args)
	keyID := args[0]

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		err = fmt.Errorf("failed to get vault for tenant %s: %w", tenantID, err)
		return auditCmdComplete(cmd, err, started)
	}

	// Check if key exists and is inactive
	keys, err := vault.ListKeyMetadata()
	if err != nil {
		err = fmt.Errorf("failed to list keys: %w", err)
		return auditCmdComplete(cmd, err, started)
	}

	var targetKey *volta.KeyMetadata
	for _, key := range keys {
		if key.KeyID == keyID {
			targetKey = &key
			break
		}
	}

	if targetKey == nil {
		err = fmt.Errorf("key %s not found", keyID)
		return auditCmdComplete(cmd, err, started)
	}

	if targetKey.Status == volta.KeyStatusActive {
		err = fmt.Errorf("cannot destroy active key %s. Rotate to a new key first", keyID)
		return auditCmdComplete(cmd, err, started)
	}

	fmt.Printf("WARNING: This will permanently destroy key %s for tenant %s\n", keyID, tenantID)
	fmt.Printf("Any data encrypted solely with this key will become unrecoverable.\n")
	fmt.Print("Are you absolutely sure? Type 'DESTROY' to confirm: ")

	var confirmation string
	_, _ = fmt.Scanln(&confirmation)

	if confirmation != "DESTROY" {
		fmt.Println("Key destruction cancelled.")
		return auditCmdComplete(cmd, nil, started)
	}

	if err = vault.DestroyKey(keyID); err != nil {
		return auditCmdComplete(cmd, fmt.Errorf("failed to destroy key: %w", err), started)
	}

	fmt.Printf("Key %s has been permanently destroyed.\n", keyID)
	return auditCmdComplete(cmd, nil, started)
}

func runKeyInfo(cmd *cobra.Command, args []string) error {
	keyID := args[0]

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		return fmt.Errorf("failed to get vault for tenant %s: %w", tenantID, err)
	}

	// Get key metadata
	keys, err := vault.ListKeyMetadata()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var targetKey *volta.KeyMetadata
	for _, key := range keys {
		if key.KeyID == keyID {
			targetKey = &key
			break
		}
	}

	if targetKey == nil {
		return fmt.Errorf("key %s not found", keyID)
	}

	// Get secrets encrypted with this key
	secrets, err := vault.ListSecrets(nil)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	secretCount := 0
	for _, secret := range secrets {
		if secret.Metadata.KeyID == keyID {
			secretCount++
		}
	}

	if jsonOutput {
		info := map[string]interface{}{
			"tenant_id":      tenantID,
			"key_id":         targetKey.KeyID,
			"status":         string(targetKey.Status),
			"active":         targetKey.Active,
			"created_at":     targetKey.CreatedAt,
			"deactivated_at": targetKey.DeactivatedAt,
			"version":        targetKey.Version,
			"secret_count":   secretCount,
		}
		return json.NewEncoder(os.Stdout).Encode(info)
	}

	fmt.Printf("Key Information for Tenant: %s\n", tenantID)
	fmt.Printf("Key ID: %s\n", targetKey.KeyID)
	fmt.Printf("Status: %s\n", targetKey.Status)
	fmt.Printf("Active: %t\n", targetKey.Active)
	fmt.Printf("Created: %s\n", targetKey.CreatedAt.Format(time.RFC3339))

	if targetKey.DeactivatedAt != nil {
		fmt.Printf("Deactivated: %s\n", targetKey.DeactivatedAt.Format(time.RFC3339))
	}

	fmt.Printf("Version: %d\n", targetKey.Version)
	fmt.Printf("Secrets encrypted with this key: %d\n", secretCount)

	return nil
}

func listKeysForTenant(tenant string) error {
	vault, err := vaultManager.GetVault(tenant)
	if err != nil {
		return fmt.Errorf("failed to get vault for tenant %s: %w", tenant, err)
	}

	keys, err := vault.ListKeyMetadata()
	if err != nil {
		return fmt.Errorf("failed to list keys for tenant %s: %w", tenant, err)
	}

	if jsonOutput {
		output := make([]map[string]interface{}, 0, len(keys))
		for _, key := range keys {
			keyInfo := map[string]interface{}{
				"tenant_id":      tenant,
				"key_id":         key.KeyID,
				"status":         string(key.Status),
				"active":         key.Active,
				"created_at":     key.CreatedAt,
				"deactivated_at": key.DeactivatedAt,
				"version":        key.Version,
			}
			output = append(output, keyInfo)
		}
		return json.NewEncoder(os.Stdout).Encode(output)
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "TENANT\tKEY ID\tSTATUS\tACTIVE\tCREATED\tVERSION\n")

	for _, key := range keys {
		fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\t%d\n",
			tenant,
			key.KeyID,
			key.Status,
			key.Active,
			key.CreatedAt.Format("2006-01-02 15:04:05"),
			key.Version,
		)
	}

	return w.Flush()
}

func listKeysAllTenants() error {
	tenants, err := vaultManager.ListTenants()
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if len(tenants) == 0 {
		fmt.Println("No tenants found.")
		return nil
	}

	if jsonOutput {
		allKeys := make([]map[string]interface{}, 0)

		for _, tenant := range tenants {
			vault, err := vaultManager.GetVault(tenant)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get vault for tenant %s: %v\n", tenant, err)
				continue
			}

			keys, err := vault.ListKeyMetadata()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to list keys for tenant %s: %v\n", tenant, err)
				continue
			}

			for _, key := range keys {
				keyInfo := map[string]interface{}{
					"tenant_id":      tenant,
					"key_id":         key.KeyID,
					"status":         string(key.Status),
					"active":         key.Active,
					"created_at":     key.CreatedAt,
					"deactivated_at": key.DeactivatedAt,
					"version":        key.Version,
				}
				allKeys = append(allKeys, keyInfo)
			}
		}

		return json.NewEncoder(os.Stdout).Encode(allKeys)
	}

	// Table output for all tenants
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "TENANT\tKEY ID\tSTATUS\tCREATED\tVERSION\n")

	for _, tenant := range tenants {
		vault, err := vaultManager.GetVault(tenant)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get vault for tenant %s: %v\n", tenant, err)
			continue
		}

		keys, err := vault.ListKeyMetadata()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to list keys for tenant %s: %v\n", tenant, err)
			continue
		}

		for _, key := range keys {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
				tenant, key.KeyID, key.Status,
				key.CreatedAt.Format("2006-01-02 15:04:05"),
				key.Version)
		}
	}

	return w.Flush()
}

func showActiveKeyForTenant(tenant string) error {
	vault, err := vaultManager.GetVault(tenant)
	if err != nil {
		return fmt.Errorf("failed to get vault for tenant %s: %w", tenant, err)
	}

	activeKey, err := vault.GetActiveKeyMetadata()
	if err != nil {
		return fmt.Errorf("failed to get active key for tenant %s: %w", tenant, err)
	}

	if jsonOutput {
		keyInfo := map[string]interface{}{
			"tenant_id":  tenant,
			"key_id":     activeKey.KeyID,
			"status":     string(activeKey.Status),
			"active":     activeKey.Active,
			"created_at": activeKey.CreatedAt,
			"version":    activeKey.Version,
		}
		return json.NewEncoder(os.Stdout).Encode(keyInfo)
	}

	fmt.Printf("Active Key for Tenant: %s\n", tenant)
	fmt.Printf("Key ID: %s\n", activeKey.KeyID)
	fmt.Printf("Status: %s\n", activeKey.Status)
	fmt.Printf("Created: %s\n", activeKey.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Version: %d\n", activeKey.Version)

	return nil
}

func showActiveKeysAllTenants() error {
	tenants, err := vaultManager.ListTenants()
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if len(tenants) == 0 {
		fmt.Println("No tenants found.")
		return nil
	}

	if jsonOutput {
		activeKeys := make([]map[string]interface{}, 0)

		for _, tenant := range tenants {
			vault, err := vaultManager.GetVault(tenant)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get vault for tenant %s: %v\n", tenant, err)
				continue
			}

			activeKey, err := vault.GetActiveKeyMetadata()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get active key for tenant %s: %v\n", tenant, err)
				continue
			}

			keyInfo := map[string]interface{}{
				"tenant_id":  tenant,
				"key_id":     activeKey.KeyID,
				"status":     string(activeKey.Status),
				"active":     activeKey.Active,
				"created_at": activeKey.CreatedAt,
				"version":    activeKey.Version,
			}
			activeKeys = append(activeKeys, keyInfo)
		}

		return json.NewEncoder(os.Stdout).Encode(activeKeys)
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "TENANT\tKEY ID\tSTATUS\tCREATED\tVERSION\n")

	for _, tenant := range tenants {
		vault, err := vaultManager.GetVault(tenant)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get vault for tenant %s: %v\n", tenant, err)
			continue
		}

		activeKey, err := vault.GetActiveKeyMetadata()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get active key for tenant %s: %v\n", tenant, err)
			continue
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
			tenant,
			activeKey.KeyID,
			activeKey.Status,
			activeKey.CreatedAt.Format("2006-01-02 15:04:05"),
			activeKey.Version,
		)
	}

	return w.Flush()
}
