package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"southwinds.dev/volta"
)

var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage vault tenants",
	Long:  `Manage vault tenants including listing, creating, closing, and bulk operations.`,
}

var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tenants",
	Long:  `List all tenants in the vault system.`,
	RunE:  runTenantList,
}

var tenantRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key <tenant-id>",
	Short: "Rotate key for a specific tenant",
	Long:  `Rotate the encryption key for a specific tenant. This will generate a new key, make it active, and re-encrypt all secrets.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTenantRotateKey,
}

var tenantRotateKeysCmd = &cobra.Command{
	Use:   "rotate-keys",
	Short: "Rotate keys for multiple tenants",
	Long:  `Perform bulk key rotation across multiple tenants.`,
	RunE:  runTenantRotateKeys,
}

var tenantRotatePassphraseCmd = &cobra.Command{
	Use:   "rotate-passphrase <tenant-id>",
	Short: "Rotate passphrase for a specific tenant",
	Long:  `Rotate the passphrase for a specific tenant. This will update the passphrase used to encrypt the tenant's keys.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTenantRotatePassphrase,
}

var tenantRotatePassphrasesCmd = &cobra.Command{
	Use:   "rotate-passphrases",
	Short: "Rotate passphrases for multiple tenants",
	Long:  `Perform bulk passphrase rotation across multiple tenants.`,
	RunE:  runTenantRotatePassphrases,
}

var tenantAuditSummaryCmd = &cobra.Command{
	Use:   "audit-summary [tenant-id]",
	Short: "Show audit summary for tenants",
	Long:  `Display audit summary for a specific tenant or all tenants.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runTenantAuditSummary,
}

// Flags for tenant operations
var (
	tenantsList    []string
	newPassphrase  string
	rotationReason string
	allTenantsFlag bool
	sinceFlag      string
	forceFlag      bool
)

func init() {
	rootCmd.AddCommand(tenantCmd)

	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantRotateKeyCmd)
	tenantCmd.AddCommand(tenantRotateKeysCmd)
	tenantCmd.AddCommand(tenantRotatePassphraseCmd)
	tenantCmd.AddCommand(tenantRotatePassphrasesCmd)
	tenantCmd.AddCommand(tenantAuditSummaryCmd)

	// Flags for list command
	tenantListCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	// Flags for single tenant rotate key command
	tenantRotateKeyCmd.Flags().StringVar(&rotationReason, "reason", "key rotation", "Reason for key rotation")
	tenantRotateKeyCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output result in JSON format")
	tenantRotateKeyCmd.Flags().BoolVar(&forceFlag, "force", false, "Skip confirmation prompt")

	// Flags for bulk rotate keys command
	tenantRotateKeysCmd.Flags().StringSliceVar(&tenantsList, "tenants", nil, "List of tenant IDs (if not specified, rotates all tenants)")
	tenantRotateKeysCmd.Flags().StringVar(&rotationReason, "reason", "bulk key rotation", "Reason for key rotation")
	tenantRotateKeysCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	tenantRotateKeysCmd.Flags().BoolVar(&forceFlag, "force", false, "Skip confirmation prompt")

	// Flags for single tenant rotate passphrase command
	tenantRotatePassphraseCmd.Flags().StringVar(&newPassphrase, "passphrase", "", "New passphrase (required)")
	tenantRotatePassphraseCmd.Flags().StringVar(&rotationReason, "reason", "passphrase rotation", "Reason for passphrase rotation")
	tenantRotatePassphraseCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output result in JSON format")
	tenantRotatePassphraseCmd.Flags().BoolVar(&forceFlag, "force", false, "Skip confirmation prompt")
	tenantRotatePassphraseCmd.MarkFlagRequired("passphrase")

	// Flags for bulk rotate passphrases command
	tenantRotatePassphrasesCmd.Flags().StringSliceVar(&tenantsList, "tenants", nil, "List of tenant IDs (if not specified, rotates all tenants)")
	tenantRotatePassphrasesCmd.Flags().StringVar(&newPassphrase, "passphrase", "", "New passphrase (required)")
	tenantRotatePassphrasesCmd.Flags().StringVar(&rotationReason, "reason", "bulk passphrase rotation", "Reason for passphrase rotation")
	tenantRotatePassphrasesCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	tenantRotatePassphrasesCmd.Flags().BoolVar(&forceFlag, "force", false, "Skip confirmation prompt")
	tenantRotatePassphrasesCmd.MarkFlagRequired("passphrase")

	// Flags for audit summary command
	tenantAuditSummaryCmd.Flags().StringVar(&sinceFlag, "since", "", "Show audit data since this time (RFC3339 format)")
	tenantAuditSummaryCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

// Command implementations

func runTenantList(cmd *cobra.Command, args []string) error {
	tenants, err := vaultManager.ListTenants()
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if len(tenants) == 0 {
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode([]string{})
		}
		fmt.Println("No tenants found.")
		return nil
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(tenants)
	}

	fmt.Printf("Found %d tenant(s):\n\n", len(tenants))
	for _, tenant := range tenants {
		fmt.Printf("  %s\n", tenant)
	}

	return nil
}

func runTenantRotateKey(cmd *cobra.Command, args []string) error {
	tenantID := args[0]

	if !forceFlag {
		fmt.Printf("This will rotate the encryption key for tenant '%s'. This operation will:\n", tenantID)
		fmt.Println("  - Generate a new encryption key")
		fmt.Println("  - Make the new key active for future encryptions")
		fmt.Println("  - Re-encrypt all existing secrets with the new key")
		fmt.Print("Continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		return fmt.Errorf("failed to get vault for tenant %s: %w", tenantID, err)
	}

	fmt.Printf("Rotating key for tenant '%s'...\n", tenantID)

	newKeyID, err := vault.RotateDataEncryptionKey(rotationReason)
	if err != nil {
		return fmt.Errorf("failed to rotate key for tenant %s: %w", tenantID, err)
	}

	if jsonOutput {
		result := map[string]interface{}{
			"tenant_id":  tenantID,
			"new_key_id": newKeyID.KeyID,
			"reason":     rotationReason,
			"timestamp":  time.Now(),
			"success":    true,
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Printf("Key rotation completed successfully for tenant '%s'\n", tenantID)
	fmt.Printf("New key ID: %s\n", newKeyID.KeyID)
	fmt.Printf("Reason: %s\n", rotationReason)
	fmt.Printf("Timestamp: %s\n", time.Now().Format(time.RFC3339))

	return nil
}

func runTenantRotateKeys(cmd *cobra.Command, args []string) error {
	targetTenants := tenantsList
	if len(targetTenants) == 0 {
		// Get all tenants
		allTenants, err := vaultManager.ListTenants()
		if err != nil {
			return fmt.Errorf("failed to list tenants: %w", err)
		}
		targetTenants = allTenants
	}

	if len(targetTenants) == 0 {
		fmt.Println("No tenants found to rotate keys.")
		return nil
	}

	if !forceFlag {
		fmt.Printf("This will rotate keys for %d tenant(s):\n", len(targetTenants))
		for _, tenant := range targetTenants {
			fmt.Printf("  %s\n", tenant)
		}
		fmt.Print("Continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	fmt.Printf("Starting bulk key rotation for %d tenant(s)...\n", len(targetTenants))

	results, err := vaultManager.RotateAllTenantKeys(targetTenants, rotationReason)
	if err != nil {
		return fmt.Errorf("bulk key rotation failed: %w", err)
	}

	return displayBulkResults("Key Rotation", results)
}

func runTenantRotatePassphrase(cmd *cobra.Command, args []string) error {
	tenantID := args[0]

	if !forceFlag {
		fmt.Printf("This will rotate the passphrase for tenant '%s'.\n", tenantID)
		fmt.Print("Continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		return fmt.Errorf("failed to get vault for tenant %s: %w", tenantID, err)
	}

	fmt.Printf("Rotating passphrase for tenant '%s'...\n", tenantID)

	err = vault.RotateKeyEncryptionKey(newPassphrase, rotationReason)
	if err != nil {
		return fmt.Errorf("failed to rotate passphrase for tenant %s: %w", tenantID, err)
	}

	if jsonOutput {
		result := map[string]interface{}{
			"tenant_id": tenantID,
			"reason":    rotationReason,
			"timestamp": time.Now(),
			"success":   true,
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Printf("Passphrase rotation completed successfully for tenant '%s'\n", tenantID)
	fmt.Printf("Reason: %s\n", rotationReason)
	fmt.Printf("Timestamp: %s\n", time.Now().Format(time.RFC3339))

	return nil
}

func runTenantRotatePassphrases(cmd *cobra.Command, args []string) error {
	targetTenants := tenantsList
	if len(targetTenants) == 0 {
		// Get all tenants
		allTenants, err := vaultManager.ListTenants()
		if err != nil {
			return fmt.Errorf("failed to list tenants: %w", err)
		}
		targetTenants = allTenants
	}

	if len(targetTenants) == 0 {
		fmt.Println("No tenants found to rotate passphrases.")
		return nil
	}

	if !forceFlag {
		fmt.Printf("This will rotate passphrases for %d tenant(s):\n", len(targetTenants))
		for _, tenant := range targetTenants {
			fmt.Printf("  %s\n", tenant)
		}
		fmt.Print("Continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	fmt.Printf("Starting bulk passphrase rotation for %d tenant(s)...\n", len(targetTenants))

	results, err := vaultManager.RotateAllTenantPassphrases(targetTenants, newPassphrase, rotationReason)
	if err != nil {
		return fmt.Errorf("bulk passphrase rotation failed: %w", err)
	}

	return displayBulkResults("Passphrase Rotation", results)
}

func runTenantAuditSummary(cmd *cobra.Command, args []string) error {
	var since *time.Time
	if sinceFlag != "" {
		parsedTime, err := time.Parse(time.RFC3339, sinceFlag)
		if err != nil {
			return fmt.Errorf("invalid time format for --since flag. Use RFC3339 format (e.g., 2006-01-02T15:04:05Z07:00): %w", err)
		}
		since = &parsedTime
	}

	if len(args) == 0 {
		return showAuditSummaryAllTenants(since)
	}

	tenantID := args[0]
	return showAuditSummaryForTenant(tenantID, since)
}

// Helper functions

func displayBulkResults(operationType string, results []volta.BulkOperationResult) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(results)
	}

	successCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		}
	}

	fmt.Printf("\n%s Results:\n", operationType)
	fmt.Printf("Total: %d, Successful: %d, Failed: %d\n\n", len(results), successCount, len(results)-successCount)

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "TENANT\tSTATUS\tERROR\tTIMESTAMP\n")

	for _, result := range results {
		status := "SUCCESS"
		errorMsg := "-"
		if !result.Success {
			status = "FAILED"
			errorMsg = result.Error
			if len(errorMsg) > 50 {
				errorMsg = errorMsg[:47] + "..."
			}
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			result.TenantID,
			status,
			errorMsg,
			result.Timestamp.Format("2006-01-02 15:04:05"),
		)
	}

	return w.Flush()
}

func showAuditSummaryForTenant(tenantID string, since *time.Time) error {
	summary, err := vaultManager.GetAuditSummary(tenantID, since)
	if err != nil {
		return fmt.Errorf("failed to get audit summary for tenant %s: %w", tenantID, err)
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(summary)
	}

	fmt.Printf("Audit Summary for Tenant: %s\n", summary.TenantID)
	fmt.Printf("Total Events: %d\n", summary.TotalEvents)
	fmt.Printf("Successful Events: %d\n", summary.SuccessfulEvents)
	fmt.Printf("Failed Events: %d\n", summary.FailedEvents)
	fmt.Printf("Passphrase Accesses: %d\n", summary.CredsAccessCount)
	fmt.Printf("Secret Accesses: %d\n", summary.SensitiveDataAccessCount)
	fmt.Printf("Key Operations: %d\n", summary.KeyOperations)

	if !summary.LastActivity.IsZero() {
		fmt.Printf("Last Activity: %s\n", summary.LastActivity.Format(time.RFC3339))
	}

	return nil
}

func showAuditSummaryAllTenants(since *time.Time) error {
	tenants, err := vaultManager.ListTenants()
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if len(tenants) == 0 {
		fmt.Println("No tenants found.")
		return nil
	}

	if jsonOutput {
		allSummaries := make([]volta.AuditSummary, 0)

		for _, tenant := range tenants {
			summary, err := vaultManager.GetAuditSummary(tenant, since)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get audit summary for tenant %s: %v\n", tenant, err)
				continue
			}
			allSummaries = append(allSummaries, summary)
		}

		return json.NewEncoder(os.Stdout).Encode(allSummaries)
	}

	// Table output for all tenants
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "TENANT\tTOTAL\tSUCCESS\tFAILED\tPASSPHRASE\tSECRETS\tKEYS\tLAST ACTIVITY\n")

	for _, tenant := range tenants {
		summary, err := vaultManager.GetAuditSummary(tenant, since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get audit summary for tenant %s: %v\n", tenant, err)
			continue
		}

		lastActivity := "-"
		if !summary.LastActivity.IsZero() {
			lastActivity = summary.LastActivity.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			summary.TenantID,
			summary.TotalEvents,
			summary.SuccessfulEvents,
			summary.FailedEvents,
			summary.CredsAccessCount,
			summary.SensitiveDataAccessCount,
			summary.KeyOperations,
			lastActivity,
		)
	}

	return w.Flush()
}
