package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status",
	Long:  "Display information about the vault including memory protection level and key status.",
	RunE:  showStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func showStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("Vault Status")
	fmt.Println("============")

	// Show memory protection
	fmt.Printf("Memory Protection: %s\n", vaultSvc.SecureMemoryProtection())

	// Show active key
	activeKey, err := vaultSvc.GetActiveKeyMetadata()
	if err != nil {
		fmt.Printf("Active Key: ERROR - %v\n", err)
	} else {
		fmt.Printf("Active Key: %s\n", activeKey.KeyID)
	}

	// Show key count
	keys, err := vaultSvc.ListKeyMetadata()
	if err != nil {
		fmt.Printf("Total Keys: ERROR - %v\n", err)
	} else {
		activeCount := 0
		inactiveCount := 0
		for _, key := range keys {
			if key.Status == "active" {
				activeCount++
			} else {
				inactiveCount++
			}
		}
		fmt.Printf("Total Keys: %d (Active: %d, Inactive: %d)\n", len(keys), activeCount, inactiveCount)
	}

	// Show secret count
	secrets, err := vaultSvc.ListSecrets(nil)
	if err != nil {
		fmt.Printf("Total Secrets: ERROR - %v\n", err)
	} else {
		fmt.Printf("Total Secrets: %d\n", len(secrets))
	}

	fmt.Printf("Vault Path: %s\n", vaultPath)

	return nil
}
