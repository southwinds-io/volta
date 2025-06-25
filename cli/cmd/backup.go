package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore vault data",
	Long:  "Create encrypted backups of vault keys and metadata, or restore from backups.",
}

var createBackupCmd = &cobra.Command{
	Use:   "create [destination-directory]",
	Short: "Create a backup",
	Long:  "Create an encrypted backup of all vault keys and metadata to the specified directory.",
	Args:  cobra.ExactArgs(1),
	RunE:  createBackup,
}

var restoreBackupCmd = &cobra.Command{
	Use:   "restore [backup-directory]",
	Short: "Restore from backup",
	Long:  "Restore vault keys and metadata from an encrypted backup directory.",
	Args:  cobra.ExactArgs(1),
	RunE:  restoreBackup,
}

var (
	backupPassphrase string
)

func init() {
	rootCmd.AddCommand(backupCmd)

	backupCmd.AddCommand(createBackupCmd)
	backupCmd.AddCommand(restoreBackupCmd)

	// Backup command flags
	createBackupCmd.Flags().StringVar(&backupPassphrase, "backup-passphrase", "", "passphrase for backup encryption (or use VAULT_BACKUP_PASSPHRASE env var)")
	restoreBackupCmd.Flags().StringVar(&backupPassphrase, "backup-passphrase", "", "passphrase for backup decryption (or use VAULT_BACKUP_PASSPHRASE env var)")
}

func createBackup(cmd *cobra.Command, args []string) error {
	destinationDir := args[0]

	// Get backup passphrase
	if backupPassphrase == "" {
		backupPassphrase = os.Getenv("VAULT_BACKUP_PASSPHRASE")
	}

	if backupPassphrase == "" {
		return fmt.Errorf("backup passphrase is required. Use --backup-passphrase flag or VAULT_BACKUP_PASSPHRASE environment variable")
	}

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destinationDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	fmt.Printf("Creating backup to: %s\n", destinationDir)

	if err := vaultSvc.Backup(destinationDir, backupPassphrase); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	fmt.Println("Backup created successfully")

	// List backup contents
	fmt.Println("\nBackup contents:")
	filepath.Walk(destinationDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(destinationDir, path)
			fmt.Printf("  %s (%d bytes)\n", relPath, info.Size())
		}
		return nil
	})

	return nil
}

func restoreBackup(cmd *cobra.Command, args []string) error {
	backupDir := args[0]

	// Get backup passphrase
	if backupPassphrase == "" {
		backupPassphrase = os.Getenv("VAULT_BACKUP_PASSPHRASE")
	}

	if backupPassphrase == "" {
		return fmt.Errorf("backup passphrase is required. Use --backup-passphrase flag or VAULT_BACKUP_PASSPHRASE environment variable")
	}

	// Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return fmt.Errorf("backup directory does not exist: %s", backupDir)
	}

	fmt.Printf("Restoring from backup: %s\n", backupDir)

	// Warning about overwriting existing vault
	fmt.Println("WARNING: This will overwrite any existing vault data.")
	fmt.Print("Continue? (yes/no): ")

	var response string
	fmt.Scanln(&response)

	if response != "yes" {
		fmt.Println("Restore cancelled")
		return nil
	}

	if err := vaultSvc.Restore(backupDir, backupPassphrase); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	fmt.Println("Backup restored successfully")
	return nil
}
