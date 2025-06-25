package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"southwinds.dev/volta"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets in the vault",
	Long:  "Store, retrieve, update, and manage secrets in the vault with encryption and metadata support.",
}

var storeSecretCmd = &cobra.Command{
	Use:   "store [secret-id]",
	Short: "Store a new secret",
	Long:  "Store a new secret with optional tags and content type. Data can be provided via stdin, file, or inline.",
	Args:  cobra.ExactArgs(1),
	RunE:  storeSecret,
}

var getSecretCmd = &cobra.Command{
	Use:   "get [secret-id]",
	Short: "Retrieve a secret",
	Long:  "Retrieve and decrypt a secret from the vault.",
	Args:  cobra.ExactArgs(1),
	RunE:  getSecret,
}

var updateSecretCmd = &cobra.Command{
	Use:   "update [secret-id]",
	Short: "Update an existing secret",
	Long:  "Update an existing secret with new data, tags, or content type.",
	Args:  cobra.ExactArgs(1),
	RunE:  updateSecret,
}

var deleteSecretCmd = &cobra.Command{
	Use:   "delete [secret-id]",
	Short: "Delete a secret",
	Long:  "Permanently delete a secret and its metadata from the vault.",
	Args:  cobra.ExactArgs(1),
	RunE:  deleteSecret,
}

var listSecretsCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets",
	Long:  "List secrets with optional filtering by tags, prefix, or content type.",
	RunE:  listSecrets,
}

var secretInfoCmd = &cobra.Command{
	Use:   "info [secret-id]",
	Short: "Show secret metadata",
	Long:  "Display metadata information for a secret without decrypting its content.",
	Args:  cobra.ExactArgs(1),
	RunE:  secretInfo,
}

var (
	// Common flags for secret operations
	secretTags        []string
	secretContentType string
	secretFile        string
	secretData        string
	outputJSON        bool
	showContent       bool

	// List flags
	filterTags    []string
	filterPrefix  string
	filterType    string
	limitResults  int
	offsetResults int
)

func init() {
	rootCmd.AddCommand(secretsCmd)

	// Add subcommands
	secretsCmd.AddCommand(storeSecretCmd)
	secretsCmd.AddCommand(getSecretCmd)
	secretsCmd.AddCommand(updateSecretCmd)
	secretsCmd.AddCommand(deleteSecretCmd)
	secretsCmd.AddCommand(listSecretsCmd)
	secretsCmd.AddCommand(secretInfoCmd)

	// Store command flags
	storeSecretCmd.Flags().StringSliceVarP(&secretTags, "tags", "t", nil, "tags for the secret")
	storeSecretCmd.Flags().StringVarP(&secretContentType, "type", "T", "text/plain", "content type (text/plain, application/json, application/yaml, application/x-pem-file, application/octet-stream)")
	storeSecretCmd.Flags().StringVarP(&secretFile, "file", "f", "", "read secret data from file (use '-' for stdin)")
	storeSecretCmd.Flags().StringVarP(&secretData, "data", "d", "", "secret data as string")

	// Update command flags
	updateSecretCmd.Flags().StringSliceVarP(&secretTags, "tags", "t", nil, "tags for the secret")
	updateSecretCmd.Flags().StringVarP(&secretContentType, "type", "T", "text/plain", "content type")
	updateSecretCmd.Flags().StringVarP(&secretFile, "file", "f", "", "read secret data from file (use '-' for stdin)")
	updateSecretCmd.Flags().StringVarP(&secretData, "data", "d", "", "secret data as string")

	// Get command flags
	getSecretCmd.Flags().BoolVar(&outputJSON, "json", false, "output in JSON format")
	getSecretCmd.Flags().BoolVar(&showContent, "show-content", true, "show secret content (disable for metadata only)")

	// List command flags
	listSecretsCmd.Flags().StringSliceVar(&filterTags, "filter-tags", nil, "filter by tags (AND logic)")
	listSecretsCmd.Flags().StringVar(&filterPrefix, "filter-prefix", "", "filter by secret ID prefix")
	listSecretsCmd.Flags().StringVar(&filterType, "filter-type", "", "filter by content type")
	listSecretsCmd.Flags().IntVar(&limitResults, "limit", 0, "limit number of results")
	listSecretsCmd.Flags().IntVar(&offsetResults, "offset", 0, "offset for pagination")
	listSecretsCmd.Flags().BoolVar(&outputJSON, "json", false, "output in JSON format")

	// Info command flags
	secretInfoCmd.Flags().BoolVar(&outputJSON, "json", false, "output in JSON format")
}

func storeSecret(cmd *cobra.Command, args []string) error {
	secretID := args[0]

	data, err := readSecretData()
	if err != nil {
		return fmt.Errorf("failed to read secret data: %w", err)
	}

	contentType := volta.ContentType(secretContentType)
	metadata, err := vaultSvc.StoreSecret(secretID, data, secretTags, contentType)
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	fmt.Printf("Secret '%s' stored successfully\n", secretID)
	fmt.Printf("Version: %d, Size: %d bytes, Key ID: %s\n",
		metadata.Version, metadata.Size, metadata.KeyID)

	return nil
}

func getSecret(cmd *cobra.Command, args []string) error {
	secretID := args[0]

	result, err := vaultSvc.GetSecret(secretID)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	if outputJSON {
		output := map[string]interface{}{
			"metadata":        result.Metadata,
			"used_active_key": result.UsedActiveKey,
		}
		if showContent {
			output["content"] = string(result.Data)
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("Secret ID: %s\n", result.Metadata.SecretID)
		fmt.Printf("Version: %d\n", result.Metadata.Version)
		fmt.Printf("Content Type: %s\n", result.Metadata.ContentType)
		fmt.Printf("Tags: %s\n", strings.Join(result.Metadata.Tags, ", "))
		fmt.Printf("Size: %d bytes\n", result.Metadata.Size)
		fmt.Printf("Created: %s\n", result.Metadata.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated: %s\n", result.Metadata.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Last Accessed: %s\n", result.Metadata.LastAccessed.Format("2006-01-02 15:04:05"))
		fmt.Printf("Access Count: %d\n", result.Metadata.AccessCount)

		// Show key information
		keyStatus := "active"
		if !result.UsedActiveKey {
			keyStatus = "rotated (requires re-encryption)"
		}
		fmt.Printf("Key Status: %s\n", keyStatus)

		if showContent {
			fmt.Println("\n--- Content ---")
			fmt.Print(string(result.Data))
			if !strings.HasSuffix(string(result.Data), "\n") {
				fmt.Println()
			}
		}

		// Show helpful information about key status
		if !result.UsedActiveKey {
			fmt.Printf("\n⚠️  Note: This secret was encrypted with a rotated key.\n")
			fmt.Printf("   Consider updating the secret to use the current key for optimal performance.\n")
		}
	}

	return nil
}

func updateSecret(cmd *cobra.Command, args []string) error {
	secretID := args[0]

	data, err := readSecretData()
	if err != nil {
		return fmt.Errorf("failed to read secret data: %w", err)
	}

	contentType := volta.ContentType(secretContentType)
	metadata, err := vaultSvc.UpdateSecret(secretID, data, secretTags, contentType)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	fmt.Printf("Secret '%s' updated successfully\n", secretID)
	fmt.Printf("Version: %d, Size: %d bytes, Key ID: %s\n",
		metadata.Version, metadata.Size, metadata.KeyID)

	return nil
}

func deleteSecret(cmd *cobra.Command, args []string) error {
	secretID := args[0]

	if err := vaultSvc.DeleteSecret(secretID); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("Secret '%s' deleted successfully\n", secretID)
	return nil
}

func listSecrets(cmd *cobra.Command, args []string) error {
	options := &volta.SecretListOptions{
		Tags:        filterTags,
		Prefix:      filterPrefix,
		Limit:       limitResults,
		Offset:      offsetResults,
		ContentType: volta.ContentType(filterType),
	}

	secrets, err := vaultSvc.ListSecrets(options)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if outputJSON {
		jsonData, err := json.MarshalIndent(secrets, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		if len(secrets) == 0 {
			fmt.Println("No secrets found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SECRET ID\tVERSION\tTYPE\tSIZE\tTAGS\tUPDATED")

		for _, secret := range secrets {
			fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s\t%s\n",
				secret.Metadata.SecretID,
				secret.Version,
				secret.Metadata.ContentType,
				secret.Metadata.Size,
				strings.Join(secret.Tags, ","),
				secret.UpdatedAt.Format("2006-01-02 15:04"),
			)
		}
		w.Flush()
	}

	return nil
}

func secretInfo(cmd *cobra.Command, args []string) error {
	secretID := args[0]

	metadata, err := vaultSvc.GetSecretMetadata(secretID)
	if err != nil {
		return fmt.Errorf("failed to get secret metadata: %w", err)
	}

	if outputJSON {
		jsonData, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("Secret ID: %s\n", metadata.SecretID)
		fmt.Printf("Version: %d\n", metadata.Version)
		fmt.Printf("Content Type: %s\n", metadata.ContentType)
		fmt.Printf("Tags: %s\n", strings.Join(metadata.Tags, ", "))
		fmt.Printf("Size: %d bytes\n", metadata.Size)
		fmt.Printf("Key ID: %s\n", metadata.KeyID)
		fmt.Printf("Created: %s\n", metadata.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated: %s\n", metadata.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Checksum: %s\n", metadata.Checksum)
	}

	return nil
}

func readSecretData() ([]byte, error) {
	if secretData != "" {
		return []byte(secretData), nil
	}

	if secretFile != "" {
		if secretFile == "-" {
			return io.ReadAll(os.Stdin)
		}
		return os.ReadFile(secretFile)
	}

	// If neither data nor file specified, read from stdin
	return io.ReadAll(os.Stdin)
}
