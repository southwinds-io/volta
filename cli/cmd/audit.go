package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"southwinds.dev/volta/audit"
)

var (
	auditJsonOutput     bool
	auditSince          string
	auditUntil          string
	auditAction         string
	auditSuccessFilter  string
	auditSecretID       string
	auditKeyID          string
	auditLimit          int
	auditOffset         int
	auditPassphraseOnly bool
	auditFailuresOnly   bool
	auditTenants        string
	auditDetails        bool
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query and analyze audit logs",
	Long: `Query and analyze audit logs across tenants. 
    
Provides comprehensive audit trail analysis including:
- Event filtering by time, action, success/failure
- Tenant-specific or cross-tenant queries
- Summary statistics and detailed event listings
- Export capabilities for compliance reporting`,
}

var auditQueryCmd = &cobra.Command{
	Use:   "query [tenant-id]",
	Short: "Query audit logs with filters",
	Long: `Query audit logs with various filtering options.
    
Examples:
  # Query all events for a tenant
  volta audit query mytenant
  
  # Query failed events in the last 24 hours
  volta audit query mytenant --failures-only --since "$(date -d '24 hours ago' -Iseconds)"
  
  # Query passphrase-related events
  volta audit query mytenant --passphrase-only
  
  # Query specific secret access
  volta audit query mytenant --secret-id "db-password"
  
  # Query with custom time range
  volta audit query mytenant --since "2024-01-01T00:00:00Z" --until "2024-01-31T23:59:59Z"`,
	RunE: runAuditQuery,
}

var auditSummaryCmd = &cobra.Command{
	Use:   "summary [tenant-id]",
	Short: "Show audit summary statistics",
	Long: `Show audit summary statistics for one or all tenants.
    
Examples:
  # Summary for specific tenant
  volta audit summary mytenant
  
  # Summary for all tenants
  volta audit summary --all-tenants
  
  # Summary since specific time
  volta audit summary mytenant --since "2024-01-01T00:00:00Z"`,
	RunE: runAuditSummary,
}

var auditEventsCmd = &cobra.Command{
	Use:   "events [tenant-id]",
	Short: "List recent audit events",
	Long: `List recent audit events with optional filtering.
    
Examples:
  # Recent events for a tenant
  volta audit events mytenant
  
  # Last 50 events
  volta audit events mytenant --limit 50
  
  # Events with details
  volta audit events mytenant --details`,
	RunE: runAuditEvents,
}

var auditFailuresCmd = &cobra.Command{
	Use:   "failures [tenant-id]",
	Short: "Show failed operations",
	Long: `Show failed operations for security monitoring.
    
Examples:
  # Recent failures for a tenant
  volta audit failures mytenant
  
  # Failures in the last week
  volta audit failures mytenant --since "$(date -d '7 days ago' -Iseconds)"`,
	RunE: runAuditFailures,
}

var auditSecretsCmd = &cobra.Command{
	Use:   "secrets [tenant-id]",
	Short: "Show secret access audit logs",
	Long: `Show audit logs related to secret access and operations.
    
Examples:
  # All secret access for a tenant
  volta audit secrets mytenant
  
  # Specific secret access
  volta audit secrets mytenant --secret-id "db-password"`,
	RunE: runAuditSecrets,
}

var auditKeysCmd = &cobra.Command{
	Use:   "keys [tenant-id]",
	Short: "Show key operation audit logs",
	Long: `Show audit logs related to key operations (rotation, creation, etc.).
    
Examples:
  # All key operations for a tenant
  volta audit keys mytenant
  
  # Specific key operations
  volta audit keys mytenant --key-id "abc123"`,
	RunE: runAuditKeys,
}

var auditPassphraseCmd = &cobra.Command{
	Use:   "passphrase [tenant-id]",
	Short: "Show passphrase-related audit logs",
	Long: `Show audit logs related to passphrase operations and access.
    
Examples:
  # Passphrase events for a tenant
  volta audit passphrase mytenant
  
  # Recent passphrase activity
  volta audit passphrase mytenant --since "$(date -d '1 hour ago' -Iseconds)"`,
	RunE: runAuditPassphrase,
}

var auditExportCmd = &cobra.Command{
	Use:   "export [tenant-id]",
	Short: "Export audit logs for compliance",
	Long: `Export audit logs in various formats for compliance reporting.
    
Examples:
  # Export all events as JSON
  volta audit export mytenant --json > audit-report.json
  
  # Export specific time range
  volta audit export mytenant --since "2024-01-01T00:00:00Z" --until "2024-01-31T23:59:59Z"`,
	RunE: runAuditExport,
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats [tenant-id]",
	Short: "Show detailed audit statistics",
	Long: `Show detailed audit statistics and analytics.
    
Examples:
  # Detailed stats for a tenant
  volta audit stats mytenant
  
  # Stats for all tenants
  volta audit stats --all-tenants`,
	RunE: runAuditStats,
}

func init() {
	rootCmd.AddCommand(auditCmd)

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditSummaryCmd)
	auditCmd.AddCommand(auditEventsCmd)
	auditCmd.AddCommand(auditFailuresCmd)
	auditCmd.AddCommand(auditSecretsCmd)
	auditCmd.AddCommand(auditKeysCmd)
	auditCmd.AddCommand(auditPassphraseCmd)
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditStatsCmd)

	// Global audit flags
	auditCmd.PersistentFlags().BoolVar(&auditJsonOutput, "json", false, "Output in JSON format")
	auditCmd.PersistentFlags().StringVar(&auditSince, "since", "", "Show events since this time (RFC3339 format)")
	auditCmd.PersistentFlags().StringVar(&auditUntil, "until", "", "Show events until this time (RFC3339 format)")
	auditCmd.PersistentFlags().IntVar(&auditLimit, "limit", 100, "Maximum number of events to return")
	auditCmd.PersistentFlags().IntVar(&auditOffset, "offset", 0, "Number of events to skip")
	auditCmd.PersistentFlags().StringVar(&auditTenants, "tenants", "", "Comma-separated list of tenants (or 'all')")
	auditCmd.PersistentFlags().BoolVar(&auditDetails, "details", false, "Show detailed event information")

	// Query-specific flags
	auditQueryCmd.Flags().StringVar(&auditAction, "action", "", "Filter by specific action")
	auditQueryCmd.Flags().StringVar(&auditSuccessFilter, "success", "", "Filter by success status (true/false)")
	auditQueryCmd.Flags().StringVar(&auditSecretID, "secret-id", "", "Filter by secret ID")
	auditQueryCmd.Flags().StringVar(&auditKeyID, "key-id", "", "Filter by key ID")
	auditQueryCmd.Flags().BoolVar(&auditPassphraseOnly, "passphrase-only", false, "Show only passphrase-related events")
	auditQueryCmd.Flags().BoolVar(&auditFailuresOnly, "failures-only", false, "Show only failed events")

	// Summary flags
	auditSummaryCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show summary for all tenants")

	// Events flags
	auditEventsCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show events for all tenants")

	// Failures flags
	auditFailuresCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show failures for all tenants")

	// Secrets flags
	auditSecretsCmd.Flags().StringVar(&auditSecretID, "secret-id", "", "Filter by specific secret ID")
	auditSecretsCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show secret access for all tenants")

	// Keys flags
	auditKeysCmd.Flags().StringVar(&auditKeyID, "key-id", "", "Filter by specific key ID")
	auditKeysCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show key operations for all tenants")

	// Passphrase flags
	auditPassphraseCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show passphrase events for all tenants")

	// Export flags
	auditExportCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Export for all tenants")

	// Stats flags
	auditStatsCmd.Flags().BoolVar(&allTenants, "all-tenants", false, "Show stats for all tenants")
}

func runAuditQuery(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	if len(args) > 0 {
		// Single tenant query
		tenantID := args[0]
		return queryTenantAudit(tenantID, options)
	}

	// Multi-tenant query
	return queryMultiTenantAudit(options)
}

func runAuditSummary(cmd *cobra.Command, args []string) error {
	var since *time.Time
	if auditSince != "" {
		parsedTime, err := time.Parse(time.RFC3339, auditSince)
		if err != nil {
			return fmt.Errorf("invalid since time format: %w", err)
		}
		since = &parsedTime
	}

	if len(args) > 0 {
		// Single tenant summary
		tenantID := args[0]
		return showTenantAuditSummary(tenantID, since)
	}

	if allTenants {
		// All tenants summary
		return showAllTenantsAuditSummary(since)
	}

	// Default tenant summary
	return showTenantAuditSummary(tenantID, since)
}

func runAuditEvents(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	if len(args) > 0 {
		tenantID := args[0]
		return showTenantEvents(tenantID, options)
	}

	if allTenants {
		return showAllTenantsEvents(options)
	}

	return showTenantEvents(tenantID, options)
}

func runAuditFailures(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	// Force failures-only
	falseVal := false
	options.Success = &falseVal

	if len(args) > 0 {
		tenantID := args[0]
		return showTenantFailures(tenantID, options)
	}

	if allTenants {
		return showAllTenantsFailures(options)
	}

	return showTenantFailures(tenantID, options)
}

func runAuditSecrets(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	if len(args) > 0 {
		tenantID := args[0]
		return showTenantSecretAccess(tenantID, options)
	}

	if allTenants {
		return showAllTenantsSecretAccess(options)
	}

	return showTenantSecretAccess(tenantID, options)
}

func runAuditKeys(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	if len(args) > 0 {
		tenantID := args[0]
		return showTenantKeyOperations(tenantID, options)
	}

	if allTenants {
		return showAllTenantsKeyOperations(options)
	}

	return showTenantKeyOperations(tenantID, options)
}

func runAuditPassphrase(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	// Force passphrase-only
	options.PassphraseAccess = true

	if len(args) > 0 {
		tenantID := args[0]
		return showTenantPassphraseEvents(tenantID, options)
	}

	if allTenants {
		return showAllTenantsPassphraseEvents(options)
	}

	return showTenantPassphraseEvents(tenantID, options)
}

func runAuditExport(cmd *cobra.Command, args []string) error {
	options, err := buildQueryOptions(args)
	if err != nil {
		return err
	}

	// Force JSON output for export
	auditJsonOutput = true

	if len(args) > 0 {
		tenantID := args[0]
		return exportTenantAudit(tenantID, options)
	}

	if allTenants {
		return exportAllTenantsAudit(options)
	}

	return exportTenantAudit(tenantID, options)
}

func runAuditStats(cmd *cobra.Command, args []string) error {
	var since *time.Time
	if auditSince != "" {
		parsedTime, err := time.Parse(time.RFC3339, auditSince)
		if err != nil {
			return fmt.Errorf("invalid since time format: %w", err)
		}
		since = &parsedTime
	}

	if len(args) > 0 {
		tenantID := args[0]
		return showTenantAuditStats(tenantID, since)
	}

	if allTenants {
		return showAllTenantsAuditStats(since)
	}

	return showTenantAuditStats(tenantID, since)
}

// Helper functions
func buildQueryOptions(args []string) (audit.QueryOptions, error) {
	options := audit.QueryOptions{
		Limit:            auditLimit,
		Offset:           auditOffset,
		PassphraseAccess: auditPassphraseOnly,
	}

	// Parse time filters
	if auditSince != "" {
		parsedTime, err := time.Parse(time.RFC3339, auditSince)
		if err != nil {
			return options, fmt.Errorf("invalid since time format: %w", err)
		}
		options.Since = &parsedTime
	}

	if auditUntil != "" {
		parsedTime, err := time.Parse(time.RFC3339, auditUntil)
		if err != nil {
			return options, fmt.Errorf("invalid until time format: %w", err)
		}
		options.Until = &parsedTime
	}

	// Parse success filter
	if auditSuccessFilter != "" {
		success, err := strconv.ParseBool(auditSuccessFilter)
		if err != nil {
			return options, fmt.Errorf("invalid success filter format: %w", err)
		}
		options.Success = &success
	}

	// Handle failures-only flag
	if auditFailuresOnly {
		falseVal := false
		options.Success = &falseVal
	}

	// Set other filters
	options.Action = auditAction
	options.SecretID = auditSecretID
	options.KeyID = auditKeyID

	return options, nil
}

func queryTenantAudit(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to query audit logs for tenant %s: %w", tenantID, err)
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(events)
	}

	return displayAuditEvents(events.Events)
}

func queryMultiTenantAudit(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	var allEvents []audit.Event
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to query audit logs for tenant %s: %v\n", tenant, err)
			continue
		}
		allEvents = append(allEvents, events.Events...)
	}

	// Sort by timestamp (newest first)
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(allEvents)
	}

	return displayAuditEvents(allEvents)
}

func showTenantAuditSummary(tenantID string, since *time.Time) error {
	summary, err := vaultManager.GetAuditSummary(tenantID, since)
	if err != nil {
		return fmt.Errorf("failed to get audit summary for tenant %s: %w", tenantID, err)
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(summary)
	}

	fmt.Printf("Audit Summary for Tenant: %s\n", summary.TenantID)
	fmt.Printf("═══════════════════════════════════════\n")
	fmt.Printf("Total Events: %d\n", summary.TotalEvents)
	fmt.Printf("Successful Events: %d\n", summary.SuccessfulEvents)
	fmt.Printf("Failed Events: %d\n", summary.FailedEvents)
	fmt.Printf("Passphrase Operations: %d\n", summary.CredsAccessCount)
	fmt.Printf("Secret Operations: %d\n", summary.SensitiveDataAccessCount)
	fmt.Printf("Key Operations: %d\n", summary.KeyOperations)

	if !summary.LastActivity.IsZero() {
		fmt.Printf("Last Activity: %s\n", summary.LastActivity.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("Last Activity: -\n")
	}

	return nil
}

func showAllTenantsAuditSummary(since *time.Time) error {
	tenants, err := vaultManager.ListTenants()
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if auditJsonOutput {
		var summaries []interface{}
		for _, tenant := range tenants {
			summary, err := vaultManager.GetAuditSummary(tenant, since)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get audit summary for tenant %s: %v\n", tenant, err)
				continue
			}
			summaries = append(summaries, summary)
		}
		return json.NewEncoder(os.Stdout).Encode(summaries)
	}

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

func showTenantEvents(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to query audit events for tenant %s: %w", tenantID, err)
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(events)
	}

	return displayAuditEvents(events.Events)
}

func showAllTenantsEvents(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	var allEvents []audit.Event
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to query audit events for tenant %s: %v\n", tenant, err)
			continue
		}
		allEvents = append(allEvents, events.Events...)
	}

	// Sort by timestamp (newest first)
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(allEvents)
	}

	return displayAuditEvents(allEvents)
}

func showTenantFailures(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to query audit failures for tenant %s: %w", tenantID, err)
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(events)
	}

	fmt.Printf("Failed Operations for Tenant: %s\n", tenantID)
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(events.Events)
}

func showAllTenantsFailures(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	var allEvents []audit.Event
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to query audit failures for tenant %s: %v\n", tenant, err)
			continue
		}
		allEvents = append(allEvents, events.Events...)
	}

	// Sort by timestamp (newest first)
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(allEvents)
	}

	fmt.Printf("Failed Operations (All Tenants)\n")
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(allEvents)
}

func showTenantSecretAccess(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to query secret access for tenant %s: %w", tenantID, err)
	}

	// Filter for secret-related events
	var secretEvents []audit.Event
	for _, event := range events.Events {
		if event.SecretID != "" || isSecretAction(event.Action) {
			secretEvents = append(secretEvents, event)
		}
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(secretEvents)
	}

	fmt.Printf("Secret Access for Tenant: %s\n", tenantID)
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(secretEvents)
}

func showAllTenantsSecretAccess(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	var allSecretEvents []audit.Event
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to query secret access for tenant %s: %v\n", tenant, err)
			continue
		}

		// Filter for secret-related events
		for _, event := range events.Events {
			if event.SecretID != "" || isSecretAction(event.Action) {
				allSecretEvents = append(allSecretEvents, event)
			}
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(allSecretEvents, func(i, j int) bool {
		return allSecretEvents[i].Timestamp.After(allSecretEvents[j].Timestamp)
	})

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(allSecretEvents)
	}

	fmt.Printf("Secret Access (All Tenants)\n")
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(allSecretEvents)
}

func showTenantKeyOperations(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to query key operations for tenant %s: %w", tenantID, err)
	}

	// Filter for key-related events
	var keyEvents []audit.Event
	for _, event := range events.Events {
		if event.KeyID != "" || isKeyAction(event.Action) {
			keyEvents = append(keyEvents, event)
		}
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(keyEvents)
	}

	fmt.Printf("Key Operations for Tenant: %s\n", tenantID)
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(keyEvents)
}

func showAllTenantsKeyOperations(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	var allKeyEvents []audit.Event
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to query key operations for tenant %s: %v\n", tenant, err)
			continue
		}

		// Filter for key-related events
		for _, event := range events.Events {
			if event.KeyID != "" || isKeyAction(event.Action) {
				allKeyEvents = append(allKeyEvents, event)
			}
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(allKeyEvents, func(i, j int) bool {
		return allKeyEvents[i].Timestamp.After(allKeyEvents[j].Timestamp)
	})

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(allKeyEvents)
	}

	fmt.Printf("Key Operations (All Tenants)\n")
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(allKeyEvents)
}

func showTenantPassphraseEvents(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to query passphrase events for tenant %s: %w", tenantID, err)
	}

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(events)
	}

	fmt.Printf("Passphrase Events for Tenant: %s\n", tenantID)
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(events.Events)
}

func showAllTenantsPassphraseEvents(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	var allEvents []audit.Event
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to query passphrase events for tenant %s: %v\n", tenant, err)
			continue
		}
		allEvents = append(allEvents, events.Events...)
	}

	// Sort by timestamp (newest first)
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(allEvents)
	}

	fmt.Printf("Passphrase Events (All Tenants)\n")
	fmt.Printf("═══════════════════════════════════════\n")
	return displayAuditEvents(allEvents)
}

func exportTenantAudit(tenantID string, options audit.QueryOptions) error {
	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to export audit logs for tenant %s: %w", tenantID, err)
	}

	exportData := map[string]interface{}{
		"export_timestamp": time.Now().UTC(),
		"tenant_id":        tenantID,
		"query_options":    options,
		"event_count":      len(events.Events),
		"events":           events,
	}

	return json.NewEncoder(os.Stdout).Encode(exportData)
}

func exportAllTenantsAudit(options audit.QueryOptions) error {
	tenants, err := getTargetTenants()
	if err != nil {
		return err
	}

	exportData := map[string]interface{}{
		"export_timestamp": time.Now().UTC(),
		"query_options":    options,
		"tenants":          make(map[string]interface{}),
	}

	totalEvents := 0
	for _, tenant := range tenants {
		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to export audit logs for tenant %s: %v\n", tenant, err)
			continue
		}

		exportData["tenants"].(map[string]interface{})[tenant] = map[string]interface{}{
			"event_count": len(events.Events),
			"events":      events,
		}
		totalEvents += len(events.Events)
	}

	exportData["total_events"] = totalEvents
	exportData["tenant_count"] = len(tenants)

	return json.NewEncoder(os.Stdout).Encode(exportData)
}

func showTenantAuditStats(tenantID string, since *time.Time) error {
	options := audit.QueryOptions{
		TenantID: tenantID,
		Since:    since,
		Limit:    10000, // Get more events for stats
	}

	events, err := vaultManager.QueryTenantAuditLogs(tenantID, options)
	if err != nil {
		return fmt.Errorf("failed to get audit stats for tenant %s: %w", tenantID, err)
	}

	stats := calculateAuditStats(events.Events, tenantID)

	if auditJsonOutput {
		return json.NewEncoder(os.Stdout).Encode(stats)
	}

	return displayAuditStats(stats)
}

func showAllTenantsAuditStats(since *time.Time) error {
	tenants, err := vaultManager.ListTenants()
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if auditJsonOutput {
		var allStats []AuditStats
		for _, tenant := range tenants {
			options := audit.QueryOptions{
				TenantID: tenant,
				Since:    since,
				Limit:    10000,
			}

			events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get audit stats for tenant %s: %v\n", tenant, err)
				continue
			}

			stats := calculateAuditStats(events.Events, tenant)
			allStats = append(allStats, stats)
		}
		return json.NewEncoder(os.Stdout).Encode(allStats)
	}

	// Display consolidated stats
	fmt.Printf("Audit Statistics (All Tenants)\n")
	fmt.Printf("═══════════════════════════════════════\n")

	for _, tenant := range tenants {
		options := audit.QueryOptions{
			TenantID: tenant,
			Since:    since,
			Limit:    10000,
		}

		events, err := vaultManager.QueryTenantAuditLogs(tenant, options)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get audit stats for tenant %s: %v\n", tenant, err)
			continue
		}

		stats := calculateAuditStats(events.Events, tenant)
		fmt.Printf("\nTenant: %s\n", tenant)
		fmt.Printf("────────────────────────────────────────\n")
		displayAuditStatsSection(stats)
	}

	return nil
}

func displayAuditEvents(events []audit.Event) error {
	if len(events) == 0 {
		fmt.Println("No audit events found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if auditDetails {
		// Detailed view
		for _, event := range events {
			fmt.Fprintf(w, "Event ID:\t%s\n", event.ID)
			fmt.Fprintf(w, "Timestamp:\t%s\n", event.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(w, "Tenant:\t%s\n", event.TenantID)
			fmt.Fprintf(w, "Action:\t%s\n", event.Action)

			status := "SUCCESS"
			if !event.Success {
				status = "FAILED"
			}
			fmt.Fprintf(w, "Status:\t%s\n", status)

			if event.Error != "" {
				fmt.Fprintf(w, "Error:\t%s\n", event.Error)
			}
			if event.SecretID != "" {
				fmt.Fprintf(w, "Secret ID:\t%s\n", event.SecretID)
			}
			if event.KeyID != "" {
				fmt.Fprintf(w, "Key ID:\t%s\n", event.KeyID)
			}
			if event.UserID != "" {
				fmt.Fprintf(w, "User ID:\t%s\n", event.UserID)
			}
			if event.Source != "" {
				fmt.Fprintf(w, "Source:\t%s\n", event.Source)
			}

			if len(event.Metadata) > 0 {
				fmt.Fprintf(w, "Metadata:\t")
				for k, v := range event.Metadata {
					fmt.Fprintf(w, "%s=%v ", k, v)
				}
				fmt.Fprintf(w, "\n")
			}

			fmt.Fprintf(w, "────────────────────────────────────────\n")
		}
	} else {
		// Compact table view
		fmt.Fprintf(w, "TIMESTAMP\tTENANT\tACTION\tSTATUS\tSECRET\tKEY\tERROR\n")

		for _, event := range events {
			timestamp := event.Timestamp.Format("2006-01-02 15:04:05")

			status := "SUCCESS"
			if !event.Success {
				status = "FAILED"
			}

			secretID := event.SecretID
			if len(secretID) > 12 {
				secretID = secretID[:12] + "..."
			}

			keyID := event.KeyID
			if len(keyID) > 12 {
				keyID = keyID[:12] + "..."
			}

			errorMsg := event.Error
			if len(errorMsg) > 30 {
				errorMsg = errorMsg[:30] + "..."
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				timestamp, event.TenantID, event.Action, status, secretID, keyID, errorMsg)
		}
	}

	return w.Flush()
}

// AuditStats represents comprehensive audit statistics
type AuditStats struct {
	TenantID           string         `json:"tenant_id"`
	GeneratedAt        time.Time      `json:"generated_at"`
	TimeRange          string         `json:"time_range"`
	TotalEvents        int            `json:"total_events"`
	SuccessfulEvents   int            `json:"successful_events"`
	FailedEvents       int            `json:"failed_events"`
	SuccessRate        float64        `json:"success_rate"`
	ActionBreakdown    map[string]int `json:"action_breakdown"`
	HourlyDistribution map[string]int `json:"hourly_distribution"`
	DailyDistribution  map[string]int `json:"daily_distribution"`
	TopFailedActions   []ActionCount  `json:"top_failed_actions"`
	TopSecrets         []SecretCount  `json:"top_secrets"`
	TopKeys            []KeyCount     `json:"top_keys"`
	FirstEvent         *time.Time     `json:"first_event,omitempty"`
	LastEvent          *time.Time     `json:"last_event,omitempty"`
	CredsOperations    int            `json:"creds_operations"`
	SecretOperations   int            `json:"secret_operations"`
	KeyOperations      int            `json:"key_operations"`
}

type ActionCount struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

type SecretCount struct {
	SecretID string `json:"secret_id"`
	Count    int    `json:"count"`
}

type KeyCount struct {
	KeyID string `json:"key_id"`
	Count int    `json:"count"`
}

func calculateAuditStats(events []audit.Event, tenantID string) AuditStats {
	stats := AuditStats{
		TenantID:           tenantID,
		GeneratedAt:        time.Now().UTC(),
		ActionBreakdown:    make(map[string]int),
		HourlyDistribution: make(map[string]int),
		DailyDistribution:  make(map[string]int),
	}

	if len(events) == 0 {
		return stats
	}

	// Basic counts
	stats.TotalEvents = len(events)

	actionCounts := make(map[string]int)
	failedActions := make(map[string]int)
	secretCounts := make(map[string]int)
	keyCounts := make(map[string]int)

	for _, event := range events {
		// Success/failure counts
		if event.Success {
			stats.SuccessfulEvents++
		} else {
			stats.FailedEvents++
			failedActions[event.Action]++
		}

		// Action breakdown
		actionCounts[event.Action]++
		stats.ActionBreakdown[event.Action]++

		// Time distributions
		hour := event.Timestamp.Format("15")
		day := event.Timestamp.Format("2006-01-02")
		stats.HourlyDistribution[hour]++
		stats.DailyDistribution[day]++

		// Secret and key counts
		if event.SecretID != "" {
			secretCounts[event.SecretID]++
		}
		if event.KeyID != "" {
			keyCounts[event.KeyID]++
		}

		// Operation type counts
		if isPassphraseAction(event.Action) {
			stats.CredsOperations++
		} else if isSecretAction(event.Action) {
			stats.SecretOperations++
		} else if isKeyAction(event.Action) {
			stats.KeyOperations++
		}

		// Time range
		if stats.FirstEvent == nil || event.Timestamp.Before(*stats.FirstEvent) {
			stats.FirstEvent = &event.Timestamp
		}
		if stats.LastEvent == nil || event.Timestamp.After(*stats.LastEvent) {
			stats.LastEvent = &event.Timestamp
		}
	}

	// Calculate success rate
	if stats.TotalEvents > 0 {
		stats.SuccessRate = float64(stats.SuccessfulEvents) / float64(stats.TotalEvents) * 100
	}

	// Top failed actions
	stats.TopFailedActions = getTopActions(failedActions, 5)

	// Top secrets and keys
	stats.TopSecrets = getTopSecrets(secretCounts, 10)
	stats.TopKeys = getTopKeys(keyCounts, 10)

	// Time range description
	if stats.FirstEvent != nil && stats.LastEvent != nil {
		duration := stats.LastEvent.Sub(*stats.FirstEvent)
		stats.TimeRange = fmt.Sprintf("%s (%.1f hours)",
			duration.String(), duration.Hours())
	}

	return stats
}

func displayAuditStats(stats AuditStats) error {
	fmt.Printf("Audit Statistics for Tenant: %s\n", stats.TenantID)
	fmt.Printf("Generated at: %s\n", stats.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("═══════════════════════════════════════\n\n")

	return displayAuditStatsSection(stats)
}

func displayAuditStatsSection(stats AuditStats) error {
	// Summary
	fmt.Printf("SUMMARY\n")
	fmt.Printf("───────\n")
	fmt.Printf("Total Events: %d\n", stats.TotalEvents)
	fmt.Printf("Successful: %d (%.1f%%)\n", stats.SuccessfulEvents, stats.SuccessRate)
	fmt.Printf("Failed: %d (%.1f%%)\n", stats.FailedEvents, 100-stats.SuccessRate)

	if stats.TimeRange != "" {
		fmt.Printf("Time Range: %s\n", stats.TimeRange)
	}

	// Operation breakdown
	fmt.Printf("\nOPERATION BREAKDOWN\n")
	fmt.Printf("──────────────────\n")
	fmt.Printf("Passphrase Operations: %d\n", stats.CredsOperations)
	fmt.Printf("Secret Operations: %d\n", stats.SecretOperations)
	fmt.Printf("Key Operations: %d\n", stats.KeyOperations)

	// Top actions
	if len(stats.ActionBreakdown) > 0 {
		fmt.Printf("\nTOP ACTIONS\n")
		fmt.Printf("───────────\n")

		// Sort actions by count
		type actionStat struct {
			action string
			count  int
		}

		var actions []actionStat
		for action, count := range stats.ActionBreakdown {
			actions = append(actions, actionStat{action, count})
		}

		sort.Slice(actions, func(i, j int) bool {
			return actions[i].count > actions[j].count
		})

		for i, action := range actions {
			if i >= 10 { // Top 10
				break
			}
			fmt.Printf("  %s: %d\n", action.action, action.count)
		}
	}

	// Failed actions
	if len(stats.TopFailedActions) > 0 {
		fmt.Printf("\nTOP FAILED ACTIONS\n")
		fmt.Printf("─────────────────\n")
		for _, action := range stats.TopFailedActions {
			fmt.Printf("  %s: %d failures\n", action.Action, action.Count)
		}
	}

	// Most accessed secrets
	if len(stats.TopSecrets) > 0 {
		fmt.Printf("\nMOST ACCESSED SECRETS\n")
		fmt.Printf("────────────────────\n")
		for i, secret := range stats.TopSecrets {
			if i >= 5 { // Top 5
				break
			}
			secretID := secret.SecretID
			if len(secretID) > 30 {
				secretID = secretID[:30] + "..."
			}
			fmt.Printf("  %s: %d accesses\n", secretID, secret.Count)
		}
	}

	// Most used keys
	if len(stats.TopKeys) > 0 {
		fmt.Printf("\nMOST USED KEYS\n")
		fmt.Printf("──────────────\n")
		for i, key := range stats.TopKeys {
			if i >= 5 { // Top 5
				break
			}
			keyID := key.KeyID
			if len(keyID) > 30 {
				keyID = keyID[:30] + "..."
			}
			fmt.Printf("  %s: %d operations\n", keyID, key.Count)
		}
	}

	return nil
}

func getTargetTenants() ([]string, error) {
	if auditTenants == "" {
		return vaultManager.ListTenants()
	}

	if auditTenants == "all" {
		return vaultManager.ListTenants()
	}

	return strings.Split(auditTenants, ","), nil
}

func getTopActions(actionCounts map[string]int, limit int) []ActionCount {
	var actions []ActionCount
	for action, count := range actionCounts {
		actions = append(actions, ActionCount{Action: action, Count: count})
	}

	sort.Slice(actions, func(i, j int) bool {
		return actions[i].Count > actions[j].Count
	})

	if len(actions) > limit {
		actions = actions[:limit]
	}

	return actions
}

func getTopSecrets(secretCounts map[string]int, limit int) []SecretCount {
	var secrets []SecretCount
	for secretID, count := range secretCounts {
		secrets = append(secrets, SecretCount{SecretID: secretID, Count: count})
	}

	sort.Slice(secrets, func(i, j int) bool {
		return secrets[i].Count > secrets[j].Count
	})

	if len(secrets) > limit {
		secrets = secrets[:limit]
	}

	return secrets
}

func getTopKeys(keyCounts map[string]int, limit int) []KeyCount {
	var keys []KeyCount
	for keyID, count := range keyCounts {
		keys = append(keys, KeyCount{KeyID: keyID, Count: count})
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Count > keys[j].Count
	})

	if len(keys) > limit {
		keys = keys[:limit]
	}

	return keys
}

func isSecretAction(action string) bool {
	secretActions := map[string]bool{
		"SECRET_CREATE":  true,
		"SECRET_READ":    true,
		"SECRET_UPDATE":  true,
		"SECRET_DELETE":  true,
		"SECRET_LIST":    true,
		"SECRET_ENCRYPT": true,
		"SECRET_DECRYPT": true,
		"SECRET_ACCESS":  true,
	}
	return secretActions[action]
}

func isKeyAction(action string) bool {
	keyActions := map[string]bool{
		"KEY_CREATE":    true,
		"KEY_ROTATE":    true,
		"KEY_DELETE":    true,
		"KEY_LIST":      true,
		"KEY_ENCRYPT":   true,
		"KEY_DECRYPT":   true,
		"KEY_DERIVE":    true,
		"KEY_OPERATION": true,
	}
	return keyActions[action]
}

func isPassphraseAction(action string) bool {
	passphraseActions := map[string]bool{
		"PASSPHRASE_ROTATE":     true,
		"PASSPHRASE_VERIFY":     true,
		"PASSPHRASE_CHANGE":     true,
		"PASSPHRASE_ACCESS":     true,
		"EMERGENCY_PASSPHRASE":  true,
		"VAULT_UNLOCK":          true,
		"DERIVATION_KEY_DERIVE": true,
		"VAULT_INITIALIZED":     true,
	}
	return passphraseActions[action]
}
