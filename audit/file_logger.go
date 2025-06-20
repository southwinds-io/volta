// audit/file_logger.go
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type FileLogger struct {
	basePath   string
	tenantID   string
	file       *os.File
	mu         sync.RWMutex
	config     *Config
	eventCache []Event // Recent events cache for faster queries
	cacheSize  int
	fileOpts   FileOptions
}

type FileOptions struct {
	FilePath   string `json:"file_path"`
	MaxSize    int    `json:"max_size,omitempty"`    // Max size in MB
	MaxBackups int    `json:"max_backups,omitempty"` // Max backup files
	MaxAge     int    `json:"max_age,omitempty"`     // Max age in days
}

// NewFileLogger creates a new file-based audit logger
func NewFileLogger(config *Config) (*FileLogger, error) {
	// Parse file-specific options
	var fileOpts FileOptions
	if err := parseOptions(config.Options, &fileOpts); err != nil {
		return nil, fmt.Errorf("invalid file logger options: %w", err)
	}

	// Validate required options
	if fileOpts.FilePath == "" {
		return nil, fmt.Errorf("file_path is required for file logger")
	}

	// Set defaults
	if fileOpts.MaxSize == 0 {
		fileOpts.MaxSize = 100 // 100MB default
	}
	if fileOpts.MaxBackups == 0 {
		fileOpts.MaxBackups = 5
	}
	if fileOpts.MaxAge == 0 {
		fileOpts.MaxAge = 30 // 30 days
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(fileOpts.FilePath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Open file for appending
	file, err := os.OpenFile(fileOpts.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	logger := &FileLogger{
		basePath:   filepath.Dir(fileOpts.FilePath),
		tenantID:   config.TenantID,
		file:       file,
		config:     config,
		fileOpts:   fileOpts,
		eventCache: make([]Event, 0),
		cacheSize:  1000,
	}

	return logger, nil
}

// Log implements the Logger interface
func (fl *FileLogger) Log(action string, success bool, metadata map[string]interface{}) error {
	event := Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		TenantID:  fl.tenantID,
		Action:    action,
		Success:   success,
		Metadata:  metadata,
	}

	return fl.writeEvent(event)
}

// writeEvent writes an event to the log file in JSONL format and updates cache
func (fl *FileLogger) writeEvent(event Event) error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	// ensures the file is open in case it has been close by a previous vault that was using this logger
	if err := fl.ensureFileOpen(); err != nil {
		return err
	}

	// Serialize event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to serialize audit event: %w", err)
	}

	// Write to file
	if _, err = fl.file.WriteString(string(eventJSON) + "\n"); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Flush to ensure it's written
	if err = fl.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log: %w", err)
	}

	// Update cache
	fl.updateCache(event)

	return nil
}

// updateCache adds event to cache and maintains size limit
func (fl *FileLogger) updateCache(event Event) {
	fl.eventCache = append(fl.eventCache, event)

	// Trim cache if it exceeds size limit
	if len(fl.eventCache) > fl.cacheSize {
		// Remove oldest events, keep newest
		fl.eventCache = fl.eventCache[len(fl.eventCache)-fl.cacheSize:]
	}
}

// Query implements the Querier interface
func (fl *FileLogger) Query(options QueryOptions) (QueryResult, error) {
	fl.mu.RLock()
	defer fl.mu.RUnlock()

	// For small queries, try cache first
	if fl.canUseCacheForQuery(options) {
		return fl.queryFromCache(options), nil
	}

	// For larger queries or when cache doesn't cover the time range, read from file
	return fl.queryFromFile(options)
}

// canUseCacheForQuery determines if the cache can satisfy the query
func (fl *FileLogger) canUseCacheForQuery(options QueryOptions) bool {
	if len(fl.eventCache) == 0 {
		return false
	}

	// If no time constraints, cache might not have all data
	if options.Since == nil && options.Until == nil {
		return false
	}

	// Check if cache covers the requested time range
	oldestCached := fl.eventCache[0].Timestamp
	if options.Since != nil && options.Since.Before(oldestCached) {
		return false
	}

	return true
}

// queryFromCache queries events from the in-memory cache
func (fl *FileLogger) queryFromCache(options QueryOptions) QueryResult {
	var filtered []Event

	for _, event := range fl.eventCache {
		if fl.matchesFilter(event, options) {
			filtered = append(filtered, event)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	// Apply limit
	if options.Limit > 0 && len(filtered) > options.Limit {
		filtered = filtered[:options.Limit]
	}

	return QueryResult{
		Events:     filtered,
		TotalCount: len(fl.eventCache),
		Filtered:   len(filtered),
		HasMore:    len(filtered) == options.Limit,
	}
}

// queryFromFile queries events from the audit log file
func (fl *FileLogger) queryFromFile(options QueryOptions) (QueryResult, error) {
	// Read all audit log files for this tenant
	files, err := fl.getAuditLogFiles()
	if err != nil {
		return QueryResult{}, fmt.Errorf("failed to get audit log files: %w", err)
	}

	var allEvents []Event
	totalCount := 0

	for _, filePath := range files {
		events, count, err := fl.readEventsFromFile(filePath, options)
		if err != nil {
			return QueryResult{}, fmt.Errorf("failed to read events from %s: %w", filePath, err)
		}
		allEvents = append(allEvents, events...)
		totalCount += count
	}

	// Sort by timestamp (newest first)
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	// Apply offset and limit
	start := options.Offset
	if start > len(allEvents) {
		start = len(allEvents)
	}

	end := len(allEvents)
	if options.Limit > 0 {
		end = start + options.Limit
		if end > len(allEvents) {
			end = len(allEvents)
		}
	}

	result := allEvents[start:end]

	return QueryResult{
		Events:     result,
		TotalCount: totalCount,
		Filtered:   len(allEvents),
		HasMore:    end < len(allEvents),
	}, nil
}

// getAuditLogFiles returns all audit log files for this tenant
func (fl *FileLogger) getAuditLogFiles() ([]string, error) {
	var files []string

	// Current log file
	files = append(files, fl.file.Name())

	// Look for rotated log files (if you implement log rotation)
	// Pattern: audit.log, audit.log.1, audit.log.2, etc.
	pattern := fl.file.Name() + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return files, nil // Return current file only if glob fails
	}

	for _, match := range matches {
		if match != fl.file.Name() {
			files = append(files, match)
		}
	}

	return files, nil
}

// readEventsFromFile reads and filters events from a specific file
func (fl *FileLogger) readEventsFromFile(filePath string, options QueryOptions) ([]Event, int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer file.Close()

	var events []Event
	totalCount := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		totalCount++

		var event Event
		if err = json.Unmarshal([]byte(line), &event); err != nil {
			// Log parse error but continue
			continue
		}

		if fl.matchesFilter(event, options) {
			events = append(events, event)
		}
	}

	if err = scanner.Err(); err != nil {
		return events, totalCount, fmt.Errorf("error reading audit log file: %w", err)
	}

	return events, totalCount, nil
}

// matchesFilter checks if an event matches the query filters
func (fl *FileLogger) matchesFilter(event Event, options QueryOptions) bool {
	// Tenant filter
	if options.TenantID != "" && event.TenantID != options.TenantID {
		return false
	}

	// Time range filter
	if options.Since != nil && event.Timestamp.Before(*options.Since) {
		return false
	}
	if options.Until != nil && event.Timestamp.After(*options.Until) {
		return false
	}

	// Action filter
	if options.Action != "" && event.Action != options.Action {
		return false
	}

	// Success filter
	if options.Success != nil && event.Success != *options.Success {
		return false
	}

	// Secret ID filter
	if options.SecretID != "" && event.SecretID != options.SecretID {
		return false
	}

	// Key ID filter
	if options.KeyID != "" && event.KeyID != options.KeyID {
		return false
	}

	// Passphrase access filter
	if options.PassphraseAccess {
		passphraseActions := []string{
			"passphrase_rotate",
			"passphrase_access",
			"derivation_key_create",
			"derivation_key_access",
			"vault_unlock",
		}

		isPassphraseAction := false
		for _, action := range passphraseActions {
			if strings.Contains(strings.ToLower(event.Action), action) {
				isPassphraseAction = true
				break
			}
		}

		if !isPassphraseAction {
			return false
		}
	}

	return true
}

// Close implements the Logger interface
func (fl *FileLogger) Close() error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if fl.file != nil {
		err := fl.file.Close()
		fl.file = nil
		return err
	}
	return nil
}

func (fl *FileLogger) ensureFileOpen() error {
	if fl.file == nil {
		var err error
		fl.file, err = os.OpenFile(fl.fileOpts.FilePath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to reopen audit log: %w", err)
		}
	}
	return nil
}

// generateEventID creates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), os.Getpid())
}
