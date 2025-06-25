package audit

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"time"
)

// Ensure SyslogLogger implements Logger interface
var _ Logger = (*SyslogLogger)(nil)

type SyslogOptions struct {
	Network  string `json:"network"`  // "tcp", "udp", ""
	Address  string `json:"address"`  // "localhost:514"
	Priority int    `json:"priority"` // syslog.LOG_INFO, etc.
	Tag      string `json:"tag"`
}

// SyslogLogger implements AuditLogger for syslog
type SyslogLogger struct {
	config     *Config
	syslogOpts SyslogOptions
	writer     *syslog.Writer
}

// NewSyslogLogger creates a new syslog audit logger with options
func NewSyslogLogger(config *Config) (*SyslogLogger, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	var syslogOpts SyslogOptions
	if err := parseOptions(config.Options, &syslogOpts); err != nil {
		return nil, fmt.Errorf("invalid syslog logger options: %w", err)
	}

	// Set defaults for syslog options if not provided
	if syslogOpts.Priority == 0 {
		// Determine syslog priority based on log level
		switch config.LogLevel {
		case "error":
			syslogOpts.Priority = int(syslog.LOG_ERR | syslog.LOG_USER)
		case "warn":
			syslogOpts.Priority = int(syslog.LOG_WARNING | syslog.LOG_USER)
		case "info":
			syslogOpts.Priority = int(syslog.LOG_INFO | syslog.LOG_USER)
		default:
			syslogOpts.Priority = int(syslog.LOG_INFO | syslog.LOG_USER)
		}
	}

	if syslogOpts.Tag == "" {
		syslogOpts.Tag = "volta-audit"
	}

	// Create syslog writer based on network configuration
	var writer *syslog.Writer
	var err error

	if syslogOpts.Network != "" && syslogOpts.Address != "" {
		// Remote syslog
		writer, err = syslog.Dial(syslogOpts.Network, syslogOpts.Address,
			syslog.Priority(syslogOpts.Priority), syslogOpts.Tag)
	} else {
		// Local syslog
		writer, err = syslog.New(syslog.Priority(syslogOpts.Priority), syslogOpts.Tag)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create syslog writer: %w", err)
	}

	return &SyslogLogger{
		config:     config,
		syslogOpts: syslogOpts,
		writer:     writer,
	}, nil
}

func (s *SyslogLogger) Log(action string, success bool, metadata map[string]interface{}) error {
	if !s.config.Enabled {
		return nil
	}

	event := Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		TenantID:  s.config.TenantID,
		Action:    action,
		Success:   success,
		Metadata:  metadata,
		Source:    "vault",
	}

	return s.writeEvent(event)
}

func (s *SyslogLogger) Close() error {
	if s.writer != nil {
		err := s.writer.Close()
		s.writer = nil
		return err
	}
	return nil
}

// Query implementation for syslog - limited capability since syslog is write-only
func (s *SyslogLogger) Query(options QueryOptions) (QueryResult, error) {
	// Syslog is typically write-only and doesn't support querying historical data
	// For querying, you would typically need to:
	// 1. Use a syslog server that stores logs (like rsyslog with database output)
	// 2. Query the syslog server's storage directly
	// 3. Or combine syslog with another audit backend for querying

	return QueryResult{
		Events:     []Event{},
		TotalCount: 0,
		Filtered:   0,
		HasMore:    false,
	}, fmt.Errorf("syslog logger does not support querying historical data")
}

func (s *SyslogLogger) writeEvent(event Event) error {
	if s.writer == nil {
		return fmt.Errorf("syslog writer not initialized")
	}

	// Convert event to JSON for structured logging
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Format the log message with prefix for easy filtering
	logMessage := fmt.Sprintf("VOLTA_AUDIT: %s", string(eventJSON))

	// Write to appropriate syslog level based on success and action
	switch {
	case !event.Success && event.Error != "":
		return s.writer.Err(logMessage)
	case !event.Success:
		return s.writer.Warning(logMessage)
	case isSecurityCriticalAction(event.Action):
		// Security-critical actions always go to notice level
		return s.writer.Notice(logMessage)
	case s.config.LogLevel == "error":
		// Only log errors when level is error
		if !event.Success {
			return s.writer.Err(logMessage)
		}
		return nil
	case s.config.LogLevel == "warn":
		// Log warnings and errors when level is warn
		if !event.Success {
			return s.writer.Warning(logMessage)
		}
		return s.writer.Info(logMessage)
	default:
		// Default to info level
		return s.writer.Info(logMessage)
	}
}

// Helper function to determine if an action is security-critical
func isSecurityCriticalAction(action string) bool {
	securityActions := map[string]bool{
		"PASSPHRASE_ROTATE":   true,
		"KEY_ROTATE":          true,
		"VAULT_UNLOCK":        true,
		"VAULT_SEAL":          true,
		"AUTH_FAILURE":        true,
		"UNAUTHORIZED_ACCESS": true,
	}
	return securityActions[action]
}
