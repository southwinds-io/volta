package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// Config defines audit logging configuration
type Config struct {
	Enabled  bool                   `json:"enabled"`
	TenantID string                 `json:"tenant_id"`
	Type     ConfigType             `json:"type"`    // "file", "database", "syslog", etc.
	Options  map[string]interface{} `json:"options"` // Provider-specific options
	LogLevel string                 `json:"log_level,omitempty"`
}

type ConfigType string

const (
	FileAuditType   ConfigType = "file"
	SyslogAuditType ConfigType = "syslog"
	NoOp            ConfigType = ""
)

// Logger interface for pluggable audit implementations
type Logger interface {
	Log(action string, success bool, metadata map[string]interface{}) error
	Query(options QueryOptions) (QueryResult, error)
	Close() error
}

// Event represents an audit log event
type Event struct {
	ID        string                 `json:"id"`
	RequestID string                 `json:"request_id"`
	Timestamp time.Time              `json:"timestamp"`
	TenantID  string                 `json:"tenant_id"`
	Action    string                 `json:"action"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	SecretID  string                 `json:"secret_id,omitempty"`
	KeyID     string                 `json:"key_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Source    string                 `json:"source,omitempty"` // IP, hostname, etc.
	SessionID string                 `json:"session_id,omitempty"`
	Command   string                 `json:"command,omitempty"`
	Duration  int64                  `json:"duration_ms,omitempty"`
}

// QueryOptions for filtering audit logs
type QueryOptions struct {
	TenantID         string
	Since            *time.Time
	Until            *time.Time
	Action           string
	Success          *bool // nil = all, true = only success, false = only failures
	SecretID         string
	KeyID            string
	Limit            int
	Offset           int
	PassphraseAccess bool // Filter for passphrase-related events
}

// QueryResult contains the results of an audit query
type QueryResult struct {
	Events     []Event `json:"events"`
	TotalCount int     `json:"total_count"`
	Filtered   int     `json:"filtered"`
	HasMore    bool    `json:"has_more"`
}

// NewLogger creates an appropriate logger based on configuration
func NewLogger(config *Config) (Logger, error) {
	if config == nil || !config.Enabled {
		return &NoOpLogger{}, nil
	}

	switch config.Type {
	case FileAuditType: // Default to file if not specified
		return NewFileLogger(config)
	case SyslogAuditType:
		return NewSyslogLogger(config)
	case NoOp:
		return &NoOpLogger{}, nil
	default:
		return nil, fmt.Errorf("unknown audit provider: %s", config.Type)
	}
}

// parseOptions converts map[string]interface{} to specific options struct
func parseOptions(options map[string]interface{}, target interface{}) error {
	if len(options) == 0 {
		return nil
	}

	// Convert to JSON and back to parse into struct
	jsonData, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	if err = json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal options: %w", err)
	}

	return nil
}
