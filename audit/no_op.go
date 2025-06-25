package audit

// NoOpLogger is a no-op implementation for when auditing is disabled
type NoOpLogger struct{}

func NewNoOpLogger() Logger {
	return new(NoOpLogger)
}

func (n *NoOpLogger) Query(options QueryOptions) (QueryResult, error) {
	return QueryResult{}, nil
}

func (n *NoOpLogger) Log(action string, success bool, metadata map[string]interface{}) error {
	return nil
}

func (n *NoOpLogger) LogSecretAccess(action, secretID string, success bool, error string) error {
	return nil
}

func (n *NoOpLogger) LogKeyOperation(action, keyID string, success bool, error string) error {
	return nil
}

func (n *NoOpLogger) Close() error {
	return nil
}
