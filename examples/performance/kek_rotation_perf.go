package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
)

const passphrase = "test-passphrase-for-performance-testing"

// TestConfig holds all configurable parameters for the performance test
type TestConfig struct {
	NumTenants           int               `json:"num_tenants"`
	SecretsPerTenant     int               `json:"secrets_per_tenant"`
	ConcurrentTenants    int               `json:"concurrent_tenants"`
	StorageBackend       string            `json:"storage_backend"`
	StorageOptions       map[string]string `json:"storage_options"`
	DerivationPassphrase string            `json:"derivation_passphrase"`
	EnableMemoryLock     bool              `json:"enable_memory_lock"`
}

// DefaultTestConfig returns a sensible default configuration
func DefaultTestConfig() TestConfig {
	return TestConfig{
		NumTenants:           10,
		SecretsPerTenant:     100,
		ConcurrentTenants:    5,
		StorageBackend:       "file",
		StorageOptions:       map[string]string{"base_path": "./test_vaults"},
		DerivationPassphrase: passphrase,
		EnableMemoryLock:     false,
	}
}

// LoadTestConfig loads configuration from a JSON file
func LoadTestConfig(filename string) (TestConfig, error) {
	config := DefaultTestConfig()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return config, nil // Return default if file doesn't exist
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err = json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// TenantMetrics holds performance metrics for a single tenant
type TenantMetrics struct {
	TenantID     string
	SecretsCount int
	RotationTime time.Duration
	Success      bool
	ErrorMessage string
}

// AggregateMetrics holds aggregated performance metrics
type AggregateMetrics struct {
	TotalSecrets        int
	SuccessfulRotations int
	FailedRotations     int
	SuccessRate         float64
	MinRotationTime     time.Duration
	MaxRotationTime     time.Duration
	AvgRotationTime     time.Duration
	MedianRotationTime  time.Duration
	P95RotationTime     time.Duration
	P99RotationTime     time.Duration
	SecretsPerSecond    float64
	RotationsPerSecond  float64
}

// TestResults holds all results from a performance test run
type TestResults struct {
	Config           TestConfig
	PerTenantResults []TenantMetrics
	AggregateMetrics AggregateMetrics
	SetupDuration    time.Duration
	TotalDuration    time.Duration
	StartTime        time.Time
	EndTime          time.Time
}

// VaultManagerWrapper provides a common interface for different storage backends
type VaultManagerWrapper interface {
	GetVault(tenantID string) (volta.VaultService, error)
	CreateVault(tenantID string) (volta.VaultService, error)
	DeleteVault(tenantID string) error
	ListVaults() ([]string, error)
	Close() error
}

// VaultManagerFactory creates vault managers for different backends
type VaultManagerFactory interface {
	CreateVaultManager(auditLogger audit.Logger) (VaultManagerWrapper, error)
	Cleanup() error
}

// FileStoreVaultManagerFactory implements VaultManagerFactory for file storage
type FileStoreVaultManagerFactory struct {
	config   TestConfig
	basePath string
}

func NewFileStoreVaultManagerFactory(config TestConfig) *FileStoreVaultManagerFactory {
	basePath := config.StorageOptions["base_path"]
	if basePath == "" {
		basePath = "./test_vaults"
	}

	return &FileStoreVaultManagerFactory{
		config:   config,
		basePath: basePath,
	}
}

func (f *FileStoreVaultManagerFactory) CreateVaultManager(auditLogger audit.Logger) (VaultManagerWrapper, error) {
	options := volta.Options{
		DerivationPassphrase: f.config.DerivationPassphrase,
		EnableMemoryLock:     f.config.EnableMemoryLock,
	}

	vaultManager := volta.NewVaultManagerFileStore(options, f.basePath, auditLogger)
	return &FileStoreVaultManagerWrapper{
		manager:  vaultManager,
		basePath: f.basePath,
	}, nil
}

func (f *FileStoreVaultManagerFactory) Cleanup() error {
	return os.RemoveAll(f.basePath)
}

// FileStoreVaultManagerWrapper wraps the file store vault manager
type FileStoreVaultManagerWrapper struct {
	manager  volta.VaultManagerService
	basePath string
}

func (f *FileStoreVaultManagerWrapper) GetVault(tenantID string) (volta.VaultService, error) {
	return f.manager.GetVault(tenantID)
}

func (f *FileStoreVaultManagerWrapper) CreateVault(tenantID string) (volta.VaultService, error) {
	return f.manager.GetVault(tenantID)
}

func (f *FileStoreVaultManagerWrapper) DeleteVault(tenantID string) error {
	return f.manager.DeleteTenant(tenantID)
}

func (f *FileStoreVaultManagerWrapper) ListVaults() ([]string, error) {
	return f.manager.ListTenants()
}

func (f *FileStoreVaultManagerWrapper) Close() error {
	return f.manager.CloseAll()
}

// PerformanceTestRunner orchestrates the performance test
type PerformanceTestRunner struct {
	config  TestConfig
	factory VaultManagerFactory
	results TestResults
}

func NewPerformanceTestRunner(config TestConfig) (*PerformanceTestRunner, error) {
	var factory VaultManagerFactory

	switch config.StorageBackend {
	case "file":
		factory = NewFileStoreVaultManagerFactory(config)
	default:
		return nil, fmt.Errorf("unsupported storage backend: %s", config.StorageBackend)
	}

	return &PerformanceTestRunner{
		config:  config,
		factory: factory,
		results: TestResults{Config: config},
	}, nil
}

func (ptr *PerformanceTestRunner) Run() error {
	ptr.results.StartTime = time.Now()

	fmt.Printf("🚀 Starting KEK Rotation Performance Test\n")
	fmt.Printf("Configuration: %d tenants, %d secrets each, %d concurrent workers\n",
		ptr.config.NumTenants, ptr.config.SecretsPerTenant, ptr.config.ConcurrentTenants)

	// Setup phase
	fmt.Printf("⚙️  Setting up test environment...\n")
	setupStart := time.Now()
	if err := ptr.setup(); err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	ptr.results.SetupDuration = time.Since(setupStart)
	fmt.Printf("✅ Setup completed in %v\n", ptr.results.SetupDuration)

	// Test execution phase
	fmt.Printf("🔄 Executing KEK rotations...\n")
	if err := ptr.executeRotations(); err != nil {
		return fmt.Errorf("rotation execution failed: %w", err)
	}

	// Results calculation
	ptr.results.EndTime = time.Now()
	ptr.results.TotalDuration = ptr.results.EndTime.Sub(ptr.results.StartTime)
	ptr.calculateAggregateMetrics()

	fmt.Printf("✅ Test completed in %v\n", ptr.results.TotalDuration)

	return nil
}

func (ptr *PerformanceTestRunner) setup() error {
	auditLogger := ptr.createAuditLogger()

	vaultManager, err := ptr.factory.CreateVaultManager(auditLogger)
	if err != nil {
		return fmt.Errorf("failed to create vault manager: %w", err)
	}
	defer vaultManager.Close()

	// Create tenants and populate with secrets
	for i := 0; i < ptr.config.NumTenants; i++ {
		tenantID := fmt.Sprintf("tenant-%d", i)

		vault, err := vaultManager.CreateVault(tenantID)
		if err != nil {
			return fmt.Errorf("failed to create vault for tenant %s: %w", tenantID, err)
		}

		// Add secrets to the vault
		for j := 0; j < ptr.config.SecretsPerTenant; j++ {
			secretName := fmt.Sprintf("secret-%d", j)
			secretData := ptr.generateSecretData(secretName, tenantID)
			value := secretData["value"].(string)
			tags := secretData["tags"].([]string)
			if _, err = vault.StoreSecret(secretName, []byte(value), tags, volta.ContentTypeText); err != nil {
				return fmt.Errorf("failed to put secret %s for tenant %s: %w", secretName, tenantID, err)
			}
		}

		if err := vault.Close(); err != nil {
			log.Printf("Warning: failed to close vault for tenant %s: %v", tenantID, err)
		}
	}

	return nil
}

func (ptr *PerformanceTestRunner) executeRotations() error {
	auditLogger := ptr.createAuditLogger()

	vaultManager, err := ptr.factory.CreateVaultManager(auditLogger)
	if err != nil {
		return fmt.Errorf("failed to create vault manager: %w", err)
	}
	defer vaultManager.Close()

	// Create work channels
	tenantCh := make(chan string, ptr.config.NumTenants)
	resultsCh := make(chan TenantMetrics, ptr.config.NumTenants)

	// Populate tenant work queue
	for i := 0; i < ptr.config.NumTenants; i++ {
		tenantCh <- fmt.Sprintf("tenant-%d", i)
	}
	close(tenantCh)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < ptr.config.ConcurrentTenants; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ptr.rotationWorker(workerID, vaultManager, tenantCh, resultsCh)
		}(i)
	}

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results
	ptr.results.PerTenantResults = make([]TenantMetrics, 0, ptr.config.NumTenants)
	for result := range resultsCh {
		ptr.results.PerTenantResults = append(ptr.results.PerTenantResults, result)
	}

	return nil
}

func (ptr *PerformanceTestRunner) rotationWorker(workerID int, vaultManager VaultManagerWrapper, tenantCh <-chan string, resultsCh chan<- TenantMetrics) {
	for tenantID := range tenantCh {
		result := ptr.rotateTenantKEK(tenantID, vaultManager)
		resultsCh <- result

		if result.Success {
			fmt.Printf("Worker %d: ✅ Rotated KEK for %s (%v)\n", workerID, tenantID, result.RotationTime)
		} else {
			fmt.Printf("Worker %d: ❌ Failed to rotate KEK for %s: %s\n", workerID, tenantID, result.ErrorMessage)
		}
	}
}

func (ptr *PerformanceTestRunner) rotateTenantKEK(tenantID string, vaultManager VaultManagerWrapper) TenantMetrics {
	start := time.Now()

	result := TenantMetrics{
		TenantID:     tenantID,
		SecretsCount: ptr.config.SecretsPerTenant,
		Success:      false,
	}

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to get vault: %v", err)
		result.RotationTime = time.Since(start)
		return result
	}
	defer vault.Close()

	// Perform KEK rotation
	if err = vault.RotateKeyEncryptionKey(passphrase, "performance testing"); err != nil {
		result.ErrorMessage = fmt.Sprintf("KEK rotation failed: %v", err)
		result.RotationTime = time.Since(start)
		return result
	}

	// Verify that secrets are still accessible after rotation
	for i := 0; i < min(5, ptr.config.SecretsPerTenant); i++ { // Sample verification
		secretName := fmt.Sprintf("secret-%d", i)
		if _, err = vault.GetSecret(secretName); err != nil {
			result.ErrorMessage = fmt.Sprintf("secret verification failed for %s: %v", secretName, err)
			result.RotationTime = time.Since(start)
			return result
		}
	}

	result.Success = true
	result.RotationTime = time.Since(start)
	return result
}

func (ptr *PerformanceTestRunner) calculateAggregateMetrics() {
	metrics := &ptr.results.AggregateMetrics
	results := ptr.results.PerTenantResults

	if len(results) == 0 {
		return
	}

	metrics.TotalSecrets = ptr.config.NumTenants * ptr.config.SecretsPerTenant

	var successfulTimes []time.Duration
	var totalTime time.Duration

	for _, result := range results {
		if result.Success {
			metrics.SuccessfulRotations++
			successfulTimes = append(successfulTimes, result.RotationTime)
			totalTime += result.RotationTime
		} else {
			metrics.FailedRotations++
		}
	}

	if len(successfulTimes) > 0 {
		// Sort times for percentile calculations
		sort.Slice(successfulTimes, func(i, j int) bool {
			return successfulTimes[i] < successfulTimes[j]
		})

		metrics.MinRotationTime = successfulTimes[0]
		metrics.MaxRotationTime = successfulTimes[len(successfulTimes)-1]
		metrics.AvgRotationTime = totalTime / time.Duration(len(successfulTimes))

		// Calculate percentiles
		metrics.MedianRotationTime = successfulTimes[len(successfulTimes)/2]
		metrics.P95RotationTime = successfulTimes[int(float64(len(successfulTimes))*0.95)]
		metrics.P99RotationTime = successfulTimes[int(float64(len(successfulTimes))*0.99)]

		// Calculate throughput
		totalTestTime := ptr.results.TotalDuration.Seconds() - ptr.results.SetupDuration.Seconds()
		if totalTestTime > 0 {
			metrics.SecretsPerSecond = float64(metrics.SuccessfulRotations*ptr.config.SecretsPerTenant) / totalTestTime
			metrics.RotationsPerSecond = float64(metrics.SuccessfulRotations) / totalTestTime
		}
	}

	// Calculate success rate
	totalRotations := len(results)
	if totalRotations > 0 {
		metrics.SuccessRate = float64(metrics.SuccessfulRotations) / float64(totalRotations) * 100.0
	}
}

func (ptr *PerformanceTestRunner) generateSecretData(secretName, tenantID string) map[string]interface{} {
	return map[string]interface{}{
		"name":        secretName,
		"tenant":      tenantID,
		"value":       fmt.Sprintf("secret-value-%d", rand.Intn(10000)),
		"timestamp":   time.Now().Unix(),
		"description": "Performance test secret",
		"tags":        []string{"test", "performance", tenantID},
	}
}

func (ptr *PerformanceTestRunner) createAuditLogger() audit.Logger {
	auditFilePath := ".volta_audit.log"

	fmt.Printf("Initializing file-based audit logger to: %s\n", auditFilePath)

	logger, err := audit.NewLogger(&audit.Config{
		Enabled: true,
		Type:    audit.FileAuditType,
		Options: map[string]interface{}{
			"file_path": auditFilePath,
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v, an NoOp Logger will be used instead.", err)
		return audit.NewNoOpLogger()
	}
	return logger
}

func (ptr *PerformanceTestRunner) PrintResults() {
	r := &ptr.results
	separator := strings.Repeat("=", 80)

	fmt.Printf("\n%s\n", separator)
	fmt.Printf("📊 PERFORMANCE TEST RESULTS\n")
	fmt.Printf("%s\n", separator)

	// Configuration summary
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Tenants: %d\n", r.Config.NumTenants)
	fmt.Printf("  Secrets per tenant: %d\n", r.Config.SecretsPerTenant)
	fmt.Printf("  Concurrent workers: %d\n", r.Config.ConcurrentTenants)
	fmt.Printf("  Storage backend: %s\n", r.Config.StorageBackend)
	fmt.Printf("  Total secrets: %d\n", r.AggregateMetrics.TotalSecrets)
	fmt.Printf("\n")

	// Timing summary
	fmt.Printf("Timing Summary:\n")
	fmt.Printf("  Setup time: %v\n", r.SetupDuration)
	fmt.Printf("  Total test time: %v\n", r.TotalDuration)
	fmt.Printf("\n")

	// Success metrics
	fmt.Printf("Success Metrics:\n")
	fmt.Printf("  Successful rotations: %d\n", r.AggregateMetrics.SuccessfulRotations)
	fmt.Printf("  Failed rotations: %d\n", r.AggregateMetrics.FailedRotations)
	fmt.Printf("  Success rate: %.2f%%\n", r.AggregateMetrics.SuccessRate)
	fmt.Printf("\n")

	// Performance metrics
	if r.AggregateMetrics.SuccessfulRotations > 0 {
		fmt.Printf("Performance Metrics:\n")
		fmt.Printf("  Min rotation time: %v\n", r.AggregateMetrics.MinRotationTime)
		fmt.Printf("  Avg rotation time: %v\n", r.AggregateMetrics.AvgRotationTime)
		fmt.Printf("  Median rotation time: %v\n", r.AggregateMetrics.MedianRotationTime)
		fmt.Printf("  95th percentile: %v\n", r.AggregateMetrics.P95RotationTime)
		fmt.Printf("  99th percentile: %v\n", r.AggregateMetrics.P99RotationTime)
		fmt.Printf("  Max rotation time: %v\n", r.AggregateMetrics.MaxRotationTime)
		fmt.Printf("\n")

		// Throughput metrics
		fmt.Printf("Throughput Metrics:\n")
		fmt.Printf("  Secrets/second: %.2f\n", r.AggregateMetrics.SecretsPerSecond)
		fmt.Printf("  Rotations/second: %.2f\n", r.AggregateMetrics.RotationsPerSecond)
		fmt.Printf("\n")
	}

	// Failed tenants (if any)
	if r.AggregateMetrics.FailedRotations > 0 {
		fmt.Printf("Failed Tenants:\n")
		for _, result := range r.PerTenantResults {
			if !result.Success {
				fmt.Printf("  %s: %s\n", result.TenantID, result.ErrorMessage)
			}
		}
		fmt.Printf("\n")
	}

	fmt.Printf("%s\n", separator)
}

func (ptr *PerformanceTestRunner) SaveResults(filename string) error {
	data, err := json.MarshalIndent(ptr.results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err = os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	return nil
}

func (ptr *PerformanceTestRunner) Cleanup() error {
	return ptr.factory.Cleanup()
}

// Helper function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	// Parse command line arguments or use defaults
	configFile := "perf_test_config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	// Load configuration
	config, err := LoadTestConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override config with environment variables if present
	if val := os.Getenv("PERF_TEST_TENANTS"); val != "" {
		if tenants, err := strconv.Atoi(val); err == nil {
			config.NumTenants = tenants
		}
	}
	if val := os.Getenv("PERF_TEST_SECRETS_PER_TENANT"); val != "" {
		if secrets, err := strconv.Atoi(val); err == nil {
			config.SecretsPerTenant = secrets
		}
	}
	if val := os.Getenv("PERF_TEST_CONCURRENT_TENANTS"); val != "" {
		if concurrent, err := strconv.Atoi(val); err == nil {
			config.ConcurrentTenants = concurrent
		}
	}
	if val := os.Getenv("PERF_TEST_STORAGE_BACKEND"); val != "" {
		config.StorageBackend = val
	}

	// Create and run the performance test
	runner, err := NewPerformanceTestRunner(config)
	if err != nil {
		log.Fatalf("Failed to create performance test runner: %v", err)
	}

	// Cleanup on exit
	defer func() {
		if err = runner.Cleanup(); err != nil {
			log.Printf("Cleanup failed: %v", err)
		}
	}()

	// Run the test
	if err := runner.Run(); err != nil {
		log.Fatalf("Performance test failed: %v", err)
	}

	// Print results
	runner.PrintResults()

	// Save results to file
	resultsFile := fmt.Sprintf("perf_test_results_%s.json", time.Now().Format("20060102_150405"))
	if err = runner.SaveResults(resultsFile); err != nil {
		log.Printf("Failed to save results to file: %v", err)
	} else {
		fmt.Printf("📄 Results saved to: %s\n", resultsFile)
	}

	fmt.Printf("🎉 Performance test completed successfully!\n")
}
