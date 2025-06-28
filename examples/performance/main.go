package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

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
	if err = runner.Run(); err != nil {
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
