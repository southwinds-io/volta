package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testDir string

func TestFileSystemStore(t *testing.T) {
	t.Run("runFileSystemStoreTest", func(t *testing.T) {
		runFileSystemStoreTest(t)
	})
}

func runFileSystemStoreTest(t *testing.T) {
	// Get configuration from environment or use defaults
	baseDir := os.Getenv("FS_BASE_DIR")
	if baseDir == "" {
		// Create a temporary directory for testing
		tempDir, err := os.MkdirTemp("", "volta-fs-test-*")
		if err != nil {
			t.Fatalf("Failed to create temporary directory: %v", err)
		}
		baseDir = tempDir
	}

	// Ensure we have a clean test directory
	testDir = filepath.Join(baseDir, "test-run")
	if err := os.RemoveAll(testDir); err != nil {
		t.Logf("Warning: Failed to clean test directory: %v", err)
	}

	t.Logf("Configuring FileSystemStore with baseDir: %s", testDir)

	// Create the FileSystemStore
	store, err := NewFileSystemStore(testDir, testTenant)
	if err != nil {
		t.Fatalf("Failed to create FileSystemStore: %v", err)
	}

	// Clean up after test - remove the test directory
	defer func() {
		if err = cleanupFileSystemStore(testDir); err != nil {
			t.Logf("Warning: Failed to cleanup filesystem store: %v", err)
		}
	}()

	// Run the generic store tests
	testStoreImplementation(t, store)
}

// cleanupFileSystemStore removes the test directory and all its contents
func cleanupFileSystemStore(testDir string) error {
	if testDir == "" || testDir == "/" {
		return nil // Safety check - don't delete root or empty path
	}

	// Only clean up if it's a test directory
	if !filepath.IsAbs(testDir) {
		return nil
	}

	// Additional safety - ensure it contains "test" in the path
	if !containsTestIndicator(testDir) {
		return nil
	}

	return os.RemoveAll(testDir)
}

// containsTestIndicator checks if the path contains indicators that it's a test directory
func containsTestIndicator(path string) bool {
	lowercasePath := filepath.ToSlash(path)
	indicators := []string{"test", "tmp", "temp"}

	for _, indicator := range indicators {
		if filepath.Base(lowercasePath) == indicator ||
			filepath.Base(filepath.Dir(lowercasePath)) == indicator ||
			strings.Contains(lowercasePath, "/"+indicator+"/") ||
			strings.Contains(lowercasePath, "/"+indicator+"-") {
			return true
		}
	}
	return false
}
