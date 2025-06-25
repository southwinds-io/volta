package persist

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	testAccessKey = "minioadmin"
	testSecretKey = "minioadmin"
)

func TestS3Store(t *testing.T) {
	endpoint := os.Getenv("S3_MINIO_ENDPOINT")
	if len(endpoint) == 0 {
		// Use testcontainers for more reliable container management
		ctx := context.Background()

		req := testcontainers.ContainerRequest{
			Image:        "minio/minio:latest",
			ExposedPorts: []string{"9000/tcp"},
			Env: map[string]string{
				"MINIO_ROOT_USER":     testAccessKey,
				"MINIO_ROOT_PASSWORD": testSecretKey,
			},
			Cmd:        []string{"server", "/data"},
			WaitingFor: wait.ForHTTP("/minio/health/live").WithPort("9000/tcp"),
		}

		minioContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			t.Fatalf("Failed to start MinIO container: %v", err)
		}

		defer func() {
			if err = minioContainer.Terminate(ctx); err != nil {
				t.Logf("Warning: Failed to terminate MinIO container: %v", err)
			}
		}()

		// Get the mapped port
		mappedPort, err := minioContainer.MappedPort(ctx, "9000")
		if err != nil {
			t.Fatalf("Failed to get mapped port: %v", err)
		}

		// Set environment for the test
		os.Setenv("S3_MINIO_ENDPOINT", fmt.Sprintf("http://localhost:%s", mappedPort.Port()))
	}

	t.Run("runS3StoreTest", func(t *testing.T) {
		runS3StoreTest(t)
	})
}

func runS3StoreTest(t *testing.T) {
	// Get configuration from environment or use defaults for testcontainers
	bucketName := os.Getenv("S3_BUCKET")
	if bucketName == "" {
		bucketName = "test-volta-store"
	}

	accessKeyID := os.Getenv("S3_MINIO_ACCESS_KEY_ID")
	if accessKeyID == "" {
		accessKeyID = "minioadmin" // Default testcontainer credentials
	}

	secretAccessKey := os.Getenv("S3_MINIO_SECRET_ACCESS_KEY")
	if secretAccessKey == "" {
		secretAccessKey = "minioadmin" // Default testcontainer credentials
	}

	// Use the endpoint set by testcontainers or fallback to environment/default
	endpointURL := os.Getenv("S3_MINIO_ENDPOINT")
	if endpointURL == "" {
		t.Fatal("S3_MINIO_ENDPOINT not set - this should be configured by the testcontainer setup")
	}

	// Extract host:port from full URL for MinIO client
	endpoint, useSSL := parseEndpoint(endpointURL)

	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1" // Default region for MinIO
	}

	keyPrefix := os.Getenv("S3_KEY_PREFIX")
	if keyPrefix == "" {
		keyPrefix = "test/" // Use a test prefix to isolate test data
	}

	// Override SSL setting from environment if provided
	if sslEnv := os.Getenv("S3_MINIO_USE_SSL"); sslEnv != "" {
		useSSL = parseBool(sslEnv)
	}

	t.Logf("Configuring S3Store with endpoint: %s, bucketName: %s, useSSL: %v", endpoint, bucketName, useSSL)

	// Use the cleaned endpoint (host:port only) for S3Store
	store, err := NewS3Store(S3Config{
		Endpoint:        endpoint, // Use cleaned endpoint (host:port only)
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Bucket:          bucketName,
		KeyPrefix:       keyPrefix,
		UseSSL:          useSSL,
		Region:          region,
	}, testTenant)

	if err != nil {
		t.Fatalf("Failed to create S3Store: %v", err)
	}

	// Clean up after test - remove objects but not the bucketName (container will be destroyed)
	defer func() {
		if err = cleanupS3Objects(bucketName, endpoint, accessKeyID, secretAccessKey, useSSL); err != nil {
			t.Logf("Warning: Failed to cleanup S3 objects: %v", err)
		}
	}()

	testStoreImplementation(t, store)
}

// parseEndpoint extracts host:port from full URL and determines SSL usage
func parseEndpoint(endpointURL string) (string, bool) {
	// Remove protocol if present
	endpoint := strings.TrimPrefix(endpointURL, "http://")
	useSSL := false

	if strings.HasPrefix(endpointURL, "https://") {
		endpoint = strings.TrimPrefix(endpointURL, "https://")
		useSSL = true
	}

	// Remove any trailing path
	if idx := strings.Index(endpoint, "/"); idx != -1 {
		endpoint = endpoint[:idx]
	}

	return endpoint, useSSL
}

// cleanupS3Objects removes all objects from the bucketName using the helper function
func cleanupS3Objects(bucketName, endpoint, accessKeyID, secretAccessKey string, useSSL bool) error {
	// Use the helper function to create MinIO client
	minioClient, err := createMinioClient(endpoint, accessKeyID, secretAccessKey, useSSL)
	if err != nil {
		return fmt.Errorf("failed to create MinIO client: %v", err)
	}

	ctx := context.Background()

	// List and delete all objects
	objectCh := minioClient.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Recursive: true,
	})

	var deleteErrors []string
	for object := range objectCh {
		if object.Err != nil {
			deleteErrors = append(deleteErrors, fmt.Sprintf("error listing object: %v", object.Err))
			continue
		}

		err = minioClient.RemoveObject(ctx, bucketName, object.Key, minio.RemoveObjectOptions{})
		if err != nil {
			deleteErrors = append(deleteErrors, fmt.Sprintf("failed to delete object %s: %v", object.Key, err))
		}
	}

	if len(deleteErrors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(deleteErrors, "; "))
	}

	return nil
}

// Helper function to create MinIO client with consistent configuration
// Now actually used by cleanupS3Objects()
func createMinioClient(endpoint, accessKeyID, secretAccessKey string, useSSL bool) (*minio.Client, error) {
	return minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
}

// Updated parseBool function
func parseBool(value string) bool {
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}
