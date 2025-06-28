# KEK Rotation Performance Test

This performance test tool evaluates the speed and reliability of Key Encryption Key (KEK) rotation operations across
multiple tenants using the Volta secret management system.

## Overview

The performance test simulates real-world scenarios by:

- Creating multiple tenant vaults
- Populating each vault with secrets
- Performing concurrent KEK rotation operations
- Measuring throughput, latency, and success rates
- Generating comprehensive performance reports

## Prerequisites

- Go 1.19 or later
- Volta library dependencies
- Sufficient disk space for test vaults (default: `./test_vaults/`)

## Quick Start

1. **Run with default configuration:**
   ```bash
   go run kek_rotation_perf.go
   ```

2. **Run with custom configuration:**
   ```bash
   go run kek_rotation_perf.go my_config.json
   ```

3. **Run with environment variables:**
   ```bash
   PERF_TEST_TENANTS=20 PERF_TEST_SECRETS_PER_TENANT=500 go run kek_rotation_perf.go
   ```

## Configuration

### Configuration File

Create a JSON configuration file to customize test parameters:

```json
{
  "num_tenants": 10,
  "secrets_per_tenant": 100,
  "concurrent_tenants": 5,
  "storage_backend": "file",
  "storage_options": {
    "base_path": "./test_vaults"
  },
  "derivation_passphrase": "test-passphrase-for-performance-testing",
  "enable_memory_lock": false
}
```

### Configuration Parameters

| Parameter               | Type   | Default                          | Description                                            |
|-------------------------|--------|----------------------------------|--------------------------------------------------------|
| `num_tenants`           | int    | 10                               | Total number of tenant vaults to create                |
| `secrets_per_tenant`    | int    | 100                              | Number of secrets to store in each vault               |
| `concurrent_tenants`    | int    | 5                                | Number of tenants to rotate concurrently               |
| `storage_backend`       | string | "file"                           | Storage backend type (currently supports "file")       |
| `storage_options`       | object | `{"base_path": "./test_vaults"}` | Backend-specific configuration                         |
| `derivation_passphrase` | string | "test-passphrase..."             | Passphrase for key derivation                          |
| `enable_memory_lock`    | bool   | false                            | Whether to enable memory locking (requires privileges) |

### Environment Variables

The following environment variables override configuration parameters:

- `PERF_TEST_TENANTS` - Number of tenants
- `PERF_TEST_SECRETS_PER_TENANT` - Secrets per tenant
- `PERF_TEST_CONCURRENT_TENANTS` - Concurrent operations
- `PERF_TEST_STORAGE_BACKEND` - Storage backend type

## Test Scenarios

### Small Scale Test (Development)

```json
{
  "num_tenants": 5,
  "secrets_per_tenant": 50,
  "concurrent_tenants": 2
}
```

### Medium Scale Test (Staging)

```json
{
  "num_tenants": 50,
  "secrets_per_tenant": 1000,
  "concurrent_tenants": 10
}
```

### Large Scale Test (Production Simulation)

```json
{
  "num_tenants": 200,
  "secrets_per_tenant": 5000,
  "concurrent_tenants": 20
}
```

## Understanding Results

### Console Output

The test produces real-time progress updates and a comprehensive results summary:

```
🚀 Starting KEK Rotation Performance Test
Configuration: 10 tenants, 100 secrets each, 5 concurrent workers
⚙️  Setting up test environment...
Initializing file-based audit logger to: .volta_audit.log
✅ Setup completed in 10.64192025s
🔄 Executing KEK rotations...
Initializing file-based audit logger to: .volta_audit.log
Worker 0: ✅ Rotated KEK for tenant-0 (316.28925ms)
Worker 2: ✅ Rotated KEK for tenant-1 (442.159375ms)
Worker 1: ✅ Rotated KEK for tenant-2 (576.237375ms)
Worker 3: ✅ Rotated KEK for tenant-3 (717.118375ms)
Worker 4: ✅ Rotated KEK for tenant-4 (837.974583ms)
Worker 0: ✅ Rotated KEK for tenant-5 (631.690125ms)
Worker 2: ✅ Rotated KEK for tenant-6 (627.547375ms)
Worker 1: ✅ Rotated KEK for tenant-7 (624.099459ms)
Worker 3: ✅ Rotated KEK for tenant-8 (614.590834ms)
Worker 4: ✅ Rotated KEK for tenant-9 (577.312708ms)
✅ Test completed in 12.169892625s

================================================================================
📊 PERFORMANCE TEST RESULTS
================================================================================
Configuration:
  Tenants: 10
  Secrets per tenant: 100
  Concurrent workers: 5
  Storage backend: file
  Total secrets: 1000

Timing Summary:
  Setup time: 10.64192025s
  Total test time: 12.169892625s

Success Metrics:
  Successful rotations: 10
  Failed rotations: 0
  Success rate: 100.00%

Performance Metrics:
  Min rotation time: 316.28925ms
  Avg rotation time: 596.501945ms
  Median rotation time: 624.099459ms
  95th percentile: 837.974583ms
  99th percentile: 837.974583ms
  Max rotation time: 837.974583ms

Throughput Metrics:
  Secrets/second: 654.46
  Rotations/second: 6.54

================================================================================
📄 Results saved to: perf_test_results_20250628_104448.json
🎉 Performance test completed successfully!
```

### Results File

Results are automatically saved to a timestamped JSON file:

- Filename format: `perf_test_results_YYYYMMDD_HHMMSS.json`
- Contains detailed per-tenant metrics and aggregate statistics

### Key Metrics Explained

- **Setup Time**: Time to create all tenant vaults and populate with secrets
- **Total Test Time**: Complete end-to-end execution time
- **Success Rate**: Percentage of KEK rotations that completed without errors
- **Rotation Time**: Individual time measurements for each tenant's KEK rotation
- **Secrets per Second**: Throughput measure (total secrets ÷ total test time)
- **Rotations per Second**: Number of tenant KEK rotations per second
- **Percentiles**: Distribution of rotation times (P95, P99 show worst-case performance)

### Worker Output

During execution, you'll see real-time progress from each worker:

- `Worker N: ✅ Rotated KEK for tenant-X (time)` - Successful rotation
- `Worker N: ❌ Failed to rotate KEK for tenant-X (error)` - Failed rotation

## Files Created During Testing

The performance test creates the following files:

1. **Test vault directories**: `./test_vaults/tenant-N/` (automatically cleaned up)
2. **Results file**: `perf_test_results_YYYYMMDD_HHMMSS.json` (preserved)
3. **Audit log**: `.volta_audit.log` (created by Volta library)

## Troubleshooting

### Common Issues

1. **Permission Errors**:
   ```bash
   mkdir -p ./test_vaults
   chmod 755 ./test_vaults
   ```

2. **Disk Space Issues**:
   ```bash
   df -h ./test_vaults  # Check available space
   ```

3. **File Descriptor Limits** (if testing many concurrent tenants):
   ```bash
   ulimit -n 4096  # Increase open file limit
   ```

4. **Memory Lock Failures** (if `enable_memory_lock: true`):
   Set `"enable_memory_lock": false` in configuration file

### Manual Cleanup

Test data is automatically cleaned up, but you can manually remove:

```bash
rm -rf ./test_vaults/
rm -f perf_test_results_*.json
rm -f .volta_audit.log
```

### Parsing Results

Results JSON can be parsed for automated analysis:

```bash
# Extract metrics using jq (if available)
cat perf_test_results_*.json | grep -o '"success_rate":[0-9.]*' | cut -d: -f2
cat perf_test_results_*.json | grep -o '"avg_rotation_time":[0-9.]*' | cut -d: -f2
```
