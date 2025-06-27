# Testing Guide for Jacked Performance Configuration System

This document describes the comprehensive testing strategy and available test suites for the Jacked performance configuration system.

## Overview

The testing framework covers:
- Unit tests for all performance configuration components
- Integration tests for CLI functionality
- Performance benchmarks
- Configuration validation
- Cross-platform compatibility
- Automated CI/CD testing

## Quick Start

### Running All Tests

```bash
# Using the test script
chmod +x run-tests.sh
./run-tests.sh

# Using Make
make test

# Using Go directly
go test ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/
```

### Running Specific Test Categories

```bash
# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Performance tests with real scanning
make test-performance

# Benchmarks
make bench

# Code coverage
make coverage
```

## Test Structure

### 1. Unit Tests

#### Types Package (`pkg/types/config_test.go`)
- **TestGetDefaultPerformanceConfig**: Validates default configuration values
- **TestGetAdvancedPerformanceConfig**: Tests advanced configuration generation
- **TestValidatePerformanceConfig**: Ensures configuration validation works correctly
- **TestGetOptimizationLevelConfig**: Tests different optimization level configurations
- **TestParseOptimizationLevel**: Validates optimization level parsing from strings
- **TestOptimizationLevelString**: Tests string representation of optimization levels

#### Config Package (`pkg/config/config_test.go`)
- **TestLoadConfigFromPath**: Tests loading configuration from specific file paths
- **TestSetConfigPath**: Validates configuration path management
- **TestReloadConfig**: Tests configuration reloading functionality
- **TestInvalidConfigYAML**: Ensures graceful handling of invalid YAML
- **TestDefaultConfigGeneration**: Verifies default configuration generation
- **TestGetConfigForOptimizationLevel**: Tests optimization level configuration retrieval

#### Command Package (`cmd/jacked/command/command_test.go`)
- **TestRootCommandFlags**: Validates CLI flag handling
- **TestPerformanceLevelValidation**: Tests performance level validation
- **TestConfigPathHandling**: Validates configuration path handling in CLI
- **TestNonInteractiveMode**: Tests non-interactive mode functionality
- **TestOptimizeCommandFlags**: Validates optimize command flags
- **TestConfigurationIntegration**: Tests integration between CLI flags and configuration

#### Table Package (`internal/tea/table/table_test.go`)
- **TestCreateTableWithNoVulnerabilities**: Tests table creation with empty data
- **TestCreateTableWithVulnerabilities**: Tests table creation with vulnerability data
- **TestCreateTableWithComplexVersions**: Tests handling of complex version formats
- **TestNonInteractiveMode**: Tests non-interactive table functionality
- **TestTableSorting**: Validates vulnerability sorting

### 2. Integration Tests

Integration tests verify that different components work together correctly:

```bash
# CLI functionality
./jacked --help
./jacked version
./jacked --performance=basic --help
./jacked --performance=balanced --help
./jacked --performance=aggressive --help
./jacked --performance=maximum --help

# Configuration file handling
./jacked --config=/path/to/config.yaml --help

# Non-interactive mode
./jacked --non-interactive --help

# Optimize command
./jacked analyze-optimized --help
```

### 3. Performance Benchmarks

Benchmarks measure the performance of key operations:

```bash
# Run all benchmarks
go test -bench=. ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/

# Specific benchmarks
go test -bench=BenchmarkGetDefaultPerformanceConfig ./pkg/types/
go test -bench=BenchmarkGetConfigForOptimizationLevel ./pkg/config/
```

#### Available Benchmarks
- `BenchmarkGetDefaultPerformanceConfig`: Configuration creation performance
- `BenchmarkGetAdvancedPerformanceConfig`: Advanced configuration creation
- `BenchmarkValidatePerformanceConfig`: Configuration validation performance
- `BenchmarkLoadConfig`: Configuration file loading performance
- `BenchmarkCreateTable`: Table creation performance

### 4. Configuration Testing

The test suite includes comprehensive configuration validation:

#### Valid Configuration Examples
```yaml
version: "1.0"
performance:
  max_concurrent_scanners: 8
  scan_timeout: 300s
  enable_caching: true
  max_cache_size: 1000
  scanners:
    npm:
      enabled: true
      timeout: 120s
      max_concurrency: 8
      caching_enabled: true
      priority: 8
```

#### Invalid Configuration Handling
- Invalid data types (string instead of number)
- Invalid duration formats
- Missing required fields
- Malformed YAML syntax

### 5. Cross-Platform Testing

Tests run on:
- Linux (Ubuntu latest)
- Windows (Windows latest)
- macOS (macOS latest)

Go versions tested:
- Go 1.21
- Go 1.22
- Go 1.23

## Test Execution

### Local Development

```bash
# Quick pre-commit validation
make pre-commit

# Full validation pipeline
make validate

# Performance regression testing
make perf-regression

# Configuration validation
make test-config
```

### Continuous Integration

The project includes GitHub Actions workflows for automated testing:

- **performance-tests.yml**: Comprehensive test pipeline
- Runs on push/PR to main/develop branches
- Tests across multiple Go versions and platforms
- Includes integration tests with real Docker images
- Generates code coverage reports

### Test Scripts

#### `run-tests.sh`
Comprehensive test script that runs:
- All unit tests
- Integration tests
- Benchmarks
- Code quality checks
- Configuration validation
- CLI functionality tests

```bash
chmod +x run-tests.sh
./run-tests.sh
```

#### `test-performance.sh`
Performance testing script for actual scanning:
- Tests all optimization levels
- Uses real Docker images
- Measures scan performance
- Validates non-interactive mode

```bash
chmod +x test-performance.sh
./test-performance.sh
```

## Code Coverage

Generate and view code coverage reports:

```bash
# Generate coverage report
make coverage

# View in browser
open coverage.html

# Command line summary
go tool cover -func=coverage.out
```

Target coverage: 80%+ for all packages

## Test Data and Fixtures

### Mock Data
Tests use mock CycloneDX BOMs and vulnerability data:
- Empty BOMs (no vulnerabilities)
- BOMs with various vulnerability types
- Complex version formats
- Different severity levels

### Configuration Fixtures
- Valid configuration files
- Invalid configuration files
- Minimal configurations
- Complete configurations with all options

## Debugging Tests

### Running Individual Tests
```bash
# Run specific test
go test -v ./pkg/types/ -run TestGetDefaultPerformanceConfig

# Run with detailed output
go test -v -race ./pkg/config/

# Run with debugging
go test -v ./cmd/jacked/command/ -run TestRootCommandFlags
```

### Test Debugging Tips
1. Use `t.Logf()` for debug output
2. Run tests with `-v` flag for verbose output
3. Use `-race` flag to detect race conditions
4. Check test files for detailed error messages

## Performance Testing Guidelines

### Benchmark Writing
```go
func BenchmarkYourFunction(b *testing.B) {
    for i := 0; i < b.N; i++ {
        // Your code here
    }
}
```

### Performance Targets
- Configuration creation: < 1ms
- Configuration validation: < 100μs
- Table creation (100 vulns): < 10ms
- CLI flag parsing: < 1ms

## Common Issues and Solutions

### Test Failures

#### "Command execution failed"
- Ensure jacked binary is built: `make build`
- Check Go version compatibility
- Verify all dependencies are available

#### "Config file not found"
- Check test creates temporary files correctly
- Verify file permissions
- Ensure cleanup after tests

#### "Race condition detected"
- Review concurrent access to shared variables
- Add proper synchronization
- Check global variable usage

### CI/CD Issues

#### Tests fail on specific platforms
- Check platform-specific code paths
- Verify file path handling (Windows vs Unix)
- Review environment variable usage

#### Timeout in integration tests
- Reduce test complexity
- Add timeouts to prevent hanging
- Use non-interactive mode for CLI tests

## Contributing Test Cases

When adding new features:

1. **Write tests first** (TDD approach)
2. **Include unit tests** for all new functions
3. **Add integration tests** for CLI changes
4. **Include benchmarks** for performance-critical code
5. **Test error cases** and edge conditions
6. **Update documentation** with new test procedures

### Test Naming Conventions
- `TestFunctionName` for unit tests
- `TestFunctionName_ErrorCase` for error scenarios
- `BenchmarkFunctionName` for benchmarks
- `TestIntegration_FeatureName` for integration tests

## Security Testing

While not implemented yet, consider adding:
- Configuration injection tests
- Path traversal tests
- Input validation tests
- Permission tests

## Future Enhancements

Planned testing improvements:
- Fuzzing tests for configuration parsing
- Load testing for high-volume scenarios
- Memory leak detection
- Performance regression detection
- Automated security scanning

## Test Metrics

The test suite should maintain:
- **Code coverage**: 80%+
- **Test execution time**: < 30 seconds
- **Benchmark variance**: < 10%
- **Platform compatibility**: 100% across supported platforms

## Support

For testing-related questions:
- Check existing test cases for examples
- Review this documentation
- Ask in project discussions
- Create issues for test failures

Remember: Good tests are the foundation of reliable software! 🧪✅
