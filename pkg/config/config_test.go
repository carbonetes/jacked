package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/carbonetes/jacked/pkg/types"
)

// TestLoadConfigFromPath tests loading configuration from a specific path
func TestLoadConfigFromPath(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-config.yaml")

	configContent := `version: "1.0"
performance:
  max_concurrent_scanners: 8
  scan_timeout: 300s
  enable_caching: true
  max_cache_size: 500
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Test loading the config
	err = LoadConfigFromPath(configPath)
	if err != nil {
		t.Fatalf("Failed to load config from path: %v", err)
	}

	// Verify the loaded configuration
	if Config.Performance.MaxConcurrentScanners != 8 {
		t.Errorf("Expected MaxConcurrentScanners to be 8, got %d", Config.Performance.MaxConcurrentScanners)
	}

	if Config.Performance.ScanTimeout != 300*time.Second {
		t.Errorf("Expected ScanTimeout to be 300s, got %v", Config.Performance.ScanTimeout)
	}

	if !Config.Performance.EnableCaching {
		t.Error("Expected caching to be enabled")
	}

	if Config.Performance.MaxCacheSize != 500 {
		t.Errorf("Expected MaxCacheSize to be 500, got %d", Config.Performance.MaxCacheSize)
	}
}

// TestLoadConfigFromInvalidPath tests loading configuration from an invalid path
func TestLoadConfigFromInvalidPath(t *testing.T) {
	invalidPath := "/non/existent/path/config.yaml"

	err := LoadConfigFromPath(invalidPath)
	if err == nil {
		t.Error("Expected error when loading from invalid path, got nil")
	}
}

// TestSetConfigPath tests setting and getting the config path
func TestSetConfigPath(t *testing.T) {
	originalPath := GetConfigPath()
	defer SetConfigPath(originalPath) // Restore original path

	testPath := "/test/path/config.yaml"
	SetConfigPath(testPath)

	if GetConfigPath() != testPath {
		t.Errorf("Expected config path to be %s, got %s", testPath, GetConfigPath())
	}
}

// TestReloadConfig tests reloading configuration
func TestReloadConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "reload-test.yaml")

	initialContent := `version: "1.0"
performance:
  max_concurrent_scanners: 4
  enable_caching: true
`

	err := os.WriteFile(configPath, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Set the config path and load initial config
	SetConfigPath(configPath)
	err = ReloadConfig()
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	// Verify initial config
	if Config.Performance.MaxConcurrentScanners != 4 {
		t.Errorf("Expected initial MaxConcurrentScanners to be 4, got %d", Config.Performance.MaxConcurrentScanners)
	}

	// Update the config file
	updatedContent := `version: "1.0"
performance:
  max_concurrent_scanners: 12
  enable_caching: false
`

	err = os.WriteFile(configPath, []byte(updatedContent), 0644)
	if err != nil {
		t.Fatalf("Failed to update test config file: %v", err)
	}

	// Reload and verify changes
	err = ReloadConfig()
	if err != nil {
		t.Fatalf("Failed to reload updated config: %v", err)
	}

	if Config.Performance.MaxConcurrentScanners != 12 {
		t.Errorf("Expected updated MaxConcurrentScanners to be 12, got %d", Config.Performance.MaxConcurrentScanners)
	}

	if Config.Performance.EnableCaching {
		t.Error("Expected caching to be disabled after reload")
	}
}

// TestDisplayConfig tests the display configuration function
func TestDisplayConfig(t *testing.T) {
	// Create a test configuration
	testConfig := types.Configuration{
		Version: "1.0",
		Performance: types.AdvancedPerformanceConfig{
			PerformanceConfig: types.PerformanceConfig{
				MaxConcurrentScanners: 8,
				ScanTimeout:           5 * time.Minute,
				EnableCaching:         true,
				MaxCacheSize:          1000,
			},
		},
	}

	// Set the global config
	originalConfig := Config
	Config = testConfig
	defer func() { Config = originalConfig }()

	// This test mainly verifies that DisplayConfig doesn't panic
	// In a real test environment, you might want to capture output
	DisplayConfig()
}

// TestGetConfigForOptimizationLevel tests getting configuration for different optimization levels
func TestGetConfigForOptimizationLevel(t *testing.T) {
	tests := []struct {
		level    types.OptimizationLevel
		expected string
	}{
		{types.OptimizationBasic, "basic"},
		{types.OptimizationBalanced, "balanced"},
		{types.OptimizationAggressive, "aggressive"},
		{types.OptimizationMaximum, "maximum"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			config := GetConfigForOptimizationLevel(tt.level)

			// Verify basic properties based on optimization level
			switch tt.level {
			case types.OptimizationBasic:
				if config.MaxConcurrentScanners > 4 {
					t.Errorf("Expected basic optimization to have low concurrency, got %d", config.MaxConcurrentScanners)
				}
			case types.OptimizationMaximum:
				if !config.EnableExperimentalFeatures {
					t.Error("Expected maximum optimization to enable experimental features")
				}
			}
		})
	}
}

// TestInvalidConfigYAML tests handling of invalid YAML configuration
func TestInvalidConfigYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid-config.yaml")

	invalidContent := `version: "1.0"
performance:
  max_concurrent_scanners: invalid_number
  scan_timeout: not_a_duration
`

	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid config file: %v", err)
	}

	err = LoadConfigFromPath(configPath)
	if err == nil {
		t.Error("Expected error when loading invalid YAML, got nil")
	}
}

// TestDefaultConfigGeneration tests that default configuration is properly generated
func TestDefaultConfigGeneration(t *testing.T) {
	// This test verifies that when no config file exists, defaults are used
	nonExistentPath := "/tmp/non-existent-config.yaml"

	// Try to load from non-existent path - should use defaults
	originalConfig := Config
	defer func() { Config = originalConfig }()

	// Clear config first
	Config = types.Configuration{}

	// Loading from non-existent path should still initialize with defaults
	LoadConfigFromPath(nonExistentPath)

	// Even if loading fails, the default config should be available through GetConfigForOptimizationLevel
	defaultConfig := GetConfigForOptimizationLevel(types.OptimizationBalanced)

	if defaultConfig.MaxConcurrentScanners <= 0 {
		t.Error("Expected default config to have positive MaxConcurrentScanners")
	}

	if defaultConfig.ScanTimeout <= 0 {
		t.Error("Expected default config to have positive ScanTimeout")
	}
}

// TestConfigPathHandling tests various config path scenarios
func TestConfigPathHandling(t *testing.T) {
	originalPath := GetConfigPath()
	defer SetConfigPath(originalPath)

	tests := []struct {
		name        string
		configPath  string
		expectError bool
	}{
		{
			name:        "empty_path",
			configPath:  "",
			expectError: true,
		},
		{
			name:        "relative_path",
			configPath:  "./test-config.yaml",
			expectError: false, // Relative paths should work if parent dir exists
		},
		{
			name:        "absolute_path_nonexistent",
			configPath:  "/absolute/path/to/config.yaml",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global config state for each test
			originalConfig := Config
			defer func() { Config = originalConfig }()

			SetConfigPath(tt.configPath)
			err := ReloadConfig()

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// BenchmarkLoadConfig benchmarks config loading performance
func BenchmarkLoadConfig(b *testing.B) {
	tempDir := b.TempDir()
	configPath := filepath.Join(tempDir, "bench-config.yaml")

	configContent := `version: "1.0"
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
    maven:
      enabled: true
      timeout: 180s
      max_concurrency: 8
      caching_enabled: true
      priority: 7
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		b.Fatalf("Failed to create benchmark config file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LoadConfigFromPath(configPath)
	}
}

// BenchmarkGetConfigForOptimizationLevel benchmarks optimization level config generation
func BenchmarkGetConfigForOptimizationLevel(b *testing.B) {
	levels := []types.OptimizationLevel{
		types.OptimizationBasic,
		types.OptimizationBalanced,
		types.OptimizationAggressive,
		types.OptimizationMaximum,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		level := levels[i%len(levels)]
		_ = GetConfigForOptimizationLevel(level)
	}
}
