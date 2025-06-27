package types

import (
	"runtime"
	"testing"
	"time"
)

// TestGetDefaultPerformanceConfig tests the default performance configuration
func TestGetDefaultPerformanceConfig(t *testing.T) {
	config := GetDefaultPerformanceConfig()

	t.Run("ConcurrencySettings", func(t *testing.T) {
		testDefaultConcurrencySettings(t, config)
	})

	t.Run("CacheSettings", func(t *testing.T) {
		testDefaultCacheSettings(t, config)
	})

	t.Run("DatabaseSettings", func(t *testing.T) {
		testDefaultDatabaseSettings(t, config)
	})

	t.Run("BatchProcessingSettings", func(t *testing.T) {
		testDefaultBatchProcessingSettings(t, config)
	})

	t.Run("MemoryManagementSettings", func(t *testing.T) {
		testDefaultMemoryManagementSettings(t, config)
	})

	t.Run("ProgressiveScanningSettings", func(t *testing.T) {
		testDefaultProgressiveScanningSettings(t, config)
	})

	t.Run("MetricsSettings", func(t *testing.T) {
		testDefaultMetricsSettings(t, config)
	})
}

func testDefaultConcurrencySettings(t *testing.T, config PerformanceConfig) {
	if config.MaxConcurrentScanners != runtime.NumCPU() {
		t.Errorf("Expected MaxConcurrentScanners to be %d, got %d", runtime.NumCPU(), config.MaxConcurrentScanners)
	}

	if config.ScanTimeout != 5*time.Minute {
		t.Errorf("Expected ScanTimeout to be %v, got %v", 5*time.Minute, config.ScanTimeout)
	}
}

func testDefaultCacheSettings(t *testing.T, config PerformanceConfig) {
	if !config.EnableCaching {
		t.Error("Expected caching to be enabled by default")
	}

	if config.CacheTimeout != 15*time.Minute {
		t.Errorf("Expected CacheTimeout to be %v, got %v", 15*time.Minute, config.CacheTimeout)
	}

	if config.MaxCacheSize != 1000 {
		t.Errorf("Expected MaxCacheSize to be 1000, got %d", config.MaxCacheSize)
	}
}

func testDefaultDatabaseSettings(t *testing.T, config PerformanceConfig) {
	if config.MaxDBConnections != 2*runtime.NumCPU() {
		t.Errorf("Expected MaxDBConnections to be %d, got %d", 2*runtime.NumCPU(), config.MaxDBConnections)
	}

	if config.MaxIdleConnections != runtime.NumCPU() {
		t.Errorf("Expected MaxIdleConnections to be %d, got %d", runtime.NumCPU(), config.MaxIdleConnections)
	}

	if config.ConnectionTimeout != 30*time.Second {
		t.Errorf("Expected ConnectionTimeout to be %v, got %v", 30*time.Second, config.ConnectionTimeout)
	}
}

func testDefaultBatchProcessingSettings(t *testing.T, config PerformanceConfig) {
	if config.BatchSize != 50 {
		t.Errorf("Expected BatchSize to be 50, got %d", config.BatchSize)
	}

	if !config.EnableBatchProcessing {
		t.Error("Expected batch processing to be enabled by default")
	}
}

func testDefaultMemoryManagementSettings(t *testing.T, config PerformanceConfig) {
	if !config.EnableMemoryOptimization {
		t.Error("Expected memory optimization to be enabled by default")
	}

	if config.MaxMemoryUsage != 512 {
		t.Errorf("Expected MaxMemoryUsage to be 512, got %d", config.MaxMemoryUsage)
	}
}

func testDefaultProgressiveScanningSettings(t *testing.T, config PerformanceConfig) {
	if !config.EnableProgressiveScanning {
		t.Error("Expected progressive scanning to be enabled by default")
	}

	if config.ComponentThresholds.Small != 50 {
		t.Errorf("Expected Small threshold to be 50, got %d", config.ComponentThresholds.Small)
	}

	if config.ComponentThresholds.Medium != 200 {
		t.Errorf("Expected Medium threshold to be 200, got %d", config.ComponentThresholds.Medium)
	}

	if config.ComponentThresholds.Large != 500 {
		t.Errorf("Expected Large threshold to be 500, got %d", config.ComponentThresholds.Large)
	}
}

func testDefaultMetricsSettings(t *testing.T, config PerformanceConfig) {
	if !config.EnableMetrics {
		t.Error("Expected metrics to be enabled by default")
	}

	if config.MetricsRetention != 24*time.Hour {
		t.Errorf("Expected MetricsRetention to be %v, got %v", 24*time.Hour, config.MetricsRetention)
	}
}

// TestGetAdvancedPerformanceConfig tests the advanced performance configuration
func TestGetAdvancedPerformanceConfig(t *testing.T) {
	config := GetAdvancedPerformanceConfig()

	t.Run("BaseConfiguration", func(t *testing.T) {
		testAdvancedBaseConfiguration(t, config)
	})

	t.Run("ScannerConfigurations", func(t *testing.T) {
		testAdvancedScannerConfigurations(t, config)
	})

	t.Run("AdvancedFeatures", func(t *testing.T) {
		testAdvancedFeatures(t, config)
	})

	t.Run("ResourceMonitoring", func(t *testing.T) {
		testAdvancedResourceMonitoring(t, config)
	})

	t.Run("ExperimentalFeatures", func(t *testing.T) {
		testAdvancedExperimentalFeatures(t, config)
	})
}

func testAdvancedBaseConfiguration(t *testing.T, config AdvancedPerformanceConfig) {
	if config.MaxConcurrentScanners != runtime.NumCPU() {
		t.Errorf("Expected MaxConcurrentScanners to be %d, got %d", runtime.NumCPU(), config.MaxConcurrentScanners)
	}
}

func testAdvancedScannerConfigurations(t *testing.T, config AdvancedPerformanceConfig) {
	expectedScanners := []string{"npm", "maven", "dpkg", "apk", "generic"}
	for _, scanner := range expectedScanners {
		t.Run(scanner, func(t *testing.T) {
			testScannerConfig(t, config, scanner)
		})
	}
}

func testScannerConfig(t *testing.T, config AdvancedPerformanceConfig, scannerName string) {
	scannerConfig, exists := config.Scanners[scannerName]
	if !exists {
		t.Errorf("Expected scanner %s to be configured", scannerName)
		return
	}

	if !scannerConfig.Enabled {
		t.Errorf("Expected scanner %s to be enabled", scannerName)
	}

	// Different scanners have different concurrency expectations
	expectedConcurrency := runtime.NumCPU()
	if scannerName == "generic" {
		expectedConcurrency = runtime.NumCPU() / 2
	}

	if scannerConfig.MaxConcurrency != expectedConcurrency {
		t.Errorf("Expected scanner %s MaxConcurrency to be %d, got %d", scannerName, expectedConcurrency, scannerConfig.MaxConcurrency)
	}

	if !scannerConfig.CachingEnabled {
		t.Errorf("Expected scanner %s to have caching enabled", scannerName)
	}

	if scannerConfig.Priority < 1 || scannerConfig.Priority > 10 {
		t.Errorf("Expected scanner %s priority to be between 1-10, got %d", scannerName, scannerConfig.Priority)
	}

	// Test specific scanner timeouts and priorities
	switch scannerName {
	case "npm":
		if scannerConfig.Timeout != 2*time.Minute {
			t.Errorf("Expected npm timeout to be %v, got %v", 2*time.Minute, scannerConfig.Timeout)
		}
		if scannerConfig.Priority != 8 {
			t.Errorf("Expected npm priority to be 8, got %d", scannerConfig.Priority)
		}
	case "maven":
		if scannerConfig.Timeout != 3*time.Minute {
			t.Errorf("Expected maven timeout to be %v, got %v", 3*time.Minute, scannerConfig.Timeout)
		}
		if scannerConfig.Priority != 7 {
			t.Errorf("Expected maven priority to be 7, got %d", scannerConfig.Priority)
		}
	}
}

func testAdvancedFeatures(t *testing.T, config AdvancedPerformanceConfig) {
	if !config.EnableSmartDeduplication {
		t.Error("Expected smart deduplication to be enabled by default")
	}

	if config.DeduplicationAccuracyLevel != 3 {
		t.Errorf("Expected deduplication accuracy level to be 3, got %d", config.DeduplicationAccuracyLevel)
	}

	if !config.EnableAdaptiveConcurrency {
		t.Error("Expected adaptive concurrency to be enabled by default")
	}

	if config.AdaptiveConcurrencyThreshold != 0.8 {
		t.Errorf("Expected adaptive concurrency threshold to be 0.8, got %f", config.AdaptiveConcurrencyThreshold)
	}
}

func testAdvancedResourceMonitoring(t *testing.T, config AdvancedPerformanceConfig) {
	if !config.EnableResourceMonitoring {
		t.Error("Expected resource monitoring to be enabled by default")
	}

	if config.CPUThreshold != 85.0 {
		t.Errorf("Expected CPU threshold to be 85.0, got %f", config.CPUThreshold)
	}

	if config.MemoryThreshold != 80.0 {
		t.Errorf("Expected memory threshold to be 80.0, got %f", config.MemoryThreshold)
	}
}

func testAdvancedExperimentalFeatures(t *testing.T, config AdvancedPerformanceConfig) {
	if config.EnableExperimentalFeatures {
		t.Error("Expected experimental features to be disabled by default")
	}

	if !config.UseParallelVersionChecking {
		t.Error("Expected parallel version checking to be enabled by default")
	}

	if config.EnablePredictiveCaching {
		t.Error("Expected predictive caching to be disabled by default")
	}
}

// TestValidatePerformanceConfig tests the validation logic for performance configuration
func TestValidatePerformanceConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   PerformanceConfig
		expected PerformanceConfig
		wantErr  bool
	}{
		{
			name: "valid config",
			config: PerformanceConfig{
				MaxConcurrentScanners: 4,
				ScanTimeout:           2 * time.Minute,
				EnableCaching:         true,
				MaxCacheSize:          500,
				BatchSize:             25,
			},
			expected: PerformanceConfig{
				MaxConcurrentScanners: 4,
				ScanTimeout:           2 * time.Minute,
				EnableCaching:         true,
				MaxCacheSize:          500,
				BatchSize:             25,
			},
			wantErr: false,
		},
		{
			name: "zero concurrency gets default",
			config: PerformanceConfig{
				MaxConcurrentScanners: 0,
				ScanTimeout:           2 * time.Minute,
			},
			expected: PerformanceConfig{
				MaxConcurrentScanners: 1,
				ScanTimeout:           2 * time.Minute,
				BatchSize:             10,
			},
			wantErr: false,
		},
		{
			name: "negative concurrency gets default",
			config: PerformanceConfig{
				MaxConcurrentScanners: -5,
				ScanTimeout:           2 * time.Minute,
			},
			expected: PerformanceConfig{
				MaxConcurrentScanners: 1,
				ScanTimeout:           2 * time.Minute,
				BatchSize:             10,
			},
			wantErr: false,
		},
		{
			name: "zero timeout gets default",
			config: PerformanceConfig{
				MaxConcurrentScanners: 4,
				ScanTimeout:           0,
			},
			expected: PerformanceConfig{
				MaxConcurrentScanners: 4,
				ScanTimeout:           5 * time.Minute,
				BatchSize:             10,
			},
			wantErr: false,
		},
		{
			name: "zero batch size gets default",
			config: PerformanceConfig{
				MaxConcurrentScanners: 4,
				ScanTimeout:           2 * time.Minute,
				BatchSize:             0,
			},
			expected: PerformanceConfig{
				MaxConcurrentScanners: 4,
				ScanTimeout:           2 * time.Minute,
				BatchSize:             10,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePerformanceConfig(tt.config)

			if result.MaxConcurrentScanners != tt.expected.MaxConcurrentScanners {
				t.Errorf("Expected MaxConcurrentScanners %d, got %d", tt.expected.MaxConcurrentScanners, result.MaxConcurrentScanners)
			}

			if result.ScanTimeout != tt.expected.ScanTimeout {
				t.Errorf("Expected ScanTimeout %v, got %v", tt.expected.ScanTimeout, result.ScanTimeout)
			}

			if result.BatchSize != tt.expected.BatchSize {
				t.Errorf("Expected BatchSize %d, got %d", tt.expected.BatchSize, result.BatchSize)
			}
		})
	}
}

// TestGetOptimizationLevelConfig tests different optimization level configurations
func TestGetOptimizationLevelConfig(t *testing.T) {
	testCases := []struct {
		level                     OptimizationLevel
		expectedConcurrencyFactor float64
		expectedTimeout           time.Duration
	}{
		{OptimizationBasic, 0.5, 8 * time.Minute},
		{OptimizationBalanced, 1.0, 5 * time.Minute},
		{OptimizationAggressive, 2.0, 3 * time.Minute},
		{OptimizationMaximum, 3.0, 2 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.level.String(), func(t *testing.T) {
			testOptimizationLevel(t, tc.level, tc.expectedConcurrencyFactor, tc.expectedTimeout)
		})
	}
}

func testOptimizationLevel(t *testing.T, level OptimizationLevel, expectedConcurrencyFactor float64, expectedTimeout time.Duration) {
	config := GetOptimizationLevelConfig(level)
	baseCPU := runtime.NumCPU()

	expectedConcurrency := int(float64(baseCPU) * expectedConcurrencyFactor)
	if expectedConcurrency < 1 {
		expectedConcurrency = 1
	}

	if config.MaxConcurrentScanners != expectedConcurrency {
		t.Errorf("Expected MaxConcurrentScanners %d, got %d", expectedConcurrency, config.MaxConcurrentScanners)
	}

	if config.ScanTimeout != expectedTimeout {
		t.Errorf("Expected ScanTimeout %v, got %v", expectedTimeout, config.ScanTimeout)
	}

	// Test that experimental features are only enabled for maximum level
	if level == OptimizationMaximum && !config.EnableExperimentalFeatures {
		t.Error("Expected experimental features to be enabled for maximum optimization")
	} else if level != OptimizationMaximum && config.EnableExperimentalFeatures {
		t.Error("Expected experimental features to be disabled for non-maximum optimization")
	}
}

// TestOptimizationLevelString tests the string representation of optimization levels
func TestOptimizationLevelString(t *testing.T) {
	tests := []struct {
		level    OptimizationLevel
		expected string
	}{
		{OptimizationBasic, "basic"},
		{OptimizationBalanced, "balanced"},
		{OptimizationAggressive, "aggressive"},
		{OptimizationMaximum, "maximum"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, got)
			}
		})
	}
}

// TestParseOptimizationLevel tests parsing optimization levels from strings
func TestParseOptimizationLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected OptimizationLevel
		wantErr  bool
	}{
		{"basic", OptimizationBasic, false},
		{"balanced", OptimizationBalanced, false},
		{"aggressive", OptimizationAggressive, false},
		{"maximum", OptimizationMaximum, false},
		{"BASIC", OptimizationBasic, false},       // Case insensitive
		{"Balanced", OptimizationBalanced, false}, // Case insensitive
		{"invalid", OptimizationBalanced, true},   // Should return balanced on error
		{"", OptimizationBalanced, true},          // Should return balanced on empty
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseOptimizationLevel(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOptimizationLevel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}
		})
	}
}

// BenchmarkGetDefaultPerformanceConfig benchmarks the default config creation
func BenchmarkGetDefaultPerformanceConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetDefaultPerformanceConfig()
	}
}

// BenchmarkGetAdvancedPerformanceConfig benchmarks the advanced config creation
func BenchmarkGetAdvancedPerformanceConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetAdvancedPerformanceConfig()
	}
}

// BenchmarkValidatePerformanceConfig benchmarks config validation
func BenchmarkValidatePerformanceConfig(b *testing.B) {
	config := GetDefaultPerformanceConfig()
	config.MaxConcurrentScanners = 0 // Force validation

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidatePerformanceConfig(config)
	}
}
