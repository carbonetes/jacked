package types

import (
	"runtime"
	"time"
)

const ConfigVersion string = "1.0"

// Performance configuration types
type PerformanceConfig struct {
	// Scanner concurrency settings
	MaxConcurrentScanners int           `yaml:"max_concurrent_scanners"`
	ScanTimeout           time.Duration `yaml:"scan_timeout"`

	// Cache settings
	EnableCaching bool          `yaml:"enable_caching"`
	CacheTimeout  time.Duration `yaml:"cache_timeout"`
	MaxCacheSize  int           `yaml:"max_cache_size"`

	// Database connection settings
	MaxDBConnections   int           `yaml:"max_db_connections"`
	MaxIdleConnections int           `yaml:"max_idle_connections"`
	ConnectionTimeout  time.Duration `yaml:"connection_timeout"`

	// Batch processing settings
	BatchSize             int  `yaml:"batch_size"`
	EnableBatchProcessing bool `yaml:"enable_batch_processing"`

	// Memory management
	EnableMemoryOptimization bool  `yaml:"enable_memory_optimization"`
	MaxMemoryUsage           int64 `yaml:"max_memory_usage_mb"`

	// Progressive scanning
	EnableProgressiveScanning bool                `yaml:"enable_progressive_scanning"`
	ComponentThresholds       ComponentThresholds `yaml:"component_thresholds"`

	// Metrics and monitoring
	EnableMetrics    bool          `yaml:"enable_metrics"`
	MetricsRetention time.Duration `yaml:"metrics_retention"`
}

// ComponentThresholds defines thresholds for different optimization levels
type ComponentThresholds struct {
	Small  int `yaml:"small"`  // Components count for small BOMs
	Medium int `yaml:"medium"` // Components count for medium BOMs
	Large  int `yaml:"large"`  // Components count for large BOMs
}

// ScannerSpecificConfig holds configuration for individual scanners
type ScannerSpecificConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Timeout        time.Duration `yaml:"timeout"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	CachingEnabled bool          `yaml:"caching_enabled"`
	Priority       int           `yaml:"priority"` // 1-10, higher is higher priority
}

// AdvancedPerformanceConfig extends PerformanceConfig with advanced settings
type AdvancedPerformanceConfig struct {
	PerformanceConfig `yaml:",inline"`

	// Scanner-specific settings
	Scanners map[string]ScannerSpecificConfig `yaml:"scanners"`

	// Advanced optimization features
	EnableSmartDeduplication     bool    `yaml:"enable_smart_deduplication"`
	DeduplicationAccuracyLevel   int     `yaml:"deduplication_accuracy_level"` // 1-5
	EnableAdaptiveConcurrency    bool    `yaml:"enable_adaptive_concurrency"`
	AdaptiveConcurrencyThreshold float64 `yaml:"adaptive_concurrency_threshold"`

	// Resource monitoring
	EnableResourceMonitoring bool    `yaml:"enable_resource_monitoring"`
	CPUThreshold             float64 `yaml:"cpu_threshold"`
	MemoryThreshold          float64 `yaml:"memory_threshold"`

	// Experimental features
	EnableExperimentalFeatures bool `yaml:"enable_experimental_features"`
	UseParallelVersionChecking bool `yaml:"use_parallel_version_checking"`
	EnablePredictiveCaching    bool `yaml:"enable_predictive_caching"`
}

// OptimizationLevel represents different levels of optimization
type OptimizationLevel int

const (
	OptimizationBasic OptimizationLevel = iota
	OptimizationBalanced
	OptimizationAggressive
	OptimizationMaximum
)

// GetDefaultPerformanceConfig returns a performance configuration with sensible defaults
func GetDefaultPerformanceConfig() PerformanceConfig {
	return PerformanceConfig{
		MaxConcurrentScanners: runtime.NumCPU(),
		ScanTimeout:           5 * time.Minute,

		EnableCaching: true,
		CacheTimeout:  15 * time.Minute,
		MaxCacheSize:  1000,

		MaxDBConnections:   runtime.NumCPU() * 2,
		MaxIdleConnections: runtime.NumCPU(),
		ConnectionTimeout:  30 * time.Second,

		BatchSize:             50,
		EnableBatchProcessing: true,

		EnableMemoryOptimization: true,
		MaxMemoryUsage:           512, // 512 MB

		EnableProgressiveScanning: true,
		ComponentThresholds: ComponentThresholds{
			Small:  50,
			Medium: 200,
			Large:  500,
		},

		EnableMetrics:    true,
		MetricsRetention: 24 * time.Hour,
	}
}

// GetAdvancedPerformanceConfig returns advanced configuration with experimental features
func GetAdvancedPerformanceConfig() AdvancedPerformanceConfig {
	base := GetDefaultPerformanceConfig()

	return AdvancedPerformanceConfig{
		PerformanceConfig: base,

		Scanners: map[string]ScannerSpecificConfig{
			"npm": {
				Enabled:        true,
				Timeout:        2 * time.Minute,
				MaxConcurrency: runtime.NumCPU(),
				CachingEnabled: true,
				Priority:       8,
			},
			"maven": {
				Enabled:        true,
				Timeout:        3 * time.Minute,
				MaxConcurrency: runtime.NumCPU(),
				CachingEnabled: true,
				Priority:       7,
			},
			"dpkg": {
				Enabled:        true,
				Timeout:        2 * time.Minute,
				MaxConcurrency: runtime.NumCPU(),
				CachingEnabled: true,
				Priority:       9,
			},
			"apk": {
				Enabled:        true,
				Timeout:        2 * time.Minute,
				MaxConcurrency: runtime.NumCPU(),
				CachingEnabled: true,
				Priority:       9,
			},
			"generic": {
				Enabled:        true,
				Timeout:        4 * time.Minute,
				MaxConcurrency: runtime.NumCPU() / 2,
				CachingEnabled: true,
				Priority:       5,
			},
		},

		EnableSmartDeduplication:     true,
		DeduplicationAccuracyLevel:   3,
		EnableAdaptiveConcurrency:    true,
		AdaptiveConcurrencyThreshold: 0.8,

		EnableResourceMonitoring: true,
		CPUThreshold:             85.0,
		MemoryThreshold:          80.0,

		EnableExperimentalFeatures: false,
		UseParallelVersionChecking: true,
		EnablePredictiveCaching:    false,
	}
}

// ValidateConfig validates the performance configuration
func (c *PerformanceConfig) Validate() error {
	if c.MaxConcurrentScanners <= 0 {
		c.MaxConcurrentScanners = runtime.NumCPU()
	}

	if c.ScanTimeout <= 0 {
		c.ScanTimeout = 5 * time.Minute
	}

	if c.CacheTimeout <= 0 {
		c.CacheTimeout = 15 * time.Minute
	}

	if c.MaxDBConnections <= 0 {
		c.MaxDBConnections = runtime.NumCPU() * 2
	}

	if c.BatchSize <= 0 {
		c.BatchSize = 50
	}

	return nil
}

// String returns a string representation of the optimization level
func (level OptimizationLevel) String() string {
	switch level {
	case OptimizationBasic:
		return "basic"
	case OptimizationBalanced:
		return "balanced"
	case OptimizationAggressive:
		return "aggressive"
	case OptimizationMaximum:
		return "maximum"
	default:
		return "unknown"
	}
}

type Configuration struct {
	Version     string                    `yaml:"version"`
	MaxFileSize int64                     `yaml:"maxFileSize"`
	Registry    Registry                  `yaml:"registry"`
	CI          CIConfiguration           `yaml:"ci"`
	Performance AdvancedPerformanceConfig `yaml:"performance"`
}

type Registry struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type CIConfiguration struct {
	FailCriteria FailCriteria `yaml:"failCriteria"`
}

// TODO: Add more logic to handle multiple fail criteria
type FailCriteria struct {
	// TODO: Add logic to handle multiple vulnerability id as fail criteria
	Vulnerabilities []string `yaml:"vulnerability"`

	Severity string `yaml:"severity"`
}
