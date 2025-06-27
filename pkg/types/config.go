package types

import (
	"fmt"
	"runtime"
	"strings"
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

// Validate validates the entire configuration
func (c *Configuration) Validate() error {
	var sb strings.Builder

	if c.Version == "" {
		sb.WriteString("version must be specified\n")
	}

	if c.MaxFileSize <= 0 {
		sb.WriteString("maxFileSize must be greater than 0\n")
	}

	if err := c.Registry.Validate(); err != nil {
		sb.WriteString(fmt.Sprintf("registry: %v\n", err))
	}

	if err := c.Performance.Validate(); err != nil {
		sb.WriteString(fmt.Sprintf("performance: %v\n", err))
	}

	if sb.Len() > 0 {
		return fmt.Errorf("configuration validation failed:\n%s", sb.String())
	}

	return nil
}

// Validate validates the registry configuration
func (r *Registry) Validate() error {
	var sb strings.Builder

	if r.Username == "" {
		sb.WriteString("username must be specified\n")
	}

	if r.Password == "" {
		sb.WriteString("password must be specified\n")
	}

	if sb.Len() > 0 {
		return fmt.Errorf("registry validation failed:\n%s", sb.String())
	}

	return nil
}

// Validate validates the CI configuration
func (ci *CIConfiguration) Validate() error {
	var sb strings.Builder

	// Add validation for CI configuration as needed

	if sb.Len() > 0 {
		return fmt.Errorf("CI configuration validation failed:\n%s", sb.String())
	}

	return nil
}

// Validate validates the fail criteria
func (fc *FailCriteria) Validate() error {
	var sb strings.Builder

	if len(fc.Vulnerabilities) == 0 {
		sb.WriteString("at least one vulnerability ID must be specified\n")
	}

	if fc.Severity == "" {
		sb.WriteString("severity must be specified\n")
	}

	if sb.Len() > 0 {
		return fmt.Errorf("fail criteria validation failed:\n%s", sb.String())
	}

	return nil
}

// ValidatePerformanceConfig validates and fixes performance configuration values
func ValidatePerformanceConfig(config PerformanceConfig) PerformanceConfig {
	// Fix invalid MaxConcurrentScanners
	if config.MaxConcurrentScanners <= 0 {
		config.MaxConcurrentScanners = 1
	}

	// Fix invalid ScanTimeout
	if config.ScanTimeout <= 0 {
		config.ScanTimeout = 5 * time.Minute
	}

	// Fix invalid BatchSize
	if config.BatchSize <= 0 {
		config.BatchSize = 10
	}

	// Fix invalid cache settings
	if config.MaxCacheSize <= 0 {
		config.MaxCacheSize = 100
	}

	if config.CacheTimeout <= 0 {
		config.CacheTimeout = 15 * time.Minute
	}

	// Fix invalid database settings
	if config.MaxDBConnections <= 0 {
		config.MaxDBConnections = runtime.NumCPU() * 2
	}

	if config.MaxIdleConnections <= 0 {
		config.MaxIdleConnections = runtime.NumCPU()
	}

	if config.ConnectionTimeout <= 0 {
		config.ConnectionTimeout = 30 * time.Second
	}

	// Fix invalid memory settings
	if config.MaxMemoryUsage <= 0 {
		config.MaxMemoryUsage = 512
	}

	// Fix invalid thresholds
	if config.ComponentThresholds.Small <= 0 {
		config.ComponentThresholds.Small = 50
	}
	if config.ComponentThresholds.Medium <= 0 {
		config.ComponentThresholds.Medium = 200
	}
	if config.ComponentThresholds.Large <= 0 {
		config.ComponentThresholds.Large = 500
	}

	if config.MetricsRetention <= 0 {
		config.MetricsRetention = 24 * time.Hour
	}

	return config
}

// GetOptimizationLevelConfig returns configuration for a specific optimization level
func GetOptimizationLevelConfig(level OptimizationLevel) AdvancedPerformanceConfig {
	base := GetDefaultPerformanceConfig()

	// Advanced config specific settings
	var enableExperimental, enableAdaptive, enablePredictive bool

	switch level {
	case OptimizationBasic:
		// Minimal resource usage
		base.MaxConcurrentScanners = max(1, runtime.NumCPU()/2)
		base.ScanTimeout = 8 * time.Minute
		base.MaxDBConnections = runtime.NumCPU()
		base.BatchSize = 25
		enableExperimental = false
		enableAdaptive = false
		enablePredictive = false

	case OptimizationBalanced:
		// Default balanced settings (already set in GetDefaultPerformanceConfig)
		enableExperimental = false
		enableAdaptive = true
		enablePredictive = false

	case OptimizationAggressive:
		// Higher performance
		base.MaxConcurrentScanners = runtime.NumCPU() * 2
		base.ScanTimeout = 3 * time.Minute
		base.MaxDBConnections = runtime.NumCPU() * 4
		base.BatchSize = 100
		enableExperimental = false
		enableAdaptive = true
		enablePredictive = false

	case OptimizationMaximum:
		// Maximum performance with experimental features
		base.MaxConcurrentScanners = runtime.NumCPU() * 3
		base.ScanTimeout = 2 * time.Minute
		base.MaxDBConnections = runtime.NumCPU() * 6
		base.BatchSize = 200
		enableExperimental = true
		enableAdaptive = true
		enablePredictive = true
	}

	return AdvancedPerformanceConfig{
		PerformanceConfig: base,
		Scanners: map[string]ScannerSpecificConfig{
			"npm": {
				Enabled:        true,
				Timeout:        2 * time.Minute,
				MaxConcurrency: base.MaxConcurrentScanners,
				CachingEnabled: true,
				Priority:       8,
			},
			"maven": {
				Enabled:        true,
				Timeout:        3 * time.Minute,
				MaxConcurrency: base.MaxConcurrentScanners,
				CachingEnabled: true,
				Priority:       7,
			},
			"dpkg": {
				Enabled:        true,
				Timeout:        2 * time.Minute,
				MaxConcurrency: base.MaxConcurrentScanners,
				CachingEnabled: true,
				Priority:       9,
			},
			"apk": {
				Enabled:        true,
				Timeout:        2 * time.Minute,
				MaxConcurrency: base.MaxConcurrentScanners,
				CachingEnabled: true,
				Priority:       9,
			},
			"generic": {
				Enabled:        true,
				Timeout:        4 * time.Minute,
				MaxConcurrency: max(1, base.MaxConcurrentScanners/2),
				CachingEnabled: true,
				Priority:       5,
			},
		},
		EnableSmartDeduplication:     true,
		DeduplicationAccuracyLevel:   3,
		EnableAdaptiveConcurrency:    enableAdaptive,
		AdaptiveConcurrencyThreshold: 0.8,
		EnableResourceMonitoring:     true,
		CPUThreshold:                 85.0,
		MemoryThreshold:              80.0,
		EnableExperimentalFeatures:   enableExperimental,
		UseParallelVersionChecking:   true,
		EnablePredictiveCaching:      enablePredictive,
	}
}

// ParseOptimizationLevel parses a string into an OptimizationLevel
func ParseOptimizationLevel(level string) (OptimizationLevel, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "basic":
		return OptimizationBasic, nil
	case "balanced":
		return OptimizationBalanced, nil
	case "aggressive":
		return OptimizationAggressive, nil
	case "maximum":
		return OptimizationMaximum, nil
	default:
		return OptimizationBalanced, fmt.Errorf("invalid optimization level: %s", level)
	}
}

// max returns the maximum of two integers (helper function for older Go versions)
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
