package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"gopkg.in/yaml.v2"
)

const (
	DefaultConfigFilename = ".jacked.yaml"
	ErrorGeneratingConfig = "Error generating default config file: "
)

// Configuration is the unified configuration structure for all Jacked settings
type Configuration struct {
	// Legacy field for backward compatibility
	MaxFileSize int `yaml:"maxFileSize,omitempty"`

	// Performance configuration - the main configuration used by the app
	Performance PerformanceConfig `yaml:"performance"`

	// CI configuration for CI/CD pipeline integration
	CI CIConfiguration `yaml:"ci,omitempty"`
}

// PerformanceConfig controls performance optimization settings
type PerformanceConfig struct {
	// Legacy fields that are actually used in the codebase
	MaxConcurrentScanners int           `yaml:"max_concurrent_scanners"`
	ScanTimeout           time.Duration `yaml:"scan_timeout,omitempty"`
	EnableCaching         bool          `yaml:"enable_caching"`
	CacheTimeout          time.Duration `yaml:"cache_timeout"`
	MaxCacheSize          int           `yaml:"max_cache_size"`
	MaxDBConnections      int           `yaml:"max_db_connections"`
	MaxIdleConnections    int           `yaml:"max_idle_connections"`
	ConnectionTimeout     time.Duration `yaml:"connection_timeout"`
	BatchSize             int           `yaml:"batch_size"`
	EnableBatchProcessing bool          `yaml:"enable_batch_processing"`

	// Experimental features for backward compatibility
	EnableExperimentalFeatures bool                             `yaml:"enable_experimental_features,omitempty"`
	Scanners                   map[string]ScannerSpecificConfig `yaml:"scanners,omitempty"`
}

// ScannerSpecificConfig for backward compatibility
type ScannerSpecificConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Timeout        time.Duration `yaml:"timeout"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	CachingEnabled bool          `yaml:"caching_enabled"`
	Priority       int           `yaml:"priority"`
}

// CIConfiguration for CI/CD integration
type CIConfiguration struct {
	FailCriteria FailCriteria `yaml:"fail_criteria,omitempty"`
}

// FailCriteria defines when CI should fail
type FailCriteria struct {
	Severity string `yaml:"severity,omitempty"` // "low", "medium", "high", "critical"
}

// OptimizationLevel for backward compatibility
type OptimizationLevel int

const (
	OptimizationBasic OptimizationLevel = iota
	OptimizationBalanced
	OptimizationAggressive
	OptimizationMaximum
)

// String returns string representation of optimization level
func (o OptimizationLevel) String() string {
	switch o {
	case OptimizationBasic:
		return "basic"
	case OptimizationBalanced:
		return "balanced"
	case OptimizationAggressive:
		return "aggressive"
	case OptimizationMaximum:
		return "maximum"
	default:
		return "balanced"
	}
}

// ParseOptimizationLevel parses optimization level from string
func ParseOptimizationLevel(s string) (OptimizationLevel, error) {
	switch s {
	case "basic":
		return OptimizationBasic, nil
	case "balanced":
		return OptimizationBalanced, nil
	case "aggressive":
		return OptimizationAggressive, nil
	case "maximum":
		return OptimizationMaximum, nil
	default:
		return OptimizationBalanced, fmt.Errorf("unknown optimization level: %s", s)
	}
}

var Config Configuration

var path string = os.Getenv("JACKED_CONFIG")

// isValidParentDir checks if the parent directory of a path exists and is writable
func isValidParentDir(filePath string) bool {
	if filePath == "" {
		return false
	}

	dir := filepath.Dir(filePath)
	if dir == "." || dir == "/" {
		return true // Current dir or root are typically valid
	}

	// Check if parent directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}

	return info.IsDir()
}

// SetConfigPath allows setting a custom configuration file path
func SetConfigPath(customPath string) {
	path = customPath
	os.Setenv("JACKED_CONFIG", path)
}

func ReloadConfig() error {
	// Validate path is not empty
	if path == "" {
		return fmt.Errorf("config path is empty")
	}

	log.Debug(fmt.Sprintf("ReloadConfig: checking path '%s'", path))
	exist, err := helper.IsFileExists(path)
	if err != nil {
		log.Debug("Error checking if config file exists: ", err)
		return err
	}

	log.Debug(fmt.Sprintf("ReloadConfig: path '%s' exists=%v", path, exist))
	if !exist {
		// Check if parent directory exists for the path
		if !isValidParentDir(path) {
			return fmt.Errorf("invalid config path (parent directory does not exist): %s", path)
		}

		// Create the config file with detailed comments and documentation
		err = GenerateDefaultConfigFile(path)
		if err != nil {
			log.Debug(ErrorGeneratingConfig, err)
			// Fallback to simple config creation
			MakeConfigFile(path)
		}
	}

	// Load the config file
	var config Configuration
	err = ReadConfigFile(&config, path)
	if err != nil {
		log.Debug("Error reading config file in ReloadConfig: ", err)
		return err
	}

	Config = config
	return nil
}

func init() {
	// Load config from file
	if path == "" {
		// Set the default path
		home, _ := os.UserHomeDir()
		defaultPath := home + string(os.PathSeparator) + DefaultConfigFilename
		path = defaultPath
		os.Setenv("JACKED_CONFIG", path)
	}

	exist, err := helper.IsFileExists(path)
	if err != nil {
		log.Debug("Error checking if config file exists: ", err)
	}

	if !exist {
		// Create the config file with detailed comments and documentation
		err = GenerateDefaultConfigFile(path)
		if err != nil {
			log.Debug(ErrorGeneratingConfig, err)
			// Fallback to simple config creation
			MakeConfigFile(path)
		}
	}

	// Load the config file
	var config Configuration
	err = ReadConfigFile(&config, path)
	if err != nil {
		log.Debug("Error reading config file in init: ", err)
		// In init, we can't return error, so fall back to defaults
		Config = New()
		return
	}

	Config = config

}

// GetConfigPath returns the current configuration file path
func GetConfigPath() string {
	return path
}

// DisplayConfig prints the current configuration for debugging
func DisplayConfig() {
	log.Debugf("Current config path: %s", path)
	log.Debugf("Max concurrent scanners: %d", Config.Performance.MaxConcurrentScanners)
	log.Debugf("Max file size: %d", Config.MaxFileSize)
	log.Debugf("Cache enabled: %v", Config.Performance.EnableCaching)
}

// New creates a new configuration with default values
func New() Configuration {
	return GetDefaultConfiguration()
}

// MakeConfigFile creates a new configuration file with default values
func MakeConfigFile(path string) {
	// Create the config file
	cfg := New()

	// Write the config file
	err := helper.WriteYAML(cfg, path)
	if err != nil {
		log.Debug("Error writing config file: ", err)
	}
}

func ReadConfigFile(config *Configuration, path string) error {
	configFile, err := os.ReadFile(path)
	if err != nil {
		log.Debug(err)
		return err
	}

	err = yaml.Unmarshal(configFile, config)
	if err != nil {
		log.Debug(err)
		return err
	}

	// Validate and fill missing fields
	if ValidateAndFillConfig(config) {
		log.Debug("Config file has missing fields, regenerating with complete configuration...")

		// Regenerate the config file with all fields and comments
		err = GenerateDefaultConfigFile(path)
		if err != nil {
			log.Debug(ErrorGeneratingConfig, err)
			// Continue with the filled config even if file regeneration fails
		} else {
			log.Debug("Config file regenerated successfully with complete configuration")
		}
	}

	return nil
}

func ReplaceConfigFile(config Configuration, path string) {
	exist, err := helper.IsFileExists(path)
	if err != nil {
		log.Debug(err)
	}

	if exist {
		err = os.Remove(path)
		if err != nil {
			log.Debug(err)
		}
	}

	// Use GenerateDefaultConfigFile for better documented output
	err = GenerateDefaultConfigFile(path)
	if err != nil {
		log.Debug(ErrorGeneratingConfig, err)
		// Fallback to simple YAML generation
		err = helper.WriteYAML(config, path)
		if err != nil {
			log.Debug(err)
		}
	}
}

// LoadConfigFromPath loads configuration from a specific file path
func LoadConfigFromPath(configPath string) error {
	exist, err := helper.IsFileExists(configPath)
	if err != nil {
		return err
	}

	if !exist {
		return os.ErrNotExist
	}

	var config Configuration
	err = ReadConfigFile(&config, configPath)
	if err != nil {
		return err
	}

	Config = config
	return nil
}

// InitializeConfig handles all configuration setup
func InitializeConfig(configFile, performance string, performanceChanged bool) *Configuration {
	// Handle custom config file path
	if configFile != "" {
		log.Debugf("Using custom config file: %s", configFile)
		SetConfigPath(configFile)
		// Reload config from the custom path
		if err := ReloadConfig(); err != nil {
			log.Warnf("Failed to reload config: %v", err)
		}
	}

	// Handle performance optimization level (only if explicitly set)
	if performanceChanged {
		ApplyPerformanceLevel(performance)
	}

	return &Config
}

// ApplyPerformanceLevel sets the performance configuration based on the specified level
func ApplyPerformanceLevel(performance string) {
	var level OptimizationLevel
	switch performance {
	case "basic":
		level = OptimizationBasic
	case "balanced":
		level = OptimizationBalanced
	case "aggressive":
		level = OptimizationAggressive
	case "maximum":
		level = OptimizationMaximum
	default:
		log.Warnf("Invalid performance level '%s', using balanced", performance)
		level = OptimizationBalanced
	}

	Config.Performance = GetConfigForOptimizationLevel(level)
	log.Debugf("Performance optimization level set to: %s", performance)
}

// SetupFailCriteria configures the fail criteria for CI mode
func SetupFailCriteria(failCriteria string) {
	if len(failCriteria) > 0 {
		failCriteria = strings.ToLower(failCriteria)
		Config.CI.FailCriteria.Severity = failCriteria
	}
}

// GetDefaultConfiguration returns a Configuration with sensible defaults
func GetDefaultConfiguration() Configuration {
	return Configuration{
		MaxFileSize: 52428800, // Legacy field: 50MB
		Performance: PerformanceConfig{
			MaxConcurrentScanners: runtime.NumCPU(),
			EnableCaching:         true,
			CacheTimeout:          1 * time.Hour,
			MaxCacheSize:          1000,
			MaxDBConnections:      10,
			MaxIdleConnections:    5,
			ConnectionTimeout:     30 * time.Second,
			BatchSize:             100,
			EnableBatchProcessing: true,
		},
		CI: CIConfiguration{
			FailCriteria: FailCriteria{
				Severity: "high", // Default to failing on high severity
			},
		},
	}
}

// GenerateDefaultConfigFile creates a minimal configuration file with only implemented features
func GenerateDefaultConfigFile(filePath string) error {
	config := GetDefaultConfiguration()

	// Generate YAML with only the fields that are actually used
	yamlContent := fmt.Sprintf(`# Jacked Vulnerability Scanner Configuration
# This is a minimal configuration with only implemented features
# 
# For documentation, visit: https://github.com/carbonetes/jacked

# Legacy field for backward compatibility (file size limit in bytes)
maxFileSize: %d

# Performance Configuration
# Controls scanning performance and resource usage
performance:
  # Number of concurrent scanners (default: number of CPU cores)
  max_concurrent_scanners: %d
  
  # Enable result caching to speed up repeated scans
  enable_caching: %t
  
  # Cache expiration time
  cache_timeout: "%s"
  
  # Maximum number of cached items
  max_cache_size: %d
  
  # Database connection settings
  max_db_connections: %d
  max_idle_connections: %d
  connection_timeout: "%s"
  
  # Batch processing settings
  batch_size: %d
  enable_batch_processing: %t

# CI/CD Integration Configuration
ci:
  # Criteria for failing CI builds
  fail_criteria:
    # Fail if vulnerabilities of this severity or higher are found
    # Options: "low", "medium", "high", "critical"
    severity: "%s"

# Note: This configuration only includes fields that are actually implemented
# in the codebase. Many advanced features shown in documentation may not
# yet be fully implemented.
`,
		config.MaxFileSize,
		config.Performance.MaxConcurrentScanners, config.Performance.EnableCaching,
		config.Performance.CacheTimeout, config.Performance.MaxCacheSize,
		config.Performance.MaxDBConnections, config.Performance.MaxIdleConnections,
		config.Performance.ConnectionTimeout, config.Performance.BatchSize,
		config.Performance.EnableBatchProcessing, config.CI.FailCriteria.Severity)

	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write file
	if err := os.WriteFile(filePath, []byte(yamlContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", filePath, err)
	}

	return nil
}

// Legacy function aliases for backward compatibility

// GetDefaultScannerConfig returns the default configuration (alias for GetDefaultConfiguration)
func GetDefaultScannerConfig() Configuration {
	return GetDefaultConfiguration()
}

// GetAdvancedPerformanceConfig returns the performance section of the default configuration
func GetAdvancedPerformanceConfig() PerformanceConfig {
	return GetDefaultConfiguration().Performance
}

// Legacy type aliases for backward compatibility
type AdvancedPerformanceConfig = PerformanceConfig
type LegacyPerformanceConfig = PerformanceConfig

// ValidateAndFillConfig validates the configuration and fills missing fields with defaults
func ValidateAndFillConfig(config *Configuration) bool {
	hasChanges := false
	defaultConfig := GetDefaultConfiguration()

	// Check and fill missing Performance fields
	if config.Performance.MaxConcurrentScanners == 0 {
		config.Performance.MaxConcurrentScanners = defaultConfig.Performance.MaxConcurrentScanners
		hasChanges = true
	}

	if config.Performance.CacheTimeout == 0 {
		config.Performance.CacheTimeout = defaultConfig.Performance.CacheTimeout
		hasChanges = true
	}

	if config.Performance.MaxCacheSize == 0 {
		config.Performance.MaxCacheSize = defaultConfig.Performance.MaxCacheSize
		hasChanges = true
	}

	if config.Performance.MaxDBConnections == 0 {
		config.Performance.MaxDBConnections = defaultConfig.Performance.MaxDBConnections
		hasChanges = true
	}

	if config.Performance.MaxIdleConnections == 0 {
		config.Performance.MaxIdleConnections = defaultConfig.Performance.MaxIdleConnections
		hasChanges = true
	}

	if config.Performance.ConnectionTimeout == 0 {
		config.Performance.ConnectionTimeout = defaultConfig.Performance.ConnectionTimeout
		hasChanges = true
	}

	if config.Performance.BatchSize == 0 {
		config.Performance.BatchSize = defaultConfig.Performance.BatchSize
		hasChanges = true
	}

	// Check and fill missing MaxFileSize
	if config.MaxFileSize == 0 {
		config.MaxFileSize = defaultConfig.MaxFileSize
		hasChanges = true
	}

	// Check and fill missing CI configuration
	if config.CI.FailCriteria.Severity == "" {
		config.CI.FailCriteria.Severity = defaultConfig.CI.FailCriteria.Severity
		hasChanges = true
	}

	return hasChanges
}
