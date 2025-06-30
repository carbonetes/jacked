package config

import (
	"runtime"
)

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GetConfigForOptimizationLevel returns configuration optimized for the specified level
func GetConfigForOptimizationLevel(level OptimizationLevel) PerformanceConfig {
	config := GetAdvancedPerformanceConfig()

	switch level {
	case OptimizationBasic:
		// Conservative settings for basic optimization
		config.MaxConcurrentScanners = min(4, max(1, runtime.NumCPU()/4))
		config.EnableCaching = true
		config.EnableBatchProcessing = false

	case OptimizationBalanced:
		config.MaxConcurrentScanners = min(8, max(2, runtime.NumCPU()/2))
		config.EnableCaching = true
		config.EnableBatchProcessing = true

	case OptimizationAggressive:
		config.MaxConcurrentScanners = min(16, max(4, runtime.NumCPU()))
		config.EnableCaching = true
		config.EnableBatchProcessing = true

	case OptimizationMaximum:
		config.MaxConcurrentScanners = min(32, max(8, runtime.NumCPU()*2))
		config.EnableCaching = true
		config.EnableBatchProcessing = true
		config.EnableExperimentalFeatures = true
	}

	return config
}

// ApplyPerformanceConfig applies performance configuration to the scanning system
func ApplyPerformanceConfig(config PerformanceConfig) {
	// This would be implemented to actually apply the configuration
	// to the various scanning components
}
