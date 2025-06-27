package config

import (
	"runtime"
	"time"

	"github.com/carbonetes/jacked/pkg/types"
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
func GetConfigForOptimizationLevel(level types.OptimizationLevel) types.AdvancedPerformanceConfig {
	config := types.GetAdvancedPerformanceConfig()

	switch level {
	case types.OptimizationBasic:
		// Conservative settings for basic optimization
		config.MaxConcurrentScanners = min(4, max(1, runtime.NumCPU()/4))
		config.EnableCaching = true
		config.EnableBatchProcessing = false
		config.EnableMemoryOptimization = false
		config.EnableProgressiveScanning = false

	case types.OptimizationBalanced:
		config.MaxConcurrentScanners = min(8, max(2, runtime.NumCPU()/2))
		config.EnableCaching = true
		config.EnableBatchProcessing = true
		config.EnableMemoryOptimization = true
		config.EnableProgressiveScanning = true

	case types.OptimizationAggressive:
		config.MaxConcurrentScanners = min(16, max(4, runtime.NumCPU()))
		config.ScanTimeout = 3 * time.Minute
		config.EnableCaching = true
		config.EnableBatchProcessing = true
		config.EnableMemoryOptimization = true
		config.EnableProgressiveScanning = true
		config.EnableAdaptiveConcurrency = true
		config.UseParallelVersionChecking = true

	case types.OptimizationMaximum:
		config.MaxConcurrentScanners = min(32, max(8, runtime.NumCPU()*2))
		config.ScanTimeout = 2 * time.Minute
		config.EnableCaching = true
		config.CacheTimeout = 30 * time.Minute
		config.EnableBatchProcessing = true
		config.BatchSize = 100
		config.EnableMemoryOptimization = true
		config.EnableProgressiveScanning = true
		config.EnableAdaptiveConcurrency = true
		config.EnableResourceMonitoring = true
		config.EnableExperimentalFeatures = true
		config.UseParallelVersionChecking = true
		config.EnablePredictiveCaching = true
	}

	return config
}

// ApplyPerformanceConfig applies performance configuration to the scanning system
func ApplyPerformanceConfig(config types.PerformanceConfig) {
	// This would be implemented to actually apply the configuration
	// to the various scanning components
}
