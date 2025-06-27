package command

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/metrics"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/spf13/cobra"
)

var (
	optimizationLevel string
	enableMetrics     bool
	showMetrics       bool
	enableProfiling   bool
	configFile        string
	maxConcurrency    int
	scanTimeout       time.Duration
	enableCaching     bool
)

// optimizeCmd represents the optimize command for performance tuning
var optimizeCmd = &cobra.Command{
	Use:   "analyze-optimized",
	Short: "Run optimized vulnerability scanning with performance enhancements",
	Long: `Run vulnerability scanning with advanced performance optimizations.

This command provides several optimization levels:
- basic: Safe optimizations with minimal resource usage
- balanced: Good balance between speed and resource usage (default)
- aggressive: Maximum performance with higher resource usage
- maximum: Experimental optimizations for maximum speed

Examples:
  jacked analyze-optimized --optimization=balanced myimage:tag
  jacked analyze-optimized --optimization=aggressive --max-concurrency=8 myimage:tag
  jacked analyze-optimized --show-metrics --enable-metrics myimage:tag`,
	Args: cobra.MinimumNArgs(1),
	Run:  runOptimizedAnalysis,
}

func init() {
	root.AddCommand(optimizeCmd)

	optimizeCmd.Flags().StringVar(&optimizationLevel, "optimization", "balanced",
		"Optimization level: basic, balanced, aggressive, maximum")
	optimizeCmd.Flags().BoolVar(&enableMetrics, "enable-metrics", true,
		"Enable performance metrics collection")
	optimizeCmd.Flags().BoolVar(&showMetrics, "show-metrics", false,
		"Show performance metrics after scan")
	optimizeCmd.Flags().BoolVar(&enableProfiling, "enable-profiling", false,
		"Enable CPU and memory profiling")
	optimizeCmd.Flags().StringVar(&configFile, "performance-config", "",
		"Path to performance configuration file")
	optimizeCmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 0,
		"Maximum number of concurrent scanners (0 = auto)")
	optimizeCmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 0,
		"Maximum time for scanning operations (0 = default)")
	optimizeCmd.Flags().BoolVar(&enableCaching, "enable-caching", true,
		"Enable vulnerability result caching")
}

func runOptimizedAnalysis(cmd *cobra.Command, args []string) {
	target := args[0]

	// Initialize metrics if enabled
	if enableMetrics {
		log.Debug("Performance metrics enabled")
	}

	// Load performance configuration
	performanceConfig := loadPerformanceConfig()

	// Apply command line overrides
	applyCommandLineOverrides(&performanceConfig)

	// Validate configuration
	if err := performanceConfig.Validate(); err != nil {
		log.Fatalf("Invalid performance configuration: %v", err)
	}

	log.Debugf("Using optimization level: %s", optimizationLevel)
	log.Debugf("Max concurrency: %d", performanceConfig.MaxConcurrentScanners)
	log.Debugf("Scan timeout: %v", performanceConfig.ScanTimeout)
	log.Debugf("Caching enabled: %v", performanceConfig.EnableCaching)

	// Set up profiling if enabled
	if enableProfiling {
		setupProfiling()
	}

	// Parse target type and set up parameters
	params := setupOptimizedParameters(target, performanceConfig)

	// Run the optimized analysis
	startTime := time.Now()
	runOptimizedScan(params, performanceConfig)
	totalDuration := time.Since(startTime)

	// Show performance metrics if requested
	if showMetrics || enableMetrics {
		displayPerformanceMetrics(totalDuration)
	}

	// Show optimization recommendations
	if performanceConfig.EnableMetrics {
		showOptimizationRecommendations()
	}
}

func loadPerformanceConfig() types.AdvancedPerformanceConfig {
	// Parse optimization level
	var level types.OptimizationLevel
	switch optimizationLevel {
	case "basic":
		level = types.OptimizationBasic
	case "balanced":
		level = types.OptimizationBalanced
	case "aggressive":
		level = types.OptimizationAggressive
	case "maximum":
		level = types.OptimizationMaximum
	default:
		log.Warnf("Unknown optimization level '%s', using 'balanced'", optimizationLevel)
		level = types.OptimizationBalanced
	}

	// Load configuration for the specified level
	performanceConfig := config.GetConfigForOptimizationLevel(level)

	// Load from file if specified
	if configFile != "" {
		log.Debugf("Loading performance config from: %s", configFile)
		// For now, just log the intention to load from file
		// Future implementation could load YAML/JSON config file
		log.Warnf("Config file loading not yet implemented, using defaults")
	}

	return performanceConfig
}

func applyCommandLineOverrides(config *types.AdvancedPerformanceConfig) {
	if maxConcurrency > 0 {
		config.MaxConcurrentScanners = maxConcurrency
	}

	if scanTimeout > 0 {
		config.ScanTimeout = scanTimeout
	}

	config.EnableCaching = enableCaching
	config.EnableMetrics = enableMetrics
}

func setupOptimizedParameters(target string, config types.AdvancedPerformanceConfig) types.Parameters {
	// This would set up the scanning parameters based on the target
	// For now, return a basic parameter structure
	params := types.Parameters{
		// Set up parameters based on target type and optimization config
	}

	// Configure diggity parameters based on target
	if isDockerImage(target) {
		params.Diggity.ScanType = 1 // Image
		params.Diggity.Input = target
	} else if isDirectory(target) {
		params.Diggity.ScanType = 3 // Filesystem
		params.Diggity.Input = target
	} else if isTarball(target) {
		params.Diggity.ScanType = 2 // Tarball
		params.Diggity.Input = target
	}

	return params
}

func runOptimizedScan(params types.Parameters, config types.AdvancedPerformanceConfig) {
	// Check if the database is up to date
	log.Debug("Checking database status...")
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)
	db.Load()

	start := time.Now()

	// Set up metrics recording if enabled
	if config.EnableMetrics {
		defer func() {
			duration := time.Since(start)
			// Record scan metrics
			metrics.GetGlobalMetrics().RecordScan(duration, 0, 0) // Component and vuln counts would be passed here
		}()
	}

	// Generate BOM using diggity (simplified for this example)
	bom := generateBOM(params)
	if bom == nil {
		log.Fatal("Failed to generate BOM")
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	log.Debugf("Generated BOM with %d components", componentCount)

	// Run optimized vulnerability analysis
	scanStart := time.Now()
	analyzer.Analyze(bom)
	scanDuration := time.Since(scanStart)

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	log.Debugf("Found %d vulnerabilities in %v", vulnCount, scanDuration)

	// Record detailed metrics
	if config.EnableMetrics {
		metrics.GetGlobalMetrics().RecordScan(scanDuration, componentCount, vulnCount)
	}

	// Display results (simplified)
	if vulnCount > 0 {
		fmt.Printf("Found %d vulnerabilities in %d components\n", vulnCount, componentCount)
	} else {
		fmt.Printf("No vulnerabilities found in %d components\n", componentCount)
	}
}

func displayPerformanceMetrics(totalDuration time.Duration) {
	fmt.Println("\n" + metrics.GetGlobalMetrics().GetFormattedSummary())

	// Show database cache statistics
	cacheStats := db.GetCacheStats()
	fmt.Printf("\nDatabase Cache Statistics:\n")
	for key, value := range cacheStats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	fmt.Printf("\nTotal execution time: %v\n", totalDuration)
}

func showOptimizationRecommendations() {
	metrics := metrics.GetGlobalMetrics()
	summary := metrics.GetSummary()

	fmt.Println("\n=== Optimization Recommendations ===")

	// Analyze cache hit rate
	if cacheHitRate, ok := summary["cache_hit_rate"].(float64); ok {
		if cacheHitRate < 0.5 {
			fmt.Println("• Consider increasing cache timeout for better performance")
		} else if cacheHitRate > 0.9 {
			fmt.Println("• Cache is working efficiently")
		}
	}

	// Analyze scan duration
	if avgDuration, ok := summary["average_scan_duration"].(string); ok {
		fmt.Printf("• Average scan duration: %s\n", avgDuration)
		// Could add recommendations based on duration
	}

	// Analyze scanner performance
	topScanners := metrics.GetTopPerformingScanners(3)
	if len(topScanners) > 0 {
		fmt.Println("• Top performing scanners:")
		for i, scanner := range topScanners {
			fmt.Printf("  %d. %s (avg: %v)\n", i+1, scanner.Name, scanner.AverageDuration)
		}
	}
}

func setupProfiling() {
	log.Debug("Profiling enabled - performance data will be collected")
	// Basic profiling setup - could be enhanced with pprof integration
	// For now, we rely on the metrics system for performance tracking
	log.Debug("Using internal metrics system for performance monitoring")
}

// Helper functions
func isDockerImage(target string) bool {
	// Simple heuristic - could be improved
	return !isDirectory(target) && !isTarball(target)
}

func isDirectory(target string) bool {
	if stat, err := os.Stat(target); err == nil {
		return stat.IsDir()
	}
	return false
}

func isTarball(target string) bool {
	// Check for common tarball extensions
	return strings.HasSuffix(target, ".tar") ||
		strings.HasSuffix(target, ".tar.gz") ||
		strings.HasSuffix(target, ".tgz") ||
		strings.HasSuffix(target, ".tar.bz2")
}

func generateBOM(params types.Parameters) *cyclonedx.BOM {
	// Use the existing diggity integration to generate the BOM
	log.Debug("Generating BOM using diggity...")

	diggityParams := params.Diggity
	// Generate unique address for the scan
	addr, err := diggity.NewAddress()
	if err != nil {
		log.Debugf("Error creating diggity address: %v", err)
		return nil
	}

	cdx.New(addr)
	switch params.Diggity.ScanType {
	case 1: // Image
		// Pull and read image from registry
		image, ref, err := reader.GetImage(diggityParams.Input, nil)
		if err != nil {
			log.Debugf("Error getting image: %v", err)
			return nil
		}

		cdx.SetMetadataComponent(addr, cdx.SetImageMetadata(*image, *ref, diggityParams.Input))

		err = reader.ReadFiles(image, addr)
		if err != nil {
			log.Debugf("Error reading image files: %v", err)
			return nil
		}
	case 2: // Tarball
		image, err := reader.ReadTarball(params.Diggity.Input)
		if err != nil {
			log.Debugf("Error reading tarball: %v", err)
			return nil
		}
		err = reader.ReadFiles(image, addr)
		if err != nil {
			log.Debugf("Error reading tarball files: %v", err)
			return nil
		}
	case 3: // Filesystem
		err := reader.FilesystemScanHandler(diggityParams.Input, addr)
		if err != nil {
			log.Debugf("Error scanning filesystem: %v", err)
			return nil
		}
	default:
		log.Debug("Invalid scan type")
		return nil
	}

	return cdx.Finalize(addr)
}
