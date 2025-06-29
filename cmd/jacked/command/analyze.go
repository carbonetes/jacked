package command

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/metrics"
	"github.com/carbonetes/jacked/internal/ui"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/ci"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/types"
)

// analyze is the main analyzer function
func analyze(params types.Parameters) {
	// Use simple analysis by default, or optimized if performance config is set
	if config.Config.Performance.MaxConcurrentScanners > 0 {
		runOptimizedAnalysisWithParams(params)
	} else {
		runSimpleAnalysis(params)
	}
}

// runOptimizedAnalysisWithParams runs optimized analysis using existing Parameters structure
func runOptimizedAnalysisWithParams(params types.Parameters) {
	// Determine optimization level from global performance config
	performanceConfig := loadPerformanceConfigFromParams(params)

	// Validate configuration
	if err := performanceConfig.Validate(); err != nil {
		log.Debugf("Invalid performance configuration, using defaults: %v", err)
		performanceConfig = config.GetConfigForOptimizationLevel(types.OptimizationBalanced)
	}

	log.Debugf("Using optimization level: %s", getOptimizationLevelName(performanceConfig))
	log.Debugf("Max concurrency: %d", performanceConfig.MaxConcurrentScanners)
	log.Debugf("Scan timeout: %v", performanceConfig.ScanTimeout)
	log.Debugf("Caching enabled: %v", performanceConfig.EnableCaching)

	// Run the optimized analysis
	startTime := time.Now()
	runOptimizedScanWithParams(params, performanceConfig)
	totalDuration := time.Since(startTime)

	// Show performance metrics if metrics are enabled or explicitly requested
	if performanceConfig.EnableMetrics || params.ShowMetrics {
		displayPerformanceMetricsFromParams(totalDuration, params)
	}
}

// loadPerformanceConfigFromParams loads performance configuration based on existing parameters
func loadPerformanceConfigFromParams(params types.Parameters) types.AdvancedPerformanceConfig {
	// Use existing config system if available
	if config.Config.Performance.MaxConcurrentScanners > 0 {
		return config.Config.Performance
	}

	// Default to balanced optimization
	return config.GetConfigForOptimizationLevel(types.OptimizationBalanced)
}

// runOptimizedScanWithParams runs optimized scan using existing Parameters structure
// runOptimizedScanWithParams runs optimized scan using existing Parameters structure
func runOptimizedScanWithParams(params types.Parameters, perfConfig types.AdvancedPerformanceConfig) {
	start := time.Now()

	// Set up metrics recording if enabled
	if perfConfig.EnableMetrics {
		defer func() {
			duration := time.Since(start)
			// Record scan metrics
			metrics.GetGlobalMetrics().RecordScan(duration, 0, 0) // Component and vuln counts would be passed here
		}()
	}

	// Determine UI mode and run complete workflow
	scanMode := ui.ModeAuto
	if params.NonInteractive {
		scanMode = ui.ModeNonInteractive
	} else if params.Quiet {
		scanMode = ui.ModeQuiet
	}

	// Run the complete workflow (database update, BOM generation, scanning) with enhanced visuals
	err := ui.RunCompleteNonInteractiveWorkflow(context.Background(), params, scanMode, perfConfig)
	if err != nil {
		log.Debugf("Workflow failed: %v", err)
		if !params.Quiet {
			fmt.Println("❌ Scanning failed")
		}
		return
	}

	// Generate BOM after workflow
	bom := generateBOMFromParams(params)
	if bom == nil {
		log.Error("Failed to generate BOM")
		return
	}

	// Run vulnerability analysis with UI
	err = ui.ScanWithUI(context.Background(), bom, params, scanMode)
	if err != nil {
		log.Debugf("Scanning failed: %v", err)
		if !params.Quiet {
			fmt.Println("❌ Scanning failed")
		}
		return
	}

	// Record metrics
	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	if perfConfig.EnableMetrics {
		scanDuration := time.Since(start)
		metrics.GetGlobalMetrics().RecordScan(scanDuration, componentCount, vulnCount)
	}

	// Handle CI mode
	if params.CI {
		ci.Run(config.Config.CI, bom)
		os.Exit(0)
	}

	elapsed := time.Since(start).Seconds()

	// Display results using UI module instead of presenter
	if params.Quiet || len(params.File) > 0 {
		ui.DisplayResults(params, elapsed, bom)
	}
}

// runSimpleAnalysis provides a simple, direct analysis path - replaces cli.Run
func runSimpleAnalysis(params types.Parameters) {
	// Check if the database is up to date
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)
	db.Load()
	start := time.Now()

	// Generate BOM
	bom := generateBOMFromParams(params)
	if bom == nil {
		log.Error("Failed to generate BOM")
		return
	}

	// Analyze BOM for vulnerabilities
	analyzer.AnalyzeCDX(bom)

	// Handle CI mode
	if params.CI {
		ci.Run(config.Config.CI, bom)
		os.Exit(0)
	}

	elapsed := time.Since(start).Seconds()
	log.Debug("Analysis complete")

	// Display results using UI module
	ui.DisplayResults(params, elapsed, bom)
}

// generateBOMFromParams generates BOM using existing diggity parameters
func generateBOMFromParams(params types.Parameters) *cyclonedx.BOM {
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
		if !params.Quiet {
			log.Infof("Fetching %s from remote registry", params.Diggity.Input)
		}
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
		if !params.Quiet {
			log.Infof("📦 Reading tarfile %s", params.Diggity.Input)
		}
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
		if !params.Quiet {
			log.Infof("📁 Reading directory %s", params.Diggity.Input)
		}
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

// displayPerformanceMetricsFromParams displays performance metrics if quiet mode is not enabled
func displayPerformanceMetricsFromParams(totalDuration time.Duration, params types.Parameters) {
	// Only show metrics if not in quiet mode and not outputting to file
	if params.Quiet || params.Format != types.Table {
		return
	}

	fmt.Println("\n" + metrics.GetGlobalMetrics().GetFormattedSummary())

	// Show database cache statistics
	cacheStats := db.GetCacheStats()
	fmt.Printf("\nDatabase Cache Statistics:\n")
	for key, value := range cacheStats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	fmt.Printf("\nTotal execution time: %v\n", totalDuration)
}

// getOptimizationLevelName returns a human-readable name for the optimization level
func getOptimizationLevelName(config types.AdvancedPerformanceConfig) string {
	// Try to match the config to known optimization levels
	if config.MaxConcurrentScanners <= 2 {
		return "basic"
	} else if config.MaxConcurrentScanners <= 4 {
		return "balanced"
	} else if config.MaxConcurrentScanners <= 8 {
		return "aggressive"
	} else {
		return "maximum"
	}
}
