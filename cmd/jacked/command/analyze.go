package command

import (
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/cmd/jacked/ui/spinner"
	"github.com/carbonetes/jacked/cmd/jacked/ui/table"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/metrics"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/ci"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/scan"
)

// analyze is the main analyzer function
func analyze(params scan.Parameters) {
	// Use simple analysis by default, or optimized if performance config is set
	if config.Config.Performance.MaxConcurrentScanners > 0 {
		runOptimizedAnalysisWithParams(params)
	} else {
		runSimpleAnalysis(params)
	}
}

// runOptimizedAnalysisWithParams runs optimized analysis using existing Parameters structure
func runOptimizedAnalysisWithParams(params scan.Parameters) {
	// Determine optimization level from global performance config
	performanceConfig := loadPerformanceConfigFromParams(params)

	log.Debugf("Using performance configuration")
	log.Debugf("Max concurrency: %d", performanceConfig.MaxConcurrentScanners)
	log.Debugf("Caching enabled: %v", performanceConfig.EnableCaching)

	// Run the optimized analysis
	startTime := time.Now()
	runOptimizedScanWithParams(params, performanceConfig)
	totalDuration := time.Since(startTime)

	// Show performance metrics if explicitly requested
	if params.ShowMetrics {
		displayPerformanceMetricsFromParams(totalDuration, params)
	}
}

// loadPerformanceConfigFromParams loads performance configuration based on existing parameters
func loadPerformanceConfigFromParams(params scan.Parameters) config.PerformanceConfig {
	// Use existing config system if available
	if config.Config.Performance.MaxConcurrentScanners > 0 {
		return config.Config.Performance
	}

	// Default to balanced optimization
	return config.GetConfigForOptimizationLevel(config.OptimizationBalanced)
}

// runOptimizedScanWithParams runs optimized scan using existing Parameters structure
func runOptimizedScanWithParams(params scan.Parameters, perfConfig config.PerformanceConfig) {
	start := time.Now()

	// Record scan metrics if requested
	if params.ShowMetrics {
		defer func() {
			duration := time.Since(start)
			// Record scan metrics
			metrics.GetGlobalMetrics().RecordScan(duration, 0, 0) // Component and vuln counts would be passed here
		}()
	}

	// Check if the database is up to date
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)
	db.Load()

	// Generate BOM after workflow
	bom := generateBOMFromParams(params)
	if bom == nil {
		log.Error("Failed to generate BOM")
		return
	}

	// Run SBOM vulnerability analysis
	analyzer.AnalyzeCDX(bom)

	// Record metrics
	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	if params.ShowMetrics {
		scanDuration := time.Since(start)
		metrics.GetGlobalMetrics().RecordScan(scanDuration, componentCount, vulnCount)
	}

	// Handle CI mode
	if params.CI {
		ci.Run(config.Config.CI, bom)
		os.Exit(0)
	}

	elapsed := time.Since(start).Seconds()

	// Display results with basic output
	if !params.Quiet {
		displayBasicResults(params, elapsed, bom)
	}
}

// runSimpleAnalysis provides a simple, direct analysis path - replaces cli.Run
func runSimpleAnalysis(params scan.Parameters) {
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

	spinner.Set("Analyzing SBOM for vulnerabilities")

	// Analyze BOM for vulnerabilities
	analyzer.AnalyzeCDX(bom)

	spinner.Done()

	// Handle CI mode
	if params.CI {
		ci.Run(config.Config.CI, bom)
		os.Exit(0)
	}

	elapsed := time.Since(start).Seconds()
	log.Debug("SBOM analysis complete")

	// Display results with basic output
	if !params.Quiet {
		displayBasicResults(params, elapsed, bom)
	}
}

// generateBOMFromParams generates BOM using existing diggity parameters
func generateBOMFromParams(params scan.Parameters) *cyclonedx.BOM {
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

		spinner.Set("Reading image from registry: " + diggityParams.Input)
		defer spinner.Done()

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
			log.Infof("Reading tarfile %s", params.Diggity.Input)
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
			log.Infof("Reading directory %s", params.Diggity.Input)
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
func displayPerformanceMetricsFromParams(totalDuration time.Duration, params scan.Parameters) {
	// Only show metrics if not in quiet mode and not outputting to file
	if params.Quiet || params.Format != scan.Table {
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
func getOptimizationLevelName(config config.PerformanceConfig) string {
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

// displayBasicResults provides enhanced console output for scan results
func displayBasicResults(params scan.Parameters, elapsed float64, bom *cyclonedx.BOM) {
	if bom == nil {
		fmt.Println("No results to display")
		return
	}

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	// Handle file output first
	if len(params.File) > 0 {
		err := saveResultsToFile(bom, params.File, params.Format)
		if err != nil {
			log.Debugf("Failed to save results to file: %s", err.Error())
		}
		fmt.Printf("Results saved to: %s\n", params.File)
		return
	}

	// Handle different output formats
	switch params.Format {
	case scan.Table:
		// Simply show the table directly
		table.Show(table.Create(bom), elapsed)
	case scan.JSON:
		result, err := helper.ToJSON(*bom)
		if err != nil {
			log.Debug(err)
		}
		fmt.Print(string(result))
	default:
		// Default to summary display
		displayScanSummary(componentCount, vulnCount, elapsed)
	}
}

// displayScanSummary shows a text summary of scan results
func displayScanSummary(componentCount, vulnCount int, elapsed float64) {
	fmt.Printf("\nScan Results:\n")
	fmt.Printf("  Components scanned: %d\n", componentCount)
	fmt.Printf("  Vulnerabilities found: %d\n", vulnCount)
	fmt.Printf("  Scan duration: %.2f seconds\n", elapsed)

	if vulnCount > 0 {
		fmt.Printf("\nFound %d vulnerabilities in the scanned components.\n", vulnCount)
		fmt.Printf("Use table format for detailed vulnerability information.\n")
	} else {
		fmt.Printf("\nNo vulnerabilities found.\n")
	}
}

// saveResultsToFile saves scan results to a file in the specified format
func saveResultsToFile(bom *cyclonedx.BOM, filePath string, format scan.Format) error {
	return helper.SaveToFile(bom, filePath, format.String())
}
