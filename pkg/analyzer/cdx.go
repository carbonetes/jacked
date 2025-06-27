package analyzer

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/scan"
)

// AnalyzeCDX is a function that takes a CycloneDX BOM as input and analyzes it for vulnerabilities.
// This is the legacy function maintained for backward compatibility.
func AnalyzeCDX(sbom *cyclonedx.BOM) {
	// If the BOM is nil, return immediately.
	if sbom == nil {
		return
	}

	// If there are no components in the BOM, return immediately.
	if sbom.Components == nil || len(*sbom.Components) == 0 {
		return
	}

	log.Debug("Starting vulnerability analysis using legacy analyzer")
	Analyze(sbom)
}

// Analyze performs optimized vulnerability analysis on a CycloneDX BOM
func Analyze(bom *cyclonedx.BOM) {
	if bom == nil {
		log.Debug("BOM is nil, skipping analysis")
		return
	}

	if bom.Components == nil {
		log.Debug("BOM has no components, skipping analysis")
		return
	}

	if len(*bom.Components) == 0 {
		log.Debug("BOM has empty components list, skipping analysis")
		return
	}

	start := time.Now()
	componentCount := len(*bom.Components)

	log.Debugf("Starting optimized vulnerability analysis for %d components", componentCount)

	// Initialize store instance
	store := db.Store{}

	// Create optimized scanner manager with new architecture
	scanManager := scan.NewManager(store)

	// Configure optimization settings based on BOM size
	if componentCount > 100 {
		// For large BOMs, increase concurrency and enable caching
		scanManager.SetConcurrency(8).
			SetCaching(true).
			SetTimeout(10 * time.Minute)
		log.Debug("Configured for large BOM analysis")
	} else if componentCount > 50 {
		// For medium BOMs, moderate settings
		scanManager.SetConcurrency(6).
			SetCaching(true).
			SetTimeout(5 * time.Minute)
		log.Debug("Configured for medium BOM analysis")
	} else {
		// For small BOMs, basic settings with caching
		scanManager.SetConcurrency(4).
			SetCaching(true).
			SetTimeout(3 * time.Minute)
		log.Debug("Configured for small BOM analysis")
	}

	// Execute vulnerability scanning
	vulns, err := scanManager.Run(bom)
	if err != nil {
		log.Debugf("Error during vulnerability scanning: %v", err)
		// Don't return on error, continue with empty results
		vulns = []cyclonedx.Vulnerability{}
	}

	// Assign results to BOM
	bom.Vulnerabilities = &vulns

	duration := time.Since(start)
	log.Debugf("Vulnerability analysis completed: %d vulnerabilities found in %v",
		len(vulns), duration)

	// Log performance metrics
	if componentCount > 0 {
		avgTimePerComponent := duration / time.Duration(componentCount)
		log.Debugf("Performance: %v per component, %d components/second",
			avgTimePerComponent, int(float64(componentCount)/duration.Seconds()))
	}

	// Clear cache periodically to prevent memory buildup
	if componentCount > 200 {
		db.ClearCache()
		log.Debug("Cleared vulnerability cache due to large BOM size")
	}
}
