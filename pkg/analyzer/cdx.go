package analyzer

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/scan"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
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

	log.Debug("Starting SBOM vulnerability analysis using legacy analyzer")
	// Use simplified analysis function
	analyzeInternal(sbom)
}

// analyzeInternal performs optimized vulnerability analysis on a CycloneDX BOM
func analyzeInternal(bom *cyclonedx.BOM) {
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

	log.Debugf("Starting comprehensive SBOM vulnerability analysis for %d components", componentCount)

	// Load configuration from file or create default with comprehensive comments
	// The config file provides complete control over all scanning behavior:
	// - Engine settings (concurrency, timeouts, caching)
	// - Matcher behavior (CPE matching, VEX processing, ignore rules)
	// - Performance optimization (adaptive settings, memory limits)
	// - Output preferences (logging, metrics)

	// Initialize store instance
	store := db.Store{}

	// Load scanner configuration (use default config)
	scannerConfig := config.GetDefaultConfiguration()

	// Convert config to matcher format
	matcherConfig := convertConfigToMatcherConfig(&scannerConfig)

	// Log the configuration being used for transparency
	log.Debugf("Using scanner configuration: concurrency=%d, caching=%t",
		matcherConfig.MaxConcurrency, matcherConfig.EnableCaching)

	// Create scanner manager with the file-based configuration
	scanManager := scan.NewManagerWithOptions(store, matcherConfig)

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
	log.Debugf("Comprehensive SBOM vulnerability analysis completed: %d vulnerabilities found in %v (config: concurrency=%d, caching=%t)",
		len(vulns), duration, matcherConfig.MaxConcurrency, matcherConfig.EnableCaching)

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

// convertConfigToMatcherConfig converts Configuration to MatcherConfig
func convertConfigToMatcherConfig(sc *config.Configuration) *matchertypes.MatcherConfig {
	// Create configuration directly from config with sensible defaults
	return &matchertypes.MatcherConfig{
		// Engine settings (these are used by the core scanning engine)
		MaxConcurrency: sc.Performance.MaxConcurrentScanners,
		EnableCaching:  sc.Performance.EnableCaching,
		EnableMetrics:  false, // Default since this field doesn't exist in new config

		// Matcher settings (these control vulnerability matching behavior)
		NormalizeByCVE:           true,       // Default value
		CPEMatching:              true,       // Default value
		DeduplicateResults:       true,       // Default value
		EnableVEXProcessing:      false,      // Default value
		VEXDocumentPaths:         []string{}, // Default value
		EnableConfidenceScoring:  false,      // Default value
		MinConfidenceThreshold:   0.8,        // Default value
		EnableTargetSWValidation: false,      // Default value
		PreciseCPEMatching:       false,      // Default value

		// Convert ignore rules (simplified for now)
		DefaultIgnoreRules: []matchertypes.IgnoreRule{},
	}
}
