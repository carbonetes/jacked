package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
)

// ScanEngine is the main scanning orchestrator
type ScanEngine struct {
	scanners     []Scanner
	config       ScanConfig
	strategy     ExecutionStrategy
	cache        CacheProvider
	metrics      MetricsCollector
	deduplicator VulnerabilityDeduplicator
	filters      []ComponentFilter
}

// NewScanEngine creates a new scanning engine with the specified configuration
func NewScanEngine(config ScanConfig) *ScanEngine {
	engine := &ScanEngine{
		config:       config,
		scanners:     make([]Scanner, 0),
		filters:      make([]ComponentFilter, 0),
		deduplicator: NewSmartDeduplicator(),
	}

	// Set default strategy based on configuration
	if config.MaxConcurrency > 1 {
		engine.strategy = NewConcurrentStrategy(config.MaxConcurrency, config.Timeout)
	} else {
		engine.strategy = NewSequentialStrategy(config.Timeout)
	}

	// Set up caching if enabled
	if config.EnableCaching {
		engine.cache = NewMemoryCache(config.CacheTTL)
	}

	// Set up metrics if enabled
	if config.EnableMetrics {
		engine.metrics = NewMetricsCollector()
	}

	return engine
}

// RegisterScanner adds a scanner to the engine
func (e *ScanEngine) RegisterScanner(scanner Scanner) {
	e.scanners = append(e.scanners, scanner)
	log.Debugf("Registered scanner: %s", scanner.Type())
}

// RegisterFilter adds a component filter
func (e *ScanEngine) RegisterFilter(filter ComponentFilter) {
	e.filters = append(e.filters, filter)
}

// SetExecutionStrategy changes the execution strategy
func (e *ScanEngine) SetExecutionStrategy(strategy ExecutionStrategy) {
	e.strategy = strategy
}

// SetCacheProvider changes the cache provider
func (e *ScanEngine) SetCacheProvider(cache CacheProvider) {
	e.cache = cache
}

// SetMetricsCollector changes the metrics collector
func (e *ScanEngine) SetMetricsCollector(metrics MetricsCollector) {
	e.metrics = metrics
}

// Scan performs vulnerability scanning on the provided BOM
func (e *ScanEngine) Scan(ctx context.Context, bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return []cyclonedx.Vulnerability{}, nil
	}

	start := time.Now()

	// Create cache key if caching is enabled
	var cacheKey string
	if e.cache != nil {
		cacheKey = e.generateCacheKey(bom)
		if cached, found := e.cache.Get(cacheKey); found {
			log.Debug("Using cached scan results")
			return cached, nil
		}
	}

	// Apply component filters
	filteredBOM := e.applyFilters(bom)

	// Select relevant scanners
	relevantScanners := e.selectRelevantScanners(filteredBOM)

	if len(relevantScanners) == 0 {
		log.Debug("No relevant scanners found for BOM")
		return []cyclonedx.Vulnerability{}, nil
	}

	log.Debugf("Executing %d scanners for %d components", len(relevantScanners), len(*filteredBOM.Components))

	// Execute scanners using the configured strategy
	results, err := e.strategy.Execute(ctx, relevantScanners, filteredBOM)
	if err != nil {
		return nil, fmt.Errorf("scan execution failed: %w", err)
	}

	// Collect vulnerabilities and handle errors
	var allVulnerabilities []cyclonedx.Vulnerability
	for _, result := range results {
		if result.Error != nil {
			log.Debugf("Scanner %s failed: %v", result.ScannerType, result.Error)
			if e.metrics != nil {
				e.metrics.RecordError(result.ScannerType, result.Error)
			}
			continue
		}

		allVulnerabilities = append(allVulnerabilities, result.Vulnerabilities...)

		if e.metrics != nil {
			e.metrics.RecordScan(result.ScannerType, result.Duration, result.ComponentCount, len(result.Vulnerabilities))
		}

		log.Debugf("Scanner %s found %d vulnerabilities in %v",
			result.ScannerType, len(result.Vulnerabilities), result.Duration)
	}

	// Deduplicate vulnerabilities
	deduplicatedVulns := e.deduplicator.Deduplicate(allVulnerabilities)

	// Cache results if caching is enabled
	if e.cache != nil && cacheKey != "" {
		e.cache.Set(cacheKey, deduplicatedVulns, e.config.CacheTTL)
	}

	totalDuration := time.Since(start)
	log.Debugf("Scan completed in %v: %d vulnerabilities found, %d after deduplication",
		totalDuration, len(allVulnerabilities), len(deduplicatedVulns))

	return deduplicatedVulns, nil
}

// applyFilters applies all registered filters to the BOM
func (e *ScanEngine) applyFilters(bom *cyclonedx.BOM) *cyclonedx.BOM {
	if len(e.filters) == 0 {
		return bom
	}

	filteredBOM := &cyclonedx.BOM{
		// Copy metadata
		BOMFormat:    bom.BOMFormat,
		SpecVersion:  bom.SpecVersion,
		SerialNumber: bom.SerialNumber,
		Version:      bom.Version,
		Metadata:     bom.Metadata,
	}

	if bom.Components != nil {
		components := *bom.Components
		for _, filter := range e.filters {
			components = filter.Filter(components)
		}
		filteredBOM.Components = &components
	}

	return filteredBOM
}

// selectRelevantScanners chooses scanners based on BOM component types
func (e *ScanEngine) selectRelevantScanners(bom *cyclonedx.BOM) []Scanner {
	if bom.Components == nil {
		return []Scanner{}
	}

	componentTypes := make(map[string]bool)
	for _, component := range *bom.Components {
		if component.Properties != nil {
			for _, prop := range *component.Properties {
				// Check for diggity:package:type (primary) and component:type (fallback)
				if prop.Name == "diggity:package:type" || prop.Name == "component:type" {
					componentTypes[prop.Value] = true
				}
			}
		}

		// Also try to extract type from PURL if available
		if component.BOMRef != "" && strings.HasPrefix(component.BOMRef, "pkg:") {
			parts := strings.Split(component.BOMRef, "/")
			if len(parts) > 0 {
				typeWithPkg := parts[0]
				if strings.HasPrefix(typeWithPkg, "pkg:") {
					ecosystem := strings.TrimPrefix(typeWithPkg, "pkg:")
					componentTypes[ecosystem] = true
				}
			}
		}
	}

	var relevantScanners []Scanner
	for _, scanner := range e.scanners {
		isRelevant := false
		for componentType := range componentTypes {
			if scanner.SupportsComponent(componentType) {
				isRelevant = true
				break
			}
		}
		if isRelevant {
			relevantScanners = append(relevantScanners, scanner)
		}
	}

	return relevantScanners
}

// generateCacheKey creates a cache key based on BOM content
func (e *ScanEngine) generateCacheKey(bom *cyclonedx.BOM) string {
	if bom.Components == nil {
		return "empty_bom"
	}

	// Create a simple hash based on component count and sample component names/versions
	key := fmt.Sprintf("components_%d", len(*bom.Components))

	// Include up to 5 components in the key for uniqueness
	for i, comp := range *bom.Components {
		if i >= 5 {
			break
		}
		key += fmt.Sprintf("_%s_%s", comp.Name, comp.Version)
	}

	return key
}

// GetMetrics returns collected metrics
func (e *ScanEngine) GetMetrics() map[string]interface{} {
	if e.metrics == nil {
		return map[string]interface{}{}
	}
	return e.metrics.GetMetrics()
}

// GetCacheStats returns cache statistics
func (e *ScanEngine) GetCacheStats() map[string]interface{} {
	if e.cache == nil {
		return map[string]interface{}{"enabled": false}
	}

	return map[string]interface{}{
		"enabled": true,
		"size":    e.cache.Size(),
	}
}
