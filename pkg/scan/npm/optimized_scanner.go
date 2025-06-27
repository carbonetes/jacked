package npm

import (
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/carbonetes/jacked/pkg/version"
)

// OptimizedScanner provides enhanced NPM vulnerability scanning with performance optimizations
type OptimizedScanner struct {
	store db.Store
	cache map[string]*[]types.Vulnerability
	mutex sync.RWMutex
}

// NewOptimizedScanner creates a new optimized NPM scanner
func NewOptimizedScanner(store db.Store) *OptimizedScanner {
	return &OptimizedScanner{
		store: store,
		cache: make(map[string]*[]types.Vulnerability),
	}
}

// Scan performs optimized NPM vulnerability scanning with batch processing
func (s *OptimizedScanner) Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	start := time.Now()
	var results []cyclonedx.Vulnerability

	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return results, nil
	}

	// Pre-filter NPM components for efficient processing
	npmComponents := s.filterNPMComponents(bom)
	if len(npmComponents) == 0 {
		return results, nil
	}

	log.Debugf("Processing %d NPM components", len(npmComponents))

	// Batch vulnerability lookup
	packageNames := s.extractPackageNames(npmComponents)
	vulnerabilityMap := s.store.BatchVulnerabilityLookup(packageNames, "nvd")

	// Process components in parallel
	resultChan := make(chan []cyclonedx.Vulnerability, len(npmComponents))
	var wg sync.WaitGroup

	// Use worker pool for controlled concurrency
	workerCount := min(len(npmComponents), 10)
	componentChan := make(chan cyclonedx.Component, len(npmComponents))

	// Send components to channel
	for _, comp := range npmComponents {
		componentChan <- comp
	}
	close(componentChan)

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var workerResults []cyclonedx.Vulnerability

			for comp := range componentChan {
				componentVulns := s.processComponent(comp, vulnerabilityMap)
				workerResults = append(workerResults, componentVulns...)
			}

			resultChan <- workerResults
		}()
	}

	// Wait for all workers and close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for workerResults := range resultChan {
		results = append(results, workerResults...)
	}

	log.Debugf("NPM scanning completed: %d vulnerabilities found in %v",
		len(results), time.Since(start))

	return results, nil
}

// filterNPMComponents extracts only NPM components from the BOM
func (s *OptimizedScanner) filterNPMComponents(bom *cyclonedx.BOM) []cyclonedx.Component {
	var npmComponents []cyclonedx.Component

	for _, c := range *bom.Components {
		if c.Properties == nil {
			continue
		}

		if helper.GetComponentType(c.Properties) == "npm" {
			npmComponents = append(npmComponents, c)
		}
	}

	return npmComponents
}

// extractPackageNames creates a list of all package names for batch lookup
func (s *OptimizedScanner) extractPackageNames(components []cyclonedx.Component) []string {
	packageSet := make(map[string]bool)
	var packages []string

	for _, comp := range components {
		packages = append(packages, comp.Name)
		packageSet[comp.Name] = true

		// Include upstream names
		if upstream := helper.FindUpstream(comp.BOMRef); upstream != "" && !packageSet[upstream] {
			packages = append(packages, upstream)
			packageSet[upstream] = true
		}
	}

	return packages
}

// processComponent processes a single NPM component for vulnerabilities
func (s *OptimizedScanner) processComponent(comp cyclonedx.Component, vulnerabilityMap map[string]*[]types.Vulnerability) []cyclonedx.Vulnerability {
	var results []cyclonedx.Vulnerability

	// Get vulnerabilities for this component
	vulns := vulnerabilityMap[comp.Name]

	// Check upstream if main package has no vulnerabilities
	if vulns == nil || len(*vulns) == 0 {
		if upstream := helper.FindUpstream(comp.BOMRef); upstream != "" {
			vulns = vulnerabilityMap[upstream]
		}
	}

	if vulns == nil || len(*vulns) == 0 {
		return results
	}

	// Parse component version once
	pkgVer, err := version.NewNpmVersion(comp.Version)
	if err != nil {
		log.Debugf("Failed to parse NPM version %s for component %s: %v", comp.Version, comp.Name, err)
		return results
	}

	// Check each vulnerability
	for _, vuln := range *vulns {
		if vuln.Constraints == "" {
			continue
		}

		match, err := pkgVer.Check(vuln.Constraints)
		if err != nil || !match {
			continue
		}

		if vex := v3.ToVex(&vuln, &comp, vuln.Constraints); vex != nil {
			results = append(results, *vex)
		}
	}

	return results
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
