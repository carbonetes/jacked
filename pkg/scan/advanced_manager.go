package scan

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
)

// ScanResult encapsulates scanner results with metadata
type ScanResult struct {
	ScannerType     string
	Vulnerabilities []cyclonedx.Vulnerability
	Duration        time.Duration
	ComponentCount  int
	Error           error
}

// AdvancedManager provides enhanced scanning capabilities with optimizations
type AdvancedManager struct {
	scanners    []Scanner
	concurrency int
	timeout     time.Duration
	cache       *ResultCache
}

// ResultCache provides intelligent caching for scan results
type ResultCache struct {
	cache    map[string][]cyclonedx.Vulnerability
	mutex    sync.RWMutex
	timeout  time.Duration
	lastUsed map[string]time.Time
}

// NewAdvancedManager creates an optimized scanning manager
func NewAdvancedManager(scanners ...Scanner) *AdvancedManager {
	return &AdvancedManager{
		scanners:    scanners,
		concurrency: runtime.NumCPU(),
		timeout:     5 * time.Minute,
		cache:       NewResultCache(15 * time.Minute),
	}
}

// NewResultCache creates a new result cache with specified timeout
func NewResultCache(timeout time.Duration) *ResultCache {
	return &ResultCache{
		cache:    make(map[string][]cyclonedx.Vulnerability),
		timeout:  timeout,
		lastUsed: make(map[string]time.Time),
	}
}

// SetConcurrency sets the maximum number of concurrent scanners
func (m *AdvancedManager) SetConcurrency(concurrency int) {
	if concurrency > 0 {
		m.concurrency = concurrency
	}
}

// SetTimeout sets the maximum timeout for scanning operations
func (m *AdvancedManager) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		m.timeout = timeout
	}
}

// Run executes all scanners with advanced optimizations
func (m *AdvancedManager) Run(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return []cyclonedx.Vulnerability{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Check cache first
	bomHash := m.computeBOMHash(bom)
	if cached := m.cache.Get(bomHash); cached != nil {
		log.Debug("Using cached scan results")
		return cached, nil
	}

	// Pre-analyze BOM to group components by type for efficient processing
	componentGroups := m.groupComponentsByType(bom)

	// Use worker pool pattern for controlled concurrency
	results := make(chan ScanResult, len(m.scanners))
	semaphore := make(chan struct{}, m.concurrency)

	var wg sync.WaitGroup

	// Launch scanners with controlled concurrency
	for i, scanner := range m.scanners {
		wg.Add(1)
		go func(idx int, s Scanner) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Execute scan with timeout
			result := m.executeScanWithTimeout(ctx, s, bom, componentGroups, idx)

			select {
			case results <- result:
			case <-ctx.Done():
				log.Debugf("Scanner %d cancelled due to timeout", idx)
			}
		}(i, scanner)
	}

	// Close results channel when all scanners complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and merge results
	var allVulnerabilities []cyclonedx.Vulnerability
	scannerResults := make([]ScanResult, 0, len(m.scanners))

	for result := range results {
		scannerResults = append(scannerResults, result)

		if result.Error != nil {
			log.Debugf("Scanner %s failed: %v", result.ScannerType, result.Error)
			continue
		}

		allVulnerabilities = append(allVulnerabilities, result.Vulnerabilities...)
		log.Debugf("Scanner %s found %d vulnerabilities in %v",
			result.ScannerType, len(result.Vulnerabilities), result.Duration)
	}

	// Enhanced deduplication with accuracy improvements
	deduplicatedVulns := m.smartDeduplication(allVulnerabilities)

	// Cache results for future use
	m.cache.Set(bomHash, deduplicatedVulns)

	log.Debugf("Scan complete: %d scanners, %d total vulnerabilities, %d after deduplication",
		len(scannerResults), len(allVulnerabilities), len(deduplicatedVulns))

	return deduplicatedVulns, nil
}

// executeScanWithTimeout runs a scanner with timeout and metrics
func (m *AdvancedManager) executeScanWithTimeout(ctx context.Context, scanner Scanner, bom *cyclonedx.BOM, componentGroups map[string]int, scannerIdx int) ScanResult {
	start := time.Now()

	// Create scanner-specific context
	scanCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// Channel to receive scan results
	resultChan := make(chan []cyclonedx.Vulnerability, 1)
	errChan := make(chan error, 1)

	// Execute scan in goroutine
	go func() {
		vulns, err := scanner.Scan(bom)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- vulns
	}()

	// Wait for result or timeout
	select {
	case vulns := <-resultChan:
		return ScanResult{
			ScannerType:     m.getScannerType(scanner),
			Vulnerabilities: vulns,
			Duration:        time.Since(start),
			ComponentCount:  len(*bom.Components),
		}
	case err := <-errChan:
		return ScanResult{
			ScannerType: m.getScannerType(scanner),
			Duration:    time.Since(start),
			Error:       err,
		}
	case <-scanCtx.Done():
		return ScanResult{
			ScannerType: m.getScannerType(scanner),
			Duration:    time.Since(start),
			Error:       scanCtx.Err(),
		}
	}
}

// smartDeduplication performs enhanced vulnerability deduplication
func (m *AdvancedManager) smartDeduplication(vulnerabilities []cyclonedx.Vulnerability) []cyclonedx.Vulnerability {
	if len(vulnerabilities) == 0 {
		return vulnerabilities
	}

	// Use a more sophisticated deduplication key
	vulnMap := make(map[string]cyclonedx.Vulnerability)

	for _, vuln := range vulnerabilities {
		// Create composite key for better deduplication
		key := m.createDeduplicationKey(vuln)

		// Keep the vulnerability with more complete information
		if existing, exists := vulnMap[key]; exists {
			if m.isMoreComplete(vuln, existing) {
				vulnMap[key] = vuln
			}
		} else {
			vulnMap[key] = vuln
		}
	}

	// Convert back to slice
	result := make([]cyclonedx.Vulnerability, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		result = append(result, vuln)
	}

	return result
}

// createDeduplicationKey creates a composite key for vulnerability deduplication
func (m *AdvancedManager) createDeduplicationKey(vuln cyclonedx.Vulnerability) string {
	key := vuln.ID + "|" + vuln.BOMRef

	// Include affected component information if available
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		for _, affect := range *vuln.Affects {
			key += "|" + affect.Ref
		}
	}

	return key
}

// isMoreComplete determines if one vulnerability has more complete information than another
func (m *AdvancedManager) isMoreComplete(vuln1, vuln2 cyclonedx.Vulnerability) bool {
	score1 := m.calculateCompletenessScore(vuln1)
	score2 := m.calculateCompletenessScore(vuln2)
	return score1 > score2
}

// calculateCompletenessScore assigns a score based on vulnerability completeness
func (m *AdvancedManager) calculateCompletenessScore(vuln cyclonedx.Vulnerability) int {
	score := 0

	if vuln.Description != "" {
		score += 10
	}
	if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
		score += 15
	}
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		score += 10
	}
	if vuln.Recommendation != "" {
		score += 5
	}
	if vuln.Properties != nil && len(*vuln.Properties) > 0 {
		score += 5
	}

	return score
}

// computeBOMHash creates a hash for BOM caching
func (m *AdvancedManager) computeBOMHash(bom *cyclonedx.BOM) string {
	if bom == nil || bom.Components == nil {
		return "empty"
	}

	// Simple hash based on component count and first few component names
	hash := fmt.Sprintf("components_%d", len(*bom.Components))
	for i, comp := range *bom.Components {
		if i >= 5 { // Limit to first 5 components for hash
			break
		}
		hash += "_" + comp.Name + "_" + comp.Version
	}

	return hash
}

// groupComponentsByType pre-analyzes BOM components for efficient processing
func (m *AdvancedManager) groupComponentsByType(bom *cyclonedx.BOM) map[string]int {
	groups := make(map[string]int)

	if bom.Components == nil {
		return groups
	}

	for _, comp := range *bom.Components {
		if comp.Properties != nil {
			for _, prop := range *comp.Properties {
				if prop.Name == "component:type" {
					groups[prop.Value]++
					break
				}
			}
		}
	}

	return groups
}

// getScannerType extracts scanner type from scanner instance
func (m *AdvancedManager) getScannerType(scanner Scanner) string {
	// Use reflection or type assertion to get scanner type
	// This is a simplified implementation
	return fmt.Sprintf("%T", scanner)
}

// Cache methods
func (c *ResultCache) Get(key string) []cyclonedx.Vulnerability {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if vulns, exists := c.cache[key]; exists {
		if lastUsed, timeExists := c.lastUsed[key]; timeExists {
			if time.Since(lastUsed) < c.timeout {
				c.lastUsed[key] = time.Now() // Update last used time
				return vulns
			}
		}
	}

	return nil
}

func (c *ResultCache) Set(key string, vulnerabilities []cyclonedx.Vulnerability) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[key] = vulnerabilities
	c.lastUsed[key] = time.Now()
}

func (c *ResultCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache = make(map[string][]cyclonedx.Vulnerability)
	c.lastUsed = make(map[string]time.Time)
}

func (c *ResultCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return len(c.cache)
}
