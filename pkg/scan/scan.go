package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
)

// Scanner defines an interface for scanning a CDX BOM for vulnerabilities.
type Scanner interface {
	Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error)
}

// Manager manages multiple Scanner implementations with optimizations.
type Manager struct {
	scanners        []Scanner
	enableCaching   bool
	maxConcurrency  int
	timeout         time.Duration
	advancedManager *AdvancedManager
}

// NewManager creates a new Manager with the provided scanners and default optimizations.
func NewManager(scanners ...Scanner) *Manager {
	return &Manager{
		scanners:        scanners,
		enableCaching:   true,
		maxConcurrency:  4, // Reasonable default
		timeout:         5 * time.Minute,
		advancedManager: NewAdvancedManager(scanners...),
	}
}

// SetCaching enables or disables result caching
func (m *Manager) SetCaching(enabled bool) *Manager {
	m.enableCaching = enabled
	return m
}

// SetConcurrency sets maximum concurrent scanners
func (m *Manager) SetConcurrency(concurrency int) *Manager {
	m.maxConcurrency = concurrency
	if m.advancedManager != nil {
		m.advancedManager.SetConcurrency(concurrency)
	}
	return m
}

// SetTimeout sets the maximum timeout for scanning operations
func (m *Manager) SetTimeout(timeout time.Duration) *Manager {
	m.timeout = timeout
	if m.advancedManager != nil {
		m.advancedManager.SetTimeout(timeout)
	}
	return m
}

// Run executes all scanners with optimizations.
// If advanced features are enabled, uses AdvancedManager, otherwise falls back to basic implementation.
func (m *Manager) Run(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return []cyclonedx.Vulnerability{}, nil
	}

	start := time.Now()

	// Use advanced manager if caching is enabled or for large BOMs
	if m.enableCaching || len(*bom.Components) > 50 {
		log.Debug("Using advanced scanning manager")
		result, err := m.advancedManager.Run(bom)
		if err == nil {
			log.Debugf("Advanced scan completed in %v", time.Since(start))
			return result, nil
		}
		log.Debugf("Advanced scan failed, falling back to basic scanning: %v", err)
	}

	// Fallback to basic concurrent scanning
	return m.runBasicScanning(bom)
}

// runBasicScanning provides the original scanning logic with minor optimizations
func (m *Manager) runBasicScanning(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var (
		vulnerabilities []cyclonedx.Vulnerability
		mu              sync.Mutex
		wg              sync.WaitGroup
		errCh           = make(chan error, len(m.scanners))
		vulnCh          = make(chan []cyclonedx.Vulnerability, len(m.scanners))
	)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Launch each scanner in its own goroutine with controlled concurrency
	semaphore := make(chan struct{}, m.maxConcurrency)

	for _, scanner := range m.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			// Acquire semaphore for concurrency control
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Channel for scan result
			resultCh := make(chan []cyclonedx.Vulnerability, 1)
			errorCh := make(chan error, 1)

			// Run scan in separate goroutine for timeout control
			go func() {
				vulns, err := s.Scan(bom)
				if err != nil {
					errorCh <- err
					return
				}
				resultCh <- vulns
			}()

			// Wait for result or timeout
			select {
			case vulns := <-resultCh:
				vulnCh <- vulns
			case err := <-errorCh:
				errCh <- err
			case <-ctx.Done():
				errCh <- fmt.Errorf("scanner timeout: %v", ctx.Err())
			}
		}(scanner)
	}

	wg.Wait()
	close(errCh)
	close(vulnCh)

	// Check for errors from any scanner - log but don't fail entire scan
	errorCount := 0
	for err := range errCh {
		if err != nil {
			log.Debugf("Scanner error: %v", err)
			errorCount++
		}
	}

	if errorCount > 0 {
		log.Debugf("Encountered %d scanner errors, continuing with available results", errorCount)
	}

	// Collect vulnerabilities from all successful scanners
	allVulns := []cyclonedx.Vulnerability{}
	for vulns := range vulnCh {
		mu.Lock()
		allVulns = append(allVulns, vulns...)
		mu.Unlock()
	}

	// Enhanced deduplication
	vulnerabilities = m.deduplicateVulnerabilities(allVulns)

	log.Debugf("Basic scan completed: %d vulnerabilities found, %d after deduplication",
		len(allVulns), len(vulnerabilities))

	return vulnerabilities, nil
}

// deduplicateVulnerabilities provides improved deduplication logic
func (m *Manager) deduplicateVulnerabilities(vulnerabilities []cyclonedx.Vulnerability) []cyclonedx.Vulnerability {
	if len(vulnerabilities) == 0 {
		return vulnerabilities
	}

	vulnMap := make(map[string]cyclonedx.Vulnerability)

	for _, v := range vulnerabilities {
		// Create a more comprehensive deduplication key
		key := m.createVulnKey(v)

		// Keep the vulnerability with more information if duplicate exists
		if existing, exists := vulnMap[key]; exists {
			if m.hasMoreInfo(v, existing) {
				vulnMap[key] = v
			}
		} else {
			vulnMap[key] = v
		}
	}

	// Convert back to slice
	result := make([]cyclonedx.Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		result = append(result, v)
	}

	return result
}

// createVulnKey creates a comprehensive key for vulnerability deduplication
func (m *Manager) createVulnKey(vuln cyclonedx.Vulnerability) string {
	key := vuln.BOMRef + "|" + vuln.ID

	// Include source information if available in properties
	if vuln.Properties != nil {
		for _, prop := range *vuln.Properties {
			if prop.Name == "database:source" {
				key += "|" + prop.Value
			}
		}
	}

	return key
}

// hasMoreInfo determines if one vulnerability has more complete information
func (m *Manager) hasMoreInfo(v1, v2 cyclonedx.Vulnerability) bool {
	score1 := m.calculateInfoScore(v1)
	score2 := m.calculateInfoScore(v2)
	return score1 > score2
}

// calculateInfoScore calculates completeness score for vulnerability
func (m *Manager) calculateInfoScore(vuln cyclonedx.Vulnerability) int {
	score := 0

	if vuln.Description != "" {
		score += 3
	}
	if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
		score += 5
	}
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		score += 2
	}
	if vuln.Recommendation != "" {
		score += 2
	}
	if vuln.Properties != nil && len(*vuln.Properties) > 0 {
		score += 1
	}

	return score
}
