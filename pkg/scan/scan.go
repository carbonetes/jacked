package scan

import (
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
)

// Scanner defines an interface for scanning a CDX BOM for vulnerabilities.
type Scanner interface {
	Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error)
}

// Manager manages multiple Scanner implementations.
type Manager struct {
	scanners []Scanner // List of scanners to run.
}

// NewManager creates a new Manager with the provided scanners.
func NewManager(scanners ...Scanner) *Manager {
	return &Manager{
		scanners: scanners,
	}
}

// Run executes all scanners concurrently on the given BOM.
// It collects all vulnerabilities found and returns them.
// If any scanner returns an error, the function returns immediately with that error.
func (m *Manager) Run(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var (
		vulnerabilities []cyclonedx.Vulnerability                               // Aggregated vulnerabilities from all scanners.
		mu              sync.Mutex                                              // Protects access to vulnerabilities slice.
		wg              sync.WaitGroup                                          // Waits for all scanners to finish.
		errCh           = make(chan error, len(m.scanners))                     // Collects errors from scanners.
		vulnCh          = make(chan []cyclonedx.Vulnerability, len(m.scanners)) // Collects vulnerabilities from scanners.
	)

	// Launch each scanner in its own goroutine.
	for _, scanner := range m.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			vulns, err := s.Scan(bom)
			if err != nil {
				errCh <- err // Send error if scan fails.
				return
			}
			vulnCh <- vulns // Send found vulnerabilities.
		}(scanner)
	}

	wg.Wait()     // Wait for all scanners to finish.
	close(errCh)  // No more errors will be sent.
	close(vulnCh) // No more vulnerabilities will be sent.

	// Check for errors from any scanner.
	for err := range errCh {
		if err != nil {
			log.Debugf("error during scan: %v", err)
			return nil, err // Return immediately on first error. (Subject to change based on error handling policy)
		}
	}

	// Collect vulnerabilities from all scanners.
	allVulns := []cyclonedx.Vulnerability{}
	for vulns := range vulnCh {
		mu.Lock()
		allVulns = append(allVulns, vulns...)
		mu.Unlock()
	}

	// Deduplicate vulnerabilities globally.
	vulnMap := make(map[string]cyclonedx.Vulnerability)
	for _, v := range allVulns {
		vulnMap[v.BOMRef+v.ID] = v
	}
	vulnerabilities = make([]cyclonedx.Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities, nil // Return all collected vulnerabilities.
}
