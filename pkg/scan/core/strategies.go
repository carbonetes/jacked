package core

import (
	"context"
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
)

// SequentialStrategy executes scanners one by one
type SequentialStrategy struct {
	timeout time.Duration
}

// NewSequentialStrategy creates a new sequential execution strategy
func NewSequentialStrategy(timeout time.Duration) *SequentialStrategy {
	return &SequentialStrategy{timeout: timeout}
}

// Execute runs scanners sequentially
func (s *SequentialStrategy) Execute(ctx context.Context, scanners []Scanner, bom *cyclonedx.BOM) ([]ScanResult, error) {
	results := make([]ScanResult, 0, len(scanners))

	for _, scanner := range scanners {
		scanCtx, cancel := context.WithTimeout(ctx, s.timeout)

		start := time.Now()
		vulns, err := scanner.Scan(scanCtx, bom)
		duration := time.Since(start)

		componentCount := 0
		if bom.Components != nil {
			componentCount = len(*bom.Components)
		}

		result := ScanResult{
			ScannerType:     scanner.Type(),
			Vulnerabilities: vulns,
			Duration:        duration,
			ComponentCount:  componentCount,
			Error:           err,
		}

		results = append(results, result)
		cancel()
	}

	return results, nil
}

// ExecuteAnalysis runs analyzers sequentially (not used in current implementation)
func (s *SequentialStrategy) ExecuteAnalysis(ctx context.Context, analyzers []Analyzer, sbom *cyclonedx.BOM) ([]AnalysisResult, error) {
	// Not implemented yet - placeholder for future analyzer support
	return []AnalysisResult{}, nil
}

// ConcurrentStrategy executes scanners concurrently with controlled parallelism
type ConcurrentStrategy struct {
	maxConcurrency int
	timeout        time.Duration
}

// NewConcurrentStrategy creates a new concurrent execution strategy
func NewConcurrentStrategy(maxConcurrency int, timeout time.Duration) *ConcurrentStrategy {
	return &ConcurrentStrategy{
		maxConcurrency: maxConcurrency,
		timeout:        timeout,
	}
}

// Execute runs scanners concurrently with controlled parallelism
func (s *ConcurrentStrategy) Execute(ctx context.Context, scanners []Scanner, bom *cyclonedx.BOM) ([]ScanResult, error) {
	results := make([]ScanResult, len(scanners))
	semaphore := make(chan struct{}, s.maxConcurrency)

	var wg sync.WaitGroup

	for i, scanner := range scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()

			start := time.Now()
			vulns, err := sc.Scan(scanCtx, bom)
			duration := time.Since(start)

			componentCount := 0
			if bom.Components != nil {
				componentCount = len(*bom.Components)
			}

			results[idx] = ScanResult{
				ScannerType:     sc.Type(),
				Vulnerabilities: vulns,
				Duration:        duration,
				ComponentCount:  componentCount,
				Error:           err,
			}
		}(i, scanner)
	}

	wg.Wait()
	return results, nil
}

// ExecuteAnalysis runs analyzers concurrently (not used in current implementation)
func (s *ConcurrentStrategy) ExecuteAnalysis(ctx context.Context, analyzers []Analyzer, sbom *cyclonedx.BOM) ([]AnalysisResult, error) {
	// Not implemented yet - placeholder for future analyzer support
	return []AnalysisResult{}, nil
}
