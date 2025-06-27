package scan

import (
	"context"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/core"
	"github.com/carbonetes/jacked/pkg/scan/factory"
)

// Manager provides backward compatibility with the new scanning architecture
type Manager struct {
	engine *core.ScanEngine
}

// Scanner defines an interface for scanning a CDX BOM for vulnerabilities (for backward compatibility)
type Scanner interface {
	Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error)
}

// NewManager creates a new Manager with the provided store and default optimizations
func NewManager(store db.Store) *Manager {
	config := core.ScanConfig{
		MaxConcurrency: 4,
		Timeout:        5 * time.Minute,
		EnableCaching:  true,
		EnableMetrics:  false,
		CacheTTL:       15 * time.Minute,
	}

	engine := core.NewScanEngine(config)

	// Register all scanners using the factory
	scannerFactory := factory.NewScannerFactory(store)
	scanners := scannerFactory.CreateAllScanners()

	for _, scanner := range scanners {
		engine.RegisterScanner(scanner)
	}

	return &Manager{engine: engine}
}

// SetCaching enables or disables result caching
func (m *Manager) SetCaching(enabled bool) *Manager {
	if enabled {
		cache := core.NewMemoryCache(15 * time.Minute)
		m.engine.SetCacheProvider(cache)
	} else {
		m.engine.SetCacheProvider(nil)
	}
	return m
}

// SetConcurrency sets maximum concurrent scanners
func (m *Manager) SetConcurrency(concurrency int) *Manager {
	if concurrency > 1 {
		strategy := core.NewConcurrentStrategy(concurrency, 5*time.Minute)
		m.engine.SetExecutionStrategy(strategy)
	} else {
		strategy := core.NewSequentialStrategy(5 * time.Minute)
		m.engine.SetExecutionStrategy(strategy)
	}
	return m
}

// SetTimeout sets the maximum timeout for scanning operations
func (m *Manager) SetTimeout(timeout time.Duration) *Manager {
	// Create new strategy with updated timeout
	config := core.ScanConfig{
		MaxConcurrency: 4,
		Timeout:        timeout,
		EnableCaching:  true,
		EnableMetrics:  false,
		CacheTTL:       15 * time.Minute,
	}

	if config.MaxConcurrency > 1 {
		strategy := core.NewConcurrentStrategy(config.MaxConcurrency, timeout)
		m.engine.SetExecutionStrategy(strategy)
	} else {
		strategy := core.NewSequentialStrategy(timeout)
		m.engine.SetExecutionStrategy(strategy)
	}

	return m
}

// Run executes all scanners with optimizations (backward compatibility method)
func (m *Manager) Run(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	ctx := context.Background()
	return m.engine.Scan(ctx, bom)
}

// GetMetrics returns collected metrics
func (m *Manager) GetMetrics() map[string]interface{} {
	return m.engine.GetMetrics()
}

// GetCacheStats returns cache statistics
func (m *Manager) GetCacheStats() map[string]interface{} {
	return m.engine.GetCacheStats()
}
