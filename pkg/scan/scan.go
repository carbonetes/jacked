package scan

import (
	"context"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/scan/core"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
	"github.com/spf13/cobra"
)

// ScanType represents the type of scan being performed
type ScanType int

// Format represents the output format for scan results
type Format string

const (
	JSON         Format = "json"
	Table        Format = "table"
	SPDXJSON     Format = "spdx-json"
	SPDXXML      Format = "spdx-xml"
	SPDXTag      Format = "spdx-tag"
	SnapshotJSON Format = "snapshot-json"
)

// Parameters holds all scan parameters
type Parameters struct {
	Quiet          bool
	Format         Format
	File           string
	CI             bool
	SkipDBUpdate   bool
	ForceDBUpdate  bool
	ShowMetrics    bool // Add flag to show performance metrics
	NonInteractive bool // Add flag to control interactive mode

	// Diggity tool parameters to be passed to the scan engine
	Diggity diggity.Parameters
}

func (o Format) String() string {
	return string(o)
}

func GetAllOutputFormat() string {
	return strings.Join([]string{JSON.String(), Table.String(), SPDXJSON.String(), SPDXXML.String(), SPDXTag.String(), SnapshotJSON.String()}, ", ")
}

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

	// Register the matcher scanner which handles all ecosystems
	matcherScanner := NewMatcherScanner(store, nil)
	engine.RegisterScanner(matcherScanner)

	return &Manager{engine: engine}
}

// NewManagerWithOptions creates a new Manager with custom matching options
func NewManagerWithOptions(store db.Store, config *matchertypes.MatcherConfig) *Manager {
	// Use configuration from matcher config if provided, otherwise use defaults
	maxConcurrency := 4
	timeout := 5 * time.Minute
	enableCaching := true
	enableMetrics := false

	if config != nil {
		maxConcurrency = config.MaxConcurrency
		if timeoutDuration, err := time.ParseDuration(config.Timeout); err == nil {
			timeout = timeoutDuration
		}
		enableCaching = config.EnableCaching
		enableMetrics = config.EnableMetrics
	}

	coreConfig := core.ScanConfig{
		MaxConcurrency: maxConcurrency,
		Timeout:        timeout,
		EnableCaching:  enableCaching,
		EnableMetrics:  enableMetrics,
		CacheTTL:       15 * time.Minute,
	}

	engine := core.NewScanEngine(coreConfig)

	// Register the matcher scanner with custom configuration
	var matcherScanner *MatcherScanner
	if config != nil {
		matcherScanner = NewMatcherScannerWithConfig(store, config)
	} else {
		matcherScanner = NewMatcherScanner(store, nil)
	}

	engine.RegisterScanner(matcherScanner)

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

// CreateScanParameters creates and initializes the scan parameters
func CreateScanParameters(c *cobra.Command, args []string, quiet, ci bool, format, file string, skip, force bool, failCriteria string) Parameters {
	return Parameters{
		Format:         Format(format),
		Quiet:          quiet,
		File:           file,
		SkipDBUpdate:   skip,
		ForceDBUpdate:  force,
		CI:             ci,
		Diggity: diggity.Parameters{
			OutputFormat: diggity.JSON,
		},
	}
}

// ValidateInputAndSetup validates input parameters and sets up scan targets
func ValidateInputAndSetup(params *Parameters, tarball, filesystem string, args []string) bool {
	if filesystem != "" {
		if found, _ := helper.IsDirExists(filesystem); !found {
			log.Fatal("directory not found: " + filesystem)
			return false
		}
		params.Diggity.ScanType = 3
		params.Diggity.Input = filesystem
		return true
	}

	if tarball != "" {
		if found, _ := helper.IsFileExists(tarball); !found {
			log.Fatal("tarball not found: " + tarball)
			return false
		}
		params.Diggity.Input = tarball
		params.Diggity.ScanType = 2
		return true
	}

	// No filesystem or tarball specified, check for image argument
	return SetupImageTarget(params, args)
}

// SetupImageTarget sets up the image target if no filesystem or tarball is specified
func SetupImageTarget(params *Parameters, args []string) bool {
	if len(args) > 0 {
		params.Diggity.Input = helper.FormatImage(args[0])
		params.Diggity.ScanType = 1
		return true
	}
	return false
}

// ValidateFormat validates the output format type provided by the user and returns true if it is valid else false
func ValidateFormat(format Format) bool {
	switch Format(format) {
	case JSON, Table, SPDXJSON, SPDXXML, SPDXTag, SnapshotJSON:
		return true
	default:
		return false
	}
}
