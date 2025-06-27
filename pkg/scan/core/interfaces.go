package core

import (
	"context"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
)

// Scanner defines the core interface for vulnerability scanning
type Scanner interface {
	// Scan processes a BOM and returns vulnerabilities
	Scan(ctx context.Context, bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error)

	// Type returns the scanner type identifier
	Type() string

	// SupportsComponent checks if scanner can handle a component type
	SupportsComponent(componentType string) bool
}

// ExecutionStrategy defines how scanners are executed
type ExecutionStrategy interface {
	Execute(ctx context.Context, scanners []Scanner, bom *cyclonedx.BOM) ([]ScanResult, error)
}

// CacheProvider defines caching interface
type CacheProvider interface {
	Get(key string) ([]cyclonedx.Vulnerability, bool)
	Set(key string, vulnerabilities []cyclonedx.Vulnerability, ttl time.Duration)
	Clear()
	Size() int
}

// MetricsCollector defines metrics collection interface
type MetricsCollector interface {
	RecordScan(scannerType string, duration time.Duration, componentCount, vulnCount int)
	RecordError(scannerType string, err error)
	GetMetrics() map[string]interface{}
}

// VulnerabilityDeduplicator handles deduplication logic
type VulnerabilityDeduplicator interface {
	Deduplicate(vulnerabilities []cyclonedx.Vulnerability) []cyclonedx.Vulnerability
}

// ScanResult encapsulates scan results with metadata
type ScanResult struct {
	ScannerType     string                    `json:"scanner_type"`
	Vulnerabilities []cyclonedx.Vulnerability `json:"vulnerabilities"`
	Duration        time.Duration             `json:"duration"`
	ComponentCount  int                       `json:"component_count"`
	Error           error                     `json:"error,omitempty"`
}

// ScanConfig holds configuration for scanning operations
type ScanConfig struct {
	MaxConcurrency   int           `yaml:"max_concurrency"`
	Timeout          time.Duration `yaml:"timeout"`
	EnableCaching    bool          `yaml:"enable_caching"`
	EnableMetrics    bool          `yaml:"enable_metrics"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	DeduplicationKey string        `yaml:"deduplication_key"`
}

// ComponentFilter filters components based on criteria
type ComponentFilter interface {
	Filter(components []cyclonedx.Component) []cyclonedx.Component
	SupportsType(componentType string) bool
}
