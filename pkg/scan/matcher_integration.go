package scan

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/matcher/processors"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// MatcherIntegrationConfig provides configuration for integrating the matcher processors
type MatcherIntegrationConfig struct {
	// Enable extended matcher
	EnableExtendedMatcher bool `json:"enable_extended_matcher"`

	// Matcher configuration
	MatcherConfig processors.ExtendedMatcherConfig `json:"matcher_config"`

	// Integration settings
	UseAsSupplementary bool `json:"use_as_supplementary"` // Use alongside existing matchers
	UseAsReplacement   bool `json:"use_as_replacement"`   // Replace existing matchers
}

// MatcherIntegration provides integration between the matcher processors and Jacked's architecture
type MatcherIntegration struct {
	store           db.Store
	extendedMatcher *processors.ExtendedVulnerabilityMatcher
	config          MatcherIntegrationConfig
}

// NewMatcherIntegration creates a new matcher integration
func NewMatcherIntegration(store db.Store, config MatcherIntegrationConfig) (*MatcherIntegration, error) {
	// Set default configuration if not provided
	if !config.EnableExtendedMatcher || config.MatcherConfig.MaxConcurrency == 0 {
		config.MatcherConfig = processors.ExtendedMatcherConfig{
			EnableCPEMatching:        true,
			EnableVEXProcessing:      false,
			EnableCVENormalization:   true,
			VEXDocumentPaths:         []string{},
			IgnoreRules:              []processors.DetailedIgnoreRule{},
			FailOnSeverity:           matchertypes.HighSeverity,
			MinSeverityFilter:        matchertypes.LowSeverity,
			MaxConcurrency:           4,
			Timeout:                  "5m",
			EnableProgressTrack:      true,
			EnableConfidenceScoring:  false,
			MinConfidenceThreshold:   0.7,
			EnableTargetSWValidation: true,
			EnableDeduplication:      true,
		}
	}

	// Create the extended matcher
	extendedMatcher, err := processors.NewExtendedVulnerabilityMatcher(config.MatcherConfig)
	if err != nil {
		return nil, err
	}

	integration := &MatcherIntegration{
		store:           store,
		extendedMatcher: extendedMatcher,
		config:          config,
	}

	// Setup ecosystem matchers from existing Jacked matchers
	if err := integration.setupEcosystemMatchers(); err != nil {
		return nil, err
	}

	return integration, nil
}

// setupEcosystemMatchers registers existing Jacked matchers with the feature matcher
func (m *MatcherIntegration) setupEcosystemMatchers() error {
	// Import existing matchers
	npmMatcher := mustCreateNPMMatcher(m.store)
	pythonMatcher := mustCreatePythonMatcher(m.store)
	mavenMatcher := mustCreateMavenMatcher(m.store)
	golangMatcher := mustCreateGolangMatcher(m.store)
	rubyMatcher := mustCreateRubyMatcher(m.store)
	dartMatcher := mustCreateDartMatcher(m.store)

	// Register with feature matcher
	m.extendedMatcher.RegisterEcosystemMatcher("npm", npmMatcher)
	m.extendedMatcher.RegisterEcosystemMatcher("python", pythonMatcher)
	m.extendedMatcher.RegisterEcosystemMatcher("maven", mavenMatcher)
	m.extendedMatcher.RegisterEcosystemMatcher("golang", golangMatcher)
	m.extendedMatcher.RegisterEcosystemMatcher("ruby", rubyMatcher)
	m.extendedMatcher.RegisterEcosystemMatcher("dart", dartMatcher)

	// For now, we'll skip CPE matcher setup as it requires more complex provider integration
	// This can be added later when proper vulnerability providers are implemented

	return nil
}

// GetExtendedMatcher returns the configured extended matcher
func (m *MatcherIntegration) GetExtendedMatcher() *processors.ExtendedVulnerabilityMatcher {
	return m.extendedMatcher
}

// Helper functions to create matchers safely
func mustCreateNPMMatcher(store db.Store) matchertypes.VulnerabilityMatcher {
	// Return a placeholder that implements the interface
	return &matcherAdapter{store: store, ecosystem: "npm"}
}

func mustCreatePythonMatcher(store db.Store) matchertypes.VulnerabilityMatcher {
	return &matcherAdapter{store: store, ecosystem: "python"}
}

func mustCreateMavenMatcher(store db.Store) matchertypes.VulnerabilityMatcher {
	return &matcherAdapter{store: store, ecosystem: "maven"}
}

func mustCreateGolangMatcher(store db.Store) matchertypes.VulnerabilityMatcher {
	return &matcherAdapter{store: store, ecosystem: "golang"}
}

func mustCreateRubyMatcher(store db.Store) matchertypes.VulnerabilityMatcher {
	return &matcherAdapter{store: store, ecosystem: "ruby"}
}

func mustCreateDartMatcher(store db.Store) matchertypes.VulnerabilityMatcher {
	return &matcherAdapter{store: store, ecosystem: "dart"}
}

// matcherAdapter provides a basic adapter for existing matchers
type matcherAdapter struct {
	store     db.Store
	ecosystem string
}

func (m *matcherAdapter) Type() matchertypes.MatcherType {
	return matchertypes.MatcherType(m.ecosystem + "-matcher")
}

func (m *matcherAdapter) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// This is a placeholder implementation - in practice, this would delegate to actual matchers
	// For now, return empty results to satisfy the interface
	return &matchertypes.MatchResults{
		Matches:        []matchertypes.Match{},
		IgnoredMatches: []matchertypes.IgnoredMatch{},
		Summary: matchertypes.MatchSummary{
			TotalPackages:      len(packages),
			PackagesWithVulns:  0,
			TotalMatches:       0,
			IgnoredMatches:     0,
			BySeverity:         make(map[string]int),
			ByFixState:         make(map[string]int),
			ExecutionTime:      "0s",
			MatcherPerformance: make(map[string]interface{}),
		},
	}, nil
}
