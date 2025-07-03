package processors

import (
	"context"
	"fmt"
	"time"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// ExtendedVulnerabilityMatcher provides enhanced vulnerability matching capabilities
// inspired by Grype's sophisticated strategies
type ExtendedVulnerabilityMatcher struct {
	// Core components
	ecosystemMatchers map[string]matchertypes.VulnerabilityMatcher
	cpeMatchers       map[string]*CPEMatcher
	stockMatcher      *CPEMatcher

	// Processors
	vexProcessor      *VEXProcessor
	ignoreProcessor   *IgnoreRuleProcessor
	severityProcessor *SeverityThresholdProcessor
	cveNormalizer     *CVENormalizer

	// Configuration
	config ExtendedMatcherConfig
}

// ExtendedMatcherConfig provides configuration for extended matching processors
type ExtendedMatcherConfig struct {
	// Basic settings
	EnableCPEMatching      bool `json:"enable_cpe_matching"`
	EnableVEXProcessing    bool `json:"enable_vex_processing"`
	EnableCVENormalization bool `json:"enable_cve_normalization"`

	// VEX settings
	VEXDocumentPaths []string `json:"vex_document_paths"`

	// Ignore rules
	IgnoreRules []DetailedIgnoreRule `json:"ignore_rules"`

	// Severity settings
	FailOnSeverity    matchertypes.Severity `json:"fail_on_severity"`
	MinSeverityFilter matchertypes.Severity `json:"min_severity_filter"`

	// Performance settings
	MaxConcurrency      int    `json:"max_concurrency"`
	Timeout             string `json:"timeout"`
	EnableProgressTrack bool   `json:"enable_progress_track"`

	// Quality settings
	EnableConfidenceScoring bool    `json:"enable_confidence_scoring"`
	MinConfidenceThreshold  float64 `json:"min_confidence_threshold"`

	// Target software validation
	EnableTargetSWValidation bool `json:"enable_target_sw_validation"`

	// Deduplication
	EnableDeduplication bool `json:"enable_deduplication"`
}

// NewExtendedVulnerabilityMatcher creates a new advanced vulnerability matcher
func NewExtendedVulnerabilityMatcher(config ExtendedMatcherConfig) (*ExtendedVulnerabilityMatcher, error) {
	matcher := &ExtendedVulnerabilityMatcher{
		ecosystemMatchers: make(map[string]matchertypes.VulnerabilityMatcher),
		cpeMatchers:       make(map[string]*CPEMatcher),
		config:            config,
	}

	// Initialize advanced processors
	if err := matcher.initializeProcessors(); err != nil {
		return nil, fmt.Errorf("failed to initialize processors: %w", err)
	}

	return matcher, nil
}

// initializeProcessors initializes all advanced processing components
func (m *ExtendedVulnerabilityMatcher) initializeProcessors() error {
	// Initialize VEX processor
	if m.config.EnableVEXProcessing {
		vexOptions := VEXProcessorOptions{
			DocumentPaths: m.config.VEXDocumentPaths,
			EnableLogging: true,
		}
		var err error
		m.vexProcessor, err = NewVEXProcessor(vexOptions)
		if err != nil {
			return fmt.Errorf("failed to initialize VEX processor: %w", err)
		}
	}

	// Initialize ignore rule processor
	m.ignoreProcessor = NewIgnoreRuleProcessor(m.config.IgnoreRules)

	// Initialize severity processor
	m.severityProcessor = NewSeverityThresholdProcessor(m.config.FailOnSeverity)

	// Initialize CVE normalizer
	m.cveNormalizer = NewCVENormalizer(m.config.EnableCVENormalization)

	return nil
}

// RegisterEcosystemMatcher registers a matcher for a specific ecosystem
func (m *ExtendedVulnerabilityMatcher) RegisterEcosystemMatcher(ecosystem string, matcher matchertypes.VulnerabilityMatcher) {
	m.ecosystemMatchers[ecosystem] = matcher
}

// RegisterCPEMatcher registers a CPE-based matcher for a specific ecosystem
func (m *ExtendedVulnerabilityMatcher) RegisterCPEMatcher(ecosystem string, matcher *CPEMatcher) {
	m.cpeMatchers[ecosystem] = matcher
}

// SetStockMatcher sets the default/stock matcher for fallback scenarios
func (m *ExtendedVulnerabilityMatcher) SetStockMatcher(matcher *CPEMatcher) {
	m.stockMatcher = matcher
}

// Type returns the matcher type
func (m *ExtendedVulnerabilityMatcher) Type() matchertypes.MatcherType {
	return "advanced-vulnerability-matcher"
}

// FindMatches performs comprehensive vulnerability matching with advanced strategies
func (m *ExtendedVulnerabilityMatcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	startTime := time.Now()

	// Phase 1: Database matching
	allMatches, err := m.searchDBForMatches(ctx, packages, opts)
	if err != nil {
		return nil, fmt.Errorf("database search failed: %w", err)
	}

	// Phase 2: Apply ignore rules
	filteredMatches, ignoredMatches := m.ignoreProcessor.ApplyIgnoreRules(allMatches)

	// Phase 3: Apply VEX processing if enabled
	if m.vexProcessor != nil {
		vexFiltered, vexIgnored, err := m.vexProcessor.ApplyVEX(ctx, filteredMatches)
		if err != nil {
			return nil, fmt.Errorf("VEX processing failed: %w", err)
		}
		filteredMatches = vexFiltered
		ignoredMatches = append(ignoredMatches, vexIgnored...)
	}

	// Phase 4: Normalize by CVE if enabled
	if m.config.EnableCVENormalization {
		filteredMatches = m.cveNormalizer.NormalizeMatches(filteredMatches)
	}

	// Phase 5: Apply severity filtering
	if m.config.MinSeverityFilter != "" {
		filteredMatches = m.severityProcessor.FilterBySeverity(filteredMatches, m.config.MinSeverityFilter)
	}

	// Phase 6: Enhance matches with severity information
	filteredMatches = m.severityProcessor.EnhanceMatchesWithSeverity(filteredMatches)

	// Phase 7: Apply confidence filtering if enabled
	if m.config.EnableConfidenceScoring {
		filteredMatches = m.filterByConfidence(filteredMatches)
	}

	// Phase 8: Deduplicate if enabled
	if m.config.EnableDeduplication {
		filteredMatches = m.deduplicateMatches(filteredMatches)
	}

	// Phase 9: Check severity threshold
	if err := m.severityProcessor.CheckSeverityThreshold(filteredMatches); err != nil {
		return nil, err
	}

	// Build comprehensive results
	results := &matchertypes.MatchResults{
		Matches:        filteredMatches,
		IgnoredMatches: ignoredMatches,
		Summary: matchertypes.MatchSummary{
			TotalPackages:      len(packages),
			PackagesWithVulns:  m.countPackagesWithVulns(filteredMatches),
			TotalMatches:       len(filteredMatches),
			IgnoredMatches:     len(ignoredMatches),
			BySeverity:         m.severityProcessor.GetSeverityDistribution(filteredMatches),
			ByFixState:         m.getFixStateDistribution(filteredMatches),
			ExecutionTime:      time.Since(startTime).String(),
			MatcherPerformance: m.getMatcherPerformance(),
		},
	}

	return results, nil
}

// searchDBForMatches performs database searches using multiple strategies
func (m *ExtendedVulnerabilityMatcher) searchDBForMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) ([]matchertypes.Match, error) {
	var allMatches []matchertypes.Match

	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		packageMatches := m.findMatchesForPackage(ctx, pkg, opts)
		allMatches = append(allMatches, packageMatches...)
	}

	return allMatches, nil
}

// findMatchesForPackage finds all matches for a single package using available strategies
func (m *ExtendedVulnerabilityMatcher) findMatchesForPackage(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) []matchertypes.Match {
	var matches []matchertypes.Match

	// Strategy 1: Ecosystem-specific matcher
	if ecosystemMatches := m.tryEcosystemMatcher(ctx, pkg, opts); len(ecosystemMatches) > 0 {
		matches = append(matches, ecosystemMatches...)
	}

	// Strategy 2: CPE-based matching
	if cpeMatches := m.tryCPEMatching(ctx, pkg, opts); len(cpeMatches) > 0 {
		matches = append(matches, cpeMatches...)
	}

	// Strategy 3: Fallback to stock matcher
	if stockMatches := m.tryStockMatcher(ctx, pkg, opts); len(stockMatches) > 0 {
		matches = append(matches, stockMatches...)
	}

	return matches
}

// tryEcosystemMatcher attempts to use ecosystem-specific matcher
func (m *ExtendedVulnerabilityMatcher) tryEcosystemMatcher(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) []matchertypes.Match {
	ecosystemMatcher, exists := m.ecosystemMatchers[pkg.Ecosystem]
	if !exists {
		return nil
	}

	matches, err := m.callEcosystemMatcher(ctx, ecosystemMatcher, pkg, opts)
	if err != nil {
		// Log error but continue with other strategies
		return nil
	}

	return matches
}

// tryCPEMatching attempts CPE-based matching if enabled
func (m *ExtendedVulnerabilityMatcher) tryCPEMatching(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) []matchertypes.Match {
	if !m.config.EnableCPEMatching {
		return nil
	}

	matches, err := m.performCPEMatching(ctx, pkg, opts)
	if err != nil {
		// Log error but continue with other strategies
		return nil
	}

	return matches
}

// tryStockMatcher attempts fallback to stock matcher if no ecosystem matcher exists
func (m *ExtendedVulnerabilityMatcher) tryStockMatcher(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) []matchertypes.Match {
	// Only use stock matcher if no ecosystem-specific matcher exists
	if _, exists := m.ecosystemMatchers[pkg.Ecosystem]; exists {
		return nil
	}

	if m.stockMatcher == nil {
		return nil
	}

	stockResults, err := m.stockMatcher.FindMatches(ctx, []matchertypes.Package{pkg}, opts)
	if err != nil {
		// Log error but continue
		return nil
	}

	return stockResults.Matches
}

// callEcosystemMatcher safely calls an ecosystem-specific matcher
func (m *ExtendedVulnerabilityMatcher) callEcosystemMatcher(ctx context.Context, matcher matchertypes.VulnerabilityMatcher, pkg matchertypes.Package, opts matchertypes.MatchOptions) ([]matchertypes.Match, error) {
	// Call the matcher with a single package
	results, err := matcher.FindMatches(ctx, []matchertypes.Package{pkg}, opts)
	if err != nil {
		return nil, err
	}
	return results.Matches, nil
}

// performCPEMatching performs CPE-based vulnerability matching
func (m *ExtendedVulnerabilityMatcher) performCPEMatching(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) ([]matchertypes.Match, error) {
	// Try ecosystem-specific CPE matcher first
	if cpeMatcher, exists := m.cpeMatchers[pkg.Ecosystem]; exists {
		results, err := cpeMatcher.FindMatches(ctx, []matchertypes.Package{pkg}, opts)
		if err != nil {
			return nil, err
		}
		return results.Matches, nil
	}

	// Fallback to stock CPE matcher
	if m.stockMatcher != nil {
		results, err := m.stockMatcher.FindMatches(ctx, []matchertypes.Package{pkg}, opts)
		if err != nil {
			return nil, err
		}
		return results.Matches, nil
	}

	return []matchertypes.Match{}, nil
}

// filterByConfidence filters matches based on confidence scores
func (m *ExtendedVulnerabilityMatcher) filterByConfidence(matches []matchertypes.Match) []matchertypes.Match {
	var filtered []matchertypes.Match

	for _, match := range matches {
		avgConfidence := m.calculateAverageConfidence(match.Details)
		if avgConfidence >= m.config.MinConfidenceThreshold {
			filtered = append(filtered, match)
		}
	}

	return filtered
}

// calculateAverageConfidence calculates average confidence from match details
func (m *ExtendedVulnerabilityMatcher) calculateAverageConfidence(details []matchertypes.MatchDetail) float64 {
	if len(details) == 0 {
		return 0.0
	}

	total := 0.0
	for _, detail := range details {
		total += detail.Confidence
	}

	return total / float64(len(details))
}

// deduplicateMatches removes duplicate matches
func (m *ExtendedVulnerabilityMatcher) deduplicateMatches(matches []matchertypes.Match) []matchertypes.Match {
	seen := make(map[string]bool)
	var deduplicated []matchertypes.Match

	for _, match := range matches {
		key := fmt.Sprintf("%s:%s:%s", match.Vulnerability.ID, match.Package.ID, match.Package.Version)
		if !seen[key] {
			deduplicated = append(deduplicated, match)
			seen[key] = true
		}
	}

	return deduplicated
}

// Helper methods for result statistics
func (m *ExtendedVulnerabilityMatcher) countPackagesWithVulns(matches []matchertypes.Match) int {
	packages := make(map[string]bool)
	for _, match := range matches {
		packages[match.Package.ID] = true
	}
	return len(packages)
}

func (m *ExtendedVulnerabilityMatcher) getFixStateDistribution(matches []matchertypes.Match) map[string]int {
	distribution := make(map[string]int)
	for _, match := range matches {
		state := string(match.Vulnerability.Fix.State)
		distribution[state]++
	}
	return distribution
}

func (m *ExtendedVulnerabilityMatcher) getMatcherPerformance() map[string]interface{} {
	return map[string]interface{}{
		"ecosystem_matchers": len(m.ecosystemMatchers),
		"cpe_matchers":       len(m.cpeMatchers),
		"vex_enabled":        m.vexProcessor != nil,
		"cve_normalization":  m.config.EnableCVENormalization,
	}
}
