package matcher

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Import the basic types we need directly
type (
	Package          = matchertypes.Package
	MatchOptions     = matchertypes.MatchOptions
	MatchResults     = matchertypes.MatchResults
	MatcherType      = matchertypes.MatcherType
	MatcherConfig    = matchertypes.MatcherConfig
	Severity         = matchertypes.Severity
	Match            = matchertypes.Match
	Vulnerability    = matchertypes.Vulnerability
	PackageType      = matchertypes.PackageType
	IgnoredMatch     = matchertypes.IgnoredMatch
	IgnoreRule       = matchertypes.IgnoreRule
	MatchSummary     = matchertypes.MatchSummary
	MatchDetail      = matchertypes.MatchDetail
	VulnerabilityRef = matchertypes.VulnerabilityRef
)

// Engine is the main vulnerability matching orchestrator
type Engine struct {
	provider         *dummyProvider // temporary placeholder
	matchers         []matchertypes.VulnerabilityMatcher
	exclusionFilters []ExclusionFilter
	config           matchertypes.MatcherConfig
}

// temporary dummy types to avoid interface conflicts
type dummyProvider struct{}

// ExclusionFilter defines interface for excluding matches
type ExclusionFilter interface {
	ShouldExclude(match Match) bool
}

// NewEngine creates a new vulnerability matching engine
func NewEngine(config matchertypes.MatcherConfig) *Engine {
	return &Engine{
		provider:         &dummyProvider{},
		matchers:         make([]matchertypes.VulnerabilityMatcher, 0),
		exclusionFilters: make([]ExclusionFilter, 0),
		config:           config,
	}
}

// RegisterMatcher adds a vulnerability matcher to the engine
func (e *Engine) RegisterMatcher(matcher matchertypes.VulnerabilityMatcher) {
	e.matchers = append(e.matchers, matcher)
}

// RegisterExclusionFilter adds an exclusion filter to the engine
func (e *Engine) RegisterExclusionFilter(filter ExclusionFilter) {
	e.exclusionFilters = append(e.exclusionFilters, filter)
}

// FindMatches processes packages and finds vulnerability matches
func (e *Engine) FindMatches(ctx context.Context, packages []Package, opts MatchOptions) (*MatchResults, error) {
	startTime := time.Now()

	// Create progress monitor
	monitor := newProgressMonitor(len(packages), opts.EnableProgressTrack)
	defer monitor.SetCompleted()

	// Initialize results
	results := &MatchResults{
		Matches:        make([]Match, 0),
		IgnoredMatches: make([]IgnoredMatch, 0),
		Summary: MatchSummary{
			TotalPackages:      len(packages),
			BySeverity:         make(map[string]int),
			ByFixState:         make(map[string]int),
			MatcherPerformance: make(map[string]interface{}),
		},
	}

	// Search for matches in the database
	allMatches, err := e.searchDBForMatches(ctx, packages, monitor, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search database for matches: %w", err)
	}

	// Apply ignore rules
	matches, ignoredMatches := e.applyIgnoreRules(allMatches, opts.IgnoreRules)

	// Normalize by CVE if requested
	if opts.NormalizeByCVE || e.config.NormalizeByCVE {
		matches = e.normalizeByCVE(matches)
	}

	// Deduplicate results if enabled
	if opts.DeduplicateResults || e.config.DeduplicateResults {
		matches = e.deduplicateMatches(matches)
	}

	// Check severity threshold
	if opts.FailSeverity != nil {
		if e.hasSeverityAtOrAbove(*opts.FailSeverity, matches) {
			return nil, NewSeverityThresholdError(*opts.FailSeverity)
		}
	}

	// Populate results
	results.Matches = matches
	results.IgnoredMatches = ignoredMatches
	results.Summary.TotalMatches = len(matches)
	results.Summary.IgnoredMatches = len(ignoredMatches)
	results.Summary.ExecutionTime = time.Since(startTime).String()

	// Calculate packages with vulnerabilities
	packageSet := make(map[string]struct{})
	for _, match := range matches {
		packageSet[match.Package.ID] = struct{}{}
	}
	results.Summary.PackagesWithVulns = len(packageSet)

	// Calculate severity and fix state summaries
	e.calculateSummaryStats(results)

	log.Debugf("vulnerability matching completed: found %d matches across %d packages",
		len(matches), len(packages))

	return results, nil
}

// searchDBForMatches searches the vulnerability database for matches
func (e *Engine) searchDBForMatches(ctx context.Context, packages []Package, monitor *progressMonitor, opts MatchOptions) ([]Match, error) {
	var allMatches []Match
	var matcherErrs []error

	// Create matcher index for efficient lookup
	matcherIndex := e.createMatcherIndex()

	// Get default matcher if available
	defaultMatcher := e.getDefaultMatcher()

	for _, pkg := range packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		monitor.PackagesProcessed.Increment()
		log.Debugf("searching for vulnerability matches for package %s@%s", pkg.Name, pkg.Version)

		// Determine which matchers to use for this package
		matchersToUse := e.getMatchersForPackage(pkg, matcherIndex, defaultMatcher, opts)

		for _, matcher := range matchersToUse {
			matches, err := e.callMatcherSafely(ctx, matcher, pkg)
			if err != nil {
				if IsFatalError(err) {
					return nil, err
				}
				log.Warnf("matcher %s returned error for package %s: %v", matcher.Type(), pkg.Name, err)
				matcherErrs = append(matcherErrs, err)
				continue
			}

			// Apply exclusion filters
			filteredMatches := e.applyExclusionFilters(matches)

			allMatches = append(allMatches, filteredMatches...)
			monitor.MatchesDiscovered.Add(int64(len(filteredMatches)))

			e.logPackageMatches(pkg, filteredMatches)
		}
	}

	// Update final counts
	monitor.MatchesDiscovered.Set(int64(len(allMatches)))

	if len(matcherErrs) > 0 {
		return allMatches, errors.Join(matcherErrs...)
	}

	return allMatches, nil
}

// createMatcherIndex creates an index of matchers by package type
func (e *Engine) createMatcherIndex() map[PackageType][]matchertypes.VulnerabilityMatcher {
	index := make(map[PackageType][]matchertypes.VulnerabilityMatcher)

	for _, matcher := range e.matchers {
		// For now, we'll use a simple mapping - this could be enhanced with more sophisticated logic
		switch matcher.Type() {
		case matchertypes.NPMMatcherType:
			index[matchertypes.NPMPkg] = append(index[matchertypes.NPMPkg], matcher)
		case matchertypes.GoMatcherType:
			index[matchertypes.GoPkg] = append(index[matchertypes.GoPkg], matcher)
		case matchertypes.MavenMatcherType:
			index[matchertypes.JavaPkg] = append(index[matchertypes.JavaPkg], matcher)
		case matchertypes.PythonMatcherType:
			index[matchertypes.PythonPkg] = append(index[matchertypes.PythonPkg], matcher)
		case matchertypes.RubyGemMatcherType:
			index[matchertypes.GemPkg] = append(index[matchertypes.GemPkg], matcher)
		case matchertypes.APKMatcherType:
			index[matchertypes.APKPkg] = append(index[matchertypes.APKPkg], matcher)
		case matchertypes.DpkgMatcherType:
			index[matchertypes.DebPkg] = append(index[matchertypes.DebPkg], matcher)
		case matchertypes.RPMMatcherType:
			index[matchertypes.RPMPkg] = append(index[matchertypes.RPMPkg], matcher)
		}
	}

	return index
}

// getDefaultMatcher returns the stock/default matcher
func (e *Engine) getDefaultMatcher() matchertypes.VulnerabilityMatcher {
	for _, matcher := range e.matchers {
		if matcher.Type() == matchertypes.StockMatcherType {
			return matcher
		}
	}
	return nil
}

// getMatchersForPackage determines which matchers to use for a specific package
func (e *Engine) getMatchersForPackage(pkg Package, index map[PackageType][]matchertypes.VulnerabilityMatcher, defaultMatcher matchertypes.VulnerabilityMatcher, opts MatchOptions) []matchertypes.VulnerabilityMatcher {
	var matchers []matchertypes.VulnerabilityMatcher

	// Check if there are specific matchers for this package type
	if typeMatchers, exists := index[pkg.Type]; exists {
		matchers = append(matchers, typeMatchers...)
	}

	// Add default matcher if no specific matchers found
	if len(matchers) == 0 && defaultMatcher != nil {
		matchers = append(matchers, defaultMatcher)
	}

	// Filter by enabled/disabled matchers
	return e.filterMatchersByOptions(matchers, opts)
}

// filterMatchersByOptions filters matchers based on match options
func (e *Engine) filterMatchersByOptions(matchers []matchertypes.VulnerabilityMatcher, opts MatchOptions) []matchertypes.VulnerabilityMatcher {
	if len(opts.EnabledMatchers) > 0 {
		var filtered []matchertypes.VulnerabilityMatcher
		for _, matcher := range matchers {
			if slices.Contains(opts.EnabledMatchers, matcher.Type()) {
				filtered = append(filtered, matcher)
			}
		}
		return filtered
	}

	if len(opts.DisabledMatchers) > 0 {
		var filtered []matchertypes.VulnerabilityMatcher
		for _, matcher := range matchers {
			if !slices.Contains(opts.DisabledMatchers, matcher.Type()) {
				filtered = append(filtered, matcher)
			}
		}
		return filtered
	}

	return matchers
}

// callMatcherSafely calls a matcher with panic recovery
func (e *Engine) callMatcherSafely(ctx context.Context, matcher matchertypes.VulnerabilityMatcher, pkg Package) ([]Match, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("matcher %s panicked for package %s: %v", matcher.Type(), pkg.Name, r)
		}
	}()

	// Create match options for the specific matcher
	opts := MatchOptions{
		CPEMatching:    e.config.CPEMatching,
		MaxConcurrency: 1, // Individual matcher calls should be sequential
		Timeout:        e.config.Timeout,
	}

	result, err := matcher.FindMatches(ctx, []Package{pkg}, opts)
	if err != nil {
		return nil, err
	}

	return result.Matches, nil
}

// applyExclusionFilters applies exclusion filters to matches
func (e *Engine) applyExclusionFilters(matches []Match) []Match {
	if len(e.exclusionFilters) == 0 {
		return matches
	}

	var filtered []Match
	for _, match := range matches {
		excluded := false
		for _, filter := range e.exclusionFilters {
			if filter.ShouldExclude(match) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, match)
		}
	}

	return filtered
}

// applyIgnoreRules applies ignore rules to matches
func (e *Engine) applyIgnoreRules(matches []Match, userRules []IgnoreRule) ([]Match, []IgnoredMatch) {
	allRules := append(e.config.DefaultIgnoreRules, userRules...)
	if len(allRules) == 0 {
		return matches, nil
	}

	var filteredMatches []Match
	var ignoredMatches []IgnoredMatch

	for _, match := range matches {
		var appliedRules []IgnoreRule

		for _, rule := range allRules {
			if e.matchesIgnoreRule(match, rule) {
				appliedRules = append(appliedRules, rule)
			}
		}

		if len(appliedRules) > 0 {
			ignoredMatches = append(ignoredMatches, IgnoredMatch{
				Match:              match,
				AppliedIgnoreRules: appliedRules,
			})
		} else {
			filteredMatches = append(filteredMatches, match)
		}
	}

	return filteredMatches, ignoredMatches
}

// matchesIgnoreRule checks if a match should be ignored based on a rule
func (e *Engine) matchesIgnoreRule(match Match, rule IgnoreRule) bool {
	if rule.Vulnerability != "" && !strings.EqualFold(match.Vulnerability.ID, rule.Vulnerability) {
		return false
	}

	if rule.Package != "" && !strings.EqualFold(match.Package.Name, rule.Package) {
		return false
	}

	if rule.Namespace != "" && !strings.EqualFold(match.Vulnerability.Namespace, rule.Namespace) {
		return false
	}

	if rule.FixState != "" && !strings.EqualFold(string(match.Vulnerability.Fix.State), rule.FixState) {
		return false
	}

	if rule.Language != "" && !strings.EqualFold(string(match.Package.Language), rule.Language) {
		return false
	}

	// Add location-based matching if needed
	if rule.Locations != "" {
		// Implementation depends on location matching requirements
	}

	return true
}

// normalizeByCVE normalizes matches by CVE ID
func (e *Engine) normalizeByCVE(matches []Match) []Match {
	// Group matches by CVE
	cveMatches := make(map[string][]Match)
	var nonCVEMatches []Match

	for _, match := range matches {
		if e.isCVE(match.Vulnerability.ID) {
			cveMatches[match.Vulnerability.ID] = append(cveMatches[match.Vulnerability.ID], match)
		} else {
			// Check if there are related CVE vulnerabilities
			for _, related := range match.Vulnerability.RelatedVulnerabilities {
				if e.isCVE(related.ID) {
					// Create a normalized match with CVE as primary
					normalizedMatch := match
					normalizedMatch.Vulnerability.ID = related.ID
					normalizedMatch.Vulnerability.Namespace = related.Namespace
					cveMatches[related.ID] = append(cveMatches[related.ID], normalizedMatch)
					goto nextMatch
				}
			}
			nonCVEMatches = append(nonCVEMatches, match)
		nextMatch:
		}
	}

	// Combine normalized matches
	var result []Match
	for _, matches := range cveMatches {
		if len(matches) == 1 {
			result = append(result, matches[0])
		} else {
			// Merge multiple matches for the same CVE
			merged := e.mergeMatches(matches)
			result = append(result, merged)
		}
	}

	result = append(result, nonCVEMatches...)
	return result
}

// isCVE checks if an ID is a CVE identifier
func (e *Engine) isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}

// mergeMatches merges multiple matches for the same vulnerability
func (e *Engine) mergeMatches(matches []Match) Match {
	if len(matches) == 0 {
		return Match{}
	}

	base := matches[0]

	// Merge details from all matches
	var allDetails []MatchDetail
	for _, match := range matches {
		allDetails = append(allDetails, match.Details...)
	}
	base.Details = allDetails

	// Merge related vulnerabilities
	relatedMap := make(map[string]VulnerabilityRef)
	for _, match := range matches {
		for _, related := range match.Vulnerability.RelatedVulnerabilities {
			relatedMap[related.ID] = related
		}
	}

	var relatedSlice []VulnerabilityRef
	for _, related := range relatedMap {
		relatedSlice = append(relatedSlice, related)
	}
	base.Vulnerability.RelatedVulnerabilities = relatedSlice

	return base
}

// deduplicateMatches removes duplicate matches
func (e *Engine) deduplicateMatches(matches []Match) []Match {
	seen := make(map[string]struct{})
	var deduplicated []Match

	for _, match := range matches {
		key := fmt.Sprintf("%s|%s|%s", match.Vulnerability.ID, match.Package.ID, match.Package.Version)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			deduplicated = append(deduplicated, match)
		}
	}

	return deduplicated
}

// hasSeverityAtOrAbove checks if any match has severity at or above threshold
func (e *Engine) hasSeverityAtOrAbove(threshold Severity, matches []Match) bool {
	severityOrder := map[Severity]int{
		matchertypes.UnknownSeverity:  0,
		matchertypes.LowSeverity:      1,
		matchertypes.MediumSeverity:   2,
		matchertypes.HighSeverity:     3,
		matchertypes.CriticalSeverity: 4,
	}

	thresholdValue := severityOrder[threshold]

	for _, match := range matches {
		if severity, exists := match.Vulnerability.Metadata["severity"]; exists {
			if sev, ok := severity.(string); ok {
				if severityOrder[Severity(sev)] >= thresholdValue {
					return true
				}
			}
		}
	}

	return false
}

// calculateSummaryStats calculates summary statistics for results
func (e *Engine) calculateSummaryStats(results *MatchResults) {
	for _, match := range results.Matches {
		// Count by severity
		if severity, exists := match.Vulnerability.Metadata["severity"]; exists {
			if sev, ok := severity.(string); ok {
				results.Summary.BySeverity[sev]++
			}
		}

		// Count by fix state
		results.Summary.ByFixState[string(match.Vulnerability.Fix.State)]++
	}
}

// logPackageMatches logs match information for a package
func (e *Engine) logPackageMatches(pkg Package, matches []Match) {
	if len(matches) == 0 {
		return
	}

	log.Debugf("found %d vulnerabilities for package %s@%s", len(matches), pkg.Name, pkg.Version)
	for i, match := range matches {
		arm := "├──"
		if i == len(matches)-1 {
			arm = "└──"
		}
		log.Debugf("  %s vulnerability: %s (namespace: %s)", arm, match.Vulnerability.ID, match.Vulnerability.Namespace)
	}
}

// SeverityThresholdError represents an error when severity threshold is exceeded
type SeverityThresholdError struct {
	Threshold Severity
}

func (e SeverityThresholdError) Error() string {
	return fmt.Sprintf("vulnerability found with severity >= %s", e.Threshold)
}

// NewSeverityThresholdError creates a new severity threshold error
func NewSeverityThresholdError(threshold Severity) error {
	return SeverityThresholdError{Threshold: threshold}
}

// IsFatalError checks if an error is fatal
func IsFatalError(err error) bool {
	return strings.Contains(err.Error(), "fatal")
}
