package matcher

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
	extended         extendedProcessors
}

// temporary dummy types to avoid interface conflicts
type dummyProvider struct{}

// ExclusionFilter defines interface for excluding matches
type ExclusionFilter interface {
	ShouldExclude(match Match) bool
}

// NewEngine creates a new vulnerability matching engine
func NewEngine(config matchertypes.MatcherConfig) *Engine {
	engine := &Engine{
		provider:         &dummyProvider{},
		matchers:         make([]matchertypes.VulnerabilityMatcher, 0),
		exclusionFilters: make([]ExclusionFilter, 0),
		config:           config,
		extended:         extendedProcessors{},
	}

	// Initialize extended processors
	engine.initializeExtendedProcessors()

	return engine
}

// initializeExtendedProcessors sets up extended matching capabilities
func (e *Engine) initializeExtendedProcessors() {
	var vexProcessor *VEXProcessor

	// Initialize VEX processor if enabled
	if e.config.EnableVEXProcessing {
		if processor, err := NewVEXProcessor(e.config.VEXDocumentPaths); err == nil {
			vexProcessor = processor
		} else {
			log.Warnf("Failed to initialize VEX processor: %v", err)
		}
	}

	e.extended = extendedProcessors{
		vexProcessor:           vexProcessor,
		detailedIgnoreRules:    e.config.DetailedIgnoreRules,
		confidenceScoring:      e.config.EnableConfidenceScoring,
		minConfidenceThreshold: e.config.MinConfidenceThreshold,
		targetSWValidation:     e.config.EnableTargetSWValidation,
		minSeverityFilter:      e.config.MinSeverityFilter,
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

	// Apply all filtering and processing
	matches, ignoredMatches := e.processMatches(allMatches, opts)

	// Check severity threshold
	if opts.FailSeverity != nil {
		if e.hasSeverityAtOrAbove(*opts.FailSeverity, matches) {
			return nil, NewSeverityThresholdError(*opts.FailSeverity)
		}
	}

	// Finalize results
	e.finalizeResults(results, matches, ignoredMatches, startTime, packages)

	log.Debugf("vulnerability matching completed: found %d matches across %d packages",
		len(matches), len(packages))

	return results, nil
}

// processMatches applies all filtering and processing to matches
func (e *Engine) processMatches(allMatches []Match, opts MatchOptions) ([]Match, []IgnoredMatch) {
	matches := allMatches
	var ignoredMatches []IgnoredMatch

	// Apply ignore rules
	matches, ignored := e.applyIgnoreRules(matches, opts.IgnoreRules)
	ignoredMatches = append(ignoredMatches, ignored...)

	// Apply enhanced ignore rules
	if len(e.extended.detailedIgnoreRules) > 0 || len(opts.DetailedIgnoreRules) > 0 {
		matches, ignored = e.applyDetailedIgnoreRules(matches, e.extended.detailedIgnoreRules, opts.DetailedIgnoreRules)
		ignoredMatches = append(ignoredMatches, ignored...)
	}

	// Apply VEX processing if enabled
	if e.extended.vexProcessor != nil && e.extended.vexProcessor.enabled {
		matches, ignored = e.applyVEXProcessing(matches)
		ignoredMatches = append(ignoredMatches, ignored...)
	}

	// Apply confidence scoring filter
	if e.extended.confidenceScoring && e.extended.minConfidenceThreshold > 0 {
		matches = e.filterByConfidence(matches, e.extended.minConfidenceThreshold)
	}

	// Apply minimum severity filter
	if e.extended.minSeverityFilter != "" || opts.MinSeverityFilter != "" {
		minSeverity := e.extended.minSeverityFilter
		if opts.MinSeverityFilter != "" {
			minSeverity = opts.MinSeverityFilter
		}
		matches = e.filterBySeverity(matches, minSeverity)
	}

	// Normalize by CVE if requested
	if opts.NormalizeByCVE || e.config.NormalizeByCVE {
		matches = e.normalizeByCVE(matches)
	}

	// Deduplicate results if enabled
	if opts.DeduplicateResults || e.config.DeduplicateResults {
		matches = e.deduplicateMatches(matches)
	}

	return matches, ignoredMatches
}

// finalizeResults populates the final results structure
func (e *Engine) finalizeResults(results *MatchResults, matches []Match, ignoredMatches []IgnoredMatch, startTime time.Time, _ []Package) {
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

// hasSeverityAtOrAbove checks if matches contain vulnerabilities at or above specified severity
func (e *Engine) hasSeverityAtOrAbove(threshold Severity, matches []Match) bool {
	severityOrder := map[string]int{
		"negligible": 0,
		"low":        1,
		"medium":     2,
		"high":       3,
		"critical":   4,
	}

	thresholdLevel, exists := severityOrder[string(threshold)]
	if !exists {
		return false
	}

	for _, match := range matches {
		severity := e.extractSeverity(match.Vulnerability)
		if level, exists := severityOrder[severity]; exists && level >= thresholdLevel {
			return true
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
func NewSeverityThresholdError(severity Severity) error {
	return fmt.Errorf("vulnerability severity %s meets or exceeds failure threshold", severity)
}

// IsFatalError checks if an error is fatal
func IsFatalError(err error) bool {
	return strings.Contains(err.Error(), "fatal")
}

// Advanced matching processors
type extendedProcessors struct {
	vexProcessor           *VEXProcessor
	detailedIgnoreRules    []matchertypes.DetailedIgnoreRule
	confidenceScoring      bool
	minConfidenceThreshold float64
	targetSWValidation     bool
	minSeverityFilter      matchertypes.Severity
}

// VEXProcessor handles VEX document processing
type VEXProcessor struct {
	documents []matchertypes.VEXDocument
	enabled   bool
}

// NewVEXProcessor creates a new VEX processor
func NewVEXProcessor(documentPaths []string) (*VEXProcessor, error) {
	processor := &VEXProcessor{
		enabled: true, // Allow enabling VEX processor even without initial documents
	}

	// Load VEX documents (simplified implementation)
	for _, path := range documentPaths {
		log.Debugf("Loading VEX document from: %s", path)
		// VEX document loading would be implemented here
		// For now, we'll create a placeholder document
		doc := matchertypes.VEXDocument{
			ID:         path,
			DocumentID: path,
			Author:     "system",
			Statements: []matchertypes.VEXStatement{},
		}
		processor.documents = append(processor.documents, doc)
	}

	return processor, nil
}

// Advanced processing methods

// applyDetailedIgnoreRules applies enhanced ignore rules to matches
func (e *Engine) applyDetailedIgnoreRules(matches []Match, engineRules, optRules []matchertypes.DetailedIgnoreRule) ([]Match, []IgnoredMatch) {
	var filteredMatches []Match
	var ignoredMatches []IgnoredMatch

	// Combine rules from engine config and options
	allRules := append(engineRules, optRules...)
	if len(allRules) == 0 {
		return matches, ignoredMatches
	}

	for _, match := range matches {
		ignored := false
		var matchedRule *matchertypes.DetailedIgnoreRule

		for _, rule := range allRules {
			if e.matchesDetailedIgnoreRule(match, rule) {
				ignored = true
				matchedRule = &rule
				break
			}
		}

		if ignored {
			ignoredMatch := IgnoredMatch{
				Match: match,
				AppliedIgnoreRules: []IgnoreRule{{
					Vulnerability: matchedRule.CVE,
					Package:       matchedRule.PackageName,
					Reason:        matchedRule.Reason,
				}},
			}
			ignoredMatches = append(ignoredMatches, ignoredMatch)
		} else {
			filteredMatches = append(filteredMatches, match)
		}
	}

	return filteredMatches, ignoredMatches
}

// matchesDetailedIgnoreRule checks if a match should be ignored based on enhanced rule
func (e *Engine) matchesDetailedIgnoreRule(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	return e.matchesPackageCriteria(match, rule) &&
		e.matchesVulnerabilityCriteria(match, rule) &&
		e.matchesFixStateCriteria(match, rule)
}

// matchesPackageCriteria checks if the match meets package-related ignore criteria
func (e *Engine) matchesPackageCriteria(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	// Package name matching
	if rule.PackageName != "" && match.Package.Name != rule.PackageName {
		return false
	}

	if rule.PackageNamePattern != "" {
		if matched, err := filepath.Match(rule.PackageNamePattern, match.Package.Name); err != nil || !matched {
			return false
		}
	}

	// Package version matching
	if rule.PackageVersion != "" && match.Package.Version != rule.PackageVersion {
		return false
	}

	return true
}

// matchesVulnerabilityCriteria checks if the match meets vulnerability-related ignore criteria
func (e *Engine) matchesVulnerabilityCriteria(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	return e.matchesCVECriteria(match, rule) &&
		e.matchesCVSSCriteria(match, rule) &&
		e.matchesSeverityCriteria(match, rule)
}

// matchesCVECriteria checks CVE-related matching criteria
func (e *Engine) matchesCVECriteria(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	// CVE matching
	if rule.CVE != "" && match.Vulnerability.ID != rule.CVE {
		return false
	}

	if rule.CVEPattern != "" {
		if matched, err := filepath.Match(rule.CVEPattern, match.Vulnerability.ID); err != nil || !matched {
			return false
		}
	}

	return true
}

// matchesCVSSCriteria checks CVSS score criteria
func (e *Engine) matchesCVSSCriteria(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	cvssScore := e.getCVSSScore(match.Vulnerability)

	if rule.MaxCVSSScore > 0 && cvssScore > rule.MaxCVSSScore {
		return false
	}

	if rule.MinCVSSScore > 0 && cvssScore < rule.MinCVSSScore {
		return false
	}

	return true
}

// matchesSeverityCriteria checks severity-related criteria
func (e *Engine) matchesSeverityCriteria(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	vulnSeverity := e.extractSeverity(match.Vulnerability)

	if rule.Severity != "" && vulnSeverity != rule.Severity {
		return false
	}

	if rule.SeverityPattern != "" {
		if matched, err := filepath.Match(rule.SeverityPattern, vulnSeverity); err != nil || !matched {
			return false
		}
	}

	return true
}

// matchesFixStateCriteria checks if the match meets fix state criteria
func (e *Engine) matchesFixStateCriteria(match Match, rule matchertypes.DetailedIgnoreRule) bool {
	// Fix state matching
	if rule.IgnoreUnfixed && match.Vulnerability.Fix.State != "fixed" {
		return true
	}

	return true
}

// getCVSSScore extracts CVSS score from vulnerability metadata
func (e *Engine) getCVSSScore(vuln Vulnerability) float64 {
	if vuln.Metadata == nil {
		return 0.0
	}

	// Try CVSS v3 first
	if score := e.extractCVSSFromVersion(vuln.Metadata, "cvssV3"); score > 0 {
		return score
	}

	// Try CVSS v2
	if score := e.extractCVSSFromVersion(vuln.Metadata, "cvssV2"); score > 0 {
		return score
	}

	// Try generic cvss field
	return e.extractGenericCVSS(vuln.Metadata)
}

// extractCVSSFromVersion extracts CVSS score from specific version metadata
func (e *Engine) extractCVSSFromVersion(metadata map[string]interface{}, versionKey string) float64 {
	if cvssData, exists := metadata[versionKey]; exists {
		if cvssMap, ok := cvssData.(map[string]interface{}); ok {
			if score, exists := cvssMap["baseScore"]; exists {
				if scoreFloat, ok := score.(float64); ok {
					return scoreFloat
				}
			}
		}
	}
	return 0.0
}

// extractGenericCVSS extracts CVSS score from generic cvss field
func (e *Engine) extractGenericCVSS(metadata map[string]interface{}) float64 {
	if cvss, exists := metadata["cvss"]; exists {
		if scoreFloat, ok := cvss.(float64); ok {
			return scoreFloat
		}
		if cvssMap, ok := cvss.(map[string]interface{}); ok {
			if score, exists := cvssMap["score"]; exists {
				if scoreFloat, ok := score.(float64); ok {
					return scoreFloat
				}
			}
		}
	}
	return 0.0
}

// applyVEXProcessing applies VEX document filtering to matches
func (e *Engine) applyVEXProcessing(matches []Match) ([]Match, []IgnoredMatch) {
	var filteredMatches []Match
	var ignoredMatches []IgnoredMatch

	if e.extended.vexProcessor == nil || !e.extended.vexProcessor.enabled {
		return matches, ignoredMatches
	}

	for _, match := range matches {
		if e.shouldIgnoreByVEX(match) {
			ignoredMatch := IgnoredMatch{
				Match:  match,
				Reason: "Excluded by VEX document",
			}
			ignoredMatches = append(ignoredMatches, ignoredMatch)
		} else {
			filteredMatches = append(filteredMatches, match)
		}
	}

	return filteredMatches, ignoredMatches
}

// shouldIgnoreByVEX checks if a match should be ignored based on VEX documents
func (e *Engine) shouldIgnoreByVEX(match Match) bool {
	for _, doc := range e.extended.vexProcessor.documents {
		for _, statement := range doc.Statements {
			if statement.VulnerabilityID == match.Vulnerability.ID {
				return statement.Status == matchertypes.VEXStatusNotAffected ||
					statement.Status == matchertypes.VEXStatusFixed
			}
		}
	}
	return false
}

// filterByConfidence filters matches based on confidence threshold
func (e *Engine) filterByConfidence(matches []Match, threshold float64) []Match {
	var filteredMatches []Match

	for _, match := range matches {
		confidence := e.calculateMatchConfidence(match)
		if confidence >= threshold {
			filteredMatches = append(filteredMatches, match)
		}
	}

	return filteredMatches
}

// calculateMatchConfidence calculates confidence score for a match
func (e *Engine) calculateMatchConfidence(match Match) float64 {
	// Simplified confidence calculation
	confidence := 1.0

	// Reduce confidence for partial matches
	if len(match.Details) > 0 {
		totalConfidence := 0.0
		for _, detail := range match.Details {
			totalConfidence += detail.Confidence
		}
		confidence = totalConfidence / float64(len(match.Details))
	}

	return confidence
}

// extractSeverity extracts severity from vulnerability metadata
func (e *Engine) extractSeverity(vuln Vulnerability) string {
	if vuln.Metadata == nil {
		return ""
	}

	// Try direct severity fields first
	if severity := e.getSeverityFromKey(vuln.Metadata, "severity"); severity != "" {
		return severity
	}
	if severity := e.getSeverityFromKey(vuln.Metadata, "baseSeverity"); severity != "" {
		return severity
	}
	if severity := e.getSeverityFromKey(vuln.Metadata, "cvss_severity"); severity != "" {
		return severity
	}
	if severity := e.getSeverityFromKey(vuln.Metadata, "risk_level"); severity != "" {
		return severity
	}

	// Try to extract from CVSS data
	return e.getSeverityFromCVSS(vuln.Metadata)
}

// getSeverityFromKey extracts severity from a specific metadata key
func (e *Engine) getSeverityFromKey(metadata map[string]interface{}, key string) string {
	if severity, exists := metadata[key]; exists {
		if severityStr, ok := severity.(string); ok {
			return strings.ToLower(severityStr)
		}
	}
	return ""
}

// getSeverityFromCVSS extracts severity from CVSS metadata
func (e *Engine) getSeverityFromCVSS(metadata map[string]interface{}) string {
	if cvssData, exists := metadata["cvss"]; exists {
		if cvssMap, ok := cvssData.(map[string]interface{}); ok {
			if severity, exists := cvssMap["baseSeverity"]; exists {
				if severityStr, ok := severity.(string); ok {
					return strings.ToLower(severityStr)
				}
			}
		}
	}
	return ""
}

// filterBySeverity filters matches based on minimum severity
func (e *Engine) filterBySeverity(matches []Match, minSeverity Severity) []Match {
	if minSeverity == "" {
		return matches
	}

	severityOrder := map[string]int{
		"negligible": 0,
		"low":        1,
		"medium":     2,
		"high":       3,
		"critical":   4,
	}

	minLevel, exists := severityOrder[string(minSeverity)]
	if !exists {
		return matches
	}

	var filteredMatches []Match
	for _, match := range matches {
		severity := e.extractSeverity(match.Vulnerability)
		if level, exists := severityOrder[severity]; exists && level >= minLevel {
			filteredMatches = append(filteredMatches, match)
		}
	}

	return filteredMatches
}
