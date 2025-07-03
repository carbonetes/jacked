package processors

import (
	"regexp"
	"strings"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// IgnoreRuleProcessor provides advanced ignore rule processing similar to Grype
type IgnoreRuleProcessor struct {
	rules []DetailedIgnoreRule
}

// DetailedIgnoreRule extends basic ignore rules with more sophisticated matching
type DetailedIgnoreRule struct {
	matchertypes.IgnoreRule

	// Extended criteria
	PackageVersion    string   `json:"package_version,omitempty"`
	PackageType       string   `json:"package_type,omitempty"`
	CVSSScore         *float64 `json:"cvss_score,omitempty"`
	CVSSScoreOperator string   `json:"cvss_score_operator,omitempty"` // >, <, >=, <=, =

	// Pattern matching
	VulnerabilityPattern string `json:"vulnerability_pattern,omitempty"` // regex pattern
	PackagePattern       string `json:"package_pattern,omitempty"`       // regex pattern

	// Conditional logic
	Conditions []IgnoreCondition `json:"conditions,omitempty"`
	Logic      string            `json:"logic,omitempty"` // "AND", "OR"

	// Metadata
	Reason      string `json:"reason,omitempty"`
	Expiry      string `json:"expiry,omitempty"` // ISO 8601 date when rule expires
	CreatedBy   string `json:"created_by,omitempty"`
	LastUpdated string `json:"last_updated,omitempty"`
}

// IgnoreCondition represents a conditional rule criteria
type IgnoreCondition struct {
	Field    string      `json:"field"`    // vulnerability.id, package.name, etc.
	Operator string      `json:"operator"` // equals, matches, contains, etc.
	Value    interface{} `json:"value"`
}

// NewIgnoreRuleProcessor creates a new ignore rule processor
func NewIgnoreRuleProcessor(rules []DetailedIgnoreRule) *IgnoreRuleProcessor {
	return &IgnoreRuleProcessor{
		rules: rules,
	}
}

// ApplyIgnoreRules applies ignore rules to matches and returns filtered and ignored matches
func (p *IgnoreRuleProcessor) ApplyIgnoreRules(matches []matchertypes.Match) ([]matchertypes.Match, []matchertypes.IgnoredMatch) {
	var filtered []matchertypes.Match
	var ignored []matchertypes.IgnoredMatch

	for _, match := range matches {
		appliedRules := p.getApplicableRules(match)
		if len(appliedRules) > 0 {
			ignoredMatch := matchertypes.IgnoredMatch{
				Match:              match,
				AppliedIgnoreRules: p.convertToBasicRules(appliedRules),
			}
			ignored = append(ignored, ignoredMatch)
		} else {
			filtered = append(filtered, match)
		}
	}

	return filtered, ignored
}

// getApplicableRules finds all ignore rules that apply to a match
func (p *IgnoreRuleProcessor) getApplicableRules(match matchertypes.Match) []DetailedIgnoreRule {
	var applicable []DetailedIgnoreRule

	for _, rule := range p.rules {
		if p.ruleApplies(rule, match) {
			applicable = append(applicable, rule)
		}
	}

	return applicable
}

// ruleApplies checks if a specific ignore rule applies to a match
func (p *IgnoreRuleProcessor) ruleApplies(rule DetailedIgnoreRule, match matchertypes.Match) bool {
	// Check basic criteria first
	if !p.matchesBasicCriteria(rule.IgnoreRule, match) {
		return false
	}

	// Check extended criteria
	if !p.matchesExtendedCriteria(rule, match) {
		return false
	}

	// Check conditional logic
	if len(rule.Conditions) > 0 {
		return p.evaluateConditions(rule, match)
	}

	return true
}

// matchesBasicCriteria checks basic ignore rule criteria
func (p *IgnoreRuleProcessor) matchesBasicCriteria(rule matchertypes.IgnoreRule, match matchertypes.Match) bool {
	checks := []func() bool{
		func() bool { return p.checkVulnerabilityID(rule.Vulnerability, match.Vulnerability.ID) },
		func() bool { return p.checkPackageName(rule.Package, match.Package.Name) },
		func() bool { return p.checkNamespace(rule.Namespace, match.Vulnerability.Namespace) },
		func() bool { return p.checkFixState(rule.FixState, match.Vulnerability.Fix.State) },
		func() bool { return p.checkLanguage(rule.Language, match.Package.Language) },
		func() bool { return p.checkLocations(rule.Locations, match.Package.Locations) },
	}

	for _, check := range checks {
		if !check() {
			return false
		}
	}
	return true
}

// Individual check methods for basic criteria
func (p *IgnoreRuleProcessor) checkVulnerabilityID(ruleValue, matchValue string) bool {
	return ruleValue == "" || p.matchesPattern(ruleValue, matchValue)
}

func (p *IgnoreRuleProcessor) checkPackageName(ruleValue, matchValue string) bool {
	return ruleValue == "" || p.matchesPattern(ruleValue, matchValue)
}

func (p *IgnoreRuleProcessor) checkNamespace(ruleValue, matchValue string) bool {
	return ruleValue == "" || p.matchesPattern(ruleValue, matchValue)
}

func (p *IgnoreRuleProcessor) checkFixState(ruleValue string, matchValue matchertypes.FixState) bool {
	return ruleValue == "" || string(matchValue) == ruleValue
}

func (p *IgnoreRuleProcessor) checkLanguage(ruleValue string, matchValue matchertypes.Language) bool {
	return ruleValue == "" || string(matchValue) == ruleValue
}

func (p *IgnoreRuleProcessor) checkLocations(ruleValue string, matchValue []matchertypes.Location) bool {
	return ruleValue == "" || p.matchesLocation(ruleValue, matchValue)
}

// matchesExtendedCriteria checks extended ignore rule criteria
func (p *IgnoreRuleProcessor) matchesExtendedCriteria(rule DetailedIgnoreRule, match matchertypes.Match) bool {
	checks := []func() bool{
		func() bool { return p.checkPackageVersion(rule.PackageVersion, match.Package.Version) },
		func() bool { return p.checkPackageType(rule.PackageType, match.Package.Type) },
		func() bool { return p.checkCVSSScore(rule.CVSSScore, rule.CVSSScoreOperator, match) },
		func() bool { return p.checkVulnerabilityPattern(rule.VulnerabilityPattern, match.Vulnerability.ID) },
		func() bool { return p.checkPackagePattern(rule.PackagePattern, match.Package.Name) },
	}

	for _, check := range checks {
		if !check() {
			return false
		}
	}
	return true
}

// Individual check methods for extended criteria
func (p *IgnoreRuleProcessor) checkPackageVersion(ruleValue, matchValue string) bool {
	return ruleValue == "" || p.matchesPattern(ruleValue, matchValue)
}

func (p *IgnoreRuleProcessor) checkPackageType(ruleValue string, matchValue matchertypes.PackageType) bool {
	return ruleValue == "" || string(matchValue) == ruleValue
}

func (p *IgnoreRuleProcessor) checkCVSSScore(ruleScore *float64, operator string, match matchertypes.Match) bool {
	if ruleScore == nil {
		return true
	}
	score := p.extractCVSSScore(match)
	return p.compareFloat64(score, *ruleScore, operator)
}

func (p *IgnoreRuleProcessor) checkVulnerabilityPattern(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}

func (p *IgnoreRuleProcessor) checkPackagePattern(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	// Package pattern matching with case-insensitive option
	matched, err := regexp.MatchString("(?i)"+pattern, value)
	return err == nil && matched
}

// evaluateConditions evaluates conditional logic for ignore rules
func (p *IgnoreRuleProcessor) evaluateConditions(rule DetailedIgnoreRule, match matchertypes.Match) bool {
	if len(rule.Conditions) == 0 {
		return true
	}

	results := p.evaluateAllConditions(rule.Conditions, match)
	return p.applyLogicOperator(rule.Logic, results)
}

// evaluateAllConditions evaluates all conditions and returns results
func (p *IgnoreRuleProcessor) evaluateAllConditions(conditions []IgnoreCondition, match matchertypes.Match) []bool {
	results := make([]bool, len(conditions))
	for i, condition := range conditions {
		results[i] = p.evaluateCondition(condition, match)
	}
	return results
}

// applyLogicOperator applies logic operator to condition results
func (p *IgnoreRuleProcessor) applyLogicOperator(logic string, results []bool) bool {
	switch strings.ToUpper(logic) {
	case "OR":
		return p.evaluateOR(results)
	case "AND", "":
		return p.evaluateAND(results)
	default:
		return p.evaluateAND(results) // Default to AND
	}
}

// evaluateOR returns true if any result is true
func (p *IgnoreRuleProcessor) evaluateOR(results []bool) bool {
	for _, result := range results {
		if result {
			return true
		}
	}
	return false
}

// evaluateAND returns true if all results are true
func (p *IgnoreRuleProcessor) evaluateAND(results []bool) bool {
	for _, result := range results {
		if !result {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (p *IgnoreRuleProcessor) evaluateCondition(condition IgnoreCondition, match matchertypes.Match) bool {
	fieldValue := p.extractFieldValue(condition.Field, match)

	switch condition.Operator {
	case "equals", "=", "==":
		return p.valueEquals(fieldValue, condition.Value)
	case "matches":
		return p.valueMatches(fieldValue, condition.Value)
	case "contains":
		return p.valueContains(fieldValue, condition.Value)
	case "starts_with":
		return p.valueStartsWith(fieldValue, condition.Value)
	case "ends_with":
		return p.valueEndsWith(fieldValue, condition.Value)
	case "greater_than", ">":
		return p.valueGreaterThan(fieldValue, condition.Value)
	case "less_than", "<":
		return p.valueLessThan(fieldValue, condition.Value)
	default:
		return false
	}
}

// extractFieldValue extracts a field value from a match using dot notation
func (p *IgnoreRuleProcessor) extractFieldValue(field string, match matchertypes.Match) interface{} {
	parts := strings.Split(field, ".")

	switch parts[0] {
	case "vulnerability":
		if len(parts) > 1 {
			switch parts[1] {
			case "id":
				return match.Vulnerability.ID
			case "namespace":
				return match.Vulnerability.Namespace
			case "package_name":
				return match.Vulnerability.PackageName
			}
		}
	case "package":
		if len(parts) > 1 {
			switch parts[1] {
			case "name":
				return match.Package.Name
			case "version":
				return match.Package.Version
			case "type":
				return string(match.Package.Type)
			case "language":
				return string(match.Package.Language)
			}
		}
	}

	return nil
}

// Helper methods for value comparison
func (p *IgnoreRuleProcessor) valueEquals(a, b interface{}) bool {
	return a == b
}

func (p *IgnoreRuleProcessor) valueMatches(value, pattern interface{}) bool {
	if strValue, ok := value.(string); ok {
		if strPattern, ok := pattern.(string); ok {
			matched, err := regexp.MatchString(strPattern, strValue)
			return err == nil && matched
		}
	}
	return false
}

func (p *IgnoreRuleProcessor) valueContains(value, substr interface{}) bool {
	if strValue, ok := value.(string); ok {
		if strSubstr, ok := substr.(string); ok {
			return strings.Contains(strValue, strSubstr)
		}
	}
	return false
}

func (p *IgnoreRuleProcessor) valueStartsWith(value, prefix interface{}) bool {
	if strValue, ok := value.(string); ok {
		if strPrefix, ok := prefix.(string); ok {
			return strings.HasPrefix(strValue, strPrefix)
		}
	}
	return false
}

func (p *IgnoreRuleProcessor) valueEndsWith(value, suffix interface{}) bool {
	if strValue, ok := value.(string); ok {
		if strSuffix, ok := suffix.(string); ok {
			return strings.HasSuffix(strValue, strSuffix)
		}
	}
	return false
}

func (p *IgnoreRuleProcessor) valueGreaterThan(a, b interface{}) bool {
	return p.compareNumeric(a, b, ">")
}

func (p *IgnoreRuleProcessor) valueLessThan(a, b interface{}) bool {
	return p.compareNumeric(a, b, "<")
}

// compareNumeric compares numeric values
func (p *IgnoreRuleProcessor) compareNumeric(a, b interface{}, operator string) bool {
	// Type conversion and numeric comparison logic would go here
	// This is a simplified version
	return false
}

// Helper methods
func (p *IgnoreRuleProcessor) matchesPattern(pattern, value string) bool {
	if pattern == value {
		return true
	}

	// Try regex matching
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}

func (p *IgnoreRuleProcessor) matchesLocation(pattern string, locations []matchertypes.Location) bool {
	for _, location := range locations {
		if p.matchesPattern(pattern, location.Path) {
			return true
		}
	}
	return false
}

func (p *IgnoreRuleProcessor) extractCVSSScore(match matchertypes.Match) float64 {
	// Extract CVSS score from vulnerability metadata
	if match.Vulnerability.Metadata != nil {
		if score, ok := match.Vulnerability.Metadata["cvss_score"].(float64); ok {
			return score
		}
	}
	return 0.0
}

func (p *IgnoreRuleProcessor) compareFloat64(a, b float64, operator string) bool {
	switch operator {
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	case "=", "==":
		return a == b
	default:
		return a == b
	}
}

func (p *IgnoreRuleProcessor) convertToBasicRules(rules []DetailedIgnoreRule) []matchertypes.IgnoreRule {
	var basicRules []matchertypes.IgnoreRule
	for _, rule := range rules {
		basicRules = append(basicRules, rule.IgnoreRule)
	}
	return basicRules
}
