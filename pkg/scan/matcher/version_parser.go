package matcher

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	versionFormat = "%d.%d.%d"
)

// VersionFormat represents different version formats supported
type VersionFormat string

const (
	SemanticFormat VersionFormat = "semantic"
	DartFormat     VersionFormat = "dart"
	RustFormat     VersionFormat = "rust"
	PythonFormat   VersionFormat = "python"
	UnknownFormat  VersionFormat = "unknown"
)

// VersionParser provides enhanced version parsing and comparison
type VersionParser struct {
	format VersionFormat
}

// NewVersionParser creates a new version parser for the given format
func NewVersionParser(format VersionFormat) *VersionParser {
	return &VersionParser{
		format: format,
	}
}

// ParseVersion parses a version string according to the specified format
func (vp *VersionParser) ParseVersion(versionStr string) (*ParsedVersion, error) {
	switch vp.format {
	case DartFormat:
		return vp.parseDartVersion(versionStr)
	case RustFormat:
		return vp.parseRustVersion(versionStr)
	case PythonFormat:
		return vp.parsePythonVersion(versionStr)
	case SemanticFormat:
		return vp.parseSemanticVersion(versionStr)
	default:
		return vp.parseFuzzyVersion(versionStr)
	}
}

// ParsedVersion represents a parsed version with metadata
type ParsedVersion struct {
	Original   string        `json:"original"`
	Normalized string        `json:"normalized"`
	Format     VersionFormat `json:"format"`
	Major      int           `json:"major"`
	Minor      int           `json:"minor"`
	Patch      int           `json:"patch"`
	Prerelease string        `json:"prerelease,omitempty"`
	BuildMeta  string        `json:"build_meta,omitempty"`
	semverObj  *semver.Version
}

// Compare compares this version with another version
func (pv *ParsedVersion) Compare(other *ParsedVersion) (int, error) {
	if pv == nil || other == nil {
		return 0, errors.New("cannot compare nil versions")
	}

	// If both have semver objects, use those for accurate comparison
	if pv.semverObj != nil && other.semverObj != nil {
		return pv.semverObj.Compare(other.semverObj), nil
	}

	// Fallback to component-wise comparison
	if pv.Major != other.Major {
		if pv.Major > other.Major {
			return 1, nil
		}
		return -1, nil
	}

	if pv.Minor != other.Minor {
		if pv.Minor > other.Minor {
			return 1, nil
		}
		return -1, nil
	}

	if pv.Patch != other.Patch {
		if pv.Patch > other.Patch {
			return 1, nil
		}
		return -1, nil
	}

	// Compare prerelease versions
	return comparePrerelease(pv.Prerelease, other.Prerelease), nil
}

// String returns the normalized version string
func (pv *ParsedVersion) String() string {
	if pv.Normalized != "" {
		return pv.Normalized
	}
	return pv.Original
}

// parseDartVersion parses Dart/Pub package versions
// Dart follows semantic versioning with some specific conventions
func (vp *VersionParser) parseDartVersion(versionStr string) (*ParsedVersion, error) {
	// Clean the version string
	cleaned := strings.TrimSpace(versionStr)

	// Remove 'v' prefix if present
	if strings.HasPrefix(cleaned, "v") {
		cleaned = cleaned[1:]
	}

	// Dart version patterns
	dartPatterns := []*regexp.Regexp{
		// Standard semver: 1.2.3, 1.2.3-alpha.1, 1.2.3+build.1
		regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z\-\.]+))?(?:\+([0-9A-Za-z\-\.]+))?$`),
		// Dart pre-release patterns: 1.2.3-dev.1.2, 1.2.3-alpha
		regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)-([a-zA-Z]+(?:\.\d+)*(?:\.\d+)?)$`),
		// Short version: 1.2 -> 1.2.0
		regexp.MustCompile(`^(\d+)\.(\d+)$`),
		// Single digit: 1 -> 1.0.0
		regexp.MustCompile(`^(\d+)$`),
	}

	for _, pattern := range dartPatterns {
		if matches := pattern.FindStringSubmatch(cleaned); matches != nil {
			return vp.buildDartVersion(matches, cleaned)
		}
	}

	// Fallback to fuzzy parsing
	return vp.parseFuzzyVersion(versionStr)
}

// buildDartVersion builds a ParsedVersion from regex matches
func (vp *VersionParser) buildDartVersion(matches []string, original string) (*ParsedVersion, error) {
	major, _ := strconv.Atoi(matches[1])
	minor := 0
	patch := 0
	prerelease := ""
	buildMeta := ""

	if len(matches) > 2 && matches[2] != "" {
		minor, _ = strconv.Atoi(matches[2])
	}

	if len(matches) > 3 && matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
	}

	if len(matches) > 4 && matches[4] != "" {
		prerelease = matches[4]
	}

	if len(matches) > 5 && matches[5] != "" {
		buildMeta = matches[5]
	}

	// Build normalized version
	normalized := fmt.Sprintf(versionFormat, major, minor, patch)
	if prerelease != "" {
		normalized += "-" + prerelease
	}
	if buildMeta != "" {
		normalized += "+" + buildMeta
	}

	// Try to create semver object for better comparison
	var semverObj *semver.Version
	if sv, err := semver.NewVersion(normalized); err == nil {
		semverObj = sv
	}

	return &ParsedVersion{
		Original:   original,
		Normalized: normalized,
		Format:     DartFormat,
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		BuildMeta:  buildMeta,
		semverObj:  semverObj,
	}, nil
}

// parseRustVersion parses Rust Cargo package versions
func (vp *VersionParser) parseRustVersion(versionStr string) (*ParsedVersion, error) {
	// Rust follows semantic versioning strictly
	return vp.parseSemanticVersion(versionStr)
}

// parsePythonVersion parses Python package versions (PEP 440)
func (vp *VersionParser) parsePythonVersion(versionStr string) (*ParsedVersion, error) {
	// Simplified PEP 440 parsing - for full implementation, use specialized library
	cleaned := strings.TrimSpace(versionStr)

	// Handle common Python version patterns
	pythonPatterns := []*regexp.Regexp{
		// Standard: 1.2.3, 1.2.3a1, 1.2.3.post1
		regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?(?:\.(post)(\d+))?$`),
		// Dev versions: 1.2.3.dev1
		regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.dev(\d+)$`),
		// Simple semver pattern
		regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`),
	}

	for _, pattern := range pythonPatterns {
		if matches := pattern.FindStringSubmatch(cleaned); matches != nil {
			return vp.buildPythonVersion(matches, cleaned)
		}
	}

	return vp.parseFuzzyVersion(versionStr)
}

// buildPythonVersion builds a ParsedVersion from Python version matches
func (vp *VersionParser) buildPythonVersion(matches []string, original string) (*ParsedVersion, error) {
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	prerelease := ""
	if len(matches) > 4 && matches[4] != "" {
		prerelease = matches[4]
		if len(matches) > 5 && matches[5] != "" {
			prerelease += matches[5]
		}
	}

	normalized := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	if prerelease != "" {
		normalized += "-" + prerelease
	}

	return &ParsedVersion{
		Original:   original,
		Normalized: normalized,
		Format:     PythonFormat,
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
	}, nil
}

// parseSemanticVersion parses standard semantic versions
func (vp *VersionParser) parseSemanticVersion(versionStr string) (*ParsedVersion, error) {
	cleaned := strings.TrimSpace(versionStr)

	// Remove 'v' prefix if present
	if strings.HasPrefix(cleaned, "v") {
		cleaned = cleaned[1:]
	}

	// Try strict semver parsing first
	if sv, err := semver.NewVersion(cleaned); err == nil {
		return &ParsedVersion{
			Original:   versionStr,
			Normalized: sv.String(),
			Format:     SemanticFormat,
			Major:      int(sv.Major()),
			Minor:      int(sv.Minor()),
			Patch:      int(sv.Patch()),
			Prerelease: sv.Prerelease(),
			BuildMeta:  sv.Metadata(),
			semverObj:  sv,
		}, nil
	}

	// Fallback to fuzzy parsing
	return vp.parseFuzzyVersion(versionStr)
}

// parseFuzzyVersion provides a fallback for non-standard version formats
func (vp *VersionParser) parseFuzzyVersion(versionStr string) (*ParsedVersion, error) {
	cleaned := strings.TrimSpace(versionStr)

	// Extract numeric components
	pattern := regexp.MustCompile(`(\d+)(?:\.(\d+))?(?:\.(\d+))?`)
	matches := pattern.FindStringSubmatch(cleaned)

	if matches == nil {
		return &ParsedVersion{
			Original:   versionStr,
			Normalized: cleaned,
			Format:     UnknownFormat,
		}, nil
	}

	major, _ := strconv.Atoi(matches[1])
	minor := 0
	patch := 0

	if len(matches) > 2 && matches[2] != "" {
		minor, _ = strconv.Atoi(matches[2])
	}

	if len(matches) > 3 && matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
	}

	normalized := fmt.Sprintf("%d.%d.%d", major, minor, patch)

	return &ParsedVersion{
		Original:   versionStr,
		Normalized: normalized,
		Format:     UnknownFormat,
		Major:      major,
		Minor:      minor,
		Patch:      patch,
	}, nil
}

// comparePrerelease compares prerelease version strings
func comparePrerelease(a, b string) int {
	if a == "" && b == "" {
		return 0
	}
	if a == "" {
		return 1 // no prerelease is greater than prerelease
	}
	if b == "" {
		return -1
	}

	// Simple lexicographic comparison for now
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// ValidateConstraint validates a version constraint string
func (vp *VersionParser) ValidateConstraint(constraint string) error {
	// Basic constraint validation
	if constraint == "" {
		return nil
	}

	// Check for common constraint patterns
	constraintPatterns := []string{
		`^[><=!~^]+\s*\d+`, // >= 1.0.0, ~1.0.0, ^1.0.0, etc.
		`^\*$`,             // *
		`^\d+`,             // 1.0.0
	}

	for _, pattern := range constraintPatterns {
		if matched, _ := regexp.MatchString(pattern, strings.TrimSpace(constraint)); matched {
			return nil
		}
	}

	return fmt.Errorf("invalid constraint format: %s", constraint)
}
