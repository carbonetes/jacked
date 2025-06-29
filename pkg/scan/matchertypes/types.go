package matchertypes

import (
	"context"
)

// VulnerabilityMatcher defines the core vulnerability matching interface
type VulnerabilityMatcher interface {
	// FindMatches identifies vulnerabilities in packages from a BOM
	FindMatches(ctx context.Context, packages []Package, opts MatchOptions) (*MatchResults, error)

	// Type returns the matcher type identifier
	Type() MatcherType
}

// Package represents a software package to be scanned
type Package struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Type         PackageType       `json:"type"`
	Language     Language          `json:"language"`
	Ecosystem    string            `json:"ecosystem"`
	CPEs         []string          `json:"cpes,omitempty"`
	Upstreams    []UpstreamPackage `json:"upstreams,omitempty"`
	Locations    []Location        `json:"locations,omitempty"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
	Dependencies []Dependency      `json:"dependencies,omitempty"`
}

// UpstreamPackage represents an upstream/source package
type UpstreamPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Location represents where a package was found
type Location struct {
	Path   string `json:"path"`
	Layer  string `json:"layer,omitempty"`
	Source string `json:"source,omitempty"`
}

// Dependency represents a package dependency
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Scope   string `json:"scope,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID                     string                 `json:"id"`
	Namespace              string                 `json:"namespace"`
	PackageName            string                 `json:"package_name"`
	VersionConstraint      string                 `json:"version_constraint"`
	CPEs                   []string               `json:"cpes,omitempty"`
	RelatedVulnerabilities []VulnerabilityRef     `json:"related_vulnerabilities,omitempty"`
	Fix                    Fix                    `json:"fix"`
	Advisories             []Advisory             `json:"advisories,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// VulnerabilityRef represents a reference to another vulnerability
type VulnerabilityRef struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
}

// Fix represents fix information for a vulnerability
type Fix struct {
	State   FixState `json:"state"`
	Version string   `json:"version,omitempty"`
}

// Advisory represents a security advisory
type Advisory struct {
	ID          string `json:"id"`
	Link        string `json:"link"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Published   string `json:"published"`
}

// Match represents a vulnerability match
type Match struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Package       Package       `json:"package"`
	Details       []MatchDetail `json:"details"`
}

// MatchDetail provides details about how a match was found
type MatchDetail struct {
	Type       MatchType              `json:"type"`
	Confidence float64                `json:"confidence"`
	SearchedBy map[string]interface{} `json:"searched_by"`
	Found      map[string]interface{} `json:"found"`
	Matcher    string                 `json:"matcher"`
}

// IgnoredMatch represents a match that was ignored due to rules
type IgnoredMatch struct {
	Match              Match        `json:"match"`
	AppliedIgnoreRules []IgnoreRule `json:"applied_ignore_rules"`
}

// IgnoreRule defines criteria for ignoring vulnerability matches
type IgnoreRule struct {
	Vulnerability string `json:"vulnerability,omitempty"`
	Package       string `json:"package,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	FixState      string `json:"fix_state,omitempty"`
	Language      string `json:"language,omitempty"`
	Locations     string `json:"locations,omitempty"`
}

// MatchResults contains the results of a vulnerability matching operation
type MatchResults struct {
	Matches        []Match        `json:"matches"`
	IgnoredMatches []IgnoredMatch `json:"ignored_matches"`
	Summary        MatchSummary   `json:"summary"`
}

// MatchSummary provides summary statistics about matching results
type MatchSummary struct {
	TotalPackages      int                    `json:"total_packages"`
	PackagesWithVulns  int                    `json:"packages_with_vulnerabilities"`
	TotalMatches       int                    `json:"total_matches"`
	IgnoredMatches     int                    `json:"ignored_matches"`
	BySeverity         map[string]int         `json:"by_severity"`
	ByFixState         map[string]int         `json:"by_fix_state"`
	ExecutionTime      string                 `json:"execution_time"`
	MatcherPerformance map[string]interface{} `json:"matcher_performance"`
}

// MatchOptions configures vulnerability matching behavior
type MatchOptions struct {
	IgnoreRules         []IgnoreRule  `json:"ignore_rules,omitempty"`
	FailSeverity        *Severity     `json:"fail_severity,omitempty"`
	NormalizeByCVE      bool          `json:"normalize_by_cve"`
	DistroType          string        `json:"distro_type,omitempty"`
	DistroVersion       string        `json:"distro_version,omitempty"`
	EnabledMatchers     []MatcherType `json:"enabled_matchers,omitempty"`
	DisabledMatchers    []MatcherType `json:"disabled_matchers,omitempty"`
	CPEMatching         bool          `json:"cpe_matching"`
	ExclusionProviders  []string      `json:"exclusion_providers,omitempty"`
	MaxConcurrency      int           `json:"max_concurrency"`
	Timeout             string        `json:"timeout"`
	EnableProgressTrack bool          `json:"enable_progress_track"`
	DeduplicateResults  bool          `json:"deduplicate_results"`
}

// MatcherConfig provides configuration for vulnerability matchers
type MatcherConfig struct {
	UseCPEs            bool
	MaxConcurrency     int
	Timeout            string
	EnableCaching      bool
	EnableMetrics      bool
	NormalizeByCVE     bool
	CPEMatching        bool
	DeduplicateResults bool
	ExclusionProviders []string
	DefaultIgnoreRules []IgnoreRule
}

// MatcherType identifies different types of vulnerability matchers
type MatcherType string

const (
	NPMMatcherType     MatcherType = "npm-matcher"
	GoMatcherType      MatcherType = "go-matcher"
	MavenMatcherType   MatcherType = "maven-matcher"
	PythonMatcherType  MatcherType = "python-matcher"
	RubyGemMatcherType MatcherType = "rubygem-matcher"
	DartMatcherType    MatcherType = "dart-matcher"
	APKMatcherType     MatcherType = "apk-matcher"
	DpkgMatcherType    MatcherType = "dpkg-matcher"
	RPMMatcherType     MatcherType = "rpm-matcher"
	StockMatcherType   MatcherType = "stock-matcher"
	VersionMatcherType MatcherType = "version-matcher"
)

type PackageType string

const (
	NPMPkg     PackageType = "npm"
	GoPkg      PackageType = "go-module"
	JavaPkg    PackageType = "java-archive"
	PythonPkg  PackageType = "python"
	GemPkg     PackageType = "gem"
	DartPkg    PackageType = "dart"
	DebPkg     PackageType = "deb"
	RPMPkg     PackageType = "rpm"
	APKPkg     PackageType = "apk"
	BinaryPkg  PackageType = "binary"
	GenericPkg PackageType = "generic"
	UnknownPkg PackageType = "unknown"
)

type Language string

const (
	JavaScript  Language = "javascript"
	TypeScript  Language = "typescript"
	Python      Language = "python"
	Java        Language = "java"
	Go          Language = "go"
	Ruby        Language = "ruby"
	Dart        Language = "dart"
	CSharp      Language = "c#"
	CPlusPlus   Language = "c++"
	C           Language = "c"
	PHP         Language = "php"
	Rust        Language = "rust"
	Swift       Language = "swift"
	Kotlin      Language = "kotlin"
	Scala       Language = "scala"
	Shell       Language = "shell"
	UnknownLang Language = "unknown"
)

type MatchType string

const (
	ExactDirectMatch   MatchType = "exact-direct-match"
	ExactIndirectMatch MatchType = "exact-indirect-match"
	FuzzyMatch         MatchType = "fuzzy-match"
	CPEMatch           MatchType = "cpe-match"
	VersionRangeMatch  MatchType = "version-range-match"
)

type FixState string

const (
	FixStateFixed    FixState = "fixed"
	FixStateNotFixed FixState = "not-fixed"
	FixStateWontFix  FixState = "wont-fix"
	FixStateUnknown  FixState = "unknown"
)

type Severity string

const (
	CriticalSeverity Severity = "critical"
	HighSeverity     Severity = "high"
	MediumSeverity   Severity = "medium"
	LowSeverity      Severity = "low"
	UnknownSeverity  Severity = "unknown"
)
