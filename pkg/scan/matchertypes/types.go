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
	Reason             string       `json:"reason,omitempty"`
}

// IgnoreRule defines criteria for ignoring vulnerability matches
type IgnoreRule struct {
	Vulnerability string `json:"vulnerability,omitempty"`
	Package       string `json:"package,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	FixState      string `json:"fix_state,omitempty"`
	Language      string `json:"language,omitempty"`
	Locations     string `json:"locations,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// DetailedIgnoreRule provides comprehensive ignore rule capabilities
type DetailedIgnoreRule struct {
	// Package matching
	PackageName        string `json:"package_name,omitempty"`
	PackageNamePattern string `json:"package_name_pattern,omitempty"`
	PackageVersion     string `json:"package_version,omitempty"`
	PackageType        string `json:"package_type,omitempty"`

	// Vulnerability matching
	CVE             string  `json:"cve,omitempty"`
	CVEPattern      string  `json:"cve_pattern,omitempty"`
	CVSS            float64 `json:"cvss,omitempty"`
	MaxCVSSScore    float64 `json:"max_cvss_score,omitempty"`
	MinCVSSScore    float64 `json:"min_cvss_score,omitempty"`
	Severity        string  `json:"severity,omitempty"`
	SeverityPattern string  `json:"severity_pattern,omitempty"`

	// Fix state matching
	FixState      string `json:"fix_state,omitempty"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`

	// Conditional logic
	MatchType string `json:"match_type,omitempty"` // "AND", "OR", "NOT"

	// Metadata
	Reason    string            `json:"reason,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Expiry    string            `json:"expiry,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
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

	// VEX and filtering options
	VEXDocumentPaths         []string             `json:"vex_document_paths,omitempty"`
	EnableVEXProcessing      bool                 `json:"enable_vex_processing"`
	DetailedIgnoreRules      []DetailedIgnoreRule `json:"detailed_ignore_rules,omitempty"`
	MinSeverityFilter        Severity             `json:"min_severity_filter,omitempty"`
	EnableConfidenceScoring  bool                 `json:"enable_confidence_scoring"`
	MinConfidenceThreshold   float64              `json:"min_confidence_threshold"`
	EnableTargetSWValidation bool                 `json:"enable_target_sw_validation"`
	PreciseCPEMatching       bool                 `json:"precise_cpe_matching"`
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

	// VEX and filtering options
	EnableVEXProcessing      bool                 `json:"enable_vex_processing"`
	VEXDocumentPaths         []string             `json:"vex_document_paths"`
	DetailedIgnoreRules      []DetailedIgnoreRule `json:"detailed_ignore_rules"`
	EnableConfidenceScoring  bool                 `json:"enable_confidence_scoring"`
	MinConfidenceThreshold   float64              `json:"min_confidence_threshold"`
	EnableTargetSWValidation bool                 `json:"enable_target_sw_validation"`
	PreciseCPEMatching       bool                 `json:"precise_cpe_matching"`
	MinSeverityFilter        Severity             `json:"min_severity_filter"`
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

// VEX-related types for Vulnerability Exploitability eXchange
type VEXStatus string

const (
	VEXStatusAffected           VEXStatus = "affected"
	VEXStatusNotAffected        VEXStatus = "not_affected"
	VEXStatusFixed              VEXStatus = "fixed"
	VEXStatusUnderInvestigation VEXStatus = "under_investigation"
)

// VEXJustification provides reasoning for VEX status
type VEXJustification string

const (
	ComponentNotPresent                         VEXJustification = "component_not_present"
	VulnerableCodeNotPresent                    VEXJustification = "vulnerable_code_not_present"
	VulnerableCodeNotInExecutePath              VEXJustification = "vulnerable_code_not_in_execute_path"
	VulnerableCodeCannotBeControlledByAdversary VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	InlineMitigationsAlreadyExist               VEXJustification = "inline_mitigations_already_exist"
)

// VEXDocument represents a VEX document structure
type VEXDocument struct {
	ID         string         `json:"id"`
	DocumentID string         `json:"document_id,omitempty"`
	Author     string         `json:"author,omitempty"`
	AuthorRole string         `json:"author_role,omitempty"`
	Timestamp  string         `json:"timestamp,omitempty"`
	Version    string         `json:"version,omitempty"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement represents a single VEX statement
type VEXStatement struct {
	VulnerabilityID string           `json:"vulnerability_id"`
	Products        []string         `json:"products,omitempty"`
	Status          VEXStatus        `json:"status"`
	Justification   VEXJustification `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"`
}
