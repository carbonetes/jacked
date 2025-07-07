package matcher

import (
	"testing"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

func TestExtractSeverity(t *testing.T) {
	engine := &Engine{}

	tests := []struct {
		name          string
		vulnerability matchertypes.Vulnerability
		expected      string
	}{
		{
			name: "severity in metadata",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{
					"severity": "HIGH",
				},
			},
			expected: "high",
		},
		{
			name: "baseSeverity in metadata",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{
					"baseSeverity": "Critical",
				},
			},
			expected: "critical",
		},
		{
			name: "severity in CVSS",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{
					"cvss": map[string]interface{}{
						"baseSeverity": "MEDIUM",
					},
				},
			},
			expected: "medium",
		},
		{
			name: "no severity",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.extractSeverity(tt.vulnerability)
			if result != tt.expected {
				t.Errorf("extractSeverity() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetCVSSScore(t *testing.T) {
	engine := &Engine{}

	tests := []struct {
		name          string
		vulnerability matchertypes.Vulnerability
		expected      float64
	}{
		{
			name: "CVSSv3 score",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{
					"cvssV3": map[string]interface{}{
						"baseScore": 7.5,
					},
				},
			},
			expected: 7.5,
		},
		{
			name: "CVSSv2 score",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{
					"cvssV2": map[string]interface{}{
						"baseScore": 6.8,
					},
				},
			},
			expected: 6.8,
		},
		{
			name: "generic CVSS score",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{
					"cvss": 8.1,
				},
			},
			expected: 8.1,
		},
		{
			name: "no CVSS score",
			vulnerability: matchertypes.Vulnerability{
				Metadata: map[string]interface{}{},
			},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.getCVSSScore(tt.vulnerability)
			if result != tt.expected {
				t.Errorf("getCVSSScore() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchesEnhancedIgnoreRule(t *testing.T) {
	engine := &Engine{}

	match := matchertypes.Match{
		Package: matchertypes.Package{
			Name:    "test-package",
			Version: "1.0.0",
		},
		Vulnerability: matchertypes.Vulnerability{
			ID: "CVE-2023-1234",
			Metadata: map[string]interface{}{
				"severity": "high",
			},
		},
	}

	tests := []struct {
		name     string
		rule     matchertypes.DetailedIgnoreRule
		expected bool
	}{
		{
			name: "matching package name",
			rule: matchertypes.DetailedIgnoreRule{
				PackageName: "test-package",
			},
			expected: true,
		},
		{
			name: "non-matching package name",
			rule: matchertypes.DetailedIgnoreRule{
				PackageName: "other-package",
			},
			expected: false,
		},
		{
			name: "matching CVE",
			rule: matchertypes.DetailedIgnoreRule{
				CVE: "CVE-2023-1234",
			},
			expected: true,
		},
		{
			name: "matching severity",
			rule: matchertypes.DetailedIgnoreRule{
				Severity: "high",
			},
			expected: true,
		},
		{
			name: "non-matching severity",
			rule: matchertypes.DetailedIgnoreRule{
				Severity: "low",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.matchesDetailedIgnoreRule(match, tt.rule)
			if result != tt.expected {
				t.Errorf("matchesDetailedIgnoreRule() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewEngine(t *testing.T) {
	config := matchertypes.MatcherConfig{
		EnableVEXProcessing:     true,
		VEXDocumentPaths:        []string{"test.vex"},
		EnableConfidenceScoring: true,
		MinConfidenceThreshold:  0.8,
		PreciseCPEMatching:      true,
	}

	engine := NewEngine(config)

	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}

	if engine.config.EnableVEXProcessing != true {
		t.Errorf("VEX processing not enabled")
	}

	// Test extended processors initialization
	if engine.extended.vexProcessor == nil {
		t.Errorf("VEX processor not initialized")
	}
}
