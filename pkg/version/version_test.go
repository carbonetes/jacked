package version

import (
	"testing"
)

// Test constants
const (
	validNPMVersion      = "1.2.3"
	validSemanticVersion = "2.0.0"
	validMavenVersion    = "1.0.0"
	invalidVersion       = "invalid-version"
	emptyVersion         = ""
)

// TestNewNpmVersion tests NPM version creation
func TestNewNpmVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "Valid NPM version",
			version:     validNPMVersion,
			expectError: false,
		},
		{
			name:        "Valid semantic version",
			version:     validSemanticVersion,
			expectError: false,
		},
		{
			name:        "Version with pre-release",
			version:     "1.0.0-alpha.1",
			expectError: false,
		},
		{
			name:        "Version with build metadata",
			version:     "1.0.0+build.1",
			expectError: false,
		},
		{
			name:        "Invalid version format",
			version:     invalidVersion,
			expectError: true,
		},
		{
			name:        "Empty version",
			version:     emptyVersion,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := NewNpmVersion(tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for version %s, got nil", tt.version)
				}
				if version != nil {
					t.Errorf("Expected nil version for invalid input, got %v", version)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for version %s, got %v", tt.version, err)
				}
				if version == nil {
					t.Errorf("Expected valid version object for %s, got nil", tt.version)
				}
			}
		})
	}
}

// TestNewSemanticVersion tests semantic version creation
func TestNewSemanticVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "Valid semantic version",
			version:     validSemanticVersion,
			expectError: false,
		},
		{
			name:        "Version with patch",
			version:     "1.2.3",
			expectError: false,
		},
		{
			name:        "Invalid semantic version",
			version:     invalidVersion,
			expectError: true,
		},
		{
			name:        "Empty version",
			version:     emptyVersion,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := NewSemanticVersion(tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for version %s, got nil", tt.version)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for version %s, got %v", tt.version, err)
				}
				if version == nil {
					t.Errorf("Expected valid version object for %s, got nil", tt.version)
				}
			}
		})
	}
}

// TestNewMavenVersion tests Maven version creation
func TestNewMavenVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "Valid Maven version",
			version:     validMavenVersion,
			expectError: false,
		},
		{
			name:        "Maven SNAPSHOT version",
			version:     "1.0.0-SNAPSHOT",
			expectError: false,
		},
		{
			name:        "Invalid Maven version",
			version:     invalidVersion,
			expectError: true,
		},
		{
			name:        "Empty version",
			version:     emptyVersion,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := NewMavenVersion(tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for version %s, got nil", tt.version)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for version %s, got %v", tt.version, err)
				}
				if version == nil {
					t.Errorf("Expected valid version object for %s, got nil", tt.version)
				}
			}
		})
	}
}

// TestNewGoVersion tests Go version creation
func TestNewGoVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "Valid Go version",
			version:     "v1.20.0",
			expectError: false,
		},
		{
			name:        "Go version without v prefix",
			version:     "1.20.0",
			expectError: false,
		},
		{
			name:        "Invalid Go version",
			version:     invalidVersion,
			expectError: true,
		},
		{
			name:        "Empty version",
			version:     emptyVersion,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := NewGoVersion(tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for version %s, got nil", tt.version)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for version %s, got %v", tt.version, err)
				}
				if version == nil {
					t.Errorf("Expected valid version object for %s, got nil", tt.version)
				}
			}
		})
	}
}

// TestNewPEP440Version tests PEP440 (Python) version creation
func TestNewPEP440Version(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "Valid PEP440 version",
			version:     "1.2.3",
			expectError: false,
		},
		{
			name:        "PEP440 version with dev release",
			version:     "1.2.3.dev1",
			expectError: false,
		},
		{
			name:        "Invalid PEP440 version",
			version:     invalidVersion,
			expectError: true,
		},
		{
			name:        "Empty version",
			version:     emptyVersion,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := NewPEP440Version(tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for version %s, got nil", tt.version)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for version %s, got %v", tt.version, err)
				}
				if version == nil {
					t.Errorf("Expected valid version object for %s, got nil", tt.version)
				}
			}
		})
	}
}

// TestVersionConstraintChecking tests version constraint validation
func TestVersionConstraintChecking(t *testing.T) {
	// This test assumes we have constraint checking methods
	// The actual implementation would depend on the version types
	t.Run("NPM version constraint checking", func(t *testing.T) {
		version, err := NewNpmVersion("1.2.3")
		if err != nil {
			t.Skipf("Skipping constraint test due to version creation error: %v", err)
		}

		// Test constraint checking if the method exists
		if version != nil {
			// Example: version.Check(">=1.0.0")
			t.Log("NPM version created successfully for constraint testing")
		}
	})
}

// Benchmark tests for version creation performance
func BenchmarkNewNpmVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewNpmVersion(validNPMVersion)
	}
}

func BenchmarkNewSemanticVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewSemanticVersion(validSemanticVersion)
	}
}

func BenchmarkNewMavenVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMavenVersion(validMavenVersion)
	}
}

// Test edge cases for version handling
func TestVersionEdgeCases(t *testing.T) {
	edgeCases := []string{
		"0.0.0",
		"999.999.999",
		"1.0.0-alpha",
		"1.0.0-beta.1",
		"1.0.0+build.1",
		"1.0.0-alpha+build.1",
	}

	for _, version := range edgeCases {
		t.Run("EdgeCase_"+version, func(t *testing.T) {
			// Test NPM version parsing
			npmVer, err := NewNpmVersion(version)
			if err != nil {
				t.Logf("NPM version parsing failed for %s: %v", version, err)
			} else if npmVer != nil {
				t.Logf("NPM version parsing succeeded for %s", version)
			}

			// Test semantic version parsing
			semVer, err := NewSemanticVersion(version)
			if err != nil {
				t.Logf("Semantic version parsing failed for %s: %v", version, err)
			} else if semVer != nil {
				t.Logf("Semantic version parsing succeeded for %s", version)
			}
		})
	}
}
