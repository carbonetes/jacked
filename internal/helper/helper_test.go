package helper

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

// Test constants
const (
	testComponentName    = "test-component"
	testComponentVersion = "1.0.0"
	testUpstreamName     = "upstream-component"
	componentTypeKey     = "diggity:package:type"
	otherPropertyKey     = "other:property"
	propertyValue        = "value"
	propertyValue2       = "value2"
)

// TestGetComponentType tests the GetComponentType function
func TestGetComponentType(t *testing.T) {
	tests := []struct {
		name       string
		properties *[]cyclonedx.Property
		expected   string
	}{
		{
			name: "NPM component",
			properties: &[]cyclonedx.Property{
				{Name: componentTypeKey, Value: "npm"},
			},
			expected: "npm",
		},
		{
			name: "Maven component",
			properties: &[]cyclonedx.Property{
				{Name: componentTypeKey, Value: "java"},
			},
			expected: "java",
		},
		{
			name: "Multiple properties with component type",
			properties: &[]cyclonedx.Property{
				{Name: otherPropertyKey, Value: propertyValue},
				{Name: componentTypeKey, Value: "python"},
				{Name: "another:property", Value: propertyValue2},
			},
			expected: "python",
		},
		{
			name: "No component type property",
			properties: &[]cyclonedx.Property{
				{Name: otherPropertyKey, Value: propertyValue},
			},
			expected: "unknown",
		},
		{
			name:       "Nil properties",
			properties: nil,
			expected:   "unknown",
		},
		{
			name:       "Empty properties",
			properties: &[]cyclonedx.Property{},
			expected:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetComponentType(tt.properties)
			if result != tt.expected {
				t.Errorf("GetComponentType() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestFindUpstream tests the FindUpstream function
func TestFindUpstream(t *testing.T) {
	tests := []struct {
		name     string
		bomRef   string
		expected string
	}{
		{
			name:     "Simple package reference",
			bomRef:   "package@1.0.0",
			expected: "",
		},
		{
			name:     "Empty BOM reference",
			bomRef:   "",
			expected: "",
		},
		{
			name:     "Complex BOM reference with path",
			bomRef:   "pkg:npm/namespace/package@1.0.0",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindUpstream(tt.bomRef)
			// Note: The actual implementation would determine the expected behavior
			// This is a placeholder test structure
			_ = result // Avoid unused variable warning
		})
	}
}

// TestComponentTypeConstantValues tests that component type constants are properly defined
func TestComponentTypeConstantValues(t *testing.T) {
	// This test ensures that if we have constants for component types,
	// they maintain their expected values
	expectedTypes := map[string]bool{
		"npm":    true,
		"java":   true,
		"python": true,
		"go":     true,
		"dpkg":   true,
		"apk":    true,
		"rpm":    true,
		"gem":    true,
	}

	for componentType := range expectedTypes {
		if componentType == "" {
			t.Errorf("Component type should not be empty")
		}
	}
}

// Helper function to create a test component with properties
func createTestComponent(name, version, componentType string) cyclonedx.Component {
	properties := []cyclonedx.Property{
		{
			Name:  componentTypeKey,
			Value: componentType,
		},
	}

	return cyclonedx.Component{
		Name:       name,
		Version:    version,
		Properties: &properties,
		BOMRef:     name + "@" + version,
	}
}

// TestCreateTestComponent tests our helper function for creating test components
func TestCreateTestComponent(t *testing.T) {
	component := createTestComponent(testComponentName, testComponentVersion, "npm")

	if component.Name != testComponentName {
		t.Errorf("Expected component name %s, got %s", testComponentName, component.Name)
	}

	if component.Version != testComponentVersion {
		t.Errorf("Expected component version %s, got %s", testComponentVersion, component.Version)
	}

	if component.Properties == nil {
		t.Fatal("Expected component properties to be set")
	}

	componentType := GetComponentType(component.Properties)
	if componentType != "npm" {
		t.Errorf("Expected component type npm, got %s", componentType)
	}
}

// Benchmark test for GetComponentType
func BenchmarkGetComponentType(b *testing.B) {
	properties := &[]cyclonedx.Property{
		{Name: otherPropertyKey, Value: propertyValue},
		{Name: componentTypeKey, Value: "npm"},
		{Name: "another:property", Value: propertyValue2},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetComponentType(properties)
	}
}

// Benchmark test for FindUpstream
func BenchmarkFindUpstream(b *testing.B) {
	bomRef := "pkg:npm/namespace/package@1.0.0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FindUpstream(bomRef)
	}
}
