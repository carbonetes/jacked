package scan

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

const (
	componentTypeProperty = "component:type"
	testCPE1              = "cpe:2.3:a:example:component:1.0.0:*:*:*:*:*:*:*"
	testCPE2              = "cpe:2.3:a:example:component:2.0.0:*:*:*:*:*:*:*"
)

func TestMatcherScannerPackageTypeMapping(t *testing.T) {
	// Create a mock scanner for testing package type mapping
	scanner := &MatcherScanner{}

	tests := []struct {
		name            string
		componentType   string
		expectedPkgType matchertypes.PackageType
	}{
		{"NPM component", "npm", matchertypes.NPMPkg},
		{"Go component", "go", matchertypes.GoPkg},
		{"Golang component", "golang", matchertypes.GoPkg},
		{"Java component", "java", matchertypes.JavaPkg},
		{"Maven component", "maven", matchertypes.JavaPkg},
		{"Python component", "python", matchertypes.PythonPkg},
		{"PyPI component", "pypi", matchertypes.PythonPkg},
		{"Ruby component", "gem", matchertypes.GemPkg},
		{"RubyGem component", "rubygem", matchertypes.GemPkg},
		{"APK component", "apk", matchertypes.APKPkg},
		{"Debian component", "deb", matchertypes.DebPkg},
		{"DPKG component", "dpkg", matchertypes.DebPkg},
		{"RPM component", "rpm", matchertypes.RPMPkg},
		{"Unknown component", "unknown", matchertypes.UnknownPkg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a component with the specified type
			properties := []cyclonedx.Property{
				{Name: componentTypeProperty, Value: tt.componentType},
			}
			component := cyclonedx.Component{
				Properties: &properties,
			}

			pkgType := scanner.getPackageType(component)
			if pkgType != tt.expectedPkgType {
				t.Errorf("Expected package type %s, got %s", string(tt.expectedPkgType), string(pkgType))
			}
		})
	}
}

func TestMatcherScannerLanguageMapping(t *testing.T) {
	scanner := &MatcherScanner{}

	tests := []struct {
		name             string
		componentType    string
		expectedLanguage matchertypes.Language
	}{
		{"NPM component", "npm", matchertypes.JavaScript},
		{"Go component", "go", matchertypes.Go},
		{"Golang component", "golang", matchertypes.Go},
		{"Java component", "java", matchertypes.Java},
		{"Maven component", "maven", matchertypes.Java},
		{"Python component", "python", matchertypes.Python},
		{"PyPI component", "pypi", matchertypes.Python},
		{"Ruby component", "gem", matchertypes.Ruby},
		{"RubyGem component", "rubygem", matchertypes.Ruby},
		{"Unknown component", "unknown", matchertypes.UnknownLang},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			properties := []cyclonedx.Property{
				{Name: componentTypeProperty, Value: tt.componentType},
			}
			component := cyclonedx.Component{
				Properties: &properties,
			}

			language := scanner.getLanguage(component)
			if language != tt.expectedLanguage {
				t.Errorf("Expected language %s, got %s", string(tt.expectedLanguage), string(language))
			}
		})
	}
}

func TestMatcherScannerComponentTypeExtraction(t *testing.T) {
	scanner := &MatcherScanner{}

	tests := []struct {
		name         string
		component    cyclonedx.Component
		expectedType string
	}{
		{
			name: "Component with property type",
			component: cyclonedx.Component{
				Properties: &[]cyclonedx.Property{
					{Name: componentTypeProperty, Value: "npm"},
				},
			},
			expectedType: "npm",
		},
		{
			name: "Component with CycloneDX type field",
			component: cyclonedx.Component{
				Type: cyclonedx.ComponentTypeLibrary,
			},
			expectedType: "library",
		},
		{
			name: "Component with no type info",
			component: cyclonedx.Component{
				Name: "test-component",
			},
			expectedType: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			componentType := scanner.getComponentType(tt.component)
			if componentType != tt.expectedType {
				t.Errorf("Expected component type %s, got %s", tt.expectedType, componentType)
			}
		})
	}
}

func TestMatcherScannerCPEExtraction(t *testing.T) {
	scanner := &MatcherScanner{}

	tests := []struct {
		name         string
		component    cyclonedx.Component
		expectedCPEs []string
	}{
		{
			name: "Component with CPE property",
			component: cyclonedx.Component{
				Properties: &[]cyclonedx.Property{
					{Name: "cpe", Value: testCPE1},
				},
			},
			expectedCPEs: []string{testCPE1},
		},
		{
			name: "Component with multiple CPE properties",
			component: cyclonedx.Component{
				Properties: &[]cyclonedx.Property{
					{Name: "cpe", Value: testCPE1},
					{Name: "cpe23", Value: testCPE2},
				},
			},
			expectedCPEs: []string{testCPE1, testCPE2},
		},
		{
			name: "Component with CPE field",
			component: cyclonedx.Component{
				CPE: testCPE1,
			},
			expectedCPEs: []string{testCPE1},
		},
		{
			name: "Component with no CPE",
			component: cyclonedx.Component{
				Name: "test-component",
			},
			expectedCPEs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := scanner.extractCPEs(tt.component)
			if len(cpes) != len(tt.expectedCPEs) {
				t.Errorf("Expected %d CPEs, got %d", len(tt.expectedCPEs), len(cpes))
				return
			}

			for i, expectedCPE := range tt.expectedCPEs {
				if cpes[i] != expectedCPE {
					t.Errorf("Expected CPE %s, got %s", expectedCPE, cpes[i])
				}
			}
		})
	}
}
