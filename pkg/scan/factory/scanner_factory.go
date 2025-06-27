package factory

import (
	"context"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/core"
)

// ScannerFactory creates scanners using the new base architecture
type ScannerFactory struct {
	store db.Store
}

// NewScannerFactory creates a new scanner factory
func NewScannerFactory(store db.Store) *ScannerFactory {
	return &ScannerFactory{store: store}
}

// CreateAllScanners creates all available scanners
func (f *ScannerFactory) CreateAllScanners() []core.Scanner {
	scanners := []core.Scanner{
		f.CreateNPMScanner(),
		f.CreateGoScanner(),
		f.CreateMavenScanner(),
		f.CreatePythonScanner(),
		f.CreateRubyScanner(),
		f.CreateAPKScanner(),
		f.CreateDpkgScanner(),
		f.CreateRPMScanner(),
		f.CreateGenericScanner(),
	}

	return scanners
}

// CreateNPMScanner creates an NPM vulnerability scanner
func (f *ScannerFactory) CreateNPMScanner() core.Scanner {
	parser := base.NewNPMVersionParser()
	provider := base.NewKeywordVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("npm", "npm", f.store, parser, provider)
}

// CreateGoScanner creates a Go vulnerability scanner
func (f *ScannerFactory) CreateGoScanner() core.Scanner {
	parser := base.NewGoVersionParser()
	provider := base.NewKeywordVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("golang", "go", f.store, parser, provider)
}

// CreateMavenScanner creates a Maven vulnerability scanner
func (f *ScannerFactory) CreateMavenScanner() core.Scanner {
	parser := base.NewMavenVersionParser()
	provider := base.NewKeywordVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("maven", "java", f.store, parser, provider)
}

// CreatePythonScanner creates a Python vulnerability scanner
func (f *ScannerFactory) CreatePythonScanner() core.Scanner {
	parser := base.NewPythonVersionParser()
	provider := base.NewKeywordVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("python", "python", f.store, parser, provider)
}

// CreateRubyScanner creates a Ruby gem vulnerability scanner
func (f *ScannerFactory) CreateRubyScanner() core.Scanner {
	parser := base.NewRubyVersionParser()
	provider := base.NewKeywordVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("rubygem", "gem", f.store, parser, provider)
}

// CreateAPKScanner creates an APK vulnerability scanner
func (f *ScannerFactory) CreateAPKScanner() core.Scanner {
	parser := base.NewAPKVersionParser()
	provider := base.NewAPKVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("apk", "apk", f.store, parser, provider)
}

// CreateDpkgScanner creates a DPKG vulnerability scanner
func (f *ScannerFactory) CreateDpkgScanner() core.Scanner {
	parser := base.NewDpkgVersionParser()
	provider := base.NewDpkgVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("dpkg", "deb", f.store, parser, provider)
}

// CreateRPMScanner creates an RPM vulnerability scanner
func (f *ScannerFactory) CreateRPMScanner() core.Scanner {
	parser := base.NewRPMVersionParser()
	provider := base.NewRPMVulnerabilityProvider(f.store)
	return base.NewCustomComponentScanner("rpm", "rpm", f.store, parser, provider)
}

// CreateGenericScanner creates a generic vulnerability scanner
func (f *ScannerFactory) CreateGenericScanner() core.Scanner {
	parser := base.NewSemanticVersionParser()
	provider := base.NewKeywordVulnerabilityProvider(f.store)

	// Create a filter for excluding specific component types that have dedicated scanners
	excludedTypes := []string{"apk", "deb", "gem", "go", "java", "npm", "python", "rpm"}
	filter := core.NewTypeBasedFilter(nil, excludedTypes)

	// For generic scanner, we need to create a custom implementation that respects the filter
	return &GenericScannerWithFilter{
		scanner: base.NewCustomComponentScanner("generic", "generic", f.store, parser, provider),
		filter:  filter,
	}
}

// GenericScannerWithFilter wraps a scanner with component filtering
type GenericScannerWithFilter struct {
	scanner core.Scanner
	filter  core.ComponentFilter
}

func (s *GenericScannerWithFilter) Type() string {
	return s.scanner.Type()
}

func (s *GenericScannerWithFilter) SupportsComponent(componentType string) bool {
	return s.filter.SupportsType(componentType)
}

func (s *GenericScannerWithFilter) Scan(ctx context.Context, bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	// Apply filter to BOM components
	if bom.Components != nil {
		components := s.filter.Filter(*bom.Components)
		filteredBOM := *bom // Copy BOM
		filteredBOM.Components = &components
		return s.scanner.Scan(ctx, &filteredBOM)
	}

	return s.scanner.Scan(ctx, bom)
}
