package golang

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Go modules
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new Go vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:                      true,
		AlwaysUseCPEForStdlib:        true,
		AllowMainModulePseudoVersion: false,
		MaxConcurrency:               4,
		EnableCaching:                true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.GoMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for Go modules
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only Go packages
	var goPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.GoPkg || pkg.Language == matchertypes.Go || pkg.Ecosystem == "go" {
			// For Go packages, we might need to handle special cases like stdlib
			if m.shouldSearchByCPE(pkg.Name) {
				// Ensure CPE matching is enabled for standard library packages
				opts.CPEMatching = true
			}
			goPackages = append(goPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, goPackages, opts)
}

// shouldSearchByCPE determines if a Go package should use CPE matching
func (m *Matcher) shouldSearchByCPE(packageName string) bool {
	// Standard library packages should use CPE matching
	stdlibPackages := []string{"stdlib", "crypto", "net", "http", "encoding"}
	for _, stdlib := range stdlibPackages {
		if packageName == stdlib {
			return true
		}
	}
	return true // AlwaysUseCPEForStdlib is true in config
}
