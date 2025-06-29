package python

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Python packages
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new Python vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        true,
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.PythonMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for Python packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only Python packages
	var pythonPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.PythonPkg || pkg.Language == matchertypes.Python || pkg.Ecosystem == "pypi" {
			pythonPackages = append(pythonPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, pythonPackages, opts)
}
