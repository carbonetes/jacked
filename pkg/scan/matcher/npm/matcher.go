package npm

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for NPM packages
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new NPM vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        true,
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.NPMMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for NPM packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only NPM packages
	var npmPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.NPMPkg || pkg.Ecosystem == "npm" {
			npmPackages = append(npmPackages, pkg)
		}
	}

	// Use base matcher for actual matching
	return m.Matcher.FindMatches(ctx, npmPackages, opts)
}
