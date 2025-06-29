package dpkg

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Debian packages
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new DPKG vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        false, // DPKG packages typically don't use CPEs
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.DpkgMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for DPKG packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only DEB packages
	var debPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.DebPkg || pkg.Ecosystem == "deb" {
			debPackages = append(debPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, debPackages, opts)
}
