package rpm

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for RPM packages
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new RPM vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        false, // RPM packages typically don't use CPEs
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.RPMMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for RPM packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only RPM packages
	var rpmPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.RPMPkg || pkg.Ecosystem == "rpm" {
			rpmPackages = append(rpmPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, rpmPackages, opts)
}
