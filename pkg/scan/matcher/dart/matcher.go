package dart

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Dart packages (Pub)
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new Dart vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        true,
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.DartMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for Dart packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only Dart packages
	var dartPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.DartPkg || pkg.Language == matchertypes.Dart || pkg.Ecosystem == "pub" || pkg.Ecosystem == "dart" {
			dartPackages = append(dartPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, dartPackages, opts)
}
