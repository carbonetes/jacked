package ruby

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Ruby gems
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new Ruby gem vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        true,
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.RubyGemMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for Ruby gems
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only Ruby gem packages
	var gemPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.GemPkg || pkg.Language == matchertypes.Ruby || pkg.Ecosystem == "rubygems" {
			gemPackages = append(gemPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, gemPackages, opts)
}
