package maven

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Maven/Java packages
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new Maven vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:             true,
		SearchMavenUpstream: true,
		SearchMavenBySHA:    true,
		MaxConcurrency:      4,
		EnableCaching:       true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.MavenMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for Maven packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only Java/Maven packages
	var javaPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.JavaPkg || pkg.Language == matchertypes.Java || pkg.Ecosystem == "maven" {
			javaPackages = append(javaPackages, pkg)
		}
	}

	// Use base matcher, but could be extended for Maven-specific logic
	results, err := m.Matcher.FindMatches(ctx, javaPackages, opts)
	if err != nil {
		return nil, err
	}

	// Maven-specific post-processing could be added here
	// For example, searching upstream Maven repositories or SHA-based matching

	return results, nil
}
