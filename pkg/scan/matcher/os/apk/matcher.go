package apk

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher handles vulnerability matching for Alpine APK packages
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new APK vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        false, // APK packages typically don't use CPEs
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.APKMatcherType, store, config),
	}
}

// FindMatches implements ecosystem-specific matching for APK packages
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Filter packages to only APK packages
	var apkPackages []matchertypes.Package
	for _, pkg := range packages {
		if pkg.Type == matchertypes.APKPkg || pkg.Ecosystem == "apk" {
			apkPackages = append(apkPackages, pkg)
		}
	}

	return m.Matcher.FindMatches(ctx, apkPackages, opts)
}
