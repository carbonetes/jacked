package stock

import (
	"context"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/base"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Matcher is a generic matcher that handles any package type using CPE matching
type Matcher struct {
	*base.Matcher
}

// NewMatcher creates a new stock vulnerability matcher
func NewMatcher(store db.Store) *Matcher {
	config := base.Config{
		UseCPEs:        true,
		MaxConcurrency: 4,
		EnableCaching:  true,
	}

	return &Matcher{
		Matcher: base.NewMatcher(matchertypes.StockMatcherType, store, config),
	}
}

// FindMatches implements generic matching for any package type
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	// Stock matcher can handle any package, but primarily relies on CPE matching
	opts.CPEMatching = true
	return m.Matcher.FindMatches(ctx, packages, opts)
}
