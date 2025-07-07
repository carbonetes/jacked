package factory

import (
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/matcher"
	"github.com/carbonetes/jacked/pkg/scan/matcher/dart"
	"github.com/carbonetes/jacked/pkg/scan/matcher/golang"
	"github.com/carbonetes/jacked/pkg/scan/matcher/maven"
	"github.com/carbonetes/jacked/pkg/scan/matcher/npm"
	"github.com/carbonetes/jacked/pkg/scan/matcher/os/apk"
	"github.com/carbonetes/jacked/pkg/scan/matcher/os/dpkg"
	"github.com/carbonetes/jacked/pkg/scan/matcher/os/rpm"
	"github.com/carbonetes/jacked/pkg/scan/matcher/python"
	"github.com/carbonetes/jacked/pkg/scan/matcher/ruby"
	"github.com/carbonetes/jacked/pkg/scan/matcher/stock"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// MatcherFactory creates and manages vulnerability matchers
type MatcherFactory struct {
	store db.Store
}

// NewMatcherFactory creates a new matcher factory
func NewMatcherFactory(store db.Store) *MatcherFactory {
	return &MatcherFactory{store: store}
}

// CreateDefaultMatchers creates the default set of vulnerability matchers
func (f *MatcherFactory) CreateDefaultMatchers() []matchertypes.VulnerabilityMatcher {
	return []matchertypes.VulnerabilityMatcher{
		f.CreateNPMMatcher(),
		f.CreateGoMatcher(),
		f.CreateMavenMatcher(),
		f.CreatePythonMatcher(),
		f.CreateRubyGemMatcher(),
		f.CreateDartMatcher(),
		f.CreateAPKMatcher(),
		f.CreateDpkgMatcher(),
		f.CreateRPMMatcher(),
		f.CreateStockMatcher(),
	}
}

// CreateNPMMatcher creates an NPM vulnerability matcher
func (f *MatcherFactory) CreateNPMMatcher() matchertypes.VulnerabilityMatcher {
	return npm.NewMatcher(f.store)
}

// CreateGoMatcher creates a Go vulnerability matcher
func (f *MatcherFactory) CreateGoMatcher() matchertypes.VulnerabilityMatcher {
	return golang.NewMatcher(f.store)
}

// CreateMavenMatcher creates a Maven vulnerability matcher
func (f *MatcherFactory) CreateMavenMatcher() matchertypes.VulnerabilityMatcher {
	return maven.NewMatcher(f.store)
}

// CreatePythonMatcher creates a Python vulnerability matcher
func (f *MatcherFactory) CreatePythonMatcher() matchertypes.VulnerabilityMatcher {
	return python.NewMatcher(f.store)
}

// CreateRubyGemMatcher creates a Ruby gem vulnerability matcher
func (f *MatcherFactory) CreateRubyGemMatcher() matchertypes.VulnerabilityMatcher {
	return ruby.NewMatcher(f.store)
}

// CreateDartMatcher creates a Dart vulnerability matcher
func (f *MatcherFactory) CreateDartMatcher() matchertypes.VulnerabilityMatcher {
	return dart.NewMatcher(f.store)
}

// CreateAPKMatcher creates an APK vulnerability matcher
func (f *MatcherFactory) CreateAPKMatcher() matchertypes.VulnerabilityMatcher {
	return apk.NewMatcher(f.store)
}

// CreateDpkgMatcher creates a DPKG vulnerability matcher
func (f *MatcherFactory) CreateDpkgMatcher() matchertypes.VulnerabilityMatcher {
	return dpkg.NewMatcher(f.store)
}

// CreateRPMMatcher creates an RPM vulnerability matcher
func (f *MatcherFactory) CreateRPMMatcher() matchertypes.VulnerabilityMatcher {
	return rpm.NewMatcher(f.store)
}

// CreateStockMatcher creates a stock/generic vulnerability matcher
func (f *MatcherFactory) CreateStockMatcher() matchertypes.VulnerabilityMatcher {
	return stock.NewMatcher(f.store)
}

// CreateMatchersWithConfig creates matchers with custom configuration
func (f *MatcherFactory) CreateMatchersWithConfig(config matcher.MatcherConfig) []matchertypes.VulnerabilityMatcher {
	matchers := f.CreateDefaultMatchers()

	// Apply configuration to all matchers
	for _, m := range matchers {
		if configurable, ok := m.(ConfigurableMatcher); ok {
			configurable.Configure(config)
		}
	}

	return matchers
}

// ConfigurableMatcher interface for matchers that can be configured
type ConfigurableMatcher interface {
	Configure(config matcher.MatcherConfig)
}

// MatcherRegistry manages registered matchers
type MatcherRegistry struct {
	matchers map[matcher.MatcherType]matchertypes.VulnerabilityMatcher
}

// NewMatcherRegistry creates a new matcher registry
func NewMatcherRegistry() *MatcherRegistry {
	return &MatcherRegistry{
		matchers: make(map[matcher.MatcherType]matchertypes.VulnerabilityMatcher),
	}
}

// Register adds a matcher to the registry
func (r *MatcherRegistry) Register(m matchertypes.VulnerabilityMatcher) {
	r.matchers[m.Type()] = m
}

// Get retrieves a matcher by type
func (r *MatcherRegistry) Get(matcherType matcher.MatcherType) matchertypes.VulnerabilityMatcher {
	return r.matchers[matcherType]
}

// GetAll returns all registered matchers
func (r *MatcherRegistry) GetAll() []matchertypes.VulnerabilityMatcher {
	var matchers []matchertypes.VulnerabilityMatcher
	for _, m := range r.matchers {
		matchers = append(matchers, m)
	}
	return matchers
}

// GetByTypes returns matchers for specific types
func (r *MatcherRegistry) GetByTypes(types []matcher.MatcherType) []matchertypes.VulnerabilityMatcher {
	var matchers []matchertypes.VulnerabilityMatcher
	for _, matcherType := range types {
		if m, exists := r.matchers[matcherType]; exists {
			matchers = append(matchers, m)
		}
	}
	return matchers
}

// Remove removes a matcher from the registry
func (r *MatcherRegistry) Remove(matcherType matcher.MatcherType) {
	delete(r.matchers, matcherType)
}

// Clear removes all matchers from the registry
func (r *MatcherRegistry) Clear() {
	r.matchers = make(map[matcher.MatcherType]matchertypes.VulnerabilityMatcher)
}

// List returns all registered matcher types
func (r *MatcherRegistry) List() []matcher.MatcherType {
	var types []matcher.MatcherType
	for matcherType := range r.matchers {
		types = append(types, matcherType)
	}
	return types
}

// Size returns the number of registered matchers
func (r *MatcherRegistry) Size() int {
	return len(r.matchers)
}
