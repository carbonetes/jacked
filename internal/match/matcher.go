package match

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/package-url/packageurl-go"
)

type Matcher struct {
	Component cyclonedx.Component
	Upstream  string
	Matches   []types.Match
	Matched   []Found
}

type Found struct {
	Ref        string
	Constraint string
	Match      types.Match
	Metadata   types.Vulnerability
}

func Find(bom cyclonedx.BOM) []*Matcher {
	return createMatchersForComponents(*bom.Components, *db.FindMatchesByPackageNames(getPackageNames(*bom.Components)))
}

func createMatchersForComponents(components []cyclonedx.Component, matches []types.Match) []*Matcher {
	if components == nil || matches == nil {
		return nil
	}

	matchers := make([]*Matcher, 0, len(components))
	for _, component := range components {
		matcher := NewMatcher(component, matches)
		if matcher.Component.BOMRef != "" {
			matchers = append(matchers, matcher)
		}
		if matcher := NewMatcher(component, matches); matcher != nil {
			Analyze(*matcher)
			if len(matcher.Matched) > 0 {
				matchers = append(matchers, matcher)
			}
		}
	}

	return matchers
}

func NewMatcher(component cyclonedx.Component, matches []types.Match) *Matcher {

	upstream := getPackageUpstream(component.PackageURL)
	matchCandidates := filterMatches(component, matches, upstream)

	return &Matcher{
		Component: component,
		Upstream:  upstream,
		Matches:   matchCandidates,
	}
}

func getPackageNames(components []cyclonedx.Component) []string {
	names := make([]string, 0, len(components))
	for _, component := range components {
		names = append(names, component.Name)
		if upstream := getPackageUpstream(component.PackageURL); upstream != "" {
			names = append(names, upstream)
		}
	}
	return helper.Unique(names)
}

func getPackageUpstream(purl string) (upstream string) {
	if purl == "" {
		return
	}

	p, err := packageurl.FromString(purl)
	if err != nil {
		log.Error(err)
		return
	}

	for _, q := range p.Qualifiers {
		if q.Key == "upstream" {
			return q.Value
		}
	}
	return
}

func Analyze(m Matcher) {
	if len(m.Matches) == 0 {
		return
	}

	switch m.Component.Type {
	case cyclonedx.ComponentTypeLibrary:
		AnalyzeLibrary(m)
	case cyclonedx.ComponentTypeOS:
		// TODO: Implement OS component analysis
	default:
		// No default action
	}
}

func AnalyzeLibrary(m Matcher) {
	if len(m.Matches) == 0 {
		return
	}

	purl, err := getPackageURL(m.Component)
	if err != nil {
		log.Error(err)
		return
	}

	switch purl.Type {
	case packageurl.TypeApk:
		m.Matched = matchApk(m)
	case packageurl.TypeMaven:
		matchMaven(m)
	case packageurl.TypeDebian:
		matchDebian(m)
	default:
		matchGeneric(m)
	}
}

func getPackageURL(component cyclonedx.Component) (packageurl.PackageURL, error) {
	return packageurl.FromString(component.PackageURL)
}

func filterMatches(component cyclonedx.Component, matches []types.Match, upstream string) []types.Match {
	matchCandidates := []types.Match{}
	for _, match := range matches {
		if match.Package == component.Name || (upstream != "" && match.Package == upstream) {
			matchCandidates = append(matchCandidates, match)
		}
	}

	return matchCandidates
}
