package match

import "github.com/carbonetes/jacked/internal/match/maven"

func matchMaven(m Matcher) {
	if m.Matches == nil || len(m.Matches) == 0 {
		return
	}

	found := []*Found{}
	for _, match := range m.Matches {
		if match.Package == m.Component.Name {
			constraint, result := maven.CheckConstraint(match.Constraints, m.Component.Version)
			if result {
				found = append(found, &Found{
					Match:      match,
					Constraint: constraint,
				})
			}
		}
	}
}
