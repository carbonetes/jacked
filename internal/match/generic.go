package match

import "github.com/carbonetes/jacked/internal/match/constraint"

func matchGeneric(m Matcher) {
	if m.Matches == nil || len(m.Matches) == 0 {
		return
	}

	found := []*Found{}
	for _, match := range m.Matches {
		constraint, result := constraint.Check(match.Constraints, m.Component.Version)
		if result {
			found = append(found, &Found{
				Match:      match,
				Constraint: constraint,
			})
		}
	}
}
